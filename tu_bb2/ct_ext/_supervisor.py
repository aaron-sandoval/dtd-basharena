"""Vendored online-decomposer supervisor functions (control_arena-free).

Copied verbatim (via inspect.getsource) from tu_bb2.policies.agents so the
ct_ext native path does not import the legacy, control_arena-coupled agents.py.
Composed-evaluation triggers use these: _online_decomposer_evaluate (the
trusted-model LLM supervisor over trigger_criteria) + _generate_next_task_description.
"""

import json
import re

from inspect_ai.model import (
    ChatMessageSystem,
    ChatMessageUser,
    GenerateConfig,
    ResponseSchema,
)
from inspect_ai.util._json import JSONSchema

from tu_bb2.constants import REJECTED_PROPOSAL_KEY
from tu_bb2.prompts.blue_prompts import OnlineDecomposerPrompts
from tu_bb2.utils import (
    ChildTaskTriggerComposedEvaluation,
    ONLINE_DECOMPOSER_ACTION,
    _OnlineDecomposerDecision,
    build_action_history_prompt,
)


# Belt-and-braces: the corrected task-writer system prompt should stop the model from
# emitting decision-block XML, but if any stray <reasoning>/<decision>/<trigger_number>
# block slips through, strip it so decision reasoning never leaks into a child task.
_DECISION_XML_RE = re.compile(
    r"<(reasoning|decision|trigger_number)>.*?</\1>", re.DOTALL | re.IGNORECASE
)


def _strip_decision_xml(text: str) -> str:
    """Remove stray decision-block XML, but never turn a non-empty completion into empty.

    If the model wrapped the entire task inside such a tag, stripping would empty the
    string and _switch(...) would silently fall back to the full root task -- a worse
    regression. In that case return the original completion unchanged.
    """
    if not text:
        return text
    stripped = _DECISION_XML_RE.sub("", text).strip()
    return stripped or text


async def _generate_next_task_description(
    model,
    generate_config: GenerateConfig,
    trigger,
    main_task_description: str,
    all_messages: list,
    reasoning: str = "",
    filter_rejected: bool = True,
) -> str:
    """Write the child task description for the agent that follows a switch.

    Args:
        model: Trusted model used for generation.
        generate_config: Generate config for the LLM call.
        trigger: The matched ChildTrigger (or default trigger object). Uses
            ``use_root_description``, ``summarize``, ``on_switch_prompt``, and
            ``use_reasoning_in_child_task_gen``.
        main_task_description: The original top-level task description.
        all_messages: Full ``state._messages`` across all child agents so far.
            Provides the history the model needs to write summaries.
        reasoning: The decomposer's reasoning text from the evaluation pass.
            Included in context when ``trigger.use_reasoning_in_child_task_gen``
            is True, so ideas already developed during evaluation are carried
            forward into the task-description generation call.
        filter_rejected: When True, drop messages tagged ``REJECTED_PROPOSAL_KEY``
            (pre-execution proposals that were rejected and never executed) before
            building the history prompt, so the summary reflects only executed
            actions. When False (default) the full history is used.

    Returns:
        The next child task description string.
    """
    if filter_rejected:
        all_messages = [
            m for m in all_messages
            if not (m.metadata or {}).get(REJECTED_PROPOSAL_KEY)
        ]

    reasoning_block = ""
    if reasoning and getattr(trigger, "use_reasoning_in_child_task_gen", False):
        reasoning_block = f"<decomposer_reasoning>\n{reasoning}\n</decomposer_reasoning>\n\n"

    if trigger.use_root_description:
        if not trigger.summarize:
            # No LLM call — use root description verbatim.
            return main_task_description
        # Ask the model to write only a trajectory summary; append to root description.
        history = build_action_history_prompt(all_messages, main_task_description)
        output = await model.generate(
            input=[
                ChatMessageSystem(content=OnlineDecomposerPrompts.DECOMPOSER_TASK_WRITER_SYSTEM_PROMPT),
                ChatMessageUser(content=f"{history}\n\n{reasoning_block}{OnlineDecomposerPrompts.DECOMPOSER_SUMMARY_ONLY_PROMPT}"),
            ],
            tools=[],
            config=generate_config,
            cache=False,
        )
        summary_text = _strip_decision_xml(output.completion or "")
        return f"{main_task_description}\n\n# Completed so far:\n{summary_text}" if summary_text else main_task_description
    else:
        # Ask the model to write the full next task description from scratch.
        history = build_action_history_prompt(all_messages, main_task_description)
        switch_prompt = OnlineDecomposerPrompts.format_switch_prompt(trigger)
        output = await model.generate(
            input=[
                ChatMessageSystem(content=OnlineDecomposerPrompts.DECOMPOSER_TASK_WRITER_SYSTEM_PROMPT),
                ChatMessageUser(content=f"{history}\n\n{reasoning_block}{switch_prompt}"),
            ],
            tools=[],
            config=generate_config,
            cache=False,
        )
        return _strip_decision_xml(output.completion or "")


async def _online_decomposer_evaluate(
    model,
    generate_config: GenerateConfig,
    triggers: list[ChildTaskTriggerComposedEvaluation],
    main_task_description: str,
    child_msgs: list,
    all_messages: list,
    decomposer_messages: list,
    agent_index: int,
    filter_rejected: bool = False,
) -> _OnlineDecomposerDecision:
    """Two-pass decomposer evaluation: reasoning + structured decision.

    When the decision is "switch", delegates task-description writing to
    ``_generate_next_task_description``.

    Args:
        model: The trusted model to use for evaluation.
        generate_config: Generate config for both passes.
        triggers: List of ChildTaskTriggerComposedEvaluation objects guiding decisions.
        main_task_description: The original top-level task description.
        child_msgs: All messages for the current child agent so far (starts with
            system message at index 0). Formatted using messages_to_xml into the
            evaluation user prompt.
        all_messages: Full ``state._messages`` across all child agents. Passed to
            ``_generate_next_task_description`` so it has complete history when
            writing the next task description.
        decomposer_messages: Interleaved history of prior child messages and
            decomposer reasoning pairs, in the order they were originally produced.
            Empty when decomposer_retain_history is False.
        agent_index: Which agent we're currently evaluating (0-based).

    Returns:
        _OnlineDecomposerDecision with action, trigger info, and new_messages.
        new_messages contains only [user_msg, assistant_msg] for this evaluation;
        the caller is responsible for prepending the delta child messages to
        new_messages before extending the interleaved history.
    """
    def _make_response_schema(include_terminate: bool) -> ResponseSchema:
        action_enum = ["continue", "switch", "terminate"] if include_terminate else ["continue", "switch"]
        return ResponseSchema(
            name="online_decomposer_decision",
            description="Decision by the online decomposer supervisor.",
            json_schema=JSONSchema(
                type="object",
                properties={
                    "reasoning": JSONSchema(
                        type="string",
                        description="Your step-by-step reasoning for the decision.",
                    ),
                    "action": JSONSchema(
                        type="string",
                        enum=action_enum,
                        description="continue = keep current agent; switch = end current agent and start new"
                        + ("; terminate = task is complete" if include_terminate else ""),
                    ),
                    "trigger_summary": JSONSchema(
                        type="string",
                        description="Summary label of the trigger that fired. Required when action is 'switch'.",
                    ),
                    "trigger_number": JSONSchema(
                        type="integer",
                        description="1-based number of the trigger that fired (from the trigger list). Required when action is 'switch'.",
                    ),
                },
                required=["reasoning", "action"],
            ),
        )

    async def _single_pass(messages: list, include_terminate: bool, fallback_action: ONLINE_DECOMPOSER_ACTION) -> tuple[dict, object]:
        """Single structured generate with one retry on JSON parse failure.

        Returns (parsed_dict, output_message).  On unrecoverable failure returns
        ({"action": fallback_action}, last_output).
        """
        config = generate_config.model_copy(update={"response_schema": _make_response_schema(include_terminate)})
        output = await model.generate(input=messages, tools=[], config=config, cache=False)
        try:
            return json.loads(output.completion), output
        except (json.JSONDecodeError, AttributeError) as e:
            retry_messages = messages + [
                output.message,
                ChatMessageUser(content=f"Your response could not be parsed as JSON: {e}. Please try again."),
            ]
            retry_output = await model.generate(input=retry_messages, tools=[], config=config, cache=False)
            try:
                return json.loads(retry_output.completion), retry_output
            except (json.JSONDecodeError, AttributeError):
                return {"action": fallback_action}, retry_output

    triggers_formatted = OnlineDecomposerPrompts.format_triggers(triggers)

    use_full_history = any(t.requires_child_history for t in triggers)
    if use_full_history:
        context_msgs = child_msgs
    else:
        # Only show the most recent assistant message and its subsequent tool responses.
        last_asst_idx = next(
            (i for i in range(len(child_msgs) - 1, -1, -1) if child_msgs[i].role == "assistant"),
            None,
        )
        if last_asst_idx is not None and last_asst_idx > 0:
            context_msgs = [child_msgs[0]] + child_msgs[last_asst_idx:]
        else:
            context_msgs = child_msgs
    action_history = build_action_history_prompt(
        context_msgs, main_task_description, full_history=use_full_history
    )

    system_msg = ChatMessageSystem(content=OnlineDecomposerPrompts.format_system_prompt(include_terminate=use_full_history))
    user_msg = ChatMessageUser(
        content=OnlineDecomposerPrompts.DECOMPOSER_EVALUATION_USER_PROMPT.format(
            action_history=action_history,
            triggers_formatted=triggers_formatted,
        )
    )

    # Single structured pass: system + interleaved history + current eval prompt.
    # When decomposer_retain_history is True, decomposer_messages contains past
    # child messages and decomposer reasoning pairs interleaved in production order.
    messages = [system_msg] + list(decomposer_messages) + [user_msg]
    parsed, output = await _single_pass(messages, include_terminate=use_full_history, fallback_action="continue")

    action: ONLINE_DECOMPOSER_ACTION = parsed.get("action", "continue")
    valid_actions: tuple[ONLINE_DECOMPOSER_ACTION, ...] = ("continue", "switch", "terminate") if use_full_history else ("continue", "switch")
    if action not in valid_actions:
        action = "continue"

    # When we didn't show full history, "switch" is a tentative result.  Re-run
    # with the complete history so the model can also choose "terminate" if the
    # task is already done.  The first query/answer is NOT included in the context
    # for this second query.
    if not use_full_history and action == "switch":
        full_action_history = build_action_history_prompt(all_messages, main_task_description, full_history=True)
        full_system_msg = ChatMessageSystem(content=OnlineDecomposerPrompts.format_system_prompt(include_terminate=True))
        full_user_msg = ChatMessageUser(
            content=OnlineDecomposerPrompts.DECOMPOSER_EVALUATION_USER_PROMPT.format(
                action_history=full_action_history,
                triggers_formatted=triggers_formatted,
            )
        )
        full_messages = [full_system_msg] + list(decomposer_messages) + [full_user_msg]
        parsed, output = await _single_pass(full_messages, include_terminate=True, fallback_action="switch")
        action: ONLINE_DECOMPOSER_ACTION = parsed.get("action", "switch")
        if action not in ("continue", "switch", "terminate"):
            action = "switch"
        # Use the full-history evaluation's messages as the record for this step.
        user_msg = full_user_msg

    try:
        trigger_number = int(parsed.get("trigger_number", 0))
    except (TypeError, ValueError):
        trigger_number = 0
    trigger_summary = parsed.get("trigger_summary", "")

    next_task_description = ""
    if action == "switch":
        # Prefer trigger_number (1-based) for reliable lookup; fall back to summary string match.
        if 1 <= trigger_number <= len(triggers):
            matched_trigger = triggers[trigger_number - 1]
        else:
            matched_trigger = next(
                (t for t in triggers if t.summary == trigger_summary), None
            )
        if matched_trigger is None:
            matched_trigger = OnlineDecomposerPrompts.ChildTriggers.DEFAULT_TRIGGER

        next_task_description = await _generate_next_task_description(
            model=model,
            generate_config=generate_config,
            trigger=matched_trigger,
            main_task_description=main_task_description,
            all_messages=all_messages,
            reasoning=parsed.get("reasoning", ""),
            filter_rejected=filter_rejected,
        )

    return _OnlineDecomposerDecision(
        action=action,
        trigger_summary=trigger_summary,
        trigger_number=trigger_number,
        next_task_description=next_task_description,
        next_implementer="U",  # hardcoded for now; restore parsed.get("next_implementer", "U") to re-enable model choice
        new_messages=[user_msg, output.message],
        reasoning=parsed.get("reasoning", ""),
        parsed=parsed,
    )
