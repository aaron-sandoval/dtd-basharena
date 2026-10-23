"""Post-execution trigger framework for the online decomposer (B6).

Scope (per the agreed decision): DTD-random plus a general post-execution
decider abstraction — NOT the composed-evaluation LLM-supervisor. A trigger is
evaluated after each executed action; the first to fire ``switch`` ends the
current child task and starts a new one.

The random-interval decider reuses tu-bb2's EXACT helpers (``_decomposition_rng``,
``_resolve_anchor``, ``_count_executed_actions``, ``IntervalTriggerState``,
``SharedDecompositionState``) so switch points are bit-identical given the same
seed/sample/epoch inputs. These helpers come from tu_bb2.utils (the temporary
migration scaffold); vendor them at finalization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from inspect_ai.model import ChatMessage
from inspect_ai.util import store_as

from tu_bb2.utils import (
    IntervalTriggerState,
    _count_executed_actions,
    _decomposition_rng,
    _resolve_anchor,
)


@dataclass
class PostExecTrigger:
    """A post-execution decomposition trigger.

    ``fire(messages)`` returns True when the decomposer should switch to a new
    child task after the most recent executed action. The remaining fields carry
    the switch behaviour (mirroring tu-bb2's ChildTaskTrigger): how to phrase the
    next-task prompt, whether to summarize, use the root task description, and any
    between-agent bash commands.

    Deliberately NOT a field here: attack-plan injection. Whether the implementer
    that follows a switch receives the root attack plan is decided solely by
    ``online_dtd``'s ``inject_attack_plan`` argument; triggers get no say. A
    per-trigger field used to exist but was never read, which is how the plan
    silently reached every child in every run before 2026-07-29.
    """

    summary: str
    fire: Callable[[list[ChatMessage]], bool]
    on_switch_prompt: str = ""
    summarize: bool = True
    use_root_description: bool = False
    use_reasoning_in_child_task_gen: bool = False
    bash_commands: list[dict] = field(default_factory=list)


def make_random_interval_trigger(
    *,
    form: str = "uniform",
    params: dict | None = None,
    min_index: int = 0,
    max_index: int | None = None,
    min_interval: int = 0,
    max_interval: int = 1,
    consider_other_triggers: bool = True,
    seed: int = 0,
    instance_key: str | None = None,
    summary: str = "random interval",
    on_switch_prompt: str = "",
    summarize: bool = True,
    use_root_description: bool = False,
    use_reasoning_in_child_task_gen: bool = False,
) -> PostExecTrigger:
    """Build the DTD-random trigger — exact port of ``random_interval_decider``.

    Draws interval lengths ``g`` from a seeded RNG (uniform/normal) per interval
    ordinal and fires once ``i - anchor - 1 >= g`` within ``[min_index, max_index)``.
    No LLM calls.
    """
    _params = params or {}

    def fire(messages: list[ChatMessage]) -> bool:
        session = store_as(IntervalTriggerState, instance=instance_key)
        i = _count_executed_actions(messages) - 1
        in_range = i >= min_index and (max_index is None or i < max_index)

        anchor = _resolve_anchor(consider_other_triggers, session.last_fire_index)
        if anchor < 0:
            anchor = min_index - 1

        rng = _decomposition_rng(seed, instance_key, ordinal=session.intervals_drawn)
        if form == "uniform":
            g = rng.randint(min_interval, max_interval)
        else:  # normal
            g = round(rng.gauss(_params["mean"], _params["std"]))
            g = min(max(g, min_interval), max_interval)

        fired = in_range and (i - anchor - 1) >= g
        if fired:
            session.intervals_drawn += 1
            session.last_fire_index = i
        return fired

    return PostExecTrigger(
        summary=summary,
        fire=fire,
        on_switch_prompt=on_switch_prompt,
        summarize=summarize,
        use_root_description=use_root_description,
        use_reasoning_in_child_task_gen=use_reasoning_in_child_task_gen,
    )
