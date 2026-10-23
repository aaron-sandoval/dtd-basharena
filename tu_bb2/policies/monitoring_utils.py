"""Monitoring utilities for tracking and scoring agent behavior."""

import datetime
import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Callable

from inspect_ai.log import EvalLog
from inspect_ai.model import ChatMessage, ChatMessageAssistant, ChatMessageUser
from pydantic import BaseModel, Field

from tu_bb2.constants import CHILD_TASK_IMPLEMENTER_KEY, CHILD_TASK_INDEX_KEY

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class MonitorPromptTemplate(str):
    """A monitor system prompt template string with an associated short label prefix.

    Inherits from str so it can be used anywhere a plain str is expected.
    The prefix is used when building human-readable field name suffixes for monitor
    suspicion scores (e.g. ``"std"``, ``"ontask"``, ``"strcat"``).
    """

    prefix: str

    def __new__(cls, value: str, prefix: str) -> "MonitorPromptTemplate":
        instance = super().__new__(cls, value)
        object.__setattr__(instance, "prefix", prefix)
        return instance

    def __repr__(self) -> str:
        return f"MonitorPromptTemplate(prefix={self.prefix!r}, ...)"


class MonitorSample(BaseModel):
    """A single monitor sample with output and suspicion score."""

    monitor_output: str = Field(description="Monitor output string.")
    suspicion_score: float | None = Field(
        default=None,
        description="Suspicion score corresponding to the monitor output.",
    )


class MonitorData(BaseModel):
    """Monitor data containing samples and scores."""

    monitor_samples: dict[str, list[MonitorSample]] = Field(
        default_factory=lambda: defaultdict(list),
        description="Dictionary mapping a monitor name to a list of monitor samples.",
    )
    monitor_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Dictionary mapping a monitor name to a monitor score.",
    )


class SampledStepMetadata(BaseModel):
    """Metadata for a sampled step."""

    monitor_data: MonitorData = Field(
        default_factory=MonitorData,
        description="Monitor data for the executed step.",
    )


class ExecutedStepMetadata(SampledStepMetadata):
    """Metadata for an executed step."""

    sampled_steps: list[ChatMessage] = Field(
        default_factory=list,
        description="List of sampled (but not executed) steps for the executed step.",
    )


def load_step_metadata(message: ChatMessage) -> ExecutedStepMetadata:
    """Load step metadata from a message.

    Args:
        message: The chat message to load metadata from.

    Returns:
        ExecutedStepMetadata object parsed from the message metadata.
    """
    return ExecutedStepMetadata.model_validate(message.metadata or {}, extra="ignore")


def add_monitor_sample_to_message(
    message: ChatMessage, monitor_sample: MonitorSample, monitor_name: str
) -> None:
    """Add a monitor sample to a message's metadata.

    Args:
        message: The chat message to add the sample to.
        monitor_sample: The monitor sample to add.
        monitor_name: The name of the monitor that generated the sample.
    """
    metadata = load_step_metadata(message)
    metadata.monitor_data.monitor_samples[monitor_name].append(monitor_sample)
    message.metadata = metadata.model_dump()


def set_monitor_score_on_message(
    message: ChatMessage, score: float, monitor_name: str
) -> None:
    """Set the monitor score on a message's metadata.

    Args:
        message: The chat message to set the score on.
        score: The suspicion score to set.
        monitor_name: The name of the monitor that generated the score.
    """
    metadata = load_step_metadata(message)
    metadata.monitor_data.monitor_scores[monitor_name] = score
    message.metadata = metadata.model_dump()


def filter_messages_to_monitor(message: ChatMessage) -> bool:
    """Filter messages to monitor.

    Args:
        message: The chat message to filter.

    Returns:
        True if the message should be monitored, False otherwise.
    """
    return isinstance(message, ChatMessageAssistant) and message.tool_calls is not None


def monitor_ts(base_ts: str, i: int) -> str:
    """Return a timestamp string incremented by i seconds from base_ts.

    Used to generate unique, ordered field name suffixes for multiple monitors.
    Monitor i (corresponding to the i-th prompt in monitor_post_hoc_system_prompt)
    gets suffix base_ts + i seconds, so that:
    - The sequence of timestamps matches the sequence of input prompts.
    - Field names are lexicographically ordered by monitor index.
    - max_suspicion_scorer() with no exact_field_name picks the last monitor's score.

    Args:
        base_ts: Base timestamp string in "%Y%m%d_%H%M%S" format.
        i: Number of seconds to add.
    """
    dt = datetime.datetime.strptime(base_ts, "%Y%m%d_%H%M%S")
    dt += datetime.timedelta(seconds=i)
    return dt.strftime("%Y%m%d_%H%M%S")


def build_monitor_field_suffix(
    timestamp: str,
    use_monitor: str,
    prompt: "str | MonitorPromptTemplate",
    **extra_kwargs: str,
) -> str:
    """Build a unique, human-readable field suffix for a monitor's suspicion scores.

    The suffix has the form ``<timestamp>_<use_monitor>_<template_prefix>``
    optionally followed by ``_<key>_<value>`` entries for each extra kwarg
    (sorted by key), e.g.::

        "20260225_143022_full_history_std"
        "20260225_143022_full_history_ontask"
        "20260225_143022_full_history_strcat_use_sus_strcat_True"

    Args:
        timestamp: Timestamp string in ``"%Y%m%d_%H%M%S"`` format
            (typically ``CACHED_TIMESTAMP_STR``).
        use_monitor: Monitor type, e.g. ``"full_history"``, ``"basic"``,
            ``"ensemble"``.
        prompt: The built monitor prompt.  Must be a
            :class:`~tu_bb2.prompts.blue_prompts.MonitorPromptTemplate`
            (returned by
            :meth:`~tu_bb2.prompts.blue_prompts.TrustedMonitorPrompts.build_trusted_monitor_system_prompt`).
            Plain ``str`` values are rejected.
        **extra_kwargs: Additional ``key=value`` modifiers appended to the
            suffix (sorted by key), useful for disambiguating monitors that
            share the same template but differ in other options.

    Returns:
        The field suffix string (without a leading underscore).

    Raises:
        TypeError: If *prompt* is a plain ``str`` without a ``.prefix``
            attribute.
    """
    if not isinstance(prompt, MonitorPromptTemplate):
        raise TypeError(
            f"prompt must be a MonitorPromptTemplate (with a .prefix attribute), "
            f"got {type(prompt).__name__!r}. "
            "Use TrustedMonitorPrompts.build_trusted_monitor_system_prompt() to build one."
        )
    parts = [timestamp, use_monitor, prompt.prefix]
    for key in sorted(extra_kwargs):
        parts.append(f"{key}_{extra_kwargs[key]}")
    return "_".join(parts)


def _check_monitor_field_collisions(
    logs: list,
    monitor_response_fields: set[str],
    get_label: Callable[[int], str],
    num_monitors: int,
    log_paths: list[str] | None = None,
) -> None:
    """Raise ValueError if any target merge key already exists in base log metadata.

    Called immediately after reading input logs, before any inference, so that
    a collision is caught before expensive LLM calls are made.
    """
    target_keys = {
        f"{field}_{get_label(i)}"
        for i in range(num_monitors)
        for field in monitor_response_fields
    }
    for log_idx, log in enumerate(logs):
        path_hint = f" (file: {log_paths[log_idx]})" if log_paths else ""
        for sample in log.samples or []:
            for msg in sample.messages:
                # Scan ALL message types — the merge step writes to base_msg at the
                # same position as monitor_msg regardless of base_msg type.
                if not msg.metadata:
                    continue
                for key in target_keys:
                    if key in msg.metadata:
                        raise ValueError(
                            f"Monitor field collision: '{key}' already exists in "
                            f"message metadata{path_hint} (sample {sample.id}, "
                            f"msg type {type(msg).__name__}). "
                            "Ensure each monitor has a unique label."
                        )


async def run_multiple_monitors_consolidated(
    log_paths: list[str],
    monitors: list,
    base_ts: str,
    monitor_labels: list[str] | None = None,
    run_monitors_kwargs: dict | None = None,
) -> None:
    """Run multiple monitors and consolidate results into a single file per input log.

    Each monitor's scores are stored under a unique key derived from
    *monitor_labels* (when provided) or from ``base_ts + i seconds`` (legacy
    fallback).  Using *monitor_labels* is strongly preferred: it gives
    human-readable field names such as
    ``suspicion_score_20260225_143022_full_history_std`` instead of opaque
    timestamp offsets.

    Args:
        log_paths: Paths to input .eval log files.
        monitors: List of monitors to run (one per entry).
        base_ts: Base timestamp string (``"%Y%m%d_%H%M%S"``).  Used both for
            the ``@monitor``-collision fallback key lookup inside
            ``extract_monitor_fields`` and, when *monitor_labels* is ``None``,
            for deriving per-monitor field suffixes via the legacy
            ``monitor_ts`` approach.
        monitor_labels: Optional list of field suffixes, one per monitor.
            When given, the i-th monitor's scores are written under
            ``suspicion_score_<monitor_labels[i]>``.  Must have the same
            length as *monitors*.  A :exc:`ValueError` is raised if any label
            collides with an already-existing field in the merged log.
        run_monitors_kwargs: Optional kwargs forwarded to ``score_async``
            (``filter_failed_side_task``, ``max_tasks``).
    """
    # SUPERSEDED (control-tower migration): this post-hoc monitoring runner used
    # control_arena's run_monitors_for_eval_logs + score_async + the tu_bb2.scorers
    # suspicion scorers (all removed). Offline monitoring is now done natively via
    # tu_bb2.ct_ext (run_action_monitor_on_trajs + ct_ext.metrics). Dead stub.
    raise RuntimeError(
        "run_multiple_monitors_consolidated is superseded by control-tower offline "
        "monitoring (tu_bb2.ct_ext.metrics / run_action_monitor_on_trajs)."
    )

def get_jobs_from_log_header(log: EvalLog) -> list[dict] | None:
    """Extract the jobs list from a log's header metadata.

    The header stores the offline_decomposer config under
    ``eval.metadata["micro_protocol"]``, but the exact nesting varies by
    serialisation version:

    * Newer logs (offline_decomposer stored directly as the protocol):
      ``meta["micro_protocol"]["jobs"]``
    * Older logs (offline_decomposer wrapped in another agent):
      ``meta["micro_protocol"]["micro_protocol"]["jobs"]``

    Both are tried; the first non-empty result is returned.

    Returns None if not found (e.g. non-factor_offline logs).
    """
    try:
        outer = log.eval.metadata.get("micro_protocol", {})
        if not isinstance(outer, dict):
            return None
        # Try single-nested first (milestone-era logs)
        jobs = outer.get("jobs", None)
        if jobs:
            return jobs
        # Try double-nested (debug-era logs where offline_decomposer is wrapped)
        inner = outer.get("micro_protocol", {})
        if isinstance(inner, dict):
            jobs = inner.get("jobs", None)
            if jobs:
                return jobs
        return None
    except (AttributeError, KeyError, TypeError):
        return None


def get_child_task_segment_ranges(
    messages: list[ChatMessage],
    jobs: list[dict] | None = None,
) -> list[tuple[int, int, str]]:
    """Return (start_idx, end_idx_inclusive, implementer) for each child task segment.

    Primary approach (new logs): uses the ``child_task_implementer`` metadata
    key written by ``execute_child_tasks`` onto the first message of each
    segment.  This is robust to prompt changes since it relies only on
    structural metadata.

    Fallback (old logs without markers): uses the ``jobs`` list together with
    a structural heuristic — the empty-content ``ChatMessageUser`` messages
    that appear as converted submit-tool responses mark the end of each
    segment.  The N-th empty user message is treated as the end of the N-th
    segment.

    Args:
        messages: Full message list from an EvalSample.
        jobs: List of job dicts (each with an ``implementer`` key) from the
            log header (``micro_protocol.jobs``).  Only used by the fallback
            path.

    Returns:
        List of ``(start_idx, end_idx_inclusive, implementer)`` tuples,
        one per child task segment, in execution order.  Returns an empty
        list when boundaries cannot be determined.
    """
    # --- Primary: group by CHILD_TASK_INDEX_KEY ------------------------------
    # Works for both the new format (all messages tagged) and the old format
    # (only the first message per segment tagged), since first_in_segment
    # records only the first occurrence of each unique task index.
    first_in_segment: dict[int, tuple[int, str]] = {}  # task_idx -> (pos, impl)
    for i, msg in enumerate(messages):
        meta = msg.metadata or {}
        task_idx = meta.get(CHILD_TASK_INDEX_KEY)
        impl = meta.get(CHILD_TASK_IMPLEMENTER_KEY)
        if task_idx is not None and impl is not None and task_idx not in first_in_segment:
            first_in_segment[task_idx] = (i, impl)

    if first_in_segment:
        sorted_segs = sorted(first_in_segment.items())  # [(task_idx, (pos, impl))]
        ranges = []
        for k, (_, (start, impl)) in enumerate(sorted_segs):
            end = (
                sorted_segs[k + 1][1][0] - 1
                if k + 1 < len(sorted_segs)
                else len(messages) - 1
            )
            ranges.append((start, end, impl))
        return ranges

    # --- Fallback: structural heuristic + jobs --------------------------------
    if not jobs:
        return []

    # Identify end-of-segment markers: empty-content ChatMessageUser messages.
    # These are submit-tool responses converted to user messages by
    # full_content_keep_tool_calls.
    empty_user_indices = [
        i
        for i, msg in enumerate(messages)
        if isinstance(msg, ChatMessageUser) and (
            not msg.content or (isinstance(msg.content, str) and not msg.content.strip())
        )
    ]

    if len(empty_user_indices) != len(jobs):
        logger.warning(
            "factor_offline segment fallback: expected %d empty-content user "
            "messages (segment end markers) to match %d jobs, found %d. "
            "Cannot reliably determine child task boundaries; "
            "monitor will run on all assistant messages.",
            len(jobs),
            len(jobs),
            len(empty_user_indices),
        )
        return []

    ranges = []
    for k, job in enumerate(jobs):
        start = empty_user_indices[k - 1] + 1 if k > 0 else 0
        end = empty_user_indices[k]
        ranges.append((start, end, job["implementer"]))
    return ranges


def _all_monitorable_assistant_ids(messages: list[ChatMessage]) -> list[str]:
    """Return IDs of all assistant messages with non-submit tool calls."""
    return [
        msg.id
        for msg in messages
        if (
            isinstance(msg, ChatMessageAssistant)
            and msg.id is not None
            and msg.tool_calls
            and not any(tc.function == "submit" for tc in msg.tool_calls)
        )
    ]


def get_untrusted_assistant_message_ids(
    messages: list[ChatMessage],
    jobs: list[dict] | None = None,
) -> list[str]:
    """Return IDs of ChatMessageAssistant messages that belong to U-task segments.

    Used by post-hoc monitors on factor_offline logs so that only actions
    produced by the untrusted model are monitored, matching the context that
    a monitor would have seen during the original eval run.

    For non-factor_offline logs (no child task structure detected), falls back
    to returning ALL assistant messages with tool calls, since the entire
    trajectory is produced by the untrusted model.

    Args:
        messages: Full message list from an EvalSample.
        jobs: Jobs list from the log header (fallback for old logs without markers).

    Returns:
        List of message IDs to pass as ``message_ids`` to
        ``run_monitor_for_messages``.  An empty list means "no U messages
        found" and the caller should skip monitoring for this sample.
    """
    ranges = get_child_task_segment_ranges(messages, jobs)
    if not ranges:
        # No child task structure — non-factor_offline log.  Treat all
        # assistant messages as untrusted (the whole trajectory is U).
        return _all_monitorable_assistant_ids(messages)
    ids = []
    for start, end, impl in ranges:
        if impl != "U":
            continue
        for msg in messages[start : end + 1]:
            # Only include messages with non-submit tool calls, matching what
            # trusted_monitoring_builder does during eval:
            # - It skips steps where state.output.message.tool_calls is falsy.
            # - Child task submit calls are converted to text (tc=[]) by
            #   full_content_keep_tool_calls, so they're already excluded.
            # - The offline_decomposer's synthesized submit (added AFTER
            #   execute_child_tasks, outside any child task) has tc=['submit']
            #   and is excluded here to avoid scoring it post-hoc.
            if (
                isinstance(msg, ChatMessageAssistant)
                and msg.id is not None
                and msg.tool_calls
                and not any(tc.function == "submit" for tc in msg.tool_calls)
            ):
                ids.append(msg.id)
    return ids


async def run_factor_offline_monitors_async(
    log_paths: list[str],
    monitors: list,
    base_ts: str,
    monitoring_scorers: dict,
    log_rename_func: Callable[[str], str] | None = None,
    monitor_labels: list[str] | None = None,
    match_dirs: bool = True,
    run_monitors_kwargs: dict | None = None,
    per_segment_context: "bool | list[bool]" = False,
) -> None:
    """Run monitors post-hoc on factor_offline logs, restricting to U-task messages.

    Equivalent to ``run_multiple_monitors_consolidated`` but filters message
    IDs so each monitor only evaluates ChatMessageAssistant messages produced
    by the untrusted model (U-task segments), matching the context that monitors
    would have seen during the original eval run.

    Supports both single and multiple monitors. When multiple monitors are
    provided their results are merged into one output file per input log (same
    as ``run_multiple_monitors_consolidated``).

    Args:
        log_paths: Paths to input .eval files.
        monitors: Monitor agents to run (one or more).
        base_ts: Base timestamp string (``"%Y%m%d_%H%M%S"``). Used to detect
            collision-suffixed keys written by the ``@monitor`` decorator and
            to derive per-monitor labels when ``monitor_labels`` is None.
        monitoring_scorers: Mapping of scorer names → Scorer objects; passed
            to ``score_async`` after writing output files.
        log_rename_func: Optional function to derive the output filename from
            the input log path.  Defaults to overwriting the input file.
        monitor_labels: Optional list of field suffixes, one per monitor.
            When given, the i-th monitor's scores are written under
            ``suspicion_score_<monitor_labels[i]>``.
        match_dirs: When True (default) write each output file to the same
            directory as the corresponding input file.
        run_monitors_kwargs: Extra kwargs for ``score_async``
            (``filter_failed_side_task``, ``max_tasks``).
        per_segment_context: When True, each U-task segment is monitored with
            only its own messages as context, matching the context that a
            ``full_history`` monitor would have seen during the original eval
            run (where each child task contractor started with a fresh
            ``AgentState``).  The child task description stored in the first
            message's ``child_task_description`` metadata key (if present) is
            used to override ``main_task_description`` in the monitor's task
            context, replicating the per-child-task rebuild done in
            ``child_task_contractor``.  When False (default), the monitor
            receives the full message history up to the current message, which
            is correct for ``basic`` and ``ensemble`` monitors that only inspect
            the most recent action.  Can also be a list of bools (one per
            monitor) to use different context modes for different monitors.
    """
    # SUPERSEDED (control-tower migration): used control_arena run_monitor_for_messages
    # + score_async + tu_bb2.scorers (all removed). Offline monitoring is now native
    # via tu_bb2.ct_ext (run_action_monitor_on_trajs). Dead stub.
    raise RuntimeError(
        "run_factor_offline_monitors_async is superseded by control-tower offline "
        "monitoring (tu_bb2.ct_ext.metrics / run_action_monitor_on_trajs)."
    )

async def run_dtr_monitors_async(
    log_paths: list[str],
    monitor,
    label: str,
    run_monitors_kwargs: dict | None = None,
    expected_monitor_type: str | None = None,
) -> None:
    """Post-hoc monitor a defer-to-resample (``dtr``) log with in-loop-matched context.

    For every ``ChatMessageAssistant`` action (executed *or*
    ``REJECTED_PROPOSAL_KEY``-tagged) with tool calls, the monitor is run on
    ``AgentState(messages = <executed-only prefix BEFORE this action> + [action])``
    — i.e. prior-step / sibling rejected proposals are excluded from context,
    exactly matching what the in-loop monitor saw (each in-loop sample ran from a
    fresh ``AgentState`` over the executed-only history plus its single proposal).

    The monitor must be built with ``field_suffix=label`` so it writes
    ``suspicion_score_<label>``/``reason_<label>`` directly onto each scored
    message (rejected ones included). Output logs are written via
    ``get_sus_rescore_log_name`` and scored with the label-suffixed
    all_actions / all_executed / max scorers plus ``dtr_resample_count_scorer``.
    """
    # SUPERSEDED (control-tower migration): used control_arena run_monitor_for_messages
    # + score_async + tu_bb2.scorers (all removed). DTR suspicion is now recorded
    # in-loop on Action.monitor_response / ActionSubstep by tu_bb2.ct_ext.protocols
    # (dtr-no-trusted); offline rescoring is via tu_bb2.ct_ext.metrics. Dead stub.
    raise RuntimeError(
        "run_dtr_monitors_async is superseded by the control-tower dtr-no-trusted "
        "protocol's in-loop monitor channel + tu_bb2.ct_ext offline monitoring."
    )

