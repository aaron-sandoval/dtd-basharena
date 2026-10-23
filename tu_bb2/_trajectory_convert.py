"""Stock-control-tower trajectory conversion that re-attaches protocol-authored
per-action metadata onto ``Action.metadata``.

control-tower's ``from_eval_log`` converter lifts only its *reserved* channels off
each executed assistant message (monitor_response, substeps, audit flag) and drops
everything else. tu-bb2's protocols attach research metadata to the executed
assistant message — child-task index (online decomposer), attack decision/score
(selective attack) — which the analysis layer needs on ``Action.metadata``.

Rather than fork the converter (the original approach: a build-time patch in
``from_eval_log.py``), we run the STOCK converter and re-attach the non-reserved
assistant-message metadata onto each executed ``Action`` by a ``tool_call_id``
join. The converter builds each executed Action from an assistant tool-call
message, so ``Action.tool_call_id`` maps back to that message's ``tool_calls[*].id``
— a stable, verified join key. This keeps tu-bb2 on stock control-tower (no fork).

Behavioral parity with the fork patch: both only populate EXECUTED actions
(messages with tool calls); rejected/resampled proposals already carry their own
metadata via substeps, and suspicion via ``monitor_response`` — neither is touched
here. Reserved keys are excluded so dedicated channels are never duplicated.

This is the single conversion entry point for tu-bb2 analysis; import
``convert_eval_logs_to_trajs_with_metadata`` instead of control-tower's converter.
"""

from pathlib import Path

from inspect_ai.log import read_eval_log

from control_tower.trajectories.from_eval_log import convert_eval_logs_to_trajs
from control_tower.trajectories.trajectory import Trajectory
from control_tower.trajectories.eval_trace_metadata import (
    MONITOR_RESULT_KEY,
    SUBSTEP_KIND_KEY,
)

# Assistant-message metadata keys control-tower surfaces through dedicated
# trajectory channels (monitor_response / substeps / audit). Never copy these onto
# the generic Action.metadata carry-over. Mirrors the fork patch's reserved set so
# this wrapper is a drop-in for it on stock control-tower.
_RESERVED_ACTION_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "monitor_result",
        MONITOR_RESULT_KEY,   # "is_monitor_result"
        SUBSTEP_KIND_KEY,     # "substep_kind"
        "sus_score",
        "monitor_name",
        "monitor_error",
        "extraction_error",
        "audited",
    }
)


def _metadata_by_tool_call_id(paths: list[Path]) -> dict[str, dict]:
    """Map every assistant tool-call id -> that message's metadata dict."""
    out: dict[str, dict] = {}
    for p in paths:
        log = read_eval_log(str(p))
        for sample in log.samples or []:
            for msg in sample.messages or []:
                md = getattr(msg, "metadata", None)
                if not md:
                    continue
                for tc in getattr(msg, "tool_calls", None) or []:
                    out[tc.id] = md
    return out


def convert_eval_logs_to_trajs_with_metadata(
    log_paths: "list[str | Path] | str | Path",
) -> list[Trajectory]:
    """Stock ``convert_eval_logs_to_trajs`` + re-attach non-reserved per-action
    assistant-message metadata onto each executed ``Action.metadata``."""
    if isinstance(log_paths, (str, Path)):
        paths = [Path(log_paths)]
    else:
        paths = [Path(p) for p in log_paths]

    trajs = convert_eval_logs_to_trajs(paths)
    meta = _metadata_by_tool_call_id(paths)
    if not meta:
        return trajs
    for t in trajs:
        for a in t.actions:
            src = meta.get(getattr(a, "tool_call_id", None))
            if not src:
                continue
            extra = {k: v for k, v in src.items() if k not in _RESERVED_ACTION_METADATA_KEYS}
            if extra:
                a.metadata = {**(a.metadata or {}), **extra}
    return trajs
