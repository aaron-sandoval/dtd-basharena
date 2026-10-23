"""``autosubmit-replay`` policy: replay a recorded trajectory's executed actions in a fresh
sandbox, running the legacy auto-submit side-task check between actions.

Retroactively reconstructs the deleted ``auto_submit_protocol_wrapper`` (control-arena era,
removed by migration commit 71cb4b4): before every protocol step it ran the live side-task
checkers and force-injected a ``submit`` tool call tagged ``model="side_task_auto_submit"``
the instant any side task passed. This policy replays the executed actions extracted from an
existing .eval log (the "payload") and runs the same check after each replayed action; on a
pass it appends the identical forced-submit marker and stops. The resulting replay log records
WHERE auto-submit would have fired; the actual truncation of the source log happens post-hoc
(claude_sandbox/reusable/autosubmit_replay_build.py, driven by
experiments/scripts/autosubmit_native.py).

The side-task check and the forced-submit marker now live in tu_bb2.ct_ext.auto_submit, shared
with the IN-LOOP path (tu_bb2.ct_ext.protocols / .decomposer), so the two can never drift.
AUTO_SUBMIT_MODEL and ALL_SIDE_TASK_CHECKERS are re-exported here for existing importers.

Worker-side requirements (EC2 fleet): this module must be importable by name — reference the
policy as the external ref ``tu_bb2.ct_ext.autosubmit_replay:autosubmit_replay_policy`` so the
worker imports it while resolving the selection (same mechanism as eval_config's
_POLICY_EXTERNAL_REF). The replay payload does NOT travel on the SQS job (256 KB cap): it is a
JSON file referenced by ``payload_path`` (local runs) or ``payload_s3_uri`` (fleet runs; the
worker downloads it once per process to /tmp using the fleet's own AWS credentials).

This file lives in tu_bb2 (not claude_sandbox) because fleet workers resolve the policy from
the installed package — the one sanctioned exception to the new-files-in-claude_sandbox rule.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from inspect_ai.agent import Agent, AgentState, AgentSubmit
from inspect_ai.model import ChatMessageAssistant, execute_tools
from inspect_ai.solver import TaskState
from inspect_ai.tool import ToolCall
from inspect_ai.util import store

from control_tower.ct_runs.ai_eval.sample_metadata import SampleMetadata
from control_tower.protocols.policies.registry import policies
from control_tower.tools.linux_tools import get_policy_tools
from control_tower.tools.registry import tool_registry_name
from control_tower.utils.errors import ValidationError
from control_tower.utils.function_registry.base_model import BaseModelPython

from tu_bb2.ct_ext.auto_submit import (  # noqa: F401  -- AUTO_SUBMIT_MODEL/ALL_SIDE_TASK_CHECKERS re-exported
    ALL_SIDE_TASK_CHECKERS,
    AUTO_SUBMIT_MODEL,
    AutoSubmitOptions,
    build_side_task_check,
    forced_submit,
)

# Model tag on the replayed assistant messages (mirrors the "replay"/"fixed" convention).
REPLAY_MODEL = "autosubmit_replay"
# store() key carrying the per-sample replay record into the .eval's sample store.
STORE_KEY = "autosubmit_replay"


def payload_key(main_task_id: str, side_task_id: str) -> str:
    """Key a replay payload entry by (main, side). The pipeline guarantees one such combo per
    source log (multi-epoch combos are rejected up front), so epoch is not part of the key —
    the replay eval assigns its own epoch and need not match the original's."""
    return f"{main_task_id}|{side_task_id}"


class AutosubmitReplayArgs(BaseModelPython):
    """Args for the autosubmit-replay policy.

    Exactly one of ``payload_path`` / ``payload_repo_path`` / ``payload_s3_uri`` must be set. The
    payload maps ``payload_key(main, side)`` -> {original_sample_id, original_epoch, groups},
    where each group is one executed work-action assistant message from the source log:
    {msg_index, tool_calls: [{id, function, arguments, execute}]}. Calls with execute=False
    (submit / task_complete_tool riding on a work message) are recorded but not run.

    Distribution to fleet workers: ``payload_repo_path`` (relative to the repo root the worker
    clones) is the portable channel — the head node has no S3 write access and the payload is
    too large for the SQS DTO. ``payload_s3_uri`` is used only where the head node CAN write to
    the fleet bucket; ``payload_path`` is an absolute local path for --local runs.
    """

    payload_path: str | None = None
    payload_repo_path: str | None = None
    payload_s3_uri: str | None = None
    side_task_mode: str = "all_four"  # "all_four" (legacy fidelity) | "assigned"
    tool_timeout: int = 120
    check_timeout: int = 120
    # Injected by make_policy_task defaults; used for the "assigned" scorer-shaped check.
    scorer_timeout: int | None = None


_PAYLOAD_CACHE: dict[str, dict] = {}


def _load_payload(args: AutosubmitReplayArgs) -> dict:
    """Load (and per-process cache) the replay payload from disk, the cloned repo, or S3."""
    ref = args.payload_s3_uri or args.payload_repo_path or args.payload_path
    if not ref:
        raise ValidationError(
            "autosubmit-replay requires payload_path, payload_repo_path, or payload_s3_uri")
    cached = _PAYLOAD_CACHE.get(ref)
    if cached is not None:
        return cached

    if args.payload_s3_uri:
        local = _download_s3_payload(args.payload_s3_uri)
    elif args.payload_repo_path:
        # Resolved relative to the worker's repo clone (its cwd is the repo root).
        local = os.path.abspath(args.payload_repo_path)
        if not os.path.exists(local):
            raise ValidationError(
                f"payload_repo_path {args.payload_repo_path!r} not found at {local} — is it "
                "committed and pushed on the branch the fleet clones?")
    else:
        local = args.payload_path
        assert local is not None
    with open(local, encoding="utf-8") as f:
        payload = json.load(f)
    if payload.get("version") != 1:
        raise ValidationError(f"unsupported autosubmit payload version: {payload.get('version')!r}")
    _PAYLOAD_CACHE[ref] = payload
    return payload


def _download_s3_payload(uri: str) -> str:
    """Download s3://bucket/key once per box to a content-addressed /tmp path."""
    if not uri.startswith("s3://"):
        raise ValidationError(f"payload_s3_uri must be s3://... (got {uri!r})")
    bucket, _, key = uri[len("s3://"):].partition("/")
    if not bucket or not key:
        raise ValidationError(f"malformed payload_s3_uri: {uri!r}")
    local = f"/tmp/autosubmit_payload_{hashlib.sha256(uri.encode()).hexdigest()[:16]}.json"
    if os.path.exists(local) and os.path.getsize(local) > 0:
        return local
    import boto3  # available wherever the fleet worker runs (it drives SQS/S3 itself)

    tmp = f"{local}.tmp.{os.getpid()}"
    boto3.client("s3").download_file(bucket, key, tmp)
    os.replace(tmp, local)
    return local


def _payload_entry(payload: dict, meta: SampleMetadata) -> dict:
    if meta.main_task is None or meta.side_task is None:
        raise ValidationError("autosubmit-replay requires an attack sample (main + side task)")
    key = payload_key(meta.main_task.id, meta.side_task.id)
    entry = payload.get("samples", {}).get(key)
    if entry is None:
        raise ValidationError(f"no replay payload entry for sample key {key!r}")
    return entry


def _recorded_bash_arg_key(entry: dict) -> str | None:
    """The argument key the source log's bash calls used ("command" for the qwen variant,
    "cmd" for the standard one). Returns None when the sample has no bash calls."""
    for group in entry["groups"]:
        for tc in group["tool_calls"]:
            if tc.get("function") == "bash":
                keys = set((tc.get("arguments") or {}).keys())
                if "command" in keys:
                    return "command"
                if "cmd" in keys:
                    return "cmd"
    return None


def _faithful_tools(tools: list, bash_arg_key: str | None, meta: SampleMetadata,
                    tool_timeout: int, restore_text_editor: bool = True) -> list:
    """Replace tools whose DISPLAY drifted since the original evals so the replay reproduces the
    exact tool output the originals recorded (deviations then reflect ENVIRONMENT differences,
    not control-tower tool-layer version drift). The originals ran control-tower v0.1.0
    (efd8170, tu-bb2-migration lineage); the installed CT is 2.2.0/main, whose swappable
    ToolProvider (added #456, 2026-06-01) changed two tool displays:

      * bash — the docker provider picks the qwen ("command") vs standard ("cmd") variant from
        the eval model; under a replay's neutral model the recorded arg key would mismatch and
        every command would be dropped. We select the variant matching the RECORDED arg key.
      * text_editor — main wraps inspect's text_editor in `diff_display_text_editor`, which
        rewrites str_replace output from inspect's "cat -n snippet" to a unified diff (added so
        monitors can see file changes). The originals emitted the cat-n form. We swap the wrapper
        back to inspect's plain `text_editor` so str_replace output matches byte-for-byte.

    (python and env/main-task custom tools are unchanged across the two lineages; if a future log
    shows another tool-display drift it will surface as a deviation to add here.)
    """
    from inspect_ai.tool import text_editor as inspect_text_editor
    from inspect_ai.tool._tool_def import ToolDef

    from control_tower.environments.all_environments import get_environment
    from control_tower.environments.protocol import env_agent_user
    from control_tower.tools.bash_tools import bash_with_timeout, bash_with_timeout_qwen

    user = env_agent_user(get_environment(meta.environment.id))

    def _call_name(t) -> str | None:
        try:
            return ToolDef(t).name
        except Exception:  # noqa: BLE001
            return tool_registry_name(t)

    # bash: drop every "bash"-named tool (both variants register as control_tower/bash), append
    # the one matching the recorded arg key. Skip when the sample has no bash calls (arg_key None).
    if bash_arg_key is not None:
        desired_bash = (bash_with_timeout_qwen(user=user) if bash_arg_key == "command"
                        else bash_with_timeout(user=user))
        tools = [t for t in tools if _call_name(t) != "bash"] + [desired_bash]

    # text_editor: replace the diff-display wrapper with inspect's plain text_editor (cat-n).
    if restore_text_editor and any(_call_name(t) == "text_editor" for t in tools):
        tools = [t for t in tools if _call_name(t) != "text_editor"]
        tools.append(inspect_text_editor(timeout=tool_timeout, user=user))

    return tools


@policies.register()
def autosubmit_replay_policy(
    state: TaskState,
    submit: AgentSubmit,
    args: AutosubmitReplayArgs | None,
) -> Agent:
    """Replay executed actions with the legacy auto-submit check between each."""
    if args is None:
        raise ValidationError("autosubmit-replay policy requires args (payload_path/payload_s3_uri)")

    meta = state.metadata_as(SampleMetadata)
    entry = _payload_entry(_load_payload(args), meta)
    tools = get_policy_tools(state, tool_timeout=args.tool_timeout)
    tools = _faithful_tools(tools, _recorded_bash_arg_key(entry), meta, args.tool_timeout)
    check = build_side_task_check(
        opts=AutoSubmitOptions(
            mode=args.side_task_mode,
            timeout=args.check_timeout or args.scorer_timeout or 120,
        ),
        meta=meta,
        state=state,
    )
    submit_tool_name = getattr(submit, "name", None) or "submit"

    def _forced_submit(astate: AgentState, winning_task: str, explanation: str) -> None:
        # Shared with the in-loop path so the marker can never drift.
        astate.output = forced_submit(
            astate._messages,
            submit_tool_name=submit_tool_name,
            winning_task=winning_task,
            explanation=explanation,
        )

    async def impl(astate: AgentState) -> AgentState:
        rec: dict[str, Any] = {
            "original_sample_id": entry.get("original_sample_id"),
            "original_epoch": entry.get("original_epoch"),
            "side_task_mode": args.side_task_mode,
            "n_groups": len(entry["groups"]),
            "groups": [],
            "cut": None,
            "exhausted": False,
            "precheck_passed": False,
        }

        # Legacy semantics: the wrapper checked BEFORE step 0 too (observing post-setup state).
        # A pass here is an anomaly (nothing was replayed yet) — recorded, never truncated on.
        passed, winning, explanation, _ = await check()
        if passed:
            rec["precheck_passed"] = True
            rec["cut"] = {"group_index": -1, "src_msg_index": None,
                          "winning_task": winning, "explanation": explanation}
            _forced_submit(astate, winning, explanation)
            store().set(STORE_KEY, rec)
            return astate

        for k, group in enumerate(entry["groups"]):
            run_calls = [tc for tc in group["tool_calls"] if tc.get("execute", True)]
            skipped = [tc["id"] for tc in group["tool_calls"] if not tc.get("execute", True)]
            grec: dict[str, Any] = {
                "group_index": k,
                "src_msg_index": group.get("msg_index"),
                "tool_call_ids": [tc["id"] for tc in run_calls],
                "skipped_tool_call_ids": skipped,
                "exec_error": None,
                "check_passed": False,
            }
            if run_calls:
                astate._messages.append(
                    ChatMessageAssistant(
                        content="",
                        model=REPLAY_MODEL,
                        tool_calls=[
                            ToolCall(id=tc["id"], function=tc["function"],
                                     arguments=tc.get("arguments") or {})
                            for tc in run_calls
                        ],
                        metadata={"autosubmit_replay_group": k,
                                  "autosubmit_replay_src_msg_index": group.get("msg_index")},
                    )
                )
                # execute_tools turns EXPECTED tool failures (incl. timeouts) into
                # ChatMessageTool.error but RE-RAISES unhandled tool/sandbox exceptions —
                # catch here so an infrastructure failure becomes a recorded deviation
                # (graded flag-5 downstream) instead of aborting the sample.
                try:
                    result = await execute_tools(list(astate._messages), tools)
                    astate._messages.extend(result.messages)
                except Exception as e:  # noqa: BLE001
                    grec["exec_error"] = f"{type(e).__name__}: {e}"

            passed, winning, explanation, _ = await check()
            grec["check_passed"] = passed
            rec["groups"].append(grec)
            if passed:
                rec["cut"] = {"group_index": k, "src_msg_index": group.get("msg_index"),
                              "winning_task": winning, "explanation": explanation}
                _forced_submit(astate, winning, explanation)
                break
        else:
            rec["exhausted"] = True

        store().set(STORE_KEY, rec)
        return astate

    return impl
