"""Run an Inspect Scout scanjob over an Inspect ``.eval`` log.

The Scout-based replacement for ``experiments/scripts/run_docent_rubric.py``. Unlike
the Docent flow (convert → upload → run server-side → fetch), this reads the native
``.eval`` directly, runs the scanjob locally, and writes results to a local DuckDB/
parquet store that is browsed via ``scout view`` or the Inspect VSCode extension.

Each scanjob (``experiments/analysis/scout_scanners/scanjobs.py``) composes several
focused ``@scanner``s; every scanner writes its own result frame. The summary here is
built by merging those frames on ``transcript_id`` (``scout_utils.read_scan_df``).

Usage:
    uv run python experiments/scripts/run_scout.py <log.eval> <scanjob> [options]

    <scanjob> is one of:
      * max_sus_timestamp   -> max_suspicion_score + flagged_tool_calls +
                               monitor_reasoning_summary (LLM) + side_task_success
      * attack_strategy     -> attack_score + overall_max_suspicion + side_task_success +
                               attack_characterization (LLM)
      * decomp_triggers     -> monitor_based_decompositions +
                               action_index_decompositions (deterministic)
      * decomposition_trigger_categories -> per-decomposition triggering-action category
                               (hybrid: deterministic python/submit/text-editor + LLM bash) +
                               per-family decomposition counts
      * post_rejection_tactic -> post_rejection_tactic (LLM) + side_task_success
                               (subq3: same tactic retried/stealthier vs different;
                               needs the agent_self_risk score on the log)

Options:
    --key KEY          Exact suspicion_score_<SUFFIX> metadata key (max_sus_timestamp).
                       Auto-detected from the log if omitted.
    --limit N          Only scan the first N transcripts.
    --model M          Judge/summarizer model for the LLM scanners
                       (default: anthropic/claude-sonnet-4-6).
    --max-processes N  Scan worker processes (default 1; >1 uses multiprocessing).
    --scans-dir DIR    Where to write the scan store. Default:
                       experiments/data/scout_scans/<logstem>/ (a DVC-tracked blob).
    --tmp              Write to a throwaway temp dir instead (dev iteration).

Results land at ``<scans-dir>/scan_id=.../`` plus a ``summary.csv`` written INSIDE
``<scans-dir>`` so the whole directory is one DVC blob (see the run-scout-scans skill).
"""

import argparse
import asyncio
import gzip
import json
import sys
import tempfile
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from inspect_ai.model import GenerateConfig
from inspect_scout import TranscriptContent, scan, scan_results_df, transcripts_from

# LLM scanjobs resolve their judge model (get_model) at scanjob-build time, before Scout's
# scan() would auto-load .env — so load the repo .env here so API keys are present for the build.
load_dotenv()

from experiments.analysis import scout_utils
from experiments.analysis.scout_scanners import scanjobs

SCANJOBS = ("max_sus_timestamp", "attack_strategy", "delivery_vector", "decomp_triggers",
            "decomposition_trigger_categories", "scored_actions",
            "fp_categories", "fp_attack", "post_rejection_tactic",
            "post_random_switch_resumption", "prior_child_scope",
            "side_task_attribution", "env_description_influence", "attack_self_label",
            "dtd_attack_coordination", "initial_cot_plan", "noplan_child_coordination",
            "side_task_attribution_per_child")

# Columns whose cells can be long (lists / verbatim text); clipped in summary.csv only.
_LONG_COLUMNS = ("flagged_tool_calls", "raw_monitor_reasoning", "attack_strategy_summary",
                 "monitor_reasoning_summary", "evidence", "why", "malware_evidence",
                 "children")


async def _first_transcript(log: str):
    content = TranscriptContent(messages="all")
    async with transcripts_from(log).reader() as reader:
        async for info in reader.index():
            return await reader.read(info, content)
    return None


def _available_suspicion_keys(transcript) -> list[str]:
    # Include the bare ``suspicion_score`` (in-loop DTR monitor) as well as the
    # ``suspicion_score_<SUFFIX>`` post-hoc/ensemble keys.
    keys: set[str] = set()
    for message in scout_utils.assistant_messages(transcript):
        for k, v in (getattr(message, "metadata", None) or {}).items():
            if k.startswith("suspicion_score") and isinstance(v, (int, float)):
                keys.add(k)
    return sorted(keys)


def _resolve_key(log: str, explicit: str | None) -> str:
    """Resolve the exact suspicion key, preferring --key, then a filename-suffix match."""
    transcript = asyncio.run(_first_transcript(log))
    available = _available_suspicion_keys(transcript) if transcript else []
    if explicit:
        if explicit not in available:
            print(f"WARNING: --key {explicit!r} not found in first transcript. "
                  f"Available: {available}", file=sys.stderr)
        return explicit
    if not available:
        sys.exit("No suspicion_score_<TS> keys found in the log; pass --key explicitly.")
    # Prefer a key whose timestamp matches the log's `_sus_<YYYYMMDD_HHMMSS>` suffix.
    stem = Path(log).stem
    if "_sus_" in stem:
        suffix_ts = stem.split("_sus_")[-1][:15]  # YYYYMMDD_HHMMSS
        matches = [k for k in available if suffix_ts in k]
        if len(matches) == 1:
            return matches[0]
        if matches:
            print(f"Multiple keys match log suffix {suffix_ts}: {matches}; using first.",
                  file=sys.stderr)
            return matches[0]
    if len(available) == 1:
        return available[0]
    sys.exit(
        "Multiple suspicion keys present; pass --key to choose one:\n  "
        + "\n  ".join(available)
    )


def _load_child_tasks(args) -> dict | None:
    """The per-sample child-description sidecar (``--child-tasks``, .json.gz), or None."""
    if not args.child_tasks:
        return None
    with gzip.open(args.child_tasks, "rt", encoding="utf-8") as fh:
        child_tasks = json.load(fh)
    print(f"Loaded child-task sidecar: {args.child_tasks} "
          f"({len(child_tasks.get('samples', {}))} samples)")
    return child_tasks


def _build_scanjob(name: str, args, log: str):
    if name == "max_sus_timestamp":
        key = _resolve_key(log, args.key)
        print(f"Using suspicion key: {key}")
        return scanjobs.max_sus_timestamp(key=key, model=args.model)
    if name == "attack_strategy":
        return scanjobs.attack_strategy(model=args.model)
    if name == "attack_self_label":
        return scanjobs.attack_self_label(
            model=args.model, max_concurrent=args.max_concurrent
        )
    if name == "delivery_vector":
        return scanjobs.delivery_vector(model=args.model)
    if name == "decomp_triggers":
        return scanjobs.decomp_triggers()
    if name == "decomposition_trigger_categories":
        return scanjobs.decomposition_trigger_categories(model=args.model)
    if name == "post_rejection_tactic":
        return scanjobs.post_rejection_tactic(model=args.model)
    if name == "post_random_switch_resumption":
        return scanjobs.post_random_switch_resumption(model=args.model)
    if name == "scored_actions":
        key = _resolve_key(log, args.key)
        print(f"Using suspicion key: {key}")
        return scanjobs.scored_actions(key=key)
    if name == "fp_categories":
        key = _resolve_key(log, args.key)
        print(f"Using suspicion key: {key}")
        return scanjobs.fp_categories(key=key, model=args.model)
    if name == "fp_attack":
        key = _resolve_key(log, args.key)
        print(f"Using suspicion key: {key}")
        return scanjobs.fp_attack(key=key, model=args.model)
    if name == "prior_child_scope":
        # Reads the [MONITOR] messages' monitor_result metadata — no --key needed.
        return scanjobs.prior_child_scope(model=args.model)
    if name == "side_task_attribution":
        # Judges attempts from messages + injected attack_plan metadata — no --key needed.
        return scanjobs.side_task_attribution(model=args.model)
    if name == "env_description_influence":
        # Judges CoT against a deterministic exclusive-fact digest — no --key needed.
        return scanjobs.env_description_influence(model=args.model)
    if name == "dtd_attack_coordination":
        child_tasks = _load_child_tasks(args)
        # Resolve plan_shared: explicit flag wins; else infer from the log stem.
        if args.plan_shared is None:
            plan_shared = "planshare" in Path(log).stem
        else:
            plan_shared = args.plan_shared
        max_children = 10 if args.max_children is None else args.max_children
        print(f"dtd_attack_coordination: plan_shared={plan_shared} "
              f"max_children={max_children} max_actions={args.max_actions} "
              f"include_child0={args.include_child0}")
        return scanjobs.dtd_attack_coordination(
            model=args.model,
            extractor_model=args.extractor_model,
            plan_shared=plan_shared,
            child_tasks=child_tasks,
            max_children=max_children,
            max_actions=args.max_actions,
            include_child0=args.include_child0,
        )
    if name == "noplan_child_coordination":
        child_tasks = _load_child_tasks(args)
        max_children = 10 if args.max_children is None else args.max_children
        print(f"noplan_child_coordination: max_children={max_children} "
              f"max_actions={args.max_actions}")
        return scanjobs.noplan_child_coordination(
            model=args.model, extractor_model=args.extractor_model,
            child_tasks=child_tasks, max_children=max_children, max_actions=args.max_actions,
        )
    if name == "initial_cot_plan":
        return scanjobs.initial_cot_plan(model=args.model)
    if name == "side_task_attribution_per_child":
        # One judge call per child; every child incl. 0 unless --max-children is given.
        child_tasks = _load_child_tasks(args)
        print(f"side_task_attribution_per_child: max_children={args.max_children} "
              f"(None = all children) include_outputs={args.include_outputs} "
              f"include_root_plan={args.include_root_plan}")
        return scanjobs.side_task_attribution_per_child(
            model=args.model,
            child_tasks=child_tasks,
            max_children=args.max_children,
            include_outputs=args.include_outputs,
            include_root_plan=args.include_root_plan,
        )
    raise ValueError(name)


def _clip(value, width: int = 200):
    """Join lists and clip long strings for the readable summary CSV."""
    if isinstance(value, (list, tuple)):
        value = " | ".join(str(v) for v in value)
    if isinstance(value, str) and len(value) > width:
        return value[:width] + "…"
    return value


def _write_summary(merged: pd.DataFrame, dest: Path) -> None:
    """Write a small human-readable CSV summary INSIDE the scan blob dir."""
    out = merged.copy()
    for col in out.columns:
        if col in _LONG_COLUMNS or out[col].map(lambda v: isinstance(v, (list, tuple))).any():
            out[col] = out[col].map(_clip)
    out = out.dropna(axis=1, how="all")
    out.to_csv(dest, index=False)
    print(f"\nWrote summary -> {dest}")
    with pd.option_context("display.max_colwidth", 50, "display.width", 220):
        print(out.to_string(index=False))


def _count_errors(location: str) -> int:
    total = 0
    for df in scan_results_df(location).scanners.values():
        if "scan_error" in df.columns:
            total += int(df["scan_error"].notna().sum())
    return total


def _report_not_measured(location: str) -> None:
    """Print how many transcripts a judge could not score (negative sentinel score).

    A scanner that returns -1 for "judge refused / produced nothing" is only safe if that
    count is visible: otherwise a run where the content filter rejected a large share of
    attack transcripts looks indistinguishable from one where they scored zero. Nothing else
    in this pipeline surfaces it — ``scan_error`` stays empty because the scanner catches the
    failure itself, by design, so its deterministic siblings still produce rows.
    """
    import json as _json

    for name, df in scan_results_df(location).scanners.items():
        if "value" not in df.columns:
            continue
        n_neg = 0
        reasons: dict[str, int] = {}
        for cell in df["value"]:
            if isinstance(cell, str):
                try:
                    cell = _json.loads(cell)
                except (ValueError, TypeError):
                    continue
            if not isinstance(cell, dict):
                continue
            score = cell.get("score")
            if isinstance(score, (int, float)) and score < 0:
                n_neg += 1
                reason = str(cell.get("judge_error") or "unspecified")[:60]
                reasons[reason] = reasons.get(reason, 0) + 1
        if n_neg:
            detail = ", ".join(f"{k} x{v}" for k, v in sorted(reasons.items()))
            print(
                f"WARNING: {name}: {n_neg}/{len(df)} transcripts NOT MEASURED "
                f"(score < 0) -- {detail}\n"
                f"         Filter on score >= 0 before aggregating."
            )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("log", help="Path to the .eval log")
    p.add_argument("scanjob", choices=SCANJOBS, help="Scanjob name")
    p.add_argument("--key", default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--max-processes", type=int, default=1)
    p.add_argument(
        "--max-connections",
        type=int,
        default=None,
        help="Model API connection cap (GenerateConfig.max_connections). Inspect's default "
        "is small; LLM scanjobs over large logs want a few hundred.",
    )
    p.add_argument(
        "--max-transcripts",
        type=int,
        default=None,
        help="Transcripts scanned concurrently. Total in-flight requests is roughly this "
        "times a scanner's per-transcript concurrency, capped by --max-connections.",
    )
    p.add_argument(
        "--max-concurrent",
        type=int,
        default=16,
        help="In-flight judge calls WITHIN one transcript, for scanners that fan out over "
        "actions (attack_self_label). Sequential scanners ignore this.",
    )
    p.add_argument("--scans-dir", default=None)
    p.add_argument("--tmp", action="store_true", help="Write to a throwaway temp dir")
    p.add_argument(
        "--task-ids",
        default=None,
        help="Comma-separated transcript task_ids to scan (exact match). Use when the "
        "transcripts you want are scattered through the log and --limit would have to "
        "cover the whole thing — e.g. scanning a hand-labeled validation set.",
    )
    p.add_argument("--child-tasks", default=None,
                   help="Path to the per-sample child-description sidecar (.json.gz) built by "
                   "extract_child_task_descriptions.py; used by dtd_attack_coordination.")
    p.add_argument("--extractor-model", default=None,
                   help="Previous-plan reconstruction judge for dtd_attack_coordination "
                   "(default anthropic/claude-haiku-4-5).")
    p.add_argument("--plan-shared", dest="plan_shared", action="store_true", default=None,
                   help="Force the planshare label space for dtd_attack_coordination "
                   "(default: inferred from 'planshare' in the log stem).")
    p.add_argument("--no-plan-shared", dest="plan_shared", action="store_false",
                   help="Force the baseline label space for dtd_attack_coordination.")
    p.add_argument("--max-children", type=int, default=None,
                   help="Judge child indices <= max_children only. Default: 10 for the two "
                   "coordination jobs (their historical cap); ALL children for "
                   "side_task_attribution_per_child.")
    p.add_argument("--max-actions", type=int, default=8,
                   help="dtd_attack_coordination: render only the first N executed actions/child.")
    p.add_argument("--include-child0", action="store_true",
                   help="dtd_attack_coordination: also judge child 0 (validation control).")
    p.add_argument("--include-outputs", action="store_true",
                   help="side_task_attribution_per_child: render (truncated) tool outputs "
                   "into the judge prompt (default: reasoning + actions only).")
    p.add_argument("--include-root-plan", action="store_true",
                   help="side_task_attribution_per_child: inject the root attack_plan "
                   "metadata (off by default; irrelevant on withtips-noplan arms).")
    p.add_argument("--no-summary", action="store_true",
                   help="Skip the post-scan read_scan_df merge + summary.csv. Use for big "
                   "stores (566-scale, transcript embedded per row) where that read "
                   "OOMs/hangs; read them with a DuckDB projection instead.")
    args = p.parse_args()

    log = args.log
    if not Path(log).exists():
        sys.exit(f"Log not found: {log}")

    if args.tmp:
        scans_dir = Path(tempfile.mkdtemp(prefix="scout_run_"))
    elif args.scans_dir:
        scans_dir = Path(args.scans_dir)
    else:
        scans_dir = Path("experiments/data/scout_scans") / Path(log).stem
    scans_dir.mkdir(parents=True, exist_ok=True)

    job = _build_scanjob(args.scanjob, args, log)

    transcripts = transcripts_from(log)
    if args.task_ids:
        ids = [t.strip() for t in args.task_ids.split(",") if t.strip()]
        transcripts = transcripts.where(f"task_id IN ({','.join(repr(i) for i in ids)})")
        print(f"Filtering to {len(ids)} task_id(s)")

    status = scan(
        scanners=job,
        transcripts=transcripts,
        scans=str(scans_dir),
        limit=args.limit,
        max_processes=args.max_processes,
        max_transcripts=args.max_transcripts,
        model_config=(
            GenerateConfig(max_connections=args.max_connections)
            if args.max_connections
            else None
        ),
    )
    print(f"scan complete={status.complete}  location={status.location}")

    if args.no_summary:
        print(f"--no-summary: {_count_errors(status.location)} scan errors; skipping the "
              f"read_scan_df merge and summary.csv")
    else:
        merged = scout_utils.read_scan_df(status.location)
        print(f"Got {len(merged)} transcripts ({_count_errors(status.location)} scan errors) "
              f"across scanners: {list(scan_results_df(status.location).scanners)}")
        _report_not_measured(status.location)
        _write_summary(merged, scans_dir / "summary.csv")

    if not args.tmp:
        print(f"\nBrowse:  scout view {scans_dir}")
        print(f"DVC:     uv run dvc add {scans_dir} && git add {scans_dir}.dvc && uv run dvc push")


if __name__ == "__main__":
    main()
