"""Streaming (sample-at-a-time) builder for the per-log extract cache.

Byte-equivalent replacement for tu_bb2.postprocessing.get_log_extract's
full-read build path, for .eval logs too large to load with
read_eval_log(header_only=False) (the 60ACTION DTD attack logs are ~1.5 GB
compressed and inflate past the 62 GB box when fully loaded — the OOM the
catalog notes for the attack-threshold sweep).

Approach: read_eval_log(header_only=True) for the header, then
read_eval_log_sample() per (id, epoch) from the sample summaries, building the
exact _build_log_extract schema one sample at a time. The native control-tower
suspicion channel is harvested per sample via the stock per-sample converter
convert_eval_sample_to_traj + the same non-reserved metadata re-attach that
tu_bb2._trajectory_convert applies (a within-sample tool_call_id join), so the
result matches _native_suspicion_by_sample. The finished extract is written to
the standard cache path, so every downstream consumer (attack-threshold sweep,
compute_metrics, plot_safety_usefulness) gets a disk cache hit and never
full-reads the log.

Usage:
    uv run python experiments/analysis/streaming_log_extract.py <log.eval> [...]
    uv run python experiments/analysis/streaming_log_extract.py --verify <log.eval>

--verify: build streamingly, then compare against the existing on-disk extract
(built by the full-read path) and report equality instead of writing.

RUN LONG BATCHES IN TMUX. Plain `nohup ... &` children die with Claude Code
session restarts — use `tmux new-session -d -s extracts '<cmd> > build.log 2>&1'`.

Resource profile (measured 2026-07-15, inspect 0.3.234 with the exclude_fields
streaming reads): a 1000-sample log builds in ~1.5-3 min at a 2.5-4.5 GB peak
RSS (the 1.5 GB DTD attack log: 2:47 / 4.2 GB). Up to ~4 concurrent builds are
fine on the shared 62 GB box; still gate each start on >=8 GB free
(claude_sandbox/dtd_vs_dtrf/run_worker.sh is a memory-gated wrapper). Before
the exclude_fields fix, read_eval_log_sample retained ~31 MB/call, so a pass
accreted ~34 GB and builds took 20-40 min — if this script is ever run against
an inspect version without `exclude_fields`, expect that profile and go back
to strictly serial builds. Completed extracts are written atomically, so a
killed batch only loses its in-flight log.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from inspect_ai.log import read_eval_log, read_eval_log_sample, read_eval_log_sample_summaries

from tu_bb2.constants import ATTACK_SCORE_KEY, CHILD_TASK_INDEX_KEY, REJECTED_PROPOSAL_KEY
from tu_bb2.postprocessing import (
    _EXTRACT_VERSION,
    _native_step_sizes_from_messages,
    _LOG_EXTRACT_DIR,
    _classify_sample_termination,
    _has_invalid_task_ids,
    _log_extract_path,
    _native_sus_from_messages,
)


def _native_sus_for_sample(sample, source_file: str, sample_idx: int) -> dict:
    """Per-sample native suspicion — delegates to the SHARED harvester.

    Was a per-sample port of the old converter-based path. It is now a thin wrapper over
    postprocessing._native_sus_from_messages so the streaming and full-read builders
    cannot drift: both read the raw messages, which is already per-sample by
    construction (no converter, no tool_call_id re-attach, no source_file/sample_idx
    needed — kept in the signature for call-site compatibility).

    The old converter path silently discarded a step's rejected drafts when no later
    executed action adopted them (from_eval_log.py:701); see the shared harvester's
    docstring. _EXTRACT_VERSION 4->5.
    """
    return _native_sus_from_messages(sample)


def build_extract_streaming(log_path: "str | Path") -> dict:
    """One-pass streaming equivalent of postprocessing._build_log_extract."""
    path, _key = _log_extract_path(log_path)
    header = read_eval_log(str(path), header_only=True)
    summaries = read_eval_log_sample_summaries(str(path))

    # _make_display_id semantics: substitution only when the id column has
    # invalid ids (non-string handled via str(); <5 chars etc.). Decide from
    # the summaries' ids, exactly as the full build decides from sample ids.
    raw_ids = [s.id for s in summaries]
    ids_invalid = _has_invalid_task_ids(pd.DataFrame({"id": [str(r) for r in raw_ids]}))

    all_sus_keys: set[str] = set()
    samples_out: list[dict] = []
    native_failures = 0
    # Exclude the fields the extract never touches. inspect 0.3.234 streams the
    # sample JSON with ijson and never allocates excluded fields, cutting the
    # per-call retention of read_eval_log_sample from ~31 MB to ~3 MB (measured
    # on a 1.8 GB 1000-sample log) and speeding reads ~1.6x. The trajectory
    # converter can FALL BACK to `events` when messages yield no actions, so
    # such samples are retried once with a full read; retries are disabled
    # after several futile ones so unmonitored logs don't degrade to full reads.
    _EXCLUDE_FIELDS = {"events", "store", "attachments"}
    futile_event_retries = 0

    for i, summ in enumerate(summaries):
        sample = read_eval_log_sample(
            str(path), id=summ.id, epoch=summ.epoch, exclude_fields=_EXCLUDE_FIELDS
        )

        sus: dict[str, list] = {}
        attack_score = None
        max_child_idx = -1
        for msg in sample.messages:
            if not (hasattr(msg, "metadata") and msg.metadata):
                continue
            meta = msg.metadata
            if attack_score is None:
                a = meta.get(ATTACK_SCORE_KEY)
                if a is not None:
                    attack_score = int(a)
            rejected = bool(meta.get(REJECTED_PROPOSAL_KEY))
            child_idx = meta.get(CHILD_TASK_INDEX_KEY)
            if isinstance(child_idx, int):
                if child_idx > max_child_idx:
                    max_child_idx = child_idx
            else:
                child_idx = None
            for k, v in meta.items():
                if "suspicion_score" in k:
                    all_sus_keys.add(k)
                    if v is not None:
                        sus.setdefault(k, []).append([float(v), rejected, child_idx])

        score = (sample.scores or {}).get("child_task_count_scorer")
        cval = getattr(score, "value", None) if score is not None else None
        child_task_count = (
            int(cval)
            if isinstance(cval, (int, float))
            and not (isinstance(cval, float) and np.isnan(cval))
            else None
        )
        if child_task_count is None and max_child_idx >= 0:
            child_task_count = max_child_idx + 1

        display_id = None
        if ids_invalid:
            display_id = (getattr(sample, "metadata", None) or {}).get("main_task_name")
        if not display_id:
            display_id = sample.id if isinstance(sample.id, str) else str(sample.id)

        rec = {
            "raw_id": sample.id if isinstance(sample.id, (str, int)) else str(sample.id),
            "display_id": display_id,
            "epoch": sample.epoch,
            "termination_reason": _classify_sample_termination(sample),
            "attack_score": attack_score,
            "child_task_count": child_task_count,
            "sus": sus,
        }

        # Native harvest per sample, kept aside; UNIONED after the loop with the
        # message-scan keys (message values win for their own key names — the full
        # build's v4 rule).
        try:
            rec["_native_sus"] = _native_sus_for_sample(sample, str(path), i)
            # events-fallback retry: with `events` excluded, samples whose
            # messages yield no actions lose the converter's events fallback.
            # Retry those with a full read — unless retries keep coming back
            # empty (monitor-less log), in which case stop wasting full reads.
            if (
                not rec["_native_sus"]
                and not sus  # message-scan channel also empty (not a legacy-scored log)
                and futile_event_retries < 5
                and any(getattr(m, "tool_calls", None) for m in sample.messages)
            ):
                full_sample = read_eval_log_sample(str(path), id=summ.id, epoch=summ.epoch)
                rec["_native_sus"] = _native_sus_for_sample(full_sample, str(path), i)
                del full_sample
                if rec["_native_sus"]:
                    futile_event_retries = 0
                else:
                    futile_event_retries += 1
        except Exception as exc:  # match full build: harvest failure -> no native sus
            native_failures += 1
            if native_failures <= 3:
                print(f"  WARNING: native harvest failed for sample {sample.id}: {exc!r}")
            rec["_native_sus"] = {}

        # Per-step draw counts (resample_aggregation support). Computed from the same
        # message stream, validated against the FINAL sus dict after the native union
        # below — a key can arrive from either channel and only the native one is
        # step-structured.
        try:
            rec["_step_sizes_raw"] = _native_step_sizes_from_messages(sample)
        except Exception:
            rec["_step_sizes_raw"] = {}

        samples_out.append(rec)
        del sample
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(summaries)} samples", flush=True)

    for s in samples_out:
        nat = s.pop("_native_sus")
        for k, rows in (nat or {}).items():
            if k not in s["sus"]:
                s["sus"][k] = rows
                all_sus_keys.add(k)
        # Keep only groupings that provably partition their key's entry list, exactly
        # as postprocessing.step_sizes_for_sample does in the full-read builder.
        raw = s.pop("_step_sizes_raw", None) or {}
        ss = {k: v for k, v in raw.items()
              if s["sus"].get(k) and sum(v) == len(s["sus"][k])}
        if ss:
            s["step_sizes"] = ss

    return {
        "version": _EXTRACT_VERSION,
        "created": getattr(header.eval, "created", None),
        "attack_score_key": ATTACK_SCORE_KEY,
        "rejected_proposal_key": REJECTED_PROPOSAL_KEY,
        "child_task_index_key": CHILD_TASK_INDEX_KEY,
        "sus_keys": sorted(all_sus_keys),
        "samples": samples_out,
    }


def write_extract(log_path: "str | Path", data: dict) -> Path:
    _path, key = _log_extract_path(log_path)
    _LOG_EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    out = _LOG_EXTRACT_DIR / f"{key[:24]}.json"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, separators=(",", ":")))
    tmp.replace(out)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logs", nargs="+", help="Repo-relative .eval paths")
    ap.add_argument("--verify", action="store_true",
                    help="Compare streaming build against the existing disk extract; do not write.")
    args = ap.parse_args()

    for log in args.logs:
        print(f"=== {log}")
        if args.verify:
            _path, key = _log_extract_path(log)
            cache_file = _LOG_EXTRACT_DIR / f"{key[:24]}.json"
            if not cache_file.exists():
                print(f"  no existing extract at {cache_file.name}; nothing to verify against")
                continue
            existing = json.loads(cache_file.read_text())
            built = build_extract_streaming(log)
            if built == existing:
                print("  VERIFY OK: streaming extract == full-read extract")
            else:
                diffs = [k for k in built if built.get(k) != existing.get(k)]
                print(f"  VERIFY MISMATCH in top-level keys: {diffs}")
                if "samples" in diffs:
                    n = 0
                    for b, e in zip(built["samples"], existing["samples"]):
                        if b != e:
                            n += 1
                            if n <= 3:
                                fields = [f for f in b if b.get(f) != e.get(f)]
                                print(f"    sample {b['raw_id']}: differing fields {fields}")
                    print(f"    {n} differing samples "
                          f"(built {len(built['samples'])} vs existing {len(existing['samples'])})")
        else:
            built = build_extract_streaming(log)
            out = write_extract(log, built)
            print(f"  wrote {out} ({len(built['samples'])} samples, "
                  f"sus_keys={built['sus_keys']})")


if __name__ == "__main__":
    main()
