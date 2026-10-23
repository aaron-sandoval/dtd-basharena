"""Drop low-fidelity replay samples from an auto-submit truncated `.eval` log.

The post-hoc auto-submit replay graded every diverging tool output 1-5 (see
``autosubmit_replay_build.DEVIATION_RUBRIC``) and stored the per-sample maximum as
``content_max_flag`` in the replay workdir's ``plan.json``. The shipped ``_autosubmit.eval``
logs truncate everything except flag 5, so "major" (4) divergences were truncated anyway.

This builds the sensitivity variants: a copy of the log with every sample whose
``content_max_flag >= --min-flag`` DELETED outright. Samples with no plan entry (zero
work actions, or replay-missing) were never replayed or truncated and are always KEPT,
so they cancel between a log and its filtered variants.

Memory discipline follows ``autosubmit_replay_build.build_truncated_log``: the source zip is
streamed one sample JSON at a time and kept samples are re-emitted as their ORIGINAL bytes.
These logs are ~1.2 GB compressed / ~10.5 GB of decompressed sample JSON, so a full
``read_eval_log`` (the ``subset_eval_log.py`` pattern) is not viable here.

Unlike the auto-submit build this changes the sample COUNT, so the three sample-count
manifests must all be filtered in step: ``summaries.json``, ``_journal/summaries/1.json``
and ``header.json``'s ``eval.dataset``. ``_journal/start.json`` embeds its own copy of
``eval.dataset`` and is patched too, so the archive never carries two different counts.

Usage:
    uv run python claude_sandbox/reusable/filter_fidelity_samples.py \
        --log experiments/_logs/tower/<stem>_autosubmit.eval \
        --plan claude_sandbox/autosubmit_out/<stem>/plan.json \
        --min-flag 4
"""

from __future__ import annotations

import argparse
import json
import time
import zipfile
from pathlib import Path

# Monkey-patches zstd into stdlib zipfile; must precede any ZipFile use on an .eval.
import inspect_ai._util.zipfile  # noqa: F401
from inspect_ai._util.zipfile import zipfile_compress_kwargs

REPO_ROOT = Path(__file__).resolve().parents[2]

# Manifests that are rewritten rather than copied. Every one of them carries a
# per-sample list whose length must track the new sample count.
_REWRITTEN = ("summaries.json", "reductions.json", "header.json",
              "_journal/start.json", "_journal/summaries/1.json")


def load_flags(plan_path: Path) -> dict[str, int]:
    """Return {f"{sample_id}|{epoch}": content_max_flag} from a replay workdir plan.json.

    plan.json is NOT a flat per-sample map: it is {"plan": {...}, "stats": {...},
    "missing": [...]}. Reading the wrong level silently yields an empty flag map and a
    no-op filter, so the caller asserts the entry count.
    """
    doc = json.loads(plan_path.read_text())
    if not isinstance(doc, dict) or "plan" not in doc:
        raise ValueError(f"{plan_path}: expected a dict with a 'plan' key, got {type(doc).__name__} "
                         f"with keys {sorted(doc)[:6] if isinstance(doc, dict) else '?'}")
    entries = doc["plan"]
    return {k: int(v.get("content_max_flag") or 0) for k, v in entries.items()}


def renamed(stem: str, new_count: int) -> str:
    """Rewrite the `_<N>_` sample-count token (index 1, right after the timestamp)."""
    parts = stem.split("_")
    parts[1] = str(new_count)
    return "_".join(parts)


def filter_log(src: Path, dst: Path, flags: dict[str, int], min_flag: int,
               plan_path: Path) -> dict:
    """Copy `src` to `dst` minus every sample whose content_max_flag >= min_flag."""
    zin = zipfile.ZipFile(str(src))
    names = zin.namelist()
    sample_names = [n for n in names if n.startswith("samples/")]
    other_names = [n for n in names if not n.startswith("samples/") and n not in _REWRITTEN]

    summaries = json.loads(zin.read("summaries.json"))
    header = json.loads(zin.read("header.json"))
    reductions = json.loads(zin.read("reductions.json")) if "reductions.json" in names else None
    jstart = json.loads(zin.read("_journal/start.json")) if "_journal/start.json" in names else None
    jsumm = (json.loads(zin.read("_journal/summaries/1.json"))
             if "_journal/summaries/1.json" in names else None)

    def key_of(sid, epoch) -> str:
        return f"{sid}|{int(epoch or 1)}"

    def dropped(sid, epoch) -> bool:
        # No plan entry => never replayed => never truncated => always kept.
        f = flags.get(key_of(sid, epoch))
        return f is not None and f >= min_flag

    drop_keys = {key_of(s.get("id"), s.get("epoch")) for s in summaries
                 if dropped(s.get("id"), s.get("epoch"))}
    kept_summaries = [s for s in summaries
                      if key_of(s.get("id"), s.get("epoch")) not in drop_keys]
    kept_ids = [s.get("id") for s in kept_summaries]
    n_kept, n_dropped = len(kept_summaries), len(drop_keys)
    if n_dropped == 0:
        raise AssertionError(
            f"filter dropped 0 samples at min_flag={min_flag} — flags map has {len(flags)} "
            f"entries; check that plan.json matches this log")

    dst.parent.mkdir(parents=True, exist_ok=True)
    zo = zipfile.ZipFile(str(dst), "w", allowZip64=True, **zipfile_compress_kwargs)
    for name in other_names:
        zo.writestr(name, zin.read(name))

    # Samples: one entry at a time, kept ones re-emitted as their original bytes.
    n_written = n_skipped = 0
    for name in sample_names:
        raw = zin.read(name)
        d = json.loads(raw)
        if dropped(d.get("id"), d.get("epoch")):
            n_skipped += 1
            continue
        zo.writestr(name, raw)
        n_written += 1
        del raw, d
    assert n_skipped == n_dropped, f"sample/summary drop mismatch: {n_skipped} != {n_dropped}"

    zo.writestr("summaries.json", json.dumps(kept_summaries, ensure_ascii=False,
                                             separators=(",", ":")))

    if jsumm is not None:
        kept_j = [s for s in jsumm if key_of(s.get("id"), s.get("epoch")) not in drop_keys]
        assert len(kept_j) == n_kept, f"journal summaries mismatch: {len(kept_j)} != {n_kept}"
        zo.writestr("_journal/summaries/1.json",
                    json.dumps(kept_j, ensure_ascii=False, separators=(",", ":")))

    if reductions is not None:
        drop_sids = {k.split("|")[0] for k in drop_keys}
        for scorer in reductions:
            if scorer.get("samples"):
                scorer["samples"] = [rs for rs in scorer["samples"]
                                     if rs.get("sample_id") not in drop_sids]
        zo.writestr("reductions.json", json.dumps(reductions, ensure_ascii=False,
                                                  separators=(",", ":")))

    def patch_dataset(obj: dict) -> None:
        ds = (obj.get("eval") or {}).get("dataset")
        if isinstance(ds, dict):
            ds["samples"] = n_kept
            if ds.get("sample_ids") is not None:
                ds["sample_ids"] = kept_ids

    if jstart is not None:
        patch_dataset(jstart)
        zo.writestr("_journal/start.json", json.dumps(jstart, ensure_ascii=False,
                                                      separators=(",", ":")))

    patch_dataset(header)
    header.setdefault("eval", {}).setdefault("metadata", {})
    header["eval"]["metadata"] = (header["eval"]["metadata"] or {}) | {
        "tu_fidelity_filter": {
            "source_log": str(src),
            "plan_json": str(plan_path),
            "min_dropped_flag": min_flag,
            "rule": "drop samples with content_max_flag >= min_dropped_flag; "
                    "samples with no plan entry are always kept",
            "n_source_samples": n_kept + n_dropped,
            "n_dropped": n_dropped,
            "n_kept": n_kept,
            "dropped_ids": sorted(drop_keys),
            "utc_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # Inherited from the source header and NOT recomputed: they pool per-action
            # suspicion over the sample set, which just changed. The audit threshold is the
            # pXX of the per-sample MAX and is computed downstream, never read from here.
            "stale_header_metrics": "tu_sus_p* inherited from the source log; do not read",
        }
    }
    zo.writestr("header.json", json.dumps(header, ensure_ascii=False, separators=(",", ":")))
    zo.close()
    zin.close()

    out_names = zipfile.ZipFile(str(dst)).namelist()
    assert len(out_names) == len(set(out_names)), "duplicate members in output zip"
    return {"kept": n_kept, "dropped": n_dropped, "written": n_written}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", required=True, help="source _autosubmit.eval (repo-relative or abs)")
    ap.add_argument("--plan", required=True, help="replay workdir plan.json")
    ap.add_argument("--min-flag", type=int, required=True, choices=(1, 2, 3, 4, 5),
                    help="drop samples whose content_max_flag is >= this")
    ap.add_argument("--out-dir", default=None, help="default: alongside the source log")
    ap.add_argument("--expect-entries", type=int, default=None,
                    help="assert plan.json['plan'] has exactly this many entries")
    ap.add_argument("--expect-kept", type=int, default=None,
                    help="assert the output has exactly this many samples")
    a = ap.parse_args()

    src = Path(a.log) if Path(a.log).is_absolute() else REPO_ROOT / a.log
    plan_path = Path(a.plan) if Path(a.plan).is_absolute() else REPO_ROOT / a.plan
    flags = load_flags(plan_path)
    if a.expect_entries is not None and len(flags) != a.expect_entries:
        raise SystemExit(f"plan entries {len(flags)} != expected {a.expect_entries}")

    n_src = len(json.loads(zipfile.ZipFile(str(src)).read("summaries.json")))
    n_drop = sum(1 for f in flags.values() if f >= a.min_flag)
    out_dir = Path(a.out_dir) if a.out_dir else src.parent
    dst = out_dir / (renamed(src.stem, n_src - n_drop) + f"_dropflag{a.min_flag}.eval")
    if a.expect_kept is not None and n_src - n_drop != a.expect_kept:
        raise SystemExit(f"kept {n_src - n_drop} != expected {a.expect_kept}")

    print(f"[filter] {src.name}\n         -> {dst.name}  (min_flag={a.min_flag}, "
          f"plan entries={len(flags)}, source={n_src})")
    stats = filter_log(src, dst, flags, a.min_flag, plan_path)
    print(f"[filter] done: kept={stats['kept']} dropped={stats['dropped']}")


if __name__ == "__main__":
    main()
