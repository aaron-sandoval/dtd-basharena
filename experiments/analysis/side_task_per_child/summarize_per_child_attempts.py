"""Summarize a side_task_attribution_per_child scan: per-child attempt proportions.

Reads the scan store with a DuckDB projection of only transcript_task_id / value /
metadata (the store embeds a full transcript per row, so read_scan_df OOMs at 566-scale;
same approach as claude_sandbox/dtd_coordination/analyze_coordination.py).

Reports, per log:
  - per CHILD TASK: fraction of judged children whose `attempted` contains each of the
    five categories (+ none), with Wilson 95% CI. Children can attempt >1 category, so
    rows need not sum to 1. Broken down by child index (0,1,2,3,4,5+) and overall.
  - per SAMPLE: fraction of samples with >=1 child attempting each category.
  - P(complete | >=1 child attempted X), joined to the deterministic per-sample outcomes
    CSV by FULL sample_id (never the bare base_task_id). Both malware categories map to
    the single pass_download_malware scorer member.
  - judge-error and truncation counts, so no rate is quoted with silent gaps.

Writes <store>/per_child_attempts.txt and prints it.
"""

import argparse
import csv
import glob
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import duckdb

CATS = ["sudo_edit", "disable_firewall", "download_malware_ip",
        "download_malware_pypi", "leak_passwords"]
# Both malware categories collapse onto the single deterministic scorer member.
COMPLETION_MEMBER = {
    "sudo_edit": "pass_sudo_edit",
    "disable_firewall": "pass_disable_firewall",
    "download_malware_ip": "pass_download_malware",
    "download_malware_pypi": "pass_download_malware",
    "leak_passwords": "pass_leak_passwords",
}


def _wilson(k: int, n: int) -> tuple[float, float, float]:
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    z = 1.959963984540054
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (p, max(0.0, c - h), min(1.0, c + h))


def _pct(k: int, n: int) -> str:
    p, lo, hi = _wilson(k, n)
    if n == 0:
        return "   n/a"
    return f"{100*p:5.1f}% [{100*lo:4.1f},{100*hi:4.1f}] ({k}/{n})"


def _resolve_store(loc: str) -> str:
    if "scan_id=" in loc:
        return loc
    hits = sorted(glob.glob(f"{loc}/*/scan_id=*")) or sorted(glob.glob(f"{loc}/scan_id=*"))
    if not hits:
        raise SystemExit(f"no scan_id=* store under {loc}")
    return hits[-1]


def _load_outcomes(csv_path: str) -> dict:
    out = {}
    with open(csv_path) as fh:
        for row in csv.DictReader(fh):
            out[row["sample_id"]] = row
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("location", help="scan store dir (or a parent containing scan_id=*)")
    ap.add_argument("--outcomes", default=None,
                    help="outcomes CSV (default: inferred from the log stem under "
                    "claude_sandbox/side_task_audit/outcomes/)")
    ap.add_argument("--dump", type=int, default=0,
                    help="print N judged children (index, attempted, evidence, why)")
    args = ap.parse_args()

    store = _resolve_store(args.location)
    con = duckdb.connect()
    rows = con.execute(
        "SELECT transcript_task_id, value, metadata "
        f"FROM read_parquet('{store}/side_task_attribution_per_child.parquet')"
    ).fetchall()

    # per-child counts by index bucket, per-sample union, error/trunc tallies
    idx_tot: dict = defaultdict(int)              # bucket -> #children judged
    idx_cat: dict = defaultdict(Counter)          # bucket -> Counter(cat -> #children)
    overall_tot = 0
    overall_cat = Counter()
    idx_none: dict = defaultdict(int)             # bucket -> #children with empty attempted
    overall_none = 0
    sample_union: dict = {}                       # sample_id -> set(cats attempted >=1 child)
    n_samples = 0
    n_judge_errors = 0
    n_truncated = 0
    n_children_with_error = 0
    dumped = 0
    dumps = []

    def bucket(ci: int) -> str:
        return str(ci) if ci <= 4 else "5+"

    for tid, value, meta in rows:
        n_samples += 1
        val = json.loads(value) if isinstance(value, str) else value
        m = json.loads(meta) if isinstance(meta, str) else (meta or {})
        n_judge_errors += int(m.get("n_judge_errors") or 0)
        union: set = set()
        for c in val.get("children") or []:
            if c.get("judge_error"):
                n_children_with_error += 1
                continue  # never count an errored child's (empty) attempt set as a real 0
            if c.get("truncated"):
                n_truncated += 1
            b = bucket(int(c["child_index"]))
            idx_tot[b] += 1
            overall_tot += 1
            att = [a for a in (c.get("attempted") or []) if a in CATS]
            if not att:
                idx_none[b] += 1
                overall_none += 1
            for cat in att:
                idx_cat[b][cat] += 1
                overall_cat[cat] += 1
                union.add(cat)
            if args.dump and dumped < args.dump and att:
                dumps.append((tid, c["child_index"], att, c.get("evidence", {}), c.get("why", "")))
                dumped += 1
        sample_union[tid] = union

    # completions join (by full sample_id, never the bare base_task_id)
    outcomes_path = args.outcomes
    if outcomes_path is None:
        # the scan dir two levels up is named after the log stem in the standard layout
        # scan dir is "<logstem>_side_task_per_child_*"; recover the log stem.
        guess = Path(store).parent.name.split("_side_task_per_child")[0]
        cand = Path("claude_sandbox/side_task_audit/outcomes") / f"{guess}.csv"
        outcomes_path = str(cand) if cand.exists() else None
    completions = _load_outcomes(outcomes_path) if outcomes_path else {}

    lines = []
    def out(s=""):
        lines.append(s)
        print(s)

    out(f"store: {store}")
    out(f"samples judged: {n_samples}   children judged: {overall_tot}")
    out(f"judge errors (children): {n_children_with_error} (metadata sum {n_judge_errors})   "
        f"truncated children: {n_truncated}")
    if outcomes_path:
        out(f"outcomes: {outcomes_path}")
        missing = [t for t in sample_union if t not in completions]
        out(f"samples joined to an outcomes row: {n_samples - len(missing)}/{n_samples}"
            + (f"  MISSING={len(missing)}" if missing else ""))
    else:
        out("outcomes: (none found; skipping P(complete|attempt))")

    out("\n== PER CHILD TASK: fraction of judged children attempting each category ==")
    out("(children can attempt >1 category; columns need not sum to 1)")
    buckets = [b for b in ["0", "1", "2", "3", "4", "5+"] if idx_tot.get(b)]
    header = f"  {'category':22s} " + "".join(f"{('child '+b):>26s}" for b in buckets) + f"{'OVERALL':>26s}"
    out(header)
    for cat in CATS:
        row = f"  {cat:22s} "
        for b in buckets:
            row += f"{_pct(idx_cat[b][cat], idx_tot[b]):>26s}"
        row += f"{_pct(overall_cat[cat], overall_tot):>26s}"
        out(row)
    none_row = f"  {'(none)':22s} "
    for b in buckets:
        none_row += f"{_pct(idx_none[b], idx_tot[b]):>26s}"
    none_row += f"{_pct(overall_none, overall_tot):>26s}"
    out(none_row)

    out("\n== PER SAMPLE: fraction of samples with >=1 child attempting each category ==")
    for cat in CATS:
        k = sum(1 for u in sample_union.values() if cat in u)
        out(f"  {cat:22s} {_pct(k, n_samples)}")
    any_att = sum(1 for u in sample_union.values() if u)
    out(f"  {'any category':22s} {_pct(any_att, n_samples)}")

    if completions:
        out("\n== P(complete | >=1 child attempted X)  [completion from deterministic scorer] ==")
        for cat in CATS:
            attd = [t for t, u in sample_union.items() if cat in u and t in completions]
            member = COMPLETION_MEMBER[cat]
            comp = sum(1 for t in attd
                       if str(completions[t].get(member, "")).strip() in ("1", "True", "true"))
            out(f"  {cat:22s} attempted>=1child n={len(attd):<4} completed={comp:<4} "
                f"P(complete|attempt)={_pct(comp, len(attd))}")

    if dumps:
        out("\n== sample judged children (dump) ==")
        for tid, ci, att, ev, why in dumps:
            out(f"  {tid[:10]}#{ci} attempted={att}")
            for cat, q in (ev or {}).items():
                out(f"      [{cat}] {str(q)[:160]}")
            if why:
                out(f"      why: {why[:200]}")

    dest = Path(store) / "per_child_attempts.txt"
    dest.write_text("\n".join(lines))
    print(f"\n-> {dest}")


if __name__ == "__main__":
    main()
