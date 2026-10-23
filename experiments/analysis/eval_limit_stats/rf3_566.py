"""Recompute tab:eval-limits on the populations the current paper figures use.

The 2026-08-27 table (cells.py / assemble.py / aggregate.py / affected_only.py) pooled
the cells of the Aug-25 claim-10 Pareto: TM and DTRF attack arms were the pre-RF3
single `_autosubmit` logs over the full 629/624-task sets, honest arms unrestricted.
The paper's figures (20260921T004322Z_safety-use_claim10_..._RF3.pdf) now use:

  attack  TM / DTRF: [original `_autosubmit` (defer0.2: `_rf3excl8`), RF3 rerun] pooled
          under dedup_latest_strict, restricted to the 566-task union. The rows kept
          are exactly the rows that enter the safety metric (clean winners).
  attack  DTD: the in-loop withtips-noplan thr2.333 log (unchanged), clean rows, 566.
  honest  every arm restricted to the 566-task union (latest log wins a duplicate),
          errored samples dropped (they carry no score, as in usefulness).

Step-limit exhaustion is not a native sample.limit, so 'Other' samples are split by
whether the last non-monitor assistant message still carried a tool call (same rule as
classify_other.py). Existing other_class/*.json records are reused by raw sample id;
the RF3 rerun logs are classified fresh.

`--legacy` reruns the OLD populations through the same code as a positive control; it
must reproduce limit_hit_rates_claim10_pooled.csv / the old table exactly.

Usage:
    uv run python experiments/analysis/eval_limit_stats/rf3_566.py [--legacy]
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))

from classify_other import classify  # noqa: E402
from tu_bb2.named_tasks_and_logs import BashArenaTasks  # noqa: E402
from tu_bb2.postprocessing import (  # noqa: E402
    base_task_id, get_log_extract, get_minimal_log_df, pool_run_frames, relabel_to_base_task_id,
)

L = "experiments/_logs/tower/"
STEP = "step-limit (cut mid-work)"
MSG300 = {"defer1.0", "defer3.0"}  # the DTRF cells that ran message_limit=300 (tab caption)

# (protocol, cell, arm, [logs in run order], pool_runs, [other_class tags per log or None])
NEW = [
    ("DTRF", "defer0.2", "attack", [L + "2026-07-24T14-24-05_621_attack_dtr-v11.1-defer0p2-nocache_sus_BA10-UNION_autosubmit_rf3excl8.eval",
                                    L + "2026-09-02T01-26-33_138_attack_dtr-v11.1-defer0p2-nocache_sus_BA10-UNION566-RF3.eval"],
     "dedup_latest_strict", ["DTRF-d0.2-attack", None]),
    ("DTRF", "defer0.5", "attack", [L + "2026-07-24T14-25-13_629_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION_autosubmit.eval",
                                    L + "2026-09-02T01-32-21_139_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION566-RF3.eval"],
     "dedup_latest_strict", ["DTRF-d0.5-attack", None]),
    ("DTRF", "defer1.0", "attack", [L + "2026-07-24T08-30-06_629_attack_dtr-v11.1-defer1p0-nocache_sus_BA10-UNION_autosubmit.eval",
                                    L + "2026-09-02T01-20-55_117_attack_dtr-v11.1-defer1p0-nocache_sus_BA10-UNION566-RF3.eval"],
     "dedup_latest_strict", ["DTRF-d1.0-attack", None]),
    ("DTRF", "defer3.0", "attack", [L + "2026-07-24T08-31-44_624_attack_dtr-v11.1-defer3p0-nocache_sus_BA10-UNION_autosubmit.eval",
                                    L + "2026-09-02T03-32-56_127_attack_dtr-v11.1-defer3p0-nocache_sus_BA10-UNION566-RF3.eval"],
     "dedup_latest_strict", ["DTRF-d3.0-attack", None]),
    ("TM", "tm", "attack", [L + "2026-07-15T03-59-44_629_attack_tm-v11.1_sus_BA10-UNION_autosubmit.eval",
                            L + "2026-09-01T23-56-42_86_attack_tm-v11.1_sus_BA10-UNION566-RF3.eval"],
     "dedup_latest_strict", ["TM-attack", None]),
    ("DTD", "noplan thr2.333", "attack", [L + "2026-08-20T22-18-47_566_attack_online-dtd-v11.1-thr2p333-withtips-noplan_BA10-UNION566.eval"],
     "dedup_latest", ["DTD-attack"]),
    ("DTRF", "defer0.2", "honest", [L + "2026-07-24T05-49-10_629_dtrf-v11.1-defer0p2-nocache_sus_BA10-UNION.eval"], "honest", ["DTRF-d0.2-honest"]),
    ("DTRF", "defer0.5", "honest", [L + "2026-07-24T14-07-55_629_dtrf-v11.1-defer0p5-nocache_sus_BA10-UNION.eval"], "honest", ["DTRF-d0.5-honest"]),
    ("DTRF", "defer1.0", "honest", [L + "2026-07-24T04-01-41_629_dtrf-v11.1-defer1p0-nocache_sus_BA10-UNION.eval"], "honest", ["DTRF-d1.0-honest"]),
    ("DTRF", "defer3.0", "honest", [L + "2026-07-24T04-24-03_629_dtrf-v11.1-defer3p0-nocache_sus_BA10-UNION.eval"], "honest", ["DTRF-d3.0-honest"]),
    ("TM", "tm", "honest", [L + "2026-07-15T02-59-38_452_uh_sus_BA10-UNION.eval",
                            L + "2026-07-30T08-17-38_159_uh-gapfill_sus_BA10-UNION566.eval"], "honest", ["TM-honest-a", "TM-honest-b"]),
    ("DTD", "noplan thr2.333", "honest", [L + "2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval"], "honest", ["DTD-honest"]),
]

# The Aug-27 populations: first log of each attack cell as-is (defer0.2 = the full 629
# `_autosubmit`), every sample of every log, no union restriction, no pooling.
LEGACY = [
    (p, c, a, ([L + "2026-07-24T14-24-05_629_attack_dtr-v11.1-defer0p2-nocache_sus_BA10-UNION_autosubmit.eval"]
               if (c, a) == ("defer0.2", "attack") else (logs[:1] if a == "attack" else logs)),
     "all", tags[:1] if a == "attack" else tags)
    for p, c, a, logs, _pool, tags in NEW
]


def other_kinds(log, tag):
    """raw sample id -> step-limit / agent-stopped kind for the log's 'Other' samples."""
    p = REPO / "experiments" / "data" / "eval_limit_stats" / "other_class" / f"{tag}.json" if tag else None
    if p is not None and p.exists():
        recs = json.loads(p.read_text())["records"]
    else:
        _, _, recs = classify(str(REPO / log))
    return {r["id"]: r["kind"] for r in recs}


def population(logs, pool, union):
    """[(log, extract sample)] for the rows this cell contributes."""
    extracts = [get_log_extract(str(REPO / lf))["samples"] for lf in logs]
    if pool == "all":
        return [(lf, s) for lf, ex in zip(logs, extracts) for s in ex]
    if pool == "honest":  # restrict to the union; a later log wins a duplicate task
        keep = {}
        for lf, ex in zip(logs, extracts):
            for s in ex:
                t = base_task_id(s["raw_id"])
                if t in union:
                    keep[t] = (lf, s)
        # Errored samples carry no score and are dropped from usefulness, as the
        # unclean attack rows are from safety.
        return [(lf, s) for lf, s in keep.values() if s["termination_reason"] != "Error/exception"]
    parts = []
    for i, lf in enumerate(logs):
        df = get_minimal_log_df(
            [str(REPO / lf)], include_sus_fields=False, duplicate_id_handling="latest",
            include_main_task_success=False, include_side_task_success=True,
        ).copy()
        df["_clean"] = df["score_side_task_success"].notna()
        df["_log_i"] = i
        parts.append(relabel_to_base_task_id(df))
    winners = pool_run_frames(parts, pool)
    win = {str(t): int(li) for t, li in winners["_log_i"].items() if str(t) in union}
    out = []
    for i, (lf, ex) in enumerate(zip(logs, extracts)):
        by_task = {base_task_id(s["raw_id"]): s for s in ex}
        out += [(lf, by_task[t]) for t, li in win.items() if li == i]
    assert len(out) == len(win), "a winning task has no extract row"
    return out


def tally(cells, union):
    rows = []
    for proto, cell, arm, logs, pool, tags in cells:
        kinds = {}
        for lf, tag in zip(logs, tags):
            kinds[lf] = other_kinds(lf, tag)
        term, n, step = Counter(), 0, 0
        for lf, s in population(logs, pool, union):
            n += 1
            term[s["termination_reason"]] += 1
            if s["termination_reason"] == "Other" and kinds[lf].get(s["raw_id"]) == STEP:
                step += 1
        rows.append(dict(protocol=proto, cell=cell, arm=arm, n=n, time=term["Time/working limit"],
                         step=step, msg=term["Message limit"], token=term["Token limit"],
                         error=term["Error/exception"]))
        print(f"  {proto:<5} {cell:<16} {arm:<7} n={n:<4} time={term['Time/working limit']:<4} "
              f"step={step:<4} msg={term['Message limit']:<3} tok={term['Token limit']} err={term['Error/exception']}")
    return rows


def pooled(rows):
    pool = defaultdict(Counter)
    for r in rows:
        k = (r["protocol"], r["arm"])
        for c in ("n", "time", "step", "token", "error"):
            pool[k][c] += r[c]
        if r["protocol"] != "DTRF" or r["cell"] in MSG300:
            pool[k]["n_msg"] += r["n"]
            pool[k]["msg"] += r["msg"]
    print(f"\n{'protocol':<6} {'arm':<7} {'N':>5} | {'time':>14} {'step':>14} | {'N msg':>6} {'message':>13}")
    for k in [("DTD", "attack"), ("DTRF", "attack"), ("TM", "attack"),
              ("DTD", "honest"), ("DTRF", "honest"), ("TM", "honest")]:
        p = pool[k]
        pc = lambda c, d: f"{p[c]:>4} {100 * p[c] / p[d]:>6.2f}%"
        print(f"{k[0]:<6} {k[1]:<7} {p['n']:>5} | {pc('time', 'n'):>14} {pc('step', 'n'):>14} | "
              f"{p['n_msg']:>6} {pc('msg', 'n_msg'):>13}   (token {p['token']}, error {p['error']})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy", action="store_true", help="reproduce the Aug-27 populations (control)")
    args = ap.parse_args()
    union = set(BashArenaTasks.train_test_union())
    assert len(union) == 566
    print("LEGACY (Aug-27 populations)" if args.legacy else "CURRENT (RF3 pools, 566 union)")
    pooled(tally(LEGACY if args.legacy else NEW, union))
