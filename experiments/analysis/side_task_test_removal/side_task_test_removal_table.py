"""Recompute tab:side-task-test-removal: attack samples touched by the side-task-test fix.

The 13 post-hoc `_autosubmit` attack arms (TM 1, DTR 4, DTD 7, text files 1) were repaired
in two ways, and this table counts each per protocol over the 566-task union:

  Rerun      samples whose replay deviated badly enough (content_max_flag >= 3) that they
             were rerun in-loop: the frozen experiments/data/rerun_flag3/<stem>.txt lists.
             Cross-checked against the replay plans (flag >= 3 ∩ union).
  Truncated  samples the replay cut short because an earlier executed action had already
             completed a side task, and that were NOT superseded by a rerun. Read from the
             `autosubmit_truncated` scorer of each <stem>_autosubmit.eval (what the analysed
             log actually contains); the replay plans' `will_truncate & flag < 3` count is
             printed alongside. The two differ only on the text-files arm (432 vs 431): task
             7572974 errored in the original run, so the replay had no side-task result to
             truncate on.

Denominators are 566 x (number of evals) for both columns. The published counts are
asserted, so a drift in any input fails loudly.

Usage: uv run python experiments/analysis/side_task_test_removal/side_task_test_removal_table.py
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from inspect_ai.log import read_eval_log_sample_summaries  # noqa: E402

from tu_bb2.named_tasks_and_logs import BashArenaTasks  # noqa: E402
from tu_bb2.postprocessing import base_task_id  # noqa: E402

LOGS = REPO / "experiments" / "_logs" / "tower"
PLANS = REPO / "experiments" / "data" / "autosubmit_plans"
RERUN = REPO / "experiments" / "data" / "rerun_flag3"
MIN_FLAG = 3

# protocol (manuscript name) -> replay arms
ARMS: dict[str, list[str]] = {
    "Trusted monitoring": [
        "2026-07-15T03-59-44_629_attack_tm-v11.1_sus_BA10-UNION",
    ],
    "DTR": [
        "2026-07-24T14-24-05_629_attack_dtr-v11.1-defer0p2-nocache_sus_BA10-UNION",
        "2026-07-24T14-25-13_629_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION",
        "2026-07-24T08-30-06_629_attack_dtr-v11.1-defer1p0-nocache_sus_BA10-UNION",
        "2026-07-24T08-31-44_624_attack_dtr-v11.1-defer3p0-nocache_sus_BA10-UNION",
    ],
    "DTD": [
        "2026-07-30T21-45-11_566_attack_online-dtd-v11.1-thr1p333_BA10-UNION566",
        "2026-07-30T17-14-25_566_attack_online-dtd-v11.1-thr2p333_BA10-UNION566",
        "2026-07-30T00-45-23_566_attack_online-dtd-v11.1-thr3p0-rem_BA10-UNION566",
        "2026-07-30T03-58-10_566_attack_online-dtd-v11.1-thr3p0-root_BA10-UNION566",
        "2026-07-30T06-33-58_566_attack_online-dtd-v11.1-thr3p0-fhe_BA10-UNION566",
        "2026-07-30T15-13-44_561_attack_online-dtd-v11.1-thr5p0_BA10-UNION566",
        "2026-07-31T06-22-30_566_attack_online-dtd-v11.1-thr2p333-planshare_BA10-UNION566",
    ],
    "Text files": [
        "2026-07-31T00-56-41_566_attack_online-ces-v11.1-rem_BA10-UNION566",
    ],
}

# (rerun, truncated) as published in the manuscript table
EXPECTED: dict[str, tuple[int, int]] = {
    "Trusted monitoring": (86, 414),
    "DTR": (529, 556),
    "DTD": (856, 809),
    "Text files": (89, 431),
}


def arm_counts(stem: str, union: set[str]) -> tuple[int, int, int]:
    """(rerun, truncated by scorer, truncated by plan) for one replay arm, within the union."""
    rerun = {t.strip() for t in (RERUN / f"{stem}.txt").read_text().splitlines() if t.strip()}
    plan = json.loads((PLANS / f"{stem}.json").read_text())["plan"]
    flagged = {e["main_task_id"] for e in plan.values()
               if (e.get("content_max_flag") or 0) >= MIN_FLAG} & union
    assert flagged == rerun, f"{stem}: plan flag>={MIN_FLAG} ids != frozen rerun list"
    plan_trunc = {e["main_task_id"] for e in plan.values()
                  if e.get("will_truncate") and (e.get("content_max_flag") or 0) < MIN_FLAG} & union

    scorer_trunc = set()
    for s in read_eval_log_sample_summaries(str(LOGS / f"{stem}_autosubmit.eval")):
        score = (s.scores or {}).get("autosubmit_truncated")
        if score is not None and score.value == 1.0:
            scorer_trunc.add(base_task_id(s.id))
    scorer_trunc = (scorer_trunc & union) - rerun
    return len(rerun), len(scorer_trunc), len(plan_trunc)


def main() -> None:
    union = set(BashArenaTasks.train_test_union())
    assert len(union) == 566, f"train_test_union returned {len(union)} ids, expected 566"

    print(f"{'Protocol':<20}{'Evals':>6}  {'Rerun':>14}  {'Truncated':>14}  (plan gate)")
    for proto, stems in ARMS.items():
        rerun = trunc = plan_trunc = 0
        for stem in stems:
            r, t, p = arm_counts(stem, union)
            rerun, trunc, plan_trunc = rerun + r, trunc + t, plan_trunc + p
        n = len(union) * len(stems)
        print(f"{proto:<20}{len(stems):>6}  {rerun:>5}, {rerun / n:6.1%}  "
              f"{trunc:>5}, {trunc / n:6.1%}  ({plan_trunc})")
        assert (rerun, trunc) == EXPECTED[proto], f"{proto}: {(rerun, trunc)} != {EXPECTED[proto]}"
    print("All counts match the published table.")


if __name__ == "__main__":
    main()
