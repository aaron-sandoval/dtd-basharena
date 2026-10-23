"""Build the defer0.2 original-log variant with the 8 RF3-unrecoverable samples DELETED.

The RF3 defer0.2 rerun (fleet 01eaadca5cbd8a46) produced no S3 result for 8 of its 146
frozen ids (2026-09-02 expired-credential window). Per the RF3 policy those tasks are
excluded from analysis entirely — never retried, never allowed to fall back to their
(flag>=3 damaged) original rows. dedup_latest_strict can only drop a task the superseding
log ATTEMPTED (has a row for), so absence from the RF3 log would silently fall back.
This builds `<original>_rf3excl8.eval`: the original post-hoc `_autosubmit` log minus
exactly those 8 samples, so the pooled pair [original_rf3excl8, rf3] contains the 8
tasks in NEITHER log and every analysis excludes them with no special handling.

Reuses filter_fidelity_samples.filter_log with a synthetic flag map (the 8 samples at
flag 5, min_flag=5) so the streaming/manifest-patch machinery stays single-sourced.
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "claude_sandbox" / "reusable"))
from filter_fidelity_samples import filter_log  # noqa: E402

EXCLUDED_TASKS = {
    "30245823", "30714276", "38868061", "39118815",
    "42299905", "42993387", "52845387", "56196399",
}
STEM = "2026-07-24T14-24-05_629_attack_dtr-v11.1-defer0p2-nocache_sus_BA10-UNION"
SRC = REPO / "experiments/_logs/tower" / f"{STEM}_autosubmit.eval"
PLAN = REPO / "experiments" / "data" / "autosubmit_plans" / f"{STEM}.json"


def main() -> None:
    plan = json.loads(PLAN.read_text())["plan"]
    flags = {k: 5 for k, v in plan.items() if v["main_task_id"] in EXCLUDED_TASKS}
    assert len(flags) == 8, f"expected 8 plan entries for the excluded tasks, got {len(flags)}"
    dst = SRC.with_name(SRC.name.replace("_autosubmit.eval", "_autosubmit_rf3excl8.eval"))
    stats = filter_log(SRC, dst, flags, min_flag=5, plan_path=PLAN)
    print(json.dumps(stats, indent=1, default=str)[:400])
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
