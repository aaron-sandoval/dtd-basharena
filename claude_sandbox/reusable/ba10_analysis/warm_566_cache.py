"""Warm the metrics cache under the 566-task restriction for every cited cell.

``task_ids`` joins the metrics cache key, so a restricted result cannot collide
with the existing 629 entries -- but it also means NOTHING is cached yet for the
restricted universe. ``claim10_truncation_bounds.py`` reads the cache and never
computes, so it prints "NOT IN METRICS CACHE" for every row until this has run.

Each cell is warmed TWICE, with and without ``bootstrap_ci``: the bootstrap
config joins the key, and ``plot_safety_usefulness.py`` reads with
``bootstrap=None`` while the error bars come from the CI-keyed entry. This
mirrors the double call in ``anchors.sh``'s ``cm`` helper.

Run (long; use tmux):
    uv run python claude_sandbox/reusable/ba10_analysis/warm_566_cache.py
    uv run python .../warm_566_cache.py --only DTRF     # substring filter
    uv run python .../warm_566_cache.py --dry-run
"""

import argparse
import sys
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH  # noqa: E402
from tu_bb2.named_tasks_and_logs import BashArenaLogs as L, resolve_task_ids  # noqa: E402
from tu_bb2.postprocessing import get_or_compute_protocol_metrics  # noqa: E402

# DTRF cells are scored with q90; TM and DTD never resample and MUST be scored
# without an aggregation (the library raises rather than silently no-op'ing).
DTRF_AGG = "q90"


def build_cells(arm_set="autosubmit"):
    """(label, attack_entry, honest_entry, resample_agg) for every cited cell.

    ``arm_set`` selects which attack arms feed the cache (kwargs incl.
    ``pool_runs`` are always read off the chosen group's cell, so the RF3
    cells warm under ``dedup_latest_strict`` automatically):

    - ``"autosubmit"`` (default): the post-hoc ``_AUTOSUBMIT`` arms as cited
      pre-repair.
    - ``"rf3"``: every flag>=3-repaired arm swaps to its ``*_RERUN_FLAG3``
      pooled cell ([original, RF3] strict); adds the Phase-A cells (rem/root/
      fhe repaired + A8b in-loop, un-repaired) and the planshare cell so one
      warm run covers every RF3-regenerated figure; drops the dropflag4 cell.
    """
    if arm_set not in ("autosubmit", "rf3"):
        raise ValueError(f"unknown arm_set {arm_set!r}")
    rf3 = arm_set == "rf3"
    sfx = " RF3" if rf3 else ""
    out = []

    def add(label, a, h, agg=None):
        if a is not None and h is not None:
            out.append((label, a, h, agg))

    # DTD front, auto-submit truncated (claims 10/11 read these).
    dtd_attack = (L.TOWER_PHASE_B_DTD_ATTACK_RERUN_FLAG3 if rf3
                  else L.TOWER_PHASE_B_DTD_ATTACK_AUTOSUBMIT)
    for i, tag in [(0, "thr1.333"), (2, "thr2.333"), (3, "thr3.0"), (4, "thr5.0")]:
        add(f"DTD {tag}{sfx}", dtd_attack[i], L.TOWER_PHASE_B_DTD_HONEST[i])
    # The canonical no-plan point (claims 4.1/6/7/10/11) — in-loop, never RF3'd.
    add("DTD no-plan thr2.333",
        L.TOWER_C14_DTD_WITHTIPS_NOPLAN_ATTACK_INLOOP_AUTOSUBMIT[0],
        L.TOWER_PHASE_B_DTD_HONEST[2])
    # DTRF front, q90.
    dtrf_attack = (L.TOWER_C10_DTRF_REDO_ATTACK_RERUN_FLAG3 if rf3
                   else L.TOWER_C10_DTRF_REDO_ATTACK_AUTOSUBMIT)
    for i, tag in [(0, "defer0.2"), (1, "defer0.5"), (2, "defer1.0"), (3, "defer3.0")]:
        add(f"DTRF {tag}{sfx}", dtrf_attack[i], L.TOWER_C10_DTRF_REDO_HONEST[i],
            DTRF_AGG)
    # TM baseline; its honest arm IS the UH anchor.
    add(f"TM{sfx}",
        (L.TOWER_C10_TM_ATTACK_RERUN_FLAG3 if rf3 else L.TOWER_C10_TM_ATTACK_AUTOSUBMIT)[0],
        L.TOWER_BA10_UH_ANCHOR_RESTORED[0])
    if not rf3:
        add("TM dropflag4", L.TOWER_C10_TM_ATTACK_AUTOSUBMIT_DROPFLAG4[0],
            L.TOWER_BA10_UH_ANCHOR_RESTORED[0])
    # CES (claim 11).
    add(f"CES{sfx}",
        (L.TOWER_C11_CES_ATTACK_RERUN_FLAG3 if rf3 else L.TOWER_C11_CES_ATTACK_AUTOSUBMIT)[0],
        L.TOWER_C11_CES_HONEST[0])
    if rf3:
        # Phase-A design-gate cells (claims 1/2/3): rem/root/fhe repaired, A8b
        # in-loop (no RF3 slot exists for it).
        for i, tag in [(0, "rem"), (1, "root"), (2, "fhe")]:
            add(f"PhaseA {tag} RF3", L.TOWER_PHASE_A_DTD_ATTACK_RERUN_FLAG3[i],
                L.TOWER_PHASE_A_DTD_HONEST[i])
        add("PhaseA A8b nosum (in-loop)", L.TOWER_PHASE_A_DTD_ATTACK_AUTOSUBMIT[3],
            L.TOWER_PHASE_A_DTD_HONEST[3])
        # Plan-sharing cell (claim 4.1), shared thr2.333 honest arm.
        add("DTD planshare thr2.333 RF3", L.TOWER_C4_DTD_PLANSHARE_ATTACK_RERUN_FLAG3[0],
            L.TOWER_PHASE_B_DTD_HONEST[2])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--task-ids", default="BA10_UNION", metavar="NAME")
    ap.add_argument("--arm-set", choices=["autosubmit", "rf3"], default="autosubmit",
                    help="Which attack arms to warm: 'autosubmit' (pre-repair, "
                         "default) or 'rf3' (the *_RERUN_FLAG3 repaired pools, "
                         "strict dedup read off the group kwargs).")
    ap.add_argument("--only", default=None, help="Substring filter on the cell label.")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--n-bootstrap", type=int, default=500)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    alias, task_ids = resolve_task_ids(args.task_ids)
    cells = [c for c in build_cells(args.arm_set) if not args.only or args.only in c[0]]
    print(f"task_ids: {alias}\narm_set: {args.arm_set}\ncells: {len(cells)}\n")

    failures = []
    for label, a, h, agg in cells:
        kw = dict(
            sus_keys=[a[1]["sus_key"]],
            attack_threshold=a[1].get("attack_threshold", 0),
            pool_runs=a[1].get("pool_runs", "epochs_equal_task"),
            resample_aggregation=agg,
        )
        print(f"--- {label}  (agg={agg or 'max'}, pool_runs={kw['pool_runs']})")
        for _p in a[0]:
            print(f"    attack:  {Path(_p).name}")
        if args.dry_run:
            continue
        for ci in (True, False):
            t0 = time.time()
            try:
                get_or_compute_protocol_metrics(
                    a[0], h[0], task_ids=task_ids, read_cache=True, write_cache=True,
                    bootstrap_ci=ci, n_bootstrap=args.n_bootstrap,
                    bootstrap_seed=args.seed, **kw,
                )
                print(f"    {'ci ' if ci else 'no-ci'} ok  {time.time() - t0:6.1f}s")
            except Exception as exc:  # keep going; one bad cell must not lose the rest
                failures.append(f"{label} (bootstrap_ci={ci}): {exc}")
                print(f"    {'ci ' if ci else 'no-ci'} FAILED after {time.time() - t0:.1f}s: {exc}")
                traceback.print_exc()

    print()
    if failures:
        print(f"{len(failures)} failure(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("all cells warmed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
