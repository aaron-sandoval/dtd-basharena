#!/usr/bin/env bash
# Shared anchors + helpers for every BA1.0-replan analysis figure.
#
# Sourced by the per-claim scripts in this directory. Defines the two usefulness
# anchors the plan mandates (with its own reuse caveats already applied) and a
# `cm` helper that populates BOTH metrics-cache keys a figure needs.
#
# ⚠ WHY `cm` RUNS compute_metrics TWICE. `plot_safety_usefulness.py` reads safety
# from the metrics cache with `bootstrap=None` in the cache key, whereas
# `compute_metrics.py --bootstrap-ci` writes under a key that INCLUDES the
# bootstrap payload (see `_protocol_cache_key` in tu_bb2/postprocessing.py).
# Populating with --bootstrap-ci alone leaves the plot reporting a cache miss.
# The second (no-CI) call is a cache hit on the per-log extracts, so it is cheap.

set -euo pipefail
cd "$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"

L=experiments/_logs/tower
OUT=experiments/data/metrics_reports_tower

# Every report in $OUT is named <UTC>_<slug>.pdf — the plotting scripts stamp their
# own output that way when --out is omitted, so anything passing an explicit --out
# must stamp it too or the file sorts wrong and its vintage is unreadable.
#
# ⚠ CALL `ts` PER FIGURE, inside the --out argument, not once at the top of a script:
# a multi-figure script writes over minutes, and the prefix is only meaningful if it
# matches the "Generated (UTC)" line the report prints on its own cover.
#
#   --out "$OUT/$(ts)_claim6_TM_giveup-N_BA10.pdf"
ts() { date -u +%Y%m%dT%H%M%SZ; }

# usefulness = 0 anchor. The June-19 member of TOWER_C10_TPOLICY_HONEST is DROPPED:
# legacy regime (no sample_time_limit, max_steps=200). The two July logs cover 629/629.
TRUSTED="$L/2026-07-15T02-57-13_453_tpolicy-gpt54nano_BA10-UNION.eval $L/2026-07-17T06-55-37_176_tpolicy-gpt54nano-gapfill_BA10-UNION.eval"

# usefulness = 1 anchor = TOWER_BA10_UH_ANCHOR_RESTORED. NOT TOWER_C10_TM_HONEST,
# whose June-25 member ran under the 2.5M-token / 3300s regime with 43% limit-kills.
UH="$L/2026-07-15T02-59-38_452_uh_sus_BA10-UNION.eval $L/2026-07-30T08-17-38_159_uh-gapfill_sus_BA10-UNION566.eval"

# cm <attack-log...> -- <honest-log...> [sus_key]
# Populates both cache keys for one (attack, honest) cell.
cm() {
  local sus_key="${SUS_KEY:-suspicion_score__tu-root-history}"
  local attack=() honest=() seen=0
  for a in "$@"; do
    if [[ "$a" == "--" ]]; then seen=1; continue; fi
    if [[ $seen -eq 0 ]]; then attack+=("$a"); else honest+=("$a"); fi
  done
  # TASK_IDS: the task universe every cell is scoped to. BA10_UNION is the 566-id
  # BA1.0 universe; it JOINS THE CACHE KEY, so warming without it populates the
  # 629 entry and every restricted lookup still misses. Override with TASK_IDS=""
  # only to reproduce a pre-2026-09 unrestricted number.
  # RAGG: resample aggregation, DTRF cells ONLY (q90). It joins the cache key too,
  # and without this passthrough `cm` could not produce the DTRF q90 entries at all.
  local common=(--safety "${attack[@]}" --usefulness "${honest[@]}"
                --sus-keys "$sus_key" --attack-threshold 0 --pool-runs dedup_latest
                ${TASK_IDS:+--task-ids $TASK_IDS}
                ${RAGG:+--resample-agg $RAGG})
  uv run python experiments/analysis/compute_metrics.py "${common[@]}" --bootstrap-ci
  uv run python experiments/analysis/compute_metrics.py "${common[@]}"
}

# Default task universe for every cell warmed through `cm`. Set before sourcing to
# override. See the 566-vs-629 note in experiments/data/claims_and_evidence_ba10.md.
: "${TASK_IDS:=BA10_UNION}"
