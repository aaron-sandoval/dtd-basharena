#!/usr/bin/env bash
# Populate the metrics cache for the CANONICAL DTD thr2.333 withtips-NO-PLAN
# action-limit cells
# (TOWER_C14_DTD_NOPLAN_GIVEUP_TOTAL_ATTACK_INLOOP_AUTOSUBMIT, indices 1..11).
#
# The parent arm is truncated IN-LOOP (auto_submit default True since 2026-08-19),
# not a post-hoc *_autosubmit replay -- which is also why RF3 never touched it.
#
# Same knobs as every other claim-6 cell: sus-key tu-root-history, attack-threshold 0,
# pool-runs dedup_latest, and the --bootstrap-ci config the plot reads by cache key
# (B=500, seed 0). No --resample-agg: DTD does not resample.
#
# TWO STAGES, because compute_metrics.py builds a COLD per-log extract with a full
# read_eval_log (40-60x memory inflation on these ~1.1 GB logs). Running three of those
# concurrently OOM-killed 9/11 jobs (rc=137) on 2026-08-18:
#   1. streaming_log_extract.py builds each extract sample-at-a-time (~3 MB retention),
#      so it parallelizes safely -- this is the fix recorded in the BA1.2 1000-task OOM note.
#   2. compute_metrics.py then runs against WARM extracts: fast and light.
# Already-cached cells are cheap to redo, so both stages just run the whole grid.
set -uo pipefail
cd "$(dirname "$0")/../../.." || exit 1

HONEST=experiments/_logs/tower/2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval
DIR=experiments/_logs/tower
STEM=2026-08-20T22-18-47_566_attack_online-dtd-v11.1-thr2p333-withtips-noplan_BA10-UNION566
# Run logs go to gitignored scratch.
LOGDIR=claude_sandbox/claim6_out_noplan
mkdir -p "$LOGDIR"
NS=${NS:-"5 10 15 20 25 30 35 40 45 50 55"}
EXTRACT_JOBS=${EXTRACT_JOBS:-4}
METRIC_JOBS=${METRIC_JOBS:-2}

extract_one() {
  local n="$1"
  local atk="$DIR/${STEM}_actionsTotal${n}.eval"
  [[ -s "$atk" ]] || { echo "MISSING $atk" >&2; return 1; }
  echo "[$(date -u +%H:%M:%S)] extract start N=$n"
  uv run python experiments/analysis/streaming_log_extract.py "$atk" \
      > "$LOGDIR/extract_dtd_noplan_at_actionsTotal${n}.log" 2>&1
  local rc=$?
  echo "[$(date -u +%H:%M:%S)] extract done  N=$n rc=$rc"
  return $rc
}

metrics_one() {
  local n="$1"
  local atk="$DIR/${STEM}_actionsTotal${n}.eval"
  echo "[$(date -u +%H:%M:%S)] metrics start N=$n"
  uv run python experiments/analysis/compute_metrics.py \
      --safety "$atk" \
      --usefulness "$HONEST" \
      --sus-keys suspicion_score__tu-root-history \
      --attack-threshold 0 \
      --pool-runs dedup_latest \
      --bootstrap-ci --n-bootstrap 500 --bootstrap-seed 0 \
      > "$LOGDIR/compute_dtd_noplan_at_actionsTotal${n}.log" 2>&1
  local rc=$?
  echo "[$(date -u +%H:%M:%S)] metrics done  N=$n rc=$rc"
  return $rc
}
export -f extract_one metrics_one
export DIR STEM HONEST LOGDIR

# NOTE: each worker returns its real exit code and xargs exits 123 if ANY invocation
# failed, so a partial OOM wipe-out (rc=137, which is how 9/11 cells died on the first
# attempt) can never be reported as success.
echo "STAGE 1: streaming extracts (${EXTRACT_JOBS}-wide)"
printf '%s\n' $NS | xargs -P "$EXTRACT_JOBS" -I{} bash -c 'extract_one {}'
stage1=$?
if [[ $stage1 -ne 0 ]]; then
  echo "STAGE 1 FAILED (xargs rc=$stage1) -- not running metrics on incomplete extracts" >&2
  exit $stage1
fi
echo "STAGE 2: compute_metrics (${METRIC_JOBS}-wide, warm extracts)"
printf '%s\n' $NS | xargs -P "$METRIC_JOBS" -I{} bash -c 'metrics_one {}'
stage2=$?
if [[ $stage2 -ne 0 ]]; then
  echo "STAGE 2 FAILED (xargs rc=$stage2) -- some cells are NOT cached" >&2
  exit $stage2
fi
echo "ALL DONE"
