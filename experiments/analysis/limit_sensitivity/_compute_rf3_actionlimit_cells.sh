#!/usr/bin/env bash
# Populate the metrics cache for the RF3-REPAIRED action-limit cells of TM and DTRF
# defer0.5 (TOWER_C6_{TM,DTRF_D0P5}_GIVEUP_ATTACK_RERUN_FLAG3, indices 0..11).
#
# Each cell pools [pre-repair `_actionsN`, RF3 `_actionsN`] under dedup_latest_strict.
# DTRF is scored --resample-agg q90 (it joins the cache key); TM has no resampling.
# Bootstrap config must match what the plot looks up by cache key: B=500, seed 0.
#
# Two stages for the same reason as _compute_dtd_actionlimit_cells.sh: compute_metrics.py
# builds a COLD per-log extract with a full read_eval_log (40-60x inflation), so extracts
# are streamed first (sample-at-a-time) and compute_metrics then runs warm.
set -uo pipefail
cd "$(dirname "$0")/../../.." || exit 1

NS=${NS:-"5 10 15 20 25 30 35 40 45 50 55"}
EXTRACT_JOBS=${EXTRACT_JOBS:-4}
METRIC_JOBS=${METRIC_JOBS:-2}
# Run logs go to gitignored scratch; the RF3 `_actionsN` halves live in tower/ with the other logs.
LOGDIR=claude_sandbox/claim6_out_rf3
TOW=experiments/_logs/tower
mkdir -p "$LOGDIR"

TM_ORIG="$TOW/2026-07-15T03-59-44_629_attack_tm-v11.1_sus_BA10-UNION_autosubmit"
TM_RF3B="$TOW/2026-09-01T23-56-42_86_attack_tm-v11.1_sus_BA10-UNION566-RF3"
TM_RF3="$TOW/2026-09-01T23-56-42_86_attack_tm-v11.1_sus_BA10-UNION566-RF3"
TM_HON="$TOW/2026-07-15T02-59-38_452_uh_sus_BA10-UNION.eval $TOW/2026-07-30T08-17-38_159_uh-gapfill_sus_BA10-UNION566.eval"

DTR_ORIG="$TOW/2026-07-24T14-25-13_629_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION_autosubmit"
DTR_RF3B="$TOW/2026-09-02T01-32-21_139_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION566-RF3"
DTR_RF3="$TOW/2026-09-02T01-32-21_139_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION566-RF3"
DTR_HON="$TOW/2026-07-24T14-07-55_629_dtrf-v11.1-defer0p5-nocache_sus_BA10-UNION.eval"

# Only the RF3 halves are new; the pre-repair halves were extracted for the earlier report.
extract_one() {
  local f="$1"
  [[ -s "$f" ]] || { echo "MISSING $f" >&2; return 1; }
  echo "[$(date -u +%H:%M:%S)] extract start $(basename "$f")"
  uv run python experiments/analysis/streaming_log_extract.py "$f" \
      > "$LOGDIR/extract_$(basename "$f" .eval).log" 2>&1
  local rc=$?
  echo "[$(date -u +%H:%M:%S)] extract done  $(basename "$f") rc=$rc"
  return $rc
}

metrics_one() {
  local arm="$1" n="$2"
  local a b hon ragg tag
  if [[ "$arm" == tm ]]; then
    hon="$TM_HON"; ragg=""
    if [[ "$n" == base ]]; then a="${TM_ORIG}.eval"; b="${TM_RF3B}.eval"
    else a="${TM_ORIG}_actions${n}.eval"; b="${TM_RF3}_actions${n}.eval"; fi
  else
    hon="$DTR_HON"; ragg="--resample-agg q90"
    if [[ "$n" == base ]]; then a="${DTR_ORIG}.eval"; b="${DTR_RF3B}.eval"
    else a="${DTR_ORIG}_actions${n}.eval"; b="${DTR_RF3}_actions${n}.eval"; fi
  fi
  tag="${arm}_${n}"
  echo "[$(date -u +%H:%M:%S)] metrics start $tag"
  uv run python experiments/analysis/compute_metrics.py \
      --safety "$a" "$b" \
      --usefulness $hon \
      --sus-keys suspicion_score__tu-root-history \
      --attack-threshold 0 \
      --pool-runs dedup_latest_strict \
      $ragg \
      --bootstrap-ci --n-bootstrap 500 --bootstrap-seed 0 \
      > "$LOGDIR/compute_${tag}.log" 2>&1
  local rc=$?
  echo "[$(date -u +%H:%M:%S)] metrics done  $tag rc=$rc"
  return $rc
}
export -f extract_one metrics_one
export LOGDIR TOW TM_ORIG TM_RF3B TM_RF3 TM_HON DTR_ORIG DTR_RF3B DTR_RF3 DTR_HON

echo "STAGE 1: streaming extracts of the RF3 halves (${EXTRACT_JOBS}-wide)"
{ echo "${TM_RF3B}.eval"; echo "${DTR_RF3B}.eval"
  for n in $NS; do echo "${TM_RF3}_actions${n}.eval"; echo "${DTR_RF3}_actions${n}.eval"; done
} | xargs -P "$EXTRACT_JOBS" -I{} bash -c 'extract_one {}'
stage1=$?
if [[ $stage1 -ne 0 ]]; then
  echo "STAGE 1 FAILED (xargs rc=$stage1) -- not running metrics on incomplete extracts" >&2
  exit $stage1
fi

echo "STAGE 2: compute_metrics (${METRIC_JOBS}-wide, warm extracts)"
{ for arm in tm dtr; do echo "$arm base"; for n in $NS; do echo "$arm $n"; done; done; } \
  | xargs -P "$METRIC_JOBS" -L1 bash -c 'metrics_one "$@"' _
stage2=$?
if [[ $stage2 -ne 0 ]]; then
  echo "STAGE 2 FAILED (xargs rc=$stage2) -- some cells are NOT cached" >&2
  exit $stage2
fi
echo "ALL DONE"
