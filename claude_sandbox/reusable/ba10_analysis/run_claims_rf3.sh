#!/usr/bin/env bash
# Regenerate every attack-bearing claim figure against the RF3-REPAIRED attack arms
# (the *_RERUN_FLAG3 groups: [original _autosubmit, RF3 rerun of the flag>=3 samples]
# pooled under dedup_latest_strict — an errored rerun DROPS the task, never falls back
# to the damaged original row). Honest arms/anchors are UNCHANGED, so usefulness does
# not move — only safety / ASR / UASR / AAR / AUROC / bounds change.
#
# NOT run here, per user decisions 2026-09-02:
#   - the four paired-significance PDFs (claims 1.2/2.2/3.1/4.1) — analyses deleted;
#   - claim 6 give-up-N / first-audit — permanently kept on the pre-repair
#     counterfactuals (no _actionsN rebuild from the RF3 logs);
#   - the two transcription bar figures (claims 3/4.1 safety bars, plan-delivery bars)
#     — their PANEL/ARMS literals are hand-updated from the compare reports this
#     script produces, then rerun separately.
#
# Prereqs (run first, in order):
#   1. streaming extracts for the 13 RF3 logs + the _rf3excl8 original (sequential);
#   2. uv run python claude_sandbox/reusable/ba10_analysis/warm_566_cache.py --arm-set rf3
#   3. the Phase-0 gate: uv run python experiments/analysis/rerun_flag3/verify_rf3_groups.py
#
# Usage:  bash claude_sandbox/reusable/ba10_analysis/run_claims_rf3.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
D=claude_sandbox/reusable/ba10_analysis

echo "########## CLAIMS 1/2/3 — Phase-A design gate (RF3-repaired safety) ##########"
bash "$D/claims_1_2_3_phaseA_rf3.sh"

echo "########## CLAIMS 3.1/4.1 — compare reports feeding the safety-bar literals ##########"
uv run python experiments/analysis/compare_protocols.py \
  --cohort phase-a-dtd-rf3 --task-ids BA10_UNION --bootstrap-ci --pdf

echo "########## CLAIM 4.1 — plan-exposure ladder + planner-matched pair (RF3) ##########"
uv run python experiments/analysis/compare_protocols.py \
  --cohort plan-ladder-rf3 --task-ids BA10_UNION --bootstrap-ci --pdf
uv run python experiments/analysis/compare_protocols.py \
  --cohort planshare-pair-rf3 --task-ids BA10_UNION --bootstrap-ci --pdf

echo "########## CLAIM 7 — attack-selection safety (RF3-repaired TM/DTRF) ##########"
uv run python claude_sandbox/reusable/claim7_attack_selection_safety.py \
  --protocol-set ba10_noplan_rf3 --dtrf-resample-agg q90 --xscale log --task-ids BA10_UNION

echo "########## CLAIM 10 — DTD no-plan point vs the DTRF q90 front (RF3) ##########"
uv run python claude_sandbox/reusable/ba10_analysis/claim101_pareto_noplan_point.py --arm-set rf3 --task-ids BA10_UNION
uv run python "$D/claim10_truncation_bounds.py" --truncated --arm-set rf3 --resample-agg q90 --task-ids BA10_UNION

echo "########## CLAIM 11 — CES vs the DTD no-plan point + TM (RF3) ##########"
uv run python "$D/claim11_ces_vs_noplan_front.py" --arm-set rf3 --task-ids BA10_UNION

echo "########## CLAIM 6 (DTD) — base vs child-0-only compare (in-loop arms, re-run per user instruction) ##########"
L=experiments/_logs/tower
RH=suspicion_score__tu-root-history
DTD_NOPLAN=$L/2026-08-20T22-18-47_566_attack_online-dtd-v11.1-thr2p333-withtips-noplan_BA10-UNION566.eval
DTD_NOPLAN_C0=${DTD_NOPLAN%.eval}_child0only.eval
DTD_NOPLAN_HON=$L/2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval
# Inputs are in-loop and untouched by RF3 — the numbers must reproduce the cited
# 20260826T001436Z compare (safety 0.850 -> 0.920); flag any drift, don't substitute silently.
uv run python experiments/analysis/compare_protocols.py \
  --protocol "DTD thr2.333 no-plan (base)"         "$DTD_NOPLAN"    "$DTD_NOPLAN_HON" \
  --protocol "DTD thr2.333 no-plan (child-0 only)" "$DTD_NOPLAN_C0" "$DTD_NOPLAN_HON" \
  --sus-keys "$RH" --attack-threshold 0 --attack-threshold 0 \
  --task-ids BA10_UNION --pdf --bootstrap-ci

echo "ALL_RF3_CLAIMS_DONE"
