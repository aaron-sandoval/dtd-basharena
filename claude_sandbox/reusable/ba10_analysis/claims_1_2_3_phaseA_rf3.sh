#!/usr/bin/env bash
# RF3-REPAIRED variant of claims_1_2_3_phaseA_autosubmit.sh. Regenerates the Phase-A
# design-gate KEY figure (claims 1/2/3) with the three post-hoc replay ATTACK arms
# (rem / root / FHE) replaced by their *_RERUN_FLAG3 pooled cells — [original _autosubmit,
# RF3 rerun of the flag>=3 samples] under pool_runs="dedup_latest_strict" (an errored rerun
# DROPS the task, never falls back to the damaged original row). Cell 3 (A8b no-summary,
# promptfix) is an IN-LOOP auto-submit run with no RF3 slot and is carried through
# UNCHANGED. Honest arms are untouched, so the usefulness figures are NOT regenerated.
#
# The paired significance PDFs (claims 1.2 / 2.2 / 3.1) are deliberately NOT regenerated:
# all four signif analyses were dropped from the claims doc per user decision 2026-09-02.
#
# Prereqs: RF3 extracts streamed and the metrics cache warmed for every Phase-A RF3 cell —
#   uv run python claude_sandbox/reusable/ba10_analysis/warm_566_cache.py --arm-set rf3
# (warms BOTH cache keys per cell; kwargs incl. pool_runs read off the group registry).
#
# Usage:  bash claude_sandbox/reusable/ba10_analysis/claims_1_2_3_phaseA_rf3.sh

source "$(dirname "${BASH_SOURCE[0]}")/anchors.sh"

# STYLE: this figure carries the naming and formatting of its predecessor,
# 20260829T024616Z_claims1-2-3_phaseA_four-variants_BA10_autosubmit_A8b_DROPFLAG4.pdf
# (verified pixel-identical when replayed on the DROPFLAG4 cells), so the two
# revisions are directly comparable by eye:
#   * Series are named "Variant 1..4" and NOT re-ordered relative to that figure:
#     1=rem (incumbent), 2=root, 3=no-summary A8b, 4=FHE. Note this is NOT the
#     group index order (rem, root, FHE, nosum) -- cells 3 and 4 are swapped on
#     purpose. Which design each variant is stays recoverable from the cover page.
#   * Deliberately OFF the protocol-style registry (all four series are DTD, which
#     the registry would draw as one hue x four lightnesses): default-cycle colors
#     C0..C3 with markers ^ P X *, DTD's triangle for the incumbent and
#     non-protocol shapes for the three axis variants.
#   * No --title (house style; the cover page holds the RF3 / dedup_latest_strict
#     identity), equal-aspect axes at a shared 0.05 tick interval, figsize 3.5x3.5.

echo "=== KEY FIGURE (four designs, RF3-repaired safety on rem/root/FHE; A8b unchanged) ==="
uv run python experiments/analysis/plot_safety_usefulness.py \
  --series-groups "TOWER_PHASE_A_DTD_ATTACK_RERUN_FLAG3[0]" "TOWER_PHASE_A_DTD_HONEST[0]" "Variant 1" \
  --series-groups "TOWER_PHASE_A_DTD_ATTACK_RERUN_FLAG3[1]" "TOWER_PHASE_A_DTD_HONEST[1]" "Variant 2" \
  --series-groups "TOWER_PHASE_A_DTD_ATTACK_AUTOSUBMIT[3]"  "TOWER_PHASE_A_DTD_HONEST[3]" "Variant 3" \
  --series-groups "TOWER_PHASE_A_DTD_ATTACK_RERUN_FLAG3[2]" "TOWER_PHASE_A_DTD_HONEST[2]" "Variant 4" \
  --series-color C0 --series-color C1 --series-color C2 --series-color C3 \
  --series-marker "^" --series-marker P --series-marker X --series-marker "*" \
  --figsize 3.5 3.5 --equal-aspect --tick-interval 0.05 \
  --trusted $TRUSTED --honest-baseline $UH --ci-width 0.95 --task-ids BA10_UNION \
  --out "$OUT/$(ts)_claims1-2-3_phaseA_four-designs_BA10_autosubmit_A8b_RF3.pdf"

echo "PHASE_A_RF3_FIGURES_DONE"
