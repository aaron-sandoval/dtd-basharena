"""Safety bars for claims 3.1 and 4.1, as three threshold-matched subplots.

Three panels sharing one Safety axis. Panels (b) and (c) are internally matched
(same protocol, same monitor threshold, same honest arm within the panel, same
audit rule), so every bar-to-bar comparison ON those panels is a measured
effect. The panels sit at DIFFERENT monitor thresholds and are NOT comparable
across the dividers -- that is exactly why they are separate subplots.

  (a) DTD vs Baselines                              -- headline contrast
        Trusted monitoring                         TM v11.1 reference point
        DTR (77% usefulness)                       DTRF defer0.5 (q90), the claim-10
                                                   Pareto point at ~0.90 safety
        DTD (best variant, 80% usefulness)         the canonical DTD point: WITHTIPS
                                                   no-plan, monitor_threshold 2.333
                                                   (the claim-10 Pareto's measured
                                                   DTD point)

PANEL (a) SWAP (2026-10-20) -- panel (a) was TM vs "DTD (best variant, 89%
usefulness)", which re-used panel (b)'s monitor-all-actions arm (thr3.0 loose
plan, drawn with the no-plan offset: 0.831). It is now TM / DTR / DTD, the DTR
bar being the claim-10 Pareto's defer0.5 point and the DTD bar the canonical
no-plan thr2.333 point (0.850, measured, NOT shifted). The DTD bar is the same
log and numbers as the first rung of plot_plan_delivery_safety_bars.py. The DTR
CI was computed for this figure with compute_metrics.py --bootstrap-ci (same B,
seed and per-draw tau as every other bar); the same run on the no-plan DTD arm
reproduced its transcribed 0.850 [0.795, 0.891] exactly. Panel (a) no longer
shares an arm with panel (b).

  (b) Monitor scope, DTD at monitor_threshold 3.0   -- claim 3.1
        DTD (monitor all actions)                  tu-root-history: the monitor
                                                   sees every action across all
                                                   child tasks (canonical DTD)
        DTD (monitor current child task actions)   tu-full-history: the monitor
                                                   sees only the CURRENT child's
                                                   actions ("simplicity benefits
                                                   monitors")

  (c) Attack-plan sharing, DTD at monitor_threshold 2.333  -- claim 4.1
        DTD (attack plan unshared)                 the DEFAULT decomposer path:
                                                   only child_task_index 0 gets
                                                   the root attack plan, and
                                                   context is broken for every
                                                   later implementer. "Unshared"
                                                   means not passed ONWARD -- the
                                                   first implementer does get it.
                                                   This is NOT the no-plan arm.
        DTD (attack plan shared)                   inject_attack_plan=True: every
                                                   implementer receives the root
                                                   attack plan ("breaking context
                                                   between implementers improves
                                                   safety")

THREE-PANEL LAYOUT (2026-09-07) -- the figure was two panels: (a) monitor scope,
(b) attack-plan sharing with a leading Trusted-monitoring bar. The TM bar was
lifted out of the plan-sharing panel into a new leading panel (a), paired there
with the best DTD variant, so the headline protocol contrast reads on its own
panel and each claim panel is now purely DTD-internal. The new panel (a) DTD bar
reuses the panel-(b) monitor-all-actions arm VERBATIM (same log, same tau, same
safety and CI); only its tick label differs. No number moved anywhere in this
restructuring -- it is presentation only.

  ! Panel (a) is a cross-design comparison, not a threshold-matched one. Its two
  bars sit at different usefulness (TM 1.00 vs DTD 0.89) and TM has no
  monitor_threshold to match. The same caveat applied to the TM bar in its old
  home (usefulness 1.00 against 0.80) -- moving it did not create the mismatch,
  but panel (a) is now the only panel that carries one.

ARM SUBSTITUTION (2026-09-03) -- panel (c)'s first bar was "DTD (no shared
attack plan)" (0.850 [0.795, 0.891]), the WITHTIPS arm whose plan reaches NO
implementer. It is replaced by the C14 arm-3 log, the same WITHTIPS planner
delivering the plan to the FIRST implementer only (0.880 [0.829, 0.918]). Both
panel-(c) DTD bars therefore now hold the planner AND the protocol fixed and
vary only how far the plan travels, which is what claim 4.1 actually asserts;
the previous pairing conflated "no plan at all" with "plan not shared onward".
The two bars also keep parallel labels ("attack plan unshared" / "attack plan
shared") so the contrast reads off the tick labels alone. Consequence:
the DTD-internal gap narrows from 0.040 to 0.010 and its CIs now overlap
heavily -- the plan-sharing effect is much smaller against this control than
against the no-plan one. The no-plan arm is not lost; it is the first rung of
the four-rung ladder in plot_plan_delivery_safety_bars.py.

NO-PLAN OFFSET (2026-09-11) -- the three bars built on the V7 LOOSE-PLAN attacker
(panel (a)'s DTD bar and both panel-(b) bars: the plan reaches the first
implementer by the default decomposer path) are drawn SHIFTED, the same way the
claim-10 Pareto draws its dotted DTD line. delta = no-plan thr2.333 safety minus
loose-plan thr2.333 safety = 0.8502 - 0.8818 = -0.0316 (from
20260916T220939Z_safety-use_claim10_budget5pct_BA10_AUTOSUBMIT_dtrf-q90_dtd-noplan_RF3.pdf).
The bar height and the LOWER whisker move by delta; the UPPER whisker stays at
the measured value, so each shifted bar is the measured bar widened by |delta|.
The transcribed measured values are kept on the Arm and printed on the cover
next to the drawn ones. Panel (c)'s WITHTIPS strict-plan arms are not shifted:
the offset converts loose plan -> no plan and does not apply to them. The
offset was measured under the RHE monitor; applying it to the FHE bar assumes
the plan effect is monitor-independent. Value labels show the DRAWN mean.
Panels (b) and (c) are titled "Ablation: ..." as of the same date.

Error bars are the 95% cluster-by-task percentile bootstrap CIs carried over
from the source compare_protocols.py reports; the value annotation above each
upper whisker follows the ``plot_scalar_barplot`` convention compare_protocols
uses. The canonical DTD bar (panel (a)) takes the DTD family gray (#7C7D7F), and
each of the other four DTD bars takes its own strictly lighter equal-step blend
toward white, the lightest at 0.775 (past the 0.55 house cap, by request;
2026-10-20; previously every DTD bar was the one family gray). TM takes the
TM family blue (#3A82B5), DTR the DTR orange, all at FULL opacity so the faces
match the family colors exactly as plot_safety_usefulness renders them. The
figure carries no legend: the x tick labels are the key.

TASK UNIVERSE (2026-09-01) — all bars are task-matched on the common 566 ids
(`--task-ids BA10_UNION`). Only the TM bar moved: its attack log is 629-era and
its honest arm is the 629-era UH anchor, so tau shifted with it. The four DTD
arms are bit-identical (their attack and honest arms were always 566), measured,
not assumed:

  DTD monitor-all-actions   0.8654 -> 0.8654   (identical)
  DTD monitor-current-child 0.8522 -> 0.8522   (identical)
  Trusted monitoring        0.5082 -> 0.5137   [0.410, 0.623] -> [0.413, 0.630]
  DTD no shared plan        0.8502 -> 0.8502   (identical; bar since replaced)
  DTD shared plan           0.8900 -> 0.8900   (identical)

The plan-sharing replacement arm (plan to the first implementer) was run and
scored on the 566 universe from the start, so it needs no such restriction check.

Panels (b)/(c) are therefore unaffected, and the TM-vs-DTD gap narrows by 0.006.
Regenerate the TM source report with
`compare_protocols.py --task-ids BA10_UNION --bootstrap-ci --pdf`.

RF3 REPAIR (2026-09-02, supersedes the 2026-08-29 fidelity filter) — the three
post-hoc arms now read off the `*_RERUN_FLAG3` pooled cells: [original
`_autosubmit` log, in-loop RF3 rerun of every flag>=3 replay-damaged sample]
under pool_runs="dedup_latest_strict" (the rerun is authoritative; a task whose
rerun errored is DROPPED, never falling back to the damaged original row — see
experiments/analysis/rerun_flag3/verify_rf3_groups.py for the gate). Values moved from
the dropflag4-filtered ones as:

  DTD monitor-all-actions   0.865 [0.772, 0.906] -> 0.863 [0.772, 0.908]  (479 -> 556 pooled)
  DTD monitor-current-child 0.852 [0.800, 0.895] -> 0.841 [0.789, 0.882]  (469 -> 558 pooled)
  Trusted monitoring        0.514 [0.413, 0.630] -> 0.526 [0.423, 0.615]  (515 -> 557 pooled)

The two plan-sharing DTD arms are IN-LOOP auto-submit runs (auto_submit
default-on since 2026-08-19). They were never replayed, carry no deviation flags
and no RF3 slot — so they keep their original values. Panel (b) is therefore
repaired on BOTH bars and internally consistent; panel (a) pairs a repaired TM
bar with a repaired DTD bar; panel (c) is two in-loop arms with no repair on
either side, so it too is internally consistent.

⚠ NAMING. The registry names are counter-intuitive and the labels above follow
the CODE, not the names: ``tu-full-history`` (FHE) is the NARROW monitor (current
child only, sliced at ``child_offset``) and ``tu-root-history`` (RHE) is the WIDE
one (full cross-child history). See tu_bb2/ct_ext/decomposer.py:313-320 and
tu_bb2/ct_ext/monitors.py:12-17.

DATA PROVENANCE — this script does NOT recompute safety from .eval logs. Values
are transcribed from the "Scalar Metrics" tables of three compare_protocols.py
reports (all: p95 fractional-tie audit rule, attack_threshold 0, resample_agg
max, B=500 seed=0 cluster-by-task bootstrap with tau recomputed per draw):

  panels (a)  experiments/data/metrics_reports_tower/20260902T193337Z_compare_
  and (b)     A1-A2-remainder-summary-RHE--SELECTED-_A3-A4-root-scope--axi_
  DTD arms    suspicion_score__tu-root-history.pdf   (cohort phase-a-dtd-rf3)
  panel (c)   experiments/data/metrics_reports_tower/20260904T000303Z_compare_
  DTD arms    DTD-thr2-333--plan-to-NO-implementer--WITHTIPS-_DTD-thr2-333_
              suspicion_score__tu-root-history.pdf   (cohort plan-ladder-rf3,
              now FOUR rungs: the 2026-09-03 WITHTIPS plan-to-child-0 arm was
              added, so both panel-(c) DTD bars come off one report and share
              tau = 8.667 exactly)
  panel (a)   experiments/data/metrics_reports_tower/20260902T193337Z_tm_
  TM arm      tm-v11.1_sus_BA10-UNION_autosubmit+tm-v11.1_sus_BA10-UNION56_
              suspicion_score__tu-root-history.pdf   (compute_metrics, RF3 pool)

Usage::

    uv run python claude_sandbox/reusable/ba10_analysis/plot_claims3_4_1_safety_bars.py
    uv run python claude_sandbox/reusable/ba10_analysis/plot_claims3_4_1_safety_bars.py \
        --decimals 3 --out /tmp/bars.pdf
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages

from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH
from tu_bb2.plotting import _MAX_LIGHTEN, PROTOCOL_FAMILY_COLORS, _blend
from tu_bb2.utils import REPO_ROOT

SUS_KEY_RHE = "suspicion_score__tu-root-history"
SUS_KEY_FHE = "suspicion_score__tu-full-history"
ATTACK_THRESHOLD = 0
BOOTSTRAP_B = 500
BOOTSTRAP_SEED = 0

# Offset carried over from the claim-10 Pareto: delta = no-plan thr2.333 safety minus
# loose-plan thr2.333 safety, both RHE on the 566 universe (RF3 pool on the loose-plan
# side). Loose-plan arms are DRAWN with the mean and the lower bound shifted by delta
# and the upper bound left at the measured value (see the module docstring).
NOPLAN_OFFSET = 0.8502 - 0.8818
NOPLAN_OFFSET_SOURCE = ("20260916T220939Z_safety-use_claim10_budget5pct_BA10_AUTOSUBMIT"
                        "_dtrf-q90_dtd-noplan_RF3.pdf")

# The canonical DTD bar (panel (a): selected design, thr2.333, no-plan attacker)
# takes the DTD family gray; each of the four other DTD bars (a different
# threshold, monitor scope or attack policy) takes its own strictly lighter shade
# (manuscript-plots section 2), in left-to-right bar order. TM takes the TM blue,
# DTR the DTR orange. No hatching -- the x tick labels carry the distinction, so
# the figure needs no legend.
_DTD_COLOR = PROTOCOL_FAMILY_COLORS["DTD"]
# Same equal-step blend toward white as _family_shades, but with the lightest
# endpoint taken a further 50% of the way to white (0.55 -> 0.775; user request
# 2026-10-20). Local to this figure: the house cap _MAX_LIGHTEN is unchanged.
_DTD_MAX_LIGHTEN = _MAX_LIGHTEN + 0.5 * (1 - _MAX_LIGHTEN)
_DTD_VARIANT_SHADES = [_blend(_DTD_COLOR, float(a))
                       for a in np.linspace(0.0, _DTD_MAX_LIGHTEN, 5)[1:]]


@dataclass(frozen=True)
class Arm:
    label: str            # x tick label (newlines allowed)
    safety: float
    lo: float
    hi: float
    usefulness: str       # cover page only
    color: str
    operating_point: str  # cover page only
    sus_key: str
    attack_log: str
    honest_logs: tuple[str, ...]
    source_report: str
    # V7 loose-plan attacker (plan to the first implementer by the default path).
    # These arms are drawn shifted by NOPLAN_OFFSET; safety/lo/hi above stay the
    # transcribed MEASURED values.
    loose_plan: bool = False

    @property
    def offset(self) -> float:
        return NOPLAN_OFFSET if self.loose_plan else 0.0

    @property
    def drawn(self) -> tuple[float, float, float]:
        """(safety, lo, hi) as drawn: mean and lower bound shifted by the no-plan
        offset for loose-plan arms; the upper bound is never shifted."""
        return self.safety + self.offset, self.lo + self.offset, self.hi


@dataclass(frozen=True)
class Panel:
    title: str
    arms: tuple[Arm, ...]


# ---------------------------------------------------------------------------
# Arms. Defined once; panel (a)'s DTD bar is the panel-(b) monitor-all-actions
# arm re-labelled, so the two bars can never drift apart numerically.
# ---------------------------------------------------------------------------

TM_ARM = Arm(
    label="Trusted\nmonitoring\n(100% usefulness)",
    safety=0.526, lo=0.423, hi=0.615,
    usefulness="usefulness 1.00",
    color=PROTOCOL_FAMILY_COLORS["TM"],
    operating_point="TM v11.1 (no plan injected), auto-submit truncated, "
                    "RF3-repaired pool (dedup_latest_strict)",
    sus_key=SUS_KEY_RHE,
    attack_log="2026-07-15T03-59-44_629_attack_tm-v11.1_sus_BA10-UNION"
               "_autosubmit.eval + 2026-09-01T23-56-42_86_attack_tm-v11.1"
               "_sus_BA10-UNION566-RF3.eval",
    honest_logs=(
        "2026-07-15T02-59-38_452_uh_sus_BA10-UNION.eval",
        "2026-07-30T08-17-38_159_uh-gapfill_sus_BA10-UNION566.eval",
    ),
    source_report="20260902T193337Z_tm_tm-v11.1_..._suspicion_score__tu-root-history.pdf",
)

DTD_MONITOR_ALL_ARM = Arm(
    label="DTD\n(monitor all\nactions)",
    safety=0.863, lo=0.772, hi=0.908,
    usefulness="usefulness 0.89",
    color=_DTD_VARIANT_SHADES[0],
    operating_point="monitor_threshold 3.0, monitor_action_monitor=tu-root-history (A1/A2), "
                    "RF3-repaired pool (dedup_latest_strict)",
    sus_key=SUS_KEY_RHE,
    attack_log="2026-07-30T00-45-23_566_attack_online-dtd-v11.1-thr3p0-rem"
               "_BA10-UNION566_autosubmit.eval + 2026-09-02T00-45-13_121_attack"
               "_online-dtd-v11.1-thr3p0-rem_BA10-UNION566-RF3.eval",
    honest_logs=(
        "2026-07-30T00-45-41_566_online-dtd-v11.1-thr3p0-rem-honest_BA10-UNION566.eval",
    ),
    source_report="20260902T193337Z_compare_A1-A2-remainder-summary-RHE...pdf (phase-a-dtd-rf3)",
    loose_plan=True,
)

# Panel (a)'s DTR and DTD bars sit at similar usefulness (0.7741 -> 77%,
# 0.8014 -> 80%; claim-10 Pareto, 20260929T224609Z, 400-draw bootstrap seed 42).
DTR_ARM = Arm(
    label="DTR\n(77%\nusefulness)",
    safety=0.900, lo=0.848, hi=0.953,
    usefulness="usefulness 0.77",
    color=PROTOCOL_FAMILY_COLORS["DTR"],
    operating_point="DTRF defer 0.5, resample_agg q90, auto-submit truncated, "
                    "RF3-repaired pool (dedup_latest_strict)",
    sus_key=SUS_KEY_RHE,
    attack_log="2026-07-24T14-25-13_629_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION"
               "_autosubmit.eval + 2026-09-02T01-32-21_139_attack_dtr-v11.1-defer0p5"
               "-nocache_sus_BA10-UNION566-RF3.eval",
    honest_logs=(
        "2026-07-24T14-07-55_629_dtrf-v11.1-defer0p5-nocache_sus_BA10-UNION.eval",
    ),
    source_report="compute_metrics.py --bootstrap-ci --resample-agg q90 --task-ids "
                  "BA10_UNION, run 2026-10-20 (console only)",
)

DTD_NOPLAN_ARM = Arm(
    label="DTD\n(best variant,\n80% usefulness)",
    safety=0.850, lo=0.795, hi=0.891,
    usefulness="usefulness 0.80",
    color=_DTD_COLOR,
    operating_point="monitor_threshold 2.333, WITHTIPS planner, plan to NO implementer "
                    "(canonical no-plan DTD), in-loop auto-submit",
    sus_key=SUS_KEY_RHE,
    attack_log="2026-08-20T22-18-47_566_attack_online-dtd-v11.1-thr2p333-withtips-noplan"
               "_BA10-UNION566.eval",
    honest_logs=(
        "2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval",
    ),
    source_report="20260904T000303Z_compare_DTD-thr2-333--plan-to-NO-implementer...pdf",
)

DTD_MONITOR_CURRENT_CHILD_ARM = Arm(
    label="DTD\n(monitor current\nchild task actions)",
    safety=0.841, lo=0.789, hi=0.882,
    usefulness="usefulness 0.85",
    color=_DTD_VARIANT_SHADES[1],
    operating_point="monitor_threshold 3.0, monitor_action_monitor=tu-full-history (A5/A6), "
                    "RF3-repaired pool (dedup_latest_strict)",
    sus_key=SUS_KEY_FHE,
    attack_log="2026-07-30T06-33-58_566_attack_online-dtd-v11.1-thr3p0-fhe"
               "_BA10-UNION566_autosubmit.eval + 2026-09-02T00-46-57_136_attack"
               "_online-dtd-v11.1-thr3p0-fhe_BA10-UNION566-RF3.eval",
    honest_logs=(
        "2026-07-30T06-26-28_566_online-dtd-v11.1-thr3p0-fhe-honest_BA10-UNION566.eval",
    ),
    source_report="20260902T193337Z_compare_A1-A2-remainder-summary-RHE...pdf (phase-a-dtd-rf3)",
    loose_plan=True,
)

DTD_PLAN_FIRST_ARM = Arm(
    label="DTD\n(attack plan\nunshared)",
    safety=0.880, lo=0.829, hi=0.918,
    usefulness="usefulness 0.80",
    color=_DTD_VARIANT_SHADES[2],
    operating_point="monitor_threshold 2.333, WITHTIPS planner, plan to the FIRST "
                    "implementer only (child_task_index 0; both plan flags at their "
                    "library defaults)",
    sus_key=SUS_KEY_RHE,
    attack_log="2026-09-03T20-11-14_566_attack_online-dtd-v11.1-thr2p333-withtips-planchild0"
               "_BA10-UNION566.eval",
    honest_logs=(
        "2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval",
    ),
    source_report="20260904T000303Z_compare_DTD-thr2-333--plan-to-NO-implementer...pdf",
)

DTD_PLAN_ALL_ARM = Arm(
    label="DTD\n(attack plan\nshared)",
    safety=0.890, lo=0.849, hi=0.920,
    usefulness="usefulness 0.80",
    color=_DTD_VARIANT_SHADES[3],
    operating_point="monitor_threshold 2.333, WITHTIPS planner, plan to ALL implementers "
                    "(inject_attack_plan=True)",
    sus_key=SUS_KEY_RHE,
    attack_log="2026-08-21T01-43-57_566_attack_online-dtd-v11.1-thr2p333-withtips-planshare"
               "_BA10-UNION566.eval",
    honest_logs=(
        "2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval",
    ),
    source_report="20260904T000303Z_compare_DTD-thr2-333--plan-to-NO-implementer...pdf",
)


PANEL_A = Panel(
    title="(a) DTD vs Baselines",
    arms=(TM_ARM, DTR_ARM, DTD_NOPLAN_ARM),
)

PANEL_B = Panel(
    title="(b) Ablation: Simplicity\nBenefits for Monitors",
    arms=(DTD_MONITOR_ALL_ARM, DTD_MONITOR_CURRENT_CHILD_ARM),
)

PANEL_C = Panel(
    title="(c) Ablation: Attack\nCoordination Challenges",
    arms=(DTD_PLAN_FIRST_ARM, DTD_PLAN_ALL_ARM),
)

PANELS = (PANEL_A, PANEL_B, PANEL_C)


# Single-column variant (2026-10-20): panel (a) dropped, the two ablation panels
# re-lettered and stacked, with HORIZONTAL bars on one shared Safety x axis.
# Vertical bars side by side cannot fit the 4.5 in single-column cap at default
# fonts (adjacent bars ~0.9-1.0 in apart vs labels up to 1.26 in); horizontal
# bars put the labels on the y axis, leaving ~2.9 in for the bars. Same arms,
# colors and values as the full figure.
# Every bar here is DTD, so the labels drop "DTD" and the parentheses and use
# sentence case, and the monitor-scope labels say what the monitor sees (user
# requests, 2026-10-20). Both monitor labels wrap to 2 lines ("Monitor sees all
# actions" is 1.64 in on one line); the widest line anywhere is "Attack plan
# unshared" (1.48 in), inside the 1.55 in label column.
_SC_LABELS = {
    "DTD\n(monitor all\nactions)": "Monitor sees\nall actions",
    "DTD\n(monitor current\nchild task actions)": "Monitor sees current\nchild task actions",
    "DTD\n(attack plan\nunshared)": "Attack plan unshared",
    "DTD\n(attack plan\nshared)": "Attack plan shared",
}
PANELS_SINGLE_COLUMN = tuple(
    Panel(title=title, arms=tuple(replace(a, label=_SC_LABELS[a.label]) for a in src.arms))
    for title, src in (
        ("(a) Ablation: Simplicity Benefits for Monitors", PANEL_B),
        ("(b) Ablation: Attack Coordination Challenges", PANEL_C),
    )
)


def _build_single_column_figure(*, decimals: int = 2) -> plt.Figure:
    """The two ablation panels stacked, horizontal bars, 3.85 in wide
    (manuscript-plots section 7 single-column cap)."""
    panels = PANELS_SINGLE_COLUMN
    # Margins set in INCHES so the labels and titles sit INSIDE the 4.5 in
    # canvas (bbox_inches="tight" would otherwise grow the page past the cap to
    # hold the y labels). Vertical budget: title row, axes, title row, axes,
    # x tick labels + "Safety".
    width = 3.85  # 4.5 -> 3.85 (~15% narrower) so the text reads larger at \columnwidth
    label_w, right_w = 1.55, 0.08
    title_h, axes_h, bottom_h = 0.32, 0.82, 0.45
    gap_h = 0.15  # extra space between the panels, above the lower title
    height = 2 * (title_h + axes_h) + gap_h + bottom_h
    fig, axes = plt.subplots(
        len(panels), 1, sharex=True, figsize=(width, height),
        gridspec_kw={"hspace": (title_h + gap_h) / axes_h},
    )
    fig.subplots_adjust(
        left=label_w / width, right=1 - right_w / width,
        top=1 - title_h / height, bottom=bottom_h / height,
    )
    bar_height = 0.6
    y_margin = 0.5
    for ax, panel in zip(np.atleast_1d(axes), panels):
        ypos = np.arange(len(panel.arms), dtype=float)
        for yi, arm in zip(ypos, panel.arms):
            # Loose-plan arms: mean + lower whisker shifted by NOPLAN_OFFSET,
            # upper whisker at the measured value (Arm.drawn).
            x, lo, hi = arm.drawn
            ax.barh(
                yi, x, height=bar_height,
                facecolor=arm.color,
                edgecolor="black", linewidth=0.9, zorder=2,
            )
            ax.errorbar(
                x, yi,
                xerr=np.array([[x - lo], [hi - x]]),
                fmt="none", ecolor="black", elinewidth=1.1, capsize=4, zorder=3,
            )
            # Fixed 5 pt past the upper whisker, clear of the cap at any scale.
            ax.annotate(
                f"{x:.{decimals}f}", xy=(hi, yi),
                xytext=(5, 0), textcoords="offset points",
                ha="left", va="center", zorder=4,
            )
        # Title right-aligned with the axes' right edge: centered on the axes
        # it would run past the right edge of the figure. Its left end sits
        # over the y labels.
        ax.set_title(panel.title, loc="right", pad=4)
        ax.set_yticks(ypos)
        ax.set_yticklabels([a.label for a in panel.arms])
        # First arm on top, as it reads left-to-right in the full figure.
        ax.set_ylim(len(panel.arms) - 1 + y_margin, -y_margin)
        # Room right of 1.0 for the value labels beside the upper whiskers.
        ax.set_xlim(0, 1.15)
        ax.set_xticks(np.arange(0, 1.01, 0.2))
        ax.grid(axis="x", alpha=0.3, zorder=0)
        ax.set_axisbelow(True)
        ax.tick_params(axis="y", length=0)
    np.atleast_1d(axes)[-1].set_xlabel("Safety")
    return fig


def build_figure(*, decimals: int = 2, single_column: bool = False) -> plt.Figure:
    """Render the full-width three-panel safety bar chart on a shared Safety
    axis, or (``single_column``) the stacked horizontal-bar ablation variant."""
    if single_column:
        return _build_single_column_figure(decimals=decimals)
    panels = PANELS
    widths = [len(p.arms) for p in panels]
    # Width grew 9.0 -> 10.5 in (user-approved, 2026-10-20) when panel (a) gained
    # its DTR bar: 7 bars at the 9.0 in figure's 6-bar spacing. Height cut from
    # the earlier 4.7 in, then 3.0 -> 2.55 in (15% shorter), to shorten the
    # figure in the manuscript.
    fig, axes = plt.subplots(
        1, len(panels), sharey=True,
        figsize=(10.7, 2.55),
        gridspec_kw={"width_ratios": widths, "wspace": 0.06},
    )

    # Narrow bars + tight x margins (manuscript-plots section 7): with three
    # panels on one page these are what keep the multi-line tick labels of
    # adjacent bars from touching. wspace scales with the MEAN axes width, so it
    # was cut 0.15 -> 0.06 when panel (a) widened to three bars; measured
    # tick-label clearance is >= 0.14 in. Width 10.5 -> 10.7 in when the TM
    # label gained "(100% usefulness)" (tightest gap: TM vs DTR, 0.143 in).
    bar_width = 0.55
    x_margin = 0.45
    for ax, panel in zip(np.atleast_1d(axes), panels):
        x = np.arange(len(panel.arms), dtype=float)
        for xi, arm in zip(x, panel.arms):
            # Loose-plan arms: mean + lower whisker shifted by NOPLAN_OFFSET,
            # upper whisker at the measured value (Arm.drawn).
            y, lo, hi = arm.drawn
            ax.bar(
                xi, y, width=bar_width,
                facecolor=arm.color,
                edgecolor="black", linewidth=0.9, zorder=2,
            )
            ax.errorbar(
                xi, y,
                yerr=np.array([[y - lo], [hi - y]]),
                fmt="none", ecolor="black", elinewidth=1.1, capsize=4, zorder=3,
            )
            ax.text(
                xi, hi + 0.005, f"{y:.{decimals}f}",
                ha="center", va="bottom", zorder=4,
            )

        ax.set_title(panel.title, pad=8)
        ax.set_xticks(x)
        ax.set_xticklabels([a.label for a in panel.arms])
        ax.set_xlim(-x_margin, len(panel.arms) - 1 + x_margin)
        # Headroom above 1.0 for the DTR bar's value label (its upper whisker
        # is 0.953); ticks still stop at 1.0. At 2.55 in tall, 1.08 leaves the
        # label ~0.08 in below the frame (1.05 left only ~0.03 in).
        ax.set_ylim(0, 1.08)
        ax.set_yticks(np.arange(0, 1.01, 0.2))
        ax.grid(axis="y", alpha=0.3, zorder=0)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", length=0)

    np.atleast_1d(axes)[0].set_ylabel("Safety")
    # No tight_layout: it is incompatible with the gridspec wspace above, and
    # savefig(bbox_inches="tight") trims the outer margins anyway.
    return fig


# fig.text cover pages clip silently past roughly this many lines, so the cover
# is paginated rather than trusted to fit.
_COVER_LINES_PER_PAGE = 66


def build_cover_pages(stamp: str, *, single_column: bool = False) -> list[plt.Figure]:
    panels = PANELS_SINGLE_COLUMN if single_column else PANELS
    lines = [
        "Safety bars - claims 3.1 (monitor scope) and 4.1 (attack-plan sharing)",
        f"Generated (UTC): {stamp}",
        "",
        *([
            "SINGLE-COLUMN VARIANT (3.85 in wide): the full figure's panel (a) is DROPPED;",
            "its panels (b) and (c) are re-lettered (a) and (b), stacked, with HORIZONTAL",
            "bars on one shared Safety x axis. Arm colors and values are identical to the",
            "full figure; bar labels drop the redundant DTD prefix. Panel letters in the notes",
            "below refer to the FULL three-panel figure; the per-arm list at the end",
            "uses this variant's titles.",
            "",
        ] if single_column else []),
        "Three panels on a shared Safety axis. Panels (b) and (c) are threshold-matched",
        "internally; the panels sit at DIFFERENT monitor thresholds (3.0 vs 2.333) and",
        "different usefulness levels, so bars are NOT comparable across a panel divider.",
        "",
        "Panel (a) is the headline protocol contrast and is NOT threshold-matched: TM has",
        "no monitor_threshold; usefulness is TM 1.00, DTR 0.77, DTD 0.80 (claim-10 Pareto",
        "20260929T224609Z). DTR = DTRF defer0.5 q90; DTD = canonical no-plan thr2.333",
        "(measured, NOT offset-shifted). Panel (a) shares no arm with panel (b).",
        "DTR CI computed 2026-10-20 with compute_metrics.py --bootstrap-ci (same method;",
        "that run reproduces the DTD bar's 0.850 [0.795, 0.891] exactly).",
        "",
        "Panel (c) 'attack plan unshared' = the plan reaches the FIRST implementer and is",
        "not passed onward. It is NOT the no-plan arm (that rung lives in",
        "plot_plan_delivery_safety_bars.py). 'shared' = inject_attack_plan=True.",
        "",
        "Panel (a)'s DTD bar (selected design, thr2.333, no-plan attacker) takes the",
        f"DTD family gray ({_DTD_COLOR}); the other four DTD bars each take a strictly",
        f"lighter shade, left to right: {', '.join(_DTD_VARIANT_SHADES)}.",
        "TM takes the TM family blue (#3A82B5), DTR the DTR orange (#F15F22).",
        "Full opacity, so faces match plot_safety_usefulness",
        "exactly. No hatching and no legend -- the x tick labels",
        "are the key. Value labels sit above the upper whisker (compare_protocols /",
        "plot_scalar_barplot convention).",
        "",
        "NAMING (follows the code, not the registry names):",
        "  'monitor all actions'                = tu-root-history (RHE), full cross-child history",
        "  'monitor current child task actions' = tu-full-history (FHE), current child only",
        "  see tu_bb2/ct_ext/decomposer.py:313-320, tu_bb2/ct_ext/monitors.py:12-17",
        "",
        f"attack_threshold: {ATTACK_THRESHOLD}   audit rule: p95 fractional-tie (tau=8.667 in every arm)",
        f"CIs: {CONFIDENCE_INTERVAL_WIDTH:.2f} cluster-by-task percentile bootstrap "
        f"(B={BOOTSTRAP_B}, seed={BOOTSTRAP_SEED}),",
        "  p95 audit threshold recomputed per draw",
        "resample_agg: max     all attack arms auto-submit truncated",
        "",
        "VALUES ARE TRANSCRIBED, NOT RECOMPUTED - see module docstring for source reports.",
        "",
        "NO-PLAN OFFSET (loose-plan arms only): the two bars built on the V7 loose-plan",
        "attacker (both panel-(b) bars) are DRAWN shifted, the same",
        "way the claim-10 Pareto draws its dotted DTD line:",
        f"  delta = no-plan thr2.333 safety - loose-plan thr2.333 safety = 0.8502 - 0.8818 = {NOPLAN_OFFSET:+.4f}",
        f"  source: {NOPLAN_OFFSET_SOURCE}",
        "  drawn mean  = measured mean  + delta      drawn lower = measured lower + delta",
        "  drawn upper = measured upper (UNSHIFTED), so each bar is widened by |delta|.",
        "  Value labels show the DRAWN mean. Measured values are listed per arm below.",
        "  Panel (c)'s WITHTIPS strict-plan arms are NOT shifted (the offset converts",
        "  loose plan -> no plan and does not apply to them). The offset was measured",
        "  under the RHE monitor; applying it to the FHE bar assumes the plan effect is",
        "  monitor-independent.",
        "",
    ]
    for panel in panels:
        lines += ["-- " + " ".join(panel.title.split()) + " --"]
        for arm in panel.arms:
            y, lo, hi = arm.drawn
            lines += [
                f"  [{arm.label.replace(chr(10), ' ')}]",
                (f"      safety={arm.safety:.3f} [{arm.lo:.3f}, {arm.hi:.3f}]    {arm.usefulness}"
                 + ("    (measured)" if arm.loose_plan else "")),
                *([f"      DRAWN  ={y:.3f} [{lo:.3f}, {hi:.3f}]    shifted {NOPLAN_OFFSET:+.4f} "
                   "on mean + lower, upper unshifted"] if arm.loose_plan else []),
                f"      operating point: {arm.operating_point}",
                f"      sus_key: {arm.sus_key}",
                f"      attack:  {arm.attack_log}",
            ]
            lines += [f"      honest:  {h}" for h in arm.honest_logs]
            lines += [f"      source:  {arm.source_report}", ""]

    pages: list[plt.Figure] = []
    for start in range(0, len(lines), _COVER_LINES_PER_PAGE):
        chunk = lines[start:start + _COVER_LINES_PER_PAGE]
        cover = plt.figure(figsize=(8.5, 11))
        cover.text(0.05, 0.98, "\n".join(chunk), va="top", family="monospace", fontsize=7)
        cover.gca().set_axis_off()
        pages.append(cover)
    return pages


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=None, help="Output PDF path.")
    parser.add_argument("--decimals", type=int, default=2, help="Value-label decimals (default 2).")
    parser.add_argument("--single-column", action="store_true",
                        help="Drop panel (a) and stack the two ablation panels at 3.85 in wide.")
    args = parser.parse_args()
    variant = "_single-column" if args.single_column else ""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or (
        REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
        / f"{stamp}_claims3-4-1_safety-bars{variant}_monitor-scope_plan-sharing.pdf"
    )
    out.parent.mkdir(parents=True, exist_ok=True)

    covers = build_cover_pages(stamp, single_column=args.single_column)
    fig = build_figure(decimals=args.decimals, single_column=args.single_column)
    with PdfPages(out) as pdf:
        for cover in covers:
            pdf.savefig(cover, bbox_inches="tight"); plt.close(cover)
        pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)
    print(f"Report saved: {out}")


if __name__ == "__main__":
    main()
