"""Safety bars for the plan-delivery ablation (claim 14 / claim 10), one protocol
per figure.

``--protocol DTD`` (the default): four DTD bars at monitor_threshold 2.333, one
shared honest arm. ``--protocol TM``: the three Trusted Monitoring bars against
the shared UH honest anchor pair. Both figures are single-column width with the
same geometry and the same legend, so they can sit side by side in the
manuscript and be read off one key.

Every bar in a figure is the same protocol, so the figure spends no channel and
no axis text on protocol identity -- the canonical family color carries it (DTD
gray, TM blue) and the cover page records it. That leaves a channel for each of
the two experimental factors. Both are NON-COLOR, so no comparison here needs
the reader to tell two bar colors apart:

  ATTACK PLAN (what the implementers got)  ->  HATCH
      No plan (reaches no implementer)         no hatch
      Loose   (no-tips planner)                '//'
      Strict  (tip-aware planner)              'xx'

  PLAN SHARING (did it travel onward?)     ->  BAR EDGE LINE STYLE + FILL SHADE
      Not shared (no further than child 0)     dashed edge, lighter fill
      Shared     (every implementer)           solid edge, family-color fill

The fill shade is a REDUNDANT second channel for sharing (the outline alone was
easy to miss). It is used only when a figure has bars at BOTH sharing levels
(DTD): the Shared bar keeps the family color exactly and Not-shared bars are the
strictly lighter variant (manuscript-plots section 2). The TM figure has no
Shared bar, so there it would only recolor every bar; its bars stay the
identity family color.

Legend text is bare -- "No plan / Loose / Strict", "Not shared / Shared" -- and
the definitions above live on the cover page. The no-delivery level keys off
``"minimal"`` in ``PLAN_HATCHES`` and in the arm literals, but reads "No plan"
on the figure; grep for the key, read the label.

The planner ALWAYS runs and its plan is always logged, including in the "No
plan" arm; that label means no implementer's prompt ever carries it, so which
planner produced it is inert there (the tip-aware one under DTD, the no-tips
one under TM). Folding no-delivery into the plan factor rather than into the
sharing one is what keeps sharing down to TWO levels, with no third dash
pattern the reader would have to tell apart: an undelivered plan reaches
nobody, so it is trivially NOT shared.

DTD, by cell:

                       | Not shared | Shared
    No plan            | 0.850      |   --
    Loose (no tips)    | 0.882      |   --
    Strict (tip-aware) | 0.880      | 0.890

TM, by cell:

                       | Not shared | Shared
    No plan            | 0.526      |   --
    Loose (no tips)    | 0.537      |   --
    Strict (tip-aware) | 0.513      |   --

Every TM bar is "Not shared": sharing ONWARD is a property only decomposition
can have, and TM runs one monolithic agent with no chain of implementers to
pass a plan along. Injecting a plan under TM changes WHICH plan the single agent
holds (the hatch), never how far it travels. The "Shared" legend entry therefore
matches no TM bar; it is kept so the TM figure's key is identical to the DTD
companion's.

COLOR. DTD (both sharing levels present): Shared keeps the family gray exactly
and Not-shared bars are the strictly lighter shade (manuscript-plots §2), as a
redundant second channel for sharing next to the outline. The plan factor is
still read from the hatch alone. TM (one sharing level): STYLE DEVIATION,
DELIBERATE, every bar takes the family color exactly and hatch/outline do the
work, since shading would only recolor all three bars.

HISTORY. 2026-08-24 .. 2026-09-04 this was one axes with both clusters
(``*_TM-vs-DTD.pdf``). 2026-09-07 the TM cluster was removed at the user's
request, leaving the single-column DTD figure. 2026-09-11 the TM cluster came
back as its own single-column figure behind ``--protocol TM``, so each protocol
is rendered alone and the DTD default is unchanged. The two protocols never
shared an arm, a threshold or an honest anchor, so neither figure's numbers
depend on the other's presence.

DATA PROVENANCE -- this script does NOT recompute safety from .eval logs. The
values in ``PROTOCOLS`` below are transcribed from the "Scalar Metrics" tables
of compare_protocols.py / compute_metrics.py reports (all: p95 audit threshold,
sus_key suspicion_score__tu-root-history, attack_threshold 0, resample_agg max,
B=500 seed=0 cluster-by-task bootstrap with tau recomputed per draw):

  DTD  experiments/data/metrics_reports_tower/20260904T000303Z_compare_DTD-thr2-333--
       plan-to-NO-implementer--WITHTIPS-_DTD-thr2-333_suspicion_score__tu-root-history.pdf
       (cohort plan-ladder-rf3; all four rungs, one shared honest arm, tau = 8.667)
  TM (loose / strict)  experiments/data/metrics_reports_tower/
       20260901T192747Z_compare_TM---no-plan--fidelity-filtered--drop-flag--4-_TM---
       no-tips-_suspicion_score__tu-root-history.pdf (task-matched 2026-09-01 values;
       that report's "no plan" row is the SUPERSEDED dropflag4 value 0.514)
  TM (no plan, RF3)    experiments/data/metrics_reports_tower/20260902T193337Z_tm_
       tm-v11.1_sus_BA10-UNION_autosubmit+tm-v11.1_sus_BA10-UNION56_suspicion_score__
       tu-root-history.pdf (compute_metrics on TOWER_C10_TM_ATTACK_RERUN_FLAG3[0],
       pool_runs dedup_latest_strict, tau = 8.667)

Re-derive the DTD report with::

    uv run python experiments/analysis/compare_protocols.py \
        --cohort plan-ladder-rf3 --task-ids BA10_UNION --bootstrap-ci --pdf

The TM arms are the named_tasks_and_logs groups TOWER_C10_TM_ATTACK_RERUN_FLAG3[0]
(no plan), TM_ABLATION_STDPLAN_ATTACK (loose) and TM_ABLATION_PLAN_ATTACK
(strict), each against the UH anchor pair listed per protocol below; the
per-arm log names are on each report's cover page.

FOURTH DTD RUNG (2026-09-03) -- the figure gained
``TOWER_C14_DTD_WITHTIPS_PLANCHILD0_ATTACK_INLOOP_AUTOSUBMIT``: the C14 arm-3
log, tip-aware planner with BOTH plan flags at their library defaults, so the
plan reaches child_task_index 0 and nobody else. Safety 0.880 [0.829, 0.918].
It is the planner-matched twin of the loose child-0 rung and it retires the
"ladder's planner confound" that ``_build_plan_ladder_rf3_cohort`` used to
carry: loose-vs-strict at the SAME sharing level is 0.882 vs 0.880, i.e. the
planner swap is worth nothing measurable, so the no plan -> not shared ->
shared movement (0.850 -> 0.880 -> 0.890) is an exposure effect and not a
planner artifact. It also makes the legend's two factors genuinely crossed
rather than nested. Density caveat: this arm ran concurrency_per_worker=8,
matched to the plan-share arm it ablates, NOT to the "No plan" arm's pinned cpw=5.

TASK UNIVERSE -- every bar is task-matched on the common 566 ids
(`--task-ids BA10_UNION`). Every DTD attack and honest arm was always 566, so
none of the DTD values moved when the 2026-09-01 task-matching pass landed. TM
is different: its honest arm is the 629-era UH anchor pair, so ALL THREE TM
bars shifted at task-matching, including the two whose attack logs were
already 566 (no plan 0.508 -> 0.514, loose 0.535 -> 0.537, strict 0.512 -> 0.513).

RF3 REPAIR (2026-09-02, supersedes the 2026-08-29 fidelity filter) -- ONE arm
per protocol is post-hoc and reads off a `*_RERUN_FLAG3` pooled cell:
[original `_autosubmit` log, in-loop RF3 rerun of every flag>=3 replay-damaged
sample] under pool_runs="dedup_latest_strict" (the rerun is authoritative; a
task whose rerun errored is DROPPED, never falling back to the damaged original
row -- gate: experiments/analysis/rerun_flag3/verify_rf3_groups.py). Values moved
from the dropflag4-filtered ones as:

  DTD loose, not shared  0.882 [0.832, 0.921] -> 0.882 [0.830, 0.919]  (488 -> 558 pooled)
  TM  no plan            0.514 [0.413, 0.630] -> 0.526 [0.423, 0.615]  (515 -> 557 pooled)

Every other arm is an IN-LOOP auto-submit run (auto_submit default-on since
2026-08-19). They were never replayed, carry no deviation flags and no RF3 slot
-- so they keep their original values. Read the repaired-vs-in-loop contrast
with that asymmetry in mind.

Usage::

    uv run python experiments/analysis/plot_plan_delivery_safety_bars.py
    uv run python experiments/analysis/plot_plan_delivery_safety_bars.py --protocol TM
    uv run python experiments/analysis/plot_plan_delivery_safety_bars.py --out /tmp/bars.pdf
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.colors import to_rgba
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import MultipleLocator

from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH
from tu_bb2.plotting import (
    PROTOCOL_DISPLAY_LABELS,
    PROTOCOL_FAMILY_COLORS,
    _family_shades,
    _lift_ylim_clear_of_top,
    _protocol_family,
)
from tu_bb2.utils import REPO_ROOT

# ---------------------------------------------------------------------------
# Config -- the two orthogonal factors, and the arms that cross them
# ---------------------------------------------------------------------------

# Factor 1: WHAT PLAN the implementers got -> hatch. Ordered three levels:
# nothing, one hatch direction, then both. The "minimal" KEY is the no-delivery
# case and reads "No plan" on the figure: a plan no implementer ever reads is,
# from the implementer's side, no plan at all -- which planner generated it is
# inert there (recorded per arm on the cover page). Key kept as "minimal" so the
# arm literals and the prose below stay greppable under one name.
PLAN_HATCHES: dict[str, tuple[str, str]] = {
    "minimal": ("", "No plan"),
    "loose": ("//", "Loose"),
    "strict": ("xx", "Strict"),
}

# Factor 2: whether the plan travelled ONWARD past the first implementer -> bar
# edge line style. Only TWO levels, because the no-delivery case lives in the
# plan factor above as "minimal" rather than as a third level here -- that is
# what keeps this channel down to dashed-vs-solid with no third dash pattern to
# tell apart. A minimal plan is trivially not shared (it reaches nobody at all),
# so the minimal bar takes the dashed "not shared" outline like the child-0 arms.
SHARE_STYLES: dict[str, tuple[str | tuple, str]] = {
    "not_shared": ((0, (5, 2.5)), "Not shared"),
    "shared": ("solid", "Shared"),
}


@dataclass(frozen=True)
class Arm:
    plan: str              # key into PLAN_HATCHES
    share: str             # key into SHARE_STYLES
    safety: float
    lo: float
    hi: float
    source_label: str
    attack_log: str


@dataclass(frozen=True)
class ProtocolSpec:
    """One figure's worth of arms plus the cover-page text that is specific to it."""
    family: str                     # key into PROTOCOL_FAMILY_COLORS / PROTOCOL_DISPLAY_LABELS
    threshold_note: str             # operating point, cover page only
    arms: tuple[Arm, ...]           # in bar order: sharing ascending, then plan type
    honest_logs: tuple[str, ...]    # shared by every arm of the protocol
    source_reports: tuple[str, ...]  # cover-page lines under VALUES ARE TRANSCRIBED
    cover_notes: tuple[str, ...]    # protocol-specific prose, after the shared definitions
    cross_check: tuple[str, ...]    # the factor cross-check table + its reading


PROTOCOLS: dict[str, ProtocolSpec] = {
    "DTD": ProtocolSpec(
        family="DTD",
        threshold_note="monitor_threshold 2.333",
        arms=(
            Arm(
                plan="minimal", share="not_shared",
                safety=0.850, lo=0.795, hi=0.891,
                source_label="DTD thr2.333 - plan to NO implementer "
                             "(inject_attack_plan_child0=False); the WITHTIPS planner still "
                             "runs and its plan is logged, but nobody reads it -> minimal",
                attack_log="2026-08-20T22-18-47_566_attack_online-dtd-v11.1-thr2p333-withtips-noplan"
                           "_BA10-UNION566.eval",
            ),
            Arm(
                plan="loose", share="not_shared",
                safety=0.882, lo=0.830, hi=0.919,
                source_label="DTD thr2.333 - no-tips planner, plan to child 0 (claim 10; "
                             "RF3-repaired pool, dedup_latest_strict)",
                attack_log="2026-07-30T17-14-25_566_attack_online-dtd-v11.1-thr2p333"
                           "_BA10-UNION566_autosubmit.eval"
                           " + 2026-09-02T01-02-41_120_attack_online-dtd-v11.1-thr2p333"
                           "_BA10-UNION566-RF3.eval",
            ),
            Arm(
                plan="strict", share="not_shared",
                safety=0.880, lo=0.829, hi=0.918,
                source_label="DTD thr2.333 - WITHTIPS planner, plan to child 0 (C14 arm 3, "
                             "both plan flags at library defaults; cpw=8)",
                attack_log="2026-09-03T20-11-14_566_attack_online-dtd-v11.1-thr2p333-withtips-planchild0"
                           "_BA10-UNION566.eval",
            ),
            Arm(
                plan="strict", share="shared",
                safety=0.890, lo=0.849, hi=0.920,
                source_label="DTD thr2.333 - WITHTIPS planner, plan to ALL implementers "
                             "(inject_attack_plan=True)",
                attack_log="2026-08-21T01-43-57_566_attack_online-dtd-v11.1-thr2p333-withtips-planshare"
                           "_BA10-UNION566.eval",
            ),
        ),
        honest_logs=(
            "2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval",
        ),
        source_reports=(
            "  experiments/data/metrics_reports_tower/20260904T000303Z_compare_DTD-thr2-333--"
            "plan-to-NO-implementer--WITHTIPS-_DTD-thr2-333_suspicion_score__tu-root-history.pdf",
            "  (cohort plan-ladder-rf3; all four rungs, one shared honest arm)",
        ),
        cover_notes=(
            "The planner ALWAYS runs and its plan is ALWAYS logged, even in the 'No plan'",
            "arm -- 'No plan' means no implementer's prompt ever carries it, so which",
            "planner produced it is inert there (it is the tip-aware one). That is why",
            "the sharing factor needs only TWO levels, with no third dash pattern to",
            "tell apart: an undelivered plan reaches nobody, so it is trivially NOT shared",
            "and takes the dashed outline just like the child-0 arms.",
            "",
            "TRUSTED MONITORING is rendered as its own single-column figure",
            "(--protocol TM) since 2026-09-11; 2026-09-07 .. 2026-09-11 it was absent,",
            "and before that both clusters shared one axes. No DTD number changes:",
            "the two protocols never shared an arm, a threshold or an honest anchor.",
        ),
        cross_check=(
            "                     | not shared | shared",
            "  No plan            | 0.850      |   --",
            "  Loose (no tips)    | 0.882      |   --",
            "  Strict (tip-aware) | 0.880      | 0.890",
            "  At the SAME sharing level, loose vs strict is 0.882 vs 0.880 -- the",
            "  planner swap is worth nothing measurable, so the no plan -> not shared",
            "  -> shared movement (0.850 -> 0.880 -> 0.890) is an EXPOSURE effect, not",
            "  a planner one.",
        ),
    ),
    "TM": ProtocolSpec(
        family="TM",
        threshold_note="tm-v11.1, always-attack",
        arms=(
            Arm(
                plan="minimal", share="not_shared",
                safety=0.526, lo=0.423, hi=0.615,
                source_label="TM - no plan injected (RF3-repaired pool, dedup_latest_strict; "
                             "TOWER_C10_TM_ATTACK_RERUN_FLAG3[0]); the no-tips planner still "
                             "runs and its plan is logged, but no implementer ever reads it "
                             "-> minimal",
                attack_log="2026-07-15T03-59-44_629_attack_tm-v11.1_sus_BA10-UNION_autosubmit.eval"
                           " + 2026-09-01T23-56-42_86_attack_tm-v11.1_sus_BA10-UNION566-RF3.eval",
            ),
            Arm(
                plan="loose", share="not_shared",
                safety=0.537, lo=0.425, hi=0.654,
                source_label="TM - no-tips plan injected (claim 10; TM_ABLATION_STDPLAN_ATTACK)",
                attack_log="2026-08-21T19-03-12_566_attack_sus_BA10-UNION-stdplan.eval",
            ),
            Arm(
                plan="strict", share="not_shared",
                safety=0.513, lo=0.422, hi=0.609,
                source_label="TM - WITHTIPS plan injected (TM_ABLATION_PLAN_ATTACK)",
                attack_log="2026-08-20T20-52-47_566_attack_sus_BA10-UNION-planinj.eval",
            ),
        ),
        honest_logs=(
            "2026-07-15T02-59-38_452_uh_sus_BA10-UNION.eval",
            "2026-07-30T08-17-38_159_uh-gapfill_sus_BA10-UNION566.eval",
        ),
        source_reports=(
            "  loose / strict:",
            "  experiments/data/metrics_reports_tower/20260901T192747Z_compare_TM---no-plan"
            "--fidelity-filtered--drop-flag--4-_TM---no-tips-_suspicion_score__tu-root-history.pdf",
            "  (task-matched 2026-09-01; its 'no plan' row is the SUPERSEDED dropflag4 0.514)",
            "  no plan (RF3 pool):",
            "  experiments/data/metrics_reports_tower/20260902T193337Z_tm_tm-v11.1_sus_BA10-UNION"
            "_autosubmit+tm-v11.1_sus_BA10-UNION56_suspicion_score__tu-root-history.pdf",
            "  (compute_metrics, pool_runs dedup_latest_strict)",
        ),
        cover_notes=(
            "The planner ALWAYS runs and its plan is ALWAYS logged, even in the 'No plan'",
            "arm -- 'No plan' means the single agent's prompt never carries it, so which",
            "planner produced it is inert there (it is the no-tips one).",
            "",
            "EVERY TM bar is 'Not shared'. Sharing ONWARD, past the first implementer, is",
            "a property only DECOMPOSITION can have; TM runs one monolithic agent with no",
            "chain of implementers to pass a plan along, so injecting a plan changes WHICH",
            "plan the agent holds (the hatch), never how far it travels. The 'Shared'",
            "legend entry therefore matches no bar here; it is kept so this figure's key",
            "is identical to the DTD companion's (--protocol DTD).",
            "",
            "DTD REMOVED from this figure (2026-09-11), at the user's request: the",
            "2026-09-04 version carried both clusters on one axes. No TM number changes:",
            "the two protocols never shared an arm, a threshold or an honest anchor.",
            "The TM honest arm is the 629-era UH anchor pair, so all three bars are",
            "task-matched to the 566 ids through it (no plan 0.508 -> 0.514 -> RF3 0.526,",
            "loose 0.535 -> 0.537, strict 0.512 -> 0.513).",
        ),
        cross_check=(
            "                     | not shared | shared",
            "  No plan            | 0.526      |   --",
            "  Loose (no tips)    | 0.537      |   --",
            "  Strict (tip-aware) | 0.513      |   --",
            "  All three CIs overlap: no injected plan helps the TM attacker. The",
            "  WITHTIPS plan lowers AUROC (0.92 -> 0.87) and ASR together, cancelling",
            "  to flat safety; the no-tips plan keeps AUROC 0.92.",
        ),
    ),
}

SUS_KEY = "suspicion_score__tu-root-history"
ATTACK_THRESHOLD = 0
BOOTSTRAP_B = 500
BOOTSTRAP_SEED = 0
BAR_ALPHA = 0.55  # face only; hatch/edge stay fully opaque for contrast
EDGE_WIDTH = 1.2
BAR_STEP = 0.20   # centre-to-centre spacing of the bars
BAR_FILL = 0.85   # bar width as a fraction of BAR_STEP -- the remainder is the
                  # gap that keeps each bar's OUTLINE its own, which the sharing
                  # factor is read off; abutting bars share an edge and the
                  # dashed/solid distinction disappears.


def build_figure(spec: ProtocolSpec) -> plt.Figure:
    """Render the single-column safety bar chart for one protocol."""
    arms = spec.arms
    # Single-column width (manuscript-plots §7 caps it at 4.5); the legend sits
    # below the axes and the tight bbox keeps it. The height was 3.6 until
    # 2026-09-21 and is now 2.7: with the default subplot margins the axes box
    # is (top - bottom) = 0.77 of the figure height, so 3.6 -> 2.7 makes the
    # y axis exactly 25% shorter while the legend below it keeps its own size
    # (the page shrinks by less than 25%). Fonts untouched (§6).
    # The same figsize for every protocol, whatever its bar count, so the
    # companion figures land on the page at identical size.
    fig, ax = plt.subplots(figsize=(4.2, 2.7))

    width = BAR_STEP * BAR_FILL
    # Family from the registry parser, not a string equality test, so this keeps
    # working if the figure is ever repointed at another protocol.
    color = PROTOCOL_FAMILY_COLORS[_protocol_family(spec.family)]
    # Sharing also gets a fill shade -- but only when this protocol actually has
    # bars at both levels. _family_shades gives [identity, lighter]: Shared (the
    # more-exposed arm) keeps the family color, Not shared is the lighter one.
    # With a single level present (TM) every bar keeps the identity color.
    shade_by_sharing = len({a.share for a in arms}) > 1
    if shade_by_sharing:
        shared_color, not_shared_color = _family_shades(color, 2)
        share_fill = {"shared": shared_color, "not_shared": not_shared_color}
    else:
        share_fill = {k: color for k in SHARE_STYLES}
    # One protocol, so protocol identity costs no visual channel at all: the
    # bars are simply centred on the axes.
    xs = (np.arange(len(arms)) - (len(arms) - 1) / 2) * BAR_STEP

    value_texts: list[plt.Text] = []
    for arm, x in zip(arms, xs):
        # TWO patches on purpose. A Patch's linestyle is applied to its hatch
        # strokes as well as its outline, so a single dashed bar would render
        # dashed HATCHING too -- the sharing factor bleeding into the plan
        # factor's channel, and neither matching its legend swatch. So: patch 1
        # carries the face + hatch with no outline (hatch stroke width comes
        # from rcParams["hatch.linewidth"], not from linewidth, so it survives
        # linewidth=0), patch 2 is an outline-only overlay that owns the line
        # style.
        ax.bar(
            x, arm.safety, width=width,
            facecolor=to_rgba(share_fill[arm.share], BAR_ALPHA),
            edgecolor="black", linewidth=0.0,
            hatch=PLAN_HATCHES[arm.plan][0], zorder=2,
        )
        ax.bar(
            x, arm.safety, width=width,
            facecolor="none", edgecolor="black", linewidth=EDGE_WIDTH,
            linestyle=SHARE_STYLES[arm.share][0], zorder=2.5,
        )
        yerr = np.array([[arm.safety - arm.lo], [arm.hi - arm.safety]])
        ax.errorbar(
            x, arm.safety, yerr=yerr, fmt="none",
            ecolor="black", elinewidth=1.1, capsize=3, zorder=3,
        )
        value_texts.append(ax.text(
            x, arm.hi + 0.02, f"{arm.safety:.2f}",
            ha="center", va="bottom", zorder=4,
        ))

    ax.set_ylabel("Safety")
    # No x tick label. Every bar is the same protocol, so a single tick under
    # the group said nothing the legend and the cover page do not; the
    # protocol is recorded on the cover.
    ax.set_xticks([])
    half = len(arms) * BAR_STEP / 2
    ax.set_xlim(-half - 0.06, half + 0.06)
    ax.set_ylim(0, 1.0)
    # Pin the y ticks at 0.2 steps: the shorter axis would otherwise let the
    # auto locator pick a coarser step than the one this figure has always had.
    ax.yaxis.set_major_locator(MultipleLocator(0.2))
    # The labels sit a fixed DATA offset above each whisker (arm.hi + 0.02)
    # but have a fixed PHYSICAL height, so on the 25%-shorter axis the tallest
    # ones crossed the ylim of 1.0; lift the limit just enough (headroom only,
    # the 0.2 tick step is unaffected).
    _lift_ylim_clear_of_top(fig, ax, value_texts)
    ax.grid(axis="y", alpha=0.3, zorder=0)
    ax.set_axisbelow(True)

    plan_handles = [
        Patch(facecolor="white", edgecolor="black", linewidth=EDGE_WIDTH,
              hatch=hatch, label=label)
        for hatch, label in PLAN_HATCHES.values()
    ]
    # Line handles, NOT patches, for the sharing factor: a boxed swatch carrying
    # only an outline style is exactly what the "minimal" swatch looks like, so
    # patches would give the two factors one identical entry. A bare line segment
    # reads unambiguously as "bar outline style".
    if shade_by_sharing:
        # The sharing factor now also has a fill, so its swatches can be boxes:
        # the gray fill keeps them apart from the white plan swatches (the
        # "minimal" one is the other outline-only box that the line handles
        # were avoiding), and they show the exact bar fill + outline.
        share_handles = [
            Patch(facecolor=to_rgba(share_fill[key], BAR_ALPHA), edgecolor="black",
                  linewidth=EDGE_WIDTH, linestyle=ls, label=label)
            for key, (ls, label) in SHARE_STYLES.items()
        ]
    else:
        share_handles = [
            Line2D([0], [0], color="black", linewidth=EDGE_WIDTH,
                   linestyle=ls, label=label)
            for ls, label in SHARE_STYLES.values()
        ]
    # ONE box holding both factors. Each section is introduced by an entry whose
    # handle draws nothing, so the section heading sits in the legend's own text
    # column; the headings are then bolded by name below. ncol=2 splits the
    # handle list column-major into ceil(n/2) rows, which for 4 plan entries and
    # 3 sharing entries lands each factor in its own column exactly. Both
    # factors are listed in full for every protocol (even where, as under TM,
    # one level matches no bar) so the companion figures share one key.
    headings = ("Attack plan", "Plan sharing")
    blank = lambda label: Line2D([], [], linestyle="none", marker="", label=label)
    handles = ([blank(headings[0])] + plan_handles
               + [blank(headings[1])] + share_handles)
    # fig.legend, NOT ax.legend: an axes legend re-attached with ax.add_artist is
    # NOT counted by savefig(bbox_inches="tight") and gets cropped off the page.
    # Figure legends are always in the tight bbox; bbox_transform keeps the
    # anchor in AXES coordinates all the same.
    leg = fig.legend(
        handles=handles, ncol=2, loc="upper center",
        # -0.05, not the usual -0.10: with the x tick label gone there is no
        # axis text under the bars for the legend to clear.
        bbox_to_anchor=(0.5, -0.05), bbox_transform=ax.transAxes,
        framealpha=0.95,
    )
    leg._legend_box.align = "left"
    for text in leg.get_texts():
        if text.get_text() in headings:
            text.set_fontweight("bold")

    return fig


def _style_note(spec: ProtocolSpec, n_word: str) -> list[str]:
    """Cover-page paragraph on how bar color is (and is not) used."""
    if len({a.share for a in spec.arms}) > 1:
        return [
            f"BAR COLOR: the {n_word.lower()} bars are variants of one protocol, so they share the",
            f"{spec.family} family hue and differ in lightness only (manuscript-plots section 2):",
            "the Shared bar is the family color, the Not-shared bars the lighter shade.",
            "That shade REPEATS the sharing outline (dashed/solid) rather than adding a",
            "factor; the plan factor is still read from the hatch alone.",
        ]
    return [
        f"STYLE DEVIATION, DELIBERATE: {n_word.lower()} variants of one protocol would",
        "normally be told apart by a lightness ramp (manuscript-plots section 2).",
        "They are not here. The brief for this figure is that BOTH factors decode",
        f"without comparing bar colors, so every bar takes the {spec.family} family color",
        "exactly and the hatch / outline channels do the work.",
    ]


def build_cover(spec: ProtocolSpec, stamp: str) -> plt.Figure:
    """Cover page listing the arms, values and source reports."""
    name = PROTOCOL_DISPLAY_LABELS[spec.family]
    color = PROTOCOL_FAMILY_COLORS[spec.family]
    n = len(spec.arms)
    n_word = {3: "Three", 4: "Four"}.get(n, str(n))
    lines = [
        f"Plan-delivery safety comparison ({name}, {spec.threshold_note})",
        f"Generated (UTC): {stamp}",
        "",
        f"{n_word} bars, ALL of them {name} ({spec.threshold_note}), one shared honest",
        "arm. The protocol is recorded HERE and nowhere on the figure: the bars carry",
        f"the canonical {spec.family} family color ({color}) and the x axis is deliberately",
        "unlabelled, since a single tick would only repeat what every bar already is.",
        "The two experimental factors are crossed and BOTH carry a non-color",
        "channel, so no comparison depends on bar color. Legend labels are bare;",
        "the definitions are here:",
        "  attack plan (WHAT the implementers got) -> HATCH",
        "      No plan = the plan reaches no implementer  (no hatch)",
        "      Loose   = no-tips planner                  ('//')",
        "      Strict  = tip-aware planner (WITHTIPS)     ('xx')",
        "  plan sharing (did it travel ONWARD?)    -> BAR EDGE LINE STYLE (+ FILL SHADE",
        "                                             when both levels are present)",
        "      Not shared = no further than child 0       (dashed edge, lighter fill)",
        "      Shared     = every implementer             (solid edge, family-color fill)",
        "",
        *spec.cover_notes,
        "",
        *_style_note(spec, n_word),
        "",
        f"sus_key: {SUS_KEY}    attack_threshold: {ATTACK_THRESHOLD}",
        f"audit rule: p95 fractional-tie threshold (tau=8.667, identical in all {n} arms)",
        f"CIs: {CONFIDENCE_INTERVAL_WIDTH:.2f} cluster-by-task percentile bootstrap "
        f"(B={BOOTSTRAP_B}, seed={BOOTSTRAP_SEED}),",
        "  p95 audit threshold recomputed per draw",
        "resample_agg: max        pool_runs: epochs_equal_task (RF3 cells: dedup_latest_strict)",
        "task_ids: BA10_UNION (566 ids)",
        "",
        "VALUES ARE TRANSCRIBED, NOT RECOMPUTED -- source reports:",
        *spec.source_reports,
        "",
        "-- Factor cross-check (safety) --",
        *spec.cross_check,
        "",
        "-- Arms --",
    ]
    for arm in spec.arms:
        lines += [
            f"  {PLAN_HATCHES[arm.plan][1]}  /  {SHARE_STYLES[arm.share][1]}",
            f"    source arm: {arm.source_label}",
            f"    safety={arm.safety:.3f} [{arm.lo:.3f}, {arm.hi:.3f}]",
            f"    attack:  {arm.attack_log}",
        ]
    lines += [f"    honest:  {log}" for log in spec.honest_logs]

    cover = plt.figure(figsize=(8.5, 11))
    cover.text(0.05, 0.98, "\n".join(lines), va="top", family="monospace", fontsize=7)
    cover.gca().set_axis_off()
    return cover


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--protocol", choices=sorted(PROTOCOLS), default="DTD",
        help="Which protocol's plan-delivery arms to render (one figure per protocol).",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Output PDF path. Default: experiments/data/metrics_reports_tower/"
             "<UTC>_plan-delivery-safety-bars_<PROTOCOL>.pdf",
    )
    args = parser.parse_args()
    spec = PROTOCOLS[args.protocol]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or (
        REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
        / f"{stamp}_plan-delivery-safety-bars_{args.protocol}.pdf"
    )
    out.parent.mkdir(parents=True, exist_ok=True)

    cover = build_cover(spec, stamp)
    fig = build_figure(spec)
    with PdfPages(out) as pdf:
        pdf.savefig(cover, bbox_inches="tight"); plt.close(cover)
        pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)
    print(f"Report saved: {out}")


if __name__ == "__main__":
    main()
