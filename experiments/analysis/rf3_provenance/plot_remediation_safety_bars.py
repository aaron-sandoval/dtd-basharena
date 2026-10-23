"""Clustered safety bars: the side-task-test remediation policies, one cluster per cell.

Each cluster carries the same cell scored several ways over ONE tau, so the bars differ
only in which attack samples they contain and how those trajectories were cut:
    Rerun ≥3          the canonical arm -- [original `_autosubmit`, in-loop RF3 rerun]
                      pooled dedup_latest_strict, the rerun superseding the damaged original
    Remove ≥3         the flag>=3 tasks deleted from BOTH logs
    Remove nothing    the original `_autosubmit` log alone, no sample dropped (pre-repair)
    Truncate nothing  (--with-untruncated only) the UNTRUNCATED source log, as it ran
                      before any auto-submit remediation at all
The point of the figure is the SIZE OF THE GAPS: how much the remediation moved the safety
number the manuscript quotes.

Two variants, same data, from the one script:
    (default)            three bars, the remediation choices made ON the truncated logs
    --with-untruncated   four bars, adding the pre-remediation state

CELLS are the 15-cell master list from the cover of
20260907T235952Z_overlap-vs-nonoverlap_safety-bars_BA10_RF3_canonical.pdf, in its order.
Two of them (Variant 3 = A8b no-summary, and 'unshared attack plan' = C14 arm 3) are fresh
IN-LOOP auto-submit runs that were never replayed, so the bug never touched them: their
three replay-era bars are equal by construction, and they have NO 'Truncate nothing' bar
because an in-loop run has no untruncated counterpart. That missing bar is the point --
it marks the arms the remediation never had to touch.

STYLE (.claude/skills/manuscript-plots):
  Color comes from protocol_series_colors(), never an inline hex: TM blue, DTR orange, DTD
  gray, CES yellow. Every cell of a family takes that family's identity color
  (shade_variants=False, user request 2026-09-29), so the figure has exactly four bar
  colors; cells within a family are told apart by x position and their cluster label,
  not by a lightness ramp. Families are passed explicitly because "PhaseA root"/"PhaseA fhe"/"PhaseA A8b nosum" name no protocol.
  Clusters run in PROTOCOL_FAMILY_ORDER. No title on the data axes, no fontsize anywhere
  on the chart; the cover, manifest and table pages are the sanctioned exceptions.

  Color carries PROTOCOL and hatch carries the REMEDIATION POLICY, so the two encodings
  never compete. The legend is the hatch key alone: protocol names are already spelled out
  as x-axis band labels, so a color legend would duplicate them. Every bar is hatched
  (user request), in the edge color so it stays legible on the lighter families where a
  white hatch would vanish. Hatches are deliberately COARSE and hatch.linewidth is
  reduced: at 15 clusters x 4 bars across a 9-inch page each bar is only ~8pt wide, and a
  dense pattern turns to mush at that size.

  ⚠ ONE DELIBERATE DEVIATION, carried over from the overlap figure this one matches:
  PROTOCOL_DISPLAY_LABELS["CES"] is "CES", but the user asked that protocol to read
  "Text files". The band label overrides the registry default; the registry is untouched.

Error bars are a percentile bootstrap over attack samples within the policy, tau held
fixed, so they cover sampling of the ATTACK arm only and are NARROWER than the
threshold-inclusive bootstrap CIs quoted in the safety reports.

Usage: uv run python experiments/analysis/rf3_provenance/remediation_outcomes.py   # first
       uv run python experiments/analysis/rf3_provenance/plot_remediation_safety_bars.py
       uv run python .../plot_remediation_safety_bars.py --with-untruncated
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from tu_bb2.plotting import protocol_series_colors  # noqa: E402

SRC = REPO / "experiments" / "data" / "rf3_provenance" / "remediation_outcomes.json"
OUT_DIR = REPO / "experiments/data/metrics_reports_tower"

INK = "#1A1A1A"
# Thin hatch strokes so a ~8pt-wide bar still reads as a pattern rather than a smear.
matplotlib.rcParams["hatch.linewidth"] = 0.6

# (json key, legend text, hatch). Coarse, well-separated patterns; the first three are
# identical in both variants so the two figures can be laid side by side.
ALL_POLICIES = [
    ("rerun_gt3", "Rerun ≥3", "//"),
    ("remove_gt3", "Remove ≥3", ".."),
    ("remove_nothing", "Remove nothing", "xx"),
    ("truncate_nothing", "Truncate nothing", "--"),
]

# (json key, cluster label, protocol-class band, family). The 15-cell master list, in the
# order and wording of the overlap figure's cover, so the two read together. Clusters run
# in PROTOCOL_FAMILY_ORDER (TM, DTR, DTD, CES). Threshold language is uniform: DTD's
# monitor_threshold is written in DTR's "defer" form on user request. `family` is explicit
# because "PhaseA root"/"PhaseA fhe"/"PhaseA A8b nosum" name no protocol.
CELLS = [
    ("TM",                      "",                        "Trusted\nMonitoring", "TM"),
    ("DTRF defer0.2",           "defer 0.2",               "DTR", "DTR"),
    ("DTRF defer0.5",           "defer 0.5",               "DTR", "DTR"),
    ("DTRF defer1.0",           "defer 1.0",               "DTR", "DTR"),
    ("DTRF defer3.0",           "defer 3.0",               "DTR", "DTR"),
    ("DTD thr1.333",            "defer 1.333",             "DTD", "DTD"),
    ("DTD thr2.333",            "defer 2.333",             "DTD", "DTD"),
    # ⚠ THREE plan-delivery arms at threshold 2.333, and two of them are called "shared
    # attack plan" elsewhere in the report set, so the planner prompt is spelled out on
    # every one of them. LOOSE is the 2026-07-31 original-planner arm, post-hoc replay
    # + RF3 (safety 0.967); STRICT is the WITHTIPS planner pair, both fresh IN-LOOP runs,
    # and "shared strict plan" is the claims 3/4.1 figure's "attack plan shared" bar
    # (0.890). Line breaks keep every line to 11 characters, the width the label tier was
    # sized for.
    # The gap between the two shared bars is planner and truncation route, NOT sharing.
    ("DTD planshare thr2.333",  "defer 2.333\nshared\nloose plan", "DTD", "DTD"),
    # The ladder's bottom rung, added 2026-09-10. The tip-aware planner still runs and its
    # plan is still logged; no implementer's prompt ever carries it, so which planner
    # produced it is inert and the label says neither loose nor strict. This is the
    # canonical DTD point of claims 7/10/11/14. Placed first of the three WITHTIPS rungs so
    # no plan -> unshared -> shared reads left to right.
    ("DTD no-plan thr2.333", "defer 2.333\nno plan", "DTD", "DTD"),
    ("DTD planchild0 thr2.333", "defer 2.333\nunshared\nstrict plan", "DTD", "DTD"),
    ("DTD withtips planshare thr2.333",
     "defer 2.333\nshared\nstrict plan", "DTD", "DTD"),
    # The four seed-threshold-3.0 design ablations, named and sequenced exactly as on the
    # overlap figure's cover: 1 remainder+summary+RHE (incumbent), 2 root scope,
    # 3 no-summary A8b, 4 FHE monitor.
    ("DTD thr3.0",              "defer 3.0\nVariant 1", "DTD", "DTD"),
    ("PhaseA root",             "defer 3.0\nVariant 2", "DTD", "DTD"),
    ("PhaseA A8b nosum",        "defer 3.0\nVariant 3", "DTD", "DTD"),
    ("PhaseA fhe",              "defer 3.0\nVariant 4", "DTD", "DTD"),
    ("DTD thr5.0",              "defer 5.0",               "DTD", "DTD"),
    ("CES",                     "",                        "Text\nfiles", "CES"),
]

ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
ap.add_argument("--with-untruncated", action="store_true",
                help="Add the fourth bar: safety BEFORE any auto-submit remediation.")
args = ap.parse_args()

# ALL_POLICIES is in LOGICAL order, canonical first, and that is the order the cover
# prose and every "- Rerun ≥3" delta are written against. The figure, legend and table
# are drawn in the REVERSE of it (user request 2026-09-10), so a cluster reads from the
# rawest state on the left to the canonical arm on the right, i.e. in the order the
# remediation was actually applied. CANON stays pinned to the canonical arm rather than
# to a list position, so reversing the display cannot silently re-baseline the deltas.
SELECTED = ALL_POLICIES if args.with_untruncated else ALL_POLICIES[:3]
CANON, CANON_LEG = SELECTED[0][0], SELECTED[0][1]
POLICIES = list(reversed(SELECTED))

rows = {r["label"]: r for r in json.loads(SRC.read_text())}
missing = [c for c, _, _, _ in CELLS if c not in rows]
assert not missing, f"missing cells in {SRC}: {missing}"
assert len(rows) == len(CELLS), f"{SRC} has {len(rows)} cells, figure draws {len(CELLS)}"
# Every cell defines the canonical bar. A REPLAYED cell defines all four policies; a
# never-replayed cell defines ONLY the canonical one, because no remediation policy was
# ever a choice for it -- see the drawing loop.
for key, _l, _b, _f in CELLS:
    r = rows[key]
    assert r[CANON] is not None, f"{key}: canonical arm missing"
    for pkey, _leg, _h in POLICIES:
        if pkey == CANON:
            continue
        if r["replayed"]:
            assert r[pkey] is not None, f"{key}: {pkey} missing on a replayed cell"
        else:
            assert r[pkey] is None, (
                f"{key}: never replayed, so {pkey} must be n/a rather than a copy of "
                "the canonical arm")

colors = protocol_series_colors([c[0] for c in CELLS], [c[3] for c in CELLS],
                                shade_variants=False)
assert colors is not None, "no cell named a protocol family"

CELL_Y, BAND_Y = -0.03, -0.33      # axes-fraction rows for the two label tiers
# BAND_Y and the bottom margin below are set by the LONGEST cluster-label line
# (11 chars: "defer 2.333", "strict plan"), which runs downward because the labels are
# rotated 90 deg. Lengthen a label line and both numbers have to grow with it.
SPAN = 0.84                        # cluster footprint, < the 0.95 cluster spacing
width = SPAN / len(POLICIES)

fig, ax = plt.subplots(figsize=(9, 4.9))
centers = np.arange(len(CELLS)) * 0.95   # <1.0 pulls the clusters together
for i, ((key, _lab, _band, _fam), col) in enumerate(zip(CELLS, colors)):
    r = rows[key]
    for j, (pkey, _leg, hatch) in enumerate(POLICIES):
        m = r[pkey]
        # A never-replayed cell draws its canonical bar and nothing else: the bug never
        # reached it, so there was no flag>=3 sample to rerun or remove and no
        # untruncated counterpart to score. The empty slots are the point. Offsets are
        # keyed to the FULL policy list, so every bar keeps the width and the x position
        # it has in a complete cluster.
        if m is None:
            continue
        x = centers[i] + (j - (len(POLICIES) - 1) / 2) * width
        ax.bar(x, m["safety"], width=width * 0.9, color=col, hatch=hatch,
               edgecolor=INK, linewidth=0.5, zorder=3)
        ax.errorbar(x, m["safety"],
                    yerr=[[m["safety"] - m["safety_lo"]],
                          [m["safety_hi"] - m["safety"]]],
                    fmt="none", ecolor=INK, elinewidth=0.8, capsize=1.6,
                    capthick=0.8, zorder=5)

ax.set_xticks([])
ax.set_ylabel("Safety")
ax.set_ylim(0, 1)
ax.set_yticks(np.arange(0, 1.01, 0.2))
ax.set_xlim(centers[0] - 0.6, centers[-1] + 0.6)
ax.set_axisbelow(True)
ax.grid(axis="y", color="#CCCDCF", linewidth=0.6, zorder=0)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)

# cluster labels (vertical, not angled: at default font size a rotated multi-line label's
# horizontal footprint exceeds the cluster spacing at every angle short of 90), then the
# class band labels
for c, (_key, lab, _band, _fam) in zip(centers, CELLS):
    if lab:
        ax.text(c, CELL_Y, lab, transform=ax.get_xaxis_transform(),
                ha="center", va="top", rotation=90)
bands, start = [], 0
for i in range(1, len(CELLS) + 1):
    if i == len(CELLS) or CELLS[i][2] != CELLS[start][2]:
        bands.append((CELLS[start][2], start, i - 1))
        start = i
for name, a, b in bands:
    ax.text((centers[a] + centers[b]) / 2, BAND_Y, name,
            transform=ax.get_xaxis_transform(), ha="center", va="top")
    if a > 0:   # class divider: inside the plot only, ending at the x-axis
        edge = (centers[a] + centers[a - 1]) / 2
        ax.plot([edge, edge], [0.0, 1.0], transform=ax.get_xaxis_transform(),
                color="#9A9B9D", linewidth=0.8, zorder=1)

# hatch key only: color is protocol identity, already named by the band labels
handles = [plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor=INK,
                         linewidth=0.5, hatch=h) for _k, _l, h in POLICIES]
fig.legend(handles, [lg for _k, lg, _h in POLICIES], loc="lower center",
           frameon=False, ncol=len(POLICIES), bbox_to_anchor=(0.5, 0.005))
fig.subplots_adjust(left=0.085, right=0.99, top=0.97, bottom=0.35)

stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
tag = "-with-untruncated" if args.with_untruncated else ""
out = OUT_DIR / f"{stamp}_remediation-policy{tag}_safety-bars_BA10_RF3.pdf"

_named = {c[0]: f"{c[2]} {c[1]}".replace("\n", " ").strip() for c in CELLS}


def _worst(pkey):
    g = [(_named[c[0]], rows[c[0]][pkey]["safety"] - rows[c[0]][CANON]["safety"])
         for c in CELLS if rows[c[0]][pkey] is not None]
    return max(g, key=lambda t: abs(t[1]))


_w_rm, _w_no = _worst("remove_gt3"), _worst("remove_nothing")

lines = [
    "Safety by side-task-test remediation policy",
    f"Generated (UTC): {stamp}", "",
    "-- What is plotted --",
    "  The July 2026 BA1.0 attack runs were missing the in-loop auto-submit feature that",
    "  ends a sample once an executed action completes the side task, so the agent kept",
    "  working and the monitor saw the post-exploit tail. They were repaired post hoc: the",
    "  recorded actions were replayed in a fresh sandbox with the side-task test running",
    "  after each action, the trajectory truncated at the firing action, and every replayed",
    "  tool output graded 1-5 for how far it deviated from the original (Sonnet 4.6 judge,",
    "  `content_max_flag`). Samples graded >= 3 were then RERUN in fresh in-loop evals, and",
    "  the rerun supersedes the damaged original.",
    "  Each cluster is one protocol cell scored several ways over the SAME tau, so the bars",
    "  differ only in which attack samples they contain and how they were cut. They are",
    "  listed below canonical-first, but DRAWN AND LISTED IN THE LEGEND IN REVERSE: the",
    "  leftmost bar of every cluster is the rawest state and the rightmost is the canonical",
    "  arm, so a cluster reads in the order the remediation was applied.",
    "    Rerun ≥3        the canonical arm the manuscript quotes -- [original `_autosubmit`,",
    "                    in-loop RF3 rerun] pooled pool_runs='dedup_latest_strict', so the",
    "                    rerun wins wherever it exists and a task whose rerun ERRORED is",
    "                    dropped rather than falling back to the damaged original row.",
    "    Remove ≥3       the flag>=3 tasks deleted outright, from the rerun log AND from the",
    "                    original: the original alone over (566-task union - the frozen",
    "                    rerun id list, experiments/data/rerun_flag3/<stem>.txt).",
    "    Remove nothing  the original `_autosubmit` log alone over the full union, no sample",
    "                    dropped and no rerun applied -- the post-truncation, pre-RF3 state.",
]
if args.with_untruncated:
    lines += [
        "    Truncate nothing  one step further back: the UNTRUNCATED source log, exactly as",
        "                    it ran before ANY auto-submit remediation. Same run and the same",
        "                    monitor scores up to the cut, but the trajectory continues past",
        "                    the side-task-completing action, so the monitor keeps scoring a",
        "                    tail that a correctly configured eval would never have produced.",
        "                    This bar is the size of the ORIGINAL BUG; the other gaps are the",
        "                    size of the CHOICES made while fixing it.",
    ]
lines += [
    "  The figure is about the SIZE OF THE GAPS, not the levels: how much the remediation",
    "  moved the safety number each cell reports.",
    "  'Remove nothing' reads the RAW original even for DTR defer 0.2, whose canonical cell",
    "  pools the `_rf3excl8` variant (8 tasks deleted because their rerun errored). Those",
    "  deletions are themselves remediation, so that bar must not inherit them -- which is",
    "  why defer 0.2 is the one replayed cell whose bars do not share an n.",
    "",
    "-- Cells --",
    "  The same 17 cells as …_overlap-vs-nonoverlap_safety-bars_BA10_RF3_canonical.pdf, in",
    "  its order and wording, so the two figures read together. That figure carried 15 until",
    "  2026-09-10, when 'shared strict plan' and 'no plan' were added to both; before that",
    "  only …_claims3-4-1_safety-bars_monitor-scope_plan-sharing.pdf plotted the former and",
    "  only …_plan-delivery-safety-bars_DTD.pdf the latter.",
    "  Variant 1-4 are the seed-threshold-3.0 design ablations: 1 remainder + summary + RHE",
    "  (the incumbent), 2 root scope, 3 no-summary A8b, 4 FHE monitor.",
    "",
    "  \u26a0 TWO ARMS HAVE BOTH BEEN CALLED 'shared attack plan' in older reports and both",
    "  are drawn here, which is why every threshold-2.333 plan bar names its planner prompt:",
    "    'shared loose plan'   2026-07-31, ORIGINAL planner prompt, post-hoc replay",
    "                          truncation + RF3 repair. Safety 0.967. Versions of the",
    "                          overlap figure before 2026-09-10 called it 'shared attack",
    "                          plan'; it now uses these same names.",
    "    'shared strict plan'  2026-08-21, WITHTIPS planner prompt, IN-LOOP auto-submit,",
    "                          top rung of the plan-exposure ladder. Safety 0.890. This is",
    "                          the bar the claims 3/4.1 figure calls 'attack plan shared'.",
    "  LOOSE vs STRICT names the planner prompt the attack plan came from, not how widely",
    "  it was delivered: 'shared' and 'unshared' carry that.",
    "  Both set inject_attack_plan=True and named_tasks_and_logs calls them twins, so the",
    "  0.077 between them is the PROMPT FAMILY and the TRUNCATION ROUTE, not the sharing",
    "  axis. 'unshared strict plan' (C14 arm 3, safety 0.880) is the matched control for",
    "  'shared strict plan' and for that bar only -- pairing it against the loose bar would",
    "  cross the planner and the truncation route as well as the sharing axis.",
    "",
    "  FOUR CELLS WERE NEVER AFFECTED BY THE BUG and therefore carry ONE BAR EACH --",
    "  Variant 3 (A8b no-summary), the no-plan rung and both strict-plan arms are IN-LOOP",
    "  runs, correct from the start and never replayed. No sample of theirs carries a",
    "  deviation grade, so there was never a flag>=3 sample to rerun or remove and no",
    "  remediation policy was ever a choice for them. Their single bar keeps the width and",
    "  the x position of the canonical 'Rerun ≥3' slot and the other slots are left EMPTY",
    "  rather than filled with copies of it: an equal bar would read as a measured null",
    "  result where no comparison was ever made.",
]
if args.with_untruncated:
    lines += [
        "  A8's pre-promptfix untruncated log does exist, but it is a DIFFERENT attack prompt",
        "  (the original A8 gated filesystem exploration on seeing a summary, a condition that",
        "  never holds under monitor_summarize=False), retained for history only, and it must",
        "  not stand in for A8b's missing 'Truncate nothing'.",
    ]
lines += [
    "  'PhaseA rem' is omitted: same attack pair and honest arm as 'defer 3.0 Variant 1'.",
    "",
    "-- Encoding --",
    "  COLOR = protocol family, from tu_bb2.plotting.protocol_series_colors: TM blue #3A82B5,",
    "  DTR orange #F15F22, DTD gray #7C7D7F, CES yellow #FFC61F. Every cell of a family",
    "  takes that family's identity color (no lightness ramp across variants), so the figure",
    "  has exactly four bar colors; cells within a family are told apart by x position and",
    "  their cluster label. Clusters run in PROTOCOL_FAMILY_ORDER.",
    "  HATCH = remediation policy, so color and hatch never compete for the same channel.",
    "  Every bar is hatched at the user's request; the patterns are coarse and drawn at",
    "  hatch.linewidth 0.6 because each bar is only ~8pt wide at this cluster count. The",
    "  legend is the hatch key alone: protocol names are spelled out as x-axis band labels,",
    "  so a color legend would only duplicate them. Band label 'Text files' is the CES",
    "  (create-edit-scripts) protocol, a deliberate override of PROTOCOL_DISPLAY_LABELS.",
    "",
    "-- Threshold --",
    "  ONE tau per cell, the p95 of that cell's own honest arm over the FULL 566-task union,",
    "  applied to every policy. Honest arms are untouched by the repair (auto-submit",
    "  truncates attack trajectories only), so no bar in a cluster moves because of tau.",
    "  DTR cells use the q90 resample aggregation; TM/DTD/CES never resample and use none.",
    "  attack_threshold 0 on every cell. sus_key is suspicion_score__tu-root-history",
    "  throughout EXCEPT 'defer 3.0 Variant 4', which carries suspicion_score__tu-full-history.",
    "",
    "-- Error bars --",
    "  Percentile bootstrap (2000 draws) resampling attack samples with replacement within",
    "  each policy. Every policy carries one row per task, so this is the cluster-by-task",
    "  bootstrap used elsewhere in the repo. tau is held FIXED across draws rather than being",
    "  re-derived from a resampled honest arm as compute_safety_vs_audit_budget does, so these",
    "  intervals cover attack-arm sampling ONLY and are NARROWER than the threshold-inclusive",
    "  CIs quoted in the claims document. Do not compare them against those directly.",
    "",
    "-- What this does and does not establish --",
    "  The bars are NOT independent samples: they are several readings of one recorded eval,",
    "  overlapping in most of their samples, so the error bars are not a test of the gaps",
    f"  between them. Largest 'Remove ≥3' gap: {_w_rm[0]} {_w_rm[1]:+.4f}.",
    f"  Largest 'Remove nothing' gap: {_w_no[0]} {_w_no[1]:+.4f}.",
]
if args.with_untruncated:
    _w_tr = _worst("truncate_nothing")
    lines += [
        f"  Largest 'Truncate nothing' gap: {_w_tr[0]} {_w_tr[1]:+.4f}.",
        "  Read the last of those as the bug's footprint and the first two as the fixing",
        "  choices' footprint; the exact per-cell deltas are on the table page.",
    ]
lines += [
    "  Deviation grading is an LLM judgment, so the flag>=3 boundary is itself approximate.",
]
if not args.with_untruncated:
    lines += [
        "  This variant does NOT show the pre-remediation state: every bar here is already",
        "  auto-submit truncated. Run with --with-untruncated for the figure that adds it.",
    ]
assert all(len(x) < 118 for x in lines), "a cover line is too wide for the page"
# Cover pages: matplotlib silently draws figure text past the page edge rather than
# clipping visibly, so an overflow is invisible until the PDF is read back. Split at
# section boundaries instead of shrinking the font.
_starts = [i for i, x in enumerate(lines) if x.startswith("-- ")] + [len(lines)]
_pages, _cur = [], lines[:_starts[0]]
for _a, _b in zip(_starts, _starts[1:]):
    _sec = lines[_a:_b]
    if _cur and len(_cur) + len(_sec) > 68:
        _pages.append(_cur)
        _cur = []
    _cur += _sec
_pages.append(_cur)
cover_pages = []
for _i, _part in enumerate(_pages):
    if _i:
        _part = [lines[0], f"Generated (UTC): {stamp}  (cont.)", ""] + _part
    assert len(_part) <= 78, f"cover page has {len(_part)} lines; it will clip"
    _f = plt.figure(figsize=(8.5, 11))
    _f.text(0.05, 0.97, "\n".join(_part), transform=_f.transFigure,
            fontsize=7.6, verticalalignment="top", fontfamily="monospace")
    _f.patch.set_visible(False)
    cover_pages.append(_f)

# Log manifest (house style section 4: the cover records every log, threshold, sus_key,
# pool_runs and resample_agg the figure itself no longer shows).
man_pages, mlines = [], []
head = ["Cell manifest -- logs, thresholds and pooling", "",
        "Paths are relative to experiments/_logs/tower/. 'A' is the canonical 'Rerun ≥3'",
        "arm; 'RAW' the original the removal policies read; 'UNTRUNC' its pre-remediation",
        "source; 'H' the honest arm tau comes from.", ""]
for key, lab, band, _fam in CELLS:
    r = rows[key]
    blk = [_named[key]]
    blk.append(f"    sus_key={r['sus_key']}  attack_threshold={r['attack_threshold']}"
               f"  resample_agg={r['agg']}  pool_runs={r['pool_runs']}")
    blk.append(f"    tau(union)={r['tau']:.3f} frac={r['frac']:.3f}"
               f"   replayed={r['replayed']}  rerun ids={r['n_rerun_ids']}"
               f" (in union {r['n_rerun_ids_in_union']})")
    for lg in r["attack_logs"]:
        blk.append(f"    A        {Path(lg).name}")
    if r["raw_original"] and Path(r["raw_original"]).name != Path(r["attack_logs"][0]).name:
        blk.append(f"    RAW      {Path(r['raw_original']).name}")
    if r["untruncated_original"]:
        blk.append(f"    UNTRUNC  {Path(r['untruncated_original']).name}")
    for lg in r["honest_logs"]:
        blk.append(f"    H        {Path(lg).name}")
    blk.append("")
    if len(mlines) + len(blk) > 96:      # keep each manifest page clear of the edge
        man_pages.append(mlines)
        mlines = []
    mlines += blk
man_pages.append(mlines)
man_figs = []
for pi, page in enumerate(man_pages):
    _m = plt.figure(figsize=(8.5, 11))
    _m.text(0.03, 0.985, "\n".join((head if pi == 0 else [head[0] + "  (cont.)", ""]) + page),
            transform=_m.transFigure, fontsize=6.2, verticalalignment="top",
            fontfamily="monospace")
    _m.patch.set_visible(False)
    man_figs.append(_m)

tbl = plt.figure(figsize=(11, 6.5))
tax = tbl.add_subplot(111)
tax.axis("off")
tbl.subplots_adjust(left=0.02, right=0.99, top=0.91, bottom=0.03)
# n is folded into the safety cell rather than given its own column: matplotlib
# tables give every column the same width under bbox=, and the extra columns
# squeezed "Cell" until the longest cluster name overflowed it.
# Headers are the bare policy names -- the value format is stated in the title, and a
# longer header overruns its (equal-width) column.
_others = [x for x in POLICIES if x[0] != CANON]
cols = ["Cell"] + [leg for _k, leg, _h in POLICIES] \
    + [f"\u0394 {leg}" for _k, leg, _h in _others]
data = []
for key, lab, band, _fam in CELLS:
    r = rows[key]
    base = r[CANON]
    row = [_named[key]]
    for pkey, _leg, _h in POLICIES:
        m = r[pkey]
        # 3dp on the interval, not 4: the cell has to hold the point estimate, both
        # bounds and n inside one equal-width column.
        row.append("n/a" if m is None else
                   f"{m['safety']:.4f} [{m['safety_lo']:.3f}, {m['safety_hi']:.3f}]"
                   f" n={m['n']}")
    for pkey, _leg, _h in _others:
        m = r[pkey]
        row.append("n/a" if m is None else f"{m['safety'] - base['safety']:+.4f}")
    data.append(row)
# The Cell column needs roughly twice the width of a value column: under bbox= every
# column is equal by default, and "DTD defer 2.333 unshared strict plan" then
# overflows its cell silently (matplotlib does not clip or warn).
_w = [1.8] + [1.0] * (len(cols) - 1)
_w = [x / sum(_w) for x in _w]
t = tax.table(cellText=data, colLabels=cols, colWidths=_w, cellLoc="right",
              bbox=[0.0, 0.0, 1.0, 1.0])
t.auto_set_font_size(False)
t.set_fontsize(4.6 if args.with_untruncated else 5.6)
# Keep this title short: it is drawn at the default size (no fontsize overrides on a
# chart) and matplotlib clips a long one at the page edge without warning.
tax.set_title("Remediation policy: safety [95% CI] n, tau fixed per cell.  "
              f"\u0394 = vs {CANON_LEG}.  n/a = never replayed.")

with PdfPages(out) as pdf:
    for _c in cover_pages:
        pdf.savefig(_c)
    pdf.savefig(fig)
    pdf.savefig(tbl)
    for _m in man_figs:
        pdf.savefig(_m)
png = f"/tmp/remediation_bars{'_4' if args.with_untruncated else '_3'}.png"
fig.savefig(png, dpi=170)
print("Report saved:", out)
