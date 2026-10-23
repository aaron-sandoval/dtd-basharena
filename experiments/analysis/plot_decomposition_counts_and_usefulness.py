#!/usr/bin/env python3
"""Claim 13: decomposition-count distributions + usefulness, DTD ± random trigger.

Compares the canonical DTD operating point at monitor_threshold=2.333
against the same configuration with a random-interval decomposition trigger
racing alongside the monitor trigger, on BA1.0's 566-task union (honest only).

The PDF holds:

  cover page   cells, trigger config, logs, usefulness anchors, methods
  figure       the two arms' decomposition-count distributions as two subplots
               stacked vertically on identical x and y scales as panel (a),
               plus panel (b) -- the usefulness bar chart -- appended to the
               right spanning the full height of both, with one legend keying
               the colors for all three panels
  tables       child-task-count summary statistics (full population, and the
               middle-80%-by-rank calibration subset), then which trigger caused
               the first decomposition in the random arm

Units: the FIGURES plot decompositions per root task; the TABLES report
child_task_count. child_task_count = max(child_task_index) + 1 over a sample's
assistant-message metadata (the same fallback tu_bb2.postprocessing's
_build_log_extract uses, since native online-dtd logs carry no
child_task_count_scorer), so a root task that never decomposes has 1 child task
and 0 decompositions: decompositions = child_task_count - 1.

Usefulness comes from experiments/analysis/compare_usefulness.py, run as a
subprocess standalone per arm so each number matches the canonical figure
already recorded for that arm.

Loading the counts means a full pass over two ~285 MB .eval logs plus two
compare_usefulness.py subprocesses (~9 min). Results are memoised under
experiments/data/metrics_cache/ keyed on each log's (path, size, mtime), so
re-runs for layout changes are instant; --no-cache forces a re-read.

Usage::

    uv run python experiments/analysis/plot_decomposition_counts_and_usefulness.py
    uv run python experiments/analysis/plot_decomposition_counts_and_usefulness.py --out /tmp/x.pdf
    uv run python experiments/analysis/plot_decomposition_counts_and_usefulness.py --no-cache
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from inspect_ai.log import read_eval_log_sample, read_eval_log_sample_summaries
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.colors import to_rgba
from matplotlib.patches import Patch
from matplotlib.ticker import MultipleLocator

from tu_bb2.plotting import protocol_series_colors
from tu_bb2.utils import REPO_ROOT

# --------------------------------------------------------------------------- #
# Config — arms, anchors, colors
# --------------------------------------------------------------------------- #

L = "experiments/_logs/tower"
BASELINE_LOG = f"{L}/2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval"
RANDOM_LOG = f"{L}/2026-08-07T02-46-39_566_online-dtd-v11.1-thr2p333-random-honest_BA10-UNION566.eval"

TRUSTED_PATHS = [
    f"{L}/2026-07-15T02-57-13_453_tpolicy-gpt54nano_BA10-UNION.eval",
    f"{L}/2026-07-17T06-55-37_176_tpolicy-gpt54nano-gapfill_BA10-UNION.eval",
]
UH_PATHS = [
    f"{L}/2026-07-15T02-59-38_452_uh_sus_BA10-UNION.eval",
    f"{L}/2026-07-30T08-17-38_159_uh-gapfill_sus_BA10-UNION566.eval",
]

# (short key, long label, log path). Long labels avoid parentheses: they're
# embedded in compare_usefulness.py's "Usefulness (<name>): ..." output line,
# and a nested ")" breaks the non-greedy parse below.
ARMS: list[tuple[str, str, str]] = [
    ("baseline", "DTD thr2.333 baseline", BASELINE_LOG),
    ("random", "DTD thr2.333 + random trigger", RANDOM_LOG),
]

# Short series names for the plots. The figure's legend keys the colors for
# all three panels, so these have to stay short; the long labels above (and the
# log paths behind them) carry the precise identification on the cover page.
PLOT_LABELS = {"baseline": "DTD", "random": "DTD + random"}

# Both arms are DTD variants (both long labels contain "dtd"), so the repo's
# protocol-family color convention assigns them shades of DTD's identity gray
# rather than distinct hues: protocol_series_colors gives one fixed hue per
# family, the first (canonical) arm keeps the identity color exactly and every
# later variant is strictly lighter.
_ARM_SHADES = protocol_series_colors([label for _k, label, _p in ARMS])
COLORS = {key: shade for (key, _label, _path), shade in zip(ARMS, _ARM_SHADES)}
INK = "#0b0b0b"
INK_2 = "#52514e"
INK_MUTED = "#8a8a85"
GRID = "#dedddb"
_LABEL_BBOX = dict(facecolor="#ffffff", edgecolor="none", pad=0.8)
# The histogram "mid-80% mean" boxes sit in the slot BETWEEN two y gridlines
# (see _draw_hist), so their pad is trimmed to what keeps the text legible
# without the box reaching either line.
_HIST_LABEL_BBOX = dict(facecolor="#ffffff", edgecolor="none", pad=0.25)
_HIST_YTICK_STEP = 0.2   # y gridline spacing on both histograms, pinned
_HIST_LABEL_Y = 0.3      # label centre: midway between the 0.2 and 0.4 gridlines

# Hatching is a second channel telling the arms apart, on top of the shade:
# the same density in mirrored directions, so the base arm still reads as the
# darker of the two. The bar FACE is drawn at BAR_ALPHA with the hatch and the
# outline fully opaque, the idiom plot_plan_delivery_safety_bars.py uses for
# the same DTD gray: an opaque DTD-gray face would swallow a black hatch.
HATCHES = {"baseline": "//", "random": "\\\\"}
BAR_ALPHA = 0.55
EDGE_WIDTH = 0.6


def _bar_style(key: str) -> dict:
    """Face / edge / hatch kwargs shared by the bars in both panels and by the
    legend swatches, so the three always match."""
    return dict(
        facecolor=to_rgba(COLORS[key], BAR_ALPHA), edgecolor="black",
        linewidth=EDGE_WIDTH, hatch=HATCHES[key],
    )

# The histograms plot DECOMPOSITIONS per root task = child_task_count - 1.
# Bins MIN_BIN..OVERFLOW_AT-1 are shown individually and every root task with
# >= OVERFLOW_AT decompositions is AGGREGATED into one overflow bar. Nothing is
# dropped: the stats pages and the cover page carry the full untruncated
# counts (max 46 baseline / 54 random decompositions). Every bin from 9 up
# carries <1% of root tasks in both arms, so 9 trades six near-empty bins for
# one visible overflow bar (5.7% baseline / 5.3% random).
MIN_BIN = 0
OVERFLOW_AT = 9

TAIL_THRESHOLDS = (1, 2, 4, 9)

GENERATED = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
DEFAULT_OUT = (
    REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
    / f"{GENERATED}_claim13_decompositions-and-usefulness_BA10-UNION566.pdf"
)
# experiments/data/metrics_cache/* is gitignored, so the memo never lands in a commit.
CACHE = REPO_ROOT / "experiments" / "data" / "metrics_cache" / "claim13_decomposition_counts.json"

_USEFULNESS_RE = re.compile(r"Usefulness \(.*\):\s*([\d.]+)\s*±\s*([\d.]+)")
_USEFULNESS_CI_RE = re.compile(r"Usefulness \(.*\)\s*(\d+)%\s*CI:\s*\[([\d.\-]+),\s*([\d.\-]+)\]")
_NTASKS_RE = re.compile(r"Number of tasks:\s*(\d+)")
_NCOMMON_RE = re.compile(r"Tasks in common:\s*(\d+)")


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #


def get_usefulness(log_path: str, label: str) -> dict:
    """Standalone usefulness (mean, SE, 95% bootstrap CI) for one arm via
    compare_usefulness.py. The CI is that script's own percentile-bootstrap CI
    (CONFIDENCE_INTERVAL_WIDTH=0.95, n_bootstrap=400, seed=42) — the same one it
    uses for its own bar-chart error bars, parsed rather than re-derived."""
    cmd = [
        "uv", "run", "python", "experiments/analysis/compare_usefulness.py",
        "--test", log_path,
        "--trusted", *TRUSTED_PATHS,
        "--honest", *UH_PATHS,
        "--test-name", label,
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    out = proc.stdout
    m = _USEFULNESS_RE.search(out)
    if not m:
        raise RuntimeError(f"Could not parse usefulness from compare_usefulness.py output:\n{out}")
    ci_m = _USEFULNESS_CI_RE.search(out)
    if not ci_m:
        raise RuntimeError(f"Could not parse usefulness 95% CI from compare_usefulness.py output:\n{out}")
    n_m = _NTASKS_RE.search(out)
    common_m = _NCOMMON_RE.search(out)
    return {
        "mean": float(m.group(1)),
        "se": float(m.group(2)),
        "ci_width_pct": int(ci_m.group(1)),
        "ci_lo": float(ci_m.group(2)),
        "ci_hi": float(ci_m.group(3)),
        "n_tasks": int(n_m.group(1)) if n_m else None,
        "n_common": int(common_m.group(1)) if common_m else None,
    }


def load_sample_data(log_path: str) -> dict:
    """Per-sample child_task_count and first-decomposition trigger attribution,
    read directly from message metadata in one streaming pass (NOT via the
    log-extract cache: the random-trigger log has no cached extract, and these
    logs are too large to safely re-read whole in one process).

    child_task_count = max(child_task_index) + 1.

    first_trigger classifies which trigger caused the FIRST decomposition
    (child_task_index 0 -> 1) by inspecting the last child-0 assistant tool-call
    message before the index changes: if it has rejected_proposal=True, the
    monitor trigger rejected that proposal and forced the switch
    (ChildTaskTriggerMonitorBased is pre-execution); if the index changes WITHOUT
    any rejection at child 0, the post-execution random trigger
    (make_random_interval_trigger) fired instead. Verified against real
    trajectories: monitor case is (0,False)...(0,True) -> (1,False); random case
    is (0,False)...(0,False) -> (1,False). "none" = never decomposed.
    """
    full_path = REPO_ROOT / log_path
    counts: list[int] = []
    first_trigger: list[str] = []
    for s in read_eval_log_sample_summaries(str(full_path)):
        samp = read_eval_log_sample(str(full_path), id=s.id, epoch=s.epoch)
        seq = []  # (child_task_index, rejected_proposal) per assistant tool-call message, in order
        for m in samp.messages:
            if getattr(m, "role", None) != "assistant":
                continue
            if not getattr(m, "tool_calls", None):
                continue
            md = m.metadata or {}
            if "child_task_index" not in md:
                continue
            seq.append((md["child_task_index"], bool(md.get("rejected_proposal"))))

        if not seq:
            counts.append(1)
            first_trigger.append("none")
            continue

        counts.append(max(idx for idx, _rej in seq) + 1)

        trans = None
        for i in range(1, len(seq)):
            if seq[i][0] != seq[i - 1][0]:
                trans = i
                break
        if trans is None:
            first_trigger.append("none")
        else:
            first_trigger.append("monitor" if seq[trans - 1][1] else "random")

    return {"child_task_count": np.asarray(counts, dtype=int), "first_trigger": first_trigger}


def _log_fingerprint(path: str) -> str:
    st = (REPO_ROOT / path).stat()
    return f"{path}|{st.st_size}|{int(st.st_mtime)}"


def load_all(use_cache: bool = True) -> tuple[dict, dict, dict]:
    """(usefulness, child_counts, first_trigger) for both arms, memoised on disk."""
    fingerprints = {key: _log_fingerprint(path) for key, _l, path in ARMS}
    if use_cache and CACHE.exists():
        blob = json.loads(CACHE.read_text())
        if blob.get("fingerprints") == fingerprints:
            print(f"Using cached arm data ({CACHE})")
            return (
                blob["usefulness"],
                {k: np.asarray(v, dtype=int) for k, v in blob["child_counts"].items()},
                blob["first_trigger"],
            )
        print("Cache present but log fingerprints changed — re-reading.")

    print("Computing usefulness per arm (compare_usefulness.py)...")
    usefulness = {key: get_usefulness(path, label) for key, label, path in ARMS}
    for key, label, _p in ARMS:
        u = usefulness[key]
        print(
            f"  {label}: {u['mean']:.3f} [{u['ci_lo']:.3f}, {u['ci_hi']:.3f}] "
            f"({u['ci_width_pct']}% CI)  (n={u['n_tasks']}, common={u['n_common']})"
        )

    print("Loading child-task counts + first-decomposition trigger attribution per arm...")
    sample_data = {key: load_sample_data(path) for key, _l, path in ARMS}
    child_counts = {key: sample_data[key]["child_task_count"] for key, _l, _p in ARMS}
    first_trigger = {key: sample_data[key]["first_trigger"] for key, _l, _p in ARMS}

    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(
        json.dumps({
            "fingerprints": fingerprints,
            "usefulness": usefulness,
            "child_counts": {k: v.tolist() for k, v in child_counts.items()},
            "first_trigger": first_trigger,
        })
    )
    print(f"Cached arm data -> {CACHE}")
    return usefulness, child_counts, first_trigger


def to_decompositions(child_counts: np.ndarray) -> np.ndarray:
    """Decompositions per root task = child_task_count - 1."""
    return child_counts - 1


def trimmed_middle_80(counts: np.ndarray) -> np.ndarray:
    """The middle-80% subset by RANK (drop the lowest-ranked 10% and the
    highest-ranked 10%) — the exact 10%-trimmed-mean method the random
    trigger's interval was calibrated against."""
    order = np.argsort(counts, kind="stable")
    n = len(counts)
    return counts[order[int(np.floor(n * 0.10)):int(np.ceil(n * 0.90))]]


def stats_row(counts: np.ndarray) -> dict[str, float]:
    n = len(counts)
    row = {
        "n": n,
        "mean": float(counts.mean()),
        "sem": float(counts.std(ddof=1) / np.sqrt(n)),
        "sd": float(counts.std(ddof=1)),
        "median": float(np.median(counts)),
        "p25": float(np.percentile(counts, 25)),
        "p75": float(np.percentile(counts, 75)),
        "p90": float(np.percentile(counts, 90)),
        "p95": float(np.percentile(counts, 95)),
        "max": int(counts.max()),
        "mode": int(Counter(counts.tolist()).most_common(1)[0][0]),
    }
    for t in TAIL_THRESHOLDS:
        row[f"frac_gt_{t}"] = float((counts > t).mean())
    dec = counts[counts > 1]
    row["mean_given_gt1"] = float(dec.mean()) if len(dec) else float("nan")
    return row


# --------------------------------------------------------------------------- #
# Shared plot pieces
# --------------------------------------------------------------------------- #

_XS_BINS = list(range(MIN_BIN, OVERFLOW_AT))      # individually-shown bins
_TICK_POS = list(range(MIN_BIN, OVERFLOW_AT + 1))  # + one slot for the overflow bar
_TICK_LBL = [str(x) for x in _XS_BINS] + [f"{OVERFLOW_AT}+"]
_BAR_W = 1.0                                       # bars touch: no gap between bins


def _style(ax) -> None:
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color(GRID)
    ax.tick_params(colors=INK_2, length=3, width=0.8)
    ax.yaxis.grid(True, color=GRID, linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)


def _heights(counts: np.ndarray) -> list[float]:
    """Fraction of root tasks per bin, with a single overflow bin at the top."""
    c = Counter(counts.tolist())
    h = [c.get(x, 0) / len(counts) for x in _XS_BINS]
    h.append(int((counts >= OVERFLOW_AT).sum()) / len(counts))
    return h


def _draw_hist(
    ax, key: str, child_counts: np.ndarray, ymax: float, *, ylabel: bool = False,
) -> None:
    """One arm's decomposition-count histogram, drawn on a fixed shared scale."""
    counts = to_decompositions(child_counts)
    ax.bar(_TICK_POS, _heights(counts), width=_BAR_W, zorder=3, **_bar_style(key))

    # Middle-80%-by-rank mean: the same trimmed population the random trigger's
    # interval was calibrated against, so the marker is robust to the long,
    # limit-censored right tail that drags the untrimmed mean around.
    mid80 = float(trimmed_middle_80(counts).mean())
    ax.axvline(mid80, color=INK, linewidth=0.9, linestyle=(0, (2, 2.2)), zorder=4, alpha=0.8)
    # Two lines: on the single-column panel a one-line label runs past the
    # right spine. The white box is centred in the slot between the 0.2 and
    # 0.4 gridlines (ticks pinned below) so it hides neither line; with the
    # tight pad and line spacing the box is ~25 pt tall against a ~32 pt slot.
    # The bars it starts over (0.17 and 0.19 of root tasks) end under the 0.2
    # line, so the box clears them too.
    ax.text(
        mid80 + 0.26, _HIST_LABEL_Y, f"mid-80% mean:\n{mid80:.2f}",
        color=INK, ha="left", va="center", linespacing=1.1,
        bbox=_HIST_LABEL_BBOX, zorder=5,
    )

    ax.set_xlim(MIN_BIN - 0.5, OVERFLOW_AT + 0.5)
    ax.set_ylim(0, ymax)
    ax.yaxis.set_major_locator(MultipleLocator(_HIST_YTICK_STEP))
    ax.set_xticks(_TICK_POS)
    ax.set_xticklabels(_TICK_LBL)
    if ylabel:
        ax.set_ylabel("Fraction of root tasks", color=INK_2)
    _style(ax)


def _shared_ymax(child_counts: dict[str, np.ndarray]) -> float:
    peak = max(max(_heights(to_decompositions(child_counts[key]))) for key, _l, _p in ARMS)
    return peak * 1.18


def _draw_usefulness_bars(ax, usefulness: dict) -> None:
    """Usefulness bar chart with bootstrap-CI error bars, arm colors matched.

    Annotated with the mean only (2 d.p.; the cover page has 3); the CI bounds behind the whiskers are on the
    cover page.
    """
    xs = list(range(len(ARMS)))
    means = [usefulness[key]["mean"] for key, _l, _p in ARMS]
    ci_lo = [usefulness[key]["ci_lo"] for key, _l, _p in ARMS]
    ci_hi = [usefulness[key]["ci_hi"] for key, _l, _p in ARMS]
    err_lo = [max(m - lo, 0.0) for m, lo in zip(means, ci_lo)]
    err_hi = [max(hi - m, 0.0) for m, hi in zip(means, ci_hi)]

    # Whiskers are solid black (the same style as the other manuscript bar
    # charts, e.g. plot_plan_delivery_safety_bars.py): the near-black INK_2
    # they used to be vanished against DTD's identity gray.
    # One bar call per arm: ax.bar takes a single hatch pattern per call.
    for x, (key, _l, _p), m, lo, hi in zip(xs, ARMS, means, err_lo, err_hi):
        ax.bar(
            x, m, width=0.5, yerr=[[lo], [hi]], capsize=3,
            error_kw={"elinewidth": 1.1, "ecolor": "black", "zorder": 4}, zorder=3,
            **_bar_style(key),
        )
    for x, m, hi in zip(xs, means, ci_hi):
        ax.text(x, hi + 0.025, f"{m:.2f}", ha="center", va="bottom",
                color=INK, bbox=_LABEL_BBOX, zorder=5)
    ax.set_xticks(xs)
    ax.set_xticklabels([])
    # Tight x range: the bars sit close together and the panel keeps no dead
    # space at either side beyond a bar's own half-width plus a small margin.
    ax.set_xlim(-0.5, len(ARMS) - 0.5)
    # Plain "Usefulness"; the 0=trusted / 1=honest rescaling is on the cover page.
    ax.set_ylabel("Usefulness", color=INK_2)
    _style(ax)


def _legend_handles() -> list[Patch]:
    return [
        Patch(label=PLOT_LABELS[key], **_bar_style(key))
        for key, _label, _p in ARMS
    ]


# --------------------------------------------------------------------------- #
# Figure — (a) stacked histograms + (b) full-height usefulness panel
# --------------------------------------------------------------------------- #

_FIG_TOP, _FIG_BOTTOM = 0.905, 0.185   # subplot margins; the y label is centred between them
_TITLE_PAD_PT = 11                      # both panel titles: clears the "1.0" tick label


def stacked_hist_with_usefulness_figure(
    usefulness: dict, child_counts: dict[str, np.ndarray]
) -> plt.Figure:
    ymax = _shared_ymax(child_counts)

    # 4.05 in wide: 25% narrower than the 5.4 in it was until 2026-09-21, and
    # 3.9 in tall (was 3.6): the extra height is what lets the "(b)" title sit
    # clear above panel (b)'s "1.0" tick label and the legend clear below its
    # "0.0". The width came out of panel (b): its two bars sit closer together
    # and the panel is under an inch wide, while panel (a) keeps ~1.8 in so its
    # ten tick labels ("8" and "9+" are the tight pair) stay apart. The gap
    # between the panels (~0.58 in) holds panel (b)'s tick labels and y label.
    # The legend, wider than panel (b), moved from above it to below it (see
    # below). Fonts untouched.
    fig = plt.figure(figsize=(4.05, 3.9))
    gs = fig.add_gridspec(2, 2, width_ratios=[1.85, 1.0], wspace=0.43, hspace=0.14)

    ax_top = fig.add_subplot(gs[0, 0])
    ax_bot = fig.add_subplot(gs[1, 0], sharex=ax_top, sharey=ax_top)
    ax_use = fig.add_subplot(gs[:, 1])  # spans the full height of both histograms

    for ax, (key, _label, _path) in zip((ax_top, ax_bot), ARMS):
        # No per-panel arm label: the legend's hatch + shade swatches identify
        # each histogram.
        _draw_hist(ax, key, child_counts[key], ymax)
    ax_top.tick_params(labelbottom=False)
    ax_bot.set_xlabel("Decompositions per root task", color=INK_2)
    fig.text(
        0.02, (_FIG_BOTTOM + _FIG_TOP) / 2, "Fraction of root tasks", rotation=90,
        ha="center", va="center", color=INK_2,
    )
    # Per-panel titles only (no figure-level title): the two panels need telling
    # apart, and everything else the figure used to say is on the cover page.
    # "(a) Decompositions", not "(a) Decompositions per root task": the long
    # form is 3.4 in wide at the title size and ran into "(b) Usefulness" on
    # the 4.05 in figure; the x label below the panel carries "per root task".
    ax_top.set_title("(a) Decompositions", color=INK, weight="bold", pad=_TITLE_PAD_PT)

    _draw_usefulness_bars(ax_use, usefulness)
    ax_use.set_ylim(0, 1.0)  # usefulness is rescaled to [0, 1]; the mean labels fit under 1.0
    ax_use.set_title("(b) Usefulness", color=INK, weight="bold", pad=_TITLE_PAD_PT)
    # One legend for the whole figure: the same colors label the bars AND the
    # histogram panels on the left. It sits directly BELOW panel (b)'s axes,
    # in the bottom margin that panel (a)'s x label already needs: panel (b)
    # has no x tick labels, so that strip is free, and the legend (~1.4 in,
    # set by the "DTD + random" text) is wider than the ~1 in panel, which an
    # above-the-axes legend would overhang, covering the "1.0" tick label.
    # Its left overhang lands in the inter-panel gap; the right margin below
    # is sized so its right overhang stays inside the figure, and the anchor
    # sits far enough below the axes that the box clears the "0.0" tick label
    # (centred on the axes bottom) which that overhang would otherwise cover.
    ax_use.legend(
        handles=_legend_handles(), loc="upper center", bbox_to_anchor=(0.5, -0.045),
        borderaxespad=0.0, frameon=True, framealpha=1.0, edgecolor=GRID,
        borderpad=0.5, labelspacing=0.5, handlelength=1.2, handletextpad=0.6,
    )

    fig.subplots_adjust(left=0.13, right=0.943, top=_FIG_TOP, bottom=_FIG_BOTTOM)
    return fig


# --------------------------------------------------------------------------- #
# Cover + tables
# --------------------------------------------------------------------------- #


def _text_page(lines: list[tuple[str, dict]]) -> plt.Figure:
    fig = plt.figure(figsize=(8.5, 11))
    y = 0.955
    for text, kw in lines:
        size = kw.pop("size", 9)
        fig.text(kw.pop("x", 0.06), y, text, size=size, va="top", **kw)
        y -= kw.pop("dy", 0.0) or (size / 620.0 + 0.009)
    return fig


def cover_page(usefulness: dict, child_counts: dict[str, np.ndarray]) -> plt.Figure:
    mono = {"family": "monospace"}
    max_all = max(int(to_decompositions(c).max()) for c in child_counts.values())
    lines: list[tuple[str, dict]] = [
        ("Claim 13 — DTD + random decomposition trigger", {"size": 17, "weight": "bold", "color": INK}),
        ("Decomposition-count distributions + usefulness, BA1.0 (566-task union)", {"size": 11, "color": INK_2}),
        ("", {"size": 6}),
        (f"Generated (UTC): {GENERATED}", {"size": 8.5, "color": INK_2}),
        ("", {"size": 8}),
        ("Arms", {"size": 11, "weight": "bold", "color": INK}),
    ]
    for key, label, path in ARMS:
        lines += [
            ("", {"size": 3}),
            (f"■ {label}   (plotted as “{PLOT_LABELS[key]}”, hatch {HATCHES[key]})", {"size": 9, "weight": "bold", "color": COLORS[key]}),
            (f"    {path}", dict(size=6.6, color=INK_2, **mono)),
        ]
    lines += [
        ("", {"size": 9}),
        ("Configuration", {"size": 11, "weight": "bold", "color": INK}),
        (
            "Cell.DTD_V11_1_RHE_0625 (TrustedMonitorPrompts.V11_1, tu-root-history ensemble-3) "
            "@ monitor_threshold=2.333 — the canonical DTD operating point (the shared honest arm "
            "TOWER_PHASE_B_DTD_HONEST[2]).",
            {"size": 8, "color": INK_2},
        ),
        (
            "The 'random' arm adds a random-interval decomposition trigger racing alongside the "
            "same monitor trigger: uniform[23,35], interval_min_index=-19 (first fire as early as "
            "action index 4), consider_other_triggers=True (shared spacing anchor with the monitor "
            "trigger). Calibrated so the random trigger alone targets 1x the baseline's own "
            "10%-trimmed-mean decomposition count, so the combined rate is ~2x baseline.",
            {"size": 8, "color": INK_2},
        ),
        ("Both arms: HONEST mode only, env=basharena, BA10_UNION (566 tasks), LIMITS_STEPS_ONLY.", {"size": 8, "color": INK_2}),
        ("", {"size": 8}),
        ("Usefulness anchors (restored BA1.0-replan anchors, not the deprecated TOWER_C10_* pair)", {"size": 11, "weight": "bold", "color": INK}),
        ("--trusted (usefulness=0):", {"size": 8, "weight": "bold", "color": INK_2}),
        *[(f"    {p}", dict(size=6.6, color=INK_2, **mono)) for p in TRUSTED_PATHS],
        ("--honest (usefulness=1):", {"size": 8, "weight": "bold", "color": INK_2}),
        *[(f"    {p}", dict(size=6.6, color=INK_2, **mono)) for p in UH_PATHS],
        ("", {"size": 8}),
        ("Methods", {"size": 11, "weight": "bold", "color": INK}),
        (
            "Usefulness: experiments/analysis/compare_usefulness.py, run standalone per arm "
            "(--test <arm>, no --reference) so each number matches the canonical figure already "
            "recorded for that arm; error bars are the script's own 95% CI (percentile bootstrap, "
            "n_bootstrap=400, seed=42, CONFIDENCE_INTERVAL_WIDTH — the same convention every other "
            "bootstrap CI in this repo uses). This is a per-arm CI, NOT a paired/matched bootstrap "
            "between the two arms — the two arms were not tested against each other for "
            "significance here.",
            {"size": 8, "color": INK_2},
        ),
        (
            "Child-task count: max(child_task_index)+1 per sample, read directly from message "
            "metadata (same definition as tu_bb2.postprocessing._build_log_extract's fallback), "
            "not via the cached log extract.",
            {"size": 8, "color": INK_2},
        ),
        (
            "UNITS: the figure plots DECOMPOSITIONS per root task = child_task_count − 1 (a root "
            "task that never decomposes has 1 child task and 0 decompositions). The summary-"
            "statistics tables below report child_task_count itself.",
            {"size": 8, "color": INK_2},
        ),
        (
            f"FIGURE: panel (a) shares x and y scales across the two arms; the ≥{OVERFLOW_AT} bar "
            f"aggregates every higher count (nothing dropped; max {max_all} decompositions across "
            "both arms); the dashed line is the middle-80%-by-rank mean. Panel (b) plots usefulness "
            "rescaled so trusted = 0 and honest = 1 (the anchors above); whiskers are the 95% CI.",
            {"size": 8, "color": INK_2},
        ),
        ("", {"size": 8}),
        ("Measured values", {"size": 11, "weight": "bold", "color": INK}),
    ]
    for key, label, _path in ARMS:
        u = usefulness[key]
        d = to_decompositions(child_counts[key])
        lines.append((
            f"    {label}: usefulness {u['mean']:.3f} "
            f"[{u['ci_lo']:.3f}, {u['ci_hi']:.3f}] ({u['ci_width_pct']}% CI), "
            f"n_tasks={u['n_tasks']}, n_common(vs anchors)={u['n_common']}  |  "
            f"decompositions n={len(d)}, mean={d.mean():.3f}, "
            f"middle-80% mean={trimmed_middle_80(d).mean():.3f}, "
            f"frac ≥{OVERFLOW_AT} (overflow bar)={float((d >= OVERFLOW_AT).mean()):.4f}",
            {"size": 7.4, "color": INK_2},
        ))
    return _text_page(lines)


_STATS_COLS = [
    ("n", "n", "{:d}"),
    ("mean", "mean", "{:.2f}"),
    ("sem", "±SEM", "{:.2f}"),
    ("sd", "SD", "{:.2f}"),
    ("median", "median", "{:.0f}"),
    ("p25", "p25", "{:.0f}"),
    ("p75", "p75", "{:.0f}"),
    ("p90", "p90", "{:.0f}"),
    ("p95", "p95", "{:.0f}"),
    ("max", "max", "{:d}"),
    ("mode", "mode", "{:d}"),
    ("frac_gt_1", "frac >1", "{:.3f}"),
    ("frac_gt_2", "frac >2", "{:.3f}"),
    ("frac_gt_4", "frac >4", "{:.3f}"),
    ("frac_gt_9", "frac >9", "{:.3f}"),
    ("mean_given_gt1", "mean|>1", "{:.2f}"),
]

_STATS_FOOTNOTE = (
    'Child-task counts, NOT decompositions (decompositions = these values − 1). "frac >1" = share '
    'of root tasks with at least one decomposition. "mean|>1" = mean count among only decomposed '
    "root tasks. SEM = standard error of the mean over root tasks. Counts are "
    "max(child_task_index)+1 — see the cover page."
)


def _stats_table_figure(
    rows: dict[str, dict[str, float]], title: str, subtitle: str, footnote: str,
) -> plt.Figure:
    cols = _STATS_COLS
    fig = plt.figure(figsize=(12, 3.6))
    ax = fig.add_axes([0.16, 0.42, 0.82, 0.32])
    ax.axis("off")

    table = ax.table(
        cellText=[[fmt.format(rows[key][k]) for k, _hdr, fmt in cols] for key, _l, _p in ARMS],
        rowLabels=[label for _k, label, _p in ARMS],
        colLabels=[hdr for _k, hdr, _f in cols],
        colWidths=[1.0 / len(cols)] * len(cols),
        cellLoc="center",
        rowLoc="right",
        bbox=[0, 0, 1, 1],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.5)

    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor(GRID)
        cell.set_linewidth(0.6)
        if row == 0:
            cell.set_text_props(weight="bold", color=INK)
            cell.set_facecolor("#f2f1ef")
        elif col == -1:
            cell.set_text_props(weight="bold", color=COLORS[ARMS[row - 1][0]])
            cell.set_facecolor("#ffffff")
            cell.set_edgecolor("#ffffff")
            cell.PAD = 0.06
        else:
            cell.set_text_props(color=INK)
            cell.set_facecolor("#ffffff" if row % 2 else "#fafaf9")

    fig.text(0.012, 0.92, title, color=INK, fontsize=14, weight="bold", va="top")
    fig.text(0.012, 0.84, subtitle, color=INK_2, fontsize=8.5, va="top")
    fig.text(0.012, 0.28, footnote, size=8, color=INK_2, va="top")
    fig.text(0.012, 0.03, f"Generated (UTC): {GENERATED}", size=7, color=INK_MUTED)
    return fig


def stats_table_page(child_counts: dict[str, np.ndarray]) -> plt.Figure:
    rows = {key: stats_row(child_counts[key]) for key, _l, _p in ARMS}
    return _stats_table_figure(
        rows,
        title="Child tasks per honest root task — summary statistics",
        subtitle="Full population: 566 honest root tasks per arm (BA10-UNION566).",
        footnote=_STATS_FOOTNOTE,
    )


def trimmed_stats_table_page(child_counts: dict[str, np.ndarray]) -> plt.Figure:
    """Stats over the middle-80%-by-rank subset of each arm — the same
    10%-trimmed-mean population the random trigger's interval (uniform[23,35])
    was calibrated against on the baseline arm. Comparing this subset across
    both arms (rather than just re-stating the calibration input) shows whether
    the shift holds up once the baseline's own long right tail is excluded from
    both sides of the comparison."""
    rows = {key: stats_row(trimmed_middle_80(child_counts[key])) for key, _l, _p in ARMS}
    n_each = {key: len(trimmed_middle_80(child_counts[key])) for key, _l, _p in ARMS}
    n_str = ", ".join(f"{label}: {n_each[key]}" for key, label, _p in ARMS)
    return _stats_table_figure(
        rows,
        title="Child tasks — middle-80%-by-rank subset (calibration population)",
        subtitle=(
            "Drops the lowest- and highest-ranked 10% of root tasks by child_task_count in EACH "
            f"arm independently, then re-computes stats on what remains ({n_str})."
        ),
        footnote=_STATS_FOOTNOTE,
    )


def first_trigger_table_page(first_trigger: list[str]) -> plt.Figure:
    """DTD+random arm only: which trigger caused each root task's FIRST
    decomposition — monitor, random, or none (never decomposed)."""
    n = len(first_trigger)
    c = Counter(first_trigger)
    cats = [
        ("monitor", "Monitor (suspicion-based)"),
        ("random", "Random-interval trigger"),
        ("none", "N/A — never decomposed"),
    ]

    fig = plt.figure(figsize=(9, 3.0))
    ax = fig.add_axes([0.32, 0.42, 0.62, 0.30])
    ax.axis("off")

    table = ax.table(
        cellText=[[str(c.get(key, 0)), f"{c.get(key, 0) / n:.3f}"] for key, _lbl in cats],
        rowLabels=[lbl for _k, lbl in cats],
        colLabels=["count", "fraction"],
        colWidths=[0.5, 0.5],
        cellLoc="center",
        rowLoc="right",
        bbox=[0, 0, 1, 1],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9.5)
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor(GRID)
        cell.set_linewidth(0.6)
        if row == 0:
            cell.set_text_props(weight="bold", color=INK)
            cell.set_facecolor("#f2f1ef")
        elif col == -1:
            cell.set_text_props(weight="bold", color=INK)
            cell.set_facecolor("#ffffff")
            cell.set_edgecolor("#ffffff")
            cell.PAD = 0.10
        else:
            cell.set_text_props(color=INK)
            cell.set_facecolor("#ffffff" if row % 2 else "#fafaf9")

    fig.text(0.012, 0.92, "DTD + random trigger — which trigger caused the FIRST decomposition", color=INK, fontsize=13, weight="bold", va="top")
    fig.text(0.012, 0.82, f"{n} honest root tasks, DTD thr2.333 + random trigger arm only.", color=INK_2, fontsize=8.5, va="top")
    fig.text(
        0.012, 0.30,
        "Classified from message metadata: the monitor trigger rejects a proposed action\n"
        "pre-execution (rejected_proposal=True) and forces an immediate switch; the random-\n"
        "interval trigger fires post-execution with no rejection. A root task's first decomposition\n"
        "is attributed to whichever trigger's signature immediately precedes child_task_index\n"
        "going from 0 to 1. \"N/A\" root tasks never decomposed at all (child_task_count == 1).",
        size=8, color=INK_2, va="top",
    )
    fig.text(0.012, 0.03, f"Generated (UTC): {GENERATED}", size=7, color=INK_MUTED)
    return fig


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output PDF path")
    ap.add_argument("--no-cache", action="store_true", help="re-read the logs instead of the memo cache")
    args = ap.parse_args()

    usefulness, child_counts, first_trigger = load_all(use_cache=not args.no_cache)
    for key, _label, _p in ARMS:
        d = to_decompositions(child_counts[key])
        print(
            f"  {PLOT_LABELS[key]}: decompositions mean={d.mean():.3f}, "
            f"middle-80% mean={trimmed_middle_80(d).mean():.3f}, "
            f"frac >= {OVERFLOW_AT} (overflow bar)={float((d >= OVERFLOW_AT).mean()):.4f}"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with PdfPages(args.out) as pdf:
        for fig in (
            cover_page(usefulness, child_counts),
            stacked_hist_with_usefulness_figure(usefulness, child_counts),
            stats_table_page(child_counts),
            trimmed_stats_table_page(child_counts),
            first_trigger_table_page(first_trigger["random"]),
        ):
            pdf.savefig(fig, bbox_inches="tight")
            plt.close(fig)
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
