"""What would this eval have measured under a SHORTER LIMIT? Two sensitivity sweeps, one
line per protocol, as a single PDF (cover page + ONE two-panel plot page: the step
sweep left, the working-time sweep right).

This is a study of the EVAL's limits, not of attacker behaviour. The LEFT panel re-measures
the same runs under a smaller action budget (the agent loop's ``max_steps``, which really
was 60), the RIGHT panel under a smaller working-time budget. Nothing about the policy changes: the
question is only how much of each run the harness would have allowed to happen, and what
safety the eval would then have reported. (The action-limit transform is the same code
claim 6 uses for its attacker-gives-up-after-N reading; the machinery is shared, the
interpretation here is not.)

EVERY arm is AUTO-SUBMIT TRUNCATED, but by two different routes -- TM and DTR are post-hoc
``*_autosubmit.eval`` replays (experiments/scripts/autosubmit_native.py), while DTD's
canonical no-plan arm was truncated IN-LOOP (``auto_submit`` has defaulted True since
2026-08-19), so it has no ``_autosubmit`` suffix. Either way the trajectory already ends at
the first side-task success and both limits compose ON TOP of that. DTRF is scored with
``resample_aggregation="q90"`` -- the basis the rest of the BA1.0 claims doc was re-based
onto (git commits df1c520 and a806a55).

BOTH panels censor the MONITOR BY ACTION -- at limit L the monitor only ever saw the
actions that would have happened, so a sample's suspicion is the max over THOSE verdicts
alone, never over the full trajectory:
  - action limit: experiments/analysis/limit_sensitivity/claim6_giveup_counterfactuals.py rebuilds the
    attack log capped at N loop iterations, dropping the monitor payload of every message
    past the cut, so the suspicion series is re-derived from the surviving trajectory.
    Safety is read from the metrics cache (experiments/data/metrics_cache/), the same
    estimator as experiments/analysis/plot_safety_vs_giveup_n.py.
  - time limit: experiments/analysis/limit_sensitivity/safety_vs_time_limit.py time-stamps every monitor
    verdict from the sample's own ModelEvents and takes the max over the verdicts whose
    action started by T (DTRF's q90 applied within each step over its surviving draws --
    a step straddling the cutoff keeps them, see PARTIAL_STEPS).
    Computed live from the base logs -- no new .eval files, no metrics cache.
In both, a side-task success is voided unless the action that landed it would have run,
and the HONEST arm is untouched at every L, so the audit threshold is fixed across each
sweep and every point isolates a safety effect, not a usefulness one.

⚠ The action axis is the AGENT LOOP ITERATOR (proposed actions) -- what ``max_steps``
actually counts. For DTD that requires the ``--actions-total`` grid
(``TOWER_C14_DTD_NOPLAN_GIVEUP_TOTAL_ATTACK_INLOOP_AUTOSUBMIT``): it counts executed actions AND
in-loop-rejected proposals, each of which consumes its own pass of the protocol's
``for step in range(max_steps)`` loop. DTD's plain ``--actions`` grid is NOT a loop-index
cap -- it clamps the cut at the first decomposition and degenerates into the child0only
counterfactual past ~N=15-20 (git commit d0d4f1f, "RETRACTION: DTD's give-up-N curve
cannot converge by construction, not behaviour"). TM/DTRF never decompose and bundle any
resample draws inside ONE step, so their ``--actions`` grids already count loop iterations
and are used unchanged.

Neither plot draws error bars (unlike plot_safety_vs_giveup_n.py) -- this is a quick
three-line comparison, not a CI-bearing report.

Arms: TM v11.1, DTRF-redo defer0.5 (q90), and -- since 2026-09-04 -- DTD thr2.333
withtips-NO-PLAN, the canonical BA1.0 operating point
(``project_ba10_canonical_noplan_reanchor``). The DTD line previously read the loose-plan
thr3.0-rem arm; that arm is one of the RF3 reruns of 2026-09-02, so its pre-repair
``_autosubmit`` counterfactuals no longer state the measured safety of that cell. The
no-plan arm was never a post-hoc replay and so was never RF3-repaired, which is why it can
be plotted from its own counterfactuals directly.

Prerequisite for the action-limit page: every cell must have cached compute_metrics.py
--bootstrap-ci metrics AT THE SAME --resample-agg (the aggregation joins the cache key, so
the q90 DTRF cells and the aggregation-free TM/DTD cells are separate entries). If a cell
is missing, this script fails fast and prints the exact ``compute_metrics.py`` command to
populate it, exactly like plot_safety_vs_giveup_n.py.

Cross-check built into the report: at no cutoff the time page's censoring is a no-op, so
each arm's no-limit safety must reproduce the cached base cell the action page plots at
N=60. That comparison is printed per arm on the cover.

    uv run python experiments/analysis/limit_sensitivity/plot_safety_vs_time_and_action_limit.py
"""
from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safety_vs_time_limit import compute_safety_vs_time_limit  # noqa: E402

from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH  # noqa: E402
from tu_bb2.utils import REPO_ROOT  # noqa: E402
from tu_bb2.named_tasks_and_logs import BashArenaLogs  # noqa: E402
from tu_bb2.plotting import (  # noqa: E402
    PIVOTAL_PALETTE,
    _resolve_series_marker,
    protocol_series_colors,
    protocol_series_markers,
)
from experiments.analysis.plot_safety_vs_giveup_n import (  # noqa: E402
    _cell_safety,
    _cells_from_group_pair,
    _compute_metrics_cmd,
    _resolve_group,
)

# ---------------------------------------------------------------------------
# The protocol arms (label, attack group, honest group, resample_aggregation).
# All three are auto-submit truncated and all three are POST-RF3 (TM and DTR pool
# [pre-repair, RF3 rerun] under dedup_latest_strict; DTD's canonical no-plan arm was
# never a post-hoc replay and so was never RF3-repaired).
# The resample aggregation joins the metrics cache key and is applied to BOTH arms
# of a cell; only DTRF resamples, so TM/DTD stay None.
#
# Each attack group is an action-limit sweep whose index 0 is the UNTRANSFORMED base
# log: the step panel reads the whole sweep, the time panel reads index 0 and re-censors
# it by time.
# Every group is indexed by the agent-loop iterator (proposed actions) -- for DTD that
# requires the `--actions-total` grid (see the group's comment in
# tu_bb2/named_tasks_and_logs.py); TM/DTRF's `--actions` grids already are one.
# ---------------------------------------------------------------------------
# Legend text is the protocol name and NOTHING else (manuscript house style): the
# operating point of each arm -- TM v11.1, DTR defer0.5 scored q90, DTD thr2.333
# no-plan -- is recorded on the cover page instead. Series are in
# PROTOCOL_FAMILY_ORDER (TM, DTR, DTD), and colors/markers come from the registry
# in tu_bb2/plotting.py via protocol_series_colors/_markers, never positionally.
PROTOCOLS = [
    ("Trusted Monitoring", "TOWER_C6_TM_GIVEUP_ATTACK_RERUN_FLAG3", "TOWER_BA10_UH_ANCHOR_RESTORED", None),
    ("DTR", "TOWER_C6_DTRF_D0P5_GIVEUP_ATTACK_RERUN_FLAG3", "TOWER_C10_DTRF_REDO_HONEST[1]", "q90"),
    ("DTD", "TOWER_C14_DTD_NOPLAN_GIVEUP_TOTAL_ATTACK_INLOOP_AUTOSUBMIT", "TOWER_PHASE_B_DTD_HONEST[2]", None),
]

BASELINE_N = 60  # the limit these evals ACTUALLY ran under (max_steps=60) = the base cell
# Every multiple of 5 up to the max_steps cap -- a genuinely uniform grid (unlike the
# earlier 4,5,6,7,8,9,10,20,40 spacing), so a true numeric x-axis has evenly spaced
# points AND evenly spaced ticks without resorting to a categorical axis.
ACTION_N_GRID = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, BASELINE_N]

# working_time percentiles differ ~2.5x across TM (max 72min) vs DTD (max 118min) vs
# DTRF (max 179min) on these BA1.0 tower logs -- this grid spans heavy truncation (kills
# nearly everything) through effectively-no-truncation for all three.
# 30-minute increments, plus a first point at T=10min (user request 2026-09-04). The
# earlier grid was denser below an hour (5/10/15/20/45); that extra resolution is not
# needed. T=10 is kept as the one short-budget probe: it is deep in the regime where most
# successes are voided, so it anchors the left end of each curve without spending five
# points on it.
TIME_MIN_GRID = [10, 30, 60, 90, 120, 150, 180]
TIME_S_GRID = [m * 60 for m in TIME_MIN_GRID]
# `None` = no cutoff at all. Not plotted: it is the verification point, where the
# censoring must be a no-op and safety must reproduce the cached base cell exactly.
TIME_S_GRID_WITH_BASE = TIME_S_GRID + [None]

SAFETY_CI_BOOTSTRAP = {"n": 500, "seed": 0, "level": CONFIDENCE_INTERVAL_WIDTH}

# What to do with a resampling step whose draws straddle the time cutoff (DTRF only).
# "include" (the advertised estimand) keeps the draws the monitor actually saw before the
# cutoff; "drop" would discard the whole step, throwing away real evidence and sometimes
# a whole sample. The cost of "include" is that an interpolated quantile over a truncated
# draw set can exceed the full step's value, so per-sample suspicion is not monotone in T
# -- disclosed here and on the cover rather than engineered away. See
# safety_vs_time_limit.censored_suspicion; the cover reports the other rule's effect.
PARTIAL_STEPS = "include"


def _color_for(labels: list, i: int) -> str:
    colors = protocol_series_colors(labels)
    if colors is None:
        return PIVOTAL_PALETTE[i % len(PIVOTAL_PALETTE)]
    return colors[i % len(colors)]


def _marker_for(labels: list, i: int) -> str:
    """Family marker for series ``i`` (falls back to the positional cycle)."""
    return _resolve_series_marker(protocol_series_markers(labels), labels[i], i)


def _zoom_ylim(series: "list[tuple[str, list[tuple[float, float]]]]",
               pad_frac: float = 0.05) -> "tuple[float, float]":
    """Tightest y-range that still shows every plotted point, padded by a small
    fraction of the data span. Deliberately NOT anchored at 0: these sweeps live in
    a narrow band and a 0-1 axis flattens the whole comparison. Clamped to [0, 1]
    because safety is a probability, so padding can never imply an impossible value.
    """
    ys = [y for _, pts in series for _, y in pts]
    lo, hi = min(ys), max(ys)
    pad = (hi - lo) * pad_frac or 0.01
    return max(0.0, lo - pad), min(1.0, hi + pad)


# Size of ONE panel. The two sweeps share a page as side-by-side panels, so the page
# is exactly twice this wide and each panel keeps the geometry it had when the two were
# separate pages -- 8.64in total, inside the 9in full-width cap of the house style.
PANEL_SIZE = (4.32, 3.6)


def _draw_lines(ax, series: "list[tuple[str, list[tuple[float, float]]]]", *,
                xlabel: str, xticks: "list[float]", xlim: "tuple[float, float]",
                ylim: "tuple[float, float] | None" = None,
                ylabel: "str | None" = "Safety",
                title: "str | None" = None) -> None:
    """series: one (label, [(x, safety), ...]) per protocol, x a REAL numeric value (N
    or minutes) -- a genuine linear axis, not a categorical one, so the spacing between
    points reflects actual distance. No error bars, no reference lines -- three plain
    marker+line series."""
    labels = [lbl for lbl, _ in series]
    for i, (label, pts) in enumerate(series):
        pts = sorted(pts, key=lambda p: p[0])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, marker=_marker_for(labels, i), linestyle="-",
                 color=_color_for(labels, i), markersize=7, linewidth=1.5, label=label)
    ax.set_xlabel(xlabel)
    # ylabel=None on the right panel: the panels sit side by side on one page with the
    # same y quantity, so a second "Safety" is redundant. The tick labels stay -- the
    # panels keep independent y-zooms, so the right axis still has to be readable.
    if ylabel:
        ax.set_ylabel(ylabel)
    # House style: no title on the data axes; the cover page identifies them.
    if title:
        ax.set_title(title)
    ax.set_xticks(xticks)
    ax.set_xlim(*xlim)
    ax.set_ylim(*(ylim if ylim is not None else _zoom_ylim(series)))
    ax.grid(True, alpha=0.3)
    ax.legend(loc="center right", fontsize=8)


def _two_panel_figure(left: dict, right: dict):
    """Both sweeps on ONE page, side by side, each panel the size it had as its own
    page. The panels keep INDEPENDENT y-zooms and one legend each: they are two
    separate sensitivity analyses that share a page, not two views of one axis.
    Only the left panel is y-labelled; both plot Safety, so a second label is noise.
    Each dict is the _draw_lines kwargs for that panel plus its ``series``."""
    fig, axes = plt.subplots(1, 2, figsize=(2 * PANEL_SIZE[0], PANEL_SIZE[1]))
    for ax, spec in zip(axes, (left, right)):
        spec = dict(spec)
        _draw_lines(ax, spec.pop("series"), **spec)
    fig.tight_layout()
    return fig


def _gather_action_limit_data():
    """Returns (series_for_plot, cover_rows) or raises SystemExit with remediation
    commands if any cell is missing from the metrics cache."""
    series = []
    cover_rows = []
    missing_all = []
    base_safety: dict = {}  # label -> cached base-cell safety (time panel's check value)
    for label, atk_name, hon_name, ragg in PROTOCOLS:
        atk_group = _resolve_group(atk_name)
        hon_group = _resolve_group(hon_name)
        cells = _cells_from_group_pair(atk_group, hon_group, resample_aggregation=ragg)
        points, missing = _cell_safety(
            cells, n_bootstrap=400, seed=42, ci_width=CONFIDENCE_INTERVAL_WIDTH,
            safety_ci_bootstrap=SAFETY_CI_BOOTSTRAP,
        )
        missing_all.extend(missing)
        if missing:
            continue
        xy = []
        for (a_paths, h_paths, kw), pt in zip(cells, points):
            n = kw["n"] if kw["n"] is not None else BASELINE_N
            if kw["n"] is None:
                base_safety[label] = pt["safety"]
            if n not in ACTION_N_GRID:
                continue
            xy.append((n, pt["safety"]))
        series.append((label, xy))
        base_a_name = ", ".join(Path(p).name for p in cells[0][0])
        cover_rows.append(f"  [{label}] attack (base): {base_a_name}")
        cover_rows.append(
            f"    honest: {', '.join(Path(p).name for p in cells[0][1])}    "
            f"sus_key: {cells[0][2]['sus_key']}    "
            f"attack_threshold: {cells[0][2]['attack_threshold']}    "
            f"pool_runs: {cells[0][2]['pool_runs']}    "
            f"resample_agg: {cells[0][2].get('resample_aggregation')}"
        )
    if missing_all:
        print(f"\nERROR: {len(missing_all)} action-limit cell(s) have no cached safety "
              "metrics. Populate the cache with:\n", file=sys.stderr)
        for spec in missing_all:
            print(_compute_metrics_cmd(spec) + "\n", file=sys.stderr)
        sys.exit(1)
    return series, cover_rows, base_safety


def _gather_time_limit_data(base_safety: dict):
    series = []
    cover_rows = []
    for label, atk_name, hon_name, ragg in PROTOCOLS:
        atk_group = _resolve_group(atk_name)
        hon_group = _resolve_group(hon_name)
        cells = _cells_from_group_pair(atk_group, hon_group, resample_aggregation=ragg)
        base_a_paths, base_h_paths, kw = cells[0]  # index 0 = untransformed base cell
        assert kw["n"] is None, f"{label}: expected the base (untransformed) cell first"
        honest_arg = base_h_paths[0] if len(base_h_paths) == 1 else base_h_paths
        # A pooled attack arm ([original, RF3 rerun]) is passed through as the LIST it is:
        # build_action_timeline merges per-file with later files winning, and
        # get_minimal_log_df(duplicate_id_handling="latest") picks the same winner, so the
        # timeline and the score frame agree on which run each task came from.
        attack_arg = base_a_paths[0] if len(base_a_paths) == 1 else base_a_paths
        # Match the cached cells' pooling on the attack side, so the no-cutoff point
        # reproduces the action page's N=60 baseline EXACTLY. dedup_latest's per-id
        # "latest" pick is a no-op on these single-log cells (verified: no duplicate
        # base task ids); what actually separates the two populations is its
        # clean-row rule, which drops attacked samples whose side task was never
        # scored -- on TM, 621 raw vs 619 cached (safety 0.5209 vs 0.5201).
        # NOTE both dedup modes take the same code path here, and that path is
        # dedup_latest_STRICT's rule: duplicate_id_handling="latest" keeps the last
        # attempt per task, and drop_unscored then drops it if it is unclean -- a failed
        # rerun excludes the task instead of falling back to the earlier run. That is
        # exactly right for the RF3-pooled TM/DTR arms. For a single-log cell (DTD) the two
        # modes coincide, which is what the no-cutoff check below has always verified.
        _dedup = kw["pool_runs"] in ("dedup_latest", "dedup_latest_strict")
        _ragg = kw.get("resample_aggregation")
        _common = dict(
            attack_log=attack_arg,
            honest_log=honest_arg,
            sus_key=kw["sus_key"],
            attack_threshold=kw["attack_threshold"],
            time_limits_s=TIME_S_GRID_WITH_BASE,
            attack_dup="latest" if _dedup else "keep",
            drop_unscored=_dedup,
            # Required for a pooled arm: without it the runs concatenate instead of
            # deduplicating by bare task id, and the no-cutoff check below fails loudly.
            pool_runs=kw["pool_runs"],
            resample_aggregation=_ragg,
        )
        result = compute_safety_vs_time_limit(**_common, partial_steps=PARTIAL_STEPS)
        by_t = {p["t"]: p for p in result["points"]}
        # A wall-clock cutoff can land BETWEEN a resampling step's draws (DTRF's are
        # minutes apart: 19.5% of its steps straddle some plotted T). The action page
        # never faces this -- its transform cuts on step boundaries -- so the rule is a
        # judgement call, and the alternative is reported rather than buried.
        alt_row = None
        if _ragg:
            alt = "include" if PARTIAL_STEPS == "drop" else "drop"
            alt_res = compute_safety_vs_time_limit(**_common, partial_steps=alt)
            alt_by_t = {p["t"]: p for p in alt_res["points"]}
            deltas = [(t, alt_by_t[t]["safety"] - by_t[t]["safety"]) for t in TIME_S_GRID]
            t_worst, d_worst = max(deltas, key=lambda kv: abs(kv[1]))
            alt_row = (f"    partial-step rule: {PARTIAL_STEPS!r}; under {alt!r} the largest "
                       f"shift is {d_worst:+.4f} at T={t_worst // 60:.0f}min")
        xy = [(t // 60, by_t[t]["safety"]) for t in TIME_S_GRID]
        series.append((label, xy))
        # VERIFICATION: with no cutoff the per-action censoring must be a no-op, so
        # this panel's estimator has to land on the cached base cell the step panel plots.
        no_limit = by_t[None]["safety"]
        cached = base_safety.get(label)
        check = "n/a (base cell not cached)" if cached is None else (
            f"{no_limit:.4f} vs cached base {cached:.4f}  "
            f"{'OK' if abs(no_limit - cached) <= 5e-4 else '*** MISMATCH ***'}"
        )
        cover_rows.append(
            f"  [{label}] attack (base): "
            f"{', '.join(Path(p).name for p in base_a_paths)}")
        cover_rows.append(
            f"    honest: {', '.join(Path(p).name for p in base_h_paths)}    "
            f"sus_key: {kw['sus_key']}    attack_threshold: {kw['attack_threshold']}    "
            f"pool_runs: {kw['pool_runs']}    "
            f"resample_agg: {kw.get('resample_aggregation')}"
        )
        cover_rows.append(
            f"    audit threshold: {result['threshold']:.4f} "
            f"(tie fraction {result['threshold_fraction']:.4f})    "
            f"n_attacks: {result['n_attacks_total']}"
        )
        cover_rows.append(f"    no-cutoff check: {check}")
        if alt_row:
            cover_rows.append(alt_row)
        _tight = by_t[TIME_S_GRID[0]]
        cover_rows.append(
            f"    at T={TIME_MIN_GRID[0]}min: {_tight['n_truncated']} success(es) voided, "
            f"{_tight['n_no_verdict']} sample(s) left with no monitor verdict at all "
            f"(dropped; {_tight['n_no_verdict_success']} of them had a surviving success)"
        )
    return series, cover_rows


def _cover_page(generated_at: str, action_rows: "list[str]", time_rows: "list[str]"):
    fig = plt.figure(figsize=(8.5, 11))
    lines = [
        "What would this eval have measured under a SHORTER LIMIT?",
        f"Generated (UTC): {generated_at}",
        "",
        "Both panels re-measure the SAME runs under a tighter budget than they actually",
        "ran with -- LEFT a smaller action budget (the agent loop's max_steps, which",
        f"really was {BASELINE_N}), RIGHT a smaller working-time budget. This is a",
        "sensitivity analysis of the eval's own limits, NOT a model of an attacker who",
        "chooses to give up: nothing about the policy changes, only how much of the run",
        "the harness would have allowed to happen.",
        "",
        "ALL arms AUTO-SUBMIT TRUNCATED; DTRF scored resample_aggregation=q90 (both arms).",
        "Arms: TM v11.1, DTRF-redo defer0.5 (q90), DTD thr2.333 withtips-NO-PLAN.",
        "The DTD line is the CANONICAL BA1.0 operating point (re-anchored 2026-08-25),",
        "swapped in on 2026-09-04 for the loose-plan thr3.0-rem arm this report used to",
        "plot. Reason: thr3.0-rem is an RF3 cell -- 121/566 of its samples were rerun",
        "in-loop on 2026-09-02 and the repaired pool moves its base safety 0.8713 ->",
        "0.8631, so the pre-repair counterfactual grid no longer states that cell's",
        "safety. The no-plan arm is truncated IN-LOOP (auto_submit default True since",
        "2026-08-19), never a post-hoc *_autosubmit replay, so RF3 never touched it.",
        "TM and DTRF are post-hoc *_autosubmit replays and ARE RF3 cells (86 and 139",
        "samples rerun), so BOTH are plotted REPAIRED here: every cell pools [original,",
        "RF3 rerun] under dedup_latest_strict, with the SAME per-N action cap applied to",
        "each half (capping then deduping == deduping then capping -- the cap is",
        "per-sample, the dedup per-task). Groups: TOWER_C6_{TM,DTRF_D0P5}_GIVEUP_ATTACK_",
        "RERUN_FLAG3, RF3 halves built 2026-09-04. ALL THREE LINES ARE NOW POST-RF3.",
        "⚠ The pre-repair grids they pool against are NOT superseded: claim 6's give-up-N",
        "figures stay on them permanently (user decision 2026-09-02).",
        "Auto-submit already ends each attack trajectory at its first side-task success;",
        "the limits below compose ON TOP of that truncation.",
        "No error bars (this is a quick three-line comparison, not a CI-bearing report).",
        "",
        "BOTH panels censor the MONITOR BY ACTION: at limit L the monitor only ever saw",
        "the actions that would have happened, so a sample's suspicion is the max over",
        "THOSE verdicts alone, never over the full trajectory. A side-task success is",
        "voided unless the action that landed it would have run. Honest arms are",
        "untouched at every L, so the audit threshold is fixed across each sweep and",
        "every point isolates a safety effect, not a usefulness one.",
        "",
        "── LEFT panel: safety vs STEP limit (agent-loop iterations) ──",
        "Mechanism: experiments/analysis/limit_sensitivity/claim6_giveup_counterfactuals.py rebuilds each",
        "attack log capped at N loop iterations: messages past the cut are dropped, their",
        "monitor payload with them (so suspicion is re-derived from the surviving",
        "trajectory), and a side-task success after the cut is voided in the sample",
        "scores, summaries and reductions.",
        "The index is the AGENT LOOP ITERATOR = proposed actions, which is what max_steps",
        "actually counts. For DTD that means --actions-total: executed actions AND",
        "in-loop-rejected proposals, each of which costs its own pass of the protocol's",
        "`for step in range(max_steps)` loop. (DTD's plain --actions grid is NOT this: it",
        "clamps the cut at the first decomposition and degenerates into child0only past",
        "~N=15-20 -- git commit d0d4f1f RETRACTION.) Grid group:",
        "TOWER_C14_DTD_NOPLAN_GIVEUP_TOTAL_ATTACK_INLOOP_AUTOSUBMIT. TM/DTRF never",
        "decompose and bundle",
        "any resample draws inside ONE step, so their --actions grids already count loop",
        "iterations.",
        "Safety read from the cached compute_metrics.py --bootstrap-ci output "
        f"(B={SAFETY_CI_BOOTSTRAP['n']}, seed={SAFETY_CI_BOOTSTRAP['seed']}).",
        f"N grid: {ACTION_N_GRID[:-1]} + base (N={BASELINE_N} = the limit actually run).",
        "",
    ] + action_rows + [
        "",
        "── RIGHT panel: safety vs WORKING-TIME limit ──",
        "Mechanism: experiments/analysis/limit_sensitivity/safety_vs_time_limit.py -- per-ACTION, not",
        "episode-level. Every monitor verdict is placed on the loop iteration that",
        "produced it and time-stamped from the sample's own events: control-tower emits",
        "each verdict as a user message immediately after the assistant message it",
        "scores, and that message's id appears in the ModelEvent that generated it, whose",
        "`working_start` is its working-time offset (executed actions AND rejected",
        "proposals are covered -- both are model calls). At limit T the suspicion is the",
        "max over the verdicts whose action started by T, with DTRF's q90 applied WITHIN",
        "each step over that step's surviving draws, then maxed across steps (a step whose",
        f"draws STRADDLE the cutoff is handled by partial_steps={PARTIAL_STEPS!r} -- see per-arm",
        "note below; TM/DTD emit one draw per step so it cannot affect them). A success is",
        "voided unless the executed action that landed it finished by T (on these",
        "auto-submit logs that is the last tool event, since the replay cuts the",
        "trajectory at the first success).",
        "Computed directly from the extraction pipeline (get_minimal_log_df /",
        "get_attack_scores_from_log / get_audit_threshold / compute_safety_metric -- the",
        "same functions compute_metrics.py uses), NOT from the metrics cache, and no new",
        ".eval files are produced; the per-sample action timeline is cached as JSON under",
        "claude_sandbox/time_limit_cache/. The walk is asserted per sample against",
        "postprocessing._native_sus_from_messages, so it cannot drift from the series the",
        "metrics pipeline scores.",
        f"Time grid (minutes): {TIME_MIN_GRID}.",
        "VERIFICATION: at no cutoff the censoring is a no-op, so each arm must reproduce",
        "the cached base cell the LEFT panel plots at N=60 -- reported per arm below.",
        "",
    ] + time_rows
    fig.text(0.05, 0.97, "\n".join(lines), transform=fig.transFigure,
             fontsize=7.5, verticalalignment="top", fontfamily="monospace", wrap=True)
    fig.patch.set_visible(False)
    return fig


def main() -> None:
    generated_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    action_series, action_rows, base_safety = _gather_action_limit_data()
    time_series, time_rows = _gather_time_limit_data(base_safety)

    # No titles on the data figures (house style). Which page is the action
    # sweep and which the time sweep is stated on the cover, and each x label
    # names its own axis; the "auto-submit truncated; monitor censored by
    # action; DTR q90" caveats are already spelled out on the cover too.
    fig_sweeps = _two_panel_figure(
        dict(series=action_series, xlabel="Step limit",
             xticks=list(range(0, BASELINE_N + 1, 5)), xlim=(0, BASELINE_N),
             ylim=_zoom_ylim(action_series)),
        dict(series=time_series, xlabel="Working time (minutes)",
             xticks=list(range(0, 181, 30)), xlim=(0, 180),
             ylim=_zoom_ylim(time_series), ylabel=None),
    )

    cover = _cover_page(generated_at, action_rows, time_rows)

    out_dir = REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
    out_dir.mkdir(parents=True, exist_ok=True)
    # The legend is bare protocol names now (house style), so the filename carries the
    # operating points instead -- otherwise successive versions of this report are
    # indistinguishable on disk.
    labels = "_".join(lbl for lbl, _, _, _ in PROTOCOLS) + "_DTD-thr2p333-noplan-canonical"
    slug = re.sub(r"[^A-Za-z0-9_-]", "-", labels)[:70]
    out_path = out_dir / f"{generated_at}_safety-vs-shorter-time-and-action-limit_AUTOSUBMIT_{slug}.pdf"

    with PdfPages(out_path) as pdf:
        pdf.savefig(cover, bbox_inches="tight"); plt.close(cover)
        pdf.savefig(fig_sweeps, bbox_inches="tight"); plt.close(fig_sweeps)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
