"""Claim 11: CES vs the DTD no-plan point (+ TM), safety-usefulness Pareto.

Replaces ``20260731T043122Z_claim11_ces-vs-dtd-front_BA10.pdf`` (pre-truncation, cited) and
``20260814T140235Z_claim11_ces-vs-dtd-front_BA10_autosubmit.pdf`` (truncated, never cited).
Same three series as those figures -- CES + TM + a DTD series, and NO DTRF series -- but the
DTD series is now the single measured no-plan point plus the dotted extrapolation, instead of
the four-point loose-plan front.

Derived from ``claude_sandbox/reusable/ba10_analysis/claim101_pareto_noplan_point.py``, which plots DTRF + TM +
no-plan-DTD. The only structural change is swapping its DTRF cells for the CES cell; all of
the dotted-DTD machinery (measured point, hypothetical shifted points, asymmetric error bars)
is carried over unchanged.

- DTD attack: 2026-08-20T22-18-47 ..._withtips-noplan_BA10-UNION566.eval (auto-submit truncated
  IN-LOOP, so it has no _autosubmit sibling). CES and TM are POST-HOC _autosubmit replays.
  Regime mismatch, not a truncation gap -- see the cover-page caveat.
- CES: the TRUNCATED arm (TOWER_C11_CES_ATTACK_AUTOSUBMIT, named_tasks_and_logs.py:4541).
  The untruncated arm reads safety 0.8824 against the truncated 0.6780, and the claims doc
  quoted the untruncated number in its body while quoting the truncated one in its summary
  table. Do not switch this back to TOWER_C11_CES_ATTACK.
- honest arms are unchanged by auto-submit, so usefulness is identical either way.

Usage:
    uv run python claude_sandbox/reusable/ba10_analysis/claim11_ces_vs_noplan_front.py
"""

import importlib.util as _ilu
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.backends.backend_pdf import PdfPages  # noqa: E402
from matplotlib.container import ErrorbarContainer  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH  # noqa: E402
from tu_bb2.named_tasks_and_logs import resolve_task_ids_arg  # noqa: E402
from tu_bb2.plotting import (  # noqa: E402
    PIVOTAL_PALETTE,
    PROTOCOL_FAMILY_ORDER,
    _resolve_series_marker,
    _su_accuracy,
    _su_ci_bounds,
    protocol_series_colors,
    protocol_series_markers,
)
from tu_bb2.postprocessing import (  # noqa: E402
    _bootstrap_distributions,
    compute_safety_vs_audit_budget,
)


def _load(path: Path, name: str):
    spec = _ilu.spec_from_file_location(name, str(path))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_CBP = _load(REPO_ROOT / "experiments" / "analysis" / "claim91_budget_pareto.py", "_cbp")
_PSU = _load(REPO_ROOT / "experiments" / "analysis" / "plot_safety_usefulness.py", "_psu")
_table_page = _PSU._table_page
_as_list = _CBP._as_list
_cell_threshold = _CBP._cell_threshold

TOWER = _CBP.TOWER
SUS_KEY = _CBP.SUS_KEY
ATTACK_THRESHOLD = _CBP.ATTACK_THRESHOLD
SAFETY_BOOT, SAFETY_SEED = _CBP.SAFETY_BOOT, _CBP.SAFETY_SEED
USE_BOOT, USE_SEED = _CBP.USE_BOOT, _CBP.USE_SEED
TRUSTED_LOGS = _CBP.TRUSTED_LOGS_BA10
BASELINE_LOGS = _CBP.BASELINE_LOGS_BA10

BUDGET = 5.0

CES_SERIES = "CES"
CES_CELL = "ces"
CES_ATTACK = (f"{TOWER}/2026-07-31T00-56-41_566_attack_online-ces-v11.1-rem"
              f"_BA10-UNION566_autosubmit.eval")
CES_HONEST = f"{TOWER}/2026-07-31T00-56-47_566_online-ces-v11.1-rem-honest_BA10-UNION566.eval"

NOPLAN_SERIES = "DTD no plan (WITHTIPS)"
NOPLAN_CELL = "noplan thr2.333"
NOPLAN_ATTACK = (f"{TOWER}/2026-08-20T22-18-47_566_attack_online-dtd-v11.1-thr2p333"
                 f"-withtips-noplan_BA10-UNION566.eval")
NOPLAN_HONEST = f"{TOWER}/2026-07-30T12-24-53_566_online-dtd-v11.1-thr2p333-honest_BA10-UNION566.eval"

# Cells: drop BOTH the "DTD (selected design)" front and the DTRF front; keep TM, add CES.
# The no-plan point gets special handling: single measured point + dotted extrapolation
# with asymmetric error bars.
# --arm-set selects which attack arms feed the figure (declarative tables in
# claim91_budget_pareto.py; kwargs incl. per-cell pool_runs come from the group registry):
#   autosubmit (default) — the post-hoc *_autosubmit replays as cited pre-repair;
#   dropflag4            — fidelity-filtered siblings (--dropflag4 is the deprecated alias);
#   rf3                  — the *_RERUN_FLAG3 repaired pools ([original, RF3 rerun] under
#                          dedup_latest_strict; a failed rerun DROPS the task).
# ⚠ The DTD no-plan point is IN-LOOP auto-submitted, has no deviation flags and no RF3 slot,
# and stays UNCHANGED in every set.
def _arm_set_from_argv() -> str:
    if "--arm-set" in sys.argv:
        _v = sys.argv[sys.argv.index("--arm-set") + 1]
        if _v not in ("autosubmit", "dropflag4", "rf3"):
            raise SystemExit(f"--arm-set must be autosubmit|dropflag4|rf3, got {_v!r}")
        return _v
    return "dropflag4" if "--dropflag4" in sys.argv else "autosubmit"


ARM_SET = _arm_set_from_argv()
DROPFLAG4 = ARM_SET == "dropflag4"


def _task_ids_from_argv() -> "tuple[str, list[str] | None]":
    """Parse --task-ids NAME|ID [ID ...] out of sys.argv (argv-sniffing to match
    --dropflag4 above). BA10_UNION is the 566-id BA1.0 universe; without it the
    TM/DTRF cells are read on their own 629-id universe while the DTD/CES cells
    are 566, so the axes would not be task-matched."""
    if "--task-ids" not in sys.argv:
        return "None (every id in the logs)", None
    i = sys.argv.index("--task-ids") + 1
    vals = []
    while i < len(sys.argv) and not sys.argv[i].startswith("--"):
        vals.append(sys.argv[i]); i += 1
    return resolve_task_ids_arg(vals)


TASK_IDS_ALIAS, TASK_IDS = _task_ids_from_argv()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dropflag_paths import to_dropflag as _to_dropflag  # noqa: E402

_SRC_CELLS = {
    "autosubmit": _CBP.CELLS_BA10_AUTOSUBMIT,
    "dropflag4": _CBP.CELLS_BA10_AUTOSUBMIT_DROPFLAG4,
    "rf3": _CBP.CELLS_BA10_AUTOSUBMIT_RF3,
}[ARM_SET]
# Per-cell pool_runs (rf3 only): pooled [original, RF3] cells MUST dedup strict
# inside compute_safety_vs_audit_budget or the pair degrades to concatenation.
POOL_RUNS = dict(_CBP.POOL_RUNS_BA10_AUTOSUBMIT_RF3) if ARM_SET == "rf3" else {}
if ARM_SET == "rf3":
    from tu_bb2.named_tasks_and_logs import BashArenaLogs as _RF3L
    _ces_paths, _ces_kw = _RF3L.TOWER_C11_CES_ATTACK_RERUN_FLAG3[0]
    assert _ces_kw["sus_key"] == SUS_KEY and _ces_kw["attack_threshold"] == ATTACK_THRESHOLD
    _CES_ATTACK = list(_ces_paths)
    POOL_RUNS[CES_CELL] = _ces_kw["pool_runs"]
elif DROPFLAG4:
    _CES_ATTACK = _to_dropflag(CES_ATTACK)
else:
    _CES_ATTACK = CES_ATTACK

CELLS = [c for c in _SRC_CELLS if c[0] == "TM"] + [
    (CES_SERIES, CES_CELL, _CES_ATTACK, CES_HONEST, False),
    (NOPLAN_SERIES, NOPLAN_CELL, NOPLAN_ATTACK, NOPLAN_HONEST, False),
]
# Protocol family per series, declared rather than parsed out of these internal
# keys — the style registry then supplies both color and marker.
SERIES_FAMILIES = {
    NOPLAN_SERIES: "DTD",
    CES_SERIES: "CES",
    "TM": "TM",
}
# Canonical protocol sequence (TM, DTR, DTD, CES), so the legend reads the same
# way here as in every other figure.
SERIES_ORDER = sorted(
    SERIES_FAMILIES, key=lambda k: PROTOCOL_FAMILY_ORDER.index(SERIES_FAMILIES[k])
)

# Display names for the plot legend ONLY. The internal keys stay as they are, and
# SERIES_FAMILIES (above) declares the protocol, so renaming a series here cannot
# move its color or marker: CES keeps the yellow diamond whatever it is called.
LEGEND_LABELS = {
    NOPLAN_SERIES: "DTD",
    # User-directed 2026-09-03: the CES series is named by its decomposition
    # TRIGGER, not the protocol. The cover page still records that it is CES.
    CES_SERIES: "Trigger: Text files",
    "TM": "Trusted Monitoring",
}

# Light gray for hypothetical error bars
LIGHT_GRAY = "#CCCCCC"

# Keep loose-plan safety/usefulness for error bar offset calculations on dotted line.
LOOSE_PLAN_CELLS = [c for c in _SRC_CELLS if c[0] == "DTD (selected design)"]


def main() -> None:
    # ---- usefulness (budget-invariant) ----
    # Compute for both plotted cells and loose-plan cells (used for error bar offsets)
    trusted_acc = _su_accuracy(TRUSTED_LOGS, task_ids=TASK_IDS).rename("tr")
    honest_acc = _su_accuracy(BASELINE_LOGS, task_ids=TASK_IDS).rename("ho")
    usefulness: dict[str, dict] = {}
    all_cells_for_usefulness = CELLS + LOOSE_PLAN_CELLS
    for _, cell, _, honest_log, pin in all_cells_for_usefulness:
        test_logs = BASELINE_LOGS if pin else _as_list(honest_log)
        test_acc = _su_accuracy(test_logs, task_ids=TASK_IDS).rename("test")
        df_u = pd.concat([test_acc, trusted_acc, honest_acc], axis=1).dropna()
        denom = df_u["ho"].mean() - df_u["tr"].mean()
        u = (df_u["test"].mean() - df_u["tr"].mean()) / denom
        boot = _bootstrap_distributions(
            df_u[["test", "tr", "ho"]].values, n_bootstrap=USE_BOOT, seed=USE_SEED)
        u_boot = (boot[:, 0] - boot[:, 1]) / (boot[:, 2] - boot[:, 1])
        u_lo, u_hi = _su_ci_bounds(u_boot, CONFIDENCE_INTERVAL_WIDTH)
        usefulness[cell] = dict(u=float(u), lo=float(u_lo), hi=float(u_hi),
                                n_common=int(len(df_u)))
        print(f"usefulness {cell}: {u:.4f} [{u_lo:.4f}, {u_hi:.4f}] n={len(df_u)}")

    # ---- safety per cell @ 5% budget ----
    # Also compute safety for loose-plan cells (used for error bar offsets on dotted line)
    safety: dict[str, pd.Series] = {}
    all_cells_for_safety = CELLS + LOOSE_PLAN_CELLS
    for series, cell, attack_log, honest_log, _ in all_cells_for_safety:
        # No DTRF series here, so nothing on this figure resamples: every arm draws one
        # untrusted sample per step. Passing an aggregation to TM/CES/DTD raises by design.
        cell_agg = None
        df = compute_safety_vs_audit_budget(
            _as_list(attack_log), _as_list(honest_log), SUS_KEY, budgets_pct=[BUDGET],
            attack_threshold=ATTACK_THRESHOLD, n_bootstrap=SAFETY_BOOT,
            seed=SAFETY_SEED, ci_width=CONFIDENCE_INTERVAL_WIDTH,
            resample_aggregation=cell_agg, task_ids=TASK_IDS,
            pool_runs=POOL_RUNS.get(cell),
        ).set_index("budget_pct")
        safety[cell] = df.loc[BUDGET]
        s = safety[cell]
        print(f"safety {cell} [agg={cell_agg or 'max'}] @ {BUDGET:.0f}%: {s['safety']:.4f} "
              f"[{s['ci_lo']:.4f}, {s['ci_hi']:.4f}] thr={s['threshold']:.4f}")

    # ---- the Pareto PDF ----
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
    _families = [SERIES_FAMILIES[k] for k in SERIES_ORDER]
    colors = protocol_series_colors(SERIES_ORDER, _families)
    markers = protocol_series_markers(SERIES_ORDER, _families)
    fig, ax = plt.subplots(figsize=(4.5, 3.78))
    rows = []

    # Plot DTRF and TM normally (error bars, markers)
    for si, label in enumerate(SERIES_ORDER):
        if label == NOPLAN_SERIES:
            continue  # Handle separately below
        cells = [c for c in CELLS if c[0] == label]
        color = colors[si]
        marker = _resolve_series_marker(markers, label, si)
        xs, ys, xerr, yerr = [], [], [[], []], [[], []]
        for _, cell, attack_log, honest_log, _pin in cells:
            s = safety[cell]
            u = usefulness[cell]
            xs.append(s["safety"]); ys.append(u["u"])
            xerr[0].append(max(0.0, s["safety"] - s["ci_lo"]))
            xerr[1].append(max(0.0, s["ci_hi"] - s["safety"]))
            yerr[0].append(max(0.0, u["u"] - u["lo"]))
            yerr[1].append(max(0.0, u["hi"] - u["u"]))
            rows.append(dict(
                series=label, cell=cell, budget_pct=BUDGET, threshold=_cell_threshold(cell),
                attack_log=attack_log, honest_log=honest_log,
                audit_threshold=s["threshold"],
                threshold_fraction=s["threshold_fraction"],
                safety=s["safety"], safety_lo=s["ci_lo"], safety_hi=s["ci_hi"],
                usefulness=u["u"], usefulness_lo=u["lo"], usefulness_hi=u["hi"],
                n_common=u["n_common"],
            ))
        ax.errorbar(
            xs, ys, xerr=np.array(xerr), yerr=np.array(yerr),
            fmt=f"-{marker}", color=color, ecolor=PIVOTAL_PALETTE[2],
            elinewidth=1.2, capsize=4, markersize=6, label=LEGEND_LABELS[label],
        )

    # ---- DTD no-plan: single measured point + dotted extrapolation with error bars ----
    # The dotted line connects the measured no-plan point to hypothetical shifted versions
    # of the loose-plan upper points, with asymmetric error bars (upper unshifted,
    # lower shifted by the safety offset).
    _noplan_i = SERIES_ORDER.index(NOPLAN_SERIES)
    noplan_color = colors[_noplan_i]
    noplan_marker = _resolve_series_marker(markers, NOPLAN_SERIES, _noplan_i)
    delta = safety[NOPLAN_CELL]["safety"] - safety["thr2.333"]["safety"]

    # Dotted line path: vertical from thr1.333 level up to measured point, then through
    # thr3.0 and thr5.0 shifted. The lowest point is ALSO shifted left.
    ext_xs = [safety["thr1.333"]["safety"] + delta,
              safety[NOPLAN_CELL]["safety"],
              safety["thr3.0"]["safety"] + delta,
              safety["thr5.0"]["safety"] + delta]
    ext_ys = [usefulness["thr1.333"]["u"],
              usefulness[NOPLAN_CELL]["u"],
              usefulness["thr3.0"]["u"],
              usefulness["thr5.0"]["u"]]

    # Error bars for dotted line:
    # 1. Lowest point (thr1.333 offset):
    #    upper: thr1.333's upper CI, lower: thr1.333's lower CI + delta
    # 2. Measured point (thr2.333):
    #    use the no-plan's measured CIs
    # 3. thr3.0 offset:
    #    upper: thr3.0's upper CI, lower: thr3.0's lower CI + delta
    # 4. thr5.0 offset:
    #    upper: thr5.0's upper CI, lower: thr5.0's lower CI + delta

    ext_xerr_lo = [
        max(0.0, (safety["thr1.333"]["ci_lo"] + delta) - ext_xs[0]),
        max(0.0, safety[NOPLAN_CELL]["safety"] - safety[NOPLAN_CELL]["ci_lo"]),
        max(0.0, (safety["thr3.0"]["ci_lo"] + delta) - ext_xs[2]),
        max(0.0, (safety["thr5.0"]["ci_lo"] + delta) - ext_xs[3]),
    ]
    ext_xerr_hi = [
        max(0.0, safety["thr1.333"]["ci_hi"] - ext_xs[0]),
        max(0.0, safety[NOPLAN_CELL]["ci_hi"] - safety[NOPLAN_CELL]["safety"]),
        max(0.0, safety["thr3.0"]["ci_hi"] - ext_xs[2]),
        max(0.0, safety["thr5.0"]["ci_hi"] - ext_xs[3]),
    ]

    # Plot the dotted line without error bars
    ax.plot(ext_xs, ext_ys, linestyle=":", color=noplan_color, linewidth=1.6, zorder=1)

    # Add error bars to the dotted line points manually (to handle asymmetric bounds properly)
    # Error bars span from (ci_lo + delta) to ci_hi for hypothetical points
    # Point 0 (thr1.333 offset): light gray
    ci_lo_0, ci_hi_0 = safety["thr1.333"]["ci_lo"], safety["thr1.333"]["ci_hi"]
    ax.plot([ci_lo_0 + delta, ci_hi_0], [ext_ys[0], ext_ys[0]], color=LIGHT_GRAY,
            linewidth=1.2, solid_capstyle="butt", zorder=2)
    ax.plot([ci_lo_0 + delta, ci_lo_0 + delta], [ext_ys[0] - 0.01, ext_ys[0] + 0.01],
            color=LIGHT_GRAY, linewidth=1.2, zorder=2)
    ax.plot([ci_hi_0, ci_hi_0], [ext_ys[0] - 0.01, ext_ys[0] + 0.01],
            color=LIGHT_GRAY, linewidth=1.2, zorder=2)

    # Point 1 (measured no-plan): series color, use standard error bars
    ax.plot([ext_xs[1]], [ext_ys[1]], noplan_marker, color=noplan_color,
            markersize=6, zorder=3)
    ax.errorbar([ext_xs[1]], [ext_ys[1]], xerr=[[ext_xerr_lo[1]], [ext_xerr_hi[1]]],
                fmt="none", ecolor=noplan_color, elinewidth=1.2, capsize=4, zorder=2)

    # Point 2 (thr3.0 offset): light gray
    ci_lo_2, ci_hi_2 = safety["thr3.0"]["ci_lo"], safety["thr3.0"]["ci_hi"]
    ax.plot([ci_lo_2 + delta, ci_hi_2], [ext_ys[2], ext_ys[2]], color=LIGHT_GRAY,
            linewidth=1.2, solid_capstyle="butt", zorder=2)
    ax.plot([ci_lo_2 + delta, ci_lo_2 + delta], [ext_ys[2] - 0.01, ext_ys[2] + 0.01],
            color=LIGHT_GRAY, linewidth=1.2, zorder=2)
    ax.plot([ci_hi_2, ci_hi_2], [ext_ys[2] - 0.01, ext_ys[2] + 0.01],
            color=LIGHT_GRAY, linewidth=1.2, zorder=2)

    # Point 3 (thr5.0 offset): light gray
    ci_lo_3, ci_hi_3 = safety["thr5.0"]["ci_lo"], safety["thr5.0"]["ci_hi"]
    ax.plot([ci_lo_3 + delta, ci_hi_3], [ext_ys[3], ext_ys[3]], color=LIGHT_GRAY,
            linewidth=1.2, solid_capstyle="butt", zorder=2)
    ax.plot([ci_lo_3 + delta, ci_lo_3 + delta], [ext_ys[3] - 0.01, ext_ys[3] + 0.01],
            color=LIGHT_GRAY, linewidth=1.2, zorder=2)
    ax.plot([ci_hi_3, ci_hi_3], [ext_ys[3] - 0.01, ext_ys[3] + 0.01],
            color=LIGHT_GRAY, linewidth=1.2, zorder=2)

    # Add usefulness error bars to the dotted line points (same CIs as loose plan)
    # These show the uncertainty in usefulness at each hypothetical point
    for i, cell in enumerate(["thr1.333", NOPLAN_CELL, "thr3.0", "thr5.0"]):
        u = usefulness[cell]
        yerr_lo = max(0.0, u["u"] - u["lo"])
        yerr_hi = max(0.0, u["hi"] - u["u"])
        ax.errorbar([ext_xs[i]], [ext_ys[i]], yerr=[[yerr_lo], [yerr_hi]],
                    fmt="none", ecolor=PIVOTAL_PALETTE[2], elinewidth=1.2, capsize=4, zorder=2)

    # Add a single legend entry for the DTD series (dotted line with marker)
    ax.plot([], [], linestyle=":", marker=noplan_marker, color=noplan_color,
            label=LEGEND_LABELS[NOPLAN_SERIES], markersize=6, linewidth=1.6)

    # Add the no-plan point to the rows for the table
    s = safety[NOPLAN_CELL]
    u = usefulness[NOPLAN_CELL]
    rows.append(dict(
        series=NOPLAN_SERIES, cell=NOPLAN_CELL, budget_pct=BUDGET, threshold=_cell_threshold(NOPLAN_CELL),
        attack_log=NOPLAN_ATTACK, honest_log=NOPLAN_HONEST,
        audit_threshold=s["threshold"],
        threshold_fraction=s["threshold_fraction"],
        safety=s["safety"], safety_lo=s["ci_lo"], safety_hi=s["ci_hi"],
        usefulness=u["u"], usefulness_lo=u["lo"], usefulness_hi=u["hi"],
        n_common=u["n_common"],
    ))

    print(f"no-plan safety offset vs thr2.333: {delta:+.4f}; dotted line corners: "
          + ", ".join(f"({x:.4f}, {y:.4f})" for x, y in zip(ext_xs, ext_ys)))

    # The figure itself is untitled (house style); this string heads the cover.
    title = (f"Claim 11: CES vs the DTD no-plan point + TM @ {BUDGET:g}% audit budget\n"
             "(BA1.0, AUTO-SUBMIT TRUNCATED, V7 attack, v11.1 tu-root-history monitor)")
    ax.set_xlabel("Safety"); ax.set_ylabel("Usefulness")
    ax.grid(alpha=0.3)
    # Extract legend handles and convert ErrorbarContainers to their line components
    handles, labels_ = ax.get_legend_handles_labels()
    handles = [h[0] if isinstance(h, ErrorbarContainer) else h for h in handles]
    # matplotlib yields bare Line2D artists (the DTD proxy) before ErrorbarContainers,
    # so re-sort into the canonical protocol sequence (TM, DTR, DTD, CES).
    _legend_rank = {LEGEND_LABELS[k]: i for i, k in enumerate(SERIES_ORDER)}
    handles, labels_ = zip(*sorted(
        zip(handles, labels_),
        key=lambda hl: _legend_rank.get(hl[1], len(_legend_rank)),
    ))
    # Lower left would sit on the CES point's error bar; center left is the empty band.
    ax.legend(handles, labels_, loc="center left")
    fig.tight_layout()

    cover = plt.figure(figsize=(8.5, 11))
    lines = [
        "Claim 11 Safety vs Usefulness (Pareto) — CES vs the DTD no-plan point",
        *title.split("\n"),
        f"Generated (UTC): {stamp}",
        # 566 vs 629 changes every TM/DTRF safety number, so a report that
        # omits the universe is not auditable.
        f"task_ids: {TASK_IDS_ALIAS}",
        f"arm_set: {ARM_SET}",
        *([
            "",
            "RF3 REPAIR: the TM, CES and loose-DTD (offset) attack cells are each the",
            "  [original _autosubmit, RF3 rerun] pool under pool_runs=dedup_latest_strict —",
            "  the RF3 rerun of each flag>=3 replay-damaged sample is authoritative, and a",
            "  task whose rerun errored is DROPPED (never falls back to the damaged original",
            "  row). The DTD no-plan point is in-loop and unchanged. See verify_rf3_groups.py.",
        ] if ARM_SET == "rf3" else []),
        "",
        "PLOT SERIES (legend names):",
        "  DTD: single measured point (thr2.333 plan-to-NO-implementer, WITHTIPS) from",
        "       20260821T173300Z_compare_DTD-thr2-333---plan-to-NO-implementer--WITHTIPS_...pdf",
        f"  \"{LEGEND_LABELS[CES_SERIES]}\" = CES: online decomposer, fixed script/config",
        "       trigger, TRUNCATED arm",
        "       (TOWER_C11_CES_ATTACK_AUTOSUBMIT / _RERUN_FLAG3 under --arm-set rf3).",
        f"       ⚠ The UNtruncated arm reads safety 0.8824 against this arm's",
        f"       {safety[CES_CELL]['safety']:.4f} — do not substitute it.",
        "  TM: trusted monitoring",
        "  (No DTRF series: claim 11 is CES-vs-DTD domination, and never had one.)",
        "",
        "DTD DOTTED LINE (hypothetical extrapolation, no data measured):",
        "  Extends from the single measured no-plan point upward through hypothetical",
        "  shifted versions of loose-plan thresholds (1.333, 3.0, 5.0). Each point is",
        "  shifted horizontally (safety axis) by delta = noplan.safety - thr2.333.safety",
        f"  = {safety[NOPLAN_CELL]['safety']:.4f} - {safety['thr2.333']['safety']:.4f}"
        f" = {delta:+.4f}. Also includes a vertical segment from the thr1.333",
        f"  usefulness level ({usefulness['thr1.333']['u']:.4f}) up to the measured point.",
        "",
        "ERROR BARS ON DOTTED LINE:",
        "  All hypothetical points have asymmetric horizontal error bars:",
        "    Upper bound (CI_hi): matches the original loose-plan threshold CI upper,",
        f"                        unshifted. (e.g., thr1.333's CI_hi = {safety['thr1.333']['ci_hi']:.4f})",
        "    Lower bound (CI_lo): shifted by the safety delta. (e.g., thr1.333's CI_lo",
        f"                        = {safety['thr1.333']['ci_lo']:.4f}, shifted = "
        f"{safety['thr1.333']['ci_lo']:.4f} + ({delta:+.4f}) = {safety['thr1.333']['ci_lo'] + delta:.4f})",
        "  Color: light gray (PIVOTAL_PALETTE[2]) for hypothetical points, series color",
        "         for the single measured point.",
        "",
        "CAVEAT (no loose-plan series): the DTD (selected design / loose-plan) points are",
        "  NOT plotted; only the single measured no-plan point appears, with its dotted",
        "  extrapolation through hypothetical shifted loose-plan points to illustrate the",
        "  safety lower bound that could be achieved with larger threshold values.",
        "",
        "CAVEAT (truncation REGIME mismatch, not a truncation gap): the withtips-noplan",
        "  attack log IS auto-submit truncated, but IN-LOOP — auto_submit has defaulted True",
        "  since 2026-08-19 (run_native.py, the CLAIM 14 block), so the trajectory really",
        "  ended at the first side-task success. It has no _autosubmit sibling because it",
        "  needs no post-hoc replay. TM / DTRF / the loose-plan DTD cells ARE post-hoc",
        "  _autosubmit replays. Both cut the post-exploit tail; they are not the same",
        "  operation (named_tasks_and_logs.py:4450-4470). CES and TM on this figure are",
        "  post-hoc replays. An earlier cover said the DTD log was NOT truncated; that was",
        "  wrong.",
        "",
        f"audit budget: {BUDGET:g}% of honest samples audited",
        "audit rule: fractional-tie threshold at the (100 - budget) percentile of the",
        "  HONEST arm's per-sample max suspicion, re-derived per budget",
        f"safety CIs: {SAFETY_BOOT}-draw cluster-by-task bootstrap (seed {SAFETY_SEED}),",
        "  threshold re-derived per draw (compute_safety_vs_audit_budget)",
        f"usefulness: (test - trusted) / (honest - trusted), {USE_BOOT}-draw bootstrap "
        f"(seed {USE_SEED});",
        "  budget-invariant; TM pinned to the pooled UH baseline (=1.0)",
        "resample_aggregation: None on every cell — no DTRF series, so nothing on this",
        "  figure has per-step alternative draws to aggregate.",
        f"sus_key: {SUS_KEY}    attack_threshold: {ATTACK_THRESHOLD}",
        f"CI width: {CONFIDENCE_INTERVAL_WIDTH:.2f}",
        "",
        "cells: only DTD no-plan + CES + TM are plotted. DTD (selected design / loose plan)",
        "  cells are used for error bar offset calculations on the dotted line, not plotted.",
        "Anchors imported from experiments/analysis/claim91_budget_pareto.py",
        "  (TRUSTED_LOGS_BA10 / BASELINE_LOGS_BA10).",
        "",
        "trusted (usefulness=0 anchor):",
        *[f"  {p}" for p in TRUSTED_LOGS],
        "honest baseline (usefulness=1 anchor, pooled):",
        *[f"  {p}" for p in BASELINE_LOGS],
        "",
        "── Plotted Cells ──",
    ]
    for r in rows:
        _pr = POOL_RUNS.get(r["cell"])
        lines += [
            f"{r['series']}  {r['cell']}" + (f"  [pool_runs={_pr}]" if _pr else ""),
            f"  attack: {', '.join(Path(x).name for x in _as_list(r['attack_log']))}",
            f"  honest: {', '.join(Path(x).name for x in _as_list(r['honest_log']))}",
            f"  safety={r['safety']:.4f} [{r['safety_lo']:.4f}, {r['safety_hi']:.4f}]"
            f"  tau={r['audit_threshold']:.4f} (frac {r['threshold_fraction']:.4f})",
            f"  usefulness={r['usefulness']:.4f} [{r['usefulness_lo']:.4f}, "
            f"{r['usefulness_hi']:.4f}]  n_common={r['n_common']}",
        ]
    cover.text(0.05, 0.98, "\n".join(lines), va="top", family="monospace", fontsize=7)
    cover.gca().set_axis_off()

    _set_sfx = {"autosubmit": "", "dropflag4": "_DROPFLAG4", "rf3": "_RF3"}[ARM_SET]
    out = out_dir / f"{stamp}_claim11_ces-vs-dtd-noplan_BA10_AUTOSUBMIT{_set_sfx}.pdf"
    table = _table_page(
        rows, generated_at=stamp,
        title=(f"Claim 11 @ {BUDGET:g}% audit budget (BA1.0, AUTO-SUBMIT TRUNCATED): "
               f"CES vs the DTD no-plan point + TM"),
        ci_width=CONFIDENCE_INTERVAL_WIDTH)
    with PdfPages(out) as pdf:
        pdf.savefig(cover, bbox_inches="tight"); plt.close(cover)
        pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)
        pdf.savefig(table, bbox_inches="tight"); plt.close(table)
    print(f"Report saved: {out}")


if __name__ == "__main__":
    main()
