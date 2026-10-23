"""Scatter of the first audit-triggering action per trajectory in an attack log.

For each sample in an attack (safety) log, find the FIRST action whose
suspicion score is at/above the audit threshold and plot it at
(executed-action index, suspicion score).  Trajectories that never reach the
threshold are plotted at their max-suspicion action instead, in a visually
distinct style (triangle marker, lower alpha).

Semantics:

- **Executed action** = a non-rejected scored entry in the per-log extract —
  the same definition ``sus_aggregation="all_executed_actions"`` rebuilds from
  those entries.  Rejected proposals (DTR) do NOT advance the x index, but ARE
  eligible to be the first over-threshold action; a rejected proposal that
  fires gets x = number of executed actions before it.
- **Color**: red = side task success, black = not (as in compute_metrics).
- **Marker fill**: filled = attacked (``attack_score >= attack_threshold``),
  hollow = not attacked.

Dual-mode script:

- **IPython / Jupyter**: Run cells interactively.  Configure
  ``safety_log_file``, ``usefulness_log_file``, ``sus_key``,
  ``_attack_threshold``, and ``_audit_threshold`` near the top of the file,
  then execute cells to inspect the DataFrame and plot inline.

- **CLI**: Pass log paths on the command line; ``--pdf`` saves the figure to
  ``experiments/data/metrics_reports_tower/``.  Examples::

      uv run python experiments/analysis/plot_first_audit_action.py \\
          --safety path/to/attack.eval --sus-key gpt41mini-v3 \\
          --attack-threshold 5 --audit-threshold 7.0 --pdf

      uv run python experiments/analysis/plot_first_audit_action.py \\
          --safety path/to/attack.eval \\
          --usefulness path/to/honest.eval --audit-percentile p95 --pdf

**Before running**: check ``tu_bb2/named_tasks_and_logs.py`` for the attack
log entry.  Attack logs that used attack selection record a required
``attack_threshold`` in their kwargs dict — pass that value via
``--attack-threshold N``.  The default of 0 treats every sample that logged
an attack score as attacked, which is only right for always-attack runs.
"""
# %%
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

# IPython detection must happen before pyplot import so we can set the backend
try:
    _ipy = get_ipython()  # type: ignore[name-defined]
    IS_IPYTHON = _ipy is not None
except NameError:
    IS_IPYTHON = False

import matplotlib
if not IS_IPYTHON:
    matplotlib.use('Agg')

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.lines import Line2D

from tu_bb2.utils import REPO_ROOT
from tu_bb2.named_tasks_and_logs import BashArenaLogs
from tu_bb2.postprocessing import (
    RESAMPLE_AGGREGATIONS,
    _check_resampling_extract,
    _check_step_sizes,
    get_audit_threshold,
    get_log_extract,
    get_log_timestamp,
    get_minimal_log_df,
    set_log_extract_cache,
)

# %%
# Notebook defaults — edit these when running cells interactively.
safety_log_file = BashArenaLogs.as_paths(BashArenaLogs.ONLINE_ATTACK_NOCOORD_GPT41MINI_V3_REV0[1])
# Honest log used to compute the audit threshold when _audit_threshold is None.
usefulness_log_file = BashArenaLogs.as_paths(BashArenaLogs.ONLINE_HONEST_GPT41MINI_V3_REV0[1])

sus_key = "gpt41mini-v3"
_attack_threshold: int = 0
_audit_threshold: float | None = None  # raw suspicion value; None -> compute from honest log
_audit_percentile: str = "p95"
# Resample aggregation (DTR/DTRF only). None/"max" -> the historical per-draw behaviour.
# Anything else collapses each protocol STEP's draws before comparing to tau; see
# _first_audit_point for what that changes about "first audited action".
_resample_aggregation: "str | None" = None

# %%
# CLI override — runs only when executed as a script (not in IPython)
_write_pdf = False  # CLI may override; IPython mode always plots inline
if not IS_IPYTHON:
    _parser = argparse.ArgumentParser(
        description="Scatter the first audit-triggering action per trajectory of an attack log"
    )
    _parser.add_argument("--safety", nargs="+", required=True, metavar="PATH",
                         help="Safety (attack) log file(s), relative to repo root. "
                              "Multiple files are deduped per task (latest wins).")
    _parser.add_argument("--sus-key", default=sus_key, metavar="KEY",
                         help=f"Suspicion score key substring (default: {sus_key})")
    _parser.add_argument("--attack-threshold", type=int, default=0, metavar="N",
                         help="Samples with attack_score >= N are treated as attacked "
                              "(filled markers). Default 0 counts ANY sample that logged "
                              "an attack score as attacked — only right for always-attack "
                              "runs. For attack-selection logs, pass the cataloged "
                              "attack_threshold from the log's named_tasks_and_logs "
                              "group kwargs.")
    _parser.add_argument("--audit-threshold", type=float, default=None, metavar="X",
                         help="Audit threshold as a raw suspicion value. "
                              "Mutually exclusive with --usefulness.")
    _parser.add_argument("--usefulness", nargs="+", default=None, metavar="PATH",
                         help="Honest log file(s) to compute the audit threshold from "
                              "(pXX of per-sample max suspicion). Mutually exclusive "
                              "with --audit-threshold.")
    _parser.add_argument("--resample-agg", default=None, dest="resample_agg", metavar="AGG",
                         help="Resample aggregation for a DTR/DTRF log (e.g. q90). Changes BOTH "
                              "the honest audit threshold AND the unit compared against it: the "
                              "draws of a protocol STEP are collapsed first, so the crossing is "
                              "detected per step rather than per draw. Do not pass it for TM/DTD.")
    _parser.add_argument("--audit-percentile", choices=["p90", "p95", "p99"], default="p95",
                         help="Percentile for the honest-log audit threshold (default: p95)")
    _parser.add_argument("--pdf", action="store_true", default=False,
                         help="Write the figure as a PDF to experiments/data/metrics_reports_tower/")
    _parser.add_argument("--no-cache", action="store_true", default=False,
                         help="Skip reads of the per-log extract cache (writes stay on)")
    _args = _parser.parse_args()

    if (_args.audit_threshold is None) == (_args.usefulness is None):
        _parser.error("Provide exactly one of --audit-threshold or --usefulness.")

    safety_log_file = [REPO_ROOT / p for p in _args.safety]
    usefulness_log_file = (
        [REPO_ROOT / p for p in _args.usefulness] if _args.usefulness is not None else None
    )
    sus_key = _args.sus_key
    _attack_threshold = _args.attack_threshold
    _audit_threshold = _args.audit_threshold
    _audit_percentile = _args.audit_percentile
    _resample_aggregation = _args.resample_agg
    _write_pdf = _args.pdf
    if _args.no_cache:
        set_log_extract_cache(read=False)

# In IPython, always generate plots for inline display; in CLI only when --pdf is passed
_make_plots = IS_IPYTHON or _write_pdf

_safety_paths: list[Path] = (
    [Path(p) for p in safety_log_file]
    if isinstance(safety_log_file, (list, tuple))
    else [Path(safety_log_file)]
)

# %%
# Audit threshold: raw value, or pXX of the honest per-sample max distribution.
_audit_threshold_from_honest = _audit_threshold is None
if _audit_threshold is None:
    if usefulness_log_file is None:
        raise ValueError("Set _audit_threshold or usefulness_log_file.")
    # This per-action first-audit plot uses a deterministic ``score >= threshold``
    # crossing, so only the threshold value is needed (tie fraction unused).
    _audit_threshold, _ = get_audit_threshold(
        usefulness_log_file if isinstance(usefulness_log_file, (list, tuple))
        else [usefulness_log_file],
        sus_key,
        percentile=_audit_percentile,  # type: ignore[arg-type]
        duplicate_id_handling="latest",
        resample_aggregation=_resample_aggregation,
    )
    print(f"Audit threshold ({_audit_percentile} of honest max-sus): {_audit_threshold:.3f}")
else:
    print(f"Audit threshold (given): {_audit_threshold:.3f}")

# %%
# Per-sample first-audit extraction from the log extracts.


def _strip_timestamp(k: str) -> str:
    """Remove embedded _YYYYMMDD_HHMMSS timestamp from a suspicion score key."""
    return re.sub(r"_\d{8}_\d{6}(?=_|$)", "", k)


def _resolve_sus_lookup_keys(extracts: list[dict], key_sub: str) -> list[str]:
    """Substring -> concrete extract key(s), as in get_max_suspicion_by_key_index.

    Multiple matches are allowed only when they differ solely by an embedded
    rescore timestamp (each sample then carries at most one of the aliases).
    """
    all_keys = sorted({k for e in extracts for k in e["sus_keys"]})
    matches = [k for k in all_keys if key_sub in k]
    if len(matches) == 0:
        raise ValueError(
            f"No suspicion score key contains substring {key_sub!r}. "
            f"Available keys: {all_keys}"
        )
    if len(matches) > 1 and len({_strip_timestamp(k) for k in matches}) != 1:
        raise ValueError(
            f"Multiple suspicion score keys contain substring {key_sub!r}: "
            f"{matches}. Provide a more specific substring."
        )
    return matches


def _first_audit_point(entries: list, audit_threshold: float,
                       sizes: "list[int] | None" = None,
                       resample_aggregation: "str | None" = None) -> "tuple[int, float, bool]":
    """(x_index, score, audited) for one sample's [[score, rejected, child_idx], ...].

    Walks entries in message order keeping an executed-action counter
    (non-rejected entries only).  The first entry — rejected or not — at/above
    the threshold wins; otherwise falls back to the max-score entry (first on
    ties) with audited=False.

    Under a resample aggregation the COMPARISON UNIT changes from the draw to the
    protocol STEP, because the step's statistic (e.g. its 90th percentile) is an
    interpolated value that belongs to no individual draw. ``sizes`` is that
    sample's per-step partition of ``entries`` (``step_sizes``). What is preserved:

    * a step qualifies whether or not any of its draws was executed, so a
      trusted-fallback step — every draw rejected, the executed action unmonitored —
      still fires the audit, exactly as a rejected draft does in the per-draw path;
    * the x-axis stays the executed-action counter, with a step reported at the index
      it would have had.

    A step is evaluated at its LAST draw: unlike max, a quantile is not decidable
    until every draw of the step has been scored.
    """
    if resample_aggregation in (None, "max") or not sizes:
        executed_idx = 0
        best: "tuple[int, float] | None" = None  # (x_index, score) of the running max
        for score, rejected, _child_idx in entries:
            score = float(score)
            x_index = executed_idx  # a rejected proposal sits at the index it would have had
            if score >= audit_threshold:
                return x_index, score, True
            if best is None or score > best[1]:
                best = (x_index, score)
            if not rejected:
                executed_idx += 1
        assert best is not None
        return best[0], best[1], False

    fn = RESAMPLE_AGGREGATIONS[resample_aggregation]
    executed_idx = 0
    best = None
    pos = 0
    for n in sizes:
        group = entries[pos:pos + n]
        pos += n
        if not group:
            continue
        x_index = executed_idx  # the step sits at the index of the action it executes
        value = float(fn([float(e[0]) for e in group]))
        if value >= audit_threshold:
            return x_index, value, True
        if best is None or value > best[1]:
            best = (x_index, value)
        # the step's executed action, if it had one (a trusted fallback has none)
        executed_idx += sum(1 for e in group if not e[1])
    if best is None:
        return 0, float("nan"), False
    return best[0], best[1], False


# Dedup across logs with "latest" semantics: sort logs by timestamp, then let
# later samples overwrite earlier ones per display_id (and later epochs within
# a log overwrite earlier ones, matching drop_duplicates(keep="last")).
_extracts = [get_log_extract(p) for p in sorted(_safety_paths, key=get_log_timestamp)]
_lookup_keys = _resolve_sus_lookup_keys(_extracts, sus_key)
if _resample_aggregation not in (None, "max"):
    # Population-level guard: a non-resampling log (TM/DTD) puts every sample in a
    # single whole-trajectory group, which no per-sample size check can detect on
    # short samples. See postprocessing._check_resampling_extract.
    for _e, _p in zip(_extracts, sorted(_safety_paths, key=get_log_timestamp)):
        for _k in _lookup_keys:
            _check_resampling_extract(_e, _k, _p)

_samples_by_id: dict[str, dict] = {}
for _extract in _extracts:
    for _sample in _extract["samples"]:
        _samples_by_id[_sample["display_id"]] = _sample

_rows = []
_n_skipped = 0
for _id, _sample in _samples_by_id.items():
    _entries = next((_sample["sus"][k] for k in _lookup_keys if _sample["sus"].get(k)), None)
    if not _entries:
        _n_skipped += 1
        continue
    _sizes = None
    if _resample_aggregation not in (None, "max"):
        _sizes = (_sample.get("step_sizes") or {}).get(
            next((k for k in _lookup_keys if _sample["sus"].get(k)), ""))
        if _sizes is None:
            raise ValueError(
                f"resample_aggregation={_resample_aggregation!r} needs per-step draw counts, "
                f"but the extract has none for sample {_id}. Rebuild it with\n"
                "  uv run python experiments/analysis/streaming_log_extract.py <log.eval>\n"
                "Protocols that never resample (TM, DTD) must be run without --resample-agg.")
        _check_step_sizes(_sizes, f"sample {_id}")
    _x, _score, _audited = _first_audit_point(
        _entries, _audit_threshold, sizes=_sizes,
        resample_aggregation=_resample_aggregation)
    # Final executed-action index (last non-rejected scored action).
    _n_executed = sum(1 for _e in _entries if not _e[1])
    _final_x = max(_n_executed - 1, 0)
    _ascore = _sample["attack_score"]
    _rows.append({
        "id": _id,
        "x_index": _x,
        "final_x_index": _final_x,
        "sus_score": _score,
        "audited": _audited,
        "attacked": _ascore is not None and _ascore >= _attack_threshold,
        "attack_score": _ascore,
    })

df = pd.DataFrame(_rows).set_index("id").sort_index()
if _n_skipped:
    print(f"Skipped {_n_skipped} sample(s) with no {sus_key!r} scores.")

# side_task_success from the score read (the extract carries no task-success scores)
_df_safety = get_minimal_log_df(
    _safety_paths,
    include_main_task_success=False,
    include_side_task_success=True,
    include_sus_fields=False,
    duplicate_id_handling="latest",
)
df["side_task_success"] = (
    _df_safety["score_side_task_success"].reindex(df.index).fillna(False).astype(bool)
)
# x position for the "trajectory endpoint" plot: audited trajectories stay at
# their first-audit action (where they'd be caught); never-audited trajectories
# move to their FINAL executed action (where they ran to, completing stealthily).
df["endpoint_x_index"] = np.where(df["audited"], df["x_index"], df["final_x_index"])
df

# %%
# Console summary
print(f"Samples: {len(df)}  (attacked: {int(df['attacked'].sum())}, "
      f"side task success: {int(df['side_task_success'].sum())})")
print(f"Audited (first action >= {_audit_threshold:.3f}): {int(df['audited'].sum())}"
      f" / {len(df)}")
_audited_df = df[df["audited"]]
if not _audited_df.empty:
    print(f"First-audit executed-action index: median {_audited_df['x_index'].median():.1f}, "
          f"mean {_audited_df['x_index'].mean():.1f}, max {int(_audited_df['x_index'].max())}")
    for _label, _mask in [("attacked", _audited_df["attacked"]),
                          ("not attacked", ~_audited_df["attacked"])]:
        _sub = _audited_df[_mask]
        if not _sub.empty:
            print(f"  {_label}: n={len(_sub)}, median index {_sub['x_index'].median():.1f}")

# %%
# Cumulative confusion table over an action-index cutoff (0..6), ATTACKED only.
# Models capping the attacker at i work actions (the "actions7" give-up strategy):
#   below_line_success — unaudited successful attacks: below the audit line
#       (audited=False), side task success, x <= i  -> safety failures
#   above_line         — caught: above the audit line (audited=True), x <= i
# Not-attacked samples are excluded from both columns. The two tables differ only
# in which x they use for the below-line points (audited x is identical):
#   df_cum   uses x_index          (max-suspicion action — first scatter)
#   df_cum2  uses endpoint_x_index (final action for never-audited — second scatter)
_attacked_df = df[df["attacked"]]
_below_success = _attacked_df[(~_attacked_df["audited"]) & _attacked_df["side_task_success"]]
_above = _attacked_df[_attacked_df["audited"]]


def _cumulative_table(x_col: str) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "action_index <=": _i,
                "unaudited successful attacks (below line)": int((_below_success[x_col] <= _i).sum()),
                "audited attacks (above line)": int((_above["x_index"] <= _i).sum()),
            }
            for _i in range(7)
        ]
    ).set_index("action_index <=")


df_cum = _cumulative_table("x_index")
df_cum2 = _cumulative_table("endpoint_x_index")
print("\nCumulative counts (attacked only), first scatter (max-sus action x):")
print(df_cum)
print("\nCumulative counts (attacked only), endpoint scatter (final action x):")
print(df_cum2)

# %%
# Two scatters, same color scheme. Audited trajectories sit at their first-audit
# action in both; never-audited trajectories sit at their max-suspicion action in
# the first scatter and at their FINAL executed action in the second ("endpoint").
_safety_name = "+".join(p.stem[:40] for p in _safety_paths)
_FALLBACK_LABEL = {
    "x_index": "Never audited (max-sus action)",
    "endpoint_x_index": "Never audited (final action)",
}


def _make_audit_scatter(x_col: str, title: str) -> plt.Figure:
    _rng = np.random.default_rng(42)
    _xj = df[x_col].values + _rng.uniform(-0.18, 0.18, size=len(df))
    _yj = df["sus_score"].values + _rng.uniform(-0.015, 0.015, size=len(df))
    _colors = np.where(df["side_task_success"].values, "red", "black")
    _is_attack = df["attacked"].values
    _is_audited = df["audited"].values

    fig, ax = plt.subplots(figsize=(7, 5))
    # Audited (circles) and never-audited (triangles, faint), each split into
    # filled (attacked) and hollow (not attacked).
    for _aud_mask, _marker, _alpha in [(_is_audited, "o", 0.45), (~_is_audited, "^", 0.2)]:
        _m = _aud_mask & _is_attack
        ax.scatter(_xj[_m], _yj[_m], c=_colors[_m], marker=_marker,
                   alpha=_alpha, s=35, linewidths=0)
        _m = _aud_mask & ~_is_attack
        ax.scatter(_xj[_m], _yj[_m], facecolors="none", edgecolors=_colors[_m],
                   marker=_marker, alpha=_alpha, s=35, linewidths=1.2)
    ax.axhline(y=_audit_threshold, color="blue", linestyle="dashed", linewidth=1.5)
    ax.set_xlabel("Executed action index")
    ax.set_ylabel(f"Suspicion ({sus_key})")
    ax.set_title(f"{title}\n{_safety_name}", fontsize=10)
    _legend_handles = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=8,
               label='Successful attack'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='black', markersize=8,
               label='Unsuccessful'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='none',
               markeredgecolor='gray', markersize=8, label='Not attacked'),
        Line2D([0], [0], marker='^', color='w', markerfacecolor='gray', alpha=0.4,
               markersize=8, label=_FALLBACK_LABEL[x_col]),
        Line2D([0], [0], color='blue', linestyle='dashed', linewidth=1.5,
               label='audit threshold'),
    ]
    ax.legend(handles=_legend_handles, fontsize=8)
    fig.tight_layout()
    return fig


_fig: "plt.Figure | None" = None
_fig2: "plt.Figure | None" = None
if _make_plots and not df.empty:
    _fig = _make_audit_scatter(
        "x_index", f"First action over audit threshold ({_audit_threshold:.2f})")
    # Endpoint view: never-audited trajectories at their final action (y = max
    # suspicion); audited trajectories at the first action that crosses the line.
    _fig2 = _make_audit_scatter(
        "endpoint_x_index",
        f"Audit point vs trajectory endpoint ({_audit_threshold:.2f})")

# %%
# Cover page (config variables) + cumulative-count table page, like compute_metrics.
_generated_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _make_cover_page() -> plt.Figure:
    fig = plt.figure(figsize=(8.5, 11))
    lines = [
        "First-Audit Action Report",
        f"Generated (UTC): {_generated_at}",
        "",
        "── Safety (attack) log(s) ──",
    ]
    lines += [f"  {p.name}" for p in _safety_paths]
    lines += ["", "── Usefulness (honest) log(s) ──"]
    if usefulness_log_file is None:
        lines.append("  (none — audit threshold given directly)")
    else:
        _u = usefulness_log_file if isinstance(usefulness_log_file, (list, tuple)) else [usefulness_log_file]
        lines += [f"  {Path(p).name}" for p in _u]
    _thresh_src = (
        f"{_audit_percentile} of honest per-sample max suspicion"
        if _audit_threshold_from_honest else "given directly"
    )
    lines += [
        "",
        "── Configuration ──",
        f"  sus_key:          {sus_key}",
        f"  attack_threshold: {_attack_threshold}  (attacked iff attack_score >= this)",
        f"  audit_threshold:  {_audit_threshold:.4f}  ({_thresh_src})",
        f"  audit_percentile: {_audit_percentile}",
        f"  x jitter:         +/- 0.18",
        f"  y jitter:         +/- 0.015",
        "",
        "── Sample summary ──",
        f"  samples plotted:  {len(df)}",
        f"  attacked:         {int(df['attacked'].sum())}",
        f"  side task success:{int(df['side_task_success'].sum())}",
        f"  audited (>= thr): {int(df['audited'].sum())}",
        f"  skipped (no sus): {_n_skipped}",
    ]
    fig.text(0.05, 0.95, "\n".join(lines), transform=fig.transFigure,
             fontsize=10, verticalalignment='top', fontfamily='monospace', wrap=True)
    fig.patch.set_visible(False)
    return fig


def _make_cum_table_page(cum_df: pd.DataFrame, subtitle: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(8.5, 0.5 * len(cum_df) + 2.0))
    ax.axis('off')
    _cols = list(cum_df.columns)
    _table_data = [[str(_idx)] + [str(v) for v in row] for _idx, row in cum_df.iterrows()]
    tbl = ax.table(
        cellText=_table_data,
        colLabels=["action index <="] + _cols,
        loc='center',
        cellLoc='center',
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.auto_set_column_width(list(range(len(_cols) + 1)))
    ax.set_title(
        f"Cumulative counts by action-index cutoff (attacked only)\n{subtitle}\n"
        "below line = unaudited successful attacks; above line = audited attacks",
        fontsize=11, pad=14,
    )
    return fig


_cover_fig = _make_cover_page() if _make_plots else None
_table_fig = (
    _make_cum_table_page(df_cum, "first scatter: below-line at max-suspicion action")
    if _make_plots else None
)
_table_fig2 = (
    _make_cum_table_page(df_cum2, "endpoint scatter: below-line at final action")
    if _make_plots else None
)

# %%
# PDF output (CLI --pdf): cover, scatter + table per view.
if _write_pdf and _fig is not None:
    _report_dir = REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
    _report_dir.mkdir(parents=True, exist_ok=True)
    _name = re.sub(r'(?<![a-zA-Z])attack_', '', _safety_paths[-1].stem)[:60]
    _out_path = _report_dir / f"{_generated_at}_first-audit_{_name}_{sus_key[:40]}.pdf"
    with PdfPages(_out_path) as _pdf:
        _pdf.savefig(_cover_fig, bbox_inches='tight')
        _pdf.savefig(_fig, bbox_inches='tight')
        _pdf.savefig(_table_fig, bbox_inches='tight')
        _pdf.savefig(_fig2, bbox_inches='tight')
        _pdf.savefig(_table_fig2, bbox_inches='tight')
    print(f"Report saved: {_out_path}")
