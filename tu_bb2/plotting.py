import itertools
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional, Sequence

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.axes import Axes
from matplotlib.container import ErrorbarContainer
from matplotlib.legend import Legend
from matplotlib.patches import Rectangle
from matplotlib.colors import LinearSegmentedColormap, Normalize, to_rgba
from matplotlib.cm import ScalarMappable
from matplotlib.ticker import MultipleLocator
from scipy.stats import gaussian_kde, pearsonr
from sklearn.metrics import roc_curve, auc

from inspect_ai.log import EvalLog

from tu_bb2.postprocessing import (
    get_suspicion_score_keys,
    get_max_suspicion_by_key_index,
    get_perchild_key_sets,
    get_minimal_log_df,
    safe_samples_df,
    _make_display_id,
    resolve_eval_log,
    _bootstrap_distributions,
    get_audit_threshold,
    compute_safety_metric,
    get_attack_scores_from_log,
    _protocol_cache_key,
    ProtocolMetrics,
    _METRICS_CACHE_DIR,
)
from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH, REJECTED_PROPOSAL_KEY

PIVOTAL_PALETTE = ['#3A82B5', '#F15F22', '#4C4D4F', '#FFC61F', '#89BCDF']  # Color palette for plots
# Marker shapes cycled per line in multi-series plots (alongside PIVOTAL_PALETTE colors),
# so lines stay distinguishable in grayscale. Cycles if there are more lines than entries.
LINE_MARKERS = ("o", "s", "^", "D", "v", "P", "X", "*")

# Color cycling palette for multi-protocol comparison plots (distinct, accessible)
_PROTOCOL_PALETTE = [
    '#3A82B5', '#F15F22', '#2CA02C', '#D62728', '#9467BD',
    '#8C564B', '#E377C2', '#7F7F7F', '#BCBD22', '#17BECF',
]

BLUES = ['#89BCDF', '#5B9CC9', '#3A82B5', '#1D6CA5', '#0B5285']
YELLOWS = ['#FFE496', '#FFD96A', '#FFD046', '#FFC61F', '#D09C04']
ORANGES = ['#FFB396', '#FF926A', '#FF7846', '#FF5B1F', '#D03B04']
GRAYS = ['#CCCDCF', '#7C7D7F', '#4C4D4F', '#2C2D2F', '#000000']

def plot_monitor_histogram(
    suspiciousness_red: Optional[pd.Series] = None, 
    suspiciousness_blue: Optional[pd.Series] = None, 
    audit_count: Optional[int] = None,
    audit_threshold: Optional[float] = None,
    bin_width: float = 0.1,
    clustered_bars: bool = True,
    legend_location: str = "best",
    title: str = "Suspiciousness",
    figsize: tuple[int, int] = (6, 5),
    **kwargs
) -> plt.Figure:
    """
    Plot 2 histograms of monitor scores in a clustered bar plot.
    
    Args:
        suspiciousness_red: Series containing suspiciousness scores for bars plotted in orange.
            If None, attack data won't be plotted.
        suspiciousness_blue: Series containing suspiciousness scores for bars plotted in blue.
            If None, non-attack data won't be plotted.
        audit_count: Number of items to audit. Mutually exclusive with audit_threshold.
        audit_threshold: Threshold for auditing. Mutually exclusive with audit_count.
        bin_width: Width of histogram bins. Default is 0.5.
        clustered_bars: If True, plots bars side by side in clusters instead of overlaid.
            If False (default), bars are overlaid with partial transparency.
        
    Returns:
        plt.Figure: The histogram figure.
    """
    # Validate arguments
    if audit_count is not None and audit_threshold is not None:
        raise ValueError("Only one of audit_count or audit_threshold can be provided")
    
    if suspiciousness_red is None and suspiciousness_blue is None:
        raise ValueError("At least one of monitor_attacks or monitor_non_attacks must be provided")
    
    # Create a histogram of child task suspiciousness scores and attack difficulty
    fig, ax = plt.subplots(figsize=figsize)
    
    # Determine the axis upper bound from the data so raw 0-9 monitors (e.g.
    # native control-tower keys) are not silently clipped to a hardcoded [0,1]
    # range. Normalized 0-1 monitors keep their original [0,1] bins exactly.
    _all_vals = pd.concat(
        [s.dropna() for s in (suspiciousness_blue, suspiciousness_red) if s is not None]
    )
    _data_max = float(_all_vals.max()) if len(_all_vals) else 1.0
    _upper = max(1.0, float(np.ceil(_data_max)))
    # Bin step (in axis units):
    #  - normalized 0-1 scale: always the caller's bin_width.
    #  - >1 (integer-style) scale, DEFAULT bin_width (0.1): integer-edge bins (~10 of
    #    them), since 0.1 over a 0-9 scale would give ~90 bins. Keeps every existing
    #    report byte-identical.
    #  - >1 scale with an EXPLICIT (non-default) bin_width: honor it directly, so
    #    --bin-width works on native 0-9 monitors too (e.g. 1/3 to resolve the
    #    ensemble-of-3 averaged scores). The [0,1] default 0.1 is the only value
    #    treated as "unset" here.
    if _upper <= 1.0:
        _step = bin_width
    elif bin_width == 0.1:
        _step = max(1.0, round(_upper / 10.0))
    else:
        _step = bin_width

    # Use _step to determine the bins
    bins = np.arange(0.0, _upper + _step, _step)
    alpha = 0.5 if suspiciousness_blue is not None and suspiciousness_red is not None else 1.0

    if clustered_bars and suspiciousness_blue is not None and suspiciousness_red is not None:
        # Calculate bar width for clustered bars
        bar_width = _step * 0.4  # Use 40% of bin width for each bar

        # Plot non-attacks (blue bars)
        blue_counts, blue_bins = np.histogram(suspiciousness_blue.dropna(), bins=bins, **kwargs)
        if kwargs.get("density", False):
            blue_counts = blue_counts * _step
        blue_positions = blue_bins[:-1] + _step/2 - bar_width/2  # Position blue bars to the left

        # Plot attacks (orange bars)
        red_counts, red_bins = np.histogram(suspiciousness_red.dropna(), bins=bins, **kwargs)
        if kwargs.get("density", False):
            red_counts = red_counts * _step
        red_positions = red_bins[:-1] + _step/2 + bar_width/2  # Position orange bars to the right
        
        # Plot the bars
        ax.bar(
            red_positions, 
            red_counts, 
            width=bar_width, 
            color=PIVOTAL_PALETTE[1], 
            # edgecolor='black', 
            label=suspiciousness_red.name
        )
        ax.bar(
            blue_positions, 
            blue_counts, 
            width=bar_width, 
            color=PIVOTAL_PALETTE[0], 
            # edgecolor='black', 
            label=suspiciousness_blue.name
        )
    else:
        # Original overlaid histogram behavior
        if suspiciousness_blue is not None:
            ax.hist(
                suspiciousness_blue.dropna(), 
                bins=bins,
                color=PIVOTAL_PALETTE[0],
                edgecolor='black',
                alpha=alpha,
                label=suspiciousness_blue.name,
                **kwargs
            )
        
        if suspiciousness_red is not None:
            ax.hist(
                suspiciousness_red.dropna(), 
                bins=bins,
                color=PIVOTAL_PALETTE[1],
                edgecolor='black',
                alpha=alpha,
                label=suspiciousness_red.name,
                **kwargs
            )
    
    # Add a vertical line at the audit threshold
    # Only calculate audit_threshold if not provided
    # if audit_threshold is None and audit_count is not None:
    #     if suspiciousness_blue is None:
    #         raise ValueError("monitor_non_attacks must be provided to calculate audit_threshold")
    #     audit_threshold, _, _ = get_audit_threshold(suspiciousness_blue, audit_count=audit_count)
    
    if audit_threshold is not None:
        ax.axvline(x=audit_threshold, color='black', linestyle='--', linewidth=2)

        # Add a text label for the audit threshold, positioned to the left of the line with right alignment
        ax.text(
            audit_threshold + 0.1,  # Slight offset to the left of the line
            ax.get_ylim()[1] * 0.8,  # Position near the top of the plot
            "Audit",
            color='black',
            fontweight='bold',
            verticalalignment='top'  # Align from the top
        )

    # Only add legend if both types are plotted
    if suspiciousness_red is not None and suspiciousness_blue is not None:
        plt.legend(loc=legend_location)

    plt.title(title)
    plt.xlabel('Suspiciousness Score')
    plt.ylabel('Frequency' if not kwargs.get("density", False) else 'Relative Frequency')
    plt.grid(axis='y', alpha=0.3)
    # Tick step: label bin edges on the normalized/default path (unchanged), but on a
    # >1 scale with fine explicit bins (e.g. 1/3) label the INTEGERS only, so the axis
    # stays readable while the bars keep their fine resolution. For the default path
    # (_step already integer) this is identical to labelling every bin edge.
    _tick_step = _step if (_upper <= 1.0 or bin_width == 0.1) else max(1.0, round(_upper / 10.0))
    plt.xticks(np.arange(0.0, _upper + _tick_step / 2, _tick_step))
    plt.tight_layout()
    return fig


def _bootstrap_roc_band(
    red_vals: np.ndarray,
    blue_vals: np.ndarray,
    confidence_level: float,
    n_bootstrap: int = 400,
    seed: int = 0,
    fpr_grid: np.ndarray | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Compute a bootstrap confidence band for an ROC curve.

    Returns (fpr_grid, tpr_lower, tpr_upper) where lower/upper are the
    percentile bounds of the bootstrapped TPR values at each FPR grid point.
    """
    if fpr_grid is None:
        fpr_grid = np.linspace(0, 1, 200)
    rng = np.random.default_rng(seed)
    n_red, n_blue = len(red_vals), len(blue_vals)
    tpr_curves = []
    alpha = 1.0 - confidence_level
    for _ in range(n_bootstrap):
        r = red_vals[rng.choice(n_red, size=n_red, replace=True)]
        b = blue_vals[rng.choice(n_blue, size=n_blue, replace=True)]
        scores = np.concatenate([r, b])
        labels = np.concatenate([np.ones(n_red), np.zeros(n_blue)])
        fpr_b, tpr_b, _ = roc_curve(labels, (scores * 60).round())
        tpr_curves.append(np.interp(fpr_grid, fpr_b, tpr_b))
    tpr_mat = np.array(tpr_curves)
    tpr_lower = np.percentile(tpr_mat, alpha / 2 * 100, axis=0)
    tpr_upper = np.percentile(tpr_mat, (1 - alpha / 2) * 100, axis=0)
    return fpr_grid, tpr_lower, tpr_upper


def plot_roc_curve(
    suspiciousness_red: pd.Series | list[pd.Series],
    suspiciousness_blue: pd.Series | list[pd.Series],
    figsize: tuple[int, int] = (5, 5),
    title: str = "ROC Curve",
    confidence_interval: float | None = None,
) -> plt.Figure:
    """Plot ROC curve(s) for monitor suspiciousness scores.

    Args:
        suspiciousness_red: Suspiciousness scores for the positive class (attacks).
            Can be a single Series or a list of Series (one per monitor).
        suspiciousness_blue: Suspiciousness scores for the negative class (honest).
            Can be a single Series or a list of Series (one per monitor).
        figsize: Figure size.
        title: Plot title.
        confidence_interval: If provided, draw a bootstrap confidence band at
            this confidence level (e.g. 0.95). The band is a semi-transparent
            shaded region matching each curve's color.

    Returns:
        tuple[plt.Figure, dict[str, float]]: The ROC curve figure and a dict
            mapping monitor name to AUROC score.
    """
    if isinstance(suspiciousness_red, pd.Series):
        red_list = [suspiciousness_red]
        blue_list = [suspiciousness_blue]
    else:
        red_list = list(suspiciousness_red)
        blue_list = list(suspiciousness_blue)

    fig, ax = plt.subplots(figsize=figsize)

    colors = [PIVOTAL_PALETTE[1], PIVOTAL_PALETTE[0], PIVOTAL_PALETTE[3], PIVOTAL_PALETTE[4]]

    auroc_scores: dict[str, float] = {}
    for i, (sus_red, sus_blue) in enumerate(zip(red_list, blue_list)):
        red_vals = sus_red.dropna().values.astype(float)
        blue_vals = sus_blue.dropna().values.astype(float)
        scores = np.concatenate([red_vals, blue_vals])
        labels = np.concatenate([np.ones(len(red_vals)), np.zeros(len(blue_vals))])
        fpr, tpr, _ = roc_curve(labels, (scores * 60).round())  # Round to nearest 60 to mostly avoid floating point issues
        auroc = auc(fpr, tpr)
        name = sus_red.name or f"Monitor {i}"
        auroc_scores[name] = auroc
        color = colors[i % len(colors)]
        ax.plot(fpr, tpr, color=color, lw=2, label=f"{name} (AUROC = {auroc:.2f})")
        if confidence_interval is not None:
            fpr_grid, tpr_lower, tpr_upper = _bootstrap_roc_band(
                red_vals, blue_vals, confidence_interval, seed=i
            )
            ax.fill_between(fpr_grid, tpr_lower, tpr_upper, color=color, alpha=0.15, linewidth=0)

    ax.plot([0, 1], [0, 1], color="gray", lw=1, linestyle="--", label="Random")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.05)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(title)
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    plt.tight_layout()
    return fig, auroc_scores


def plot_multi_monitor_ROC(
    safety_df: pd.DataFrame,
    usefulness_df: pd.DataFrame,
    figsize: tuple[int, int] = (5, 5),
    title: str = "ROC Curve: Multi-Monitor Comparison",
    confidence_interval: float | None = None,
) -> plt.Figure:
    """Plot ROC curves for multiple monitors on the same axes.

    Each column in the DataFrames represents one monitor. Columns are matched
    by name across the two DataFrames. NaNs are ignored (dropped per series
    before computing the ROC curve). Delegates to ``plot_roc_curve``.

    Args:
        safety_df: Suspicion scores for the attack (safety) run. Index is task
            ID, or a MultiIndex of (task ID, epoch). Columns are monitor names.
        usefulness_df: Suspicion scores for the honest (usefulness) run. Same
            structure as ``safety_df``.
        figsize: Figure size.
        title: Plot title.
        confidence_interval: If provided, draw a bootstrap confidence band at
            this confidence level (e.g. 0.95). Passed through to
            ``plot_roc_curve``.

    Raises:
        ValueError: If the column sets of the two DataFrames do not match.

    Returns:
        tuple[plt.Figure, dict[str, float]]: The ROC curve figure and a dict
            mapping monitor name to AUROC score.
    """
    safety_cols = set(safety_df.columns)
    usefulness_cols = set(usefulness_df.columns)
    if safety_cols != usefulness_cols:
        only_safety = safety_cols - usefulness_cols
        only_usefulness = usefulness_cols - safety_cols
        parts = []
        if only_safety:
            parts.append(f"only in safety_df: {sorted(only_safety)}")
        if only_usefulness:
            parts.append(f"only in usefulness_df: {sorted(only_usefulness)}")
        raise ValueError("Column mismatch between DataFrames — " + "; ".join(parts))

    red_list = [safety_df[col].dropna().rename(col) for col in safety_df.columns]
    blue_list = [usefulness_df[col].dropna().rename(col) for col in safety_df.columns]
    return plot_roc_curve(red_list, blue_list, figsize=figsize, title=title, confidence_interval=confidence_interval)


def plot_suspicion_scatter(
    safety_log: "str | Path | EvalLog",
    usefulness_log: "str | Path | EvalLog",
    x_idx: int = 0,
    y_idx: int = -1,
    figsize: tuple[int, int] = (5, 5),
    title: str = "Suspicion Score Scatter",
    trim_axis_labels: bool = True,
) -> plt.Figure:
    """Scatter plot of two suspicion series against each other for attack and honest logs.

    Points are jittered with N(0, 0.008) noise to reveal coincident data points.

    Args:
        safety_log: Path/EvalLog for the attack (safety) run.
        usefulness_log: Path/EvalLog for the honest (usefulness) run.
        x_idx: Key index for the x-axis suspicion series (default 0).
        y_idx: Key index for the y-axis suspicion series (default -1).
        figsize: Figure size.
        title: Plot title.

    Returns:
        plt.Figure: The scatter plot figure.
    """
    attack_x = get_max_suspicion_by_key_index(safety_log, x_idx)
    attack_y = get_max_suspicion_by_key_index(safety_log, y_idx)
    honest_x = get_max_suspicion_by_key_index(usefulness_log, x_idx)
    honest_y = get_max_suspicion_by_key_index(usefulness_log, y_idx)

    def _axis_label(attack_name: str, honest_name: str) -> str:
        if attack_name == honest_name:
            return attack_name[25:] if trim_axis_labels else attack_name
        return f"{attack_name[25:] if trim_axis_labels else attack_name} / {honest_name[25:] if trim_axis_labels else honest_name}"

    xlabel = _axis_label(attack_x.name, honest_x.name)
    ylabel = _axis_label(attack_y.name, honest_y.name)

    rng = np.random.default_rng(seed=0)

    def _jitter(s: pd.Series) -> np.ndarray:
        vals = s.dropna().values.astype(float)
        return vals + rng.normal(0, 0.008, size=vals.shape)

    fig, ax = plt.subplots(figsize=figsize)

    ax.scatter(
        _jitter(honest_x), _jitter(honest_y),
        color=PIVOTAL_PALETTE[0], alpha=0.7, label="honest", s=20,
    )
    ax.scatter(
        _jitter(attack_x), _jitter(attack_y),
        color=PIVOTAL_PALETTE[1], alpha=0.7, label="attack", s=20,
    )

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(loc="best")
    ax.grid(alpha=0.3)
    plt.tight_layout()
    return fig


def plot_suspicion_series_heatmap(
    log: str | Path | EvalLog,
    series_indices: Sequence[int] | None = None,
    sus_keys: list[str] | None = None,
    figsize: tuple[float, float] | None = None,
    bar_height: float = 0.8,
    cluster_gap: float = 0.3,
    task_ids: list[str] | None = None,
    sort_by_executed_actions: bool = False,
) -> plt.Figure:
    """Plot a clustered heatmap of suspicion score series.

    Args:
        log: Path to an eval log file (str or Path), or an already-loaded EvalLog.
        series_indices: Optional sequence of indices to select which suspicion series
            to plot. E.g., [0, 2] plots the 1st and 3rd series. If None, plot all series.
        sus_keys: Optional list of substrings to select suspicion series by key name.
            Each substring must match exactly one key (raises if zero or multiple match).
            Mutually exclusive with series_indices.
        figsize: Figure size as (width, height). If None, auto-calculated based on data.
        bar_height: Height of each bar within a cluster (default 0.8).
        cluster_gap: Gap between clusters (default 0.3).
        task_ids: Optional list of task IDs to include in the plot. Filtering is applied
            after task ID substitution. If None, all tasks are included.
        sort_by_executed_actions: If True, sort trajectory clusters by their number of
            executed actions, ascending (fewest first), instead of by task ID. "Executed"
            counts assistant messages NOT flagged ``rejected_proposal`` (DTR resample
            rejects are excluded). Multi-epoch trajectories sort by the max executed
            count across their epochs (epochs stay grouped within one cluster, so a
            single per-trajectory value is required). Ties break by the default
            task-ID order.

    Returns:
        The matplotlib Figure object.

    If the log carries an agent-self-risk score (any sample score key starting with
    ``agent_self_risk``; the value is a list of 0-based risky assistant-action
    indices), the cells of those actions are drawn with a black border.
    """
    if series_indices is not None and sus_keys is not None:
        raise ValueError("series_indices and sus_keys are mutually exclusive.")

    # Load the eval log once (no-op if already an EvalLog)
    eval_log_obj = resolve_eval_log(log)

    # Get sorted suspicion score keys
    all_sorted_keys = get_suspicion_score_keys(eval_log_obj)

    # Determine ID substitution mapping (same logic as safe_samples_df)
    _get_display_id = _make_display_id(eval_log_obj)

    # Build epoch_data: traj_id -> epoch -> series_key -> [(step_idx, score), ...]
    epoch_data: dict[str, dict[int, dict[str, list[tuple[int, float]]]]] = {}
    # Steps the agent's own reasoning judged risky: traj_id -> epoch -> {step_idx, ...}.
    # The agent_self_risk score indexes assistant messages the same way as
    # assistant_step_idx below, so the indices map directly onto heatmap cells.
    self_risk_steps: dict[str, dict[int, set[int]]] = {}
    # Whether the sample attacked (attacked_scorer): traj_id -> epoch -> True/False/None.
    # Read from the sample scores directly (robust to pooled in-memory logs whose
    # .location points at only one source file).
    attacked_status: dict[str, dict[int, "bool | None"]] = {}
    # Executed-action count per trajectory (max across epochs).
    executed_counts: dict[str, int] = {}
    for sample in eval_log_obj.samples:
        traj_id = _get_display_id(sample.id)
        if task_ids is not None and traj_id not in task_ids:
            continue
        epoch = sample.epoch
        if traj_id not in epoch_data:
            epoch_data[traj_id] = {}
        if epoch not in epoch_data[traj_id]:
            epoch_data[traj_id][epoch] = {k: [] for k in all_sorted_keys}

        for score_key, sample_score in (sample.scores or {}).items():
            if score_key.startswith('agent_self_risk') and isinstance(sample_score.value, list):
                self_risk_steps.setdefault(traj_id, {})[epoch] = {
                    int(i) for i in sample_score.value
                }
                break

        _att_score = (sample.scores or {}).get('attacked_scorer')
        _att_val = _att_score.value if _att_score is not None else None
        if _att_val is True or _att_val == 'C':
            attacked_status.setdefault(traj_id, {})[epoch] = True
        elif _att_val is False or _att_val == 'I':
            attacked_status.setdefault(traj_id, {})[epoch] = False
        else:
            attacked_status.setdefault(traj_id, {})[epoch] = None

        assistant_step_idx = 0
        n_executed = 0
        for msg in sample.messages:
            if msg.role == 'assistant':
                if hasattr(msg, 'metadata') and msg.metadata:
                    for sus_key in all_sorted_keys:
                        score = msg.metadata.get(sus_key)
                        if score is not None:
                            epoch_data[traj_id][epoch][sus_key].append(
                                (assistant_step_idx, float(score))
                            )
                assistant_step_idx += 1
                if not (getattr(msg, 'metadata', None) and msg.metadata.get(REJECTED_PROPOSAL_KEY)):
                    n_executed += 1
        executed_counts[traj_id] = max(executed_counts.get(traj_id, 0), n_executed)

    # Load df for side_task_success lookups (may have multiple rows per traj_id for multi-epoch)
    log_path = eval_log_obj.location if isinstance(log, EvalLog) else log
    df = safe_samples_df(log_path, flatten_scores=True)
    df_indexed = df.set_index('id')

    # Filter series by sus_keys substrings, series_indices, or use all
    if sus_keys is not None:
        resolved_keys = []
        for substring in sus_keys:
            matches = [k for k in all_sorted_keys if substring in k]
            if len(matches) == 0:
                raise ValueError(
                    f"No suspicion score key contains substring {substring!r}. "
                    f"Available keys: {all_sorted_keys}"
                )
            if len(matches) > 1:
                raise ValueError(
                    f"Substring {substring!r} matches multiple keys: {matches}. "
                    f"Use a more specific substring."
                )
            resolved_keys.append(matches[0])
        sorted_keys = resolved_keys
        original_indices = [all_sorted_keys.index(k) for k in resolved_keys]
    elif series_indices is not None:
        sorted_keys = [all_sorted_keys[i] for i in series_indices]
        original_indices = list(series_indices)
    else:
        sorted_keys = all_sorted_keys
        original_indices = list(range(len(all_sorted_keys)))

    n_series = len(sorted_keys)

    # Sort trajectory IDs: numeric (int or digit-string) by value, else alphabetically
    traj_ids = list(epoch_data.keys())

    def _traj_sort_key(tid: object) -> tuple:
        s = str(tid)
        if s.isdigit():
            return (0, int(s), '')
        return (1, 0, s)

    if sort_by_executed_actions:
        sorted_traj_ids = sorted(
            traj_ids, key=lambda tid: (executed_counts.get(tid, 0), _traj_sort_key(tid))
        )
    else:
        sorted_traj_ids = sorted(traj_ids, key=_traj_sort_key)
    n_trajectories = len(sorted_traj_ids)

    # Determine epoch count (max across all trajectories)
    n_epochs = max((len(epoch_data[tid]) for tid in sorted_traj_ids), default=1)
    multi_epoch = n_epochs > 1
    n_rows_per_cluster = n_epochs * n_series  # total bar rows per cluster

    # Find max number of steps across all trajectories/epochs/series
    max_steps = 0
    for traj_id in sorted_traj_ids:
        for epoch_dict in epoch_data[traj_id].values():
            for series_key in sorted_keys:
                steps = epoch_dict.get(series_key, [])
                if steps:
                    max_steps = max(max_steps, max(s[0] for s in steps) + 1)

    # Calculate figure size if not specified
    if figsize is None:
        width = max(12, max_steps * 0.3 + 4)
        height = max(8, n_trajectories * (n_rows_per_cluster * bar_height + cluster_gap) * 0.5)
        figsize = (width, height)

    # Create figure with custom layout
    fig = plt.figure(figsize=figsize)

    # Main heatmap axes (leave space on right for side_task, attacked, max_sus
    # columns and colorbar). The attacked column sits between side_task and max_sus.
    ax_main = fig.add_axes([0.12, 0.1, 0.62, 0.8])
    ax_side_task = fig.add_axes([0.75, 0.1, 0.025, 0.8])
    ax_attacked = fig.add_axes([0.78, 0.1, 0.025, 0.8])
    ax_max_sus = fig.add_axes([0.81, 0.1, 0.03, 0.8])
    ax_colorbar = fig.add_axes([0.85, 0.3, 0.015, 0.4])

    # Create green-red colormap for suspicion scores
    cmap = LinearSegmentedColormap.from_list('suspicion', ['green', 'yellow', 'red'], N=256)
    norm = Normalize(vmin=0.0, vmax=0.9)

    # Calculate y positions for each trajectory cluster
    cluster_height = n_rows_per_cluster * bar_height + cluster_gap
    y_positions = {}
    for i, traj_id in enumerate(sorted_traj_ids):
        y_positions[traj_id] = (n_trajectories - 1 - i) * cluster_height

    # Helper: y coordinate of a bar given series_idx and epoch_idx within a cluster.
    # Layout is epoch-as-outer: epoch 0's series occupy the top n_series rows,
    # epoch 1's series occupy the next n_series rows, etc.
    # Within each epoch block, series_idx=0 is at the top.
    def _bar_y(base_y: float, epoch_idx: int, series_idx: int) -> float:
        row_from_bottom = n_rows_per_cluster - 1 - (epoch_idx * n_series + series_idx)
        return base_y + row_from_bottom * bar_height

    # Plot heatmap
    ax_main.set_xlim(-0.5, max_steps - 0.5)
    ax_main.set_ylim(-cluster_gap, n_trajectories * cluster_height)

    for traj_id in sorted_traj_ids:
        base_y = y_positions[traj_id]
        traj_epochs = sorted(epoch_data[traj_id].keys())

        for epoch_idx, epoch in enumerate(traj_epochs):
            epoch_series_data = epoch_data[traj_id][epoch]
            risky_steps = self_risk_steps.get(traj_id, {}).get(epoch, set())
            for series_idx, series_key in enumerate(sorted_keys):
                y = _bar_y(base_y, epoch_idx, series_idx)
                for step_idx, score in epoch_series_data.get(series_key, []):
                    if step_idx in risky_steps:
                        edge_kwargs = dict(edgecolor='black', linewidth=1.2, zorder=3)
                    else:
                        edge_kwargs = dict(edgecolor='none')
                    rect = Rectangle(
                        (step_idx - 0.5, y), 1, bar_height,
                        facecolor=cmap(norm(score)), **edge_kwargs,
                    )
                    ax_main.add_patch(rect)

        # Black separator lines between epoch groups (each group = all series of one epoch).
        # Only drawn when there are multiple epochs.
        if multi_epoch:
            for ei in range(n_epochs - 1):
                sep_y = base_y + (n_rows_per_cluster - (ei + 1) * n_series) * bar_height
                ax_main.axhline(y=sep_y, color='black', linewidth=0.8, alpha=0.8)

    # Configure main axes
    ax_main.set_xlabel('Step Index')
    ax_main.set_ylabel('Task ID')
    ax_main.set_title('Suspicion Score Series Comparison')

    # Set y-ticks at cluster centers
    yticks = [y_positions[tid] + (n_rows_per_cluster * bar_height) / 2 for tid in sorted_traj_ids]
    ax_main.set_yticks(yticks)
    ax_main.set_yticklabels(sorted_traj_ids)

    # Add horizontal grid lines between clusters (gray)
    for i in range(n_trajectories + 1):
        y_line = i * cluster_height - cluster_gap / 2
        ax_main.axhline(y=y_line, color='gray', linewidth=0.5, alpha=0.5)

    # Plot side_task column — one rectangle per epoch per trajectory
    ax_side_task.set_xlim(0, 1)
    ax_side_task.set_ylim(-cluster_gap, n_trajectories * cluster_height)

    for traj_id in sorted_traj_ids:
        base_y = y_positions[traj_id]
        traj_epochs = sorted(epoch_data[traj_id].keys())

        if traj_id in df_indexed.index:
            traj_df = df_indexed.loc[[traj_id]]  # always a DataFrame, even for single row
        else:
            traj_df = pd.DataFrame()

        for epoch_idx, epoch in enumerate(traj_epochs):
            side_task_val = None
            if not traj_df.empty and 'score_side_task_success' in traj_df.columns:
                if 'epoch' in traj_df.columns:
                    epoch_rows = traj_df[traj_df['epoch'] == epoch]
                    if not epoch_rows.empty:
                        side_task_val = epoch_rows.iloc[0]['score_side_task_success']
                else:
                    side_task_val = traj_df.iloc[0]['score_side_task_success']

            # Determine color: red=attack succeeded, cyan=failed, blank=NaN
            if side_task_val is True or side_task_val == 'C':
                color = 'red'
            elif side_task_val is False or side_task_val == 'I':
                color = 'cyan'
            else:
                color = 'none'

            # y for the bottom of this epoch's block
            epoch_base_y = base_y + (n_rows_per_cluster - (epoch_idx + 1) * n_series) * bar_height
            rect = Rectangle(
                (0, epoch_base_y), 1, n_series * bar_height,
                facecolor=color,
                edgecolor='black' if color != 'none' else 'gray',
                linewidth=0.5,
            )
            ax_side_task.add_patch(rect)

    ax_side_task.set_xticks([])
    ax_side_task.set_yticks([])
    ax_side_task.set_xlabel('side\ntask', fontsize=8, rotation=0)
    ax_side_task.xaxis.set_label_position('top')

    # Plot attacked column — one rectangle per epoch per trajectory, same boolean
    # red/cyan coloring as side_task (red=attacked, cyan=not attacked, blank=no record).
    ax_attacked.set_xlim(0, 1)
    ax_attacked.set_ylim(-cluster_gap, n_trajectories * cluster_height)

    for traj_id in sorted_traj_ids:
        base_y = y_positions[traj_id]
        traj_epochs = sorted(epoch_data[traj_id].keys())
        for epoch_idx, epoch in enumerate(traj_epochs):
            attacked_val = attacked_status.get(traj_id, {}).get(epoch)
            if attacked_val is True:
                color = 'red'
            elif attacked_val is False:
                color = 'cyan'
            else:
                color = 'none'
            epoch_base_y = base_y + (n_rows_per_cluster - (epoch_idx + 1) * n_series) * bar_height
            rect = Rectangle(
                (0, epoch_base_y), 1, n_series * bar_height,
                facecolor=color,
                edgecolor='black' if color != 'none' else 'gray',
                linewidth=0.5,
            )
            ax_attacked.add_patch(rect)

    ax_attacked.set_xticks([])
    ax_attacked.set_yticks([])
    ax_attacked.set_xlabel('atk', fontsize=8, rotation=0)
    ax_attacked.xaxis.set_label_position('top')

    # Plot max_sus column — one box per epoch per series per trajectory
    ax_max_sus.set_xlim(0, 1)
    ax_max_sus.set_ylim(-cluster_gap, n_trajectories * cluster_height)

    for traj_id in sorted_traj_ids:
        base_y = y_positions[traj_id]
        traj_epochs = sorted(epoch_data[traj_id].keys())

        for epoch_idx, epoch in enumerate(traj_epochs):
            epoch_series_data = epoch_data[traj_id][epoch]
            for series_idx, series_key in enumerate(sorted_keys):
                steps_data = epoch_series_data.get(series_key, [])
                max_sus = max((score for _, score in steps_data), default=0.0)
                y = _bar_y(base_y, epoch_idx, series_idx)
                rect = Rectangle(
                    (0, y), 1, bar_height,
                    facecolor=cmap(norm(max_sus)),
                    edgecolor='black', linewidth=0.3,
                )
                ax_max_sus.add_patch(rect)

    ax_max_sus.set_xticks([])
    ax_max_sus.set_yticks([])
    ax_max_sus.set_xlabel('max\nsus', fontsize=8, rotation=0)
    ax_max_sus.xaxis.set_label_position('top')

    # Add colorbar
    sm = ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cb = fig.colorbar(sm, cax=ax_colorbar)
    cb.set_label('Suspicion Score', fontsize=8)
    cb.set_ticks([0.0, 0.45, 0.9])
    cb.set_ticklabels(['0.0', '0.45', '0.9'])

    # Legend placement: find first trajectory (from top) whose max step across all
    # epochs is < 60% of x-axis. If none qualify, fall back to the trajectory with
    # the fewest total score points across all its epochs.
    traj_max_steps = {}
    traj_total_scores = {}
    for traj_id in sorted_traj_ids:
        traj_max = 0
        total_scores = 0
        for epoch_dict in epoch_data[traj_id].values():
            for series_key in sorted_keys:
                steps = epoch_dict.get(series_key, [])
                if steps:
                    traj_max = max(traj_max, max(s[0] for s in steps) + 1)
                total_scores += len(steps)
        traj_max_steps[traj_id] = traj_max
        traj_total_scores[traj_id] = total_scores

    x_threshold = 0.6 * max_steps
    legend_y = None
    for traj_id in sorted_traj_ids:
        if traj_max_steps[traj_id] < x_threshold:
            legend_y = y_positions[traj_id] + (n_rows_per_cluster * bar_height) / 2
            break
    if legend_y is None:
        fewest_traj = min(sorted_traj_ids, key=lambda tid: traj_total_scores[tid])
        legend_y = y_positions[fewest_traj] + (n_rows_per_cluster * bar_height) / 2

    legend_text = ""
    if multi_epoch:
        legend_text += f"Epochs: {n_epochs}\n"
    legend_text += "Series:\n"
    for orig_idx, key in zip(original_indices, sorted_keys):
        if key == 'suspicion_score':
            label = f"{orig_idx}: ORIG"
        else:
            timestamp = key.replace('suspicion_score_', '')
            label = f"{orig_idx}: {timestamp}"
        legend_text += f"{label}\n"
    if self_risk_steps:
        legend_text += "black border = attack action\n"

    ax_main.text(
        max_steps - 1, legend_y, legend_text.strip(),
        fontsize=9,
        verticalalignment='center',
        horizontalalignment='right',
        fontfamily='monospace',
        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
    )

    # Get log filename for title
    if isinstance(log, EvalLog):
        log_name = Path(log.location).name if log.location else "EvalLog"
    else:
        log_name = Path(log).name
    plt.suptitle(f'Log: {log_name}', fontsize=10, y=0.98)

    return fig


# ---------------------------------------------------------------------------
# Accuracy comparison scatter plot
# ---------------------------------------------------------------------------

# 3x3 color map for (ref_count_capped, test_count_capped) combinations.
#           test=1      test=2      test=3
# ref=1     Black       Blue        Cyan
# ref=2     Orange      Green       Teal
# ref=3     Red         Yellow      Lime
_COUNT_COLOR_MAP = {
    (1, 1): "#000000",
    (1, 2): "#0066FF",
    (1, 3): "#00FFFF",
    (2, 1): "#FF8800",
    (2, 2): "#00AA00",
    (2, 3): "#00AAAA",
    (3, 1): "#FF0000",
    (3, 2): "#FFDD00",
    (3, 3): "#88FF00",
}


def plot_accuracy_comparison(
    *,
    ax: Axes,
    df_merged: pd.DataFrame,
    reference_col: str,
    test_col: str,
    xlabel: str,
    ylabel: str,
    title_prefix: str,
    jitter_points: bool,
    green_region_drop: float = 0.30,
    filter_drop_gt: float | None = None,
    jitter_std: float = 0.01,
    plot_mean: bool = True,
    show_pearson: bool = True,
    color_by_counts: bool = True,
    plot_stderr: bool = False,
    legend_location: str = "upper left",
) -> None:
    """Plots baseline vs test accuracy with a shaded "big drop" region.

    Args:
      ax: Axes to draw into.
      df_merged: DataFrame containing ``reference_col`` and ``test_col``.
        If *color_by_counts* is True, must also contain ``ref_count_capped``
        and ``test_count_capped`` columns.
      reference_col: Column name for baseline accuracy.
      test_col: Column name for test accuracy.
      xlabel: X-axis label.
      ylabel: Y-axis label.
      title_prefix: Title prefix (the function appends ``(n=...)``).
      jitter_points: Whether to jitter points.
      green_region_drop: Drop threshold defining the shaded green region, in
        absolute accuracy points (0.30 = 30 percentage points).
      filter_drop_gt: If provided, only plot points where
        (baseline - test) > *filter_drop_gt*.
      jitter_std: Standard deviation of the Gaussian jitter.
      plot_mean: If True, plot the overall mean as a red X.
      show_pearson: If True, show Pearson correlation coefficient.
      color_by_counts: If True, color points by the number of component scores
        (1-3 for reference x 1-3 for test = 9 colors). If False, use a
        single color for all points. Default is True.
      plot_stderr: If True, plot bootstrap standard error of the mean error
        bars at the mean point along both axes. Requires plot_mean=True.
    """
    if color_by_counts:
        if "ref_count_capped" not in df_merged.columns or "test_count_capped" not in df_merged.columns:
            raise ValueError(
                "Expected `ref_count_capped` and `test_count_capped` columns "
                "in df_merged when color_by_counts=True."
            )

    plot_cols = [reference_col, test_col]
    if color_by_counts:
        plot_cols.extend(["ref_count_capped", "test_count_capped"])

    df_plot = df_merged[plot_cols].dropna()
    if filter_drop_gt is not None:
        df_plot = df_plot[
            (df_plot[reference_col] - df_plot[test_col]) > filter_drop_gt
        ]

    ax.grid(True)

    x_vals = np.linspace(0, 1, 400)
    y_cutoff = x_vals - green_region_drop
    ax.fill_between(
        x_vals,
        0,
        np.clip(y_cutoff, 0, 1),
        color="lightgreen",
        alpha=0.3,
        zorder=0,
    )

    if color_by_counts:
        for (ref_cnt, test_cnt), color in _COUNT_COLOR_MAP.items():
            mask = (df_plot["ref_count_capped"] == ref_cnt) & (
                df_plot["test_count_capped"] == test_cnt
            )
            df_subset = df_plot[mask]

            if df_subset.empty:
                continue

            if jitter_points:
                rng = np.random.default_rng()
                x_plot = df_subset[reference_col].to_numpy() + rng.normal(
                    0, jitter_std, size=len(df_subset)
                )
                y_plot = df_subset[test_col].to_numpy() + rng.normal(
                    0, jitter_std, size=len(df_subset)
                )
            else:
                x_plot = df_subset[reference_col].to_numpy()
                y_plot = df_subset[test_col].to_numpy()

            ax.scatter(
                x_plot,
                y_plot,
                color=color,
                label=f"Ref:{ref_cnt}xTest:{test_cnt} (n={len(df_subset)})",
                alpha=0.7,
            )
    else:
        if jitter_points and not df_plot.empty:
            rng = np.random.default_rng()
            x_all = df_plot[reference_col].to_numpy() + rng.normal(
                0, jitter_std, size=len(df_plot)
            )
            y_all = df_plot[test_col].to_numpy() + rng.normal(
                0, jitter_std, size=len(df_plot)
            )
        else:
            x_all = df_plot[reference_col].to_numpy()
            y_all = df_plot[test_col].to_numpy()

        ax.scatter(
            x_all,
            y_all,
            color="blue",
            label=f"Tasks (n={len(df_plot)})",
        )

    ax.plot([0, 1], [0, 1], linestyle="--", color="black", linewidth=1)
    if plot_mean:
        mean_x = df_plot[reference_col].mean()
        mean_y = df_plot[test_col].mean()
        ax.scatter(
            mean_x,
            mean_y,
            color="red",
            marker="x",
            s=100,
            label="Overall Mean",
        )
        if plot_stderr and len(df_plot) >= 2:
            data_array = df_plot[[reference_col, test_col]].to_numpy().astype(float)
            bootstrap_means = _bootstrap_distributions(data_array, n_bootstrap=400)
            x_se = bootstrap_means[:, 0].std()
            y_se = bootstrap_means[:, 1].std()
            ax.errorbar(
                mean_x,
                mean_y,
                xerr=x_se,
                yerr=y_se,
                fmt="none",
                color="red",
                capsize=5,
                linewidth=2,
                zorder=5,
            )

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(f"{title_prefix} (n={len(df_plot)})")
    ax.set_aspect("equal", adjustable="box")

    if show_pearson:
        if len(df_plot) >= 2:
            pearson_corr_overall, _ = pearsonr(
                df_plot[reference_col],
                df_plot[test_col],
            )
            pearson_text = f"Overall Pearson r={pearson_corr_overall:.2f}"
        else:
            pearson_text = "Overall Pearson r=N/A"
        ax.text(
            0.05,
            0.85,
            pearson_text,
            transform=ax.transAxes,
            fontsize=10,
            verticalalignment="top",
        )

    ax.legend(loc=legend_location)

# ---------------------------------------------------------------------------
# Per-child-task KDE helpers
# ---------------------------------------------------------------------------

_PERCHILD_AUX_SUFFIXES = ("_answer", "_explanation", "_metadata")


def _find_perchild_col(df_flat: pd.DataFrame, sus_key: str) -> "str | None":
    """Return the single perchild scorer value column matching sus_key, or None."""
    all_pc = {c for c in df_flat.columns if c.startswith("score_") and "perchild" in c}
    value_cols = [
        c for c in all_pc
        if not any(c == other + sfx for other in all_pc for sfx in _PERCHILD_AUX_SUFFIXES)
    ]
    matches = [c for c in value_cols if sus_key in c]
    if not matches:
        return None
    if len(matches) > 1:
        raise ValueError(
            f"Multiple perchild scorer columns contain {sus_key!r}: {matches}"
        )
    return matches[0]


def _perchild_scores_long(df_flat: pd.DataFrame, col: str) -> pd.DataFrame:
    """Long-format (id, key, score) from a flattened samples DataFrame."""
    rows = []
    for _, row in df_flat.iterrows():
        v = row[col]
        if isinstance(v, dict):
            for k, score in v.items():
                if score is not None:
                    rows.append({"id": row["id"], "key": k, "score": float(score)})
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["id", "key", "score"])


def _perchild_resolve_map(all_key_sets: list) -> dict:
    """Map shifted key sets to canonical forms.

    Non-singletons: groups by normalised shape (subtract min), maps each to the
    highest-valued representative.  Singletons: resolve to the singleton whose
    value equals the minimum key value across all canonical non-singleton sets;
    raises ValueError if any singleton's value exceeds that minimum.
    """
    groups: dict = defaultdict(list)
    singletons: list = []
    for s in all_key_sets:
        if s is None:
            continue
        if len(s) >= 2:
            min_val = min(int(k) for k in s)
            norm = frozenset(int(k) - min_val for k in s)
            groups[norm].append(s)
        else:
            singletons.append(s)

    resolve_map: dict = {}
    canonical_sets: list = []
    for group in groups.values():
        canonical = max(group, key=lambda s: min(int(k) for k in s))
        canonical_sets.append(canonical)
        for s in group:
            if s != canonical:
                resolve_map[s] = canonical

    if canonical_sets and singletons:
        min_canonical_val = min(int(k) for cs in canonical_sets for k in cs)
        canonical_singleton = frozenset({str(min_canonical_val)})
        for s in singletons:
            val = int(next(iter(s)))
            if val > min_canonical_val:
                raise ValueError(
                    f"Singleton key set {s!r} has value {val} > minimum canonical "
                    f"value {min_canonical_val}; cannot resolve unambiguously."
                )
            if s != canonical_singleton:
                resolve_map[s] = canonical_singleton

    return resolve_map


def _apply_perchild_resolve_map(
    scores_df: pd.DataFrame, ks_series: pd.Series, resolve_map: dict
) -> pd.DataFrame:
    """Apply a resolve_map to the 'key' column of a long-format scores DataFrame."""
    per_sample: dict = {}
    for sample_id, keyset in ks_series.items():
        if keyset is None or keyset not in resolve_map:
            continue
        canonical = resolve_map[keyset]
        old_sorted = sorted(keyset, key=int)
        new_sorted = sorted(canonical, key=int)
        per_sample[sample_id] = dict(zip(old_sorted, new_sorted))

    def _remap(row: pd.Series) -> str:
        return per_sample.get(row["id"], {}).get(row["key"], row["key"])

    scores_df = scores_df.copy()
    scores_df["key"] = scores_df.apply(_remap, axis=1)
    return scores_df


# ---------------------------------------------------------------------------
# Public: plot_suspicion_kde_for_logs
# ---------------------------------------------------------------------------

def plot_suspicion_kde_for_logs(
    logs_with_labels: "list[tuple[str | Path, str]]",
    sus_key: str,
    title: str = "Suspicion score distributions",
    figsize: "tuple[int, int]" = (10, 5),
) -> plt.Figure:
    """KDE plot of suspicion score distributions across multiple logs.

    For each log:

    * **Offline-decomposer** (perchild scorer column matching *sus_key* found):
      plots one KDE line per resolved child-task key.
    * **Regular**: plots one KDE line for the overall max-suspicion distribution,
      using a key derived by removing any ``_perchild_`` segment from *sus_key*.

    Resolved child-task keys share a colour across all logs; logs are
    distinguished by linestyle (solid → dashed → dotted → dashdot).

    Args:
        logs_with_labels: List of ``(log_file_path, label)`` pairs.
        sus_key: Substring matched against perchild scorer column names.  For
            non-perchild logs the derived key is *sus_key* with ``'_perchild_'``
            removed (e.g. ``'full_history_perchild_std'`` → ``'full_history_std'``).
        title: Figure title.
        figsize: Figure size passed to ``plt.subplots``.

    Returns:
        The matplotlib ``Figure``.
    """
    regular_key = sus_key.replace("_perchild_", "_")
    linestyles = ["-", "--", ":", "-."]

    # --- Pass 1: load and classify each log ---
    log_data: list[dict] = []
    for log_file, label in logs_with_labels:
        log_path = Path(log_file)
        df_flat = safe_samples_df(log_path, flatten_scores=True)
        col = _find_perchild_col(df_flat, sus_key)
        if col is not None:
            log_data.append({
                "label": label,
                "is_perchild": True,
                "scores_df": _perchild_scores_long(df_flat, col),
                "key_sets": get_perchild_key_sets(log_path),
            })
        else:
            series = get_max_suspicion_by_key_index(log_path, regular_key)
            log_data.append({
                "label": label,
                "is_perchild": False,
                "vals": series.dropna().values,
            })

    # --- Pass 2: build + apply resolution map across all perchild logs ---
    all_key_sets: list = [
        ks
        for entry in log_data
        if entry["is_perchild"]
        for ks in entry["key_sets"].tolist()
    ]
    if all_key_sets:
        resolve_map = _perchild_resolve_map(all_key_sets)
        for entry in log_data:
            if entry["is_perchild"]:
                entry["scores_df"] = _apply_perchild_resolve_map(
                    entry["scores_df"], entry["key_sets"], resolve_map
                )

    # --- Determine resolved key order for consistent colour assignment ---
    resolved_keys: set[str] = set()
    for entry in log_data:
        if entry["is_perchild"]:
            resolved_keys.update(entry["scores_df"]["key"].unique())
    all_keys_sorted = sorted(
        resolved_keys, key=lambda k: int(k) if k.isdigit() else k
    )
    colors = plt.cm.tab10.colors
    key_color = {k: colors[i % 10] for i, k in enumerate(all_keys_sorted)}
    nonperchild_color = colors[len(all_keys_sorted) % 10]

    # --- Plot ---
    fig, ax = plt.subplots(figsize=figsize)
    x = np.linspace(0, 1, 300)

    for log_idx, entry in enumerate(log_data):
        linestyle = linestyles[log_idx % len(linestyles)]
        label_base = entry["label"]

        if entry["is_perchild"]:
            scores_df = entry["scores_df"]
            for key in all_keys_sorted:
                vals = scores_df.loc[scores_df["key"] == key, "score"].dropna().values
                # Need >=2 points with nonzero spread for a KDE (degenerate
                # series -> singular covariance); skip otherwise.
                if len(vals) < 2 or float(np.ptp(vals)) == 0.0:
                    continue
                ax.plot(x, gaussian_kde(vals)(x),
                        color=key_color[key], linestyle=linestyle,
                        label=f"{label_base} key={key}")
        else:
            vals = entry["vals"]
            if len(vals) >= 2 and float(np.ptp(vals)) != 0.0:
                ax.plot(x, gaussian_kde(vals)(x),
                        color=nonperchild_color, linestyle=linestyle,
                        label=label_base)

    ax.set_xlabel("Suspicion score")
    ax.set_ylabel("Density")
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Shared scalar barplot (clusters = metrics, bars = outer keys)
# ---------------------------------------------------------------------------

def plot_scalar_barplot(
    bar_data: "dict[str, dict[str, float]]",
    title: "str | None" = "Scalar Metrics",
    metric_names: "list[str] | None" = None,
    figsize: "tuple[float, float] | None" = None,
    colors: "None | dict | Sequence" = None,
    bar_ci: "dict[str, dict[str, tuple[float, float]]] | None" = None,
    hatches: "SeriesHatches" = None,
    legend_below: bool = False,
    bar_fill: float = 0.7,
) -> plt.Figure:
    """Clustered bar chart with metric names on x-axis.

    Args:
        bar_data: Outer key → {metric_name: float}.  Each outer key becomes one
            bar in every metric cluster.  Typically outer keys are protocol
            labels or suspicion-score key names.
        title: Figure title; ``None`` (or "") draws no title, the manuscript
            default for a data figure.
        metric_names: Explicit metric order.  Defaults to
            ``["Safety", "AAR", "UASR", "ASR", "AUROC"]``.  Metrics missing from
            a series' dict render as NaN (no bar), so older cached metrics
            lacking ``AAR`` simply leave a gap rather than raising.
        figsize: Figure size.  Auto-sized when ``None``.
        bar_ci: Optional outer key → {metric_name: (lo, hi)} absolute CI bounds
            drawn as asymmetric error bars.  Bars without an entry (or with a
            non-finite bound) get no error bar; value labels sit above the
            upper whisker when one exists.
        hatches: Optional bar hatching, resolved per outer key like
            ``colors``: ``True`` cycles ``BAR_HATCHES`` positionally, a dict
            is looked up by outer key, a sequence is indexed positionally.
            A hatched bar draws its face at ``BAR_HATCH_FACE_ALPHA`` with an
            opaque black outline and hatch; the legend swatches are the bar
            patches themselves, so they carry the same hatch. ``None`` (the
            default) draws plain opaque bars exactly as before.
        legend_below: Put the legend under the x axis (one entry per row)
            instead of top-centre inside the axes. For a single-column
            figure (``figsize`` width 4.5) with long series labels, no
            in-axes position clears every value label, and the automatic
            y-limit lift that keeps the in-axes legend clear then wastes a
            third of a 0-1 score axis; below the axes the y range stays put.
            The same placement as ``plot_plan_delivery_safety_bars.py``.
            ``False`` (the default) keeps the in-axes legend and the lift.
        bar_fill: Fraction of each metric cluster's pitch (the metric
            clusters sit one x unit apart) covered by its bars, so each bar
            is ``bar_fill / n_outer`` wide and the gap between clusters is
            ``1 - bar_fill``. Raising it widens every bar AND closes up the
            clusters at a fixed axes width, which is what a single-column
            figure needs for the 8 pt value labels to be narrower than the
            bars they sit on. 0.7 (the default) is the historic geometry.
    """
    if metric_names is None:
        metric_names = ["Safety", "AAR", "UASR", "ASR", "AUROC"]
    outer_keys = list(bar_data.keys())
    n_outer = len(outer_keys)
    n_metrics = len(metric_names)
    crowded = n_outer > 4

    if figsize is None:
        if not crowded:
            # Unchanged historic auto-size (n_outer=4, n_metrics=4 -> (8, 4)).
            figsize = (min(8, max(5, 2 * n_outer * n_metrics / 2)), 4)
        else:
            # ~0.28in per bar (half the prior 0.55) so the chart is ~50%
            # narrower; bar width / cluster spacing scale with figure width.
            figsize = (min(14, 0.28 * n_outer * n_metrics + 2), 4.4)

    fig, ax = plt.subplots(figsize=figsize)
    bar_width = bar_fill / max(n_outer, 1)
    x = list(range(n_metrics))
    label_fs = 8 if not crowded else 7
    label_rot = 0 if not crowded else 90

    max_upper = 0.0
    value_texts: "list[plt.Text]" = []
    for i, key in enumerate(outer_keys):
        vals = [bar_data[key].get(m, float("nan")) for m in metric_names]
        offsets = [xi + (i - (n_outer - 1) / 2) * bar_width for xi in x]
        color = _resolve_series_color(colors, key, i)

        # Asymmetric error bars from absolute (lo, hi) CI bounds, NaN where
        # absent so bars without a CI render exactly as before.
        yerr = None
        uppers: "list[float]" = [float("nan")] * len(vals)
        if bar_ci is not None:
            lo_err, hi_err = [], []
            key_ci = bar_ci.get(key, {})
            for m, val in zip(metric_names, vals):
                lo, hi = key_ci.get(m, (float("nan"), float("nan")))
                if pd.isna(val) or pd.isna(lo) or pd.isna(hi):
                    lo_err.append(float("nan"))
                    hi_err.append(float("nan"))
                else:
                    lo_err.append(max(val - lo, 0.0))
                    hi_err.append(max(hi - val, 0.0))
                    uppers[metric_names.index(m)] = hi
                    max_upper = max(max_upper, hi)
            if any(not pd.isna(e) for e in lo_err):
                yerr = [lo_err, hi_err]

        hatch = _resolve_series_hatch(hatches, key, i)
        if hatch is None:
            style: dict = {"color": color}
        else:
            style = {
                "facecolor": to_rgba(color, BAR_HATCH_FACE_ALPHA),
                "edgecolor": "black", "linewidth": BAR_HATCH_EDGE_WIDTH,
                "hatch": hatch,
            }
        bars = ax.bar(
            offsets, vals, width=bar_width, label=key,
            yerr=yerr, capsize=2.5 if yerr is not None else 0.0,
            error_kw={"linewidth": 1.0, "alpha": 0.8},
            **style,
        )
        for bar, val, upper in zip(bars, vals, uppers):
            if not pd.isna(val):
                label_y = (upper if not pd.isna(upper) else bar.get_height()) + 0.02
                value_texts.append(ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    label_y,
                    f"{val:.2f}",
                    ha="center", va="bottom", fontsize=label_fs,
                    rotation=label_rot,
                ))

    ax.set_xticks(x)
    ax.set_xticklabels(metric_names)
    # Headroom for vertical value labels when crowded (extra when whiskers
    # extend past 1.0).
    _ylim_top = 1.0 if not crowded else 1.15
    if max_upper > 0.0:
        _ylim_top = max(_ylim_top, max_upper + (0.08 if not crowded else 0.18))
    ax.set_ylim(0, _ylim_top)
    ax.set_ylabel("Score")
    if title:
        ax.set_title(title)
    if n_outer > 1:
        if crowded:
            ax.legend(fontsize=7, loc="upper left", bbox_to_anchor=(1.01, 1.0),
                      borderaxespad=0.0)
        elif legend_below:
            # Under the axes, anchored to the axes so it clears the x tick
            # labels; tight_layout counts an axes legend in the axes' tight
            # bbox and leaves room for it below.
            ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.14), ncol=1)
        else:
            # Top centre, inside the axes. The middle clusters (AAR / UASR /
            # ASR) are usually the short ones, but nothing guarantees that a
            # tall bar or its value label never sits under the legend, so
            # measure both after a draw and lift the y-limit until the legend
            # clears everything beneath it. ("lower right" used to land on
            # the ASR / AUROC bars.)
            leg = ax.legend(loc="upper center")
            _lift_ylim_clear_of_legend(fig, ax, leg, value_texts)
    # Whatever the legend did, no value label may run into the top spine: the
    # labels sit a fixed DATA offset above the whiskers but have a fixed
    # PHYSICAL height, so on a short axes box (a single-column figsize) the
    # tallest ones reached past the ``max_upper + 0.08`` headroom.
    _lift_ylim_clear_of_top(fig, ax, value_texts)
    fig.tight_layout()
    return fig


def _lift_ylim_clear_of_legend(
    fig: plt.Figure,
    ax: plt.Axes,
    legend: "Legend",
    texts: "Sequence[plt.Text]",
    pad: float = 0.02,
) -> None:
    """Raise ``ax``'s upper y-limit so an in-axes legend overlaps none of ``texts``.

    ``texts`` are the value labels drawn with ``va="bottom"`` directly above each
    bar (or its upper whisker), so clearing them clears the bars too. Only
    labels whose x-extent intersects the legend's matter: a top-centre legend
    over a short middle cluster costs no headroom, while a tall bar under it
    lifts the limit just enough. Everything is measured in axes fraction after
    a draw, where the legend box and the text heights are invariant under a
    y-limit change, so the new limit is solved in one step rather than by
    iterating. ``pad`` is the clearance in axes fraction.
    """
    if not texts:
        return
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    to_axes = ax.transAxes.inverted()
    lb = legend.get_window_extent(renderer).transformed(to_axes)
    _, y_top = ax.get_ylim()
    needed = y_top
    for t in texts:
        tb = t.get_window_extent(renderer).transformed(to_axes)
        if tb.x1 <= lb.x0 or tb.x0 >= lb.x1:
            continue  # not under the legend
        room = lb.y0 - pad - tb.height  # axes fraction left for the label's bottom
        if room <= 0.0:
            continue  # legend taller than the axes; nothing sensible to do
        _, label_y = t.get_position()  # data coords, va="bottom"
        needed = max(needed, label_y / room)
    if needed > y_top:
        ax.set_ylim(0, needed)


def _lift_ylim_clear_of_top(
    fig: plt.Figure,
    ax: plt.Axes,
    texts: "Sequence[plt.Text]",
    pad: float = 0.02,
) -> None:
    """Raise ``ax``'s upper y-limit so none of ``texts`` touches the top spine.

    ``texts`` are value labels drawn with ``va="bottom"`` at a data y (their
    bottom edge). Measured in axes fraction after a draw, where a text's
    height is invariant under a y-limit change, so the new limit is solved in
    one step: a label whose bottom sits at data ``y`` needs
    ``(y - y0) / (y_top - y0) + height + pad <= 1``. ``pad`` is the clearance
    in axes fraction. Only ever raises the limit, never lowers it, and leaves
    a tick locator alone (a MultipleLocator keeps its step; the extra range
    is headroom, not a tick). Companion of ``_lift_ylim_clear_of_legend``.
    """
    if not texts:
        return
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    to_axes = ax.transAxes.inverted()
    y0, y_top = ax.get_ylim()
    needed = y_top
    for t in texts:
        height = t.get_window_extent(renderer).transformed(to_axes).height
        room = 1.0 - height - pad
        if room <= 0.0:
            continue  # label taller than the axes; nothing sensible to do
        _, label_y = t.get_position()  # data coords, va="bottom"
        needed = max(needed, y0 + (label_y - y0) / room)
    if needed > y_top:
        ax.set_ylim(y0, needed)


# ---------------------------------------------------------------------------
# Multi-protocol comparison plots
# ---------------------------------------------------------------------------

# Series-color override accepted by the multi-protocol plots below. May be:
#   - None: use the default cycling palette (unchanged legacy behavior).
#   - dict label -> hex color: looked up per series by label.
#   - sequence of hex colors: indexed positionally.
SeriesColors = "None | dict[str, str] | Sequence[str]"

# Bar hatching: an opt-in SECOND channel telling the bars of one cluster apart
# on top of their fill color, for figures whose series are shades of a single
# protocol hue (e.g. a base arm vs its counterfactual, both DTD gray). Cycled
# positionally: the first series gets "//", the second the mirrored "\\", so
# two variants read as a pair; later series fall through to the denser
# patterns. A hatched bar draws its FACE at BAR_HATCH_FACE_ALPHA with the
# hatch and the outline fully opaque -- an opaque DTD-gray face would swallow
# a black hatch. Same idiom and values as plot_plan_delivery_safety_bars.py
# and plot_decomposition_counts_and_usefulness.py, so the manuscript's
# hatched bar charts match.
BAR_HATCHES: "tuple[str, ...]" = ("//", "\\\\", "xx", "..", "++", "oo")
BAR_HATCH_FACE_ALPHA = 0.55
BAR_HATCH_EDGE_WIDTH = 0.6
SeriesHatches = "None | bool | dict[str, str] | Sequence[str]"


# ---------------------------------------------------------------------------
# Protocol-family style convention (colors + markers)
# ---------------------------------------------------------------------------
# Fixed identity colors AND markers so the core protocol families look the same
# in every plot, regardless of series order or which subset of families appears.
# Family membership is detected FROM THE SERIES LABEL (see _protocol_family), so
# labels must name the protocol (e.g. "TM v11.1", "DTR defer1.0", "DTD-rem
# thr3.0") for the convention to engage; callers whose labels cannot name the
# protocol pass ``families=`` explicitly instead.
#
# NAMING: the manuscript's "DTR" is the defer-to-resample protocol WITH a
# trusted fallback, which log filenames, log-group names and older series labels
# spell "DTRF". Both spellings resolve to the single "DTR" family below. The
# no-trusted-fallback variant is not plotted, so it has no reserved style.
PROTOCOL_FAMILY_COLORS: "dict[str, str]" = {
    "TM": PIVOTAL_PALETTE[0],   # blue      #3A82B5
    "DTR": PIVOTAL_PALETTE[1],  # orange    #F15F22  (formerly keyed "DTRF")
    "DTD": GRAYS[1],            # gray      #7C7D7F  (one step lighter than
                                #  PIVOTAL_PALETTE[2] #4C4D4F, so black error
                                #  bars stay visible where they overlap a bar)
    "CES": PIVOTAL_PALETTE[3],  # yellow    #FFC61F
}

# One marker per family, so a protocol keeps its shape across reports (the old
# behavior cycled LINE_MARKERS positionally, which made the marker depend on how
# many series happened to precede it). Variants of one family share the marker;
# the shade ramp carries the variant distinction.
PROTOCOL_FAMILY_MARKERS: "dict[str, str]" = {
    "TM": "o", "DTR": "s", "DTD": "^", "CES": "D",
}

# Canonical order protocols should appear in (legend, bar clusters, table rows).
PROTOCOL_FAMILY_ORDER: "tuple[str, ...]" = ("TM", "DTR", "DTD", "CES")

# Default legend text per family. Never append an operating point (defer
# threshold, monitor-prompt version, resample aggregation, dataset tag) to
# these — that information belongs on the report's cover page.
PROTOCOL_DISPLAY_LABELS: "dict[str, str]" = {
    "TM": "Trusted Monitoring", "DTR": "DTR", "DTD": "DTD", "CES": "CES",
}

# Colors for series whose label matches no family, chosen to avoid the
# reserved family hues above (cycled if there are more such series).
_NON_FAMILY_COLORS = [
    '#2CA02C', '#D62728', '#9467BD', '#8C564B',
    '#E377C2', '#17BECF', '#BCBD22', '#89BCDF',
]

# Markers for non-family series: LINE_MARKERS minus the family-reserved shapes,
# so a nameless series can never be mistaken for a protocol.
_NON_FAMILY_MARKERS = [
    m for m in LINE_MARKERS if m not in set(PROTOCOL_FAMILY_MARKERS.values())
]


def _protocol_family(label: "str | None") -> "str | None":
    """Classify a series label into a protocol family (key of
    PROTOCOL_FAMILY_COLORS), or None if the label names no known family.

    Case-insensitive. "dtd" is tested before "dtr" (they share a prefix), and
    "dtrf" is simply a legacy spelling of "dtr" — there is no separate
    no-trusted-fallback family.
    """
    if not label:
        return None
    s = str(label).lower()
    if "dtd" in s:
        return "DTD"
    if "dtr" in s:  # covers "dtrf" too
        return "DTR"
    if (re.search(r"(?<![a-z0-9])tm(?![a-z0-9])", s)
            or "trusted monitoring" in s or "trusted-monitoring" in s):
        return "TM"
    if re.search(r"(?<![a-z0-9])ces(?![a-z0-9])", s):
        return "CES"
    return None


def _blend(hex_color: str, amount: float) -> str:
    """Blend toward white (amount > 0) or black (amount < 0); |amount| <= 1."""
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    target = 255 if amount > 0 else 0
    a = abs(amount)
    r, g, b = (round(c + (target - c) * a) for c in (r, g, b))
    return f"#{r:02X}{g:02X}{b:02X}"


# Most a variant may be blended toward white. Beyond this the lightest shade
# stops reading against a white page — the CES yellow is the least tolerant.
_MAX_LIGHTEN = 0.55


def _family_shades(base: str, n: int) -> "list[str]":
    """``n`` shades of one hue: the family's identity color FIRST, then
    strictly lighter variants. Never darker than the base, so the base color
    always marks the canonical arm and a variant can never out-weight it.

    ``n == 1`` -> exactly ``[base]`` (a family with a single variant keeps its
    identity color).
    """
    if n <= 1:
        return [base]
    return [_blend(base, float(a)) for a in np.linspace(0.0, _MAX_LIGHTEN, n)]


def _series_families(
    labels: "Sequence[str | None]",
    families: "Sequence[str | None] | None" = None,
) -> "list[str | None]":
    """Family per series: an explicit ``families`` entry wins over the label.

    ``families`` is positional against ``labels``; a None entry (or a short
    sequence) falls back to ``_protocol_family(label)``. Use it wherever the
    label cannot name its protocol — e.g. the CES cohort in compare_protocols.py
    is labelled "create-edit", which no parser could classify.
    """
    out: "list[str | None]" = []
    for i, lbl in enumerate(labels):
        explicit = None
        if families is not None and i < len(families):
            explicit = families[i]
        out.append(explicit if explicit else _protocol_family(lbl))
    return out


def protocol_series_colors(
    labels: "Sequence[str | None]",
    families: "Sequence[str | None] | None" = None,
    shade_variants: bool = True,
) -> "list[str] | None":
    """Assign one color per series under the protocol-family convention.

    - A family with exactly one series in ``labels`` gets its fixed identity
      color from PROTOCOL_FAMILY_COLORS (TM blue, DTR orange, DTD gray,
      CES yellow).
    - A family with N > 1 series (protocol variants — e.g. two TM monitor
      versions, or a DTD threshold pair) gets the base color first and N-1
      strictly LIGHTER shades of that family's hue only, assigned in the order
      the labels are given.
    - Labels naming no family get _NON_FAMILY_COLORS (never a family hue).

    ``families`` overrides the label-derived family per series (see
    ``_series_families``).

    ``shade_variants=False`` gives every series of a family the family's
    identity color, so a figure shows one color per protocol no matter how
    many cells each has. For figures whose variants are already told apart by
    another channel (x position, hatch) and read better without the ramp.

    Returns a color list aligned positionally with ``labels``, or None when NO
    series names a family — callers should then keep their legacy palette, so
    plots of arbitrary non-protocol series render exactly as before.
    """
    fams = _series_families(labels, families)
    if not any(fams):
        return None
    counts = Counter(f for f in fams if f)
    shades = {
        fam: iter(_family_shades(PROTOCOL_FAMILY_COLORS[fam], n) if shade_variants
                  else [PROTOCOL_FAMILY_COLORS[fam]] * n)
        for fam, n in counts.items()
    }
    fallback = itertools.cycle(_NON_FAMILY_COLORS)
    return [next(shades[fam]) if fam else next(fallback) for fam in fams]


def protocol_series_markers(
    labels: "Sequence[str | None]",
    families: "Sequence[str | None] | None" = None,
) -> "list[str] | None":
    """Assign one marker per series under the protocol-family convention.

    Mirrors ``protocol_series_colors``: every series of a family gets that
    family's SINGLE marker (variants are told apart by shade, not shape), and
    series naming no family cycle ``_NON_FAMILY_MARKERS`` so they can never be
    mistaken for a protocol.

    Returns None when no series names a family, so non-protocol plots keep the
    legacy positional ``LINE_MARKERS`` cycle unchanged.
    """
    fams = _series_families(labels, families)
    if not any(fams):
        return None
    fallback = itertools.cycle(_NON_FAMILY_MARKERS or LINE_MARKERS)
    return [
        PROTOCOL_FAMILY_MARKERS[fam] if fam else next(fallback) for fam in fams
    ]


def protocol_sort_key(label: "str | None") -> "tuple[int, str]":
    """Sort key putting series in PROTOCOL_FAMILY_ORDER, unknowns last.

    Use with ``sorted(labels, key=protocol_sort_key)`` (or to order a list of
    (label, data) pairs) so protocols appear in the same sequence in every
    legend, bar cluster and table.
    """
    fam = _protocol_family(label)
    idx = PROTOCOL_FAMILY_ORDER.index(fam) if fam in PROTOCOL_FAMILY_ORDER \
        else len(PROTOCOL_FAMILY_ORDER)
    return (idx, str(label or ""))


def _resolve_series_color(
    colors: "None | dict | Sequence",
    label: str,
    index: int,
    palette: Sequence = _PROTOCOL_PALETTE,
) -> str:
    """Pick a color for one series, honoring a caller-supplied override.

    Falls back to the cycling ``palette`` so that ``colors=None`` (or a missing
    label / short sequence) reproduces the legacy appearance exactly.
    """
    if colors is None:
        return palette[index % len(palette)]
    if isinstance(colors, dict):
        return colors.get(label, palette[index % len(palette)])
    return colors[index % len(colors)]


def _resolve_series_hatch(
    hatches: "SeriesHatches", label: str, index: int,
) -> "str | None":
    """Hatch pattern for one bar series, or None for a plain bar.

    ``True`` cycles ``BAR_HATCHES`` by position; a dict is looked up by
    ``label`` (missing -> None); a sequence is indexed by position (cycled).
    """
    if hatches is None or hatches is False:
        return None
    if hatches is True:
        return BAR_HATCHES[index % len(BAR_HATCHES)]
    if isinstance(hatches, dict):
        return hatches.get(label)
    return hatches[index % len(hatches)]


def _resolve_series_marker(
    markers: "None | str | dict | Sequence",
    label: str,
    index: int,
    cycle: Sequence = LINE_MARKERS,
) -> str:
    """Pick a marker for one series, honoring a caller-supplied override.

    Mirrors ``_resolve_series_color``: ``None`` falls back to the positional
    ``cycle`` (pass the family markers as ``cycle`` to get the house style), a
    bare string forces one marker on every series, a dict is looked up by label,
    and a sequence is indexed positionally.
    """
    if markers is None:
        return cycle[index % len(cycle)]
    if isinstance(markers, str):
        return markers
    if isinstance(markers, dict):
        return markers.get(label, cycle[index % len(cycle)])
    return markers[index % len(markers)]

def plot_multi_protocol_ROC(
    protocols_sus: "list[tuple]",
    title: str = "ROC Curve: Protocol Comparison",
    figsize: "tuple[int, int] | None" = None,
    colors: "None | dict | Sequence" = None,
) -> "tuple[plt.Figure, dict[str, float]]":
    """ROC curves with one line per protocol.

    Args:
        protocols_sus: List of ``(label, attack_values, honest_values)`` or
            ``(label, attack_values, honest_values, attack_weights,
            honest_weights)`` where each ``*_values`` is a 1-D float array of
            per-sample max suspicion scores. When per-row weights are supplied
            (e.g. the inverse-cluster-size design weights from
            ``pool_runs="epochs_equal_task"``) the ROC uses ``sample_weight`` so
            the displayed AUROC matches the weighted scalar; omit them (3-tuple)
            for the unweighted curve.
        title: Figure title.
        figsize: Figure size.  When ``None``, defaults to ``(6, 6)`` for up to
            4 series (unchanged) and grows for denser comparisons.
        colors: Per-series color override (see ``_resolve_series_color``).

    Returns:
        ``(fig, auroc_scores)`` where ``auroc_scores`` maps label → AUROC float.
    """
    n = len(protocols_sus)
    if figsize is None:
        # <=4 series: identical to the historic default. More series get a
        # slightly larger square so the (n+1)-entry legend stays legible.
        figsize = (6, 6) if n <= 4 else (7.5, 7.5)

    fig, ax = plt.subplots(figsize=figsize)
    auroc_scores: dict[str, float] = {}

    for i, _series in enumerate(protocols_sus):
        label, red_vals, blue_vals = _series[0], _series[1], _series[2]
        red_w = _series[3] if len(_series) > 3 else None
        blue_w = _series[4] if len(_series) > 4 else None
        red_vals = np.asarray(red_vals, dtype=float)
        blue_vals = np.asarray(blue_vals, dtype=float)
        red_w = np.ones(len(red_vals)) if red_w is None else np.asarray(red_w, float)
        blue_w = np.ones(len(blue_vals)) if blue_w is None else np.asarray(blue_w, float)
        _rmask, _bmask = ~np.isnan(red_vals), ~np.isnan(blue_vals)
        red_vals, red_w = red_vals[_rmask], red_w[_rmask]
        blue_vals, blue_w = blue_vals[_bmask], blue_w[_bmask]
        if len(red_vals) < 2 or len(blue_vals) < 2:
            continue
        scores = np.concatenate([red_vals, blue_vals])
        labels_arr = np.concatenate([np.ones(len(red_vals)), np.zeros(len(blue_vals))])
        sw = np.concatenate([red_w, blue_w])
        fpr, tpr, _ = roc_curve(labels_arr, (scores * 60).round(), sample_weight=sw)
        auroc = auc(fpr, tpr)
        auroc_scores[label] = auroc
        color = _resolve_series_color(colors, label, i)
        ax.plot(fpr, tpr, color=color, lw=2, label=f"{label} (AUROC={auroc:.2f})")

    ax.plot([0, 1], [0, 1], color="gray", lw=1, linestyle="--", label="Random")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.05)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(title)
    ax.legend(loc="lower right", fontsize=8 if n <= 4 else 7)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    return fig, auroc_scores


def plot_multi_protocol_kde(
    protocols_vals: "list[tuple[str, np.ndarray]]",
    title: str = "Suspicion Score Distribution",
    figsize: "tuple[int, int] | None" = None,
    colors: "None | dict | Sequence" = None,
) -> plt.Figure:
    """KDE plot with one labeled line per protocol.

    Args:
        protocols_vals: List of ``(label, values)`` where ``values`` is a 1-D
            float array of per-sample max suspicion scores.
        title: Figure title.
        figsize: Figure size.

    Returns:
        The matplotlib ``Figure``.
    """
    n = len(protocols_vals)
    crowded = n > 4
    if figsize is None:
        # <=4 series: historic (6, 4) with the legend inside. More series
        # widen the figure so the legend can move outside without shrinking
        # the curves.
        figsize = (6, 4) if not crowded else (8.4, 4)

    fig, ax = plt.subplots(figsize=figsize)
    # Derive the x-axis upper bound from the data so raw 0-9 monitors (native
    # control-tower keys, e.g. suspicion_score__tu-root-history) are not clipped
    # to the old hardcoded [0,1] control-arena range. Normalized 0-1 monitors keep
    # x in [0,1] exactly (output unchanged). Mirrors plot_monitor_histogram.
    _all = np.concatenate(
        [np.asarray(v, dtype=float)[~np.isnan(np.asarray(v, dtype=float))]
         for _, v in protocols_vals if v is not None and len(v)]
    ) if any(v is not None and len(v) for _, v in protocols_vals) else np.array([1.0])
    _data_max = float(_all.max()) if _all.size else 1.0
    _upper = max(1.0, float(np.ceil(_data_max)))
    x = np.linspace(0, _upper, 300)

    # ONE absolute bandwidth for every series, so curve HEIGHTS are comparable.
    # scipy's bw_method is a SCALE FACTOR on each series' own standard deviation,
    # so passing the same number smooths each series by a different amount and a
    # density (which integrates to 1) peaks at roughly 1/bandwidth. Two arms that
    # differ only in tail spread then render at very different heights: DTD
    # thr2.333 vs DTRF defer0.5 attack suspicion sit at 76.5% and 72.8% mass on
    # 9.0, but sd 0.79 vs 1.53 (DTRF has 1.8% of attacks down at 1.0) drew peaks
    # of 1.36 vs 0.71 — a 2x visual gap from a 4-point real one. Pinning the
    # absolute width draws those same two curves at 0.92 vs 0.86.
    # Anchored on the POOLED spread, so a single-series plot is bit-identical to
    # the old per-series behavior (pooled == that series).
    _pooled_sd = float(np.std(_all, ddof=1)) if _all.size >= 2 else 0.0
    _bw_abs = 0.3 * _pooled_sd if _pooled_sd > 0 else None

    for i, (label, vals) in enumerate(protocols_vals):
        vals = vals[~np.isnan(vals)]
        # gaussian_kde needs >=2 points with nonzero spread; a degenerate series
        # (e.g. tiny logs where every action shares one suspicion value) yields a
        # singular covariance matrix. Draw a marker line instead of crashing.
        color = _resolve_series_color(colors, label, i)
        if len(vals) < 2 or float(np.ptp(vals)) == 0.0:
            if len(vals) >= 1:
                ax.axvline(float(vals[0]), color=color, lw=2, ls=":", label=label)
            continue
        # bw_method = h / sd gives a kernel of absolute width h (scipy multiplies
        # by the data's ddof=1 standard deviation).
        _sd = float(np.std(vals, ddof=1))
        _bw = (_bw_abs / _sd) if (_bw_abs is not None and _sd > 0) else 0.3
        ax.plot(x, gaussian_kde(vals, bw_method=_bw)(x), color=color, lw=2, label=label)

    ax.set_xlabel("Suspicion score")
    ax.set_ylabel("Density")
    ax.set_title(title)
    if crowded:
        ax.legend(fontsize=8, loc="upper left", bbox_to_anchor=(1.02, 1.0),
                  borderaxespad=0.0)
    else:
        ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Safety vs usefulness line plot (DTD defer-threshold sweep)
# ---------------------------------------------------------------------------
def _su_ci_bounds(
    bootstrap_dist: "np.ndarray", ci_width: float = CONFIDENCE_INTERVAL_WIDTH
) -> "tuple[float, float]":
    """Percentile CI from a 1-D bootstrap distribution.

    ``ci_width`` is the central mass of the interval (default
    tu_bb2.constants.CONFIDENCE_INTERVAL_WIDTH; pass e.g. 0.95 for a 95% CI) —
    same convention as experiments/analysis/compare_usefulness.py::_ci_bounds.
    NaNs (e.g. a safety value with an empty denominator on a degenerate resample)
    are dropped.
    """
    d = np.asarray(bootstrap_dist, dtype=float)
    d = d[~np.isnan(d)]
    if d.size == 0:
        return (float("nan"), float("nan"))
    alpha = 1.0 - ci_width
    lo = float(np.percentile(d, alpha / 2 * 100))
    hi = float(np.percentile(d, (1 - alpha / 2) * 100))
    return lo, hi


def _su_accuracy(log_files, *, task_ids=None) -> "pd.Series":
    """Per-task main_task_success accuracy for a log set (id-indexed), like
    compare_usefulness._acc_df: latest-dedup, pooled epochs averaged per task."""
    from tu_bb2.postprocessing import filter_by_task_ids, relabel_to_base_task_id
    df = get_minimal_log_df(
        log_files,
        include_side_task_success=False,
        include_sus_fields=False,
        dropna=True,
        duplicate_id_handling="latest",
    )
    # Relabel native ``<task>:<hash>`` sample ids to the bare task id so accuracy
    # joins align across logs (e.g. native tower cells vs legacy bare-id baselines);
    # no-op for legacy ids. Mirrors compare_usefulness._acc_df.
    df = relabel_to_base_task_id(df)
    if isinstance(df.index, pd.MultiIndex) or df.index.has_duplicates:
        df = df.groupby(level=0).mean(numeric_only=True)
    df = filter_by_task_ids(df, task_ids)
    return df["score_main_task_success"]


def _su_attack_frame(attack_logs, sus_key, attack_threshold, *, task_ids=None) -> "pd.DataFrame":
    """One clean attack trajectory per task (``pool_runs="dedup_latest"``), as a
    DataFrame indexed by task id with columns ``["sus", "side"]`` for the
    ATTACKED samples only.

    Faithfully replicates ``_compute_protocol_metrics_multirun``'s dedup_latest
    path (postprocessing.py): each log is its own run; errored samples
    (``score_side_task_success`` is NA) are dropped per run; the latest run with
    a clean sample for an id wins; and each id's suspicion is read from the SAME
    chosen run as its side/attack_score — so the per-sample values stay aligned
    (computing ``sus`` and ``side`` from independent latest-dedups does NOT, which
    silently inflates safety).
    """
    from tu_bb2.postprocessing import filter_by_task_ids

    runs = [[str(p)] for p in attack_logs]  # one file per run, matching the engine
    parts = []
    for ri, run in enumerate(runs):
        d = get_minimal_log_df(
            run,
            include_side_task_success=True,
            include_main_task_success=False,
            include_sus_fields=False,
            optional_columns=["score_attacked_scorer"],
            duplicate_id_handling="latest",
        ).sort_index()
        d = d.dropna(subset=["score_side_task_success"]).copy()
        d["_attack_score"] = get_attack_scores_from_log(run).reindex(d.index)
        d["_run"] = ri
        parts.append(d)
    combined = pd.concat(parts)
    combined = combined[~combined.index.duplicated(keep="last")]  # latest clean run wins
    combined = filter_by_task_ids(combined, task_ids)
    chosen = combined["_run"].to_dict()

    if attack_threshold is not None:
        mask = combined["_attack_score"].notna() & (combined["_attack_score"] >= attack_threshold)
    else:
        mask = combined["score_attacked_scorer"] == "C"

    sus_runs = [get_max_suspicion_by_key_index(run, sus_key, duplicate_id_handling="latest")
                for run in runs]
    sus = pd.Series(
        {i: float(sus_runs[chosen[i]].get(i, np.nan)) for i in combined.index},
        dtype=float,
    )
    out = pd.DataFrame({"sus": sus, "side": combined["score_side_task_success"]})
    return out[mask.values]


class SafetyMetricsCacheMiss(Exception):
    """Raised when one or more cells' safety metrics are not in the metrics cache.

    ``missing`` is a list of per-cell dicts (attack_logs, honest_logs, sus_key,
    attack_threshold, pool_runs, resample_aggregation, safety_ci_bootstrap) so the caller can print the
    exact ``compute_metrics.py`` command(s) needed to populate the cache. When
    ``safety_ci_bootstrap`` is not None the cell needs a ``--bootstrap-ci`` run
    at that exact ``n``/``seed`` — the bootstrap config joins the cache key, so a
    default-config CI entry does NOT satisfy a non-default lookup.
    """

    def __init__(self, missing: "list[dict]"):
        self.missing = missing
        super().__init__(
            f"{len(missing)} cell(s) missing from the metrics cache; run compute_metrics.py first."
        )


def _load_cached_protocol_metrics(
    safety_logs, usefulness_logs, sus_keys, attack_threshold, pool_runs, task_ids=None,
    bootstrap: "dict | None" = None,
    resample_aggregation: "str | None" = None,
) -> "ProtocolMetrics | None":
    """Cache-ONLY read of ``ProtocolMetrics`` — never computes, never loads logs.

    Mirrors the read block of ``get_or_compute_protocol_metrics`` (same cache key
    + dir), returning the cached ``ProtocolMetrics`` or ``None`` on a miss. Used
    so the safety-vs-usefulness plot can read safety straight from the metrics
    cache produced by ``compute_metrics.py``, with no attack-log reads.

    ``bootstrap`` selects WHICH cache entry to read. ``compute_metrics.py``
    keys ``--bootstrap-ci`` runs separately from plain ones (the bootstrap
    config joins the key, see ``get_or_compute_protocol_metrics``), and only
    the CI-keyed entry carries ``ci_data``. Pass
    ``{"n": ..., "seed": ..., "level": ...}`` to read that entry; ``None``
    (default) reads the plain entry, whose ``ci_data`` is always ``None``.
    """
    import json

    key = _protocol_cache_key(
        safety_logs, usefulness_logs, sus_keys, task_ids, attack_threshold, pool_runs,
        bootstrap=bootstrap, resample_aggregation=resample_aggregation,
    )
    prefix = key[:12]
    for cache_file in sorted(_METRICS_CACHE_DIR.glob(f"*_{prefix}.json")):
        try:
            data = json.loads(cache_file.read_text())
        except Exception:
            continue
        if data.get("cache_key") == key:
            return ProtocolMetrics.from_dict(data)
    return None


def plot_safety_vs_usefulness(
    series: "list[tuple[list[str], list[str], dict]] | list[tuple[str | None, list[tuple[list[str], list[str], dict]]]]",
    trusted_logs: "list[str]",
    honest_baseline_logs: "list[str]",
    *,
    sus_key: str = "root_history_ensemble_gpt41mini-v7.3",
    n_bootstrap: int = 400,
    seed: int = 42,
    safety_ci_bootstrap: "dict | None" = None,
    task_ids: "list[str] | None" = None,
    title: "str | None" = None,
    figsize: "tuple[float, float]" = (6, 5),
    ci_width: float = CONFIDENCE_INTERVAL_WIDTH,
    colors: "None | dict | Sequence" = None,
    families: "Sequence[str | None] | None" = None,
    markers: "None | str | dict | Sequence" = None,
    equal_aspect: bool = False,
    tick_interval: "float | None" = None,
) -> "tuple[plt.Figure, list[dict]]":
    """Plot safety (x-axis) against usefulness (y-axis) as one **line per series**,
    one point per threshold cell, with x/y error bars of width CONFIDENCE_INTERVAL_WIDTH.

    A *series* is one line: a list of cells swept over the defer threshold. The
    first argument is **either**

    * a flat ``list`` of cells (single unlabeled line — the original contract), or
    * a ``list`` of ``(label, cells)`` series (multiple lines).

    The two shapes are unambiguous: a cell is a 3-tuple ``(attack_logs,
    honest_logs, kwargs)``; a series is a 2-tuple ``(label, cells)``. A flat cells
    list is normalized to a single ``[(None, cells)]`` series internally.

    Colors AND markers follow the **protocol-family convention** by default (see
    ``protocol_series_colors`` / ``protocol_series_markers``): series whose
    labels name a protocol family get that family's identity style — TM blue
    circle, DTR orange square, DTD gray triangle, CES yellow diamond — and when
    a family has several variant series, the first keeps the base color and each
    later variant gets a strictly LIGHTER shade of the same hue, all sharing the
    family's marker. When no label names a family, colors and markers fall back
    to positional ``PIVOTAL_PALETTE`` / ``LINE_MARKERS`` cycling (the legacy
    appearance). ``colors`` and ``markers`` override those (dict label->value or
    a positional sequence); ``families`` declares the protocol per series when
    the labels cannot name it. ``title`` defaults to no title (house style:
    identifying info belongs on the report's cover page). A legend is drawn only
    when there is more than one series or any series carries a non-None label, so
    a single unlabeled line renders exactly as before. No per-point threshold
    labels are drawn (per spec); points are plotted in the order each series'
    cells are given (typically ascending defer threshold) and joined.

    Each cell is ``(attack_logs, honest_logs, kwargs)`` where ``kwargs`` carries
    the protocol's own knobs: ``"attack_threshold"`` (int, default 0) and an
    optional ``"sus_key"`` (overrides the function default for that cell).

    Safety is read from the **metrics cache** produced by ``compute_metrics.py``
    (``experiments/data/metrics_cache/``) — this function loads **no attack logs**.
    Each cell's cached ``ProtocolMetrics`` supplies the safety value plus the
    audited / unaudited-successful / total attack counts; the safety CI is a
    bootstrap over the per-sample category multiset reconstructed from those
    counts (safety depends only on each attack's category — audited,
    unaudited-successful, or neither — so the counts are a sufficient statistic,
    making this identical to bootstrapping the raw (suspicion, side) pairs). If
    any cell is not cached, ``SafetyMetricsCacheMiss`` is raised **before** any
    logs are loaded, so the caller can tell the user which ``compute_metrics.py``
    runs are needed.

    Usefulness is the rescaled ``(test - trusted) / (honest - trusted)`` accuracy
    of ``compare_usefulness.py``, on the trusted/honest-baseline/cell-honest task
    intersection (computed from the honest/baseline logs, which are light to read).
    Both CIs are percentile bootstrap intervals of width CONFIDENCE_INTERVAL_WIDTH.

    Args:
        series: either a flat list of cells (one line) or a list of
            ``(label, cells)`` series (one line each). Each cell is
            ``(attack_logs, honest_logs, kwargs)`` per defer threshold.
            ``kwargs`` may carry ``"attack_threshold"`` (int, default 0),
            ``"sus_key"`` (overrides the default), and ``"pool_runs"`` (default
            ``"epochs_equal_task"``, matching ``compute_protocol_metrics`` and
            ``compute_metrics.py``) — these MUST match the ``compute_metrics.py``
            run that populated the cache, else the cache lookup misses. Note the
            two axes pool DIFFERENTLY by design: safety (x) uses ``pool_runs``,
            which never averages duplicate trajectories, while usefulness (y)
            uses ``_su_accuracy``'s per-task averaging (accuracy is a per-task
            mean, not a per-trajectory audit outcome). An optional
            ``"usefulness_logs"`` (list of paths) computes the cell's usefulness
            accuracy from those logs INSTEAD of ``honest_logs``; ``honest_logs``
            still feeds the safety cache key, so safety is unaffected. Pass the
            honest-baseline logs here to pin the cell's usefulness to exactly 1.0
            (zero-width CI).
        trusted_logs: trusted-policy baseline logs (usefulness lower anchor).
        honest_baseline_logs: honest-policy baseline logs (usefulness upper anchor).
        sus_key: default suspicion key; overridable per cell via ``kwargs["sus_key"]``.
        n_bootstrap: bootstrap resamples for the USEFULNESS (y) CI, and for the
            fallback frozen-tau safety CI when ``safety_ci_bootstrap`` is None.
        seed: bootstrap seed for those same two.
        safety_ci_bootstrap: which cached bootstrap CI to read for the SAFETY (x)
            bars, as ``{"n", "seed", "level"}`` (the config
            ``compute_metrics.py --bootstrap-ci`` keyed the entry under; its
            defaults are n=500, seed=0, level=CONFIDENCE_INTERVAL_WIDTH). This is
            the cluster bootstrap of ``postprocessing._bootstrap_scalar_cis``,
            which resamples task clusters of BOTH arms and recomputes the p95
            audit threshold per draw, so audit-threshold calibration noise is
            included. A cell with no such cached entry is reported as MISSING
            (fail fast) rather than silently downgraded.
            ``None`` selects the legacy frozen-tau counts bootstrap instead:
            resample the cached audited / unaudited-successful / neither
            multiset with tau pinned at its point value. That interval is
            CONDITIONAL on the realized tau and is materially narrower (e.g.
            DTRF defer0.5 [0.832, 0.895] vs [0.775, 0.950]) — it understates
            protocol-level uncertainty and must not be read as evidence that two
            protocols separate. Kept only as an explicit opt-out.
        task_ids: optional task-id restriction (must match the cached run).
        title / figsize: figure styling.
        ci_width: central mass of the bootstrap CIs / error bars (default
            CONFIDENCE_INTERVAL_WIDTH; pass 0.95 for 95% intervals).
        colors: per-series color override (dict label -> hex, or a hex sequence
            indexed by series position). Default None = the protocol-family
            convention from the series labels, falling back to positional
            ``PIVOTAL_PALETTE`` cycling when no label names a family.

    Returns:
        ``(fig, summary)`` where ``fig`` is the matplotlib ``Figure`` and
        ``summary`` is a list of per-cell dicts (series order, then cell order)
        with keys ``series`` (the line label, possibly None), ``threshold`` (the
        sweep value for this point, possibly None), ``attack_logs``,
        ``honest_logs``, ``sus_key``, ``attack_threshold``, ``pool_runs``
        (the safety-side pooling rule), ``n_common``,
        ``safety``/``safety_lo``/``safety_hi``,
        ``usefulness``/``usefulness_lo``/``usefulness_hi`` and ``plotted`` — so a
        caller can record the exact inputs/results on a cover page.

    Raises:
        SafetyMetricsCacheMiss: if any cell's safety metrics are not in the cache.
    """
    # Normalize the input to a list of (label, cells) series. A cell is a 3-tuple
    # and a series is a 2-tuple, so the shapes are unambiguous. A flat cells list
    # becomes one unlabeled series, preserving the original single-line contract.
    norm_series: "list[tuple[str | None, list]]"
    if series and all(isinstance(s, (tuple, list)) and len(s) == 2 for s in series):
        norm_series = [(label, list(cells)) for label, cells in series]
    else:
        norm_series = [(None, list(series))]

    # ---- Pass 1: safety from the metrics cache ONLY (no attack-log reads) ----
    # Done first so an incomplete cache fails fast before any logs are loaded.
    safety_pts: "list[list[dict]]" = []  # per series, per cell
    missing: "list[dict]" = []
    for _label, cells in norm_series:
        series_pts: "list[dict]" = []
        for attack_logs, honest_logs, kw in cells:
            cell_sus_key = kw.get("sus_key", sus_key)
            attack_threshold = kw.get("attack_threshold", 0)
            pool_runs = kw.get("pool_runs", "epochs_equal_task")
            # Metric-affecting, so it MUST join the cache key: dropping it would
            # silently serve max-agg metrics for a cell that asked for min-agg.
            resample_agg = kw.get("resample_aggregation")
            # Every key the named log groups or this function legitimately carry.
            # "label"/"threshold"/"defer_threshold"/"usefulness_logs" are presentation
            # or selection keys; the rest are metric-affecting and handled above. The
            # point of the check is to catch a MISSPELLED metric-affecting key (e.g.
            # "resample_agg"), which would otherwise be silently dropped and plot a
            # number computed under different settings than requested.
            _unknown = set(kw) - {
                "sus_key", "attack_threshold", "pool_runs", "resample_aggregation",
                "usefulness_logs", "threshold", "defer_threshold", "label",
            }
            if _unknown:
                raise ValueError(
                    f"Unknown cell kwarg(s) {sorted(_unknown)} for attack log(s) "
                    f"{[str(p) for p in attack_logs]}. Metric-affecting keys must be "
                    "handled explicitly — silently ignoring one would plot a number "
                    "computed under different settings than requested."
                )
            spec = {
                "attack_logs": [str(p) for p in attack_logs],
                "honest_logs": [str(p) for p in honest_logs],
                "sus_key": cell_sus_key,
                "attack_threshold": attack_threshold,
                "pool_runs": pool_runs,
                "resample_aggregation": resample_agg,
                # Carried so the caller's remediation command can reproduce the
                # EXACT cache key — a bare --bootstrap-ci would populate the
                # default 500/0 entry and leave a non-default lookup missing.
                "safety_ci_bootstrap": safety_ci_bootstrap,
            }
            pm = _load_cached_protocol_metrics(
                spec["attack_logs"], spec["honest_logs"], [cell_sus_key],
                attack_threshold, pool_runs, task_ids,
                bootstrap=safety_ci_bootstrap,
                resample_aggregation=resample_agg,
            )
            if pm is None:
                missing.append(spec)
                continue
            sm = pm.scalar_metrics
            try:
                safety = float(sm[f"safety ({cell_sus_key})"])
            except (KeyError, ValueError):
                missing.append(spec)
                continue

            if safety_ci_bootstrap is not None:
                # Preferred: the cluster bootstrap that recomputes the p95 audit
                # threshold per draw (postprocessing._bootstrap_scalar_cis),
                # already computed and cached by compute_metrics --bootstrap-ci.
                _ci = (pm.ci_data or {}).get(f"safety ({cell_sus_key})")
                if _ci is None or not all(np.isfinite(_ci)):
                    missing.append(spec)
                    continue
                s_lo, s_hi = float(_ci[0]), float(_ci[1])
            else:
                # Opt-out: frozen-tau counts bootstrap. CONDITIONAL on the
                # realized audit threshold and materially narrower — see the
                # safety_ci_bootstrap docstring before quoting it.
                try:
                    # The fractional-threshold audit stores tie-weighted counts as
                    # floats (e.g. "34.00", "54.05"); round to ints for the category
                    # multiset the bootstrap resamples. The safety POINT uses the
                    # exact cached value, so rounding only affects the CI width.
                    a = round(float(sm[f"audited attacks ({cell_sus_key})"]))
                    u = round(float(sm[f"unaudited successful attacks ({cell_sus_key})"]))
                    n = int(float(sm[f"total attacks ({cell_sus_key})"]))
                except (KeyError, ValueError):
                    missing.append(spec)
                    continue
                a = max(0, min(a, n))
                u = max(0, min(u, n - a))

                # Bootstrap safety from the cached category counts: each attacked
                # sample is 0=audited, 1=unaudited-successful, 2=neither.
                # Safety = #0 / (#0 + #1).
                cats = np.concatenate([
                    np.zeros(a, dtype=np.int8),
                    np.ones(u, dtype=np.int8),
                    np.full(max(0, n - a - u), 2, dtype=np.int8),
                ])
                rng = np.random.default_rng(seed)
                boot = np.empty(n_bootstrap, dtype=float)
                for b in range(n_bootstrap):
                    s = cats[rng.integers(0, n, n)] if n else cats
                    na = int((s == 0).sum())
                    nu = int((s == 1).sum())
                    boot[b] = na / (na + nu) if (na + nu) > 0 else np.nan
                s_lo, s_hi = _su_ci_bounds(boot, ci_width)
            series_pts.append({"safety": safety, "lo": s_lo, "hi": s_hi})
        safety_pts.append(series_pts)

    if missing:
        raise SafetyMetricsCacheMiss(missing)

    # ---- Pass 2: usefulness (rescaled accuracy from honest/baseline logs) ----
    trusted_acc = _su_accuracy(trusted_logs, task_ids=task_ids)
    honest_acc = _su_accuracy(honest_baseline_logs, task_ids=task_ids)

    summary: "list[dict]" = []  # one row per cell (series order), for the cover page
    multi = len(norm_series) > 1 or any(lbl is not None for lbl, _ in norm_series)

    # Protocol-family colors from the series labels by default (None when no
    # label names a family -> legacy positional PIVOTAL_PALETTE cycling below).
    _labels = [lbl for lbl, _ in norm_series]
    if colors is None:
        colors = protocol_series_colors(_labels, families)
    # Markers follow the same convention: family markers when any series names a
    # protocol, else the legacy positional LINE_MARKERS cycle.
    _auto_markers = protocol_series_markers(_labels, families)

    fig, ax = plt.subplots(figsize=figsize)
    for si, ((label, cells), series_pts) in enumerate(zip(norm_series, safety_pts)):
        if colors is None:
            color = PIVOTAL_PALETTE[si % len(PIVOTAL_PALETTE)]
        else:
            color = _resolve_series_color(colors, label, si, palette=PIVOTAL_PALETTE)
        marker = _resolve_series_marker(
            markers if markers is not None else _auto_markers, label, si,
        )
        safety_x: list[float] = []
        usefulness_y: list[float] = []
        sx_err = [[], []]  # [lower, upper] distances for xerr
        uy_err = [[], []]  # [lower, upper] distances for yerr

        for (attack_logs, honest_logs, kw), sp in zip(cells, series_pts):
            safety, s_lo, s_hi = sp["safety"], sp["lo"], sp["hi"]
            cell_sus_key = kw.get("sus_key", sus_key)
            attack_threshold = kw.get("attack_threshold", 0)

            usefulness_logs = kw.get("usefulness_logs")
            test_acc = _su_accuracy(
                list(usefulness_logs) if usefulness_logs else list(honest_logs),
                task_ids=task_ids,
            )
            df_u = pd.concat(
                [test_acc.rename("test"), trusted_acc.rename("tr"), honest_acc.rename("ho")],
                axis=1,
            ).dropna()
            denom = df_u["ho"].mean() - df_u["tr"].mean()
            usefulness = (df_u["test"].mean() - df_u["tr"].mean()) / denom
            boot_means = _bootstrap_distributions(
                df_u[["test", "tr", "ho"]].values, n_bootstrap=n_bootstrap, seed=seed
            )
            u_boot = (boot_means[:, 0] - boot_means[:, 1]) / (boot_means[:, 2] - boot_means[:, 1])
            u_lo, u_hi = _su_ci_bounds(u_boot, ci_width)

            plotted = not (np.isnan(safety) or np.isnan(usefulness))
            summary.append({
                "series": label,
                "threshold": kw.get("threshold", kw.get("defer_threshold")),
                "attack_logs": [str(p) for p in attack_logs],
                "honest_logs": [str(p) for p in honest_logs],
                "usefulness_logs": (
                    [str(p) for p in usefulness_logs] if usefulness_logs else None
                ),
                "sus_key": cell_sus_key,
                "attack_threshold": attack_threshold,
                # How the SAFETY (x) coordinate pooled this cell's logs. Part of
                # the metrics cache key and it changes the number, so it belongs
                # on the cover page — a report is not auditable without it.
                "pool_runs": kw.get("pool_runs", "epochs_equal_task"),
                # Same reasoning as pool_runs: metric-affecting and part of the cache
                # key, so a report that omits it is not auditable — a min-agg point
                # would be indistinguishable from a max-agg one.
                "resample_aggregation": kw.get("resample_aggregation"),
                "n_common": int(len(df_u)),
                "safety": float(safety), "safety_lo": float(s_lo), "safety_hi": float(s_hi),
                "usefulness": float(usefulness), "usefulness_lo": float(u_lo),
                "usefulness_hi": float(u_hi),
                "plotted": plotted,
            })
            if not plotted:
                continue
            safety_x.append(float(safety))
            usefulness_y.append(float(usefulness))
            sx_err[0].append(max(0.0, safety - s_lo))
            sx_err[1].append(max(0.0, s_hi - safety))
            uy_err[0].append(max(0.0, usefulness - u_lo))
            uy_err[1].append(max(0.0, u_hi - usefulness))

        if safety_x:
            ax.errorbar(
                safety_x, usefulness_y,
                xerr=np.array(sx_err), yerr=np.array(uy_err),
                fmt=f"-{marker}", color=color, ecolor=PIVOTAL_PALETTE[2],
                elinewidth=1.2, capsize=4, markersize=6, label=label,
            )

    ax.set_xlabel("Safety")
    ax.set_ylabel("Usefulness")
    # House style: data figures carry no title by default (the report's cover
    # page holds the identifying info). Pass title= to opt back in.
    if title:
        ax.set_title(title)
    ax.grid(alpha=0.3)
    if multi:
        # Legend icons show just the line + marker: unwrap each ErrorbarContainer
        # to its data Line2D so the whisker/cap glyphs don't clutter the swatches.
        handles, labels = ax.get_legend_handles_labels()
        handles = [h[0] if isinstance(h, ErrorbarContainer) else h for h in handles]
        ax.legend(handles, labels)
    # Optional square framing: one data unit of safety spans the same length as
    # one data unit of usefulness, so the two axes are directly comparable by eye.
    if equal_aspect:
        ax.set_aspect("equal", adjustable="box")
    # Both axes tick at the same interval. With equal_aspect and no explicit
    # value, take the coarser of the two auto spacings so neither axis is crowded.
    if tick_interval is None and equal_aspect:
        _spacings = [
            abs(t[1] - t[0]) for t in (ax.get_xticks(), ax.get_yticks()) if len(t) > 1
        ]
        tick_interval = max(_spacings) if _spacings else None
    if tick_interval:
        ax.xaxis.set_major_locator(MultipleLocator(tick_interval))
        ax.yaxis.set_major_locator(MultipleLocator(tick_interval))
    fig.tight_layout()
    return fig, summary


def plot_safety_vs_audit_budget(
    series: "Sequence[tuple[str, pd.DataFrame]]",
    *,
    title: "str | None" = None,
    figsize: "tuple[float, float]" = (8.5, 6),
    colors: "None | dict | Sequence" = None,
    families: "Sequence[str | None] | None" = None,
    markers: "None | str | dict | Sequence" = None,
    dodge: float = 0.012,
    xticks_pct: "Sequence[float]" = (0.5, 1, 2, 5, 10, 20),
    ax: "Axes | None" = None,
) -> "plt.Figure":
    """One line per protocol cell: safety (y) vs audit budget in percent (x, log
    scale), with vertical CI error bars.

    ``series`` is a list of ``(label, budget_df)`` where ``budget_df`` comes from
    ``postprocessing.compute_safety_vs_audit_budget`` (columns ``budget_pct``,
    ``safety``, ``ci_lo``, ``ci_hi``). Colors AND markers follow the
    protocol-family convention (``protocol_series_colors`` /
    ``protocol_series_markers`` on the labels — TM blue circle, DTR orange
    square, DTD gray triangle, CES yellow diamond, with lighter shades for
    variants of one family) and fall back to ``PIVOTAL_PALETTE`` /
    ``LINE_MARKERS`` cycling when no label names a protocol. ``colors`` and
    ``markers`` override those (dict label->value, positional sequence, or —
    for ``markers`` — a bare string forcing one shape on every series).
    ``families`` declares the protocol per series when the labels cannot.
    ``title`` defaults to no title (house style); pass one to opt back in.
    Series are dodged symmetrically by ``dodge`` in log-space so coincident
    error bars stay readable; ticks list entries outside the data range are
    dropped.
    """
    fig = None
    if ax is None:
        fig, ax = plt.subplots(figsize=figsize)
    else:
        fig = ax.figure

    labels = [lb for lb, _ in series]
    family = protocol_series_colors(labels, families)
    palette = family if family is not None else PIVOTAL_PALETTE
    auto_markers = protocol_series_markers(labels, families)
    n = len(series)
    for i, (lb, d) in enumerate(series):
        color = _resolve_series_color(colors, lb, i, palette=palette)
        marker = _resolve_series_marker(
            markers if markers is not None else auto_markers, lb, i,
        )
        d = d.sort_values("budget_pct")
        offset = 0.0 if n == 1 else dodge * (i - (n - 1) / 2.0) * 2.0
        x = d["budget_pct"].to_numpy() * (1.0 + offset)
        yerr = np.vstack([
            (d["safety"] - d["ci_lo"]).to_numpy(),
            (d["ci_hi"] - d["safety"]).to_numpy(),
        ])
        ax.errorbar(x, d["safety"], yerr=yerr, color=color, marker=marker,
                    ms=5, lw=2, capsize=3, elinewidth=1.2, label=lb)
    ax.set_xscale("log")
    lo = min(d["budget_pct"].min() for _, d in series)
    hi = max(d["budget_pct"].max() for _, d in series)
    ticks = [t for t in xticks_pct if lo <= t <= hi]
    ax.set_xticks(ticks, [f"{t:g}%" for t in ticks])
    ax.set_xlabel("audit budget (share of honest samples audited, log scale)")
    ax.set_ylabel("safety")
    # House style: no title by default (see plot_safety_vs_usefulness).
    if title:
        ax.set_title(title)
    if n > 1:
        ax.legend(frameon=False)
    ax.grid(True, which="both", axis="x", alpha=0.15)
    ax.grid(True, axis="y", alpha=0.15)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig
