"""Plot safety (x-axis) vs usefulness (y-axis) across a DTD defer-threshold sweep.

One point per threshold cell, joined by a line. Multiple lines can be drawn on the
same axes — one per protocol family (a set of protocols sharing all parameters
except the defer threshold) — via repeated ``--series-groups`` (see below); each
line gets its own color + marker + legend entry. With x/y error bars of width
``tu_bb2.constants.CONFIDENCE_INTERVAL_WIDTH``. Safety is **read from the metrics
cache** that ``experiments/analysis/compute_metrics.py`` writes
(``experiments/data/metrics_cache/``) — this script loads **no attack logs**.

The safety (x) CI is the **cluster bootstrap that recomputes the p95 audit
threshold per draw** (``postprocessing._bootstrap_scalar_cis``), read from the
cache entry a ``compute_metrics.py --bootstrap-ci`` run wrote — so
audit-threshold calibration noise is included. That noise is not a detail: on
BA1.0 it is essentially the entire interval width (resampling only the honest arm,
with the attack arm held fixed, reproduces the full AAR interval almost exactly,
against ~±0.035 of attack-side binomial noise). The legacy alternative — a counts
bootstrap over the cached audited/unaudited-successful/total scalars with the
threshold FROZEN — is 2-3x narrower (DTRF defer0.5 [0.832, 0.895] vs
[0.775, 0.950]), is conditional on the realized threshold, and must not be read as
evidence that two protocols separate. It survives only behind
``--counts-safety-ci``. If a cell is not cached, the script FAILS FAST and prints the
exact ``compute_metrics.py`` command(s) to populate it. Usefulness is the rescaled
``(test - trusted) / (honest - trusted)`` accuracy of ``compare_usefulness.py``
(from the honest/baseline logs). The plotting + metric logic lives in
``tu_bb2.plotting.plot_safety_vs_usefulness``; this script is just the CLI driver.

IMPORTANT: run ``compute_metrics.py --bootstrap-ci`` for every cell first (same
--attack-threshold and --pool-runs as the cell), so the safety metrics AND their
CI are cached before plotting. The bootstrap config joins the cache key, so a cell
cached without ``--bootstrap-ci`` (or at a different --n-bootstrap/--bootstrap-seed
than ``--safety-ci-n-bootstrap``/``--safety-ci-seed``) counts as a cache miss.

CLI (one cell per positionally-paired --attack-run / --honest-run)::

    uv run python experiments/analysis/plot_safety_usefulness.py \
        --attack-run <2/30 attack logs...> --honest-run <2/30 honest logs...> \
        --attack-run <3/30 attack logs...> --honest-run <3/30 honest logs...> \
        --trusted <trusted baseline logs...> \
        --honest-baseline <honest baseline logs...>

By default it writes a PDF (parameter cover page + the plot + a per-series data
table of the plotted points: threshold, safety and usefulness with CI ranges) to
``experiments/data/metrics_reports_tower/<UTC>_safety-use_<slug>.pdf``, like the other
analysis scripts. Pass ``--out`` to override the path (``.pdf`` keeps the cover
page + table; any other extension writes just the plot image).

``--attack-threshold`` and ``--sus-key`` accept one value per cell (paired by
position); cells without an explicit value fall back to 0 and the default sus key.

For multiple lines, pass ``--series-groups ATTACK_GROUP HONEST_GROUP [LABEL]`` once
per line, naming ``BashArenaLogs`` groups (each a defer-threshold sweep) that are
matched on ``defer_threshold``; ``[LABEL]`` defaults to ``ATTACK_GROUP``::

    uv run python experiments/analysis/plot_safety_usefulness.py \
        --series-groups ONLINE_ATTACK_DTD_REV1 ONLINE_HONEST_DTD "DTD v7.3 1.5M" \
        --series-groups ONLINE_DTD_THR_2P5MTOK_v73_ATTACK ONLINE_DTD_THR_2P5MTOK_v73_HONEST "DTD v7.3 2.5M" \
        --trusted <trusted logs...> --honest-baseline <baseline logs...>

Each named group must be a defer-threshold sweep of shape
``list[tuple[logs, {"defer_threshold": ...}]]`` (e.g. ``ONLINE_HONEST_DTD``);
not-yet-run cells (empty log list) are omitted with a note.

**Line colors**: series follow the protocol-family convention
(``tu_bb2.plotting.protocol_series_colors``), detected FROM EACH LINE'S LABEL —
so make every label name its protocol ("TM …", "DTRF …", "DTD …", "DTR …",
case-insensitive). A family with one line gets its fixed identity color (TM blue
#3A82B5, DTRF orange #F15F22, DTD gray #7C7D7F, DTR yellow #FFC61F), consistent
across reports regardless of line order. A family with several variant lines
(e.g. the same protocol under two monitor versions or attack recipes) gets
light->dark shades of that family's hue alone, in the order the series are
passed. Labels naming no family get non-family fallback colors; if no label
names a family, the legacy positional palette is used. No flag needed — just
name the labels well.

With no ``--series-groups``/``--attack-run`` the script falls back to the named
groups ``BashArenaLogs.ONLINE_ATTACK_DTD_REV1`` + ``ONLINE_HONEST_DTD`` (matched on
``defer_threshold``) as a single line; ``--trusted`` / ``--honest-baseline`` are
still required.
"""
from __future__ import annotations

import argparse
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH
from tu_bb2.utils import REPO_ROOT
from tu_bb2.named_tasks_and_logs import (
    BashArenaLogs, TASK_IDS_CLI_HELP, resolve_task_ids_arg,
)
from tu_bb2.plotting import plot_safety_vs_usefulness, SafetyMetricsCacheMiss
from tu_bb2.postprocessing import RESAMPLE_AGGREGATIONS

_DEFAULT_SUS_KEY = "root_history_ensemble_gpt41mini-v7.3"

# Heading for the cover / data-table pages when --title is omitted. The PLOT
# itself stays untitled (house style); these text pages still need a name.
_DEFAULT_PAGE_HEADING = "Safety vs Usefulness"

# Usefulness anchors used when --honest-baseline / --trusted are omitted. Both MUST be free
# of limit censoring: a depressed honest anchor inflates usefulness, a depressed trusted
# anchor deflates it, and the two do not cancel.
#
# These are the BA1.0-replan restored anchors (audited 2026-07-30): token_limit=None,
# sample_time_limit=11700, message_limit=300, max_steps=60; ZERO token-limit and ZERO
# time-limit terminations in all four logs. max_steps=60 is the intended experimental
# governor and applies identically to the test cells (it binds on 27%/19% of trusted samples
# vs 0.7%/0% of honest ones — state that asymmetry when reporting).
#
# Previous defaults, both retired here (see the deprecation notes on the constants in
# tu_bb2/named_tasks_and_logs.py):
#   honest  UH_2P5MTOK_ORIGINAL_TASKS — 35% of samples killed by a 2.5M token limit.
#   trusted TOWER_TPOLICY_GPT54NANO   — uncensored, but pools max_steps=200 and =60 logs.
#
# For BA1.2 (60ACTION / BA12-TRAIN1000) work, pass the BA1.2 anchors explicitly:
#   --trusted <TOWER_60ACTION_TPOLICY>  --honest-baseline <TOWER_BA12_UH_USEFULNESS_BASELINE>
_DEFAULT_HONEST_BASELINE = BashArenaLogs.TOWER_BA10_UH_ANCHOR_RESTORED_PATHS
_DEFAULT_TRUSTED = BashArenaLogs.TOWER_BA10_TPOLICY_ANCHOR_RESTORED_PATHS


def _relpath(p: str) -> str:
    """Repo-relative path for readable printed commands."""
    try:
        return str(Path(p).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return p


def _compute_metrics_cmd(spec: dict, task_ids_arg: "str | None" = None) -> str:
    """The exact compute_metrics.py command that would populate a missing cell's cache."""
    atk = " ".join(_relpath(p) for p in spec["attack_logs"])
    hon = " ".join(_relpath(p) for p in spec["honest_logs"])
    # A CI-keyed lookup needs a --bootstrap-ci run at the SAME n/seed: the
    # bootstrap config joins the cache key, so a bare --bootstrap-ci (which
    # defaults to 500/0) would not satisfy a non-default lookup.
    bs = spec.get("safety_ci_bootstrap")
    boot = (
        f" \\\n    --bootstrap-ci --n-bootstrap {bs['n']} --bootstrap-seed {bs['seed']}"
        if bs else ""
    )
    # resample_aggregation joins the cache key too, so the remediation command must
    # carry it or the populated entry would not satisfy the lookup that failed.
    _ragg = spec.get("resample_aggregation")
    ragg = f" --resample-agg {_ragg}" if _ragg else ""
    # task_ids joins the cache key as well, so a remediation command without it
    # would populate the UNRESTRICTED entry and the same lookup would miss again.
    tids = f" --task-ids {task_ids_arg}" if task_ids_arg else ""
    return (
        "uv run python experiments/analysis/compute_metrics.py \\\n"
        f"    --safety {atk} \\\n"
        f"    --usefulness {hon} \\\n"
        f"    --sus-keys {spec['sus_key']} "
        f"--attack-threshold {spec['attack_threshold']} "
        f"--pool-runs {spec['pool_runs']}"
        f"{ragg}"
        f"{tids}"
        f"{boot}"
    )


def _abs(paths: list[str]) -> list[str]:
    """Resolve repo-relative paths against REPO_ROOT (absolute paths pass through)."""
    out = []
    for p in paths:
        pp = Path(p)
        out.append(str(pp if pp.is_absolute() else REPO_ROOT / pp))
    return out


def _cell_kwargs(a_kw: dict, threshold: "float | None" = None,
                 resample_aggregation: "str | None" = None) -> dict:
    """Per-cell kwargs from an attack group's metadata, preserving every key that
    is part of the metrics cache key: ``attack_threshold``, ``sus_key``,
    ``pool_runs`` (several groups pin a non-default ``pool_runs`` such as
    ``"dedup_latest"``; dropping it would mis-key the cache lookup) and
    ``resample_aggregation``.

    The SAFETY (x) coordinate defaults to ``"epochs_equal_task"``, matching
    ``compute_protocol_metrics`` and ``compute_metrics.py``. Safety must never be
    computed by averaging duplicate trajectories together — the epoch modes keep
    each trajectory as its own row and only reweight tasks to equal total weight,
    while ``dedup_latest`` keeps one clean trajectory per task; both are valid
    safety estimators. (The USEFULNESS (y) coordinate deliberately uses a
    different rule — per-task averaging in ``plotting._su_accuracy`` — because
    accuracy is a per-task mean, not a per-trajectory audit outcome.)

    Groups that pool a partial run with its rerun still pin ``dedup_latest``
    explicitly, which continues to win over this default: for a SUPERSESSION pool
    the later run replaces the earlier one, and averaging the two at 1/n would
    re-admit the superseded (often limit-censored) samples into the audit
    threshold.

    ``threshold`` is the sweep value (defer/monitor threshold) identifying this
    point on its line; carried through to the summary / data-table page only (not
    part of the cache key).

    ``resample_aggregation`` is the per-SERIES override from ``--series-resample-agg``;
    a value pinned on the group itself wins. It DOES join the cache key, so a cell
    asking for one will miss until ``compute_metrics.py --resample-agg`` has populated
    it. Only ever set it for a resampling protocol (DTR/DTRF) — TM and DTD have no
    per-step structure and the library raises rather than silently no-op'ing."""
    return {
        "attack_threshold": a_kw.get("attack_threshold", 0),
        "sus_key": a_kw.get("sus_key", _DEFAULT_SUS_KEY),
        "pool_runs": a_kw.get("pool_runs", "epochs_equal_task"),
        "resample_aggregation": a_kw.get("resample_aggregation", resample_aggregation),
        "threshold": threshold,
    }


def _threshold_from_logs(paths: list[str]) -> "float | None":
    """Parse the sweep threshold from a log filename token, e.g. ``thr2p0`` -> 2.0,
    ``defer0p5`` -> 0.5, ``thr0p100`` -> 0.1 (the convention the index-matched
    TOWER_*_DEFER_* / ONLINE_* runs encode it in). Returns None if absent."""
    for p in paths:
        m = re.search(r"(?:thr|defer)(\d+)p(\d+)", Path(p).name)
        if m:
            return float(f"{m.group(1)}.{m.group(2)}")
    return None


def _cells_from_group_pair(attack_group, honest_group,
                           resample_aggregation: "str | None" = None,
                           ) -> list[tuple[list[str], list[str], dict]]:
    """Build one line's cells by pairing an attack group with an honest group, each
    a ``list[tuple[logs, kwargs]]`` swept over the deferral trigger.

    Two pairing modes, chosen automatically:

    * **defer_threshold** — when every populated entry of BOTH groups carries a
      ``"defer_threshold"`` kwarg (e.g. ``ONLINE_ATTACK_DTD_REV1`` /
      ``ONLINE_HONEST_DTD``), attack and honest cells are matched on that value.
    * **index** — otherwise the groups are paired by position (the convention for
      the index-aligned ``TOWER_*_DEFER_*`` groups, which encode the threshold in
      the log name rather than a kwarg). ``None`` entries are skipped.

    Cell kwargs come from the **attack** group via :func:`_cell_kwargs`. Cells whose
    attack OR honest log list resolves to empty / ``None`` are *not-yet-run*
    placeholders; they are omitted with a note rather than emitted (an empty cell is
    missing data, not a cache miss, and would produce blank ``compute_metrics.py``
    remediation args).
    """
    def _carries_threshold(group) -> bool:
        return all(e is not None and "defer_threshold" in e[1] for e in group)

    cells: list[tuple[list[str], list[str], dict]] = []

    if _carries_threshold(attack_group) and _carries_threshold(honest_group):
        honest_by_thr = [
            (kw["defer_threshold"], BashArenaLogs.as_paths(logs))
            for logs, kw in honest_group
        ]
        for a_logs, a_kw in attack_group:
            thr = a_kw["defer_threshold"]
            match = next(
                (h for t, h in honest_by_thr if math.isclose(t, thr, rel_tol=1e-9, abs_tol=1e-12)),
                None,
            )
            if match is None:
                print(f"WARNING: no honest cell for defer_threshold={thr}; skipping attack cell.")
                continue
            a_paths = [str(p) for p in BashArenaLogs.as_paths(a_logs)]
            h_paths = [str(p) for p in match]
            if not a_paths or not h_paths:
                print(f"note: omitting defer_threshold={thr} (not yet run: "
                      f"{'attack' if not a_paths else 'honest'} arm has no logs).")
                continue
            cells.append((a_paths, h_paths, _cell_kwargs(
                a_kw, threshold=thr, resample_aggregation=resample_aggregation)))
        return cells

    # Index-matched groups (e.g. TOWER_*_DEFER_*): pair by position, skip None.
    if len(attack_group) != len(honest_group):
        print(f"WARNING: index-matched groups differ in length "
              f"({len(attack_group)} attack vs {len(honest_group)} honest); "
              "pairing the common prefix.")
    for i, (a_entry, h_entry) in enumerate(zip(attack_group, honest_group)):
        if a_entry is None or h_entry is None:
            print(f"note: omitting index {i} (not yet run: "
                  f"{'attack' if a_entry is None else 'honest'} entry is None).")
            continue
        a_logs, a_kw = a_entry
        h_logs, _h_kw = h_entry
        a_paths = [str(p) for p in BashArenaLogs.as_paths(a_logs)]
        h_paths = [str(p) for p in BashArenaLogs.as_paths(h_logs)]
        if not a_paths or not h_paths:
            print(f"note: omitting index {i} (not yet run: "
                  f"{'attack' if not a_paths else 'honest'} arm has no logs).")
            continue
        thr = a_kw.get("defer_threshold", _threshold_from_logs(a_paths))
        cells.append((a_paths, h_paths, _cell_kwargs(
                a_kw, threshold=thr, resample_aggregation=resample_aggregation)))
    return cells


def _resolve_group(name: str):
    """Resolve a BashArenaLogs group name to its value.

    An optional ``[i]`` index suffix selects a single entry as a one-element group,
    e.g. ``"TOWER_TM_V11_1_ATTACK[0]"`` yields just the TM cell — handy for overlaying
    a single baseline point next to a swept line (the attack/honest indices must
    correspond). Without the suffix the whole group is returned.
    """
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\[(-?\d+)\]", name)
    base = m.group(1) if m else name
    try:
        group = getattr(BashArenaLogs, base)
    except AttributeError:
        raise SystemExit(f"ERROR: unknown BashArenaLogs group {base!r}.")
    if m is None:
        return group
    idx = int(m.group(2))
    try:
        return [group[idx]]
    except (IndexError, TypeError):
        raise SystemExit(f"ERROR: index {idx} out of range for group {base!r} "
                         f"(len {len(group) if hasattr(group, '__len__') else '?'}).")


def _doc_page(
    summary: list[dict],
    trusted_logs: list[str],
    honest_baseline_logs: list[str],
    *,
    generated_at: str,
    default_sus_key: str,
    n_bootstrap: int,
    seed: int,
    title: str,
    task_ids,
    ci_width: float,
    safety_ci_bootstrap: "dict | None" = None,
) -> "plt.Figure":
    """Cover page recording the exact parameters + per-cell results, mirroring the
    doc page that compare_usefulness.py / compute_metrics.py write."""
    fig = plt.figure(figsize=(8.5, 11))
    # Name the SAFETY estimator explicitly: the two available intervals answer
    # different questions and differ by 2-3x in width, so a reader must never
    # have to guess which one the x-bars are.
    safety_ci_desc = (
        f"cluster bootstrap by task id, p95 audit threshold RECOMPUTED per draw "
        f"(B={safety_ci_bootstrap['n']}, seed={safety_ci_bootstrap['seed']}; cached)"
        if safety_ci_bootstrap else
        f"counts bootstrap, audit threshold FIXED at its point value "
        f"(B={n_bootstrap}, seed={seed}) — CONDITIONAL on tau, understates uncertainty"
    )
    lines = [
        "Safety vs Usefulness Report",
        f"Generated (UTC): {generated_at}",
        f"title: {title if title else '(none - untitled figure)'}",
        f"CI width: {ci_width} (x/y error bars)",
        f"default sus_key: {default_sus_key}",
        f"n_bootstrap: {n_bootstrap}    seed: {seed}    task_ids: {task_ids}",
        f"safety (x) CI: {safety_ci_desc}",
        f"usefulness (y) CI: bootstrap over per-task accuracy (B={n_bootstrap}, seed={seed})",
        # The two axes pool multi-log arms by DIFFERENT rules, on purpose. Stating
        # it here means a reader never has to infer it from the CI method string.
        "pooling: safety (x) per-cell pool_runs below (never averages "
        "trajectories); usefulness (y) averages duplicates per task",
        "",
    ]
    # Print a per-line header only when there is >1 line or any line is labeled,
    # so the single-default-line cover page stays byte-for-byte as before.
    labels = [row.get("series") for row in summary]
    multi = len(set(labels)) > 1 or any(lbl is not None for lbl in labels)
    prev_label = object()  # sentinel so the first row always opens a line header
    for i, row in enumerate(summary):
        if multi and row.get("series") != prev_label:
            prev_label = row.get("series")
            lines.append(f"── Line: {prev_label} ──")
        lines.append(f"── Cell {i}{'' if row['plotted'] else '  (NOT PLOTTED: nan)'} ──")
        lines.append("  safety (attack) log(s):")
        lines += [f"    {Path(p).name}" for p in row["attack_logs"]]
        lines.append("  usefulness (honest) log(s):")
        lines += [f"    {Path(p).name}" for p in row["honest_logs"]]
        if row.get("usefulness_logs"):
            # Only rendered when the cell's usefulness accuracy was computed from an
            # override log set (--pin-usefulness-to-baseline); absent otherwise so
            # override-free reports stay byte-identical to pre-override ones.
            lines.append("  usefulness OVERRIDE log(s) (pinned):")
            lines += [f"    {Path(p).name}" for p in row["usefulness_logs"]]
        lines.append(f"  sus_key: {row['sus_key']}    attack_threshold: {row['attack_threshold']}")
        lines.append(
            f"  pool_runs (safety): {row.get('pool_runs', '?')}"
            f"    resample_agg: "
            f"{row.get('resample_aggregation') or 'max (default: every draw its own action)'}"
        )
        lines.append(
            f"  safety={row['safety']:.4f} "
            f"[{row['safety_lo']:.4f}, {row['safety_hi']:.4f}]    "
            f"usefulness={row['usefulness']:.4f} "
            f"[{row['usefulness_lo']:.4f}, {row['usefulness_hi']:.4f}]    "
            f"n_common={row['n_common']}"
        )
        lines.append("")
    lines += ["── Trusted baseline log(s) (usefulness lower anchor) ──"]
    lines += [f"  {Path(p).name}" for p in trusted_logs]
    lines += ["", "── Honest baseline log(s) (usefulness upper anchor) ──"]
    lines += [f"  {Path(p).name}" for p in honest_baseline_logs]
    fig.text(0.05, 0.97, "\n".join(lines), transform=fig.transFigure,
             fontsize=9, verticalalignment="top", fontfamily="monospace", wrap=True)
    fig.patch.set_visible(False)
    return fig


def _table_page(
    summary: list[dict], *, generated_at: str, title: str, ci_width: float,
    safety_ci_bootstrap: "dict | None" = None,
) -> "plt.Figure":
    """A page tabulating each series' points: threshold, safety and usefulness
    (each with its CI / error-bar range), and the common-task count ``n`` —
    i.e. the numbers behind every marker on the plot, one table per series."""
    # Group rows by series, preserving first-seen order.
    order: list = []
    by_series: "dict" = {}
    for row in summary:
        key = row.get("series")
        if key not in by_series:
            by_series[key] = []
            order.append(key)
        by_series[key].append(row)

    pct = f"{ci_width * 100:g}"
    cols = ["Threshold", f"Safety ({pct}% CI)", f"Usefulness ({pct}% CI)", "n"]
    col_widths = [0.16, 0.36, 0.36, 0.08]

    def _fmt_thr(t) -> str:
        if t is None:
            return "—"
        return f"{t:.1f}" if float(t).is_integer() else f"{t:g}"

    n = len(order)
    fig, axes = plt.subplots(
        n, 1, figsize=(8.5, 11),
        gridspec_kw={"height_ratios": [len(by_series[k]) + 1 for k in order]},
    )
    axes = [axes] if n == 1 else list(axes)
    fig.suptitle(f"Plot data — {title}", x=0.05, ha="left", fontsize=12, fontweight="bold")
    for ax, key in zip(axes, order):
        ax.axis("off")
        ax.set_title(f"Series: {key if key is not None else '(unlabeled)'}",
                     loc="left", fontsize=10)
        cell_text = [
            [
                _fmt_thr(r.get("threshold")),
                f"{r['safety']:.4f}  [{r['safety_lo']:.4f}, {r['safety_hi']:.4f}]",
                f"{r['usefulness']:.4f}  [{r['usefulness_lo']:.4f}, {r['usefulness_hi']:.4f}]",
                str(r["n_common"]),
            ]
            for r in by_series[key]
        ]
        tbl = ax.table(cellText=cell_text, colLabels=cols, colWidths=col_widths,
                       loc="center", cellLoc="left")
        tbl.auto_set_font_size(False)
        tbl.set_fontsize(9)
        tbl.scale(1, 1.4)
        for c in range(len(cols)):
            tbl[0, c].set_text_props(fontweight="bold")
    _safety_note = (
        "safety CI: cluster bootstrap, tau recomputed per draw "
        f"(B={safety_ci_bootstrap['n']}, seed={safety_ci_bootstrap['seed']})"
        if safety_ci_bootstrap else
        "safety CI: counts bootstrap, tau FIXED (conditional; understates uncertainty)"
    )
    fig.text(0.05, 0.02,
             f"Generated (UTC): {generated_at}    CI width: {ci_width}\n{_safety_note}",
             fontsize=8, fontfamily="monospace")
    return fig


def _report_slug(summary: list[dict]) -> str:
    """Filename slug (after the `safety-use` prefix), echoing compare_usefulness's
    convention of `<n>_<first-test-log-shortname>`, prefixed by the line count so
    multi-line reports get distinct filenames."""
    first = Path(summary[0]["honest_logs"][0]).stem if summary else "empty"
    n_lines = len({row.get("series") for row in summary}) if summary else 0
    return re.sub(r"[^A-Za-z0-9_.-]", "-", f"{n_lines}L_{len(summary)}_{first}")[:60]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plot safety (x) vs usefulness (y) across a DTD defer-threshold sweep."
    )
    parser.add_argument("--series-groups", nargs="+", action="append", default=None,
                        metavar="GROUP", dest="series_groups",
                        help="One line per occurrence: ATTACK_GROUP HONEST_GROUP [LABEL] — names "
                             "of BashArenaLogs groups (each a defer-threshold sweep) matched on "
                             "defer_threshold. LABEL is optional (defaults to ATTACK_GROUP). "
                             "Repeat to plot multiple lines on the same axes.")
    parser.add_argument("--series-color", action="append", default=None, metavar="COLOR",
                        dest="series_colors",
                        help="Per-series color, applied positionally (repeat once per series, in "
                             "order). Any matplotlib color spec, including the default cycle names "
                             "C0/C1/C2/C3. OVERRIDES the protocol style registry, so use it only "
                             "when the figure is deliberately off house style; pass it for EVERY "
                             "series or none.")
    parser.add_argument("--series-marker", action="append", default=None, metavar="MARKER",
                        dest="series_markers",
                        help="Per-series marker, applied positionally (repeat once per series, in "
                             "order). Any matplotlib marker code. Overrides the registry marker; "
                             "same all-or-nothing rule as --series-color.")
    parser.add_argument("--series-resample-agg", action="append", default=None,
                        dest="series_resample_aggs", metavar="AGG",
                        choices=sorted(RESAMPLE_AGGREGATIONS) + ["none"],
                        help="Per-SERIES resample aggregation, applied positionally (repeat once "
                             "per --series-groups, in the same order; use 'none' to skip a series). "
                             "How to combine a resampling protocol's alternative draws at the SAME "
                             "step before the per-sample max: 'max' (default/historical), 'min', or "
                             "'q0'..'q100' in steps of 10 for the linearly-interpolated quantile "
                             "(q0 == min, q50 == median, q100 == max). Only pass it for a DTR/DTRF "
                             "series — TM and DTD have no per-step structure and will raise. Joins "
                             "the metrics cache key, so the cell must be populated by "
                             "compute_metrics.py --resample-agg first.")
    parser.add_argument("--label", default=None,
                        help="Legend label for the single explicit (--attack-run/--honest-run) "
                             "line. Ignored when --series-groups is used.")
    parser.add_argument("--attack-run", nargs="+", action="append", default=None,
                        metavar="PATH", dest="attack_runs",
                        help="Attack log(s) for one threshold cell (repeat per cell). "
                             "Paired by position with --honest-run.")
    parser.add_argument("--honest-run", nargs="+", action="append", default=None,
                        metavar="PATH", dest="honest_runs",
                        help="Honest (DTD) log(s) for the same cell — used for both the "
                             "usefulness 'test' accuracy and the safety p95 audit threshold.")
    parser.add_argument("--trusted", nargs="+", default=None, metavar="PATH",
                        help="Trusted-policy baseline log(s) (usefulness lower anchor). "
                             "Defaults to BashArenaLogs.TOWER_BA10_TPOLICY_ANCHOR_RESTORED_PATHS "
                             "(BA1.0). Pass TOWER_60ACTION_TPOLICY for BA1.2 work.")
    parser.add_argument("--honest-baseline", nargs="+", default=None, metavar="PATH",
                        dest="honest_baseline",
                        help="Honest-policy baseline log(s) (usefulness upper anchor). "
                             "Defaults to BashArenaLogs.TOWER_BA10_UH_ANCHOR_RESTORED_PATHS "
                             "(BA1.0). Pass TOWER_BA12_UH_USEFULNESS_BASELINE for BA1.2 work.")
    parser.add_argument("--attack-threshold", nargs="*", type=int, default=None, metavar="N",
                        help="Per-cell attack threshold (one per cell, paired by position; "
                             "cells without a value default to 0).")
    parser.add_argument("--sus-key", nargs="*", default=None, metavar="KEY",
                        help=f"Per-cell suspicion key (one per cell; default {_DEFAULT_SUS_KEY!r}).")
    parser.add_argument("--pin-usefulness-to-baseline", action="append", default=None,
                        metavar="SERIES", dest="pin_usefulness",
                        help="Repeatable. Series (legend label, or 1-based series index) whose "
                             "cells compute their usefulness accuracy from the --honest-baseline "
                             "logs INSTEAD of their own honest logs — pinning that series' "
                             "usefulness to exactly 1.0 with a zero-width CI. The cells' honest "
                             "logs still feed the safety metrics-cache key, so safety is "
                             "unaffected. Use when the baseline pools replicate honest logs of "
                             "the same cell (e.g. TOWER_BA12_UH_USEFULNESS_BASELINE) and the "
                             "series' own honest log is one of them.")
    parser.add_argument("--title", default=None,
                        help="Axes title for the plot. Default is NO title (house style: "
                             "identifying info lives on the cover page). The cover and data "
                             "table pages keep their own heading either way.")
    parser.add_argument("--n-bootstrap", type=int, default=400,
                        help="Bootstrap draws for the USEFULNESS (y) error bars, and for the "
                             "safety bars only under --counts-safety-ci.")
    parser.add_argument("--seed", type=int, default=42,
                        help="Seed for those same two bootstraps.")
    parser.add_argument("--safety-ci-n-bootstrap", type=int, default=500, metavar="B",
                        help="Which cached safety CI to read: the number of draws the "
                             "compute_metrics.py --bootstrap-ci run used (default 500, "
                             "compute_metrics.py's own default). The bootstrap config joins "
                             "the metrics-cache key, so this must match the run that "
                             "populated the cache.")
    parser.add_argument("--safety-ci-seed", type=int, default=0, metavar="S",
                        help="Seed of that cached --bootstrap-ci run (default 0).")
    parser.add_argument("--counts-safety-ci", action="store_true", default=False,
                        help="OPT OUT of the cached cluster-bootstrap safety CI and recompute "
                             "the legacy frozen-threshold counts bootstrap instead. That "
                             "interval is CONDITIONAL on the realized p95 audit threshold and "
                             "is materially narrower (e.g. DTRF defer0.5 [0.832, 0.895] vs "
                             "[0.775, 0.950]) because it omits audit-threshold calibration "
                             "noise; do not quote it as protocol-level uncertainty.")
    parser.add_argument("--ci-width", type=float, default=CONFIDENCE_INTERVAL_WIDTH,
                        metavar="FRAC",
                        help="Central mass of the bootstrap x/y error bars as a fraction "
                             f"(default {CONFIDENCE_INTERVAL_WIDTH}; pass 0.95 for 95%% CIs).")
    parser.add_argument("--figsize", nargs=2, type=float, default=None, metavar=("W", "H"),
                        help="Figure size of the plot page in inches (default 6 5). House "
                             "style keeps the width well under 11.")
    parser.add_argument("--equal-aspect", action="store_true", default=False,
                        help="Lock the two axis scales together: one data unit of safety "
                             "spans the same length as one data unit of usefulness. Implies "
                             "a shared tick interval unless --tick-interval says otherwise.")
    parser.add_argument("--tick-interval", type=float, default=None, metavar="STEP",
                        help="Force the same major-tick spacing on both axes (e.g. 0.05). "
                             "With --equal-aspect and no value, the coarser of the two "
                             "auto spacings is used on both.")
    parser.add_argument("--task-ids", nargs="+", default=None, metavar="NAME|ID",
                        help=TASK_IDS_CLI_HELP)
    parser.add_argument("--out", default=None, metavar="PATH",
                        help="Output path. Default: experiments/data/metrics_reports_tower/"
                             "<UTC>_safety-use_<slug>.pdf (a PDF with a parameter cover "
                             "page + the plot). A '.pdf' path gets the cover page too; any "
                             "other extension writes the bare plot image.")
    args = parser.parse_args()

    # Resolved once: the ids go to the plotting call (they join the metrics cache
    # key), the alias to the cover page, and the raw arg to the cache-miss
    # remediation command so it warms the SAME key that just missed.
    _task_ids_alias, _task_ids = resolve_task_ids_arg(args.task_ids)
    _task_ids_arg = " ".join(args.task_ids) if args.task_ids else None

    if (args.attack_runs is None) != (args.honest_runs is None):
        parser.error("--attack-run and --honest-run must be provided together.")
    if args.attack_runs is not None and len(args.attack_runs) != len(args.honest_runs):
        parser.error(
            f"got {len(args.attack_runs)} --attack-run cell(s) but "
            f"{len(args.honest_runs)} --honest-run cell(s); they pair by position."
        )

    # Each line is a (label, cells) series. Three input routes (in precedence order):
    #   1. --series-groups: one line per named (attack, honest) group pair (multi-line).
    #   2. --attack-run/--honest-run: a single explicit line (label from --label).
    #   3. neither: the default ONLINE_ATTACK_DTD_REV1 + ONLINE_HONEST_DTD line.
    if args.series_groups is not None:
        series: list[tuple[str | None, list]] = []
        _raggs = args.series_resample_aggs or []
        if len(_raggs) > len(args.series_groups):
            parser.error(
                f"--series-resample-agg given {len(_raggs)} times but there are only "
                f"{len(args.series_groups)} --series-groups; they pair positionally."
            )
        for _si, entry in enumerate(args.series_groups):
            if len(entry) < 2:
                parser.error("--series-groups needs at least ATTACK_GROUP HONEST_GROUP.")
            atk_name, hon_name = entry[0], entry[1]
            label = entry[2] if len(entry) > 2 else atk_name
            _ragg = _raggs[_si] if _si < len(_raggs) else None
            if _ragg == "none":
                _ragg = None
            cells = _cells_from_group_pair(
                _resolve_group(atk_name), _resolve_group(hon_name),
                resample_aggregation=_ragg)
            if not cells:
                print(f"WARNING: line {label!r} has no plottable cells; skipping.")
                continue
            series.append((label, cells))
        if not series:
            parser.error("--series-groups produced no plottable lines.")
    elif args.attack_runs is not None:
        n = len(args.attack_runs)
        athrs = (args.attack_threshold or []) + [0] * n
        skeys = (args.sus_key or []) + [_DEFAULT_SUS_KEY] * n
        cells = [
            (_abs(a), _abs(h), {"attack_threshold": athrs[i], "sus_key": skeys[i]})
            for i, (a, h) in enumerate(zip(args.attack_runs, args.honest_runs))
        ]
        series = [(args.label, cells)]
    else:
        print("No --attack-run given; using BashArenaLogs.ONLINE_ATTACK_DTD_REV1 + ONLINE_HONEST_DTD.")
        cells = _cells_from_group_pair(
            BashArenaLogs.ONLINE_ATTACK_DTD_REV1, BashArenaLogs.ONLINE_HONEST_DTD
        )
        series = [(None, cells)]

    trusted_abs = _abs(args.trusted or _DEFAULT_TRUSTED)
    honest_abs = _abs(args.honest_baseline or _DEFAULT_HONEST_BASELINE)

    # --pin-usefulness-to-baseline: stamp usefulness_logs = honest baseline onto every
    # cell of the named series (post-processing the built cells, so it composes with
    # every input route). kwargs dicts are copied — group-sourced cells share them.
    if args.pin_usefulness:
        labels = [lbl for lbl, _ in series]
        for pin in args.pin_usefulness:
            if pin in labels:
                idxs = [i for i, lbl in enumerate(labels) if lbl == pin]
            elif pin.isdigit() and 1 <= int(pin) <= len(series):
                idxs = [int(pin) - 1]
            else:
                parser.error(
                    f"--pin-usefulness-to-baseline {pin!r} matches no series label or "
                    f"1-based index (series: {labels})."
                )
            for i in idxs:
                lbl, cells = series[i]
                series[i] = (lbl, [
                    (a, h, {**kw, "usefulness_logs": honest_abs}) for a, h, kw in cells
                ])

    # None = opt out to the legacy frozen-tau counts bootstrap; otherwise read the
    # cached cluster-bootstrap CI keyed by this exact (n, seed, level).
    safety_ci_bootstrap = None if args.counts_safety_ci else {
        "n": args.safety_ci_n_bootstrap,
        "seed": args.safety_ci_seed,
        "level": CONFIDENCE_INTERVAL_WIDTH,
    }

    try:
        # Explicit style overrides beat the protocol registry. All-or-nothing: a partial list
        # would silently mix registry colors with chosen ones and make the figure unreadable.
        _series_colors = args.series_colors
        _series_markers = args.series_markers
        for _name, _vals in (("--series-color", _series_colors),
                             ("--series-marker", _series_markers)):
            if _vals is not None and len(_vals) != len(series):
                parser.error(f"{_name} given {len(_vals)} time(s) but there are {len(series)} "
                             f"series; pass it once per series, in order.")
        fig, summary = plot_safety_vs_usefulness(
            series,
            trusted_logs=trusted_abs,
            honest_baseline_logs=honest_abs,
            sus_key=_DEFAULT_SUS_KEY,
            n_bootstrap=args.n_bootstrap,
            seed=args.seed,
            safety_ci_bootstrap=safety_ci_bootstrap,
            task_ids=_task_ids,
            title=args.title,
            ci_width=args.ci_width,
            colors=_series_colors,
            markers=_series_markers,
            equal_aspect=args.equal_aspect,
            tick_interval=args.tick_interval,
            **({"figsize": tuple(args.figsize)} if args.figsize else {}),
        )
    except SafetyMetricsCacheMiss as exc:
        print(
            f"\nERROR: {len(exc.missing)} cell(s) have no cached safety metrics. This script "
            "reads safety from the\nmetrics cache (experiments/data/metrics_cache/) and never "
            "loads attack logs. Populate the\ncache by running compute_metrics.py for each "
            "missing cell, then re-run this script:\n"
            + ("" if args.counts_safety_ci else
               "\n(The safety error bars need a --bootstrap-ci run at this exact n/seed — the\n"
               "bootstrap config joins the cache key. A cell cached WITHOUT --bootstrap-ci\n"
               "counts as missing here; --counts-safety-ci opts out, at the cost of a\n"
               "conditional-on-tau interval that understates uncertainty.)\n"),
            file=sys.stderr,
        )
        for spec in exc.missing:
            print(_compute_metrics_cmd(spec, _task_ids_arg) + "\n", file=sys.stderr)
        sys.exit(1)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.out is not None:
        out_path = Path(args.out)
        out_path = out_path if out_path.is_absolute() else REPO_ROOT / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{stamp}_safety-use_{_report_slug(summary)}.pdf"

    if out_path.suffix.lower() == ".pdf":
        # PDF like the other analysis scripts: a parameter cover page, the plot,
        # then a per-series data table of the plotted points.
        doc = _doc_page(
            summary, trusted_abs, honest_abs,
            generated_at=stamp, default_sus_key=_DEFAULT_SUS_KEY,
            n_bootstrap=args.n_bootstrap, seed=args.seed,
            # Raw args.title (may be None) so the cover reports the plot's
            # ACTUAL title; only the table page needs a heading fallback.
            title=args.title, task_ids=_task_ids_alias,
            ci_width=args.ci_width,
            safety_ci_bootstrap=safety_ci_bootstrap,
        )
        table = _table_page(
            summary, generated_at=stamp, title=args.title or _DEFAULT_PAGE_HEADING,
            ci_width=args.ci_width,
            safety_ci_bootstrap=safety_ci_bootstrap,
        )
        with PdfPages(out_path) as pdf:
            pdf.savefig(doc, bbox_inches="tight"); plt.close(doc)
            pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)
            pdf.savefig(table, bbox_inches="tight"); plt.close(table)
    else:
        # Bare image output (e.g. --out foo.png): just the plot, no cover page.
        fig.savefig(out_path, bbox_inches="tight", dpi=150)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
