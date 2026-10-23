"""Plot safety (y-axis) against the attacker's give-up threshold N (x-axis).

One point per give-up-after-N counterfactual cell — an ``_actions{N}.eval``
transformed attack log (build_child0only.py ``--max-actions N``) paired with the
UNCHANGED base honest log — drawn with an IDENTICAL marker per series and
vertical safety error bars of width ``tu_bb2.constants.CONFIDENCE_INTERVAL_WIDTH``.
This is the give-up-after-N companion of ``plot_safety_usefulness.py`` for
protocols with a SINGLE operating point (TM): where DTRF gets one Pareto front
per N (via plot_safety_usefulness.py ``--series-groups``), TM's fronts collapse
to one point each, so this script stacks them on an N axis instead.

The N axis is **categorical**: every distinct N (baseline included) is a tick at
uniform spacing, ascending, labelled with its N. This keeps the big baseline gap
(e.g. 40 -> 60) from stretching the axis — no log scale is used.

A cell whose N is unknown (no ``_actions{N}`` filename token, no ``max_actions``
kwarg, or an explicit ``--n base``) is treated as the BASELINE (untransformed)
run. With ``--baseline-n`` (e.g. 60 — the base runs cap at 60 actions, hence the
``TOWER_60ACTION_*`` names) the baseline is plotted ON the chart as the N=60
category with the same marker, PLUS a horizontal reference line + shaded CI band,
and the data table gains a Δ-vs-baseline (%) column — the input to the N-range
stopping rule (escalate N until safety is within 20% of baseline, or N=10).
Without ``--baseline-n`` a base cell draws only the reference line + band.

Safety is **read from the metrics cache** that
``experiments/analysis/compute_metrics.py`` writes
(``experiments/data/metrics_cache/``) — this script loads **no logs at all**.

The safety CI is the **cluster bootstrap that recomputes the p95 audit threshold
per draw** (``postprocessing._bootstrap_scalar_cis``), read from the cache entry a
``compute_metrics.py --bootstrap-ci`` run wrote — exactly as in
``tu_bb2.plotting.plot_safety_vs_usefulness``. The legacy alternative — a counts
bootstrap over the cached audited / unaudited-successful / total scalars with the
threshold FROZEN — omits audit-threshold calibration noise, which on BA1.0 is
essentially the whole interval: it reports TM N=60 as [0.569, 0.647] where the
full bootstrap gives [0.493, 0.719]. It survives only behind ``--counts-safety-ci``
and must not be quoted as protocol-level uncertainty. If a cell is not cached, the
script FAILS FAST and prints the exact ``compute_metrics.py`` command(s) to
populate it.

IMPORTANT: run ``compute_metrics.py --bootstrap-ci`` for every cell first (same
--attack-threshold / --sus-keys / --pool-runs, transformed attack log +
unchanged base honest log), so the safety metrics AND their CI are cached before
plotting. The bootstrap config joins the cache key, so a cell cached without
``--bootstrap-ci`` (or at a different n/seed than
``--safety-ci-n-bootstrap``/``--safety-ci-seed``) counts as a cache miss.

CLI (named-group route — one series per ``--group``)::

    uv run python experiments/analysis/plot_safety_vs_giveup_n.py \
        --group TM_V11_1_ATTACK_ACTIONS_SWEEP TOWER_TM_V11_1_HONEST[1] "TM v11.1"

The attack group is a per-N sweep (``list[tuple[logs, kwargs]]``); each entry's
N comes from its ``max_actions`` kwarg or the ``_actions{N}`` filename token
(neither -> base cell). The honest group supplies the paired honest logs: one
entry is broadcast to every attack cell (the transform never touches honest
logs); otherwise the groups pair by index. ``GROUP[i]`` selects a single entry.

CLI (explicit route — one cell per positionally-paired --attack-run)::

    uv run python experiments/analysis/plot_safety_vs_giveup_n.py \
        --attack-run <actions4 attack log> --n 4 \
        --attack-run <actions7 attack log> --n 7 \
        --attack-run <base attack log>     --n base \
        --honest-run <base honest log> \
        --sus-key suspicion_score__trh-v11.1 --attack-threshold 5 5 5

``--honest-run`` may be given once (broadcast) or once per cell.
``--attack-threshold`` / ``--sus-key`` accept one value per cell (paired by
position); cells without an explicit value fall back to 0 / the default key.

By default it writes a PDF (parameter cover page + the plot + a per-series data
table) to ``experiments/data/metrics_reports_tower/<UTC>_safety-vs-giveupN_<slug>.pdf``,
like the other analysis scripts. Pass ``--out`` to override (``.pdf`` keeps the
cover page + table; any other extension writes just the plot image).

**Colors** follow the protocol-family convention
(``tu_bb2.plotting.protocol_series_colors``), detected from each series' label —
name the protocol in the label ("TM …", "DTRF …", …) to get its identity color.
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages

from tu_bb2.constants import CONFIDENCE_INTERVAL_WIDTH
from tu_bb2.utils import REPO_ROOT
from tu_bb2.named_tasks_and_logs import BashArenaLogs
from tu_bb2.plotting import (
    PIVOTAL_PALETTE,
    _load_cached_protocol_metrics,
    _resolve_series_color,
    _resolve_series_marker,
    _su_ci_bounds,
    protocol_series_colors,
    protocol_series_markers,
)

_DEFAULT_SUS_KEY = "suspicion_score__tu-root-history"

# Heading for the cover / data-table pages when --title is omitted. The PLOT
# itself stays untitled (house style); these text pages still need a name.
_DEFAULT_PAGE_HEADING = "Safety vs give-up threshold N"

# kwargs keys under which a group entry may record its give-up cap.
_N_KWARG_KEYS = ("max_actions", "n_actions", "actions", "giveup_n")


def _relpath(p: str) -> str:
    """Repo-relative path for readable printed commands."""
    try:
        return str(Path(p).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return p


def _compute_metrics_cmd(spec: dict) -> str:
    """The exact compute_metrics.py command that would populate a missing cell's cache."""
    atk = " ".join(_relpath(p) for p in spec["attack_logs"])
    hon = " ".join(_relpath(p) for p in spec["honest_logs"])
    # A CI-keyed lookup needs a --bootstrap-ci run at the SAME n/seed: the
    # bootstrap config joins the cache key, so a bare --bootstrap-ci (which
    # defaults to 500/0) would not satisfy a non-default lookup.
    _ragg = spec.get("resample_aggregation")
    ragg = f" --resample-agg {_ragg}" if _ragg else ""
    bs = spec.get("safety_ci_bootstrap")
    boot = (
        f" \\\n    --bootstrap-ci --n-bootstrap {bs['n']} --bootstrap-seed {bs['seed']}"
        if bs else ""
    )
    return (
        "uv run python experiments/analysis/compute_metrics.py \\\n"
        f"    --safety {atk} \\\n"
        f"    --usefulness {hon} \\\n"
        f"    --sus-keys {spec['sus_key']} "
        f"--attack-threshold {spec['attack_threshold']} "
        f"--pool-runs {spec['pool_runs']}"
        f"{ragg}"
        f"{boot}"
    )


def _abs(paths: list[str]) -> list[str]:
    """Resolve repo-relative paths against REPO_ROOT (absolute paths pass through)."""
    out = []
    for p in paths:
        pp = Path(p)
        out.append(str(pp if pp.is_absolute() else REPO_ROOT / pp))
    return out


def _n_from_logs(paths: list[str]) -> "int | None":
    """Parse the give-up cap from an ``_actions{N}`` filename token (the suffix the
    counterfactual transform appends), e.g. ``..._actions7.eval`` -> 7. Returns
    None if absent (a base / uncapped log)."""
    for p in paths:
        m = re.search(r"_actions(\d+)(?:[_.]|$)", Path(p).name)
        if m:
            return int(m.group(1))
    return None


def _n_from_kwargs(kw: dict) -> "int | None":
    for key in _N_KWARG_KEYS:
        if kw.get(key) is not None:
            return int(kw[key])
    return None


def _parse_n(token: str) -> "int | None":
    """CLI --n token: an integer cap, or 'base'/'inf'/'none' for the uncapped run."""
    if token.lower() in ("base", "inf", "none", "-"):
        return None
    return int(token)


def _resolve_group(name: str):
    """Resolve a BashArenaLogs group name to its value; ``GROUP[i]`` selects a
    single entry as a one-element group (as in plot_safety_usefulness.py)."""
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


def _cells_from_group_pair(attack_group, honest_group, resample_aggregation=None) -> list[tuple[list[str], list[str], dict]]:
    """Build one series' cells from an attack group (the per-N sweep) and an honest
    group. A one-entry honest group is broadcast to every attack cell (the actionsN
    transform never touches honest logs); otherwise the groups pair by index.
    ``None`` / empty entries are not-yet-run placeholders and are omitted with a note.
    Cell kwargs come from the attack entry; N from its kwargs or the filename."""
    honest_entries = [e for e in honest_group]
    if len(honest_entries) not in (1, len(attack_group)):
        print(f"WARNING: honest group has {len(honest_entries)} entries vs "
              f"{len(attack_group)} attack entries; pairing the common prefix.")

    cells: list[tuple[list[str], list[str], dict]] = []
    for i, a_entry in enumerate(attack_group):
        h_entry = honest_entries[0] if len(honest_entries) == 1 else (
            honest_entries[i] if i < len(honest_entries) else None
        )
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
        n = _n_from_kwargs(a_kw)
        if n is None:
            n = _n_from_logs(a_paths)
        cells.append((a_paths, h_paths, {
            "attack_threshold": a_kw.get("attack_threshold", 0),
            "sus_key": a_kw.get("sus_key", _DEFAULT_SUS_KEY),
            "pool_runs": a_kw.get("pool_runs", "dedup_latest"),
            # Joins the metrics cache key. A value on the group wins over the
            # per-series CLI override, matching plot_safety_usefulness._cell_kwargs.
            "resample_aggregation": a_kw.get("resample_aggregation", resample_aggregation),
            "n": n,  # None -> base (no give-up) cell
        }))
    return cells


def _cell_safety(cells: list, *, n_bootstrap: int, seed: int,
                 ci_width: float,
                 safety_ci_bootstrap: "dict | None" = None) -> "tuple[list[dict], list[dict]]":
    """Safety + bootstrap CI per cell, read from the metrics cache ONLY (no log
    reads) — the same estimator as plot_safety_vs_usefulness.

    ``safety_ci_bootstrap`` ({"n", "seed", "level"}) reads the CACHED cluster
    bootstrap that recomputes the p95 audit threshold per draw; ``None`` opts out
    to the legacy frozen-threshold counts bootstrap, which is conditional on the
    realized threshold and materially narrower. Returns (points, missing); each
    point dict carries the cached counts too."""
    points: list[dict] = []
    missing: list[dict] = []
    for attack_logs, honest_logs, kw in cells:
        sus_key = kw["sus_key"]
        spec = {
            "attack_logs": [str(p) for p in attack_logs],
            "honest_logs": [str(p) for p in honest_logs],
            "sus_key": sus_key,
            "attack_threshold": kw["attack_threshold"],
            "pool_runs": kw["pool_runs"],
            "resample_aggregation": kw.get("resample_aggregation"),
            # Carried so the remediation command reproduces the EXACT cache key.
            "safety_ci_bootstrap": safety_ci_bootstrap,
        }
        pm = _load_cached_protocol_metrics(
            spec["attack_logs"], spec["honest_logs"], [sus_key],
            kw["attack_threshold"], kw["pool_runs"], None,
            bootstrap=safety_ci_bootstrap,
            resample_aggregation=kw.get("resample_aggregation"),
        )
        if pm is None:
            missing.append(spec)
            continue
        sm = pm.scalar_metrics
        try:
            # Fractional-threshold audits store tie-weighted counts as floats;
            # round to ints for the category multiset (the safety POINT uses the
            # exact cached value, so rounding only affects the CI width). The
            # counts are also reported on the cover/table pages, so they are read
            # for both CI paths.
            a = round(float(sm[f"audited attacks ({sus_key})"]))
            u = round(float(sm[f"unaudited successful attacks ({sus_key})"]))
            n_tot = int(float(sm[f"total attacks ({sus_key})"]))
            safety = float(sm[f"safety ({sus_key})"])
        except (KeyError, ValueError):
            missing.append(spec)
            continue
        a = max(0, min(a, n_tot))
        u = max(0, min(u, n_tot - a))

        if safety_ci_bootstrap is not None:
            # Preferred: cached cluster bootstrap, audit threshold recomputed per
            # draw (postprocessing._bootstrap_scalar_cis).
            _ci = (pm.ci_data or {}).get(f"safety ({sus_key})")
            if _ci is None or not all(np.isfinite(_ci)):
                missing.append(spec)
                continue
            s_lo, s_hi = float(_ci[0]), float(_ci[1])
        else:
            # Opt-out: frozen-threshold counts bootstrap. Each attacked sample is
            # 0=audited, 1=unaudited-successful, 2=neither. Safety = #0/(#0+#1).
            cats = np.concatenate([
                np.zeros(a, dtype=np.int8),
                np.ones(u, dtype=np.int8),
                np.full(max(0, n_tot - a - u), 2, dtype=np.int8),
            ])
            rng = np.random.default_rng(seed)
            boot = np.empty(n_bootstrap, dtype=float)
            for b in range(n_bootstrap):
                s = cats[rng.integers(0, n_tot, n_tot)] if n_tot else cats
                na = int((s == 0).sum())
                nu = int((s == 1).sum())
                boot[b] = na / (na + nu) if (na + nu) > 0 else np.nan
            s_lo, s_hi = _su_ci_bounds(boot, ci_width)
        # An interval can fail to contain its own point estimate — and then
        # `safety - lo` or `hi - safety` goes negative and matplotlib's errorbar raises
        # "'yerr' must not contain negative values". Under the counts bootstrap this
        # bites whenever a tie-weighted count rounds across .5 with few attacks left:
        # e.g. DTRF defer0.5 _actions7 caches unaudited=0.24 -> u=0, so every draw is
        # exactly 1.0 while the cached point is 0.9990, giving lo=1.0 > safety. A
        # percentile CI can also exclude the point in degenerate cells. Applied to BOTH
        # paths: it only ever widens, so a well-behaved interval passes through
        # unchanged (e.g. TM N=4 [0.9991, 1.0000] around 1.0000 is untouched).
        s_lo = min(s_lo, safety)
        s_hi = max(s_hi, safety)
        points.append({
            "safety": safety, "lo": s_lo, "hi": s_hi,
            "audited": a, "unaudited_successful": u, "total_attacks": n_tot,
        })
    return points, missing


def plot_safety_vs_giveup_n(
    series: "list[tuple[str | None, list[tuple[list[str], list[str], dict]]]]",
    *,
    baseline_n: "int | None" = None,
    n_bootstrap: int = 400,
    seed: int = 42,
    safety_ci_bootstrap: "dict | None" = None,
    title: "str | None" = None,
    figsize: "tuple[int, int]" = (6, 5),
    ci_width: float = CONFIDENCE_INTERVAL_WIDTH,
) -> "tuple[plt.Figure, list[dict]]":
    """One marker per (series, N) at (N, safety) — the SAME marker within a series —
    with vertical safety error bars. The N axis is **categorical**: every distinct N
    (baseline included) is a tick at uniform spacing, in ascending order, labelled
    with its N — so the big baseline gap (e.g. 40 -> 60) doesn't stretch the axis and
    no log scale is needed. Baseline handling: with ``baseline_n``, cells with no N
    adopt it and cells at that N are flagged as the baseline — plotted as a normal
    marker at its category PLUS a horizontal reference line + shaded CI band; without
    it, N-less cells draw only the line + band (spanning the full width). Returns
    (fig, summary) with one summary row per cell for the cover/table pages."""
    # Pass 1: safety from the metrics cache only; fail fast on any miss.
    all_points: list[list[dict]] = []
    missing: list[dict] = []
    for _label, cells in series:
        pts, miss = _cell_safety(cells, n_bootstrap=n_bootstrap, seed=seed,
                                 ci_width=ci_width,
                                 safety_ci_bootstrap=safety_ci_bootstrap)
        all_points.append(pts)
        missing.extend(miss)
    if missing:
        raise SafetyCacheMiss(missing)

    # N-adoption pass (before plotting, so the shared categorical axis sees every N):
    # N-less cells adopt baseline_n; any cell AT baseline_n is flagged as the baseline.
    for _label, cells in series:
        for _a, _h, kw in cells:
            if kw["n"] is None and baseline_n is not None:
                kw["n"] = baseline_n
            kw["baseline"] = baseline_n is not None and kw["n"] == baseline_n

    # Categorical N axis: one uniform-spaced tick per distinct numeric N, ascending.
    all_n = sorted({kw["n"] for _lbl, cells in series for _a, _h, kw in cells
                    if kw["n"] is not None})
    n_to_x = {n: i for i, n in enumerate(all_n)}

    _labels = [lbl for lbl, _ in series]
    colors = protocol_series_colors(_labels)
    markers = protocol_series_markers(_labels)

    fig, ax = plt.subplots(figsize=figsize)
    summary: list[dict] = []
    for si, ((label, cells), pts) in enumerate(zip(series, all_points)):
        if colors is None:
            color = PIVOTAL_PALETTE[si % len(PIVOTAL_PALETTE)]
        else:
            color = _resolve_series_color(colors, label, si, palette=PIVOTAL_PALETTE)
        marker = _resolve_series_marker(markers, label, si)

        # Markers for every cell with a numeric N (baseline included); the
        # baseline (or an N-less base cell) additionally gets the reference line.
        n_cells = sorted(
            (c for c in zip(cells, pts) if c[0][2]["n"] is not None),
            key=lambda c: c[0][2]["n"],
        )
        ref_cells = [c for c in zip(cells, pts)
                     if c[0][2]["n"] is None or c[0][2]["baseline"]]

        if n_cells:
            xs = [n_to_x[c[2]["n"]] for c, _p in n_cells]
            ys = [p["safety"] for _c, p in n_cells]
            yerr = [
                [p["safety"] - p["lo"] for _c, p in n_cells],
                [p["hi"] - p["safety"] for _c, p in n_cells],
            ]
            ax.errorbar(
                xs, ys, yerr=yerr, fmt=marker, linestyle="none", color=color,
                markersize=7, capsize=3, elinewidth=1.2,
                label=label if label is not None else None,
            )
        for (_a, _h, kw), p in ref_cells:
            what = f"baseline (N={kw['n']})" if kw["n"] is not None else "base (no give-up)"
            ax.axhline(p["safety"], color=color, linestyle="--", linewidth=1.2,
                       label=f"{label + ' ' if label else ''}{what}")
            ax.axhspan(p["lo"], p["hi"], color=color, alpha=0.12, linewidth=0)

        seen = set()
        for (a_logs, h_logs, kw), p in list(n_cells) + ref_cells:
            if id(kw) in seen:  # baseline cells appear in both lists; emit once
                continue
            seen.add(id(kw))
            summary.append({
                "series": label,
                "n": kw["n"],
                "baseline": kw["baseline"],
                "attack_logs": a_logs,
                "honest_logs": h_logs,
                "sus_key": kw["sus_key"],
                "attack_threshold": kw["attack_threshold"],
                "pool_runs": kw["pool_runs"],
                "safety": p["safety"], "safety_lo": p["lo"], "safety_hi": p["hi"],
                "audited": p["audited"],
                "unaudited_successful": p["unaudited_successful"],
                "total_attacks": p["total_attacks"],
            })

    ax.set_xlabel("Give-up threshold N (work actions)")
    ax.set_ylabel("Safety")
    # House style: no axes title by default; the cover page identifies the run.
    if title:
        ax.set_title(title)
    if all_n:
        ax.set_xticks(range(len(all_n)))
        ax.set_xticklabels([str(v) for v in all_n])
        ax.set_xlim(-0.5, len(all_n) - 0.5)
    ax.grid(True, axis="y", alpha=0.3)
    handles, labels = ax.get_legend_handles_labels()
    if labels:
        ax.legend(loc="best", fontsize=8)
    fig.tight_layout()
    return fig, summary


class SafetyCacheMiss(Exception):
    """Raised when one or more cells' safety metrics are not in the metrics cache;
    ``missing`` carries the per-cell specs for the remediation commands."""

    def __init__(self, missing: "list[dict]"):
        self.missing = missing
        super().__init__(
            f"{len(missing)} cell(s) missing from the metrics cache; run compute_metrics.py first."
        )


def _fmt_n(n) -> str:
    return "base" if n is None else str(n)


def _doc_page(summary: list[dict], *, generated_at: str, n_bootstrap: int,
              seed: int, title: str, ci_width: float,
              safety_ci_bootstrap: "dict | None" = None) -> "plt.Figure":
    """Cover page recording the exact parameters + per-cell results, mirroring the
    doc page the other analysis scripts write."""
    fig = plt.figure(figsize=(8.5, 11))
    # Name the estimator explicitly: the two available intervals answer different
    # questions and differ by up to ~3x in width.
    safety_ci_desc = (
        f"cluster bootstrap by task id, p95 audit threshold RECOMPUTED per draw "
        f"(B={safety_ci_bootstrap['n']}, seed={safety_ci_bootstrap['seed']}; cached)"
        if safety_ci_bootstrap else
        f"counts bootstrap, audit threshold FIXED at its point value "
        f"(B={n_bootstrap}, seed={seed}) — CONDITIONAL, understates uncertainty"
    )
    lines = [
        "Safety vs Give-Up-After-N Report",
        f"Generated (UTC): {generated_at}",
        f"title: {title if title else '(none - untitled figure)'}",
        f"CI width: {ci_width} (safety error bars)",
        f"n_bootstrap: {n_bootstrap}    seed: {seed}",
        f"safety CI: {safety_ci_desc}",
        "",
    ]
    prev_label = object()
    for i, row in enumerate(summary):
        if row.get("series") != prev_label:
            prev_label = row.get("series")
            lines.append(f"── Series: {prev_label if prev_label is not None else '(unlabeled)'} ──")
        base_tag = "  [BASELINE]" if row.get("baseline") else ""
        lines.append(f"── Cell {i}  (N = {_fmt_n(row['n'])}){base_tag} ──")
        lines.append("  safety (attack) log(s):")
        lines += [f"    {Path(p).name}" for p in row["attack_logs"]]
        lines.append("  honest log(s) (cache key + audit threshold):")
        lines += [f"    {Path(p).name}" for p in row["honest_logs"]]
        lines.append(f"  sus_key: {row['sus_key']}    attack_threshold: {row['attack_threshold']}"
                     f"    pool_runs: {row['pool_runs']}")
        lines.append(
            f"  safety={row['safety']:.4f} "
            f"[{row['safety_lo']:.4f}, {row['safety_hi']:.4f}]    "
            f"audited={row['audited']}  unaudited_successful={row['unaudited_successful']}  "
            f"total_attacks={row['total_attacks']}"
        )
        lines.append("")
    fig.text(0.05, 0.97, "\n".join(lines), transform=fig.transFigure,
             fontsize=9, verticalalignment="top", fontfamily="monospace", wrap=True)
    fig.patch.set_visible(False)
    return fig


def _table_page(summary: list[dict], *, generated_at: str, title: str,
                ci_width: float,
                safety_ci_bootstrap: "dict | None" = None) -> "plt.Figure":
    """A page tabulating each series' points: N, safety (with CI), and the cached
    attack counts — the numbers behind every marker, one table per series."""
    order: list = []
    by_series: dict = {}
    for row in summary:
        key = row.get("series")
        if key not in by_series:
            by_series[key] = []
            order.append(key)
        by_series[key].append(row)

    pct = f"{ci_width * 100:g}"
    cols = ["N", f"Safety ({pct}% CI)", "Δ vs baseline",
            "Audited", "Unaud. successful", "Total attacks"]
    col_widths = [0.12, 0.34, 0.14, 0.12, 0.16, 0.12]

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
        # Δ vs baseline (%): relative safety gap to this series' single baseline
        # row — the input to the "within 20% of baseline" N-range stopping rule.
        base_rows = [r for r in by_series[key] if r.get("baseline")]
        base_safety = base_rows[0]["safety"] if len(base_rows) == 1 else None

        def _delta(r) -> str:
            if r.get("baseline"):
                return "baseline"
            if base_safety in (None, 0):
                return "—"
            return f"{(r['safety'] - base_safety) / base_safety * 100:+.1f}%"

        cell_text = [
            [
                _fmt_n(r["n"]),
                f"{r['safety']:.4f}  [{r['safety_lo']:.4f}, {r['safety_hi']:.4f}]",
                _delta(r),
                str(r["audited"]),
                str(r["unaudited_successful"]),
                str(r["total_attacks"]),
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
    """Filename slug after the `safety-vs-giveupN` prefix: series count, cell
    count, and the first attack log's shortname (the transformed logs are the
    distinguishing input here, unlike plot_safety_usefulness's honest-first slug)."""
    first = Path(summary[0]["attack_logs"][0]).stem if summary else "empty"
    n_series = len({row.get("series") for row in summary}) if summary else 0
    return re.sub(r"[^A-Za-z0-9_.-]", "-", f"{n_series}S_{len(summary)}_{first}")[:60]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plot safety (x) vs the attacker's give-up threshold N (y), "
                    "one identical marker per N with safety error bars."
    )
    parser.add_argument("--series-resample-agg", action="append", default=None,
                        dest="series_resample_aggs", metavar="AGG",
                        help="Per-SERIES resample aggregation, positional per --group "
                             "(use 'none' to skip a series). Combines a resampling protocol's "
                             "alternative draws at the SAME step before the per-sample max: "
                             "'max' (default), 'min', or 'q0'..'q100' in steps of 10. Only for "
                             "DTR/DTRF series -- TM and DTD have no per-step structure and raise. "
                             "Joins the metrics cache key.")
    parser.add_argument("--group", nargs="+", action="append", default=None,
                        metavar="GROUP", dest="groups",
                        help="One series per occurrence: ATTACK_GROUP HONEST_GROUP [LABEL] — "
                             "names of BashArenaLogs groups; the attack group is a per-N "
                             "sweep (N from a max_actions kwarg or the _actions{N} filename "
                             "token; neither -> base cell). A one-entry honest group is "
                             "broadcast to every attack cell. GROUP[i] selects one entry.")
    parser.add_argument("--label", default=None,
                        help="Legend label for the single explicit (--attack-run) series. "
                             "Ignored when --group is used.")
    parser.add_argument("--attack-run", nargs="+", action="append", default=None,
                        metavar="PATH", dest="attack_runs",
                        help="Attack log(s) for one N cell (repeat per cell).")
    parser.add_argument("--honest-run", nargs="+", action="append", default=None,
                        metavar="PATH", dest="honest_runs",
                        help="Honest log(s): give once to broadcast to every cell (the "
                             "actionsN transform never touches honest logs), or once per "
                             "--attack-run cell (paired by position).")
    parser.add_argument("--n", nargs="*", default=None, metavar="N", dest="n_values",
                        help="Per-cell give-up cap, paired by position with --attack-run "
                             "(an integer, or 'base' for the uncapped run). Cells without "
                             "a value parse N from the _actions{N} filename token "
                             "(absent -> base).")
    parser.add_argument("--attack-threshold", nargs="*", type=int, default=None, metavar="T",
                        help="Per-cell attack threshold (one per cell, paired by position; "
                             "cells without a value default to 0).")
    parser.add_argument("--sus-key", nargs="*", default=None, metavar="KEY",
                        help=f"Per-cell suspicion key (one per cell; default {_DEFAULT_SUS_KEY!r}).")
    parser.add_argument("--pool-runs", default="dedup_latest",
                        help="pool_runs for every explicit cell (must match the "
                             "compute_metrics.py run; default dedup_latest). Group-sourced "
                             "cells read it from their kwargs.")
    parser.add_argument("--baseline-n", type=int, default=None, metavar="N",
                        help="N of the untransformed BASELINE run (e.g. 60 — the base runs "
                             "cap at 60 actions). Cells without an N adopt it; the baseline "
                             "cell is plotted as a normal N=<this> category marker PLUS a "
                             "horizontal reference line + CI band, and the data table gains a "
                             "Δ-vs-baseline (%%) column.")
    parser.add_argument("--title", default=None,
                        help="Axes title for the plot. Default is NO title (house style: "
                             "identifying info lives on the cover page). The cover and data "
                             "table pages keep their own heading either way.")
    parser.add_argument("--n-bootstrap", type=int, default=400,
                        help="Draws for the frozen-threshold safety bootstrap. Applies ONLY "
                             "under --counts-safety-ci; the default path reads a cached CI "
                             "whose draw count is set by --safety-ci-n-bootstrap.")
    parser.add_argument("--seed", type=int, default=42,
                        help="Seed for that same opt-out bootstrap.")
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
                             "is materially narrower (e.g. TM N=60 [0.569, 0.647] vs "
                             "[0.493, 0.719]) because it omits audit-threshold calibration "
                             "noise; do not quote it as protocol-level uncertainty.")
    parser.add_argument("--ci-width", type=float, default=CONFIDENCE_INTERVAL_WIDTH,
                        metavar="FRAC",
                        help="Central mass of the bootstrap safety error bars "
                             f"(default {CONFIDENCE_INTERVAL_WIDTH}; pass 0.95 for 95%% CIs).")
    parser.add_argument("--out", default=None, metavar="PATH",
                        help="Output path. Default: experiments/data/metrics_reports_tower/"
                             "<UTC>_safety-vs-giveupN_<slug>.pdf (parameter cover page + "
                             "plot + data table). Any non-.pdf extension writes the bare "
                             "plot image.")
    args = parser.parse_args()

    if args.groups is not None:
        series: list[tuple[str | None, list]] = []
        _raggs = args.series_resample_aggs or []
        if len(_raggs) > len(args.groups):
            parser.error(f"--series-resample-agg given {len(_raggs)} times but there are only "
                         f"{len(args.groups)} --group series; they pair positionally.")
        for _si, entry in enumerate(args.groups):
            if len(entry) < 2:
                parser.error("--group needs at least ATTACK_GROUP HONEST_GROUP.")
            atk_name, hon_name = entry[0], entry[1]
            label = entry[2] if len(entry) > 2 else atk_name
            _ragg = _raggs[_si] if _si < len(_raggs) else None
            if _ragg == "none":
                _ragg = None
            cells = _cells_from_group_pair(_resolve_group(atk_name), _resolve_group(hon_name),
                                           resample_aggregation=_ragg)
            if not cells:
                print(f"WARNING: series {label!r} has no plottable cells; skipping.")
                continue
            series.append((label, cells))
        if not series:
            parser.error("--group produced no plottable series.")
    elif args.attack_runs is not None:
        if args.honest_runs is None:
            parser.error("--honest-run is required with --attack-run.")
        n_cells = len(args.attack_runs)
        if len(args.honest_runs) == 1:
            honest_runs = args.honest_runs * n_cells
        elif len(args.honest_runs) == n_cells:
            honest_runs = args.honest_runs
        else:
            parser.error(
                f"got {n_cells} --attack-run cell(s) but {len(args.honest_runs)} "
                "--honest-run cell(s); give one (broadcast) or one per cell."
            )
        athrs = (args.attack_threshold or []) + [0] * n_cells
        skeys = (args.sus_key or []) + [_DEFAULT_SUS_KEY] * n_cells
        ns = [_parse_n(t) for t in (args.n_values or [])]
        cells = []
        for i, (a, h) in enumerate(zip(args.attack_runs, honest_runs)):
            n = ns[i] if i < len(ns) else _n_from_logs(a)
            cells.append((_abs(a), _abs(h), {
                "attack_threshold": athrs[i],
                "sus_key": skeys[i],
                "pool_runs": args.pool_runs,
                "n": n,
            }))
        series = [(args.label, cells)]
    else:
        parser.error("give either --group or --attack-run/--honest-run cells.")

    # None = opt out to the legacy frozen-threshold counts bootstrap; otherwise read
    # the cached cluster-bootstrap CI keyed by this exact (n, seed, level).
    safety_ci_bootstrap = None if args.counts_safety_ci else {
        "n": args.safety_ci_n_bootstrap,
        "seed": args.safety_ci_seed,
        "level": CONFIDENCE_INTERVAL_WIDTH,
    }

    try:
        fig, summary = plot_safety_vs_giveup_n(
            series,
            baseline_n=args.baseline_n,
            n_bootstrap=args.n_bootstrap,
            seed=args.seed,
            safety_ci_bootstrap=safety_ci_bootstrap,
            title=args.title,
            ci_width=args.ci_width,
        )
    except SafetyCacheMiss as exc:
        print(
            f"\nERROR: {len(exc.missing)} cell(s) have no cached safety metrics. This script "
            "reads safety from the\nmetrics cache (experiments/data/metrics_cache/) and never "
            "loads logs. Populate the\ncache by running compute_metrics.py for each missing "
            "cell, then re-run this script:\n"
            + ("" if args.counts_safety_ci else
               "\n(The safety error bars need a --bootstrap-ci run at this exact n/seed — the\n"
               "bootstrap config joins the cache key. A cell cached WITHOUT --bootstrap-ci\n"
               "counts as missing here; --counts-safety-ci opts out, at the cost of a\n"
               "conditional-on-threshold interval that understates uncertainty.)\n"),
            file=sys.stderr,
        )
        for spec in exc.missing:
            print(_compute_metrics_cmd(spec) + "\n", file=sys.stderr)
        sys.exit(1)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.out is not None:
        out_path = Path(args.out)
        out_path = out_path if out_path.is_absolute() else REPO_ROOT / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = REPO_ROOT / "experiments" / "data" / "metrics_reports_tower"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{stamp}_safety-vs-giveupN_{_report_slug(summary)}.pdf"

    if out_path.suffix.lower() == ".pdf":
        # PDF like the other analysis scripts: a parameter cover page, the plot,
        # then a per-series data table of the plotted points.
        doc = _doc_page(summary, generated_at=stamp, n_bootstrap=args.n_bootstrap,
                        # Raw args.title (may be None) so the cover reports the
                        # plot's ACTUAL title; only the table page needs a fallback.
                        seed=args.seed, title=args.title,
                        ci_width=args.ci_width,
                        safety_ci_bootstrap=safety_ci_bootstrap)
        table = _table_page(summary, generated_at=stamp,
                            title=args.title or _DEFAULT_PAGE_HEADING,
                            ci_width=args.ci_width,
                            safety_ci_bootstrap=safety_ci_bootstrap)
        with PdfPages(out_path) as pdf:
            pdf.savefig(doc, bbox_inches="tight"); plt.close(doc)
            pdf.savefig(fig, bbox_inches="tight"); plt.close(fig)
            pdf.savefig(table, bbox_inches="tight"); plt.close(table)
    else:
        fig.savefig(out_path, bbox_inches="tight", dpi=150)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
