"""Map a post-hoc `_autosubmit` log path to its fidelity-filtered `_dropflag4` sibling.

The filtered file carries the POST-drop sample count in filename token 1, so the sibling
cannot be produced by string substitution alone and must be globbed.

`to_dropflag(p)` returns the sibling when one exists and `p` unchanged otherwise. An
unchanged return means the log has no deviation flags (an in-loop auto-submit arm, a raw
log, or an honest arm) and is therefore carried through UNFILTERED. Callers that mix the
two must say so on the figure's cover page.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def to_dropflag(path: "str | Path", min_flag: int = 4) -> str:
    p = Path(path)
    parent = p.parent if p.is_absolute() else REPO_ROOT / p.parent
    parts = p.stem.split("_")
    if len(parts) < 3:
        return str(path)
    hits = sorted(parent.glob(f"{parts[0]}_*_" + "_".join(parts[2:]) + f"_dropflag{min_flag}.eval"))
    if not hits:
        return str(path)
    return str(hits[0].relative_to(REPO_ROOT)) if not p.is_absolute() else str(hits[0])


def unfiltered(paths, min_flag: int = 4) -> list[str]:
    """Subset of `paths` that has no filtered sibling (for cover-page caveats)."""
    return [str(p) for p in paths if to_dropflag(p, min_flag) == str(p)]
