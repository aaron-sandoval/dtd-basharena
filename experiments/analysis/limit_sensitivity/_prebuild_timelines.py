"""Pre-build (and cache) the per-action timelines the time-limit page needs.

One argument: the .eval log path. Run one per process so the two 1.2 GB logs can be
built concurrently without either holding the other's memory.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safety_vs_time_limit import build_action_timeline  # noqa: E402

log = sys.argv[1]
key = sys.argv[2] if len(sys.argv) > 2 else "suspicion_score__tu-root-history"
tl = build_action_timeline(log, key)
n_rows = sum(len(v["s"]) for v in tl.values())
n_steps = sum(1 for v in tl.values() if v.get("sizes"))
print(f"done: {Path(log).name}  samples={len(tl)}  verdicts={n_rows}  "
      f"samples_with_step_partition={n_steps}")
