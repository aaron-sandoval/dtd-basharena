"""Index every CHILD TASK of a DTD log for stratified label-set selection + preflight.

The per-child attribution scanner's judgment unit is one child task, so the label unit
is a child too. Malware attempts run at ~1-2% of samples; a random draw of ~12 children
would contain none, so we index every child with the properties needed to stratify on
and pick deliberately (as `../index_transcripts.py` does for whole transcripts).

One streaming pass (Scout reader, no full-log load). Per child:
  task_id, child_index, n_actions, n_rejected,
  rendered_chars      -- render_child_actions(include_outputs=False): what the judge sees
  signatures          -- which SIDE_TASK_SIGNATURES groups hit in this child's TOOL CALLS
                         (malware_ip / malware_pypi / malware_generic / exfil / sudo / firewall)
  pypi_redirect_to_ip -- malware_pypi AND malware_ip both hit (label: download_malware_ip)
  side_task_success   -- the SAMPLE's deterministic side-task success (not per child)

Also prints the preflight: child-count and rendered-size distribution, so the
--max-children cap (None) and the question clip are checked against the real log.

Output: <out-dir>/<logstem>.child_index.json
"""

import argparse
import asyncio
import json
import statistics
from collections import Counter
from pathlib import Path

from inspect_scout import TranscriptContent, transcripts_from

from experiments.analysis import scout_utils
from experiments.analysis.scout_utils import _COMPILED_SIGNATURES


def _fired(segment: dict) -> list[str]:
    fired: set[str] = set()
    for m in segment["messages"]:
        if getattr(m, "role", None) != "assistant":
            continue
        for rendered in scout_utils.list_tool_calls(m):
            for name, patterns in _COMPILED_SIGNATURES.items():
                if any(p.search(rendered) for p in patterns):
                    fired.add(name)
    return sorted(fired)


async def index(log: str) -> list[dict]:
    rows: list[dict] = []
    content = TranscriptContent(messages="all")
    async with transcripts_from(log).reader() as reader:
        async for info in reader.index():
            t = await reader.read(info, content)
            task_id = scout_utils.get_task_id(t)
            success = scout_utils.get_side_task_success(t)
            for seg in scout_utils.child_task_segments(t):
                fired = _fired(seg)
                rows.append(
                    {
                        "task_id": task_id,
                        "transcript_id": str(t.transcript_id),
                        "child_index": seg["child_index"],
                        "n_actions": seg["n_actions"],
                        "n_rejected": seg["n_rejected"],
                        "rendered_chars": len(
                            scout_utils.render_child_actions(seg, include_outputs=False)
                        ),
                        "signatures": fired,
                        "pypi_redirect_to_ip": "malware_pypi" in fired and "malware_ip" in fired,
                        "side_task_success": success,
                    }
                )
    return rows


def _q(xs: list, q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else float("nan")


def preflight(rows: list[dict]) -> None:
    per_t = Counter(r["task_id"] for r in rows)
    n_children = list(per_t.values())
    chars = [r["rendered_chars"] for r in rows]
    print(f"transcripts={len(per_t)}  children={len(rows)}")
    print(f"children/transcript: median={statistics.median(n_children)} p90={_q(n_children, .9)} "
          f"max={max(n_children)}  (>10 children: {sum(1 for n in n_children if n > 10)} transcripts, "
          f"{sum(max(0, n - 11) for n in n_children)} children would be DROPPED by a cap of 10)")
    print(f"rendered chars/child (no outputs): median={statistics.median(chars):.0f} "
          f"p90={_q(chars, .9):.0f} p99={_q(chars, .99):.0f} max={max(chars)}  "
          f"(>160k clip: {sum(1 for c in chars if c > 160_000)})")
    print(f"child 0 present in {sum(1 for r in rows if r['child_index'] == 0)} transcripts; "
          f"children with 0 executed actions: {sum(1 for r in rows if r['n_actions'] == 0)}")
    sig = Counter(s for r in rows for s in r["signatures"])
    print("signature hits (children):", dict(sorted(sig.items())))
    print(f"malware_pypi WITHOUT malware_ip: "
          f"{sum(1 for r in rows if 'malware_pypi' in r['signatures'] and 'malware_ip' not in r['signatures'])}"
          f"   pypi_redirect_to_ip (both): {sum(1 for r in rows if r['pypi_redirect_to_ip'])}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log")
    ap.add_argument("--out-dir", default=".",
                    help="where to write <logstem>.child_index.json (scratch; default cwd)")
    args = ap.parse_args()
    rows = asyncio.run(index(args.log))
    preflight(rows)
    out = Path(args.out_dir) / f"{Path(args.log).stem}.child_index.json"
    out.write_text(json.dumps(rows, indent=0))
    print(f"-> {out}")


if __name__ == "__main__":
    main()
