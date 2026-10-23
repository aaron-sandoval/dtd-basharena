"""Classify every 'Other'-terminated sample as step-limit exhaustion vs the agent
stopping on its own (an empty reply, no tool call), for the claim-10 PDF cells."""
import sys, json, collections, argparse
from pathlib import Path
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from inspect_ai.log import read_eval_log_sample
from tu_bb2.postprocessing import get_log_extract

def is_monitor(m):
    md = getattr(m, "metadata", None) or {}
    return bool(md.get("is_monitor_result") or md.get("monitor_result") or md.get("monitor_name"))

def classify(lf):
    ext = get_log_extract(lf)
    others = [s for s in ext["samples"] if s["termination_reason"] == "Other"]
    out = collections.Counter(); recs = []
    for s in others:
        smp = read_eval_log_sample(lf, id=s["raw_id"], epoch=s["epoch"])
        agent_msgs = [m for m in smp.messages
                      if getattr(m, "role", None) == "assistant" and not is_monitor(m)]
        last = agent_msgs[-1] if agent_msgs else None
        has_tc = bool(getattr(last, "tool_calls", None)) if last is not None else False
        n_exec = sum(1 for m in smp.messages if (getattr(m, "metadata", None) or {}).get("dtr_metadata")
                     or (getattr(m, "metadata", None) or {}).get("decision"))
        warn = any((getattr(m, "metadata", None) or {}).get("_step_limit_warning") for m in smp.messages)
        kind = "step-limit (cut mid-work)" if has_tc else "agent stopped (no tool call)"
        out[kind] += 1
        recs.append(dict(id=s["raw_id"], kind=kind, n_agent_msgs=len(agent_msgs),
                         n_exec_marked=n_exec, step_warning=warn))
    return len(ext["samples"]), out, recs

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("log"); ap.add_argument("tag")
    a = ap.parse_args()
    n, out, recs = classify(str(REPO / a.log))
    res = dict(tag=a.tag, log=Path(a.log).name, n_samples=n, other=dict(out), records=recs)
    p = REPO / "experiments" / "data" / "eval_limit_stats" / "other_class" / f"{a.tag}.json"
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(res))
    tot = sum(out.values())
    print(f"{a.tag:<28} N={n:<4} Other={tot:<4} " + "  ".join(f"{k}={v} ({v/n:.1%})" for k, v in out.most_common()))
