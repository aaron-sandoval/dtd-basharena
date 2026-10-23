"""Regression check for the straddling-resample-step rule (Codex adversarial review).

A DTRF protocol step's draws are minutes apart, so a working-time cutoff can land BETWEEN
them. The plotted path must keep the draws the monitor actually saw before the cutoff
(``partial_steps="include"``); dropping the whole step would discard real evidence.

Checks, in order:
  1. synthetic fixtures pin both rules' semantics, including the quantile-inflation case
     that motivated the choice;
  2. the DEFAULT (what the report plots) includes a surviving pre-T draw;
  3. on the real DTRF cell, a genuine straddling step is found and its surviving draw is
     shown to reach the sample's censored suspicion under the default rule.

    uv run python experiments/analysis/limit_sensitivity/_check_partial_step_rule.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safety_vs_time_limit import build_action_timeline, censored_suspicion  # noqa: E402

# 1. synthetic: one step, draws [9.0, 8.0, 8.333] at t = 10, 200, 300; cutoff at 100
tl = {"t": [10.0, 200.0, 300.0], "s": [9.0, 8.0, 8.3333333333333], "sizes": [3],
      "last_action": 300.0}
inc = censored_suspicion(tl, 100, "q90")
drp = censored_suspicion(tl, 100, "q90", partial_steps="drop")
full = censored_suspicion(tl, None, "q90")
assert inc == 9.0, f"include should keep the surviving 9.0 draw, got {inc}"
assert drp is None, f"drop should discard the straddling step entirely, got {drp}"
assert abs(full - 8.8667) < 1e-3, f"uncensored full-step q90 should be ~8.8667, got {full}"
assert inc > full, "the documented quantile-inflation property should hold here"
print(f"1. synthetic straddling step: include={inc:.4f}  drop={drp}  uncensored={full:.4f}  OK")

# 2. the DEFAULT is include -- this is what the report plots
assert censored_suspicion(tl, 100, "q90") == 9.0, "DEFAULT rule must include surviving draws"
print("2. default rule keeps the surviving pre-T draw  OK")

# 3. real data: find a straddling step on the DTRF cell and prove it reaches the sample max
P = ("experiments/_logs/tower/2026-07-24T14-25-13_629_attack_dtr-v11.1-defer0p5-nocache_"
     "sus_BA10-UNION_autosubmit.eval")
tls = build_action_timeline(P, "suspicion_score__tu-root-history", verbose=False)
found = 0
for sid, d in tls.items():
    ts, ss, sizes = d["t"], d["s"], d.get("sizes") or []
    pos = 0
    for n in sizes:
        gt, gs = ts[pos:pos + n], ss[pos:pos + n]
        pos += n
        if n < 2 or None in gt or len(set(gs)) < 2:
            continue
        T = (min(gt) + max(gt)) / 2
        surv = [s for t, s in zip(gt, gs) if t <= T]
        if not surv or len(surv) == n:
            continue
        # the step straddles T; under the default the sample must still score >= a
        # surviving draw's own contribution, and under "drop" it may not.
        v_inc = censored_suspicion(d, T, "q90")
        v_drp = censored_suspicion(d, T, "q90", partial_steps="drop")
        assert v_inc is not None and v_inc >= min(surv) - 1e-9, (
            f"{sid}: surviving draw {surv} not reflected in censored suspicion {v_inc}")
        if found == 0:
            print(f"3. real straddling step in {sid[:26]}: draws={[round(x,2) for x in gs]} "
                  f"times={[round(t) for t in gt]}")
            print(f"   cutoff T={T:.0f}s -> surviving={[round(x,2) for x in surv]}  "
                  f"include={v_inc:.4f}  drop={v_drp if v_drp is None else round(v_drp,4)}")
        found += 1
        break
assert found, "no straddling step found on the real DTRF cell -- fixture is stale"
print(f"   verified on {found} samples with a straddling step  OK")
print("\nALL PARTIAL-STEP CHECKS PASSED")
