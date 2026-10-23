"""Validate the per-action time-limit machinery on ONE arm against its cached base cell.

    uv run python experiments/analysis/limit_sensitivity/_check_time_limit_arm.py <TM|DTRF|DTD>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safety_vs_time_limit import compute_safety_vs_time_limit, verify_no_limit  # noqa: E402

T = "experiments/_logs/tower/"
ARMS = {
    # label: (attack, honest, resample_agg, cached base safety)
    "TM": (T + "2026-07-15T03-59-44_629_attack_tm-v11.1_sus_BA10-UNION_autosubmit.eval",
           [T + "2026-07-15T02-59-38_452_uh_sus_BA10-UNION.eval",
            T + "2026-07-30T08-17-38_159_uh-gapfill_sus_BA10-UNION566.eval"], None, 0.5201),
    "DTRF": (T + "2026-07-24T14-25-13_629_attack_dtr-v11.1-defer0p5-nocache_sus_BA10-UNION_autosubmit.eval",
             T + "2026-07-24T14-07-55_629_dtrf-v11.1-defer0p5-nocache_sus_BA10-UNION.eval", "q90", 0.9258),
    "DTD": (T + "2026-07-30T00-45-23_566_attack_online-dtd-v11.1-thr3p0-rem_BA10-UNION566_autosubmit.eval",
            T + "2026-07-30T00-45-41_566_online-dtd-v11.1-thr3p0-rem-honest_BA10-UNION566.eval", None, 0.8713),
}
GRID = [m * 60 for m in (5, 10, 15, 20, 30, 45, 60, 90, 120, 150, 180)] + [None]

arm = sys.argv[1]
attack, honest, ragg, cached = ARMS[arm]
res = compute_safety_vs_time_limit(
    attack_log=attack, honest_log=honest,
    sus_key="suspicion_score__tu-root-history", attack_threshold=0,
    time_limits_s=GRID, attack_dup="latest", drop_unscored=True,
    resample_aggregation=ragg,
)
print(f"[{arm}] tau={res['threshold']:.4f} frac={res['threshold_fraction']:.4f} "
      f"n_attacks={res['n_attacks_total']} resample_agg={ragg}")
for p in res["points"]:
    t = "none" if p["t"] is None else f"{p['t'] // 60:>4.0f}m"
    print(f"  T={t}  safety={p['safety']:.4f}  n={p['total_attacks']:>4}  "
          f"voided={p['n_truncated']:>4}  no_verdict={p['n_no_verdict']:>3} "
          f"(with success: {p['n_no_verdict_success']})")
verify_no_limit(res, cached)
print(f"OK: [{arm}] no-limit point reproduces the cached base safety {cached}")
