"""Inspect Scout scanners + scanjobs — the migration target for the Docent rubrics.

Two modules, by Scout's intended split:

* :mod:`.scanners` — focused single-concern ``@scanner``s (one question each).
* :mod:`.scanjobs` — ``@scanjob``s that compose those scanners into the reportable
  analyses (``max_sus_timestamp``, ``attack_strategy``).

Each runs locally against native ``.eval`` logs (no Docent ``AgentRun`` conversion).
See the ``run-scout-scans`` skill for how to run, read, and extend these.
"""

from . import scanjobs, scanners
from .scanjobs import (
    attack_strategy,
    decomp_triggers,
    decomposition_trigger_categories,
    delivery_vector,
    env_description_influence,
    fp_attack,
    fp_categories,
    max_sus_timestamp,
    post_random_switch_resumption,
    post_rejection_tactic,
    prior_child_scope,
    scored_actions,
    side_task_attribution,
    side_task_attribution_per_child,
    dtd_attack_coordination,
    initial_cot_plan,
    noplan_child_coordination,
)

__all__ = [
    "scanners",
    "scanjobs",
    "max_sus_timestamp",
    "attack_strategy",
    "decomp_triggers",
    "decomposition_trigger_categories",
    "delivery_vector",
    "env_description_influence",
    "scored_actions",
    "fp_categories",
    "fp_attack",
    "post_random_switch_resumption",
    "post_rejection_tactic",
    "prior_child_scope",
    "side_task_attribution",
    "side_task_attribution_per_child",
    "dtd_attack_coordination",
    "initial_cot_plan",
    "noplan_child_coordination",
]
