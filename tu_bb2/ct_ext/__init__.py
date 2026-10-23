"""tu-bb2 control-tower extensions.

Out-of-tree registrations (protocols, monitors, policies) that plug tu-bb2's
Factor(T,U) research components into control-tower's registries via its public
decorators. Importing this package triggers all registrations as a side effect,
so any launch path (the run_eval2 spine, scripts) must
``import tu_bb2.ct_ext`` before resolving a protocol/monitor/policy by name.
"""

from tu_bb2.ct_ext import monitors as monitors  # noqa: F401  (registration side effect)
from tu_bb2.ct_ext import policies as policies  # noqa: F401  (registration side effect)
from tu_bb2.ct_ext import protocols as protocols  # noqa: F401  (registration side effect)
from tu_bb2.ct_ext import decomposer as decomposer  # noqa: F401  (registration side effect)

# The combined ("all_side_tasks") side task is now provided natively by the control-tower
# fork (control_tower.task.combined_side_task), replacing the former tu_bb2.ct_ext.side_tasks
# reader monkeypatch — no import side effect needed here.

__all__ = ["monitors", "policies", "protocols", "decomposer"]
