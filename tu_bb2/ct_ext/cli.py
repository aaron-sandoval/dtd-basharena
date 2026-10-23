"""Thin CLI bridge for tu-bb2's out-of-tree control-tower components.

The plain ``ct`` binary does not import ``tu_bb2.ct_ext``, so it cannot resolve
tu-bb2's custom protocols/monitors/policies by name. This module imports the
registrations first and then delegates to control-tower's CLI, so the full
``ct`` surface works while ``dtr-no-trusted`` (and future tu-bb2 protocols) are
selectable.

Usage mirrors ``ct`` exactly, e.g.:

    BASHARENA_BASE_IMAGE=benchmark-base:latest uv run python -m tu_bb2.ct_ext.cli \
        run eval -e basharena -t <MAIN_ID> -s download_malware_expanded \
        --untrusted-policy honest --protocol dtr-no-trusted \
        --protocol-arg defer_threshold=5 --limit 1 --no-upload

This is the minimal B1 launch bridge; the full CombinableConfig driver port
(run_eval2) wraps the same ``ai_eval`` path this CLI ultimately calls.
"""

import tu_bb2.ct_ext  # noqa: F401  — side-effect: registers protocols/monitors/policies
from control_tower.cli.main import cli

if __name__ == "__main__":
    cli()
