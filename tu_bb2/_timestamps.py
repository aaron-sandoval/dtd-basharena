"""Local timestamp utilities (vendored from control_arena.utils._utils).

SINGLE SOURCE of the process-global cached timestamp. Every consumer (monitor
field-suffix labels, rescore log filenames, sus-score-key labels) must import
``CACHED_TIMESTAMP_STR`` from HERE — introducing a second ``timestamp_str()``
call desyncs the in-log field-suffix label from the filename/sus-key (the bug
fixed historically in control-arena commit 7a9dde8; see memory notes).
"""

import datetime
import re
from pathlib import Path


def timestamp_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")


# Computed once at module load — the one cached value all consumers share.
CACHED_TIMESTAMP_STR = timestamp_str()


def get_sus_rescore_log_name(log_path: "str | Path") -> str:
    """Rescored log filename with '_sus_' + timestamp inserted/updated before the
    extension (verbatim port of control_arena.utils._utils.get_sus_rescore_log_name)."""
    filename = Path(log_path).name
    timestamp_pattern = r"_sus_\d{8}_\d{6}\.eval$"
    # Use the cached process-global timestamp (NOT a fresh timestamp_str()) so the
    # rescore filename's timestamp matches the field-suffix / sus-key labels built
    # from CACHED_TIMESTAMP_STR (the single-source alignment this module enforces).
    new_timestamp = CACHED_TIMESTAMP_STR
    if re.search(timestamp_pattern, filename):
        return re.sub(r"_sus_\d{8}_\d{6}(\.eval)$", f"_sus_{new_timestamp}\\1", filename)
    return filename[:-5] + "_sus_" + new_timestamp + filename[-5:]
