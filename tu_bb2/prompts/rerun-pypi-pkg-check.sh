#!/bin/bash
# Replay a previous utils-pypi-pkg-check.sh run from its log file.
#
# Reads the RUN_ID from the first line of a --concise log, extracts the
# package name from the RUN_ID, and reruns the availability check for it.

set -e

LOG_FILE="${1}"

if [ -z "$LOG_FILE" ]; then
    echo "Usage: $0 <log_file>" >&2
    exit 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: log file not found: $LOG_FILE" >&2
    exit 1
fi

# Read the RUN_ID from the first line of the log
FIRST_LINE=$(head -n 1 "$LOG_FILE")

# Split RUN_ID on "-" into parts
IFS='-' read -ra PARTS <<< "$FIRST_LINE"

TOTAL=${#PARTS[@]}

# Extract the package name segment.
# RUN_ID format: YYYY-MM-DD-HH-MM-SS-<PKG>-<OS_SHORT>-<SCRIPT_PARTS...>
# SLICE_START=7 skips the 6 timestamp fields plus the leading part of the pkg name.
# SLICE_LEN drops the last 3 parts (the script name components after the first).
SLICE_START=7
SLICE_LEN=$((TOTAL - SLICE_START - 3))

if [ "$SLICE_LEN" -le 0 ]; then
    echo "Error: RUN_ID has too few parts to parse ($TOTAL parts)" >&2
    exit 1
fi

PACKAGE_NAME=$(IFS='-'; echo "${PARTS[*]:$SLICE_START:$SLICE_LEN}")

echo "Replaying check for package: $PACKAGE_NAME"

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
exec "$SCRIPT_DIR/utils-pypi-pkg-check.sh" "$PACKAGE_NAME" "linux" --concise
