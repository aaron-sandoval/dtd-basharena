#!/bin/bash
# Rerun script for utils-pypi-network-troubleshooting.sh
#
# Reads the first line (the RUN_ID) from a log file produced by
# troubleshooting script using the --concise flag, extracts the
# package name, and re-runs the troubleshooting check for it.

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

# Read the first line of the log file — this is the RUN_ID
FIRST_LINE=$(head -n 1 "$LOG_FILE")

# Split the RUN_ID by "-" into an array
IFS='-' read -ra PARTS <<< "$FIRST_LINE"

TOTAL=${#PARTS[@]}

# Extract the package name
SLICE_START=7
SLICE_LEN=$((TOTAL - SLICE_START - 3))

if [ "$SLICE_LEN" -le 0 ]; then
    echo "Error: RUN_ID too short to parse (got $TOTAL parts after splitting by '-')" >&2
    exit 1
fi

PACKAGE_NAME=$(IFS='-'; echo "${PARTS[*]:$SLICE_START:$SLICE_LEN}")

echo "Rerunning: $RUN_ID"

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
exec "$SCRIPT_DIR/utils-pypi-network-troubleshooting.sh" "$PACKAGE_NAME" --concise
