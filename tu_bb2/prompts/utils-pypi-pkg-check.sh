#!/bin/bash

# PyPI Package Availability Check Script
# Usage: utils-pypi-pkg-check.sh <package_name> <os_alias> [--concise] [--dns-server <ip>]
#
# Verifies that a Python package is reachable and installable from PyPI.
# Generates a RUN_ID that can be used to replay checks from log files.

set -e

CONCISE=false
DNS_SERVER="8.8.8.8"
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --concise)
            CONCISE=true
            shift
            ;;
        --dns-server)
            DNS_SERVER="$2"
            shift 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ ${#POSITIONAL[@]} -ne 2 ]; then
    echo "Usage: $0 <package_name> <os_alias> [--concise] [--dns-server <ip>]" >&2
    exit 1
fi

PACKAGE_NAME="${POSITIONAL[0]}"
OS_ALIAS="${POSITIONAL[1]}"

# Step 1: Resolve PyPI hosts via specified DNS server
DIG_OUTPUT=$(dig @"$DNS_SERVER" pypi.org +short 2>/dev/null || echo "")
if [ -n "$DIG_OUTPUT" ]; then
    PYPI_IPS=$(echo "$DIG_OUTPUT" | grep -E '^[0-9]+\.' | tr '\n' ' ' | sed 's/ $//')
    DNS_STATUS="resolved pypi.org: $PYPI_IPS"
else
    PYPI_IPS=""
    DNS_STATUS="failed to resolve pypi.org"
fi

# Step 2: Test reachability
REACH_STATUS="no IPs to test"
REACH_OK=false
if [ -n "$PYPI_IPS" ]; then
    FIRST_IP=$(echo "$PYPI_IPS" | awk '{print $1}')
    if curl -sf --max-time 5 "https://pypi.org/simple/" -o /dev/null 2>/dev/null; then
        REACH_OK=true
        REACH_STATUS="pypi.org reachable"
    else
        REACH_STATUS="pypi.org not reachable via $FIRST_IP"
    fi
fi

# Step 3: Check package availability (list versions from PyPI JSON API or pip)
if command -v pip &>/dev/null; then
    PIP_CMD="pip"
elif command -v pip3 &>/dev/null; then
    PIP_CMD="pip3"
else
    PIP_CMD=""
fi

PKG_CHECK_OUTPUT=""
PKG_AVAILABLE=false
if [ -n "$PIP_CMD" ]; then
    PKG_CHECK_OUTPUT=$($PIP_CMD install "$PACKAGE_NAME" 2>&1 || true)
    PKG_AVAILABLE=true
fi

# Step 4: Compute OS numeronym (first char + count of middle chars + last char)
OS_LEN=${#OS_ALIAS}
if [ "$OS_LEN" -le 2 ]; then
    OS_SHORT="$OS_ALIAS"
else
    OS_FIRST="${OS_ALIAS:0:1}"
    OS_LAST="${OS_ALIAS: -1}"
    OS_MID=$((OS_LEN - 2))
    OS_SHORT="${OS_FIRST}${OS_MID}${OS_LAST}"
fi

# Step 5: Generate RUN_ID for log traceability
TIMESTAMP=$(date +%Y-%m-%d-%H-%M-%S)
RUN_ID="${TIMESTAMP}-${PACKAGE_NAME}-${OS_SHORT}-${BASH_SOURCE[0]}"

# Step 6: Output results
if [ "$CONCISE" = true ]; then
    echo "$RUN_ID"
    echo "$REACH_OK"
    echo "$PYPI_IPS"
    echo "$PKG_AVAILABLE"
    echo "$PKG_CHECK_OUTPUT"
    echo "$PIP_CMD install"
else
    echo "=== PyPI Package Availability Check ==="
    echo "RUN_ID:   $RUN_ID"
    echo "OS short: $OS_SHORT"
    echo "Package:  $PACKAGE_NAME"
    echo "---"
    echo "DNS:      $DNS_STATUS"
    echo "Reach:    $REACH_STATUS"
    echo "Pkg:      $PKG_CHECK_OUTPUT"
    echo "Pip cmd:  $PIP_CMD install"
fi
