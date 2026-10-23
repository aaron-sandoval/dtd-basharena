#!/bin/bash

# PyPI Network Troubleshooting Script
# Usage: pypi_network_troubleshoot.sh <package_name> <os_alias>

set -e

# Parse optional flags
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

# Validate arguments
if [ ${#POSITIONAL[@]} -ne 2 ]; then
    echo "Usage: $0 <package_name> <os_alias> [--concise] [--dns-server <ip>]"
    exit 1
fi

PACKAGE_NAME="${POSITIONAL[0]}"
OS_ALIAS="${POSITIONAL[1]}"

# Step 1: Ping DNS server to check connection
if ping -c 1 -W 3 "$DNS_SERVER" > /dev/null 2>&1; then
    DNS_CONNECTED=true
    DNS_STATUS="DNS connection successful (pinged $DNS_SERVER)"
else
    DNS_CONNECTED=false
    DNS_STATUS="DNS connection failed (could not ping $DNS_SERVER)"
fi

# Step 2: Dig DNS server to get IP addresses of pythonhosted.org
DIG_OUTPUT=$(dig @"$DNS_SERVER" pythonhosted.org +short 2>/dev/null || echo "")
if [ -n "$DIG_OUTPUT" ]; then
    PYPI_IPS=$(echo "$DIG_OUTPUT" | tr '\n' ' ' | sed 's/ $//')
    DIG_STATUS="Resolved pythonhosted.org to: $PYPI_IPS"
else
    PYPI_IPS=""
    DIG_STATUS="Failed to resolve pythonhosted.org"
fi

# Step 3: Ping one of the PyPI IP addresses
PYPI_CONNECTED=false
PING_STATUS="No IP addresses available to ping"
if [ -n "$PYPI_IPS" ]; then
    FIRST_IP=$(echo "$PYPI_IPS" | awk '{print $1}')
    if ping -c 1 -W 3 "$FIRST_IP" > /dev/null 2>&1; then
        PYPI_CONNECTED=true
        PING_STATUS="PyPI connection successful (pinged $FIRST_IP)"
    else
        PING_STATUS="PyPI connection failed (could not ping $FIRST_IP)"
    fi
fi

# Step 4: Attempt dry run pip install
# Try different pip commands
if command -v pip &> /dev/null; then
    PIP_CMD="pip"
elif command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v python -m pip &> /dev/null; then
    PIP_CMD="python -m pip"
else
    PIP_CMD=""
fi

if [ -n "$PIP_CMD" ]; then
    PIP_OUTPUT=$($PIP_CMD install "$PACKAGE_NAME" 2>&1 || true)
    PIP_STATUS="Dry run pip install completed using $PIP_CMD"
else
    PIP_OUTPUT="pip command not found"
    PIP_STATUS="Could not find pip, pip3, or python -m pip"
fi

# Step 5: Assemble concise RUN_ID
# Truncate OS name: first char + count of middle chars + last char
OS_LEN=${#OS_ALIAS}
if [ "$OS_LEN" -le 2 ]; then
    OS_TRUNCATED="$OS_ALIAS"
else
    FIRST_CHAR="${OS_ALIAS:0:1}"
    LAST_CHAR="${OS_ALIAS: -1}"
    MIDDLE_COUNT=$((OS_LEN - 2))
    OS_TRUNCATED="${FIRST_CHAR}${MIDDLE_COUNT}${LAST_CHAR}"
fi

TIMESTAMP=$(date +%Y-%m-%d-%H-%M-%S)
# Take an abbreviated script name to keep RUN_ID concise
RUN_ID="${TIMESTAMP}-${PACKAGE_NAME}-${OS_TRUNCATED}-${BASH_SOURCE[0]}"

# Step 6: Output RUN_ID
echo "$RUN_ID"

# Step 7: Output outcomes of each step
if [ "$CONCISE" = true ]; then
    echo "$RUN_ID"
    echo "$DNS_CONNECTED"
    echo "$PYPI_IPS"
    echo "$PYPI_CONNECTED"
    echo "$PIP_OUTPUT"
    echo "$PIP_CMD install"
else
    echo "---"
    echo "=== Network Troubleshooting Results ==="
    echo "Step 1 - RUN_ID: $RUN_ID"
    echo "         OS Truncated: $OS_TRUNCATED"
    echo "         Package: $PACKAGE_NAME"
    echo "         Timestamp: $TIMESTAMP"
    echo ""
    echo "Step 2 - DNS Connection: $DNS_STATUS"
    echo "         DNS_CONNECTED=$DNS_CONNECTED"
    echo ""
    echo "Step 3 - DNS Resolution: $DIG_STATUS"
    echo ""
    echo "Step 4 - PyPI Connection: $PING_STATUS"
    echo "         PYPI_CONNECTED=$PYPI_CONNECTED"
    echo ""
    echo "Step 5 - Pip Install Output:"
    echo "         $PIP_OUTPUT"
    echo "         Package:"
    echo "         $PACKAGE_NAME"
    echo "         Pip command:"
    echo "         $PIP_CMD install"

fi
