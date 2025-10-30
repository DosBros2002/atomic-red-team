#!/usr/bin/env bash

# Test script to diagnose issues with the main linux-runner.sh
# This helps identify what's failing when you run with sudo

set -euo pipefail

echo "=== Atomic Red Team Linux Runner Diagnostic ==="
echo "Current user: $(whoami)"
echo "EUID: $EUID"
echo "Current directory: $(pwd)"
echo "Script directory: $(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test atomics path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATOMICS_PATH="$SCRIPT_DIR/../atomics"
echo "Atomics path: $ATOMICS_PATH"

if [[ -d "$ATOMICS_PATH" ]]; then
    echo "✅ Atomics directory exists"
else
    echo "❌ Atomics directory NOT found"
    exit 1
fi

# Test Linux index
LINUX_INDEX="$ATOMICS_PATH/Indexes/linux-index.yaml"
echo "Linux index path: $LINUX_INDEX"

if [[ -f "$LINUX_INDEX" ]]; then
    echo "✅ Linux index file exists"
    TECHNIQUE_COUNT=$(grep -E "^\s*T[0-9]{4}(\.[0-9]{3})?:" "$LINUX_INDEX" | wc -l)
    echo "✅ Found $TECHNIQUE_COUNT techniques in index"
    
    # Count executable techniques
    EXECUTABLE_COUNT=0
    for technique in $(grep -E "^\s*T[0-9]{4}(\.[0-9]{3})?:" "$LINUX_INDEX" | sed 's/^\s*//' | sed 's/:.*$//' | sort -u); do
        yaml_file="$ATOMICS_PATH/$technique/$technique.yaml"
        if [[ -f "$yaml_file" ]] && grep -q "linux" "$yaml_file" 2>/dev/null; then
            ((EXECUTABLE_COUNT++))
        fi
    done
    echo "✅ Found $EXECUTABLE_COUNT executable Linux techniques"
else
    echo "❌ Linux index file NOT found"
    exit 1
fi

# Test PowerShell availability
if command -v pwsh >/dev/null 2>&1; then
    echo "✅ PowerShell 7 is available"
    pwsh --version
else
    echo "❌ PowerShell 7 not found - will need to install"
fi

# Test package manager
if command -v apt-get >/dev/null 2>&1; then
    echo "✅ apt-get available (Debian/Ubuntu)"
elif command -v yum >/dev/null 2>&1; then
    echo "✅ yum available (RHEL/CentOS)"
elif command -v dnf >/dev/null 2>&1; then
    echo "✅ dnf available (Fedora)"
else
    echo "⚠️  Unknown package manager"
fi

# Test internet connectivity
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Internet connectivity available"
else
    echo "❌ No internet connectivity - may affect dependency installation"
fi

# Test write permissions for output directory
OUTPUT_DIR="/var/tmp/art-results-test"
if mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
    echo "✅ Can create output directory: $OUTPUT_DIR"
    rmdir "$OUTPUT_DIR" 2>/dev/null || true
else
    echo "❌ Cannot create output directory: $OUTPUT_DIR"
fi

echo ""
echo "=== Diagnostic Complete ==="
echo "If all checks pass, the main script should work."
echo "Run the main script with: sudo ./linux-runner.sh"
