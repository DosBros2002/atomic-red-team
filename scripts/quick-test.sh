#!/usr/bin/env bash

# Quick test to verify the filtering works
cd "$(dirname "${BASH_SOURCE[0]}")"
ATOMICS_PATH="../atomics"

echo "=== Quick Linux Technique Filter Test ==="

# Test the filtering logic
all_techniques=($(grep -E "^\s*T[0-9]{4}(\.[0-9]{3})?:" "$ATOMICS_PATH/Indexes/linux-index.yaml" | sed 's/^\s*//' | sed 's/:.*$//' | sort -u | head -20))
LINUX_TECHNIQUES=()

echo "Testing first 20 techniques from index..."
for technique in "${all_techniques[@]}"; do
    yaml_file="$ATOMICS_PATH/$technique/$technique.yaml"
    if [[ -f "$yaml_file" ]]; then
        if grep -q -i "linux" "$yaml_file" 2>/dev/null; then
            LINUX_TECHNIQUES+=("$technique")
            echo "✅ $technique - Has Linux tests"
        else
            echo "⚠️  $technique - Has YAML but no Linux tests"
        fi
    else
        echo "❌ $technique - No YAML file"
    fi
done

echo ""
echo "Summary: Found ${#LINUX_TECHNIQUES[@]} executable Linux techniques out of ${#all_techniques[@]} checked"
echo "Executable techniques: ${LINUX_TECHNIQUES[*]}"
