#!/usr/bin/env bash
# run-poltergeist.sh — Scan for secrets using poltergeist, with grep fallback.
# Handles: tool discovery, fallback logic, JSON output.
#
# Usage: bash scripts/run-poltergeist.sh <target_dir>
# Output: JSON to stdout (candidates array)
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
POLTERGEIST="${HARNESS_ROOT}/bins/poltergeist"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target_dir>" >&2
    exit 1
fi

TARGET_DIR="$1"
harness_require_inside_root "$HARNESS_ROOT" "$TARGET_DIR" "target directory"

if [ -x "${POLTERGEIST}" ]; then
    exec "${POLTERGEIST}" --format json "${TARGET_DIR}"
fi

# Grep-based fallback: scan for common secret patterns
echo '{"tool":"grep-fallback","candidates":['
first=true
while IFS= read -r -d '' file; do
    # Skip binary files and common non-secret files
    case "$file" in
        *.min.js|*.map|*.lock|*.sum|node_modules/*|.git/*|target/*|vendor/*) continue ;;
    esac
    matches=$(grep -n -E \
        -e 'AKIA[0-9A-Z]{16}' \
        -e '-----BEGIN.*PRIVATE KEY-----' \
        -e '(password|passwd|pwd)\s*[:=]\s*["\x27][^"\x27]{8,}' \
        -e '(api[_-]?key|apikey)\s*[:=]\s*["\x27][^"\x27]{16,}' \
        -e 'ghp_[0-9a-zA-Z]{36}' \
        -e 'sk-[0-9a-zA-Z]{32,}' \
        -e 'eyJ[0-9a-zA-Z_-]*\.eyJ[0-9a-zA-Z_-]*' \
        "$file" 2>/dev/null || true)
    if [ -n "$matches" ]; then
        while IFS= read -r line; do
            lineno="${line%%:*}"
            content="${line#*:}"
            # Redact the actual value
            redacted=$(echo "$content" | sed -E 's/(AKIA[0-9A-Z]{4})[0-9A-Z]{12}(\w+)/\1...REDACTED/g; s/(-----BEGIN.*PRIVATE KEY-----).*/\1...REDACTED-----/; s/((password|passwd|pwd)\s*[:=]\s*["\x27]).{8,}/\1...REDACTED/g; s/((api[_-]?key|apikey)\s*[:=]\s*["\x27]).{16,}/\1...REDACTED/g; s/(ghp_)[0-9a-zA-Z]{4,}.*/\1...REDACTED/g; s/(sk-)[0-9a-zA-Z]{4,}.*/\1...REDACTED/g')
            if [ "$first" = true ]; then first=false; else echo ","; fi
            printf '{"file":"%s","line":%s,"match":"%s","source":"grep-fallback"}' \
                "$file" "$lineno" "$(echo "$redacted" | sed 's/"/\\"/g')"
        done <<< "$matches"
    fi
done < <(find "${TARGET_DIR}" -type f -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/target/*' -print0 2>/dev/null)
echo ']}'
