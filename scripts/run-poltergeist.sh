#!/usr/bin/env bash
# run-poltergeist.sh — Scan for secrets using poltergeist, with grep fallback.
# Handles: tool discovery, fallback logic, JSON output.
#
# Usage: bash scripts/run-poltergeist.sh <target_dir>
# Output: JSON to stdout (tool JSON object)
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
POLTERGEIST="${HARNESS_ROOT}/bins/poltergeist"
PYTHON="$(command -v python3 2>/dev/null || true)"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target_dir>" >&2
    exit 1
fi

TARGET_DIR="$1"
harness_require_inside_root "$HARNESS_ROOT" "$TARGET_DIR" "target directory"

if [ -x "${POLTERGEIST}" ]; then
    if [ -z "${PYTHON}" ]; then
        echo '{"error":"python3 not found","hint":"python3 is required to normalize poltergeist JSON output"}' >&2
        exit 1
    fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/poltergeist.XXXXXX")"
    err_tmp="$(mktemp "${TMPDIR:-/tmp}/poltergeist.err.XXXXXX")"
    trap 'rm -f "$tmp" "$err_tmp"' EXIT
    if ! "${POLTERGEIST}" --format json "${TARGET_DIR}" >"$tmp" 2>"$err_tmp"; then
        cat "$err_tmp" >&2
        exit 1
    fi
    "${PYTHON}" - "$tmp" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
patterns = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,})\b"),
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s]+"),
    re.compile(r"(?i)((?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*)[^\s,;]+"),
)
sensitive_keys = {"secret", "value", "match", "content", "snippet", "context", "raw", "password", "passwd", "token", "api_key", "private_key", "raw_value"}

def scrub(value, key=""):
    if isinstance(value, dict):
        return {name: scrub(item, str(name).lower()) for name, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, key) for item in value]
    if isinstance(value, str):
        if key in sensitive_keys:
            return "<redacted>"
        result = value
        for pattern in patterns:
            result = pattern.sub("<redacted>", result)
        return result
    return value

for index, char in enumerate(text):
    if char not in "[{":
        continue
    candidate = text[index:].strip()
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        continue
    print(json.dumps(scrub(parsed)))
    raise SystemExit(0)
raise SystemExit("poltergeist did not emit JSON")
PY
    exit 0
fi

if [ "${VULNOPS_ALLOW_POLTERGEIST_GREP_FALLBACK:-0}" != "1" ]; then
    echo '{"error":"poltergeist not found","hint":"run: bash scripts/install-tools.sh poltergeist"}' >&2
    exit 127
fi

if [ -z "${PYTHON}" ]; then
    echo '{"error":"python3 not found","hint":"python3 is required to emit schema-valid fallback JSON"}' >&2
    exit 1
fi

json_string() {
    "${PYTHON}" -c 'import json, sys; print(json.dumps(sys.stdin.read()))'
}

# Explicit degraded grep-based fallback: scan for common secret patterns.
echo '{"schema_version":"2.0","tool":"grep-fallback","candidates":['
first=true
candidate_index=0
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
            candidate_index=$((candidate_index + 1))
            rel_file="${file#${TARGET_DIR}/}"
            if [ "$rel_file" = "$file" ]; then
                rel_file="${file#./}"
            fi
            content_lc="$(printf '%s' "$content" | tr '[:upper:]' '[:lower:]')"
            secret_type="unknown"
            severity="medium"
            case "$content_lc" in
                *private\ key*) secret_type="private-key"; severity="high" ;;
                *password*|*passwd*|*pwd*) secret_type="password"; severity="high" ;;
                *api*key*|*apikey*|*akia*) secret_type="api-key"; severity="high" ;;
                *ghp_*|*sk-*|*eyj*) secret_type="token"; severity="high" ;;
            esac
            candidate_id="$(printf 'SEC-%03d' "$candidate_index")"
            evidence_ref="${rel_file}:${lineno}"
            raw_ref="grep-fallback:${candidate_index}"
            if [ "$first" = true ]; then first=false; else echo ","; fi
            printf '{"id":%s,"type":%s,"classification":"candidate","severity":%s,"file":%s,"line":%s,"redacted_value":%s,"evidence_refs":[%s],"raw_ref":%s,"source":"grep-fallback"}' \
                "$(printf '%s' "$candidate_id" | json_string)" \
                "$(printf '%s' "$secret_type" | json_string)" \
                "$(printf '%s' "$severity" | json_string)" \
                "$(printf '%s' "$rel_file" | json_string)" \
                "$lineno" \
                '"<redacted>"' \
                "$(printf '%s' "$evidence_ref" | json_string)" \
                "$(printf '%s' "$raw_ref" | json_string)"
        done <<< "$matches"
    fi
done < <(find "${TARGET_DIR}" -type f -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/target/*' -print0 2>/dev/null)
echo ']}'
