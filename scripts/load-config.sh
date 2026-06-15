#!/usr/bin/env bash
# load-config.sh — Export env vars from config.toml
#
# Usage:
#   eval "$(bash scripts/load-config.sh)"   # in current shell
#   source scripts/load-config.sh            # in a subshell
#
# Falls back to system python3 if .venv is missing.
# No config.toml = silent exit 0.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_PY="${HARNESS_ROOT}/.venv/bin/python"
PARSER="${HARNESS_ROOT}/scripts/parse-config.py"

if [ ! -f "${HARNESS_ROOT}/config.toml" ]; then
    exit 0
fi

if [ ! -x "${CONFIG_PY}" ]; then
    # Fallback: try system python3 with tomllib (3.11+)
    CONFIG_PY="$(command -v python3 2>/dev/null || true)"
    if [ -z "${CONFIG_PY}" ]; then
        echo "[config] python3 not found — cannot parse config.toml" >&2
        exit 0
    fi
fi

"${CONFIG_PY}" "${PARSER}" "${HARNESS_ROOT}"

