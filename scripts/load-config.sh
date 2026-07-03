#!/usr/bin/env bash
# load-config.sh — Export env vars from config.toml
#
# Usage:
#   eval "$(bash scripts/load-config.sh)"   # in current shell
#   source scripts/load-config.sh            # in a subshell
#
# Uses system python3 with tomllib (3.11+).
# No config.toml = silent exit 0.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_PY="$(command -v python3 2>/dev/null || true)"
PARSER="${HARNESS_ROOT}/scripts/parse-config.py"

if [ ! -f "${HARNESS_ROOT}/config.toml" ]; then
    exit 0
fi


"${CONFIG_PY}" "${PARSER}" "${HARNESS_ROOT}"

