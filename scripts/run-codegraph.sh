#!/usr/bin/env bash
# Canonical typed codegraph entrypoint.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "${HARNESS_ROOT}/scripts/codegraph-adapter.py" "$@"
