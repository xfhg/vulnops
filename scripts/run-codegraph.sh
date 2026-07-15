#!/usr/bin/env bash
# Canonical typed codegraph entrypoint.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$#" -lt 5 ]; then
    echo "Usage: $0 <query|callers|callees|impact|affected> <subject> --project <path> --output <json> [--receipt <json>]" >&2
    exit 64
fi
operation="$1"
subject="$2"
shift 2
exec python3 "${HARNESS_ROOT}/scripts/codegraph-adapter.py" "$operation" "$subject" "$@"
