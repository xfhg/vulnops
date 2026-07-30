#!/usr/bin/env bash
# Stable reproduction entrypoint; offline packages intentionally omit a backend.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <scan_base> <finding_id> <detect|prepare|exec|clean> [-- command ...]" >&2
    exit 2
fi

backend="${HARNESS_ROOT}/scripts/safe-reproduction-backend.sh"
if [ ! -x "$backend" ]; then
    if [ "$3" = "detect" ]; then
        echo "unavailable"
        exit 1
    fi
    echo "safe reproduction is unavailable in this runtime profile" >&2
    exit 4
fi

exec "$backend" "$@"
