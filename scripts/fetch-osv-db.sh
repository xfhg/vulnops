#!/usr/bin/env bash
# Fetch the reviewed snapshot, or explicitly create a new complete reviewed lock.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="${HARNESS_ROOT}/config/osv-snapshot.lock.json"
CACHE_ROOT="${HARNESS_ROOT}/.harness/osv-db"

case "$#" in
    0)
        [ -f "$LOCK" ] || {
            echo "[fetch-osv-db] ERROR: missing OSV snapshot lock: $LOCK" >&2
            exit 1
        }
        python3 "${HARNESS_ROOT}/scripts/osv_snapshot.py" sync \
            --lock "$LOCK" \
            --cache-root "$CACHE_ROOT"
        ;;
    2)
        if [ "$1" != "--refresh-lock" ]; then
            echo "Usage: $0 [--refresh-lock <snapshot-id>]" >&2
            exit 2
        fi
        python3 "${HARNESS_ROOT}/scripts/osv_snapshot.py" refresh-lock \
            --lock "$LOCK" \
            --cache-root "$CACHE_ROOT" \
            --snapshot "$2"
        ;;
    *)
        echo "Usage: $0 [--refresh-lock <snapshot-id>]" >&2
        exit 2
        ;;
esac
