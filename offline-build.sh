#!/usr/bin/env bash
# Rebuild one platform archive from its authoritative JSON chunk manifest.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
PLATFORM=""
OUTPUT=""
FORCE=false

usage() {
    echo "Usage: $0 --platform <linux_amd64|darwin_arm64> [--output PATH] [--force]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --platform)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            PLATFORM="$2"
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            OUTPUT="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "[offline-build] ERROR: unknown argument: $1" >&2
            usage >&2
            exit 64
            ;;
    esac
done

case "$PLATFORM" in
    linux_amd64|darwin_arm64) ;;
    *) echo "[offline-build] ERROR: --platform is required" >&2; usage >&2; exit 64 ;;
esac

manifest="${HARNESS_ROOT}/offline/${PLATFORM}/offline-pack-chunks.json"
[ -f "$manifest" ] || {
    echo "[offline-build] ERROR: missing platform chunk manifest: $manifest" >&2
    exit 1
}

args=(rebuild-chunks "$manifest")
if [ -n "$OUTPUT" ]; then
    args+=(--output "$OUTPUT")
fi
if [ "$FORCE" = true ]; then
    args+=(--force)
fi
python3 "${HARNESS_ROOT}/scripts/offline_package.py" "${args[@]}"
