#!/usr/bin/env bash
# run-wraith.sh — Scan a lockfile for vulnerabilities using wraith.
# Handles: OSV database path, tool discovery, offline mode.
#
# Usage: bash scripts/run-wraith.sh <lockfile_path>
# Output: JSON to stdout
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
WRAITH="${HARNESS_ROOT}/bins/wraith"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <lockfile_path>" >&2
    exit 1
fi

LOCKFILE="$1"
harness_require_inside_root "$HARNESS_ROOT" "$LOCKFILE" "lockfile"

if [ ! -x "${WRAITH}" ]; then
    echo '{"error":"wraith not found","hint":"run: bash scripts/install-tools.sh wraith"}' >&2
    exit 1
fi

# Verify OSV database exists
DB_DIR="${HARNESS_ROOT}/.harness/osv-db"
MIN_OSV_DB_FILES=3
MIN_OSV_DB_SIZE_KB=51200
DB_FILE_COUNT=0
DB_SIZE_KB=0
if [[ -d "${DB_DIR}" ]]; then
    DB_FILE_COUNT="$(find "${DB_DIR}" -type f | wc -l | tr -d ' ')"
    DB_SIZE_KB="$(du -sk "${DB_DIR}" 2>/dev/null | awk '{print $1}')"
fi
if [[ ! -d "${DB_DIR}" ]] || [[ "${DB_FILE_COUNT}" -lt "${MIN_OSV_DB_FILES}" ]] || [[ "${DB_SIZE_KB:-0}" -lt "${MIN_OSV_DB_SIZE_KB}" ]]; then
    echo "{\"error\":\"OSV database missing or incomplete\",\"files\":${DB_FILE_COUNT},\"size_kb\":${DB_SIZE_KB:-0},\"hint\":\"run: bash scripts/fetch-osv-db.sh\"}" >&2
    exit 1
fi

export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="${DB_DIR}"
exec "${WRAITH}" scan --offline --format json "${LOCKFILE}"
