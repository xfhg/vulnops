#!/usr/bin/env bash
# Run Wraith offline and persist only its normalized, bounded contract.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <repo-root> <lockfile> <normalized-json> <receipt-json>" >&2
    exit 64
fi
repo="$1"; lockfile="$2"; output="$3"; receipt="$4"
harness_require_inside_root "$HARNESS_ROOT" "$repo" "repository"
harness_require_inside_root "$HARNESS_ROOT" "$lockfile" "lockfile"
harness_require_allowed_output "$HARNESS_ROOT" "$output"
harness_require_allowed_output "$HARNESS_ROOT" "$receipt"
relative_lockfile="${lockfile#${repo%/}/}"
if [ "$relative_lockfile" = "$lockfile" ] || ! python3 "${HARNESS_ROOT}/scripts/dependency_contract.py" "$relative_lockfile"; then
    echo "Wraith input is not a supported target-relative dependency file" >&2
    exit 64
fi
db="${HARNESS_ROOT}/.harness/osv-db"
if [ ! -x "${HARNESS_ROOT}/bins/wraith" ] || [ ! -x "${HARNESS_ROOT}/bins/osv-scanner" ]; then
    echo "Wraith or its OSV scanner dependency is unavailable" >&2
    exit 1
fi
if [ ! -d "$db" ]; then
    echo "OSV database is unavailable" >&2
    exit 1
fi
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$db"
tmp="$(mktemp "${TMPDIR}/wraith.XXXXXX")"; trap 'rm -f "$tmp"' EXIT
set +e
"${HARNESS_ROOT}/bins/wraith" scan --offline --format json "$lockfile" >"$tmp"
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
    echo "Wraith operational failure (exit ${status})" >&2
    exit "$status"
fi
python3 "${HARNESS_ROOT}/scripts/normalize-wraith.py" --repo "$repo" --lockfile "$lockfile" --output "$output" --receipt "$receipt" <"$tmp"
