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
ecosystem="$(python3 "${HARNESS_ROOT}/scripts/dependency_contract.py" --ecosystem "$relative_lockfile")"
db="${HARNESS_ROOT}/.harness/osv-db"
osv_lock="${HARNESS_ROOT}/config/osv-snapshot.lock.json"
if [ ! -x "${HARNESS_ROOT}/bins/wraith" ] || [ ! -x "${HARNESS_ROOT}/bins/osv-scanner" ]; then
    echo "Wraith or its OSV scanner dependency is unavailable" >&2
    exit 1
fi
python3 "${HARNESS_ROOT}/scripts/osv_snapshot.py" verify \
    --lock "$osv_lock" --cache-root "$db" --ecosystem "$ecosystem"
read -r db_snapshot db_sha < <(
    python3 - "$osv_lock" "$ecosystem" <<'PY'
import json,sys
document=json.load(open(sys.argv[1],encoding="utf-8"))
item=next(item for item in document["ecosystems"] if item["name"]==sys.argv[2])
print(document["snapshot"],item["sha256"])
PY
)
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$db"
tmp="$(mktemp "${TMPDIR}/wraith.XXXXXX")"
stderr_tmp="$(mktemp "${TMPDIR}/wraith-stderr.XXXXXX")"
trap 'rm -f "$tmp" "$stderr_tmp"' EXIT
set +e
"${HARNESS_ROOT}/bins/wraith" scan --offline --format json "$lockfile" >"$tmp" 2>"$stderr_tmp"
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
    echo "Wraith operational failure (exit ${status})" >&2
    exit "$status"
fi
if [ -s "$stderr_tmp" ]; then
    detail="$(tr '\n' ' ' <"$stderr_tmp" | tr -s ' ' | cut -c1-500)"
    echo "Wraith emitted unexpected diagnostics: ${detail}" >&2
    exit 1
fi
python3 "${HARNESS_ROOT}/scripts/normalize-wraith.py" \
    --repo "$repo" \
    --lockfile "$lockfile" \
    --ecosystem "$ecosystem" \
    --database-snapshot "$db_snapshot" \
    --database-sha256 "$db_sha" \
    --output "$output" \
    --receipt "$receipt" \
    <"$tmp"
