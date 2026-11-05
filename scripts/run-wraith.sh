#!/usr/bin/env bash
# Run Wraith offline and persist only its normalized, bounded contract.
set -euo pipefail
# Only fixed stage explanations reach direct callers, including failures in
# shared path helpers and subprocesses. Raw scanner data stays trap-cleaned.
exec 3>&2
exec >/dev/null 2>&1
failure_status=1
failure_stage=invocation
tmp=""; stderr_tmp=""
trap '
    exit_status=$?
    rm -f -- "$tmp" "$stderr_tmp"
    if [ "$exit_status" -ne 0 ]; then
        printf "Wraith %s failed\n" "$failure_stage" >&3
        exit "$failure_status"
    fi
' EXIT
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
failure_status=64
failure_stage=input_validation
if [ "$#" -ne 4 ]; then
    exit 64
fi
repo="$1"; lockfile="$2"; output="$3"; receipt="$4"
harness_require_inside_root "$HARNESS_ROOT" "$repo" "repository"
harness_require_inside_root "$HARNESS_ROOT" "$lockfile" "lockfile"
harness_require_allowed_output "$HARNESS_ROOT" "$output"
harness_require_allowed_output "$HARNESS_ROOT" "$receipt"
relative_lockfile="${lockfile#${repo%/}/}"
if [ "$relative_lockfile" = "$lockfile" ] || ! python3 "${HARNESS_ROOT}/scripts/dependency_contract.py" "$relative_lockfile"; then
    exit 64
fi
ecosystem="$(python3 "${HARNESS_ROOT}/scripts/dependency_contract.py" --ecosystem "$relative_lockfile")"
db="${HARNESS_ROOT}/.harness/osv-db"
osv_lock="${HARNESS_ROOT}/config/osv-snapshot.lock.json"
failure_status=70
failure_stage=prerequisite
if [ ! -x "${HARNESS_ROOT}/bins/wraith" ] || [ ! -x "${HARNESS_ROOT}/bins/osv-scanner" ]; then
    exit 1
fi
failure_status=71
failure_stage=database_verification
python3 "${HARNESS_ROOT}/scripts/osv_snapshot.py" verify \
    --lock "$osv_lock" --cache-root "$db" --ecosystem "$ecosystem"
db_identity="$(
    python3 - "$osv_lock" "$ecosystem" <<'PY'
import json,sys
document=json.load(open(sys.argv[1],encoding="utf-8"))
item=next(item for item in document["ecosystems"] if item["name"]==sys.argv[2])
print(document["snapshot"],item["sha256"])
PY
)"
read -r db_snapshot db_sha <<<"$db_identity"
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$db"
failure_status=1
failure_stage=invocation
tmp="$(mktemp "${TMPDIR}/wraith.XXXXXX")"
stderr_tmp="$(mktemp "${TMPDIR}/wraith-stderr.XXXXXX")"
failure_status=72
failure_stage=scanner_execution
set +e
"${HARNESS_ROOT}/bins/wraith" scan --offline --format json "$lockfile" >"$tmp" 2>"$stderr_tmp"
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
    exit 1
fi
failure_status=73
failure_stage=unexpected_diagnostics
if [ -s "$stderr_tmp" ]; then
    exit 1
fi
failure_status=74
failure_stage=normalization
python3 "${HARNESS_ROOT}/scripts/normalize-wraith.py" \
    --repo "$repo" \
    --lockfile "$lockfile" \
    --ecosystem "$ecosystem" \
    --database-snapshot "$db_snapshot" \
    --database-sha256 "$db_sha" \
    --scanner-exit-status "$status" \
    --output "$output" \
    --receipt "$receipt" \
    <"$tmp"
