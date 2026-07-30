#!/usr/bin/env bash
# Optional source-tree backend for contained safe reproduction.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <scan_base> <finding_id> <detect|prepare|exec|clean> [-- command ...]" >&2
    exit 2
fi

SCAN_BASE="$1"
FINDING_ID="$2"
ACTION="$3"
shift 3

if [[ ! "$FINDING_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || [[ "$FINDING_ID" == *..* ]]; then
    echo "unsafe finding id" >&2
    exit 2
fi

harness_require_allowed_output "$HARNESS_ROOT" "$SCAN_BASE"

detect_backend() {
    local requested="${VULNOPS_REPRODUCTION_SANDBOX:-auto}"
    if [ "$requested" = "auto" ] || [ "$requested" = "bubblewrap" ]; then
        "${HARNESS_ROOT}/scripts/probe-bubblewrap.sh"
        return $?
    fi
    return 1
}

if [ "$ACTION" = "detect" ]; then
    if backend="$(detect_backend)"; then
        echo "$backend"
        exit 0
    fi
    echo "unavailable"
    exit 1
fi

CONTEXT="${VULNOPS_AUDIT_CONTEXT:-${HARNESS_ROOT}/.harness/audit-context.json}"
IFS=$'\t' read -r REPO_PATH RUN_ID EXPECTED_FINGERPRINT REPRODUCTION_MODE < <(python3 - "$CONTEXT" "$SCAN_BASE" <<'PY'
import json
import sys
from pathlib import Path
doc = json.loads(Path(sys.argv[1]).read_text())
if Path(str(doc.get("scan_base", ""))).resolve() != Path(sys.argv[2]).resolve():
    raise SystemExit("audit context scan mismatch")
print("\t".join([doc["repo_path"], doc["run_id"], doc["target_fingerprint"], doc.get("reproduction_mode", "off")]))
PY
)
WORK_BASE="${HARNESS_ROOT}/work/${RUN_ID}/reproduction/${FINDING_ID}"
SOURCE_DIR="${WORK_BASE}/source"
HOME_DIR="${WORK_BASE}/home"
ARTIFACT_DIR="${SCAN_BASE}/sast/reproduction/${FINDING_ID}"

mkdir -p "$(dirname "$WORK_BASE")" "$(dirname "$ARTIFACT_DIR")"
harness_require_allowed_output "$HARNESS_ROOT" "$WORK_BASE"
harness_require_allowed_output "$HARNESS_ROOT" "$ARTIFACT_DIR"

case "$ACTION" in
    prepare)
        if [ "$REPRODUCTION_MODE" != "safe" ]; then
            echo "safe reproduction is disabled in config" >&2
            exit 3
        fi
        backend="$(detect_backend)" || { echo "no proven safe sandbox backend" >&2; exit 4; }
        before="$(python3 "${HARNESS_ROOT}/scripts/target-fingerprint.py" "$REPO_PATH")"
        if [ "$before" != "$EXPECTED_FINGERPRINT" ]; then
            echo "target fingerprint changed before reproduction" >&2
            exit 5
        fi
        rm -rf "$WORK_BASE"
        mkdir -p "$SOURCE_DIR" "$HOME_DIR" "$ARTIFACT_DIR"
        tar -C "$REPO_PATH" --exclude=.git -cf - . | tar -C "$SOURCE_DIR" -xf -
        after="$(python3 "${HARNESS_ROOT}/scripts/target-fingerprint.py" "$REPO_PATH")"
        if [ "$after" != "$EXPECTED_FINGERPRINT" ]; then
            echo "target fingerprint changed while preparing reproduction" >&2
            exit 5
        fi
        printf '%s\n' "$backend" >"${WORK_BASE}/sandbox-backend"
        echo "$SOURCE_DIR"
        ;;
    exec)
        [ -d "$SOURCE_DIR" ] || { echo "prepare the workspace first" >&2; exit 6; }
        [ "${1:-}" = "--" ] || { echo "exec requires -- command" >&2; exit 2; }
        shift
        [ $# -gt 0 ] || { echo "missing command" >&2; exit 2; }
        backend="$(cat "${WORK_BASE}/sandbox-backend" 2>/dev/null || true)"
        [ "$backend" = "bubblewrap" ] || { echo "workspace has no supported sandbox" >&2; exit 4; }
        timeout_seconds="${VULNOPS_REPRODUCTION_TIMEOUT_SECONDS:-120}"
        cpu_seconds="${VULNOPS_REPRODUCTION_CPU_SECONDS:-60}"
        memory_kb="$(( ${VULNOPS_REPRODUCTION_MEMORY_MB:-1024} * 1024 ))"
        max_processes="${VULNOPS_REPRODUCTION_MAX_PROCESSES:-64}"
        max_output_bytes="$(( ${VULNOPS_REPRODUCTION_MAX_OUTPUT_KB:-256} * 1024 ))"
        output="${HARNESS_ROOT}/.harness/tmp/reproduction-${RUN_ID}-${FINDING_ID}-$$.log"
        sandbox_args=(--unshare-all --die-with-parent --new-session --tmpfs / --ro-bind /usr /usr)
        for system_dir in /bin /sbin /lib /lib64; do
            if [ -e "$system_dir" ]; then
                sandbox_args+=(--ro-bind "$system_dir" "$system_dir")
            fi
        done
        sandbox_args+=(
            --proc /proc --dev /dev --dir /etc --tmpfs /tmp --dir /workspace
            --bind "$WORK_BASE" /workspace
            --chdir /workspace/source
            --setenv HOME /workspace/home
            --setenv TMPDIR /tmp
            --setenv PATH /usr/bin:/bin
        )
        set +e
        env -i PATH="/usr/bin:/bin" \
            timeout --signal=KILL "${timeout_seconds}s" \
            bwrap "${sandbox_args[@]}" \
                /bin/bash -c \
                'ulimit -t "$1"; ulimit -v "$2"; ulimit -u "$3"; shift 3; exec "$@"' \
                sandbox "$cpu_seconds" "$memory_kb" "$max_processes" "$@" \
                >"$output" 2>&1
        rc=$?
        set -e
        python3 "${HARNESS_ROOT}/scripts/redact-output.py" "$output" "$max_output_bytes"
        rm -f "$output"
        exit "$rc"
        ;;
    clean)
        case "$WORK_BASE" in
            "${HARNESS_ROOT}/work/"*) rm -rf "$WORK_BASE" ;;
            *) echo "refusing unsafe cleanup path" >&2; exit 7 ;;
        esac
        ;;
    *)
        echo "unknown action: $ACTION" >&2
        exit 2
        ;;
esac
