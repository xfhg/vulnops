#!/usr/bin/env bash
# Optional Linux backend for configured contained safe reproduction.

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

discard_native_authority() {
    local descriptor="${VULNOPS_ADVANTAGE_CALL:-}"
    case "$descriptor" in
        fd:*)
            descriptor="${descriptor#fd:}"
            case "$descriptor" in
                ''|*[!0-9]*) echo "invalid native authority descriptor" >&2; exit 2 ;;
            esac
            # Only validated decimal digits enter this descriptor-close command.
            eval "exec ${descriptor}<&-"
            ;;
    esac
    unset VULNOPS_ADVANTAGE_CALL
}

if [ "$ACTION" = "detect" ]; then
    discard_native_authority
    if backend="$(detect_backend)"; then
        echo "$backend"
        exit 0
    fi
    echo "unavailable"
    exit 1
fi

if [ -n "${VULNOPS_ADVANTAGE_CONTEXT:-}" ]; then
    linked_identity="$(python3 "${HARNESS_ROOT}/scripts/advantage_owners.py" \
        "$VULNOPS_ADVANTAGE_CONTEXT" "$SCAN_BASE" "${VULNOPS_EXPERIMENT_PHASE:-}" "$FINDING_ID")" || exit 2
    IFS=$'\t' read -r REPO_PATH RUN_ID REPRODUCTION_MODE \
        VULNOPS_REPRODUCTION_TIMEOUT_SECONDS VULNOPS_REPRODUCTION_CPU_SECONDS \
        VULNOPS_REPRODUCTION_MEMORY_MB VULNOPS_REPRODUCTION_MAX_PROCESSES \
        VULNOPS_REPRODUCTION_MAX_OUTPUT_KB <<<"$linked_identity"
    discard_native_authority
else
CONTEXT="${VULNOPS_AUDIT_CONTEXT:-${HARNESS_ROOT}/.harness/audit-context.json}"
audit_owner="$(python3 - "$HARNESS_ROOT" "$CONTEXT" "$SCAN_BASE" "${VULNOPS_EXPERIMENT_PHASE:-}" "$FINDING_ID" <<'PY'
import json
import os
import re
import sys
from pathlib import Path
root, context_path, scan_path, phase, workspace = sys.argv[1:]
sys.path.insert(0, str(Path(root) / "scripts"))
from run_lifecycle import assert_owner
doc = json.loads(Path(context_path).read_text())
scan = Path(scan_path).resolve()
if Path(str(doc.get("scan_base", ""))).resolve() != scan:
    raise SystemExit("audit context scan mismatch")
manifest = json.loads((scan / "run-manifest.json").read_text())
for key in ("run_id", "attempt_id"):
    if not doc.get(key) or doc[key] != manifest.get(key):
        raise SystemExit("reproduction context differs from current owner: " + key)
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", doc["run_id"]) or ".." in doc["run_id"]:
    raise SystemExit("unsafe reproduction run identity")
assert_owner(scan, doc.get("launcher_session_id"))
if phase:
    from investigation_experiments import inside, load, validate_request
    prefix = "experiment-" + phase + "-"
    if not workspace.startswith(prefix) or manifest.get("phases", {}).get(phase) != "running":
        raise SystemExit("experiment workspace has no active owner")
    request = load(inside(scan, scan / phase / "experiments" / workspace[len(prefix):] / "request.json"))
    validate_request(doc, request, scan)
    if request.get("attempt_id") != doc["attempt_id"]:
        raise SystemExit("experiment request belongs to another attempt")
budget = manifest.get("experiment_budget", {}) if phase else {}
values = [doc.get("source_root") or doc["repo_path"], doc["run_id"], manifest.get("reproduction_mode", "off")]
for key, default in (("timeout_seconds", 120), ("cpu_seconds", 60), ("memory_mb", 1024),
                     ("max_processes", 64), ("max_output_kb", 256)):
    value = budget.get(key) if phase else int(os.environ.get("VULNOPS_REPRODUCTION_" + key.upper(), default))
    if type(value) is not int or value <= 0:
        raise SystemExit("invalid current reproduction resource limit: " + key)
    values.append(str(value))
if any(not isinstance(value, str) or any(char in value for char in "\t\r\n") for value in values):
    raise SystemExit("invalid reproduction owner fields")
print("\t".join(values))
PY
)" || exit 2
IFS=$'\t' read -r REPO_PATH RUN_ID REPRODUCTION_MODE \
    VULNOPS_REPRODUCTION_TIMEOUT_SECONDS VULNOPS_REPRODUCTION_CPU_SECONDS \
    VULNOPS_REPRODUCTION_MEMORY_MB VULNOPS_REPRODUCTION_MAX_PROCESSES \
    VULNOPS_REPRODUCTION_MAX_OUTPUT_KB <<<"$audit_owner"
fi
harness_require_inside_root "$HARNESS_ROOT" "$REPO_PATH" "reproduction source"
WORK_BASE="${HARNESS_ROOT}/work/${RUN_ID}/reproduction/${FINDING_ID}"
SOURCE_DIR="${WORK_BASE}/source"
HOME_DIR="${WORK_BASE}/home"
ARTIFACT_DIR="${SCAN_BASE}/sast/reproduction/${FINDING_ID}"
if [ -n "${VULNOPS_EXPERIMENT_PHASE:-}" ]; then
    case "$VULNOPS_EXPERIMENT_PHASE" in
        sast|intrusion) ARTIFACT_DIR="${SCAN_BASE}/${VULNOPS_EXPERIMENT_PHASE}/experiments" ;;
        investigation|handoff)
            [ -n "${VULNOPS_ADVANTAGE_CONTEXT:-}" ] || { echo "linked phase requires explicit Advantage owner" >&2; exit 2; }
            ARTIFACT_DIR="${SCAN_BASE}/${VULNOPS_EXPERIMENT_PHASE}/experiments"
            ;;
        *) echo "invalid experiment owner phase" >&2; exit 2 ;;
    esac
fi

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
        rm -rf "$WORK_BASE"
        mkdir -p "$SOURCE_DIR" "$HOME_DIR" "$ARTIFACT_DIR"
        tar -C "$REPO_PATH" --exclude=.git -cf - . | tar -C "$SOURCE_DIR" -xf -
        printf '%s\n' "$backend" >"${WORK_BASE}/sandbox-backend"
        echo "$SOURCE_DIR"
        ;;
    exec)
        [ "$REPRODUCTION_MODE" = "safe" ] || { echo "safe reproduction is disabled in config" >&2; exit 3; }
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
        if [ -n "${VULNOPS_EXPERIMENT_PHASE:-}" ]; then
            # Experiments publish exit-code observations only, never raw proof logs.
            output=/dev/null
        fi
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
                'ulimit -t "$1"; ulimit -v "$2"; ulimit -u "$3"; ulimit -f "$4"; shift 4; exec "$@"' \
                sandbox "$cpu_seconds" "$memory_kb" "$max_processes" "$(( (max_output_bytes + 1023) / 1024 ))" "$@" \
                >"$output" 2>&1
        rc=$?
        set -e
        if [ "$output" != /dev/null ]; then
            python3 "${HARNESS_ROOT}/scripts/redact-output.py" "$output" "$max_output_bytes"
            rm -f "$output"
        fi
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
