#!/usr/bin/env bash
# Launch one optional linked remediation execution after a completed audit.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <completed-scan-base>" >&2
    exit 2
fi
SOURCE_SCAN="$1"
rm -f "${HARNESS_ROOT}/.harness/remediation-context.json"
eval "$("${HARNESS_ROOT}/scripts/load-config.sh")"
OMP_BIN="${HARNESS_ROOT}/bins/omp"
if [ ! -x "$OMP_BIN" ]; then OMP_BIN="$(command -v omp 2>/dev/null || true)"; fi
if [ -z "$OMP_BIN" ]; then
    echo "[remediation] omp not found — run: bash scripts/install-tools.sh" >&2
    exit 1
fi
"${HARNESS_ROOT}/scripts/bootstrap-omp.sh" >/dev/null
"${HARNESS_ROOT}/scripts/validate-config.sh" >/dev/null

export VULNOPS_REMEDIATION_CONTEXT="${HARNESS_ROOT}/.harness/remediation-context.json"
VULNOPS_REMEDIATION_LAUNCHER_SESSION_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}${RANDOM}"
export VULNOPS_REMEDIATION_LAUNCHER_SESSION_ID
"${HARNESS_ROOT}/scripts/run-remediation.sh" "$SOURCE_SCAN" >/dev/null

close_interrupted_remediation() {
    if ! python3 "${HARNESS_ROOT}/scripts/close-interrupted-remediation.py" \
        "$VULNOPS_REMEDIATION_CONTEXT" \
        --launcher-session-id "$VULNOPS_REMEDIATION_LAUNCHER_SESSION_ID"; then
        echo "[remediation] warning: interrupted state could not be closed" >&2
    fi
}
finish_launcher() {
    local status="${1:-$?}"
    trap - EXIT INT TERM
    close_interrupted_remediation
    exit "$status"
}
trap 'finish_launcher $?' EXIT
trap 'finish_launcher 130' INT
trap 'finish_launcher 143' TERM

"${OMP_BIN}" \
    --append-system-prompt "${HARNESS_ROOT}/.omp/main/vulnops-remediation-main.md" \
    --tools "read,bash,edit,write,grep,glob,lsp,task,job,todo,irc,ask" \
    --approval-mode yolo \
    "generate the linked production remediation patches for the selected completed audit"
