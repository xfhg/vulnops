#!/usr/bin/env bash
# Launch a separately owned, explicitly selected linked Advantage execution.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
usage() {
    echo "Usage: $0 <completed-scan-base> [--mode standard|deep|diff|actions] [--depth quick|balanced|full]"
    echo "       [--patch FILE --repository KEY] [--verify-fix ID ...] [--assess-patch-risk]"
    echo "       [--hardening] [--track-finding ID ...] [--action-source COMPLETED-ADVANTAGE]"
    echo "       [--source-root PATH]"
    echo "Defaults: --mode deep --depth full (ordinary audit defaults are unchanged)."
}
if [ "${1:-}" = --help ] || [ "${1:-}" = -h ]; then usage; exit 0; fi
if [ "$#" -eq 0 ] || [[ "$1" = -* ]]; then usage >&2; exit 2; fi
# Keep argument boundaries (including spaces in source and patch paths) intact.
init_args=("$@")
shift
while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode|--depth|--patch|--repository|--verify-fix|--track-finding|--action-source|--source-root)
            if [ "$#" -lt 2 ] || [[ "$2" = --* ]]; then echo "[advantage] missing value for $1" >&2; exit 2; fi
            if [ "$1" = --mode ]; then
                case "$2" in standard|deep|diff|actions) ;; *) echo "[advantage] invalid mode: $2" >&2; exit 2 ;; esac
            elif [ "$1" = --depth ]; then
                case "$2" in quick|balanced|full) ;; *) echo "[advantage] invalid depth: $2" >&2; exit 2 ;; esac
            fi
            shift 2 ;;
        --assess-patch-risk|--hardening) shift ;;
        *) echo "[advantage] unknown argument: $1" >&2; exit 2 ;;
    esac
done
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}${RANDOM}"
export VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID
export VULNOPS_LAUNCHER_PID=$$
# Never inherit ownership of another launcher's overlay or audit context.
unset VULNOPS_OMP_RUNTIME_CONFIG VULNOPS_LAUNCHER_SESSION_ID VULNOPS_ADVANTAGE_CONTEXT VULNOPS_ADVANTAGE_CALL
finish_launcher() {
    local status="${1:-$?}"
    trap - EXIT INT TERM
    rm -f "${VULNOPS_OMP_RUNTIME_CONFIG:-}"
    echo "[advantage] exit status: $status" >&2
    exit "$status"
}
# Native invocation teardown owns temporary Advantage inputs and descendants.
trap 'finish_launcher $?' EXIT
trap 'finish_launcher 130' INT
trap 'finish_launcher 143' TERM
config_exports="$("${HARNESS_ROOT}/scripts/load-config.sh")" || exit 1
eval "$config_exports"
export VULNOPS_OMP_CONTROLLER_SELECTOR="$OMP_ADVANTAGE_MODEL_SELECTOR"
OMP_BIN="${HARNESS_ROOT}/bins/omp"
if [ ! -x "$OMP_BIN" ]; then OMP_BIN="$(command -v omp 2>/dev/null || true)"; fi
if [ -z "$OMP_BIN" ]; then echo "[advantage] omp not found; prepare the runtime first" >&2; exit 1; fi
harness_loading 2 "configuration" "${HARNESS_ROOT}/scripts/bootstrap-omp.sh" >/dev/null
harness_loading 3 "toolchain checks" "${HARNESS_ROOT}/scripts/validate-config.sh" >/dev/null
# Carry the exact request into OMP; baseline admission belongs to its controller.
VULNOPS_ADVANTAGE_LAUNCH_REQUEST="$(python3 -c '
import json, os, sys
print(json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd(),
                  "launcher_session_id": os.environ["VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID"]}))
' "${init_args[@]}")"
export VULNOPS_ADVANTAGE_LAUNCH_REQUEST
harness_prepare_omp_runtime "$HARNESS_ROOT"
cd "$HARNESS_ROOT"
status=0
"$OMP_BIN" \
    --no-session \
    --append-system-prompt "${HARNESS_ROOT}/.omp/main/vulnops-advantage-main.md" \
    --tools "$(harness_omp_tools)" \
    --config "$VULNOPS_OMP_RUNTIME_CONFIG" \
    --model "${OMP_ADVANTAGE_MODEL_SELECTOR%:*}" \
    --thinking "${OMP_ADVANTAGE_MODEL_SELECTOR##*:}" \
    --extension "${HARNESS_ROOT}/.omp/guards/target-readonly.ts" \
    --approval-mode yolo \
    "Initialize the selected standalone Advantage execution inside this OMP session using python3 scripts/init-advantage.py --from-launcher, then complete it with native todo, tools and phase agents. The exact source and options are bound in VULNOPS_ADVANTAGE_LAUNCH_REQUEST. Do not start an ordinary audit." || status=$?
exit "$status"
