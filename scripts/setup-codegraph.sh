#!/usr/bin/env bash
# Build disposable current navigation outside the read-only source tree.
# Keep containment here; the helper owns the whole preparation deadline and workers.
set -Eeuo pipefail
trap 'exit 2' ERR

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Reject invalid budgets before containment or project creation mutates any workspace.
python3 "${HARNESS_ROOT}/scripts/codegraph_setup.py" --validate-timeout
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
if [ -z "${CODEGRAPH_TARGET_DIR:-}" ] || [ -z "${CODEGRAPH_RUNTIME_DIR:-}" ]; then
    echo "[setup-codegraph] CODEGRAPH_TARGET_DIR and CODEGRAPH_RUNTIME_DIR are required" >&2
    exit 2
fi
harness_require_inside_root "$HARNESS_ROOT" "$CODEGRAPH_TARGET_DIR" "codegraph source" || exit 2
harness_require_inside_root "$HARNESS_ROOT" "$CODEGRAPH_RUNTIME_DIR" "codegraph runtime" || exit 2
exec python3 "${HARNESS_ROOT}/scripts/codegraph_setup.py"
