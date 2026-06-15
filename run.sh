#!/usr/bin/env bash
# run.sh — Validate prepared audit runtime, load config, and run OMP.
# Usage: bash run.sh "audit the target repo"
#        bash run.sh                   (opens OMP interactive)
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Keep tool homes, caches, temp files, and agent side effects inside the
# harness repo during audit execution.
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

# Audit runtime must be fully prepared before OMP starts. Bootstrap commands
# such as install-tools.sh, fetch-osv-db.sh, dependency setup, and clone-target.sh
# stay outside this path.
"${HARNESS_ROOT}/scripts/validate-config.sh" >/dev/null

# Load config.toml → env vars, sync models.yml to OMP
eval "$("${HARNESS_ROOT}/scripts/load-config.sh")"

# Prefer bundled OMP, fall back to global install
OMP_BIN="${HARNESS_ROOT}/bins/omp"
if [ ! -x "${OMP_BIN}" ]; then
    OMP_BIN="$(command -v omp 2>/dev/null || true)"
fi
if [ -z "${OMP_BIN}" ]; then
    echo "[error] omp not found — run: bash scripts/install-tools.sh" >&2
    exit 1
fi

"${OMP_BIN}" \
    --model "on-prem/${ON_PREM_MODEL_NAME}" \
    --append-system-prompt "${HARNESS_ROOT}/.omp/main/vulnops-main.md" \
    --tools "read,bash,grep,find,lsp,task,todo,ask" \
    "$@"
