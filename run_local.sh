#!/usr/bin/env bash
# Local macOS entrypoint: reuse global OMP login before harness containment.
set +x
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
launcher="${HARNESS_ROOT}/run.sh"
if [ "${1:-}" = "--advantage" ]; then
    shift
    launcher="${HARNESS_ROOT}/advantage.sh"
    # Usage errors and help must not acquire credentials or start an audit.
    if [ "$#" -eq 0 ] || [[ "$1" = -* ]]; then
        exec "$launcher" "$@"
    fi
fi
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
if [ -n "${NODE_EXTRA_CA_CERTS:-}" ] && [ ! -r "$NODE_EXTRA_CA_CERTS" ]; then
    echo "[error] root CA is unreadable; set NODE_EXTRA_CA_CERTS to your PEM bundle" >&2
    exit 1
fi
export PI_NATIVES_DIR="${HARNESS_ROOT}/bins"
if [ -z "${OPENAI_CODEX_OAUTH_TOKEN:-}" ]; then
    OPENAI_CODEX_OAUTH_TOKEN="$(harness_loading 1 "global login" "${HARNESS_ROOT}/bins/omp" token openai-codex)"
fi
if [ -z "$OPENAI_CODEX_OAUTH_TOKEN" ]; then
    echo "[error] global OMP login returned no credential" >&2
    exit 1
fi
export OPENAI_CODEX_OAUTH_TOKEN
exec "$launcher" "$@"
