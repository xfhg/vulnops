#!/usr/bin/env bash
# jail.sh — Execute a command with harness-local homes, caches, and temp paths.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

# Load centralized config (config.toml → env vars)
if [ -f "${HARNESS_ROOT}/config.toml" ] && [ -x "${HARNESS_ROOT}/scripts/load-config.sh" ]; then
    eval "$("${HARNESS_ROOT}/scripts/load-config.sh")" 2>/dev/null || true
fi

# If no arguments, print jail status
if [ $# -eq 0 ]; then
    echo "Jail status:"
    echo "  Root:     ${HARNESS_ROOT}"
    echo "  PATH:     ${HARNESS_ROOT}/bins:\$PATH"
    echo "  Scans:    ${HARNESS_ROOT}/scans"
    echo "  Target:   ${HARNESS_ROOT}/target (read-only by policy, not chmod-enforced)"
    echo "  Work:     ${HARNESS_ROOT}/work"
    echo "  HOME:     ${HOME}"
    echo "  TMPDIR:   ${TMPDIR}"
    echo "  Cache:    ${XDG_CACHE_HOME}"
    echo ""
    echo "Installed tools:"
    for tool in wraith poltergeist; do
        if command -v "$tool" &>/dev/null; then
            echo "  ${tool}: $(command -v "$tool")"
        else
            echo "  ${tool}: NOT INSTALLED"
        fi
    done
    if [ -x "${HARNESS_ROOT}/.venv/bin/graphify" ]; then
        echo "  graphify: ${HARNESS_ROOT}/.venv/bin/graphify"
    elif command -v graphify &>/dev/null; then
        echo "  graphify: $(command -v graphify)"
    else
        echo "  graphify: NOT INSTALLED (optional — run: bash scripts/install-tools.sh)"
    fi
    exit 0
fi

# Run the command
exec "$@"
