#!/usr/bin/env bash
# Optional source-tree shell isolator used only by enforced mode.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mode="${VULNOPS_LINUX_AGENT_EGRESS:-enforced}"
real_shell="${VULNOPS_AGENT_REAL_SHELL:-/bin/bash}"

[ "$(uname -s)" = "Linux" ] || {
    echo "[agent-shell-isolator] enforced isolation requires Linux" >&2
    exit 1
}
[ "$mode" = "enforced" ] || {
    echo "[agent-shell-isolator] invalid network mode: $mode" >&2
    exit 1
}

bwrap_bin="$(command -v bwrap 2>/dev/null || true)"
[ -n "$bwrap_bin" ] || {
    echo "[agent-shell-isolator] enforced mode requires bubblewrap" >&2
    exit 1
}

for directory in .harness work scans remediations; do
    mkdir -p "${HARNESS_ROOT}/${directory}"
done

args=(
    --unshare-net
    --die-with-parent
    --new-session
    --ro-bind / /
    --dev-bind /dev /dev
    --proc /proc
    --tmpfs /tmp
)
for directory in .harness work scans remediations; do
    args+=(--bind "${HARNESS_ROOT}/${directory}" "${HARNESS_ROOT}/${directory}")
done
if [ -d "${HARNESS_ROOT}/target" ]; then
    args+=(--ro-bind "${HARNESS_ROOT}/target" "${HARNESS_ROOT}/target")
fi

exec "$bwrap_bin" "${args[@]}" "$real_shell" "$@"
