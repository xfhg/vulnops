#!/usr/bin/env bash
# Prove the exact network namespace primitive used for agent shell execution.
set -euo pipefail

[ "$(uname -s 2>/dev/null || true)" = "Linux" ] || {
    echo "agent network isolation requires Linux" >&2
    exit 1
}
bwrap_bin="$(command -v bwrap 2>/dev/null || true)"
[ -n "$bwrap_bin" ] || {
    echo "bubblewrap is unavailable" >&2
    exit 1
}

args=(
    --unshare-net
    --die-with-parent
    --new-session
    --ro-bind / /
    --dev-bind /dev /dev
    --proc /proc
    --tmpfs /tmp
)
"$bwrap_bin" "${args[@]}" /bin/sh -c '
    test -d /proc/self/ns &&
    touch /tmp/vulnops-agent-isolation &&
    test -f /tmp/vulnops-agent-isolation &&
    if command -v python3 >/dev/null 2>&1; then
        ! python3 -c "import socket; socket.create_connection((\"1.1.1.1\", 53), 0.2)" >/dev/null 2>&1
    fi
' >/dev/null 2>&1 || {
    echo "bubblewrap agent network-isolation probe failed" >&2
    exit 1
}
echo "bubblewrap-unshare-net"
