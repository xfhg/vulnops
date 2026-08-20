#!/usr/bin/env bash
# Prove that bubblewrap can create the namespaces and isolated filesystem used
# by safe reproduction. Binary presence alone is not a support signal.

set -euo pipefail

if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then
    echo "safe reproduction unavailable: requires Linux" >&2
    exit 1
fi

bwrap_bin="$(command -v bwrap 2>/dev/null || true)"
if [ -z "$bwrap_bin" ]; then
    echo "bubblewrap is unavailable" >&2
    exit 1
fi

probe_args=(
    --unshare-all
    --die-with-parent
    --new-session
    --tmpfs /
    --proc /proc
    --dev /dev
    --tmpfs /tmp
    --ro-bind /usr /usr
)
for system_dir in /bin /sbin /lib /lib64; do
    if [ -e "$system_dir" ]; then
        probe_args+=(--ro-bind "$system_dir" "$system_dir")
    fi
done

"$bwrap_bin" "${probe_args[@]}" /bin/sh -c '
    test -d /proc/self/ns &&
    test ! -e /etc/passwd &&
    test ! -e /home &&
    touch /tmp/vulnops-bwrap-probe &&
    test -f /tmp/vulnops-bwrap-probe
' >/dev/null 2>&1 || {
    echo "bubblewrap namespace/isolation probe failed" >&2
    exit 1
}

echo "bubblewrap"
