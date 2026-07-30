#!/usr/bin/env bash
# OMP shellPath wrapper for policy-only packages and optional source isolation.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mode="${VULNOPS_LINUX_AGENT_EGRESS:-enforced}"
real_shell="${VULNOPS_AGENT_REAL_SHELL:-/bin/bash}"

case "$mode" in
    policy_only)
        exec "$real_shell" "$@"
        ;;
    enforced)
        isolator="${HARNESS_ROOT}/scripts/agent-shell-isolator.sh"
        [ -x "$isolator" ] || {
            echo "[agent-shell] enforced mode requires an installed isolation backend" >&2
            exit 1
        }
        exec "$isolator" "$@"
        ;;
    *)
        echo "[agent-shell] invalid network mode: $mode" >&2
        exit 1
        ;;
esac
