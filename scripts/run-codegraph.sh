#!/usr/bin/env bash
# run-codegraph.sh — codegraph CLI wrapper for vulnops.
#
# Thin layer that adds harness containment, log redirection, and an explicit
# action dispatch. The upstream codegraph CLI is AST-only, runs fully offline,
# and exposes init / status /
# query / search. We do NOT wire the in-process API surface here — agents
# call this wrapper and parse stdout.
#
# Usage:
#   bash scripts/run-codegraph.sh <action> [-- <cli-args>...]
#   actions: status | init [path] | query <symbol> [--format json] | search <pattern>

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

CODEGRAPH_BIN="${HARNESS_ROOT}/bins/codegraph"
CODEGRAPH_INDEX_DIR="${CODEGRAPH_INDEX_DIR:-${HARNESS_ROOT}/.codegraph}"

if [ $# -lt 1 ]; then
    cat <<EOF >&2
Usage: $0 <action> [-- <cli-args>...]

Actions:
  status                Show current codegraph index state
  init [path]           Build a codegraph index for <path> (default: VULNOPSV3_TARGET)
  query <symbol>        Look up a symbol in the index
  search <pattern>      FTS5 search across the index
EOF
    exit 64
fi

if [ ! -x "${CODEGRAPH_BIN}" ]; then
    echo "codegraph binary not installed at ${CODEGRAPH_BIN}" >&2
    exit 127
fi

action="$1"
shift

case "$action" in
    status)
        exec "${CODEGRAPH_BIN}" status
        ;;
    init)
        target="${1:-${VULNOPSV3_TARGET:-${HARNESS_ROOT}/target}}"
        mkdir -p "${CODEGRAPH_INDEX_DIR}"
        exec "${CODEGRAPH_BIN}" init "${target}"
        ;;
    query|search)
        log_slug="cg-$(echo "$action $*"|tr '/ ' '__' | tr -cd '[:alnum:]._-')"
        log_path="${HARNESS_ROOT}/.harness/logs/${log_slug}.log"
        mkdir -p "$(dirname "${log_path}")"
        "${CODEGRAPH_BIN}" "$action" "$@" 2>"${log_path}"
        ;;
    *)
        echo "unknown action: ${action}" >&2
        exit 64
        ;;
esac
