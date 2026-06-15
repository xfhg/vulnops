#!/usr/bin/env bash
# cleanup.sh — Clean ephemeral harness state
# Does NOT remove scan outputs (those are the deliverables).
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[cleanup]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $0 [target|work|logs|all|status]

What to clean:
  status    Show what would be cleaned (default)
  work      Remove ephemeral agent workspace (work/*)
  logs      Remove old log files (.harness/logs/*)
  target    Remove cloned target repo (target/*)
  all       Clean work + logs + target (keeps scans)
  --full    Nuclear: remove everything including scans

Examples:
  $0              # Show status
  $0 work         # Clean work directory
  $0 all          # Clean work + logs + target
  $0 --full       # Remove everything (scans included)
EOF
}

show_status() {
    echo "Harness state:"
    echo ""

    echo "target/ (cloned repos):"
    if [ -d "${HARNESS_ROOT}/target" ]; then
        local count
        count="$(find "${HARNESS_ROOT}/target" -maxdepth 1 -mindepth 1 -not -name '.*' | wc -l | tr -d ' ')"
        echo "  ${count} item(s)"
        if [ -f "${HARNESS_ROOT}/target/.target-info" ]; then
            echo "  Last target: $(grep 'repo_url:' "${HARNESS_ROOT}/target/.target-info" | cut -d: -f2- | xargs)"
        fi
    else
        echo "  (empty)"
    fi
    echo ""

    echo "work/ (ephemeral):"
    if [ -d "${HARNESS_ROOT}/work" ]; then
        local size
        size="$(du -sh "${HARNESS_ROOT}/work" 2>/dev/null | cut -f1)"
        echo "  Size: ${size:-0}"
    else
        echo "  (empty)"
    fi
    echo ""

    echo ".harness/logs/:"
    if [ -d "${HARNESS_ROOT}/.harness/logs" ]; then
        local count
        count="$(find "${HARNESS_ROOT}/.harness/logs" -type f | wc -l | tr -d ' ')"
        echo "  ${count} file(s)"
    else
        echo "  (empty)"
    fi
    echo ""

    echo "scans/ (deliverables):"
    if [ -d "${HARNESS_ROOT}/scans" ]; then
        local count size
        count="$(find "${HARNESS_ROOT}/scans" -maxdepth 2 -mindepth 2 -type d 2>/dev/null | wc -l | tr -d ' ')"
        size="$(du -sh "${HARNESS_ROOT}/scans" 2>/dev/null | cut -f1)"
        echo "  ${count} scan(s), ${size:-0}"
    else
        echo "  (empty)"
    fi
}

clean_work() {
    log "Cleaning work/..."
    rm -rf "${HARNESS_ROOT}/work/"*
    log "Done."
}

clean_logs() {
    log "Cleaning .harness/logs/..."
    rm -f "${HARNESS_ROOT}/.harness/logs/"*
    log "Done."
}

clean_target() {
    log "Cleaning target/..."
    # Need to restore write permission before removing
    chmod -R u+w "${HARNESS_ROOT}/target" 2>/dev/null || true
    find "${HARNESS_ROOT}/target" -mindepth 1 -not -name '.*' -exec rm -rf {} + 2>/dev/null || true
    rm -f "${HARNESS_ROOT}/target/.target-info"
    log "Done."
}

clean_scans() {
    log "Cleaning scans/..."
    rm -rf "${HARNESS_ROOT}/scans/"*
    log "Done."
}

# Main
target="${1:-status}"

case "$target" in
    status)  show_status ;;
    work)    clean_work ;;
    logs)    clean_logs ;;
    target)  clean_target ;;
    all)     clean_work; clean_logs; clean_target ;;
    --full)  clean_work; clean_logs; clean_target; clean_scans ;;
    --help)  usage ;;
    *)       echo "Unknown: $target"; usage; exit 1 ;;
esac
