#!/usr/bin/env bash
# clone-target.sh — Clone a repository to target/ for audit
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${HARNESS_ROOT}/target"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[clone]${NC} $*"; }
warn() { echo -e "${YELLOW}[clone]${NC} $*"; }
err()  { echo -e "${RED}[clone]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $0 <repo_url> [branch] [clone_dir]

Clone a repository into target/.

Arguments:
  repo_url    Git repository URL (SSH or HTTPS)
  branch      Branch to checkout (optional, defaults to repo default)
  clone_dir   Subdirectory name within target/ (optional, defaults to "repo")

Examples:
  $0 https://github.com/user/app.git
  $0 git@github.com:user/app.git main app-main
  $0 https://github.com/user/app.git develop myapp

After cloning, the target directory is treated as read-only by audit policy.
EOF
}

main() {
    if [ $# -lt 1 ] || [ "$1" = "--help" ]; then
        usage
        exit 0
    fi

    local repo_url="$1"
    local branch="${2:-}"
    local clone_name="${3:-repo}"
    local dest="${TARGET_DIR}/${clone_name}"

    # Safety: never allow writing inside target/
    mkdir -p "$TARGET_DIR"

    # Check if target already exists
    if [ -d "$dest" ]; then
        err "Target directory already exists: ${dest}"
        err "Remove it first or choose a different clone_dir."
        exit 1
    fi

    # Build clone command
    local cmd=(git clone)
    if [ -n "$branch" ]; then
        cmd+=(--branch "$branch")
    fi
    cmd+=(--depth 1 "$repo_url" "$dest")

    log "Cloning: ${repo_url}"
    [ -n "$branch" ] && log "Branch: ${branch}"
    log "Destination: ${dest}"
    log ""

    if ! "${cmd[@]}"; then
        err "Clone failed."
        rm -rf "$dest"
        exit 1
    fi

    # Jail: make the entire target directory read-only
    log ""
    log "Jailing target directory (read-only)..."
    chmod -R a-w "$dest"

    # Also remove write permission on the directory itself
    # (chmod a-w on files is enough, but directories need -w too)
    find "$dest" -type d -exec chmod a-w {} +

    # Verify jailing
    if touch "${dest}/.write-test" 2>/dev/null; then
        err "WARNING: Jailing failed — target is still writable!"
        rm -f "${dest}/.write-test"
        exit 1
    fi

    log ""
    log "Target jailed successfully: ${dest}"
    log "Contents:"
    ls -la "$dest" | head -20

    # Record metadata
    cat > "${TARGET_DIR}/.target-info" <<INFO
repo_url: ${repo_url}
branch: ${branch:-$(cd "$dest" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")}
clone_dir: ${clone_name}
cloned_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
commit: $(cd "$dest" && git rev-parse HEAD 2>/dev/null || echo "unknown")
short_sha: $(cd "$dest" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
INFO

    log "Metadata written to target/.target-info"
}

main "$@"
