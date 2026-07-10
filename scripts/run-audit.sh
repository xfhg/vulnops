#!/usr/bin/env bash
# run-audit.sh — Detect the repo in target/ and compute all audit paths
# The user clones manually. This script just reads what's there.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
TARGET_DIR="${HARNESS_ROOT}/target"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

err()  { echo -e "${RED}[audit]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[audit]${NC} $*" >&2; }
log()  { echo -e "${GREEN}[audit]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $0 [depth]

Detect the target repo inside target/ and prepare audit paths.
The user must have already cloned the repo into target/.

Arguments:
  depth   quick|balanced|full (default: quick)

The script expects a single subdirectory in target/ (e.g. target/myrepo/).
If there's a .git inside target/ directly, that works too.

Examples:
  $0              # Quick audit
  $0 balanced     # Balanced depth

EOF
}

# Find the repo root inside target/
find_repo_root() {
    # Case 1: target/<name>/.git exists
    local candidates=()
    while IFS= read -r -d '' d; do
        candidates+=("$d")
    done < <(find "$TARGET_DIR" -maxdepth 2 -name ".git" -type d -print0 2>/dev/null)

    if [ ${#candidates[@]} -eq 0 ]; then
        err "No git repository found in target/"
        err "Clone a repo first: git clone <url> target/<name>"
        exit 1
    fi

    if [ ${#candidates[@]} -gt 1 ]; then
        warn "Multiple repos found in target/:"
        for c in "${candidates[@]}"; do
            warn "  $(dirname "$c" | sed "s|${TARGET_DIR}/||")"
        done
        err "Keep only one. Clean others: bash scripts/cleanup.sh target"
        exit 1
    fi

    # Return parent of .git
    dirname "${candidates[0]}"
}

main() {
    local depth="${1:-${VULNOPS_DEFAULT_DEPTH:-quick}}"
    case "$depth" in
        quick|balanced|full) ;;
        *) err "Invalid depth: ${depth}. Use quick, balanced, or full."; exit 1 ;;
    esac

    # ── Verify tools ──
    local tools_ok=true
    for tool in wraith poltergeist omp codegraph; do
        if [ -x "${HARNESS_ROOT}/bins/${tool}" ]; then
            local ver
            ver="$("${HARNESS_ROOT}/bins/${tool}" --version 2>/dev/null || echo 'unknown')"
            log "  ${tool}: ${ver}"
        else
            err "  ${tool}: NOT INSTALLED — run: bash scripts/install-tools.sh"
            tools_ok=false
        fi
    done
    # osv-scanner is a wraith dependency — warn but don't block
    if [ ! -x "${HARNESS_ROOT}/bins/osv-scanner" ]; then
        warn "  osv-scanner: NOT IN BINS/ — SCA scans may fail"
    fi
    if [ "$tools_ok" = false ]; then
        err "Missing tools. Install them first."
        exit 1
    fi

    # ── Find repo ──
    local clone_dir
    clone_dir="$(find_repo_root)"
    local repo_name
    repo_name="$(basename "$clone_dir")"

    # ── Verify it's readable ──
    if [ ! -r "$clone_dir" ]; then
        err "Cannot read: ${clone_dir}"
        exit 1
    fi

    # ── Compute repo_id ──
    local remote_url
    remote_url="$(cd "$clone_dir" && git remote get-url origin 2>/dev/null || echo "$clone_dir")"
    local short_hash
    short_hash="$(printf '%s' "$remote_url" | shasum | cut -c1-8)"
    local repo_id="${repo_name}-${short_hash}"

    local short_sha
    short_sha="$(cd "$clone_dir" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d)"

    local target_fingerprint
    target_fingerprint="$(python3 "${HARNESS_ROOT}/scripts/target-fingerprint.py" "$clone_dir")"

    local repo_scan_root="${HARNESS_ROOT}/scans/${repo_id}"
    local ctx="${HARNESS_ROOT}/.harness/audit-context.json"
    local reproduction_mode="${VULNOPS_REPRODUCTION_MODE:-off}"
    case "$reproduction_mode" in
        off|safe) ;;
        *) err "Invalid reproduction mode: ${reproduction_mode}"; exit 1 ;;
    esac
    local run_id=""
    local scan_base=""
    local resumed=false

    # Resume only the current incomplete v2 run for the same repository,
    # commit, depth, and exact working-tree fingerprint. Completed runs are
    # never read as audit input; a new isolated run is created instead.
    if [ -f "$ctx" ]; then
        local resume_fields
        resume_fields="$(python3 - "$ctx" "$clone_dir" "$short_sha" "$depth" "$target_fingerprint" "$reproduction_mode" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    doc = json.loads(path.read_text())
except Exception:
    raise SystemExit(0)
if doc.get("schema_version") != "2.0":
    raise SystemExit(0)
if str(doc.get("repo_path")) != sys.argv[2]:
    raise SystemExit(0)
if str(doc.get("short_sha")) != sys.argv[3] or str(doc.get("depth")) != sys.argv[4]:
    raise SystemExit(0)
if str(doc.get("target_fingerprint")) != sys.argv[5]:
    raise SystemExit(0)
if str(doc.get("reproduction_mode")) != sys.argv[6]:
    raise SystemExit(0)
scan_base = Path(str(doc.get("scan_base", "")))
manifest = scan_base / "run-manifest.json"
try:
    run = json.loads(manifest.read_text())
except Exception:
    raise SystemExit(0)
if run.get("status") in {"complete", "failed"}:
    raise SystemExit(0)
print(f"{doc.get('run_id', '')}\t{scan_base}")
PY
)"
        if [ -n "$resume_fields" ]; then
            IFS=$'\t' read -r run_id scan_base <<<"$resume_fields"
            resumed=true
        fi
    fi

    if [ -z "$scan_base" ]; then
        run_id="$(date -u +%Y%m%dT%H%M%SZ)-${short_sha}-$$"
        scan_base="${repo_scan_root}/runs/${run_id}"
    fi
    harness_require_allowed_output "$HARNESS_ROOT" "$scan_base"

    # ── Create scan directories ──
    mkdir -p "${scan_base}/repo-context"
    mkdir -p "${scan_base}/repo-context/research"
    mkdir -p "${scan_base}/sca/findings"
    mkdir -p "${scan_base}/sast/deepdive"
    mkdir -p "${scan_base}/sast/verify"
    mkdir -p "${scan_base}/sast/reproduction"
    mkdir -p "${scan_base}/sast/fixes"
    mkdir -p "${scan_base}/intelligence/codegraph-runs"
    mkdir -p "${scan_base}/intelligence"
    mkdir -p "${scan_base}/triage"
    mkdir -p "${scan_base}/report"
    mkdir -p "${scan_base}/intrusion/findings"
    mkdir -p "${scan_base}/secrets/findings"
    mkdir -p "${scan_base}/intrusion"
    mkdir -p "${scan_base}/intrusion/codegraph-runs"
    mkdir -p "${scan_base}/final-reconciliation"
    mkdir -p "${scan_base}/final-verification/results"

    # ── codegraph: required AST toolkit. Index lives under ${scan_base}/.codegraph
    # so two audits against different repos don't clobber each other's index.
    # ${clone_dir} is the actual checked-out target; the per-scan index is
    # the parallel branch the agents consult.
    if [ -x "${HARNESS_ROOT}/bins/codegraph" ]; then
        CODEGRAPH_TARGET_DIR="${clone_dir}" \
        CODEGRAPH_INDEX_DIR="${scan_base}/.codegraph" \
            bash "${HARNESS_ROOT}/scripts/setup-codegraph.sh" || true
    fi

    # ── Write v2 run manifest, task ledger, and audit context atomically ──
    local init_args=(
        --harness-root "$HARNESS_ROOT"
        --repo-path "$clone_dir"
        --scan-base "$scan_base"
        --run-id "$run_id"
        --repo-name "$repo_name"
        --remote-url "$remote_url"
        --repo-id "$repo_id"
        --commit "$short_sha"
        --depth "$depth"
        --target-fingerprint "$target_fingerprint"
        --reproduction-mode "$reproduction_mode"
        --model "${OMP_MODEL_SELECTOR:-${ON_PREM_MODEL_NAME:-unknown}}"
    )
    if [ "$resumed" = true ]; then
        init_args+=(--resume)
    fi
    python3 "${HARNESS_ROOT}/scripts/init-run.py" "${init_args[@]}"

    log ""
    log "Target detected: ${clone_dir}"
    log "  Repo ID:    ${repo_id}"
    log "  Commit:     ${short_sha}"
    log "  Scan base:  ${scan_base}"
    log "  Run ID:     ${run_id}"
    log "  Depth:      ${depth}"
    log "  Reproduction: ${reproduction_mode}"
    if [ "$resumed" = true ]; then
        log "  Resume:     current incomplete v2 run"
    fi
    log ""
    log "Context: ${ctx}"

}

main "$@"
