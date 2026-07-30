#!/usr/bin/env bash
# run-audit.sh — Detect the repo in target/ and compute all audit paths
# The user clones manually. This script just reads what's there.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
# run-audit.sh is a documented standalone entry point as well as an OMP child.
# Load canonical configuration here so model identity never depends on a parent
# shell having invoked run.sh first.
eval "$("${HARNESS_ROOT}/scripts/load-config.sh")"
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
  depth   quick|balanced|full (default: harness.default_depth)

The script expects a single subdirectory in target/ (e.g. target/myrepo/).
If there's a .git inside target/ directly, that works too.

Examples:
  $0              # Configured default depth
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
    for tool in wraith poltergeist omp codegraph osv-scanner; do
        if [ -x "${HARNESS_ROOT}/bins/${tool}" ]; then
            local ver
            ver="$("${HARNESS_ROOT}/bins/${tool}" --version 2>/dev/null || echo 'unknown')"
            log "  ${tool}: ${ver}"
        else
            err "  ${tool}: NOT INSTALLED — run: bash scripts/install-tools.sh"
            tools_ok=false
        fi
    done
    if [ "$tools_ok" = false ]; then
        err "Missing tools. Install them first."
        exit 1
    fi
    local network_mode="${VULNOPS_LINUX_AGENT_EGRESS:-enforced}"
    case "$network_mode" in
        enforced|policy_only) ;;
        *) err "Invalid agent egress mode: ${network_mode}"; exit 1 ;;
    esac
    if [ "$(uname -s)" = "Darwin" ] && [ "$network_mode" != "policy_only" ]; then
        err "Darwin requires explicit policy_only agent egress."
        exit 1
    fi
    if [ -f "${HARNESS_ROOT}/offline-pack-manifest.json" ]; then
        if ! bash "${HARNESS_ROOT}/setup.sh" verify >/dev/null; then
            err "Offline package verification failed."
            exit 1
        fi
        log "  package: immutable inventory and offline prerequisites verified"
    else
        if ! python3 "${HARNESS_ROOT}/scripts/osv_snapshot.py" verify \
            --lock "${HARNESS_ROOT}/config/osv-snapshot.lock.json" \
            --cache-root "${HARNESS_ROOT}/.harness/osv-db"; then
            err "Complete checksum-pinned OSV snapshot is unavailable."
            exit 1
        fi
        if [ "$(uname -s)" = "Linux" ] && [ "$network_mode" = "enforced" ] \
            && ! "${HARNESS_ROOT}/scripts/probe-agent-isolation.sh" >/dev/null; then
            err "Enforced agent egress requires working bubblewrap network isolation."
            exit 1
        fi
        log "  package: development tree with complete OSV snapshot"
    fi
    if ! bash "${HARNESS_ROOT}/scripts/probe-toolchain.sh" >/dev/null; then
        err "Audit toolchain failed its contained functional probe."
        exit 1
    fi
    log "  toolchain: functional contracts passed"

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
    short_hash="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:8])' "$remote_url")"
    local repo_id="${repo_name}-${short_hash}"

    local short_sha
    short_sha="$(cd "$clone_dir" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d)"

    local target_fingerprint
    target_fingerprint="$(python3 "${HARNESS_ROOT}/scripts/target-fingerprint.py" "$clone_dir")"

    local repo_scan_root="${HARNESS_ROOT}/scans/${repo_id}"
    local ctx="${HARNESS_ROOT}/.harness/audit-context.json"
    local reproduction_mode="${VULNOPS_REPRODUCTION_MODE:-off}"
    local primary_model="${OMP_MODEL_SELECTOR:-${ON_PREM_MODEL_NAME:-unknown}}"
    local orchestrator_model="${OMP_ORCHESTRATOR_MODEL_SELECTOR:-${primary_model}}"
    local task_model="${OMP_TASK_MODEL_SELECTOR:-${primary_model}}"
    local slow_model="${OMP_SLOW_MODEL_SELECTOR:-${primary_model}}"
    local smol_model="${OMP_SMOL_MODEL_SELECTOR:-${primary_model}}"
    local verifier_model="${OMP_VERIFIER_MODEL_SELECTOR:-${primary_model}}"
    case "$reproduction_mode" in
        off|safe) ;;
        *) err "Invalid reproduction mode: ${reproduction_mode}"; exit 1 ;;
    esac
    local run_id=""
    local scan_base=""
    local resumed=false
    local resume_mode=""

    # Resume only the current incomplete v2 run for the same repository,
    # commit, depth, and exact working-tree fingerprint. Completed runs are
    # never read as audit input; a new isolated run is created instead.
    if [ -f "$ctx" ]; then
        local resume_fields
        resume_fields="$(python3 "${HARNESS_ROOT}/scripts/resume-run.py" \
            "$ctx" "$clone_dir" "$short_sha" "$depth" "$target_fingerprint" \
            "$reproduction_mode" "$primary_model" "$orchestrator_model" \
            "$task_model" "$slow_model" "$smol_model" "$verifier_model" \
            --network-mode "$network_mode")"
        if [ -n "$resume_fields" ]; then
            IFS=$'\t' read -r run_id scan_base resume_mode <<<"$resume_fields"
            resumed=true
        fi
    fi

    if [ -z "$scan_base" ]; then
        run_id="$(date -u +%Y%m%dT%H%M%SZ)-${short_sha}-$$"
        scan_base="${repo_scan_root}/runs/${run_id}"
    fi
    harness_require_allowed_output "$HARNESS_ROOT" "$scan_base"

    if [ "$resume_mode" = "recover" ]; then
        local recovery_fields recovery_phase retained_count cleared_count
        recovery_fields="$(python3 "${HARNESS_ROOT}/scripts/recover-run.py" "$scan_base" "$ctx" "$depth")"
        IFS=$'\t' read -r recovery_phase retained_count cleared_count <<<"$recovery_fields"
        log "  Recovery:   reset ${recovery_phase}; retained ${retained_count} validated phase(s), cleared ${cleared_count} phase(s)"
    fi

    # ── Create scan directories ──
    mkdir -p "${scan_base}/repo-context"
    mkdir -p "${scan_base}/repo-context/research"
    mkdir -p "${scan_base}/tool-collection"
    mkdir -p "${scan_base}/sast/deepdive"
    mkdir -p "${scan_base}/sast/hunt-tasks"
    mkdir -p "${scan_base}/sast/verify"
    mkdir -p "${scan_base}/sast/reproduction"
    mkdir -p "${scan_base}/campaign-planning"
    mkdir -p "${scan_base}/report"
    mkdir -p "${scan_base}/intrusion/results"
    mkdir -p "${scan_base}/intrusion/codegraph-runs"
    mkdir -p "${scan_base}/synthesis"
    mkdir -p "${scan_base}/final-verification/results"

    # ── codegraph indexes an immutable harness-local source snapshot. The
    # upstream CLI stores its database beneath the indexed project, so it must
    # never be pointed at the read-only target checkout.
    if [ -x "${HARNESS_ROOT}/bins/codegraph" ]; then
        CODEGRAPH_TARGET_DIR="${clone_dir}" \
        CODEGRAPH_RUNTIME_DIR="${HARNESS_ROOT}/.harness/codegraph/${run_id}" \
            bash "${HARNESS_ROOT}/scripts/setup-codegraph.sh"
    fi
    local post_index_fingerprint
    post_index_fingerprint="$(python3 "${HARNESS_ROOT}/scripts/target-fingerprint.py" "$clone_dir")"
    if [ "$post_index_fingerprint" != "$target_fingerprint" ]; then
        err "Target working tree changed while preparing the Codegraph snapshot."
        exit 1
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
        --network-mode "$network_mode"
        --model "$primary_model"
        --orchestrator-model "$orchestrator_model"
        --task-model "$task_model"
        --slow-model "$slow_model"
        --smol-model "$smol_model"
        --verifier-model "$verifier_model"
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
    log "  Agent egress: ${network_mode}"
    if [ "$resumed" = true ]; then
        log "  Resume:     current recoverable canonical v2 run (${resume_mode})"
    fi
    log ""
    log "Context: ${ctx}"

}

main "$@"
