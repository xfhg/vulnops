#!/usr/bin/env bash
# run-audit.sh — Discover the application repositories in target/ and compute all audit paths
# The user populates target/ manually. This script only reads those working trees.
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
INVENTORY_FILE=""
export VULNOPS_LAUNCHER_PID="${VULNOPS_LAUNCHER_PID:-$PPID}"

cleanup_inventory() {
    if [ -n "$INVENTORY_FILE" ]; then
        rm -f -- "$INVENTORY_FILE"
    fi
}
trap cleanup_inventory EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

err()  { echo -e "${RED}[audit]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[audit]${NC} $*" >&2; }
log()  { echo -e "${GREEN}[audit]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $0 [--fresh] [--no-codegraph] [--application-name <name>] [depth]

Detect the application source beneath target/ and prepare audit paths. The
application may be one Git repository or a set of repositories. Every source
reference is relative to the common application source root.

Options:
  --fresh                   Start a new audit, preserving all previous run artifacts.
  --no-codegraph            Skip the run-local Codegraph snapshot and graph queries.
  --application-name NAME   Stable display name for a multi-repository application.

Arguments:
  depth                     quick|balanced|full (default: harness.default_depth)

Examples:
  $0
  $0 --application-name payments balanced
  $0 --no-codegraph --application-name payments balanced

EOF
}

# Repository discovery and identity are centralized in target-inventory.py so
# initialization, resume, and validation use the same ordered repository set.

main() {
    local codegraph_mode="enabled"
    local codegraph_limitation=""
    local depth="${VULNOPS_DEFAULT_DEPTH:-quick}"
    local application_name="${VULNOPS_APPLICATION_NAME:-}"
    local fresh="${VULNOPS_AUDIT_FRESH:-0}"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --fresh)
                fresh=1
                shift ;;
            --no-codegraph)
                codegraph_mode="disabled"
                codegraph_limitation="Codegraph explicitly disabled; graph-assisted coverage was not performed."
                shift ;;
            --application-name)
                if [ "$#" -lt 2 ]; then err "--application-name requires a value"; exit 1; fi
                application_name="$2"
                shift 2
                ;;
            quick|balanced|full) depth="$1"; shift ;;
            -h|--help) usage; return 0 ;;
            *) err "Invalid argument: $1"; usage >&2; exit 1 ;;
        esac
    done

    # ── Verify tools ──
    local tools_ok=true
    for tool in wraith poltergeist omp osv-scanner; do
        if [ -x "${HARNESS_ROOT}/bins/${tool}" ]; then
            local ver
            ver="$("${HARNESS_ROOT}/bins/${tool}" --version 2>/dev/null || echo 'unknown')"
            log "  ${tool}: ${ver}"
        else
            err "  ${tool}: NOT INSTALLED — run: bash scripts/install-tools.sh"
            tools_ok=false
        fi
    done
    if [ "$codegraph_mode" = "enabled" ]; then
        if [ -x "${HARNESS_ROOT}/bins/codegraph" ]; then
            log "  codegraph: available; version and indexing checked during bounded preparation"
        else
            codegraph_mode="disabled"
            codegraph_limitation="Codegraph binary is unavailable; graph-assisted coverage was not performed."
            warn "  ${codegraph_limitation} Continuing source-only."
        fi
    else
        warn "  codegraph: disabled by explicit --no-codegraph option"
    fi
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
        log "  package: development tree with complete OSV snapshot"
    fi
    if [ "$(uname -s)" = "Linux" ] && [ "$network_mode" = "enforced" ] \
        && ! "${HARNESS_ROOT}/scripts/probe-agent-isolation.sh" >/dev/null; then
        err "Enforced agent egress requires working bubblewrap network isolation."
        exit 1
    fi
    if ! VULNOPS_CODEGRAPH_MODE="$codegraph_mode" bash "${HARNESS_ROOT}/scripts/probe-toolchain.sh" >/dev/null; then
        err "Audit toolchain failed its contained functional probe."
        exit 1
    fi
    if [ "$codegraph_mode" = "enabled" ] && [ -s "${HARNESS_ROOT}/.harness/probes/toolchain/codegraph-limitation.txt" ]; then
        codegraph_mode="disabled"
        codegraph_limitation="$(<"${HARNESS_ROOT}/.harness/probes/toolchain/codegraph-limitation.txt")"
        warn "  ${codegraph_limitation} Continuing source-only."
    fi
    log "  toolchain: functional contracts passed"

    # ── Discover the application repository set ──
    INVENTORY_FILE="${HARNESS_ROOT}/.harness/tmp/target-inventory.$$.json"
    local inventory_file="$INVENTORY_FILE"
    mkdir -p "$(dirname "$inventory_file")"
    local inventory_args=("$TARGET_DIR" --output "$inventory_file")
    if [ -n "$application_name" ]; then
        inventory_args+=(--application-name "$application_name")
    fi
    if ! python3 "${HARNESS_ROOT}/scripts/target-inventory.py" "${inventory_args[@]}"; then
        err "Could not discover a valid application repository set beneath target/."
        exit 1
    fi
    local inventory_fields=()
    while IFS= read -r -d '' value; do
        inventory_fields+=("$value")
    done < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); values=(d["source_root"],d["application_name"],d["remote_url"],d["application_id"],d["revision"],str(d["repository_count"])); sys.stdout.buffer.write(b"\0".join(str(v).encode() for v in values)+b"\0")' "$inventory_file")
    if [ "${#inventory_fields[@]}" -ne 6 ]; then
        err "Target inventory did not provide the required application identity."
        exit 1
    fi
    local clone_dir="${inventory_fields[0]}"
    local repo_name="${inventory_fields[1]}"
    local remote_url="${inventory_fields[2]}"
    local repo_id="${inventory_fields[3]}"
    local short_sha="${inventory_fields[4]}"
    local repository_count="${inventory_fields[5]}"

    if [ ! -r "$clone_dir" ]; then
        err "Cannot read application source root: ${clone_dir}"
        exit 1
    fi

    local repo_scan_root="${HARNESS_ROOT}/scans/${repo_id}"
    local ctx="${VULNOPS_AUDIT_CONTEXT:-${HARNESS_ROOT}/.harness/audit-context.json}"
    local reproduction_mode="${VULNOPS_REPRODUCTION_MODE:-off}"
    case "$reproduction_mode" in
        off|safe) ;;
        *) err "Invalid reproduction mode: ${reproduction_mode}"; exit 1 ;;
    esac
    local run_id=""
    local scan_base=""
    local resumed=false
    local resume_mode=""

    # Fresh skips old progress, but repeated initialization in its owning launcher
    # retains the run already selected by that session.
    local resume_fields
    local resume_args=("$ctx")
    if [ "$fresh" = "1" ]; then
        resume_args+=(--fresh)
    fi
    resume_fields="$(python3 "${HARNESS_ROOT}/scripts/resume-run.py" "${resume_args[@]}")"
    if [ -n "$resume_fields" ]; then
        IFS=$'\t' read -r run_id scan_base resume_mode <<<"$resume_fields"
        resumed=true
    fi

    if [ -z "$scan_base" ]; then
        run_id="$(date -u +%Y%m%dT%H%M%SZ)-${short_sha}-$$"
        scan_base="${repo_scan_root}/runs/${run_id}"
    fi
    harness_require_allowed_output "$HARNESS_ROOT" "$scan_base"




    # ── Write schema 2.0 run manifest, task ledger, and audit context atomically ──
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
        --repositories-file "$inventory_file"
        --reproduction-mode "$reproduction_mode"
        --network-mode "$network_mode"
        --codegraph-mode "$codegraph_mode"
        --codegraph-limitation "$codegraph_limitation"
        --prepare-codegraph
    )
    if [ "$resumed" = true ]; then
        init_args+=(--resume)
    fi
    python3 "${HARNESS_ROOT}/scripts/init-run.py" "${init_args[@]}" >/dev/null
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
    cat "$ctx"

    log ""
    log "Application source: ${clone_dir}"
    log "  App ID:      ${repo_id}"
    log "  Revision:    ${short_sha}"
    log "  Repositories: ${repository_count}"
    log "  Scan base:    ${scan_base}"
    log "  Run ID:       ${run_id}"
    log "  Depth:      ${depth}"
    log "  Reproduction: ${reproduction_mode}"
    log "  Agent egress: ${network_mode}"
    if [ "$resumed" = true ]; then
        log "  Resume:     current recoverable VulnOps V5 run (${resume_mode})"
    fi
    log ""
    log "Context: ${ctx}"

}

main "$@"
