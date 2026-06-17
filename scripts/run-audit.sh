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
    local depth="${1:-quick}"
    case "$depth" in
        quick|balanced|full) ;;
        *) err "Invalid depth: ${depth}. Use quick, balanced, or full."; exit 1 ;;
    esac

    # ── Verify tools ──
    local tools_ok=true
    for tool in wraith poltergeist omp; do
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

    local scan_base="${HARNESS_ROOT}/scans/${repo_id}"
    harness_require_allowed_output "$HARNESS_ROOT" "$scan_base"

    # ── Create scan directories ──
    mkdir -p "${scan_base}/repo-context"
    mkdir -p "${scan_base}/sca/findings"
    mkdir -p "${scan_base}/sast/findings"
    mkdir -p "${scan_base}/sast/deepdive"
    mkdir -p "${scan_base}/sast/verify"
    mkdir -p "${scan_base}/secrets/findings"
    mkdir -p "${scan_base}/intelligence/graphify-runs"
    mkdir -p "${scan_base}/triage"
    mkdir -p "${scan_base}/report"
    mkdir -p "${scan_base}/intrusion/findings"
    mkdir -p "${scan_base}/final-reconciliation"

    # ── Write audit context ──
    local ctx="${HARNESS_ROOT}/.harness/audit-context.json"
    cat > "$ctx" <<ENDJSON
{
  "repo_name": "${repo_name}",
  "remote_url": "${remote_url}",
  "repo_id": "${repo_id}",
  "short_sha": "${short_sha}",
  "depth": "${depth}",
  "harness_root": "${HARNESS_ROOT}",
  "repo_path": "${clone_dir}",
  "scan_base": "${scan_base}",
  "paths": {
	    "repo_context": "${scan_base}/repo-context",
	    "repo_md": "${scan_base}/repo-context/repo.md",
	    "repo_context_json": "${scan_base}/repo-context/repo-context.json",
	    "security_surfaces_json": "${scan_base}/repo-context/security-surfaces.json",
	    "sca": "${scan_base}/sca",
	    "sca_raw_advisories": "${scan_base}/sca/raw-advisories.json",
	    "sast": "${scan_base}/sast",
	    "sast_threat_model": "${scan_base}/sast/threat-model.json",
	    "sast_threat_model_md": "${scan_base}/sast/threat-model.md",
	    "sast_task_manifest": "${scan_base}/sast/task-manifest.json",
	    "sast_decompose_md": "${scan_base}/sast/decompose.md",
	    "sast_deepdive": "${scan_base}/sast/deepdive",
	    "sast_verify": "${scan_base}/sast/verify",
	    "sast_raw_findings": "${scan_base}/sast/raw-findings.json",
	    "sast_verified_findings": "${scan_base}/sast/verified-findings.json",
	    "sast_dropped_findings": "${scan_base}/sast/dropped-findings.json",
	    "sast_coverage_ledger": "${scan_base}/sast/coverage-ledger.json",
	    "secrets": "${scan_base}/secrets",
	    "secrets_redacted_candidates": "${scan_base}/secrets/redacted-candidates.json",
	    "intelligence": "${scan_base}/intelligence",
	    "intelligence_evidence_corpus": "${scan_base}/intelligence/evidence-corpus.json",
	    "intelligence_attack_surface_map": "${scan_base}/intelligence/attack-surface-map.json",
	    "intelligence_graphify_plan": "${scan_base}/intelligence/graphify-intel-plan.json",
	    "intelligence_cards": "${scan_base}/intelligence/investigation-cards.json",
	    "intelligence_coverage_gaps": "${scan_base}/intelligence/coverage-gaps.json",
	    "intelligence_rule_gaps": "${scan_base}/intelligence/rule-gaps.json",
	    "intelligence_graphify_runs": "${scan_base}/intelligence/graphify-runs",
	    "triage": "${scan_base}/triage",
	    "intrusion_seeds": "${scan_base}/triage/intrusion-seeds.json",
	    "report": "${scan_base}/report",
	    "intrusion": "${scan_base}/intrusion",
	    "intrusion_findings": "${scan_base}/intrusion/findings",
	    "intrusion_enrichment": "${scan_base}/intrusion/enrichment.json",
	    "graphify_plan": "${scan_base}/intrusion/graphify-plan.json",
	    "graphify_runs": "${scan_base}/intrusion/graphify-runs",
	    "final_reconciliation": "${scan_base}/final-reconciliation",
	    "final_reconciliation_findings": "${scan_base}/final-reconciliation/findings.json",
	    "final_report_md": "${scan_base}/report/security-report.md",
	    "final_report_json": "${scan_base}/report/security-report.json"
  },
  "tools": {
    "wraith": "${HARNESS_ROOT}/bins/wraith",
    "poltergeist": "${HARNESS_ROOT}/bins/poltergeist",
    "omp": "${HARNESS_ROOT}/bins/omp",
    "osv_scanner": "${HARNESS_ROOT}/bins/osv-scanner",
    "run_wraith": "${HARNESS_ROOT}/scripts/run-wraith.sh",
    "run_poltergeist": "${HARNESS_ROOT}/scripts/run-poltergeist.sh",
    "run_graphify": "${HARNESS_ROOT}/scripts/run-graphify.sh",
    "build_intelligence": "${HARNESS_ROOT}/scripts/build-intelligence.py"
  },
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
ENDJSON

    log ""
    log "Target detected: ${clone_dir}"
    log "  Repo ID:    ${repo_id}"
    log "  Commit:     ${short_sha}"
    log "  Scan base:  ${scan_base}"
    log "  Depth:      ${depth}"
    log ""
    log "Context: ${ctx}"

    cat "$ctx"
}

main "$@"
