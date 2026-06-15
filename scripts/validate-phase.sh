#!/usr/bin/env bash
# Validate the required artifacts for one audit phase or SAST subphase.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <scan_base> <phase>" >&2
    exit 2
fi

SCAN_BASE="$1"
PHASE="$2"

harness_setup_containment "$HARNESS_ROOT"
harness_require_allowed_output "$HARNESS_ROOT" "$SCAN_BASE"

PYTHON="${HARNESS_ROOT}/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
    PYTHON="$(command -v python3 2>/dev/null || true)"
fi
if [ -z "$PYTHON" ]; then
    echo "[validate-phase] ERROR: python3 not found" >&2
    exit 1
fi

errors=0

err() {
    echo "[validate-phase] ERROR: $*" >&2
    errors=$((errors + 1))
}

check_file() {
    local path="$1"
    if [ ! -f "$path" ]; then
        err "missing: $path"
    fi
}

check_json() {
    local path="$1"
    check_file "$path"
    if [ -f "$path" ]; then
        "$PYTHON" -m json.tool "$path" >/dev/null || err "invalid JSON: $path"
    fi
}

check_manifest_status() {
    local path="$1"
    shift
    if [ ! -f "$path" ]; then
        return
    fi
    "$PYTHON" - "$path" "$@" <<'PY' || err "invalid terminal status in $path"
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
allowed = set(sys.argv[2:])
sys.exit(0 if manifest.get("status") in allowed else 1)
PY
}

case "$PHASE" in
    recon)
        check_file "${SCAN_BASE}/repo-context/repo.md"
        check_json "${SCAN_BASE}/repo-context/repo-context.json"
        check_json "${SCAN_BASE}/repo-context/phase-manifest.json"
        ;;
    sca)
        check_file "${SCAN_BASE}/sca/summary.md"
        check_json "${SCAN_BASE}/sca/raw-advisories.json"
        check_json "${SCAN_BASE}/sca/phase-manifest.json"
        ;;
    secrets)
        check_file "${SCAN_BASE}/secrets/summary.md"
        check_json "${SCAN_BASE}/secrets/redacted-candidates.json"
        check_json "${SCAN_BASE}/secrets/phase-manifest.json"
        ;;
    sast-threatmodel)
        check_file "${SCAN_BASE}/sast/threat-model.md"
        check_json "${SCAN_BASE}/sast/threat-model.json"
        ;;
    sast-decompose)
        check_file "${SCAN_BASE}/sast/decompose.md"
        check_json "${SCAN_BASE}/sast/task-manifest.json"
        ;;
    sast-deepdive)
        check_json "${SCAN_BASE}/sast/raw-findings.json"
        ;;
    sast-verify)
        check_json "${SCAN_BASE}/sast/verified-findings.json"
        check_json "${SCAN_BASE}/sast/dropped-findings.json"
        ;;
    sast)
        check_json "${SCAN_BASE}/sast/threat-model.json"
        check_json "${SCAN_BASE}/sast/task-manifest.json"
        check_json "${SCAN_BASE}/sast/raw-findings.json"
        check_json "${SCAN_BASE}/sast/verified-findings.json"
        check_json "${SCAN_BASE}/sast/dropped-findings.json"
        check_json "${SCAN_BASE}/sast/coverage-ledger.json"
        check_file "${SCAN_BASE}/sast/summary.md"
        check_json "${SCAN_BASE}/sast/phase-manifest.json"
        ;;
    triage)
        check_file "${SCAN_BASE}/triage/consolidated.md"
        check_json "${SCAN_BASE}/triage/findings.json"
        check_json "${SCAN_BASE}/triage/phase-manifest.json"
        ;;
    intrusion)
        check_file "${SCAN_BASE}/intrusion/summary.md"
        check_json "${SCAN_BASE}/intrusion/enrichment.json"
        check_json "${SCAN_BASE}/intrusion/phase-manifest.json"
        check_manifest_status "${SCAN_BASE}/intrusion/phase-manifest.json" ok degraded skipped failed
        ;;
    final-reconciliation)
        check_json "${SCAN_BASE}/final-reconciliation/findings.json"
        check_file "${SCAN_BASE}/final-reconciliation/summary.md"
        check_json "${SCAN_BASE}/final-reconciliation/phase-manifest.json"
        ;;
    report)
        check_file "${SCAN_BASE}/report/security-report.md"
        check_json "${SCAN_BASE}/report/security-report.json"
        check_json "${SCAN_BASE}/report/phase-manifest.json"
        ;;
    *)
        err "unknown phase: $PHASE"
        ;;
esac

if [ "$errors" -gt 0 ]; then
    echo "[validate-phase] ${PHASE} failed with ${errors} error(s)" >&2
    exit 1
fi

echo "[validate-phase] ${PHASE} artifacts present"
