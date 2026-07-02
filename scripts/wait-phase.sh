#!/usr/bin/env bash
# Wait for one phase to become artifact-complete, then run validate-phase.sh.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <scan_base> <phase> [timeout_seconds]" >&2
    exit 2
fi

SCAN_BASE="$1"
PHASE="$2"
TIMEOUT_SECONDS="${3:-900}"
INTERVAL_SECONDS="${WAIT_PHASE_INTERVAL_SECONDS:-5}"

harness_setup_containment "$HARNESS_ROOT"
harness_require_allowed_output "$HARNESS_ROOT" "$SCAN_BASE"

PYTHON="$(command -v python3 2>/dev/null || true)"
if [ -z "$PYTHON" ]; then
    echo "[wait-phase] ERROR: python3 not found" >&2
    exit 1
fi

required_paths() {
    case "$PHASE" in
        recon)
            printf '%s\n' \
                "${SCAN_BASE}/repo-context/repo.md" \
                "${SCAN_BASE}/repo-context/repo-context.json" \
                "${SCAN_BASE}/repo-context/phase-manifest.json"
            ;;
        sca)
            printf '%s\n' \
                "${SCAN_BASE}/sca/summary.md" \
                "${SCAN_BASE}/sca/raw-advisories.json" \
                "${SCAN_BASE}/sca/phase-manifest.json"
            ;;
        secrets)
            printf '%s\n' \
                "${SCAN_BASE}/secrets/summary.md" \
                "${SCAN_BASE}/secrets/redacted-candidates.json" \
                "${SCAN_BASE}/secrets/phase-manifest.json"
            ;;
        sast-threatmodel)
            printf '%s\n' \
                "${SCAN_BASE}/sast/threat-model.md" \
                "${SCAN_BASE}/sast/threat-model.json"
            ;;
        sast-decompose)
            printf '%s\n' \
                "${SCAN_BASE}/sast/decompose.md" \
                "${SCAN_BASE}/sast/task-manifest.json"
            ;;
        sast-deepdive)
            printf '%s\n' "${SCAN_BASE}/sast/raw-findings.json"
            ;;
        sast-verify)
            printf '%s\n' \
                "${SCAN_BASE}/sast/verified-findings.json" \
                "${SCAN_BASE}/sast/dropped-findings.json"
            ;;
        sast)
            printf '%s\n' \
                "${SCAN_BASE}/sast/threat-model.json" \
                "${SCAN_BASE}/sast/task-manifest.json" \
                "${SCAN_BASE}/sast/raw-findings.json" \
                "${SCAN_BASE}/sast/verified-findings.json" \
                "${SCAN_BASE}/sast/dropped-findings.json" \
                "${SCAN_BASE}/sast/coverage-ledger.json" \
                "${SCAN_BASE}/sast/summary.md" \
                "${SCAN_BASE}/sast/phase-manifest.json"
            ;;
        intelligence)
            printf '%s\n' \
                "${SCAN_BASE}/intelligence/evidence-corpus.json" \
                "${SCAN_BASE}/intelligence/attack-surface-map.json" \
                "${SCAN_BASE}/intelligence/intel-plan.json" \
                "${SCAN_BASE}/intelligence/investigation-cards.json" \
                "${SCAN_BASE}/intelligence/coverage-gaps.json" \
                "${SCAN_BASE}/intelligence/rule-gaps.json" \
                "${SCAN_BASE}/intelligence/summary.md" \
                "${SCAN_BASE}/intelligence/phase-manifest.json"
            ;;
        triage)
            printf '%s\n' \
                "${SCAN_BASE}/triage/consolidated.md" \
                "${SCAN_BASE}/triage/findings.json" \
                "${SCAN_BASE}/triage/intrusion-seeds.json" \
                "${SCAN_BASE}/triage/phase-manifest.json"
            ;;
        intrusion)
            printf '%s\n' \
                "${SCAN_BASE}/intrusion/summary.md" \
                "${SCAN_BASE}/intrusion/enrichment.json" \
                "${SCAN_BASE}/intrusion/intrusion-plan.json" \
                "${SCAN_BASE}/intrusion/phase-manifest.json"
            ;;
        final-reconciliation)
            printf '%s\n' \
                "${SCAN_BASE}/final-reconciliation/findings.json" \
                "${SCAN_BASE}/final-reconciliation/summary.md" \
                "${SCAN_BASE}/final-reconciliation/phase-manifest.json"
            ;;
        report)
            printf '%s\n' \
                "${SCAN_BASE}/report/security-report.md" \
                "${SCAN_BASE}/report/security-report.json" \
                "${SCAN_BASE}/report/phase-manifest.json"
            ;;
        *)
            echo "[wait-phase] ERROR: unknown phase: $PHASE" >&2
            exit 2
            ;;
    esac
}

files_exist() {
    local path
    while IFS= read -r path; do
        [ -f "$path" ] || return 1
    done < <(required_paths)
}

intrusion_terminal() {
    "$PYTHON" - "$SCAN_BASE" <<'PY'
import json
import sys
from pathlib import Path

scan = Path(sys.argv[1])
manifest_path = scan / "intrusion" / "phase-manifest.json"
enrichment_path = scan / "intrusion" / "enrichment.json"
plan_path = scan / "intrusion" / "intrusion-plan.json"
if not manifest_path.is_file() or not enrichment_path.is_file() or not plan_path.is_file():
    sys.exit(1)
try:
    manifest = json.loads(manifest_path.read_text())
    json.loads(enrichment_path.read_text())
    plan = json.loads(plan_path.read_text())
except Exception:
    sys.exit(1)
sys.exit(0 if manifest.get("status") == "ok" and plan.get("mode") == "targeted-ooda" else 1)
PY
}

phase_ready() {
    files_exist || return 1
    if [ "$PHASE" = "intrusion" ]; then
        intrusion_terminal || return 1
    fi
    return 0
}

start_epoch="$(date +%s)"
deadline=$((start_epoch + TIMEOUT_SECONDS))

while ! phase_ready; do
    now="$(date +%s)"
    if [ "$now" -ge "$deadline" ]; then
        echo "[wait-phase] ERROR: timed out waiting for ${PHASE} after ${TIMEOUT_SECONDS}s" >&2
        echo "[wait-phase] expected artifacts:" >&2
        required_paths >&2
        exit 1
    fi
    remaining=$((deadline - now))
    if [ "$remaining" -lt "$INTERVAL_SECONDS" ]; then
        sleep "$remaining"
    else
        sleep "$INTERVAL_SECONDS"
    fi
done

"${HARNESS_ROOT}/scripts/validate-phase.sh" "$SCAN_BASE" "$PHASE"
