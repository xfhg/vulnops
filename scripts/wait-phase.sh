#!/usr/bin/env bash
# Manual/CI recovery helper. Main orchestration uses OMP yield and IRC.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then echo "Usage: $0 <scan_base> <phase> [timeout_seconds]" >&2; exit 2; fi
scan="$1";phase="$2";timeout="${3:-900}";interval="${WAIT_PHASE_INTERVAL_SECONDS:-5}"
harness_setup_containment "$HARNESS_ROOT";harness_require_allowed_output "$HARNESS_ROOT" "$scan"
case "$phase" in
  recon) directory="repo-context"; artifact="repo-context/security-surfaces.json" ;;
  tool-collection) directory="tool-collection"; artifact="tool-collection/collection.json" ;;
  sast) directory="sast"; artifact="sast/verified-findings.json" ;;
  campaign-planning) directory="campaign-planning"; artifact="campaign-planning/campaign-plan.json" ;;
  intrusion) directory="intrusion"; artifact="intrusion/intrusion-results.json" ;;
  synthesis) directory="synthesis"; artifact="synthesis/findings.json" ;;
  final-verification) directory="final-verification"; artifact="final-verification/findings.json" ;;
  report) directory="report"; artifact="report/security-report.json" ;;
  *) echo "[wait-phase] ERROR: unknown canonical phase: $phase" >&2; exit 2 ;;
esac
deadline=$((SECONDS+timeout))
while [ "$SECONDS" -lt "$deadline" ]; do
  if [ -f "$scan/$artifact" ] && [ -f "$scan/$directory/phase-manifest.json" ]; then
    exec bash "${HARNESS_ROOT}/scripts/validate-phase.sh" "$scan" "$phase"
  fi
  sleep "$interval"
done
echo "[wait-phase] ERROR: timed out waiting for $phase" >&2
exit 1
