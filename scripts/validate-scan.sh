#!/usr/bin/env bash
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
if [ "$#" -ne 1 ]; then echo "Usage: $0 <scan_base>" >&2; exit 2; fi
harness_setup_containment "$HARNESS_ROOT"
harness_require_allowed_output "$HARNESS_ROOT" "$1"
exec python3 "${HARNESS_ROOT}/scripts/validate-scan-v2.py" "$HARNESS_ROOT" "$1"
