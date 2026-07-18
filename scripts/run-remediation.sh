#!/usr/bin/env bash
# Initialize or recover one linked remediation execution for a completed audit.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <completed-scan-base>" >&2
    exit 2
fi
eval "$("${HARNESS_ROOT}/scripts/load-config.sh")"
exec python3 "${HARNESS_ROOT}/scripts/init-remediation.py" "$1"
