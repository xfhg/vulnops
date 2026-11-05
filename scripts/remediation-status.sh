#!/usr/bin/env bash
# Print a compact read-only view of one linked remediation execution.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
if [ "$#" -ne 1 ]; then echo "Usage: $0 <remediation-base>" >&2; exit 2; fi
BASE="$1"
harness_require_allowed_output "$HARNESS_ROOT" "$BASE"
python3 - "$HARNESS_ROOT" "$BASE" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();base=Path(sys.argv[2]).resolve()
sys.path.insert(0,str(root/"scripts"))
from remediation_common import load_object,read_remediation
try:
    if (base/"remediation.json").is_file():
        bundle=read_remediation(base)
        identity=bundle
        source=bundle["source"]["scan_ref"]
        counts=bundle["counts"]
        complete=True
    else:
        identity=load_object(base/"remediation-manifest.json")
        source=identity.get("source_scan_ref","unknown")
        counts={}
        complete=False
    print("Linked Remediation Status")
    print(f"- Base: {base}")
    print(f"- Remediation ID: {identity.get('remediation_id','unknown')}")
    print(f"- Source audit: {source}")
    print(f"- State: {identity.get('status','unknown')}")
    print(f"- Model: {identity.get('model','unknown')}")
    print(f"- Patch ready: {counts.get('patch_ready','unknown')}")
    print(f"- Manual required: {counts.get('manual_required','unknown')}")
    print(f"- Bundle: {base/'remediation.json'}")
    print(f"- Summary: {base/'summary.md'}")
    print("- Validation: recorded publication only; no current-source or apply-check replay")
except (OSError,ValueError) as exc:
    print(f"[remediation-status] {exc}",file=sys.stderr)
    raise SystemExit(1)
raise SystemExit(0 if complete else 1)
PY
