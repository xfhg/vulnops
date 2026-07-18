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
import json, os, subprocess, sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();base=Path(sys.argv[2]).resolve()
def load(path):
    try:return json.loads(path.read_text())
    except Exception:return {}
manifest=load(base/"remediation-manifest.json");bundle=load(base/"remediation.json")
counts=bundle.get("counts",{}) if isinstance(bundle,dict) else {}
print("Linked Remediation Status")
print(f"- Base: {base.relative_to(root) if base.is_relative_to(root) else base}")
print(f"- Remediation ID: {manifest.get('remediation_id','unknown')}")
print(f"- Source audit: {manifest.get('source_scan_ref','unknown')}")
print(f"- State: {manifest.get('status','unknown')}")
print(f"- Model: {manifest.get('model','unknown')}")
print(f"- Patch ready: {counts.get('patch_ready','unknown')}")
print(f"- Manual required: {counts.get('manual_required','unknown')}")
print(f"- Bundle: {base/'remediation.json'}")
print(f"- Summary: {base/'summary.md'}")
context=load(Path(os.environ.get("VULNOPS_REMEDIATION_CONTEXT",root/".harness/remediation-context.json")))
validation=None
if Path(str(context.get("remediation_base",""))).resolve()==base:
    validation=subprocess.run([sys.executable,str(root/"scripts/validate-remediation.py"),str(base)],cwd=root,capture_output=True,text=True)
print(f"- Validation: {'ok' if validation and validation.returncode==0 else 'not current' if validation is None else 'failed'}")
raise SystemExit(0 if manifest.get("status") in {"ok","degraded"} and validation and validation.returncode==0 else 1)
PY
