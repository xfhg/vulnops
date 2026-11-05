#!/usr/bin/env bash
# Read recorded completion and operational detail without replaying historical work.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
PYTHON="$(command -v python3 2>/dev/null || true)"
if [ -z "$PYTHON" ]; then echo "[audit-status] python3 not found" >&2; exit 1; fi
SCAN_BASE="${1:-}"
if [ -z "$SCAN_BASE" ]; then
    SCAN_BASE="$("$PYTHON" - "$HARNESS_ROOT" <<'PY'
import json,os,sys
from pathlib import Path
path=Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",str(Path(sys.argv[1])/".harness/audit-context.json")))
try:
    value=json.loads(path.read_text())
    if not isinstance(value,dict) or not isinstance(value.get("scan_base"),str) or not value["scan_base"]:
        raise ValueError("missing or invalid scan_base")
    print(value["scan_base"])
except (OSError,ValueError) as exc:
    print(f"[audit-status] {path}: {exc}",file=sys.stderr)
    raise SystemExit(2)
PY
)"
fi
harness_require_allowed_output "$HARNESS_ROOT" "$SCAN_BASE"
"$PYTHON" - "$HARNESS_ROOT" "$SCAN_BASE" <<'PY'
import importlib.util,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();scan=Path(sys.argv[2]).resolve()
sys.path.insert(0,str(root/"scripts"))
from run_lifecycle import audit_phases
spec=importlib.util.spec_from_file_location("audit_read",root/"scripts/validate-scan-v2.py")
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
print("Audit Status")
print(f"- Scan: {scan}")
try:
    if (scan/"report/security-report.json").is_file():
        from report_bundle import publication_identity
        publication=publication_identity(scan,expected_kind="audit")
        run={"status":"complete","run_id":publication["run_id"],"repository":publication["repository"]}
    else:
        run=reader.read_state(scan)
    print(f"- State: {run['status']}")
    print(f"- Run ID: {run['run_id']}")
    print(f"- Application: {run.get('repository','unknown')}")
    if run['status']!='complete':
        for phase in audit_phases(run):print(f"- {phase}: {run['phases'][phase]}")
        unfinished=next((phase for phase in audit_phases(run) if run['phases'][phase] not in reader.TERMINAL),None)
        if unfinished:print(f"- Resume boundary: {unfinished}")
        ledger_path=scan/"task-ledger.json"
        if ledger_path.exists():
            ledger=reader.read_document(scan,"task-ledger.json")
            if not isinstance(ledger.get('tasks'),list):raise ValueError('task-ledger.json: missing or invalid tasks')
            for row in ledger['tasks']:
                if isinstance(row,dict) and row.get('status')=='running':
                    print(f"- Active phase: {row.get('phase','unknown')} ({row.get('id','unknown')})")
        if run.get('error'):print(f"- Error: {run['error']}")
    if run['status']=='complete':
        report=reader.read_publication(scan)
        summary=report['summary']
        print(f"- Findings: {summary.get('total','unknown')} assessed dossiers")
        print(f"- Confirmed within assessed scope: {summary.get('confirmed','unknown')}")
        print(f"- Environment required (unconfirmed): {summary.get('needs_environment','unknown')}")
        assessment=report.get('assessment',{})
        for scope in assessment.get('scopes',[]):
            print(f"- Assessed scope: {scope['assessment_id']} (started {scope.get('started_at') or 'unknown'})")
        print(f"- Published: {report.get('date','unknown')}")
        print('- Later-source applicability: not inferred from publication')
        counts=report.get('diversity_counts',{})
        print(f"- Finding model diversity (reported cohort): {counts.get('diverse',0)} diverse, {counts.get('same_model',0)} same-model")
        print(f"- Final report: {scan/'report/security-report.md'}")
        print(f"- JSON report: {scan/'report/security-report.json'}")
    print('- Validation: recorded state only; historical phases not replayed')
except (ValueError,OSError) as exc:
    print(f"[audit-status] {exc}",file=sys.stderr)
    raise SystemExit(1)
raise SystemExit(0 if run['status']=='complete' else 1)
PY
