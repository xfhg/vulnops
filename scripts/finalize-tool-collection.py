#!/usr/bin/env python3
"""Close the parallel scanner workers into one deterministic phase."""
from __future__ import annotations
import argparse,json,os
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def load(path:Path)->Any:return json.loads(path.read_text(encoding="utf-8"))
def write(path:Path,doc:object)->None:
    path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp");tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n");tmp.replace(path)
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("scan_base",type=Path);a=p.parse_args();root=Path(__file__).resolve().parent.parent;context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")));sca=load(a.scan_base/"tool-collection/sca-advisories.json");secrets=load(a.scan_base/"tool-collection/secrets-redacted.json");receipts=["tool-collection/wraith-receipt.json","tool-collection/poltergeist-receipt.json"]
    warnings=[]
    for ref in receipts:
        receipt=load(a.scan_base/ref)
        if receipt.get("status")!="ok" or receipt.get("parse_status")!="ok":raise SystemExit(f"tool receipt is not healthy: {ref}")
        warnings.extend(str(x) for x in receipt.get("warnings",[]))
    collection={"schema_version":"2.0","run_id":str(context.get("run_id","")),"sca_ref":"tool-collection/sca-advisories.json","secrets_ref":"tool-collection/secrets-redacted.json","receipts":receipts,"warnings":warnings};write(a.scan_base/"tool-collection/collection.json",collection)
    (a.scan_base/"tool-collection/summary.md").write_text(f"# Tool Collection\n\n- Dependency advisories: {sca.get('advisory_count',0)}\n- Redacted secret candidates: {secrets.get('candidate_count',0)}\n- Healthy tool receipts: {len(receipts)}\n")
    manifest={"phase":"tool-collection","status":"degraded" if warnings else "ok","started_at":now(),"completed_at":now(),"inputs":["repo-context/repo-context.json"],"outputs":["tool-collection/collection.json","tool-collection/sca-advisories.json","tool-collection/secrets-redacted.json",*receipts,"tool-collection/summary.md"],"coverage":{"dependency_advisories":sca.get("advisory_count",0),"secret_candidates":secrets.get("candidate_count",0)},"tool_versions":{},"warnings":warnings,"errors":[]};write(a.scan_base/"tool-collection/phase-manifest.json",manifest);return 0
if __name__=="__main__":raise SystemExit(main())
