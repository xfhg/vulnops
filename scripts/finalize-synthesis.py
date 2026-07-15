#!/usr/bin/env python3
"""Close model-authored synthesis after strict schema validation."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def write(path:Path,doc:object)->None:
    path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp");tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n");tmp.replace(path)
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("scan_base",type=Path);a=p.parse_args();root=Path(__file__).resolve().parent.parent;context=json.loads(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")).read_text());path=a.scan_base/"synthesis/findings.json"
    result=subprocess.run([sys.executable,str(root/"scripts/validate-json.py"),str(root/"schemas/v2/synthesis-findings.schema.json"),str(path)],capture_output=True,text=True,check=False)
    if result.returncode:print(result.stderr,file=sys.stderr);return 1
    findings=json.loads(path.read_text()).get("findings",[]);counts={name:sum(x.get("origin")==name for x in findings) for name in ("standalone_known","known_impact_expansion","composite_chain","independent_discovery","cross_evidence_discovery")};needs=sum(x.get("status")=="needs_environment" for x in findings)
    (a.scan_base/"synthesis/summary.md").write_text("# Synthesis\n\n"+"\n".join(f"- {k.replace('_',' ').title()}: {v}" for k,v in counts.items())+f"\n- Needs environment: {needs}\n")
    manifest={"phase":"synthesis","status":"degraded" if needs else "ok","started_at":now(),"completed_at":now(),"inputs":["campaign-planning/evidence-index.json","intrusion/intrusion-results.json","sast/verified-findings.json"],"outputs":["synthesis/findings.json","synthesis/summary.md"],"coverage":{"findings":len(findings),"needs_environment":needs,**counts},"tool_versions":{"primary_model":str(context.get("model","unknown"))},"warnings":[],"errors":[]};write(a.scan_base/"synthesis/phase-manifest.json",manifest);return 0
if __name__=="__main__":raise SystemExit(main())
