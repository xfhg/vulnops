#!/usr/bin/env python3
"""Close synthesis without a model only when no candidate source exists."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from pathlib import Path
from intrusion_contract import composition_resolved
from evidence_accounting import synthesis_inputs
from dossier_contract import objective_assessments
from run_lifecycle import require_active_phase
def load(path:Path):return json.loads(path.read_text(encoding="utf-8"))
def requires_synthesis(scan:Path,verified,intrusion:dict)->bool:
    candidates=[candidate for result in intrusion.get("results",[]) for candidate in result.get("candidates",[])]
    return bool(verified or candidates or synthesis_inputs(scan) or not composition_resolved(intrusion))
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("scan_base",type=Path);a=p.parse_args();root=Path(__file__).resolve().parent.parent;verified=load(a.scan_base/"sast/verified-findings.json");intrusion=load(a.scan_base/"intrusion/intrusion-results.json")
    context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")))
    try:
        require_active_phase(a.scan_base,context,"synthesis")
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print(f"[empty-synthesis] {exc}",file=sys.stderr);return 1
    if requires_synthesis(a.scan_base,verified,intrusion):
        print("[empty-synthesis] candidate or unresolved composition sources exist; synthesis is required",file=sys.stderr);return 2
    path=a.scan_base/"synthesis/findings.json";path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps({"schema_version":"2.0","run_id":str(context.get("run_id","")),"findings":[],"objective_assessments":objective_assessments(a.scan_base,[])},indent=2,sort_keys=True)+"\n")
    return subprocess.run([sys.executable,str(root/"scripts/finalize-synthesis.py"),str(a.scan_base)],check=False).returncode
if __name__=="__main__":raise SystemExit(main())
