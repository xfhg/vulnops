#!/usr/bin/env python3
"""Close synthesis without a model only when no candidate source exists."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from pathlib import Path
def load(path:Path):return json.loads(path.read_text(encoding="utf-8"))
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("scan_base",type=Path);a=p.parse_args();root=Path(__file__).resolve().parent.parent;verified=load(a.scan_base/"sast/verified-findings.json");intrusion=load(a.scan_base/"intrusion/intrusion-results.json")
    candidates=[candidate for result in intrusion.get("results",[]) for candidate in result.get("candidates",[])]
    if verified or candidates:
        print("[empty-synthesis] candidate sources exist; model synthesis is required",file=sys.stderr);return 2
    context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")));path=a.scan_base/"synthesis/findings.json";path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps({"schema_version":"2.0","run_id":str(context.get("run_id","")),"findings":[]},indent=2,sort_keys=True)+"\n")
    return subprocess.run([sys.executable,str(root/"scripts/finalize-synthesis.py"),str(a.scan_base)],check=False).returncode
if __name__=="__main__":raise SystemExit(main())
