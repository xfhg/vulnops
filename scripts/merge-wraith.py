#!/usr/bin/env python3
"""Merge per-lockfile normalized Wraith documents without raw artifacts."""
from __future__ import annotations
import argparse,hashlib,json,os,subprocess
from datetime import datetime,timezone
from pathlib import Path
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def write(path:Path,doc:object)->bytes:
    data=json.dumps(doc,indent=2,sort_keys=True).encode()+b"\n";path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp");tmp.write_bytes(data);tmp.replace(path);return data
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--receipt",type=Path,required=True);p.add_argument("--input-receipt",type=Path,action="append",default=[]);p.add_argument("inputs",type=Path,nargs="*");a=p.parse_args();started=now();advisories={};packages=0
    for path in a.inputs:
        doc=json.loads(path.read_text());packages+=int(doc.get("packages_scanned",0))
        for item in doc.get("advisories",[]):advisories[item["id"]]=item
    databases={}
    for receipt_path in a.input_receipt:
        receipt=json.loads(receipt_path.read_text())
        if receipt.get("status")!="ok" or receipt.get("parse_status")!="ok":raise SystemExit("input Wraith receipt is unhealthy")
        for item in receipt.get("databases",[]):
            key=(str(item.get("ecosystem")),str(item.get("snapshot")),str(item.get("sha256")))
            databases[key]={"ecosystem":key[0],"snapshot":key[1],"sha256":key[2]}
    values=sorted(advisories.values(),key=lambda x:(x["package"],x["version"],x["advisory_id"]));doc={"schema_version":"2.0","tool":"wraith","packages_scanned":packages,"advisory_count":len(values),"advisories":values};data=write(a.output,doc);root=Path(__file__).resolve().parent.parent;version=subprocess.run([str(root/"bins/wraith"),"--version"],capture_output=True,text=True,check=False).stdout.strip().splitlines();operation="offline-multi-lockfile-scan" if a.inputs else "no-supported-lockfiles";write(a.receipt,{"schema_version":"2.0","tool":"wraith","operation":operation,"status":"ok","version":version[0] if version else "unknown","started_at":started,"completed_at":now(),"parse_status":"ok","result_count":len(values),"packages_scanned":packages,"databases":sorted(databases.values(),key=lambda x:x["ecosystem"]),"normalized_sha256":hashlib.sha256(data).hexdigest(),"warnings":[]});return 0
if __name__=="__main__":raise SystemExit(main())
