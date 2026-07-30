#!/usr/bin/env python3
"""Normalize the actual Wraith envelope without retaining raw tool output."""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

def now() -> str: return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def write(path: Path, doc: object) -> bytes:
    data = json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_bytes(data); tmp.replace(path)
    return data
def severity(value: object) -> str:
    text = str(value or "unknown").lower()
    return text if text in {"critical", "high", "medium", "low", "unknown"} else "unknown"
def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--repo", type=Path, required=True); p.add_argument("--lockfile", type=Path, required=True); p.add_argument("--ecosystem", required=True); p.add_argument("--database-snapshot", required=True); p.add_argument("--database-sha256", required=True); p.add_argument("--output", type=Path, required=True); p.add_argument("--receipt", type=Path, required=True); a=p.parse_args()
    started=now()
    try: raw=json.load(sys.stdin)
    except json.JSONDecodeError as exc: raise SystemExit(f"Wraith emitted malformed JSON: {exc}")
    if not isinstance(raw, dict): raise SystemExit("Wraith envelope must be an object")
    if raw.get("results") is None and raw.get("package_count") == 0 and raw.get("vulnerability_count") == 0:
        raw["results"] = []
    if not isinstance(raw.get("results"), list): raise SystemExit("Wraith envelope must contain a results array, or null only for a zero-count scan")
    repo=a.repo.resolve(); lockfile=a.lockfile.resolve()
    try: lockfile_ref=str(lockfile.relative_to(repo))
    except ValueError: raise SystemExit("Wraith lockfile escapes repository")
    if not lockfile.is_file(): raise SystemExit("Wraith lockfile is missing")
    advisories=[]
    for package in raw["results"]:
        if not isinstance(package, dict): raise SystemExit("Wraith result must be an object")
        name=str(package.get("Package", "")).strip(); version=str(package.get("Version", "")).strip(); ecosystem=str(package.get("Ecosystem", "")).strip()
        vulns=package.get("FoundVulnerabilities", [])
        if not isinstance(vulns, list): raise SystemExit("FoundVulnerabilities must be an array")
        for vuln in vulns:
            if not isinstance(vuln, dict): raise SystemExit("Wraith vulnerability must be an object")
            advisory=str(vuln.get("ID", "")).strip()
            if not name or not advisory: raise SystemExit("Wraith result is missing package or advisory ID")
            stable=hashlib.sha256("\0".join((ecosystem,name,version,advisory)).encode()).hexdigest()[:16]
            refs=[str(item)[:512] for item in vuln.get("References", []) if isinstance(item,str)][:10]
            advisories.append({"id":f"SCA-{stable}","advisory_id":advisory,"package":name,"version":version,"ecosystem":ecosystem,"severity":severity(vuln.get("Severity")),"summary":str(vuln.get("Summary", ""))[:1000],"references":refs,"source_lockfile":lockfile_ref})
    package_count=raw.get("package_count"); vulnerability_count=raw.get("vulnerability_count")
    if not isinstance(package_count,int) or package_count < 0: raise SystemExit("Wraith package_count must be a non-negative integer")
    if package_count != len(raw["results"]): raise SystemExit("Wraith package_count does not match results")
    if vulnerability_count != len(advisories): raise SystemExit("Wraith vulnerability_count does not match flattened advisories")
    observed_ecosystems={str(item.get("Ecosystem","")) for item in raw["results"]}
    if observed_ecosystems and observed_ecosystems != {a.ecosystem}: raise SystemExit("Wraith result ecosystem does not match the locked input ecosystem")
    doc={"schema_version":"2.0","tool":"wraith","packages_scanned":package_count,"advisory_count":len(advisories),"advisories":advisories}
    data=write(a.output,doc)
    root=Path(__file__).resolve().parent.parent; v=subprocess.run([str(root/"bins/wraith"),"--version"],capture_output=True,text=True,check=False).stdout.strip().splitlines()
    write(a.receipt,{"schema_version":"2.0","tool":"wraith","operation":"offline-scan","status":"ok","version":v[0] if v else "unknown","started_at":started,"completed_at":now(),"parse_status":"ok","result_count":len(advisories),"packages_scanned":package_count,"databases":[{"ecosystem":a.ecosystem,"snapshot":a.database_snapshot,"sha256":a.database_sha256}],"normalized_sha256":hashlib.sha256(data).hexdigest(),"warnings":[]})
    return 0
if __name__=="__main__": raise SystemExit(main())
