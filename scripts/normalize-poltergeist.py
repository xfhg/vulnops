#!/usr/bin/env python3
"""Normalize Poltergeist output without persisting any matched value."""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess
from datetime import datetime, timezone
from pathlib import Path

def now() -> str: return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def write(path: Path, doc: object) -> bytes:
    data=json.dumps(doc,indent=2,sort_keys=True).encode()+b"\n"; path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_bytes(data); tmp.replace(path); return data
def parse_embedded(text: str) -> object:
    decoder=json.JSONDecoder()
    for index,char in enumerate(text):
        if char not in "[{": continue
        try: value,end=decoder.raw_decode(text[index:])
        except json.JSONDecodeError: continue
        if not text[index+end:].strip(): return value
    raise ValueError("Poltergeist did not emit a terminal JSON document")
def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--target",type=Path,required=True); p.add_argument("--input",type=Path,required=True); p.add_argument("--scanner-exit",type=int,choices=(0,1),required=True); p.add_argument("--output",type=Path,required=True); p.add_argument("--receipt",type=Path,required=True); a=p.parse_args(); started=now()
    raw=parse_embedded(a.input.read_text(encoding="utf-8",errors="replace"))
    if not isinstance(raw,dict): raise SystemExit("Poltergeist envelope must be an object")
    if raw.get("results") is None and isinstance(raw.get("summary"),dict) and raw["summary"].get("matches_found")==0:
        raw["results"]=[]
    if not isinstance(raw.get("results"),list): raise SystemExit("Poltergeist envelope must contain results, or null only for a zero-match scan")
    target=a.target.resolve(); candidates_by_id={}
    for item in raw["results"]:
        if not isinstance(item,dict): raise SystemExit("Poltergeist result must be an object")
        path=Path(str(item.get("file_path", "")))
        if path.is_absolute():
            resolved=path.resolve()
        else:
            cwd_candidate=(Path.cwd()/path).resolve()
            resolved=cwd_candidate if cwd_candidate.is_file() else (target/path).resolve()
        try: rel=str(resolved.relative_to(target))
        except ValueError: raise SystemExit("Poltergeist result escapes target")
        if not resolved.is_file(): raise SystemExit("Poltergeist result references a missing target file")
        line=int(item.get("line_number",0)); rule=str(item.get("rule_id") or item.get("rule_name") or "unknown")
        if line < 1: raise SystemExit("Poltergeist result has invalid line")
        stable=hashlib.sha256("\0".join((rule,rel,str(line))).encode()).hexdigest()[:16]
        candidate={"id":f"SEC-{stable}","type":str(item.get("rule_name") or rule)[:200],"rule_id":rule[:200],"classification":"candidate","file":rel,"line":line,"redaction":"<redacted>","exposure_path":"Matched in repository source; validity and runtime exposure require validation.","validity":"unknown"}
        candidates_by_id[candidate["id"]]=candidate
    candidates=sorted(candidates_by_id.values(),key=lambda item:(item["file"],item["line"],item["rule_id"],item["id"]))
    summary=raw.get("summary") if isinstance(raw.get("summary"),dict) else {}
    reported_counts=[summary.get(key) for key in ("matches_found","total_secrets_found","total_matches","matches") if isinstance(summary.get(key),int)]
    for count in reported_counts:
        if count < len(candidates): raise SystemExit("Poltergeist summary count is lower than its unique normalized records")
    match_count=max([len(raw["results"]),*reported_counts])
    doc={"schema_version":"2.0","tool":"poltergeist","match_count":match_count,"candidate_count":len(candidates),"candidates":candidates}; data=write(a.output,doc)
    root=Path(__file__).resolve().parent.parent; v=subprocess.run([str(root/"bins/poltergeist"),"--version"],capture_output=True,text=True,check=False).stdout.strip().splitlines()
    write(a.receipt,{"schema_version":"2.0","tool":"poltergeist","operation":"secret-scan","status":"ok","version":v[0] if v else "unknown","started_at":started,"completed_at":now(),"parse_status":"ok","result_count":len(candidates),"normalized_sha256":hashlib.sha256(data).hexdigest(),"warnings":[]})
    return 0
if __name__=="__main__": raise SystemExit(main())
