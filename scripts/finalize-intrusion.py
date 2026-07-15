#!/usr/bin/env python3
"""Aggregate exactly one strict terminal result for every planned campaign."""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def load(path:Path,fallback:Any)->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError):return fallback
def write(path:Path,doc:object)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n"); tmp.replace(path)
def resolve(scan:Path,ref:str)->Path|None:
    base=ref.split(":",1)[0].split("#",1)[0]; candidate=(scan/base).resolve()
    try:candidate.relative_to(scan.resolve())
    except ValueError:return None
    return candidate if candidate.is_file() else None
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("scan_base",type=Path); a=p.parse_args(); root=Path(__file__).resolve().parent.parent; context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")),{}); plan=load(a.scan_base/"campaign-planning/campaign-plan.json",{}); errors=[]; results=[]; candidate_ids=set()
    campaigns=plan.get("campaigns",[]) if isinstance(plan,dict) else []
    for campaign in campaigns:
        cid=str(campaign.get("id","")); path=a.scan_base/f"intrusion/results/{cid}.json"; result=load(path,None)
        if not isinstance(result,dict):errors.append(f"missing intrusion result for {cid}");continue
        if result.get("campaign_id")!=cid:errors.append(f"campaign ID mismatch in {path.name}");continue
        status=result.get("status"); candidates=result.get("candidates")
        if status=="candidate" and (not isinstance(candidates,list) or not candidates):errors.append(f"{cid} candidate status requires candidates")
        if status!="candidate" and candidates:errors.append(f"{cid} non-candidate status may not contain candidates")
        question_ids={str(x.get("id")) for x in campaign.get("graph_questions",[]) if isinstance(x,dict)}
        query_refs=[str(x) for x in result.get("graph_query_receipts",[])];evidence_graph_refs=[str(x) for x in result.get("graph_evidence_refs",[])]
        receipt_question_ids={Path(ref.split(":",1)[0].split("#",1)[0]).parent.name for ref in query_refs}
        if receipt_question_ids!=question_ids or len(query_refs)!=len(question_ids):errors.append(f"{cid} must record exactly one receipt for every planned graph question")
        if not set(evidence_graph_refs).issubset(set(query_refs)):errors.append(f"{cid} graph evidence refs must be a subset of executed query receipts")
        for ref in [*result.get("evidence_refs",[]),*query_refs]:
            if resolve(a.scan_base,str(ref)) is None:errors.append(f"{cid} unresolved artifact reference: {ref}")
        for ref in query_refs:
            receipt_path=resolve(a.scan_base,str(ref));receipt=load(receipt_path or Path("/nonexistent"),{})
            if receipt.get("tool")!="codegraph" or receipt.get("status")!="ok" or receipt.get("parse_status")!="ok":errors.append(f"{cid} cites unhealthy graph query receipt: {ref}")
            context_path=receipt_path.with_name("context.json") if receipt_path else None
            if context_path is None or not context_path.is_file() or receipt.get("normalized_sha256")!=hashlib.sha256(context_path.read_bytes()).hexdigest():errors.append(f"{cid} graph receipt hash does not match sibling context.json: {ref}")
            if ref in evidence_graph_refs and not receipt.get("meaningful"):errors.append(f"{cid} cites non-meaningful graph evidence: {ref}")
        for candidate in candidates if isinstance(candidates,list) else []:
            fid=str(candidate.get("id","")) if isinstance(candidate,dict) else ""
            if not fid or fid in candidate_ids:errors.append(f"duplicate or missing intrusion candidate ID: {fid!r}")
            candidate_ids.add(fid)
        results.append(result)
    extra={p.stem for p in (a.scan_base/"intrusion/results").glob("*.json")}-{str(c.get("id")) for c in campaigns}
    if extra:errors.append("orphan intrusion results: "+", ".join(sorted(extra)))
    wrapper={"schema_version":"2.0","run_id":str(context.get("run_id","")),"results":results}; output_path=a.scan_base/"intrusion/intrusion-results.json"; write(output_path,wrapper)
    checked=subprocess.run([sys.executable,str(root/"scripts/validate-json.py"),str(root/"schemas/v2/intrusion-results.schema.json"),str(output_path)],capture_output=True,text=True,check=False)
    if checked.returncode:errors.append(checked.stderr.strip() or "intrusion result schema validation failed")
    counts={name:sum(1 for r in results if r.get("status")==name) for name in ("candidate","closed","rejected","needs_environment")}
    summary="# Intrusion Campaign Results\n\n"+"\n".join(f"- {k.replace('_',' ').title()}: {v}" for k,v in counts.items())+"\n"; (a.scan_base/"intrusion/summary.md").write_text(summary)
    manifest={"phase":"intrusion","status":"failed" if errors else "degraded" if counts["needs_environment"] else "ok","started_at":now(),"completed_at":now(),"inputs":["campaign-planning/evidence-index.json","campaign-planning/campaign-plan.json"],"outputs":["intrusion/intrusion-results.json","intrusion/summary.md"],"coverage":{"campaigns":len(campaigns),**counts},"tool_versions":{"primary_model":str(context.get("model","unknown")),"codegraph":"typed-adapter-v2"},"warnings":[],"errors":errors}; write(a.scan_base/"intrusion/phase-manifest.json",manifest)
    if errors:
        for error in errors:print(f"[finalize-intrusion] ERROR: {error}",file=__import__('sys').stderr)
        return 1
    return 0
if __name__=="__main__":raise SystemExit(main())
