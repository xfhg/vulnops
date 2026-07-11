#!/usr/bin/env python3
"""Finalize strict synthesized findings from fresh-context verifier results."""
from __future__ import annotations
import argparse, importlib.util, json, os, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from model_identity import model_diversity
SAFE=re.compile(r"^F-[0-9]{3}$")
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def load(path:Path,fallback:Any)->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError):return fallback
def write(path:Path,doc:object)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n"); tmp.replace(path)
def validate_candidate(root:Path,candidate:object)->list[str]:
    spec=importlib.util.spec_from_file_location("validator",root/"scripts/validate-json.py"); module=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(module); schema=load(root/"schemas/v2/synthesis-findings.schema.json",{}); return module.Validator(schema).collect(candidate,schema["$defs"]["finding"])
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("repo_path",type=Path); p.add_argument("scan_base",type=Path); a=p.parse_args(); root=Path(__file__).resolve().parent.parent; context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")),{}); primary=str(context.get("model",os.environ.get("OMP_MODEL_SELECTOR",""))); verifier=str(context.get("verifier_model",os.environ.get("OMP_VERIFIER_MODEL_SELECTOR",""))); diversity=model_diversity(primary,verifier); source=load(a.scan_base/"synthesis/findings.json",{}); candidates=source.get("findings",[]) if isinstance(source,dict) else []; findings=[]; rejections=[]; errors=[]
    ids=[str(x.get("id")) for x in candidates if isinstance(x,dict)]
    if len(ids)!=len(set(ids)):errors.append("synthesis contains duplicate finding IDs")
    for candidate in candidates:
        fid=str(candidate.get("id","")); ref=f"final-verification/results/{fid}.json"
        if not SAFE.fullmatch(fid):errors.append(f"unsafe synthesized finding ID: {fid!r}");continue
        if (candidate.get("verification") or {}).get("model")!=primary:errors.append(f"{fid} source validation did not use the configured primary model");continue
        result=load(a.scan_base/ref,None)
        if not isinstance(result,dict):errors.append(f"missing independent verifier result for {fid}");continue
        if result.get("model")!=verifier or result.get("model_diversity") is not diversity:errors.append(f"{fid} verifier model metadata mismatch");continue
        primitive_ids=[str(x.get("primitive_id")) for x in candidate.get("primitive_steps",[]) if isinstance(x,dict)]
        result_ids=[str(x.get("primitive_id")) for x in result.get("primitive_results",[]) if isinstance(x,dict)]
        if candidate.get("finding_kind")=="chain":
            if len(primitive_ids)<2:errors.append(f"{fid} chain requires at least two primitive steps");continue
            if result_ids!=primitive_ids:errors.append(f"{fid} verifier did not assess every chain primitive in order");continue
            if result.get("status") in {"verified","corrected"} and any(x.get("status")!="verified" for x in result.get("primitive_results",[])):errors.append(f"{fid} cannot verify a chain with an unverified primitive");continue
        elif result.get("primitive_results"):
            errors.append(f"{fid} non-chain verifier result must not contain primitive results");continue
        status=result.get("status")
        if status=="rejected":rejections.append({"id":fid,"reason":str(result.get("closure_reason")),"independent_verification_ref":ref});continue
        finding=dict(candidate)
        if status=="corrected":
            corrected=result.get("corrected_finding")
            if not isinstance(corrected,dict) or corrected.get("id")!=fid:errors.append(f"invalid corrected finding for {fid}");continue
            problems=validate_candidate(root,corrected)
            if problems:errors.append(f"corrected finding {fid} is invalid: {'; '.join(problems[:8])}");continue
            finding=corrected
        elif status not in {"verified","needs_environment"}:errors.append(f"unknown verifier status for {fid}");continue
        if status=="needs_environment":finding["status"]="needs_environment"; finding["verification"]={**finding["verification"],"level":"environment_required"}; finding["closure_rationale"]=str(result.get("closure_reason"))
        finding["verdict"]="needs_environment" if finding.get("status")=="needs_environment" else "confirmed"; finding["model_diversity"]=diversity; finding["independent_verification_ref"]=ref; findings.append(finding)
    extras={x.stem for x in (a.scan_base/"final-verification/results").glob("*.json")}-set(ids)
    if extras:errors.append("orphan verifier results: "+", ".join(sorted(extras)))
    output={"schema_version":"2.0","run_id":str(context.get("run_id","")),"model_diversity":diversity,"findings":findings,"rejections":rejections}; write(a.scan_base/"final-verification/findings.json",output)
    counts={"confirmed":sum(x["verdict"]=="confirmed" for x in findings),"needs_environment":sum(x["verdict"]=="needs_environment" for x in findings),"rejected":len(rejections)}; (a.scan_base/"final-verification/summary.md").write_text("# Independent Final Verification\n\n"+"\n".join(f"- {k.replace('_',' ').title()}: {v}" for k,v in counts.items())+f"\n- Model diversity: {str(diversity).lower()}\n")
    manifest={"phase":"final-verification","status":"failed" if errors else "degraded" if counts["needs_environment"] else "ok","started_at":now(),"completed_at":now(),"inputs":["synthesis/findings.json"],"outputs":["final-verification/findings.json","final-verification/summary.md"],"coverage":{"candidates":len(candidates),**counts},"tool_versions":{"primary_model":primary,"verifier_model":verifier,"model_diversity":str(diversity).lower()},"warnings":[],"errors":errors}; write(a.scan_base/"final-verification/phase-manifest.json",manifest)
    if errors:
        for error in errors:print(f"[finalize-verification] ERROR: {error}",file=__import__('sys').stderr)
        return 1
    return 0
if __name__=="__main__":raise SystemExit(main())
