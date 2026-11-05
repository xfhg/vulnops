#!/usr/bin/env python3
"""Finalize strict synthesized findings from fresh-context verifier results."""
from __future__ import annotations
import argparse, importlib.util, json, os, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from model_identity import finding_contributors, finding_diversity, diversity_summary
from intrusion_contract import validate_transitions, resolution, primitive_updates_view
from evidence_refs import EvidenceIssue, validate_evidence_refs
from evidence_accounting import (claim_diagnostics, diagnostic, effective_support, summarize,
                                 validate_non_promoted)
from dossier_contract import validate_dossier, validate_dossier_review, objective_assessments, validate_publication_schema
from artifact_policy import publication_content_error
from run_lifecycle import assessment_ref, current_assessment, routing_for_artifact, require_active_phase
from gap_dossier import (accepted_candidates, supplementary_only, unreviewed_row,
                         validate_unreviewed, require_cohort, synthesis_selector, validate_review_admission)
SAFE=re.compile(r"^F-[0-9]{3}$")
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def load(path:Path,fallback:Any)->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError):return fallback
def write(path:Path,doc:object)->None:
    error=publication_content_error(doc)
    if error:raise ValueError(error)
    if path.name=="findings.json":validate_publication_schema(doc,"final-findings.schema.json")
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n"); tmp.replace(path)
def validate_candidate(root:Path,candidate:object,schema_name:str="synthesis-findings.schema.json")->list[str]:
    spec=importlib.util.spec_from_file_location("validator",root/"scripts/validate-json.py"); module=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(module); schema=load(root/"schemas/v2"/schema_name,{}); return module.Validator(schema).collect(candidate,schema["$defs"]["finding"] if schema_name=="synthesis-findings.schema.json" else schema)
def effective_assessment(root:Path,candidate:dict,result:dict,primary:str)->dict:
    """Assess the corrected sequence, never the sequence it replaced."""
    fid=candidate["id"]; status=result.get("status")
    if result.get("finding_id")!=fid:raise ValueError(f"{fid} verifier finding identity mismatch")
    finding=result.get("corrected_finding") if status=="corrected" else candidate
    if not isinstance(finding,dict) or finding.get("id")!=fid:raise ValueError(f"{fid} invalid effective finding identity")
    if status not in {"rejected", "evidence_limited"}:
        problems=validate_candidate(root,finding)
        if problems:raise ValueError(f"{fid} invalid effective finding: {'; '.join(problems[:8])}")
        if finding["verification"].get("actor")!="vulnops-synthesis" or finding["verification"]["model"]!=primary:raise ValueError(f"{fid} effective finding synthesizer model mismatch")
    if status!="corrected" and result.get("corrected_finding") is not None:raise ValueError(f"{fid} unexpected corrected finding")
    ids=[step["primitive_id"] for step in finding.get("primitive_steps",[])]
    assessments=result.get("primitive_results",[])
    transitions=result.get("transition_results",[])
    if finding.get("finding_kind")=="chain":
        if len(ids)<2 or len(ids)!=len(set(ids)):raise ValueError(f"{fid} invalid chain primitive sequence")
        if [step.get("primitive_id") for step in assessments]!=ids:raise ValueError(f"{fid} verifier did not assess effective primitives in order")
        edges=list(zip(ids,ids[1:]))
        for label,items in (("finding",finding.get("transitions",[])),("verifier",transitions)):
            if [(edge.get("producer_id"),edge.get("consumer_id")) for edge in items]!=edges:raise ValueError(f"{fid} {label} transitions do not match effective sequence")
        if status in {"verified","corrected"}:
            if any(step.get("status")!="verified" for step in assessments):raise ValueError(f"{fid} unverified primitive")
            if any(edge.get("resolution",{}).get("outcome")!="established" for edge in transitions):raise ValueError(f"{fid} unestablished transition")
    elif ids or assessments or transitions or finding.get("transitions"):
        raise ValueError(f"{fid} non-chain cannot contain primitive or transition assessments")
    joint=result.get("joint_conditions",{})
    if status in {"verified","corrected"} and (joint.get("outcome")!="established" or not joint.get("evidence_refs")):
        raise ValueError(f"{fid} conditions are not jointly established")
    if status=="needs_environment":
        finding={**finding,"status":"needs_environment","verification":{**finding["verification"],"level":"environment_required"},"closure_rationale":result["closure_reason"]}
    return dict(finding)
def validate_assessment(root:Path,scan:Path,target:Path,candidate:dict,result:dict,primary:str,primitives:dict,routing:dict,*,repositories:list[dict])->dict:
    problems=validate_candidate(root,result,"independent-verification-result.schema.json")
    if problems:raise ValueError("invalid verifier result: "+"; ".join(problems[:8]))
    try:
        source_routing = routing_for_artifact(scan, "synthesis/findings.json", routing)
    except ValueError as exc:
        if "missing producing model assignment" not in str(exc) or result["status"] not in {"rejected","evidence_limited"}:
            raise
        source_routing = {}
    source_primary = source_routing.get("agents", {}).get("vulnops-synthesis", primary)
    if (scan/"synthesis/dispatch.json").is_file():
        manifest=load(scan/"run-manifest.json",{})
        source_primary=synthesis_selector(scan,{"run_id":manifest.get("run_id"),
            "attempt_id":manifest.get("attempt_id"),"model_routing":source_routing},candidate)
    finding=effective_assessment(root,candidate,result,source_primary)
    verifier=routing["agents"]["vulnops-independent-verify-one"]
    if result.get("actor")!="vulnops-independent-verify-one" or result.get("model")!=verifier:raise ValueError("independent verifier differs from assigned route")
    if result["status"] in {"evidence_limited", "rejected"}:
        if result["status"] == "evidence_limited":
            row=result.get("non_promoted",{})
            if row.get("id")!=candidate["id"] or row.get("disposition")!="evidence_limited" or row.get("input_refs")!=[f"synthesis/findings.json:{candidate['id']}"]:
                raise ValueError("evidence-limited verifier result must account for its exact input claim")
            validate_non_promoted(row,routing,scan,target,repositories,actor="vulnops-independent-verify-one")
        elif result.get("non_promoted") is not None:
            raise ValueError("non-promoted closure requires evidence_limited status")
        # Rejection/limitation is a review outcome, not a replay of the old
        # dossier against changed source. Preserve whatever attribution resolves.
        owners={"verification":{"source_validation_refs":[item["artifact_ref"] for item in finding.get("contributors",[])]}}
        try:
            contributors=finding_contributors(scan,owners,routing,source_root=target,repositories=repositories)
        except EvidenceIssue:
            contributors=[]
        if contributors and finding.get("contributors")!=contributors:
            raise ValueError("limited finding contributor ownership mismatch")
        claim_diagnostics(scan,target,repositories,finding,owner="synthesis/findings.json",item_id=candidate["id"],historical=True)
        if result["status"] == "rejected":
            validate_evidence_refs(scan,target,repositories,result["evidence_refs"],owner="verifier.evidence_refs")
    else:
        if result.get("non_promoted") is not None:raise ValueError("non-promoted closure requires evidence_limited status")
        contributors=finding_contributors(scan,finding,routing,primitives,source_root=target,repositories=repositories)
        if finding.get("contributors")!=contributors:raise ValueError("effective finding contributors differ from relied-upon evidence")
        effective=effective_support(scan,target,repositories,finding,used_optional=set())
        validate_dossier(scan,target,repositories,effective)
        expected={(row["reference"],row["obligation"]) for row in [*candidate.get("optional_support",[]),*finding.get("optional_support",[])]}
        reviews=result.get("optional_support_reviews",[])
        if {(row["reference"],row["obligation"]) for row in reviews}!=expected or len(reviews)!=len(expected):
            raise ValueError("independent verifier must challenge every optional-support rationale")
        for row in reviews:
            if not row["reason"].strip() or not row["evidence_refs"]:raise ValueError("optional support challenge requires independent inspected evidence")
            artifacts=validate_evidence_refs(scan,target,repositories,row["evidence_refs"],owner="optional_support_reviews")
            if len(artifacts)==len(row["evidence_refs"]):raise ValueError("optional support challenge requires independently inspected source")
            if result["status"] in {"verified","corrected"} and not row["sufficient"]:
                raise ValueError("optional support challenge did not establish sufficient proof")
        resolution(scan,result.get("joint_conditions"))
        inspected=validate_evidence_refs(scan,target,repositories,result.get("evidence_refs"),owner="verifier.evidence_refs")
        if len(inspected)==len(result.get("evidence_refs",[])):
            raise ValueError("current independent confirmation requires inspected current source")
        for assessment in result.get("primitive_results",[]):
            validate_evidence_refs(scan,target,repositories,assessment.get("evidence_refs"),owner="verifier.primitive_results")
        if finding["finding_kind"]=="chain":
            effective_ids=[step["primitive_id"] for step in finding["primitive_steps"]]
            for edges in (effective.get("transitions",[]),result.get("transition_results",[])):
                validate_transitions(scan,target,effective_ids,edges,primitives,require_established=result["status"] in {"verified","corrected"})
    diverse=bool(contributors) and finding_diversity(contributors,verifier)
    if result.get("model_diversity") is not diverse:raise ValueError("independent finding diversity differs from effective contributors")
    validate_dossier_review(scan,target,repositories,finding,result)
    return finding
def assessment_diagnostics(scan,target,repositories,candidate,result,routing,primitives):
    diagnostics=[];fid=candidate["id"];ref=f"final-verification/results/{fid}.json"
    if result["status"] in {"evidence_limited", "rejected"}:
        diagnostics.extend(claim_diagnostics(scan,target,repositories,result,owner=ref,item_id=fid))
        diagnostics.extend(claim_diagnostics(scan,target,repositories,candidate,owner="synthesis/findings.json",item_id=fid,historical=True))
        owners={"verification":{"source_validation_refs":[item["artifact_ref"] for item in candidate.get("contributors",[])]}}
        try:finding_contributors(scan,owners,routing,source_root=target,repositories=repositories)
        except EvidenceIssue as exc:diagnostics.append(diagnostic(exc.code,ref,"candidate_support",[fid]))
    else:
        effective=result["corrected_finding"] if result["status"]=="corrected" else candidate
        finding_contributors(scan,effective,routing,primitives,source_root=target,repositories=repositories,diagnostics=diagnostics)
    return diagnostics

def missing_review_closure(scan:Path,context:dict,candidate:dict,supplements:list[dict])->dict|None:
    if not supplementary_only(candidate,supplements):
        return None
    target=Path(context.get("source_root") or context["repo_path"])
    contributors=finding_contributors(scan,candidate,context["model_routing"],
                                     source_root=target,repositories=context["repositories"])
    if contributors!=candidate.get("contributors"):
        raise ValueError("unreviewed candidate contributor ownership differs")
    return unreviewed_row(scan,context,candidate,phase="final-verification",
                          input_refs=[f"synthesis/findings.json:{candidate['id']}"])


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("repo_path",type=Path); p.add_argument("scan_base",type=Path)
    p.add_argument("--cohort",choices=("complete","original","supplementary"),default="complete")
    a=p.parse_args(); root=Path(__file__).resolve().parent.parent
    a.scan_base=a.scan_base.resolve()
    context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")),{})
    require_active_phase(a.scan_base,context,"final-verification")
    if a.repo_path.resolve()!=Path(context["repo_path"]).resolve():
        raise ValueError("verification source differs from its active execution")
    routing=context["model_routing"]; primary=routing["agents"]["vulnops-synthesis"]; verifier=routing["agents"]["vulnops-independent-verify-one"]
    source=load(a.scan_base/"synthesis/findings.json",{})
    candidates=source.get("findings",[]) if isinstance(source,dict) else []; findings=[]; rejections=[]; errors=[]
    if not isinstance(source,dict) or not isinstance(source.get("findings"),list):
        raise ValueError("synthesis/findings.json: findings must be an array")
    if current_assessment(source,context):
        validate_publication_schema(source,"synthesis-findings.schema.json")
    non_promoted=list(source.get("non_promoted",[]));diagnostics=[];target=Path(context.get("source_root") or context["repo_path"])
    supplements=accepted_candidates(a.scan_base,context=context)
    inherited_unreviewed=list(source.get("unreviewed",[]))
    if inherited_unreviewed:validate_unreviewed(a.scan_base,context,inherited_unreviewed,supplements,"synthesis")
    unreviewed=[]
    if a.cohort=="original":require_cohort(context,"final-verification","original")
    reviewed_results={}
    ids=[str(x.get("id")) for x in candidates if isinstance(x,dict)]
    index=load(a.scan_base/"campaign-planning/evidence-index.json",{}); intrusion=load(a.scan_base/"intrusion/intrusion-results.json",{})
    primitives={x["id"]:x for x in index.get("primitives",[])}
    primitives.update({x["id"]:x for row in intrusion.get("results",[]) for x in primitive_updates_view(a.scan_base,context,row)})
    if len(ids)!=len(set(ids)):errors.append("synthesis contains duplicate finding IDs")
    for candidate in candidates:
        if not isinstance(candidate,dict):
            errors.append("synthesis/findings.json: finding must be an object")
            continue
        if a.cohort=="original" and supplementary_only(candidate,supplements):
            continue
        fid=str(candidate.get("id","")); ref=f"final-verification/results/{fid}.json"
        if not SAFE.fullmatch(fid):errors.append(f"unsafe synthesized finding ID: {fid!r}");continue
        if (a.scan_base/ref).resolve()!=(a.scan_base/ref).absolute():
            errors.append(f"redirected independent verifier result for {fid}");continue
        result=load(a.scan_base/ref,None)
        if not isinstance(result,dict):
            if (a.scan_base/ref).exists():
                errors.append(f"malformed independent verifier result for {fid}; reject the failed publication before optional closure");continue
            try:
                closure=missing_review_closure(a.scan_base,context,candidate,supplements)
            except (ValueError,OSError,KeyError) as exc:
                errors.append(f"{fid}: {exc}");continue
            if closure is not None:
                unreviewed.append(closure);continue
            errors.append(f"missing independent verifier result for {fid}");continue
        status=result.get("status")
        if status not in {"verified","corrected","rejected","needs_environment","evidence_limited"}:errors.append(f"unknown verifier status for {fid}");continue
        if context.get("attempt_id") and not current_assessment(result,context):
            if supplementary_only(candidate,supplements):
                try:closure=missing_review_closure(a.scan_base,context,candidate,supplements)
                except (ValueError,OSError,KeyError) as exc:errors.append(f"{fid}: {exc}")
                else:unreviewed.append(closure)
                continue
            errors.append(f"{fid}: retained verifier result requires a current independent review")
            continue
        try:
            validate_review_admission(a.scan_base,context,candidate,result)
            finding=validate_assessment(root,a.scan_base,target,candidate,result,primary,primitives,routing,repositories=context["repositories"])
            diagnostics.extend(assessment_diagnostics(a.scan_base,target,context["repositories"],candidate,result,routing,primitives))
        except (ValueError,OSError,KeyError) as exc:errors.append(f"{fid}: {exc}");continue
        reference=assessment_ref(context)
        if reference:
            finding={**finding,"assessment_context":reference}
        reviewed_results[fid]=result
        if status=="evidence_limited":
            non_promoted.append(result["non_promoted"])
            continue
        if status=="rejected":
            rejection={"id":fid,"reason":str(result.get("closure_reason")),"independent_verification_ref":ref}
            if reference:rejection["assessment_context"]=reference
            rejections.append(rejection)
            continue
        if status=="needs_environment":finding["status"]="needs_environment"; finding["verification"]={**finding["verification"],"level":"environment_required"}; finding["closure_rationale"]=str(result.get("closure_reason"))
        finding["verdict"]="needs_environment" if finding.get("status")=="needs_environment" else "confirmed"; finding["model_diversity"]=finding_diversity(finding["contributors"],verifier); finding["independent_verification_ref"]=ref; findings.append(finding)
    extras={x.stem for x in (a.scan_base/"final-verification/results").glob("*.json")}-set(ids)
    if extras:errors.append("orphan verifier results: "+", ".join(sorted(extras)))
    if a.cohort=="original":
        if errors:
            for error in errors:print(f"[finalize-verification] ERROR: {error}",file=__import__("sys").stderr)
            return 1
        return 0
    if unreviewed:validate_unreviewed(a.scan_base,context,unreviewed,candidates,"final-verification")
    aggregate=diversity_summary(findings); diversity=aggregate["model_diversity"]
    output={"schema_version":"2.0","run_id":str(context.get("run_id","")),"verifier_model":verifier,**aggregate,"findings":findings,"rejections":rejections,"non_promoted":non_promoted,"input_claims":source.get("input_claims",[]),"evidence_quality":summarize(diagnostics),"prior_run_reconciliation":source.get("prior_run_reconciliation",[])}
    output["unreviewed"]=[*inherited_unreviewed,*unreviewed]
    if assessment_ref(context):output["assessment_context"]=assessment_ref(context)
    try:output["objective_assessments"]=objective_assessments(a.scan_base,findings,results=reviewed_results,candidates=candidates)
    except (ValueError,OSError,KeyError) as exc:errors.append(f"objective accounting: {exc}")
    else:
        if assessment_ref(context):
            for row in output["objective_assessments"]:row["assessment_context"]=assessment_ref(context)
    terminal={row["id"]:("eligible" if row.get("verdict") in {"confirmed","needs_environment"} else "rejected") for row in [*findings,*rejections]}
    terminal.update({row["id"]:row["disposition"] for row in non_promoted})
    terminal.update({row["id"]:"unreviewed" for row in unreviewed})
    for row in output["input_claims"]:
        outcomes={terminal[fid] for fid in row["finding_ids"] if fid in terminal}
        if row["finding_ids"] and not outcomes:errors.append("input claim lost its terminal finding disposition")
        if outcomes and "eligible" not in outcomes:
            row["disposition"]="unreviewed" if "unreviewed" in outcomes else "evidence_limited" if "evidence_limited" in outcomes else "rejected"
    try:
        spec=importlib.util.spec_from_file_location("synthesis_finalizer",root/"scripts/finalize-synthesis.py"); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        output["prior_run_reconciliation"]=module.reconcile_prior(context,a.scan_base,output,final=True)
    except (ValueError,OSError,KeyError) as exc:errors.append(f"prior reconciliation: {exc}")
    counts={"confirmed":sum(x["verdict"]=="confirmed" for x in findings),"needs_environment":sum(x["verdict"]=="needs_environment" for x in findings),"rejected":len(rejections),"evidence_limited":sum(row["disposition"]=="evidence_limited" for row in non_promoted),**aggregate["diversity_counts"]}
    if output.get("unreviewed"):counts["unreviewed"]=len(output["unreviewed"])
    manifest={"phase":"final-verification","status":"degraded" if counts["needs_environment"] else "ok","started_at":now(),"completed_at":now(),"inputs":["synthesis/findings.json"],"outputs":["final-verification/findings.json","final-verification/summary.md"],"coverage":{"candidates":len(candidates),**counts},"tool_versions":{"synthesis_model":primary,"verifier_model":verifier,"model_diversity":str(diversity).lower()},"warnings":[],"errors":[]}
    if output.get("unreviewed"):
        if not errors:manifest["status"]="degraded"
    if errors:
        for error in errors:print(f"[finalize-verification] ERROR: {error}",file=__import__('sys').stderr)
        return 1
    error=publication_content_error(manifest)
    if error:raise ValueError(error)
    require_active_phase(a.scan_base,context,"final-verification")
    write(a.scan_base/"final-verification/findings.json",output)
    (a.scan_base/"final-verification/summary.md").write_text("# Independent Final Verification\n\n"+"\n".join(f"- {k.replace('_',' ').title()}: {v}" for k,v in counts.items())+f"\n- Verifier model: {verifier}\n- Model diversity: {str(diversity).lower()}\n")
    write(a.scan_base/"final-verification/phase-manifest.json",manifest)
    return 0
if __name__=="__main__":raise SystemExit(main())
