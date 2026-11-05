#!/usr/bin/env python3
"""Close model-authored synthesis after strict schema validation."""
from __future__ import annotations
import argparse,json,os,sys
from datetime import datetime,timezone
from pathlib import Path
from model_identity import finding_contributors
from evidence_refs import EvidenceIssue
from evidence_accounting import (account_inputs, claim_diagnostics, classify_refs, diagnostic,
                                 summarize, synthesis_inputs, validate_non_promoted, input_reference)
from dossier_contract import validate_dossier, objective_assessments, validate_publication_schema
from evidence_accounting import effective_support
from artifact_policy import publication_content_error
from run_lifecycle import assessment_ref, current_assessment, routing_for_artifact, require_active_phase
from gap_dossier import (accepted, accepted_candidates, preserve_original, close_supplementary_draft,
                         validate_unreviewed, require_cohort, bind_original_draft, load_original_draft,
                         synthesis_selector, require_synthesis_publication)
from synthesis_contract import semantic_synthesis
from report_bundle import read_publication
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def write(path:Path,doc:object)->None:
    error=publication_content_error(doc)
    if error:raise ValueError(error)
    path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp");tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n");tmp.replace(path)
def prior_reports(scan:Path):
    """Read up to eight available completed ordinary sibling publications."""
    scan=scan.resolve()
    count=0
    for path in sorted(scan.parent.glob("*/report/security-report.json"),reverse=True):
        try:
            if (path.parent.parent==scan or path.resolve()!=path or not path.is_file()
                    or path.stat().st_size>64*1024*1024):
                continue
            publication=read_publication(path.parent.parent,expected_kind="audit")
            report=publication["report"]
            cohorts=[report.get("findings",[]),report.get("historical_findings",[])]
            if any(not isinstance(rows,list) or any(not isinstance(row,dict)
                    or not isinstance(row.get("id"),str) or not row["id"] for row in rows)
                    for rows in cohorts):
                continue
            identities=[row["id"] for rows in cohorts for row in rows if row.get("verdict")=="confirmed"]
            if len(identities)!=len(set(identities)):
                continue
        except (OSError,ValueError,RuntimeError):
            continue
        yield {"path":str(path),"run_id":publication["run_id"],"report":publication["report"]}
        count+=1
        if count==8:
            break

def prior_reference(scan:Path,reference:str)->Path:
    """Constrain supplied historical references without following them."""
    path=Path(reference)
    root=scan.resolve().parent
    if (not path.is_absolute() or ".." in path.parts or str(path)!=reference
            or path.name!="security-report.json" or path.parent.name!="report"
            or path.parent.parent.parent!=root or path.parent.parent==scan.resolve()):
        raise ValueError("prior reconciliation must reference a sibling report")
    return path

def reconcile_prior(context:dict,scan:Path,doc:dict,*,final:bool=False)->list[dict]:
    """Compare available historical roots without inheriting their verdicts."""
    supplied=doc.get("prior_run_reconciliation",[]); keyed={}
    for item in supplied:
        key=(item["prior_report_ref"],item["prior_finding_id"])
        prior_reference(scan,item["prior_report_ref"])
        for ref in item["evidence_refs"]:
            relative=Path(ref)
            if relative.is_absolute() or ".." in relative.parts or not (scan/relative).resolve().is_relative_to(scan.resolve()) or not (scan/relative).is_file():raise ValueError("prior reconciliation evidence must resolve in current scan")
        if key in keyed:raise ValueError("duplicate prior-run reconciliation")
        keyed[key]=item
    current={item["id"]:item for item in doc.get("findings",[])}
    output=[];available=set()
    for publication in prior_reports(scan):
        path=Path(publication["path"]);prior=publication["report"]
        available.add(str(path))
        for finding in [*prior.get("findings",[]),*prior.get("historical_findings",[])]:
            if finding.get("verdict")!="confirmed":continue
            key=(str(path),finding["id"])
            item=keyed.pop(key,None)
            applicability={"source":"Historical source observations require fresh source review before current confirmation.","policy":"Historical conclusions do not establish the current assessment's scope or policy.","deployment":"Prior deployment assumptions are not inherited; current applicability must be established."}
            if item is None:
                item={"prior_report_ref":str(path),"prior_finding_id":finding["id"],"status":"not_revisited","reason":"No current investigation was linked to this available prior root.","evidence_refs":[],"current_finding_ids":[],"applicability":applicability}
            else:
                item=dict(item)
                item["applicability"]={name:item["applicability"][name] if item["applicability"][name].startswith(text) else f"{text} {item['applicability'][name]}" for name,text in applicability.items()}
                ids=item["current_finding_ids"]
                rejected={row["id"]:row for row in [*doc.get("rejections",[]),*doc.get("non_promoted",[]),*doc.get("unreviewed",[])]}
                if any(fid not in current and fid not in rejected for fid in ids):raise ValueError("prior reconciliation references unknown current finding")
                if final and ids and any(fid in rejected or current.get(fid,{}).get("verdict")!="confirmed" for fid in ids):
                    item["status"]="not_revisited"
                    item["reason"]="Current linked claim was rejected, unreviewed, or remains environment-required; the prior root has not been independently revalidated. "+item["reason"]
                    item["current_finding_ids"]=[fid for fid in ids if fid in current]
                    item["evidence_refs"]=item["evidence_refs"]+[rejected[fid]["independent_verification_ref"] for fid in ids if fid in rejected and "independent_verification_ref" in rejected[fid]]
                    ids=item["current_finding_ids"]
                if any(fid not in current for fid in ids):raise ValueError("prior reconciliation references unknown current finding")
                if item["status"]!="not_revisited" and not item["evidence_refs"]:raise ValueError("prior reconciliation requires current evidence")
                if item["status"] in {"revalidated","superseded"} and not ids:raise ValueError("prior reconciliation requires a current finding")
                if final and item["status"] in {"revalidated","superseded"} and any(
                        current[fid].get("verdict")!="confirmed" or not current_assessment(current[fid],context)
                        for fid in ids):raise ValueError("prior revalidation requires current independent confirmation")
            output.append(item)
    for (reference,_),supplied_item in keyed.items():
        if reference in available:
            raise ValueError("reconciliation references an unknown prior root")
        item=dict(supplied_item)
        item["status"]="not_revisited"
        limitation="Prior report is unavailable or outside the bounded completed-report comparison; its cited root and relationship could not be checked."
        item["reason"]=limitation+" "+item["reason"] if not item["reason"].startswith(limitation) else item["reason"]
        item["current_finding_ids"]=[fid for fid in item["current_finding_ids"] if fid in current]
        output.append(item)
    return output
def finalize_document(scan:Path,context:dict,doc:dict,*,include_supplementary:bool=True)->dict:
    error=publication_content_error(doc)
    if error:raise ValueError(error)
    routing=context["model_routing"];target=Path(context.get("source_root") or context["repo_path"]);repositories=context["repositories"]
    inputs=synthesis_inputs(scan,include_supplementary=include_supplementary);diagnostics=[];non_promoted=doc.get("non_promoted",[])
    unreviewed=doc.get("unreviewed",[])
    if unreviewed:
        if not include_supplementary:raise ValueError("original synthesis cannot close optional claims")
        validate_unreviewed(scan,context,unreviewed,accepted_candidates(scan,context=context),"synthesis")
    coverage_path=scan/"sast/coverage-ledger.json"
    repairs={input_reference(ref):row
             for row in (json.loads(coverage_path.read_text()).get("non_promoted",[]) if coverage_path.is_file() else [])
             if row.get("correction_repair") for ref in row["input_refs"]}
    ids=[row["id"] for row in non_promoted]
    if len(ids)!=len(set(ids)):raise ValueError("duplicate non-promoted claim identity")
    for row in non_promoted:
        upstream=repairs.get(input_reference(row["input_refs"][0])) if row.get("input_refs") else None
        assigned = routing_for_artifact(scan,"sast/coverage-ledger.json",routing) if row==upstream else routing
        if row!=upstream and row.get("review"):
            assigned={**assigned,"agents":{**assigned["agents"],"vulnops-synthesis":synthesis_selector(scan,context,row)}}
        validate_non_promoted(row,assigned,scan,target,repositories,
                              actor="vulnops-verify-one" if row==upstream else "vulnops-synthesis",
                              historical=row==upstream)
        if row!=upstream and assessment_ref(context) and not row.get("assessment_context"):
            row["assessment_context"]=assessment_ref(context)
        for issue in row.get("diagnostics",[]):
            if issue["owner"]!="synthesis/findings.json" or issue["affected_item_ids"]!=[row["id"]] or issue["disposition"]!="evidence_limited":
                raise ValueError("non-promoted diagnostics must belong to their exact synthesis claim")
            diagnostics.append(issue)
        for ref in row["input_refs"]:
            repair=repairs.get(input_reference(ref))
            if repair and row["disposition"]=="evidence_limited" and row.get("correction_repair")!=repair["correction_repair"]:
                raise ValueError("continued evidence-limited closure must retain source-owned correction repair")
            _,issues=classify_refs(scan,target,repositories,[ref],owner="synthesis/findings.json",field="non_promoted.input_refs",affected_item_ids=[row["id"]],kind="artifact")
            diagnostics.extend(issues)
            original=inputs.get(input_reference(ref))
            if original:
                diagnostics.extend(claim_diagnostics(scan,target,repositories,original,owner=ref,item_id=row["id"],historical=True))
    retained=[]
    for finding in doc.get("findings",[]):
        verification=finding["verification"]
        if verification.get("actor")!="vulnops-synthesis" or verification.get("model")!=synthesis_selector(scan,context,finding):
            raise ValueError("synthesizer attribution differs from assigned route")
        finding_diagnostics=[]
        try:
            finding["contributors"]=finding_contributors(scan,finding,routing,source_root=target,repositories=repositories,diagnostics=finding_diagnostics)
            if not include_supplementary and any(row["actor"]=="vulnops-gap-investigator" for row in finding["contributors"]):
                raise ValueError("original synthesis allowance cannot process supplementary claims")
            validate_dossier(scan,target,repositories,effective_support(scan,target,repositories,finding,used_optional=set()))
        except EvidenceIssue as exc:
            closure=next((row for row in non_promoted if row["id"]==finding["id"] and row["disposition"]=="evidence_limited"),None)
            if closure is None:
                raise ValueError(f"{finding['id']}: {exc.code}; targeted source review or precise deferral is required") from None
            issues=claim_diagnostics(scan,target,repositories,finding,owner="synthesis/findings.json",item_id=finding["id"])
            issues.append(diagnostic(exc.code,"synthesis/findings.json",finding["id"],[finding["id"]]))
            closure["diagnostics"]=issues
            diagnostics.extend(issues)
            continue
        if finding["id"] in ids:raise ValueError("eligible finding also has non-promoted disposition")
        diagnostics.extend(finding_diagnostics)
        retained.append(finding)
    doc["findings"]=retained
    doc["non_promoted"]=non_promoted
    doc["input_claims"]=account_inputs(inputs,retained,non_promoted,doc.get("input_claims"),unreviewed=unreviewed)
    doc["evidence_quality"]=summarize(diagnostics)
    doc["objective_assessments"]=objective_assessments(scan,retained)
    if assessment_ref(context):doc["assessment_context"]=assessment_ref(context)
    return doc
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("scan_base",type=Path)
    p.add_argument("--stage",choices=("complete","original","supplementary"),default="complete")
    p.add_argument("--supplementary-failed",action="store_true")
    p.add_argument("--list-prior-reports",action="store_true",
                   help="Read available completed ordinary sibling reports without changing the audit")
    a=p.parse_args()
    if a.list_prior_reports:
        print(json.dumps(list(prior_reports(a.scan_base)),indent=2))
        return 0
    root=Path(__file__).resolve().parent.parent
    context=json.loads(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")).read_text())
    path=a.scan_base/"synthesis/findings.json"
    original_path=a.scan_base/"synthesis/original-findings.json"
    try:
        require_active_phase(a.scan_base,context,"synthesis")
        routing=context["model_routing"]
        if a.supplementary_failed and a.stage!="supplementary":
            raise ValueError("optional failure closure requires supplementary synthesis")
        if a.stage=="original":
            require_cohort(context,"synthesis","original")
            doc=json.loads((a.scan_base/"synthesis/original-draft.json").read_text())
        elif a.stage=="supplementary":
            original=load_original_draft(a.scan_base,context,"synthesis/original-findings.json")
            validate_publication_schema(original,"synthesis-findings.schema.json")
            if a.supplementary_failed:
                doc=close_supplementary_draft(a.scan_base,context,original)
            else:
                require_synthesis_publication(context,"supplementary")
                doc=json.loads((a.scan_base/"synthesis/supplementary-draft.json").read_text())
                preserve_original(original,doc)
        else:
            if accepted_candidates(a.scan_base,context=context):
                raise ValueError("accepted supplementary candidates require protected staged synthesis")
            doc=json.loads(path.read_text())
        doc=finalize_document(a.scan_base,context,doc,include_supplementary=a.stage!="original")
        doc["prior_run_reconciliation"]=reconcile_prior(context,a.scan_base,doc)
        errors=[]
        target=Path(context.get("source_root") or context["repo_path"])
        index=json.loads((a.scan_base/"campaign-planning/evidence-index.json").read_text())
        intrusion=json.loads((a.scan_base/"intrusion/intrusion-results.json").read_text())
        semantic_synthesis(a.scan_base,target,doc,index,intrusion,"",errors,context)
        if errors:raise ValueError("; ".join(errors))
        if a.stage=="supplementary":preserve_original(original,doc)
        if a.stage=="original":
            write(original_path,doc)
            bind_original_draft(context,"synthesis/original-findings.json")
            return 0
    except (ValueError,OSError,KeyError,TypeError) as exc:print(f"synthesis provenance/reconciliation: {exc}",file=sys.stderr);return 1
    write(path,doc)
    findings=json.loads(path.read_text()).get("findings",[]);counts={name:sum(x.get("origin")==name for x in findings) for name in ("standalone_known","known_impact_expansion","composite_chain","independent_discovery","cross_evidence_discovery")};needs=sum(x.get("status")=="needs_environment" for x in findings)
    limited=sum(row["disposition"]=="evidence_limited" for row in doc["non_promoted"])
    unreviewed_summary=f"\n- Unreviewed supplementary inputs: {len(doc['unreviewed'])}\n" if doc.get("unreviewed") else ""
    (a.scan_base/"synthesis/summary.md").write_text("# Synthesis\n\n"+"\n".join(f"- {k.replace('_',' ').title()}: {v}" for k,v in counts.items())+f"\n- Needs environment: {needs}\n- Evidence-limited claims: {limited}\n"+unreviewed_summary)
    manifest={"phase":"synthesis","status":"degraded" if needs else "ok","started_at":now(),"completed_at":now(),"inputs":["campaign-planning/evidence-index.json","intrusion/intrusion-results.json","sast/verified-findings.json"],"outputs":["synthesis/findings.json","synthesis/summary.md"],"coverage":{"findings":len(findings),"needs_environment":needs,"evidence_limited":limited,"input_claims":len(doc["input_claims"]),**counts},"tool_versions":{"synthesis_model":routing["agents"]["vulnops-synthesis"]},"warnings":[],"errors":[]}
    if accepted(a.scan_base,context=context) is not None:
        manifest["inputs"].append("gap-exploration/results.json")
        manifest["coverage"]["unreviewed"]=len(doc.get("unreviewed",[]))
        if doc.get("unreviewed"):manifest["status"]="degraded"
    write(a.scan_base/"synthesis/phase-manifest.json",manifest)
    return 0
if __name__=="__main__":raise SystemExit(main())
