#!/usr/bin/env python3
"""Validate the canonical schema 2.0 phase contract used by VulnOps V5."""
from __future__ import annotations
import argparse, copy, hashlib, importlib.util, json, os, subprocess, sys
from pathlib import Path
from typing import Any
from artifact_policy import oversized_artifacts, phase_for_artifact
from run_lifecycle import run_status, current_assessment, assessment_ref, routing_for_artifact
from sast_contract import validate_hunt_result, validate_retained_hunt, effective_threat_model, validate_sast_evidence_accounting, validate_recon_provenance
from campaign_contract import validate_selection
from intrusion_contract import validate_intrusion, primitive_updates_view, result_evidence_diagnostics
from model_identity import finding_contributors, finding_diversity, diversity_summary, contributor_union, validate_provenance
from investigation_experiments import validate_result as validate_experiment_result
from evidence_refs import artifact_value, validate_evidence_refs
from evidence_accounting import classify_refs, summarize, validate_non_promoted
from exploration_evidence import recon_evidence_quality
from objective_contract import validate_investigation_document
from dossier_contract import objective_assessments
from synthesis_contract import semantic_synthesis
from gap_dossier import (accepted_candidates, synthesis_selector, validate_unreviewed,
                         validate_review_admission)
PHASE_DIR={"recon":"repo-context","tool-collection":"tool-collection","sast":"sast","campaign-planning":"campaign-planning","intrusion":"intrusion","gap-exploration":"gap-exploration","synthesis":"synthesis","final-verification":"final-verification","report":"report"}
def load(path:Path,errors:list[str])->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,UnicodeError,json.JSONDecodeError) as exc:errors.append(f"cannot read {path}: {exc}")
    return None
def schema(root:Path,name:str,path:Path,errors:list[str],each:bool=False,semantic:str|None=None,target:Path|None=None)->None:
    command=[sys.executable,str(root/"scripts/validate-json.py"),str(root/f"schemas/v2/{name}"),str(path)]+(["--each"] if each else [])
    if semantic:command.extend(["--semantic",semantic])
    if target is not None:command.extend(["--target",str(target)])
    result=subprocess.run(command,capture_output=True,text=True,check=False)
    if result.returncode:errors.append(result.stderr.strip() or f"schema failure: {path}")
def artifact(scan:Path,ref:str)->Path|None:
    relative=ref.split(":",1)[0].split("#",1)[0]; path=(scan/relative).resolve()
    try:path.relative_to(scan.resolve())
    except ValueError:return None
    return path if path.is_file() else None
def target_file(target:Path,relative:str)->bool:
    path=(target/relative).resolve()
    try:path.relative_to(target.resolve())
    except ValueError:return False
    return path.is_file()
def manifest(scan:Path,phase:str,errors:list[str])->dict:
    directory=PHASE_DIR[phase]; doc=load(scan/directory/"phase-manifest.json",errors)
    if not isinstance(doc,dict):return {}
    if doc.get("phase")!=phase:errors.append(f"{phase} manifest phase mismatch")
    if doc.get("status") not in ({"ok","degraded","skipped"} if phase=="gap-exploration" else {"ok","degraded"}):errors.append(f"{phase} manifest is not successful terminal state")
    for key in ("started_at","completed_at"):
        if not isinstance(doc.get(key),str) or not doc[key]:errors.append(f"{phase} manifest missing {key}")
    for key in ("inputs","outputs","warnings","errors"):
        if not isinstance(doc.get(key),list):errors.append(f"{phase} manifest missing list {key}")
    if doc.get("errors"):
        errors.append(f"{phase} successful terminal manifest may not contain errors")
    for ref in doc.get("outputs",[]) if isinstance(doc.get("outputs"),list) else []:
        if artifact(scan,str(ref)) is None:errors.append(f"{phase} manifest output does not resolve: {ref}")
    return doc
def semantic_campaign(scan:Path,target:Path,index:dict,plan:dict,errors:list[str],context:dict)->None:
    records={x.get("id"):x for x in index.get("records",[]) if isinstance(x,dict)}; primitives={x.get("id"):x for x in index.get("primitives",[]) if isinstance(x,dict)}
    if len(records)!=len(index.get("records",[])):errors.append("evidence record IDs must be unique")
    if len(primitives)!=len(index.get("primitives",[])):errors.append("primitive IDs must be unique")
    for record in records.values():
        try:
            contributors=record.get("contributors",[])
            if contributors:
                expected=finding_contributors(scan,{"verification":{"source_validation_refs":[item["artifact_ref"] for item in contributors]}},context["model_routing"],source_root=target,repositories=context["repositories"])
                if contributors!=expected:raise ValueError("evidence record contributor set is not canonical")
            if record.get("source_kind") in {"recon","reproduction"} or record.get("artifact_ref","").startswith(("sast/raw-findings.json:", "sast/verified-findings.json:", "sast/validation-results.json:")):
                source = artifact_value(scan, record["artifact_ref"])
                actual = source.get("contributors", [])
                if record["source_kind"] == "sast":
                    reviews = load(scan/"sast/validation-results.json", errors) or []
                    review = next((row for row in reviews if row["candidate_id"] == record["source_id"]), None)
                    if review:
                        actual = contributor_union(actual, [review["provenance"]])
                if record["artifact_ref"].startswith("sast/validation-results.json:"):
                    candidate_id = source["candidate_id"]
                    owner = artifact_value(scan, f"sast/validation-queue.json:{candidate_id}")
                    verified = load(scan/"sast/verified-findings.json", errors) or []
                    owner = next((row for row in verified if row["id"] == candidate_id), owner)
                    provenance = validate_provenance(source["provenance"], routing_for_artifact(scan,f"sast/verify/{candidate_id}.json",context["model_routing"]),
                        "vulnops-verify-one", f"sast/verify/{candidate_id}.json")
                    if record["source_id"] != source["id"] or artifact_value(scan, provenance["artifact_ref"]) != source:
                        raise ValueError("review record differs from its source-owned publication")
                    actual = contributor_union(owner["contributors"], [provenance])
                if contributors != actual:
                    raise ValueError("evidence record contributors differ from canonical source ownership")
            if record.get("source_kind") in {"sca","secret","tool_warning"} and contributors:raise ValueError("deterministic scanner output must not have model contributors")
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(f"{record.get('id')}: {exc}")
    line_counts={}
    for primitive in primitives.values():
        expected=contributor_union(*(records.get(rid,{}).get("contributors",[]) for rid in primitive.get("source_record_ids",[])))
        if primitive.get("contributors")!=expected:errors.append(f"{primitive.get('id')} contributors differ from canonical source records")
        try:
            _,issues=classify_refs(scan,target,context["repositories"],primitive["evidence_refs"],owner=primitive["id"],field="evidence_refs",affected_item_ids=[primitive["id"]],historical=not current_assessment(primitive,context))
            if issues and primitive.get("trust")=="confirmed":errors.append("unusable evidence cannot establish a confirmed primitive")
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
    expected_sources=[]
    for path,key in ((scan/"tool-collection/sca-advisories.json","advisories"),(scan/"tool-collection/secrets-redacted.json","candidates"),(scan/"sast/verified-findings.json",None),(scan/"sast/dropped-findings.json",None)):
        doc=load(path,errors)
        items=doc.get(key,[]) if key and isinstance(doc,dict) else doc if isinstance(doc,list) else []
        for item in items:
            if not isinstance(item,dict):continue
            source_id=str(item.get("raw_id") or item.get("id"))
            source_kind="sca" if key=="advisories" else "secret" if key=="candidates" else "sast"
            expected_sources.append((source_kind,source_id))
    indexed_sources={(str(item.get("source_kind")),str(item.get("source_id"))) for item in records.values()}
    for source in expected_sources:
        if source not in indexed_sources:errors.append(f"upstream evidence is missing from canonical index: {source[0]}:{source[1]}")
    for primitive in primitives.values():
        for rid in primitive.get("source_record_ids",[]):
            if rid not in records:errors.append(f"primitive {primitive.get('id')} references unknown record {rid}")
            elif primitive.get("type")=="credential" and records[rid].get("source_kind")=="secret" and records[rid].get("disposition")=="unresolved":
                errors.append(f"primitive {primitive.get('id')} promotes an unverified secret scanner candidate")
    campaigns=plan.get("campaigns",[]); ids=[x.get("id") for x in campaigns if isinstance(x,dict)]
    if len(ids)!=len(set(ids)):errors.append("campaign IDs must be unique")
    for campaign in campaigns:
        for rid in campaign.get("starting_evidence",[]):
            if rid not in records:errors.append(f"{campaign.get('id')} references unknown evidence {rid}")
        for pid in campaign.get("primitive_ids",[]):
            if pid not in primitives:errors.append(f"{campaign.get('id')} references unknown primitive {pid}")
        for relative in campaign.get("source_files",[]):
            if not target_file(target,str(relative)):errors.append(f"{campaign.get('id')} source file does not exist: {relative}")
        question_ids=set()
        for question in campaign.get("graph_questions",[]):
            qid=question.get("id")
            if qid in question_ids:errors.append(f"{campaign.get('id')} graph question IDs must be unique")
            question_ids.add(qid)
    coverage=plan.get("coverage") or {}
    if coverage.get("evidence_records")!=len(records) or coverage.get("primitives")!=len(primitives) or coverage.get("campaigns")!=len(campaigns):errors.append("campaign plan coverage counts do not match canonical artifacts")
def semantic_intrusion(scan:Path,target:Path,index:dict,results:dict,errors:list[str],context:dict)->None:
    try:validate_intrusion(scan,target,context,index,results)
    except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
def validate_final_results(root:Path,scan:Path,target:Path,context:dict,final:dict,errors:list[str])->None:
    spec=importlib.util.spec_from_file_location("final_verification_contract",root/"scripts/finalize-verification.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    source=load(scan/"synthesis/findings.json",errors) or {}
    index=load(scan/"campaign-planning/evidence-index.json",errors) or {}
    intrusion=load(scan/"intrusion/intrusion-results.json",errors) or {}
    primitives={item["id"]:item for item in index.get("primitives",[])}
    primitives.update({item["id"]:item for result in intrusion.get("results",[]) for item in primitive_updates_view(scan,context,result)})
    expected_findings=[];expected_rejections=[];expected_limited=copy.deepcopy(source.get("non_promoted",[]));diagnostics=[]
    supplements=accepted_candidates(scan,context=context)
    inherited=source.get("unreviewed",[])
    supplied=final.get("unreviewed",[])
    if supplied[:len(inherited)]!=inherited:
        errors.append("final unreviewed closures do not preserve synthesis dispositions")
    unreviewed=supplied[len(inherited):]
    try:
        validate_unreviewed(scan,context,inherited,supplements,"synthesis")
        validate_unreviewed(scan,context,unreviewed,source.get("findings",[]),"final-verification")
    except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
    unreviewed_ids={row["id"] for row in unreviewed}
    for candidate in source.get("findings",[]):
        fid=candidate["id"];ref=f"final-verification/results/{fid}.json"
        if fid in unreviewed_ids:continue
        result=load(scan/ref,errors)
        if not isinstance(result,dict):continue
        try:
            routing=context["model_routing"]
            if assessment_ref(context) and not current_assessment(result,context):
                raise ValueError("independent result lacks current assessment_context")
            validate_review_admission(scan,context,candidate,result)
            finding=module.validate_assessment(root,scan,target,candidate,result,synthesis_selector(scan,context,candidate),primitives,routing,repositories=context["repositories"])
            diagnostics.extend(module.assessment_diagnostics(scan,target,context["repositories"],candidate,result,routing,primitives))
            status=result["status"]
            if status=="evidence_limited":
                expected_limited.append(result["non_promoted"])
                continue
            if status=="rejected":
                rejection={"id":fid,"reason":result["closure_reason"],"independent_verification_ref":ref}
                if assessment_ref(context):rejection["assessment_context"]=assessment_ref(context)
                expected_rejections.append(rejection)
                continue
            if status=="needs_environment":
                finding["status"]="needs_environment"
                finding["verification"]={**finding["verification"],"level":"environment_required"}
                finding["closure_rationale"]=result["closure_reason"]
            finding.update(verdict="needs_environment" if finding["status"]=="needs_environment" else "confirmed",
                           model_diversity=finding_diversity(finding["contributors"],result["model"]),independent_verification_ref=ref)
            if assessment_ref(context):finding["assessment_context"]=assessment_ref(context)
            expected_findings.append(finding)
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(f"{fid}: {exc}")
    if final.get("findings")!=expected_findings or final.get("rejections")!=expected_rejections:
        errors.append("final findings differ from effective independently assessed claims")
    if final.get("non_promoted",[])!=expected_limited:errors.append("final local dispositions differ from source-owned assessments")
    if final.get("evidence_quality",summarize([]))!=summarize(diagnostics):
        errors.append("final evidence-quality accounting differs from independent assessments")
    terminal={row["id"]:"eligible" for row in expected_findings}
    terminal.update({row["id"]:"rejected" for row in expected_rejections})
    terminal.update({row["id"]:row["disposition"] for row in expected_limited})
    terminal.update({row["id"]:"unreviewed" for row in unreviewed})
    expected_claims=copy.deepcopy(source.get("input_claims",[]))
    for row in expected_claims:
        outcomes={terminal[fid] for fid in row["finding_ids"] if fid in terminal}
        if row["finding_ids"] and not outcomes:errors.append("final input claim has no terminal disposition")
        if outcomes and "eligible" not in outcomes:row["disposition"]="unreviewed" if "unreviewed" in outcomes else "evidence_limited" if "evidence_limited" in outcomes else "rejected"
    if final.get("input_claims",[])!=expected_claims:errors.append("final input claim accounting differs from assessed outcomes")
    try:
        aggregate=diversity_summary(expected_findings)
        if any(final.get(key)!=value for key,value in aggregate.items()):errors.append("final diversity aggregate differs from accepted findings")
        if final.get("verifier_model")!=context["model_routing"]["agents"]["vulnops-independent-verify-one"]:errors.append("final verifier route mismatch")
    except (ValueError,KeyError,TypeError) as exc:errors.append(str(exc))
    expected_ids={item["id"] for item in source.get("findings",[])}
    actual_ids={path.stem for path in (scan/"final-verification/results").glob("*.json")}
    if not (expected_ids-unreviewed_ids)<=actual_ids or not actual_ids<=expected_ids:
        errors.append("independent verifier result owner set differs from synthesis")
    try:
        reviews={item["id"]:load(scan/"final-verification/results"/f"{item['id']}.json",errors)
                 for item in source.get("findings",[]) if item["id"] not in unreviewed_ids}
        objectives=objective_assessments(scan,expected_findings,results=reviews,candidates=source["findings"])
        if assessment_ref(context):
            for row in objectives:row["assessment_context"]=assessment_ref(context)
        if final.get("objective_assessments")!=objectives:
            errors.append("final objective outcomes differ from independently reviewed success conditions")
    except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("harness_root",type=Path); p.add_argument("scan_base",type=Path); p.add_argument("phase",choices=tuple(PHASE_DIR)); a=p.parse_args(); root=a.harness_root.resolve(); scan=a.scan_base.resolve(); errors=[]
    run=load(scan/"run-manifest.json",errors)
    if not isinstance(run,dict):
        errors.append("run-manifest.json: expected object");run={}
    if not isinstance(run.get("run_id"),str) or not run["run_id"]:
        errors.append("run-manifest.json: missing or invalid run_id")
    if run.get("workflow")!="canonical-redteam-v2":
        errors.append("run-manifest.json: invalid workflow (ordinary audit required)")
    try:run_status(run.get("status"))
    except ValueError as exc:errors.append(f"run-manifest.json: invalid status: {exc}")
    phases=run.get("phases")
    if not isinstance(phases,dict) or not isinstance(phases.get(a.phase),str) or phases[a.phase] not in {"ok","degraded","skipped","pending","running","failed"}:
        errors.append(f"run-manifest.json: missing or invalid phases.{a.phase}")
    if errors:
        for error in errors:print(f"[validate-phase-v2] ERROR: {error}",file=sys.stderr)
        return 1
    if phases[a.phase] in {"ok","degraded","skipped"}:
        print(f"[validate-phase-v2] {a.phase} accepted checkpoint (historical output not replayed)")
        return 0
    context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")),errors) or {}
    target=Path(str(context.get("source_root") or context.get("repo_path","")))
    if Path(str(context.get("scan_base",""))).resolve()!=scan:errors.append("audit context scan mismatch")
    if context.get("run_id")!=run.get("run_id"):errors.append("audit context run mismatch")
    if context.get("workflow")!="canonical-redteam-v2":errors.append("audit context is not the canonical greenfield workflow")
    if a.phase!="report" and not target.is_dir():errors.append("audit context source_root: current source is unavailable")
    phase=a.phase
    for relative,size,limit in oversized_artifacts(scan):
        if phase_for_artifact(relative)==phase:errors.append(f"artifact exceeds bounded size policy: {relative} ({size}>{limit})")
    if phase=="recon":
        for path in (scan/"repo-context/repo.md",):
            if not path.is_file():errors.append(f"missing {path}")
        schema(root,"repo-context.schema.json",scan/"repo-context/repo-context.json",errors,semantic="repo-context",target=target); schema(root,"security-surfaces.schema.json",scan/"repo-context/security-surfaces.json",errors,semantic="security-surfaces",target=target)
        for name in ("overview.json","trust-boundaries.json","input-surfaces.json"):schema(root,"recon-research.schema.json",scan/"repo-context/research"/name,errors)
        try:validate_recon_provenance(scan,context.get("model_routing") or {})
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
        try:
            expected_quality = recon_evidence_quality(scan, target, context["repositories"])
            document = load(scan/"repo-context/repo-context.json", errors) or {}
            if document.get("evidence_quality", summarize([])) != expected_quality:
                errors.append("Recon evidence-quality accounting differs from owned source publications")
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
    elif phase=="tool-collection":
        schema(root,"sca-advisories.schema.json",scan/"tool-collection/sca-advisories.json",errors,semantic="sca-advisories",target=target); schema(root,"secrets-redacted.schema.json",scan/"tool-collection/secrets-redacted.json",errors,semantic="secrets-redacted",target=target); schema(root,"dependency-limitations.schema.json",scan/"tool-collection/dependency-limitations.json",errors); schema(root,"tool-collection.schema.json",scan/"tool-collection/collection.json",errors)
        for name,artifact_name in (("wraith-receipt.json","sca-advisories.json"),("poltergeist-receipt.json","secrets-redacted.json")):
            schema(root,"tool-receipt.schema.json",scan/"tool-collection"/name,errors); receipt=load(scan/"tool-collection"/name,errors)
            if isinstance(receipt,dict) and (scan/"tool-collection"/artifact_name).is_file() and receipt.get("normalized_sha256")!=hashlib.sha256((scan/"tool-collection"/artifact_name).read_bytes()).hexdigest():errors.append(f"{name} normalized hash mismatch")
            if isinstance(receipt,dict) and (receipt.get("status")!="ok" or receipt.get("parse_status")!="ok" or receipt.get("warnings")):errors.append(f"{name} must be healthy and warning-free")
        collection_doc=load(scan/"tool-collection/collection.json",errors) or {}
        limitation_doc=load(scan/"tool-collection/dependency-limitations.json",errors) or {}
        if collection_doc.get("limitations")!=limitation_doc.get("limitations"):errors.append("tool collection limitations differ from the staged authority")
        if collection_doc.get("warnings"):errors.append("tool collection must not publish warnings")
    elif phase=="sast":
        schema(root,"threat-model.schema.json",scan/"sast/threat-model.json",errors); schema(root,"hunt-plan.schema.json",scan/"sast/hunt-plan.json",errors); schema(root,"candidate-finding.schema.json",scan/"sast/raw-findings.json",errors,True); schema(root,"validation-result.schema.json",scan/"sast/validation-results.json",errors,True); schema(root,"coverage-ledger.schema.json",scan/"sast/coverage-ledger.json",errors); schema(root,"wishlist.schema.json",scan/"sast/wishlist.json",errors)
        try:validate_sast_evidence_accounting(scan,context.get("model_routing") or {},source_root=target,repositories=context["repositories"])
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
        hunt_plan=load(scan/"sast/hunt-plan.json",errors) or {}; threat_doc=load(scan/"sast/threat-model.json",errors) or {}; expected_packets=set();cell_map={str(cell.get("id")):cell for cell in hunt_plan.get("cells",[]) if isinstance(cell,dict)};packet_limit=int((hunt_plan.get("budget") or {}).get("context_packet_bytes",65536))
        ledger=load(scan/"sast/coverage-ledger.json",errors) or {}
        accepted_tasks={row.get("id"):row for row in ledger.get("tasks",[]) if isinstance(row,dict) and row.get("artifact_valid")}
        for kind,document in (("threat-model",threat_doc),("hunt-plan",hunt_plan)):
            try:validate_investigation_document(scan,target,context["repositories"],document,kind)
            except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
        mapping_map={str(mapping.get("id")):mapping for mapping in threat_doc.get("hunt_mappings",[]) if isinstance(mapping,dict)};base_cells=[cell for cell in cell_map.values() if cell.get("lead_key") is None]
        if {str(cell.get("mapping_id")) for cell in base_cells}!=set(mapping_map):errors.append("hunt plan cells do not match the threat-model mapping set")
        for cell in base_cells:
            mapping=mapping_map.get(str(cell.get("mapping_id")))
            if not mapping:continue
            expected={"surface_ids":mapping.get("surface_ids"),"subsystem":mapping.get("subsystem_id"),"attack_class_id":mapping.get("attack_class_id"),"priority":mapping.get("priority"),"threat_ids":mapping.get("threat_ids"),"asset_ids":mapping.get("asset_ids"),"attacker":mapping.get("attacker"),"entrypoint_ids":mapping.get("entrypoint_ids"),"boundary_ids":mapping.get("boundary_ids"),"files":mapping.get("source_files"),"security_question":mapping.get("security_question"),"stop_conditions":mapping.get("stop_conditions"),"applicability_reason":mapping.get("applicability_reason")}
            if any(cell.get(key)!=value for key,value in expected.items()):errors.append(f"hunt cell does not preserve contextual mapping: {cell.get('id')}")
        phase_threat=threat_doc
        validated_amendments={}
        for task in hunt_plan.get("tasks",[]):
            task_id=str(task.get("id","")); expected_packets.add(f"{task_id}.json"); packet=load(scan/"sast/hunt-tasks"/f"{task_id}.json",errors) or {}
            expected_cells=packet.get("cells",[])
            if packet.get("run_id")!=hunt_plan.get("run_id") or packet.get("hunt_plan_ref")!="sast/hunt-plan.json" or packet.get("task")!=task:
                errors.append(f"hunt task packet mismatch: {task_id}")
            if {cell.get("id") for cell in expected_cells if isinstance(cell,dict)}!=set(task.get("cell_ids",[])):
                errors.append(f"hunt task packet cell ownership mismatch: {task_id}")
            for key,ids_key in (("attack_objectives","objective_ids"),("investigation_questions","question_ids")):
                if {row.get("id") for row in packet.get(key,[]) if isinstance(row,dict)}!=set(task[ids_key]):
                    errors.append(f"hunt packet {key} differs from assigned questions: {task_id}")
            packet_path=scan/"sast/hunt-tasks"/f"{task_id}.json"
            if packet_path.is_file() and packet_path.stat().st_size>packet_limit:errors.append(f"hunt task packet exceeds bounded context: {task_id}")
            if task_id in hunt_plan.get("deferred_task_ids",[]):
                deferred=next((row for row in ledger.get("tasks",[]) if row.get("id")==task_id),{})
                if deferred.get("status")!="deferred" or deferred.get("artifact_valid") is not False:
                    errors.append(f"deferred hunt task lacks allocation-limit disposition: {task_id}")
                continue
            result_path=scan/"sast/deepdive"/f"{task_id}.json"; result=load(result_path,errors)
            if isinstance(result,dict):
                retained=context.get("attempt_id") and task_id in accepted_tasks and accepted_tasks[task_id].get("attempt_id")!=context["attempt_id"]
                try:
                    result_errors=(validate_retained_hunt(task,expected_cells,result) if retained else
                        validate_hunt_result(root,target,task,[cell for cell in expected_cells if isinstance(cell,dict)],result,phase_threat,context.get("repositories"),context.get("model_routing"),scan=scan))
                except (ValueError,KeyError,TypeError) as exc:result_errors=[str(exc)]
                errors.extend(f"{task_id}: {message}" for message in result_errors)
                if not result_errors:
                    phase_threat=effective_threat_model(phase_threat,result.get("model_amendments",[]))
                    validated_amendments.update({item["id"]:item for item in result.get("model_amendments",[])})
        for amendment in hunt_plan.get("model_amendments",[]):
            if validated_amendments.get(amendment.get("id"))!=amendment:errors.append("hunt plan amendment lacks validated worker provenance")
        actual_packets={path.name for path in (scan/"sast/hunt-tasks").glob("*.json")} if (scan/"sast/hunt-tasks").is_dir() else set()
        if actual_packets!=expected_packets:errors.append("hunt task packet set does not match hunt plan")
        for name in ("verified-findings.json","dropped-findings.json","dedup-clusters.json"):
            if not isinstance(load(scan/"sast"/name,errors),list if name!="dedup-clusters.json" else dict):errors.append(f"sast/{name} has wrong shape")
    elif phase=="campaign-planning":
        schema(root,"evidence-index.schema.json",scan/"campaign-planning/evidence-index.json",errors); schema(root,"campaign-plan.schema.json",scan/"campaign-planning/campaign-plan.json",errors); index=load(scan/"campaign-planning/evidence-index.json",errors) or {}; plan=load(scan/"campaign-planning/campaign-plan.json",errors) or {}
        semantic_campaign(scan,target,index,plan,errors,context)
        try:validate_selection(scan,target,context,plan)
        except (ValueError,OSError) as exc:errors.append(str(exc))
    elif phase=="intrusion":
        schema(root,"intrusion-results.schema.json",scan/"intrusion/intrusion-results.json",errors)
        results=load(scan/"intrusion/intrusion-results.json",errors) or {}
        semantic_intrusion(scan,target,load(scan/"campaign-planning/evidence-index.json",errors) or {},results,errors,context)
    elif phase=="gap-exploration":
        try:
            from gap_exploration_contract import validate_phase
            validate_phase(scan,context)
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
    elif phase=="synthesis":
        schema(root,"synthesis-findings.schema.json",scan/"synthesis/findings.json",errors); doc=load(scan/"synthesis/findings.json",errors) or {}; index=load(scan/"campaign-planning/evidence-index.json",errors) or {}; intrusion=load(scan/"intrusion/intrusion-results.json",errors) or {}; semantic_synthesis(scan,target,doc,index,intrusion,str(run.get("model","")),errors,context)
        try:
            spec=importlib.util.spec_from_file_location("synthesis_accounting",root/"scripts/finalize-synthesis.py")
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            expected=module.finalize_document(scan,context,copy.deepcopy(doc))
            for key in ("input_claims","non_promoted","unreviewed","evidence_quality","objective_assessments"):
                if doc.get(key)!=expected.get(key):errors.append(f"synthesis {key} differs from canonical local accounting")
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
    elif phase=="final-verification":
        schema(root,"final-findings.schema.json",scan/"final-verification/findings.json",errors);final_doc=load(scan/"final-verification/findings.json",errors) or {};synthesis_items=[]
        validate_final_results(root,scan,target,context,final_doc,errors)
        for item in final_doc.get("findings",[]):
            if artifact(scan,str(item.get("independent_verification_ref",""))) is None:errors.append(f"{item.get('id')} independent verification reference does not resolve")
        for item in final_doc.get("rejections",[]):
            if artifact(scan,str(item.get("independent_verification_ref",""))) is None:errors.append(f"{item.get('id')} rejection reference does not resolve")
    elif phase=="report":
        schema(root,"report.schema.json",scan/"report/security-report.json",errors)
        report=load(scan/"report/security-report.json",errors) or {}
        final=load(scan/"final-verification/findings.json",errors) or {}
        try:
            spec=importlib.util.spec_from_file_location("report_accounting",root/"scripts/render-report.py")
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            support_limitations=module.validate_accepted_authority(scan,final,context)
            if not set(support_limitations)<=set(report.get("limitations",[])):
                errors.append("report omits unavailable retained supporting-reference limitations")
            projection=module.assessment_projection(final,context)
            for key,value in projection.items():
                if report.get(key)!=value:errors.append(f"report {key} differs from recorded assessment scope")
            if report.get("gap_exploration")!=module.gap_projection(scan,projection["findings"],context):
                errors.append("report supplementary outcomes differ from accepted investigation and independent review")
            aggregate=diversity_summary(projection["findings"])
            for key,value in aggregate.items():
                if report.get(key)!=value:errors.append(f"report {key} differs from accepted findings")
            records=[*projection["findings"],*projection["rejections"],*projection["non_promoted"],*projection["unreviewed"],*projection["objective_assessments"]]
            if report.get("assessment")!=module.report_assessment(context,records or [final]):
                errors.append("report assessment differs from accepted source scopes")
            repositories=[]
            for scope in report.get("assessment",{}).get("scopes",[]):
                for repository in scope.get("repositories") or []:
                    if repository not in repositories:repositories.append(repository)
            if report.get("repositories")!=repositories:
                errors.append("report repositories differ from accepted source scopes")
            if report.get("model_routing")!=module.accepted_routing(final,context):
                errors.append("report model_routing differs from recorded producing assignment")
            if report.get("verifier_model")!=final.get("verifier_model"):
                errors.append("report verifier_model differs from accepted final verification")
            summary=report.get("summary",{})
            confirmed=[row for row in projection["findings"] if row["verdict"]=="confirmed"]
            expected_counts={"total":len(projection["findings"]),"confirmed":len(confirmed),
                             "rejected":len(projection["rejections"]),
                             "unreviewed":len(projection["unreviewed"]),
                             "needs_environment":sum(row["verdict"]=="needs_environment" for row in projection["findings"])}
            for severity in module.SEVERITIES:
                expected_counts[severity]=sum(row["severity"]==severity for row in confirmed)
            for origin in module.ORIGINS:
                expected_counts[origin]=sum(row["origin"]==origin for row in confirmed)
            for key,value in expected_counts.items():
                if summary.get(key)!=value:errors.append(f"report summary.{key} differs from accepted assessment projection")
            if (scan/"report/security-report.md").read_text(encoding="utf-8")!=module.render_markdown(report,scan):
                errors.append("report Markdown differs from its canonical dossier projection")
            explanation_limits=[]
            quality,limited=module.evidence_accounting(scan,final,explanation_limits,context)
            accounting=report.get("investigation_accounting",{})
            if (report.get("evidence_quality")!=quality or accounting.get("evidence_limited")!=limited[:200]
                    or accounting.get("counts",{}).get("evidence_limited")!=len(limited)
                    or accounting.get("truncated",{}).get("evidence_limited")!=max(0,len(limited)-200)
                    or report.get("summary",{}).get("evidence_limited")!=len(limited)):
                errors.append("report evidence quality accounting differs from owning phase publications")
            coverage_input=module.coverage_input(scan,explanation_limits,context)
            coverage_projection=module.sanitized({key:value[:200] if isinstance(value,list) else value for key,value in coverage_input.items()})
            if report.get("coverage")!=coverage_projection:
                errors.append("report coverage differs from available historical accounting")
            if coverage_input.get("availability")=="unavailable" and coverage_input["limitation"] not in report.get("limitations",[]):
                errors.append("report omits unavailable historical coverage limitation")
            historical=module.investigation_accounting(scan,coverage_input,explanation_limits,context)
            history=module.sanitized(historical["historical_planning_deferrals"])
            history_count=historical["counts"]["historical_planning_deferrals"]
            history_omitted=max(0,history_count-200) if history_count is not None else None
            if any(limit not in report.get("limitations",[]) for limit in explanation_limits):
                errors.append("report omits unavailable explanatory context limitation")
            if (accounting.get("historical_planning_deferrals")!=history[:200]
                    or accounting.get("counts",{}).get("historical_planning_deferrals")!=history_count
                    or accounting.get("truncated",{}).get("historical_planning_deferrals")!=history_omitted
                    or report.get("summary",{}).get("historical_planning_deferrals")!=history_count):
                errors.append("report historical planning accounting differs from planning publications")
        except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(str(exc))
    if phase in {"sast","intrusion"}:
        for directory in sorted((scan/phase/"experiments").glob("*")):
            try:
                request_path=directory/"request.json"
                request=load(request_path,errors)
                result=load(directory/"result.json",errors)
                if not isinstance(request,dict) or not isinstance(result,dict):continue
                if directory.name!=request.get("experiment_id") or request.get("owner_phase")!=phase:
                    raise ValueError("experiment directory differs from its phase owner")
                validate_experiment_result(context,request,result,request_path)
            except (ValueError,OSError,KeyError,TypeError) as exc:errors.append(f"invalid experiment: {exc}")
    schema(root,"phase-manifest.schema.json",scan/PHASE_DIR[phase]/"phase-manifest.json",errors)
    phase_manifest=manifest(scan,phase,errors)
    coverage=phase_manifest.get("coverage",{}) if isinstance(phase_manifest.get("coverage"),dict) else {}
    expected_phase_status={
        "recon":"ok",
        "tool-collection":"ok",
        "campaign-planning":"ok",
        "intrusion":"degraded" if coverage.get("needs_environment") or coverage.get("execution_failed") else "ok",
        "synthesis":"degraded" if coverage.get("needs_environment") or coverage.get("unreviewed") else "ok",
        "final-verification":"degraded" if coverage.get("needs_environment") or coverage.get("unreviewed") else "ok",
        "report":"degraded" if coverage.get("needs_environment") else "ok",
    }.get(phase)
    if expected_phase_status is not None and phase_manifest.get("status")!=expected_phase_status:
        errors.append(f"{phase} manifest must close {expected_phase_status}; status must reflect material capability loss, not normal operating results")
    if phase=="tool-collection" and (phase_manifest.get("status")!="ok" or phase_manifest.get("warnings")):
        errors.append("healthy deterministic tool collection must close ok and warning-free")
    if phase=="sast":
        ledger_doc=load(scan/"sast/coverage-ledger.json",errors) or {}
        funnel=ledger_doc.get("funnel",{}) if isinstance(ledger_doc,dict) else {}
        cells=ledger_doc.get("cells",[]) if isinstance(ledger_doc,dict) else []
        material_loss=bool(funnel.get("environment_required")) or any(isinstance(cell,dict) and cell.get("status") in {"failed","externally_blocked"} for cell in cells)
        expected_status="degraded" if material_loss else "ok"
        if phase_manifest.get("status")!=expected_status:
            errors.append(f"SAST manifest must close {expected_status}; configured depth limits are BAU coverage, not degradation")
        if any(isinstance(cell,dict) and cell.get("status") in {"deferred","shallow"} for cell in cells):
            errors.append("final SAST coverage must close deferred/shallow cells with their terminal reason")
        for status in ("depth_limited","externally_blocked","locally_unresolved","failed"):
            expected_count=sum(1 for cell in cells if isinstance(cell,dict) and cell.get("status")==status)
            if (phase_manifest.get("coverage") or {}).get(status,0)!=expected_count:
                errors.append(f"SAST manifest {status} count does not match the coverage ledger")
    if phase in {"sast","intrusion","synthesis","final-verification"}:
        if phase=="sast":
            rows=ledger_doc.get("non_promoted",[])
        elif phase=="intrusion":
            rows=[row for result in results.get("results",[]) for row in result.get("non_promoted",[])]
        else:
            rows=(doc if phase=="synthesis" else final_doc).get("non_promoted",[])
        if coverage.get("evidence_limited",0)!=sum(row.get("disposition")=="evidence_limited" for row in rows):
            errors.append("phase evidence-limited count differs from owned dispositions")
    if errors:
        for error in errors:print(f"[validate-phase-v2] ERROR: {error}",file=sys.stderr)
        return 1
    print(f"[validate-phase-v2] {phase} valid");return 0
if __name__=="__main__":raise SystemExit(main())
