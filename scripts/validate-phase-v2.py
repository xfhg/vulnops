#!/usr/bin/env python3
"""Validate the sole canonical VulnOps v2 phase contract."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, subprocess, sys
from pathlib import Path
from typing import Any
from artifact_policy import oversized_artifacts, phase_for_artifact
from harness_contract import harness_contract_sha256
from operator_context import identity as operator_context_identity
from operator_context import inspect_context
from sast_contract import validate_hunt_result
PHASE_DIR={"recon":"repo-context","tool-collection":"tool-collection","sast":"sast","campaign-planning":"campaign-planning","intrusion":"intrusion","synthesis":"synthesis","final-verification":"final-verification","report":"report"}
def load(path:Path,errors:list[str])->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:errors.append(f"missing {path}")
    except json.JSONDecodeError as exc:errors.append(f"invalid JSON {path}: {exc}")
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
    if doc.get("status") not in {"ok","degraded"}:errors.append(f"{phase} manifest is not successful terminal state")
    for key in ("started_at","completed_at"):
        if not isinstance(doc.get(key),str) or not doc[key]:errors.append(f"{phase} manifest missing {key}")
    for key in ("inputs","outputs","warnings","errors"):
        if not isinstance(doc.get(key),list):errors.append(f"{phase} manifest missing list {key}")
    if doc.get("errors"):
        errors.append(f"{phase} successful terminal manifest may not contain errors")
    for ref in doc.get("outputs",[]) if isinstance(doc.get("outputs"),list) else []:
        if artifact(scan,str(ref)) is None:errors.append(f"{phase} manifest output does not resolve: {ref}")
    return doc
def semantic_campaign(scan:Path,target:Path,index:dict,plan:dict,errors:list[str])->None:
    records={x.get("id"):x for x in index.get("records",[]) if isinstance(x,dict)}; primitives={x.get("id"):x for x in index.get("primitives",[]) if isinstance(x,dict)}
    if len(records)!=len(index.get("records",[])):errors.append("evidence record IDs must be unique")
    if len(primitives)!=len(index.get("primitives",[])):errors.append("primitive IDs must be unique")
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
    operator_doc=load(scan/"repo-context/operator-context.json",errors) or {}
    for item in operator_doc.get("observations",[]) if isinstance(operator_doc,dict) else []:
        source=("operator_context",str(item.get("id")))
        if source not in indexed_sources:errors.append(f"upstream evidence is missing from canonical index: {source[0]}:{source[1]}")
    for primitive in primitives.values():
        for rid in primitive.get("source_record_ids",[]):
            if rid not in records:errors.append(f"primitive {primitive.get('id')} references unknown record {rid}")
            elif primitive.get("type")=="credential" and records[rid].get("source_kind")=="secret" and records[rid].get("disposition")=="unresolved":
                errors.append(f"primitive {primitive.get('id')} promotes an unverified secret scanner candidate")
    campaigns=plan.get("campaigns",[]); ids=[x.get("id") for x in campaigns if isinstance(x,dict)]
    if len(ids)!=len(set(ids)):errors.append("campaign IDs must be unique")
    counts={lane:0 for lane in ("primitive_led","gap_driven","direct_validation")}
    for campaign in campaigns:
        counts[campaign.get("lane")]=counts.get(campaign.get("lane"),0)+1
        for rid in campaign.get("starting_evidence",[]):
            if rid not in records:errors.append(f"{campaign.get('id')} references unknown evidence {rid}")
        for pid in campaign.get("primitive_ids",[]):
            if pid not in primitives:errors.append(f"{campaign.get('id')} references unknown primitive {pid}")
        for relative in campaign.get("source_files",[]):
            if not target_file(target,str(relative)):errors.append(f"{campaign.get('id')} source file does not exist: {relative}")
    for lane,count in counts.items():
        if count>int((plan.get("budget") or {}).get(lane,0)):errors.append(f"{lane} campaigns exceed budget")
    coverage=plan.get("coverage") or {}
    if coverage.get("evidence_records")!=len(records) or coverage.get("primitives")!=len(primitives) or coverage.get("campaigns")!=len(campaigns):errors.append("campaign plan coverage counts do not match canonical artifacts")
def semantic_synthesis(scan:Path,target:Path,doc:dict,index:dict,intrusion:dict,primary:str,errors:list[str])->None:
    known={x.get("id") for x in index.get("primitives",[]) if isinstance(x,dict)}
    evidence_sources={(str(x.get("source_kind")),str(x.get("source_id"))) for x in index.get("records",[]) if isinstance(x,dict)}
    plan_doc=load(scan/"campaign-planning/campaign-plan.json",errors) or {};campaign_ids={str(x.get("id")) for x in plan_doc.get("campaigns",[]) if isinstance(x,dict)};intrusion_ids={str(x.get("campaign_id")) for x in intrusion.get("results",[]) if isinstance(x,dict)}
    updates={str(x.get("id")) for result in intrusion.get("results",[]) if isinstance(result,dict) for x in result.get("primitive_updates",[]) if isinstance(x,dict) and x.get("id")}
    ids=[]
    for finding in doc.get("findings",[]):
        fid=str(finding.get("id")); ids.append(fid)
        if (finding.get("verification") or {}).get("model")!=primary:errors.append(f"{fid} source validation model mismatch")
        trace=finding.get("trace",[])
        if not trace or trace[0].get("kind")!="entrypoint" or trace[-1].get("kind")!="sink":errors.append(f"{fid} trace must run from entrypoint to sink")
        if any(step.get("kind")!="propagation" for step in trace[1:-1]):errors.append(f"{fid} intermediate trace steps must be propagation")
        for location in [*finding.get("root_causes",[]),*trace]:
            if not target_file(target,str(location.get("file",""))):errors.append(f"{fid} source file does not exist: {location.get('file')}")
        for source in finding.get("source_refs",[]):
            if artifact(scan,str(source.get("artifact_ref",""))) is None:errors.append(f"{fid} unresolved source reference: {source.get('artifact_ref')}")
            kind=str(source.get("kind"));source_id=str(source.get("source_id"));index_kind="secret" if kind=="secret" else kind
            if kind in {"recon","operator_context","sca","secret","sast","reproduction"} and (index_kind,source_id) not in evidence_sources:errors.append(f"{fid} source ID does not resolve in evidence index: {kind}:{source_id}")
            if kind=="campaign" and source_id not in campaign_ids:errors.append(f"{fid} references unknown campaign: {source_id}")
            if kind=="intrusion" and source_id not in intrusion_ids:errors.append(f"{fid} references unknown intrusion result: {source_id}")
        if finding.get("source_refs") and all(source.get("kind")=="operator_context" for source in finding["source_refs"]):errors.append(f"{fid} operator context cannot be the sole finding source")
        for ref in [*(finding.get("verification") or {}).get("source_validation_refs",[]),*finding.get("graph_receipt_refs",[])]:
            if artifact(scan,str(ref)) is None:errors.append(f"{fid} unresolved validation reference: {ref}")
        for ref in finding.get("graph_receipt_refs",[]):
            receipt_path=artifact(scan,str(ref));receipt=load(receipt_path,errors) if receipt_path else {}
            context_path=receipt_path.with_name("context.json") if receipt_path else None
            if not isinstance(receipt,dict) or not receipt.get("meaningful") or context_path is None or not context_path.is_file() or receipt.get("normalized_sha256")!=hashlib.sha256(context_path.read_bytes()).hexdigest():errors.append(f"{fid} cites invalid or non-meaningful graph receipt: {ref}")
        steps=finding.get("primitive_steps",[])
        if finding.get("finding_kind")=="chain":
            if finding.get("origin")!="composite_chain" or len(steps)<2:errors.append(f"{fid} chain requires composite origin and at least two steps")
            for step in steps:
                if step.get("primitive_id") not in known|updates:errors.append(f"{fid} chain references unknown primitive {step.get('primitive_id')}")
            for left,right in zip(steps,steps[1:]):
                if str(left.get("output_capability","")).strip().casefold()!=str(right.get("input_capability","")).strip().casefold():errors.append(f"{fid} chain capability transition is not closed between {left.get('primitive_id')} and {right.get('primitive_id')}")
        elif steps:errors.append(f"{fid} non-chain finding must not contain primitive steps")
        dependency=finding.get("dependency");secret=finding.get("secret")
        if finding.get("finding_kind")=="dependency":
            if not isinstance(dependency,dict) or dependency.get("reachability")!="reachable":errors.append(f"{fid} dependency finding requires proven reachable affected use")
        elif dependency is not None:errors.append(f"{fid} non-dependency finding must use dependency: null")
        if finding.get("finding_kind")=="secret":
            if not isinstance(secret,dict) or secret.get("redaction")!="<redacted>" or secret.get("validity") not in {"confirmed_format","likely"}:errors.append(f"{fid} secret finding requires exact redaction and supported validity")
        elif secret is not None:errors.append(f"{fid} non-secret finding must use secret: null")
        if finding.get("status")=="needs_environment" and (finding.get("verification") or {}).get("level")!="environment_required":errors.append(f"{fid} needs_environment status requires environment_required verification")
    if len(ids)!=len(set(ids)):errors.append("synthesis finding IDs must be unique")
def semantic_intrusion(scan:Path,target:Path,index:dict,results:dict,errors:list[str])->None:
    known={str(x.get("id")) for x in index.get("primitives",[]) if isinstance(x,dict)}
    for result in results.get("results",[]):
        cid=str(result.get("campaign_id"));updates={str(x.get("id")) for x in result.get("primitive_updates",[]) if isinstance(x,dict)}
        for update in result.get("primitive_updates",[]):
            for ref in update.get("evidence_refs",[]) if isinstance(update,dict) else []:
                if artifact(scan,str(ref)) is None:errors.append(f"{cid} new primitive has unresolved evidence: {ref}")
        for candidate in result.get("candidates",[]):
            candidate_id=str(candidate.get("id"));trace=candidate.get("trace",[])
            if not trace or trace[0].get("kind")!="entrypoint" or trace[-1].get("kind")!="sink" or any(x.get("kind")!="propagation" for x in trace[1:-1]):errors.append(f"{candidate_id} intrusion trace is not ordered entrypoint-to-sink")
            for location in [*candidate.get("root_causes",[]),*trace]:
                if not target_file(target,str(location.get("file",""))):errors.append(f"{candidate_id} references missing target file: {location.get('file')}")
            for ref in candidate.get("evidence_refs",[]):
                if artifact(scan,str(ref)) is None:errors.append(f"{candidate_id} unresolved evidence reference: {ref}")
            primitive_ids=[str(x) for x in candidate.get("primitive_ids",[])]
            for primitive_id in primitive_ids:
                if primitive_id not in known|updates:errors.append(f"{candidate_id} references unknown primitive: {primitive_id}")
            if candidate.get("finding_kind")=="chain" and len(primitive_ids)<2:errors.append(f"{candidate_id} chain candidate requires at least two primitives")
            if candidate.get("validation_level")=="environment_required":errors.append(f"{candidate_id} environment-required hypothesis cannot use candidate status")
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("harness_root",type=Path); p.add_argument("scan_base",type=Path); p.add_argument("phase",choices=tuple(PHASE_DIR)); a=p.parse_args(); root=a.harness_root.resolve(); scan=a.scan_base.resolve(); errors=[]
    schema(root,"run-manifest.schema.json",scan/"run-manifest.json",errors); run=load(scan/"run-manifest.json",errors) or {}; context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")),errors) or {}; target=Path(str(context.get("repo_path","")))
    if Path(str(context.get("scan_base",""))).resolve()!=scan:errors.append("audit context scan mismatch")
    if context.get("run_id")!=run.get("run_id"):errors.append("audit context run mismatch")
    if context.get("workflow")!="canonical-redteam-v2":errors.append("audit context is not the canonical greenfield workflow")
    current_contract=harness_contract_sha256(root)
    if context.get("harness_contract_sha256")!=current_contract or run.get("harness_contract_sha256")!=current_contract:errors.append("harness contract fingerprint mismatch")
    if context.get("sast_budget")!=run.get("sast_budget"):errors.append("SAST budget snapshot mismatch")
    try: current_operator_context=inspect_context(Path(str((context.get("paths") or {}).get("operator_context",root/"context"))))
    except (OSError,ValueError) as exc:errors.append(f"cannot inspect operator context: {exc}");current_operator_context={}
    current_operator_identity=operator_context_identity(current_operator_context) if current_operator_context else {}
    if context.get("operator_context")!=current_operator_identity or run.get("operator_context")!=current_operator_identity:errors.append("operator context changed during audit")
    if context.get("network")!=run.get("network") or context.get("offline_package")!=run.get("offline_package"):errors.append("offline package or agent egress identity mismatch")
    if not target.is_dir():errors.append("audit target is unavailable")
    phase=a.phase
    for relative,size,limit in oversized_artifacts(scan):
        if phase_for_artifact(relative)==phase:errors.append(f"artifact exceeds bounded size policy: {relative} ({size}>{limit})")
    if phase=="recon":
        for path in (scan/"repo-context/repo.md",):
            if not path.is_file():errors.append(f"missing {path}")
        schema(root,"repo-context.schema.json",scan/"repo-context/repo-context.json",errors,semantic="repo-context",target=target); schema(root,"security-surfaces.schema.json",scan/"repo-context/security-surfaces.json",errors,semantic="security-surfaces",target=target)
        for name in ("overview.json","trust-boundaries.json","input-surfaces.json"):schema(root,"recon-research.schema.json",scan/"repo-context/research"/name,errors)
        schema(root,"operator-context.schema.json",scan/"repo-context/operator-context.json",errors)
        operator_artifact=load(scan/"repo-context/operator-context.json",errors) or {}
        if current_operator_context and operator_artifact.get("files")!=current_operator_context.get("files"):errors.append("operator-context artifact inventory differs from live immutable input")
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
        schema(root,"threat-model.schema.json",scan/"sast/threat-model.json",errors,semantic="threat-model",target=target); schema(root,"hunt-plan.schema.json",scan/"sast/hunt-plan.json",errors,semantic="hunt-plan",target=target); schema(root,"candidate-finding.schema.json",scan/"sast/raw-findings.json",errors,True,"candidate",target); schema(root,"validation-result.schema.json",scan/"sast/validation-results.json",errors,True,"validation-result",target); schema(root,"coverage-ledger.schema.json",scan/"sast/coverage-ledger.json",errors); schema(root,"wishlist.schema.json",scan/"sast/wishlist.json",errors)
        hunt_plan=load(scan/"sast/hunt-plan.json",errors) or {}; threat_doc=load(scan/"sast/threat-model.json",errors) or {}; plan_sha=hashlib.sha256((scan/"sast/hunt-plan.json").read_bytes()).hexdigest() if (scan/"sast/hunt-plan.json").is_file() else ""; expected_packets=set();cell_map={str(cell.get("id")):cell for cell in hunt_plan.get("cells",[]) if isinstance(cell,dict)};packet_limit=int((hunt_plan.get("budget") or {}).get("context_packet_bytes",65536))
        if hunt_plan.get("budget")!=run.get("sast_budget"):errors.append("hunt plan budget differs from the run identity snapshot")
        mapping_map={str(mapping.get("id")):mapping for mapping in threat_doc.get("hunt_mappings",[]) if isinstance(mapping,dict)};base_cells=[cell for cell in cell_map.values() if cell.get("lead_key") is None]
        if {str(cell.get("mapping_id")) for cell in base_cells}!=set(mapping_map):errors.append("hunt plan cells do not match the threat-model mapping set")
        for cell in base_cells:
            mapping=mapping_map.get(str(cell.get("mapping_id")))
            if not mapping:continue
            expected={"surface_ids":mapping.get("surface_ids"),"subsystem":mapping.get("subsystem_id"),"attack_class_id":mapping.get("attack_class_id"),"priority":mapping.get("priority"),"threat_ids":mapping.get("threat_ids"),"asset_ids":mapping.get("asset_ids"),"attacker":mapping.get("attacker"),"entrypoint_ids":mapping.get("entrypoint_ids"),"boundary_ids":mapping.get("boundary_ids"),"files":mapping.get("source_files"),"security_question":mapping.get("security_question"),"stop_conditions":mapping.get("stop_conditions"),"applicability_reason":mapping.get("applicability_reason")}
            if any(cell.get(key)!=value for key,value in expected.items()):errors.append(f"hunt cell does not preserve contextual mapping: {cell.get('id')}")
        for task in hunt_plan.get("tasks",[]):
            task_id=str(task.get("id","")); expected_packets.add(f"{task_id}.json"); packet=load(scan/"sast/hunt-tasks"/f"{task_id}.json",errors) or {}
            expected_cells=[cell_map.get(str(cell_id)) for cell_id in task.get("cell_ids",[])]
            if packet.get("run_id")!=hunt_plan.get("run_id") or packet.get("hunt_plan_ref")!="sast/hunt-plan.json" or packet.get("hunt_plan_sha256")!=plan_sha or packet.get("task")!=task or packet.get("cells")!=expected_cells:errors.append(f"hunt task packet mismatch: {task_id}")
            packet_path=scan/"sast/hunt-tasks"/f"{task_id}.json"
            if packet_path.is_file() and packet_path.stat().st_size>packet_limit:errors.append(f"hunt task packet exceeds bounded context: {task_id}")
            result_path=scan/"sast/deepdive"/f"{task_id}.json"; result=load(result_path,errors)
            if isinstance(result,dict):
                result_errors=validate_hunt_result(root,target,task,[cell for cell in expected_cells if isinstance(cell,dict)],result,threat_doc)
                errors.extend(f"{task_id}: {message}" for message in result_errors)
        actual_packets={path.name for path in (scan/"sast/hunt-tasks").glob("*.json")} if (scan/"sast/hunt-tasks").is_dir() else set()
        if actual_packets!=expected_packets:errors.append("hunt task packet set does not match hunt plan")
        for name in ("verified-findings.json","dropped-findings.json","dedup-clusters.json"):
            if not isinstance(load(scan/"sast"/name,errors),list if name!="dedup-clusters.json" else dict):errors.append(f"sast/{name} has wrong shape")
    elif phase=="campaign-planning":
        schema(root,"evidence-index.schema.json",scan/"campaign-planning/evidence-index.json",errors); schema(root,"campaign-plan.schema.json",scan/"campaign-planning/campaign-plan.json",errors); index=load(scan/"campaign-planning/evidence-index.json",errors) or {}; plan=load(scan/"campaign-planning/campaign-plan.json",errors) or {}; semantic_campaign(scan,target,index,plan,errors)
    elif phase=="intrusion":
        schema(root,"intrusion-results.schema.json",scan/"intrusion/intrusion-results.json",errors); plan=load(scan/"campaign-planning/campaign-plan.json",errors) or {}; results=load(scan/"intrusion/intrusion-results.json",errors) or {}; expected=[x.get("id") for x in plan.get("campaigns",[])]; actual=[x.get("campaign_id") for x in results.get("results",[])];
        if expected!=actual:errors.append("intrusion results must match campaign plan exactly and in order")
        semantic_intrusion(scan,target,load(scan/"campaign-planning/evidence-index.json",errors) or {},results,errors)
    elif phase=="synthesis":
        schema(root,"synthesis-findings.schema.json",scan/"synthesis/findings.json",errors); doc=load(scan/"synthesis/findings.json",errors) or {}; index=load(scan/"campaign-planning/evidence-index.json",errors) or {}; intrusion=load(scan/"intrusion/intrusion-results.json",errors) or {}; semantic_synthesis(scan,target,doc,index,intrusion,str(run.get("model","")),errors)
    elif phase=="final-verification":
        schema(root,"final-findings.schema.json",scan/"final-verification/findings.json",errors);final_doc=load(scan/"final-verification/findings.json",errors) or {};synthesis_items=[]
        for item in final_doc.get("findings",[]):
            if isinstance(item,dict):synthesis_items.append({key:value for key,value in item.items() if key not in {"verdict","model_diversity","independent_verification_ref"}})
        semantic_synthesis(scan,target,{"findings":synthesis_items},load(scan/"campaign-planning/evidence-index.json",errors) or {},load(scan/"intrusion/intrusion-results.json",errors) or {},str(run.get("model","")),errors)
        for item in final_doc.get("findings",[]):
            if artifact(scan,str(item.get("independent_verification_ref",""))) is None:errors.append(f"{item.get('id')} independent verification reference does not resolve")
        for item in final_doc.get("rejections",[]):
            if artifact(scan,str(item.get("independent_verification_ref",""))) is None:errors.append(f"{item.get('id')} rejection reference does not resolve")
    elif phase=="report":schema(root,"report.schema.json",scan/"report/security-report.json",errors)
    schema(root,"phase-manifest.schema.json",scan/PHASE_DIR[phase]/"phase-manifest.json",errors)
    phase_manifest=manifest(scan,phase,errors)
    coverage=phase_manifest.get("coverage",{}) if isinstance(phase_manifest.get("coverage"),dict) else {}
    expected_phase_status={
        "recon":"degraded" if coverage.get("operator_context_skipped") else "ok",
        "tool-collection":"ok",
        "campaign-planning":"ok",
        "intrusion":"degraded" if coverage.get("needs_environment") else "ok",
        "synthesis":"degraded" if coverage.get("needs_environment") else "ok",
        "final-verification":"degraded" if coverage.get("needs_environment") else "ok",
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
        material_loss=bool(funnel.get("environment_required")) or any(isinstance(cell,dict) and cell.get("status")=="failed" for cell in cells)
        expected_status="degraded" if material_loss else "ok"
        if phase_manifest.get("status")!=expected_status:
            errors.append(f"SAST manifest must close {expected_status}; configured depth limits are BAU coverage, not degradation")
        if any(isinstance(cell,dict) and cell.get("status") in {"deferred","shallow"} for cell in cells):
            errors.append("final SAST coverage must close deferred/shallow cells as depth_limited")
        expected_depth_limited=sum(1 for cell in cells if isinstance(cell,dict) and cell.get("status")=="depth_limited")
        if (phase_manifest.get("coverage") or {}).get("depth_limited")!=expected_depth_limited:
            errors.append("SAST manifest depth_limited count does not match the coverage ledger")
    if target.is_dir():
        result=subprocess.run([sys.executable,str(root/"scripts/target-fingerprint.py"),str(target)],capture_output=True,text=True,check=False)
        if result.returncode or result.stdout.strip()!=run.get("target_fingerprint"):errors.append("target working tree changed during audit")
    if errors:
        for error in errors:print(f"[validate-phase-v2] ERROR: {error}",file=sys.stderr)
        return 1
    print(f"[validate-phase-v2] {phase} valid");return 0
if __name__=="__main__":raise SystemExit(main())
