#!/usr/bin/env python3
"""Build the single evidence ledger and typed attack-primitive catalog."""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path
from typing import Any
from model_identity import contributor_union, finding_contributors, validate_provenance
from evidence_refs import SCAN_NAMESPACES, EvidenceIssue, artifact_value, navigation_file, validate_evidence_refs
from evidence_accounting import classify_refs, diagnostic, effective_support, summarize
from objective_contract import load_registry, validate_binding, validate_registry
from sast_contract import sast_review_support
from run_lifecycle import current_assessment, require_active_phase, routing_for_artifact

def load(path: Path, fallback: Any) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): return fallback
def write(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(json.dumps(doc,separators=(",",":"),sort_keys=True)+"\n"); tmp.replace(path)
def stable(prefix: str, *parts: object) -> str:
    return prefix+hashlib.sha256("\0".join(str(x) for x in parts).encode()).hexdigest()[:12].upper()
def strings(items: object) -> list[str]: return [str(x) for x in items] if isinstance(items,list) else []

def retain_binding(record, objectives, questions, *sources):
    """Retain only explicit, mutually consistent owner bindings."""
    for source in sources:
        if "objective_id" not in source and "question_id" not in source:
            continue
        validate_binding(source, objectives, questions)
        binding = {key: source[key] for key in ("objective_id", "question_id")}
        if "objective_id" in record and any(record[key] != value for key, value in binding.items()):
            raise ValueError("evidence source has conflicting objective/question bindings")
        record.update(binding)

def classify_record(scan, source_root, repositories, rec, item, *, candidate=None, historical=False):
    """Keep source questions, never turn a citation string into a capability."""
    issues = []
    terminal_review = candidate is not None and (
        rec.get("non_promoted") or item["status"] not in {"source_verified", "environment_required"})
    if not historical and rec["source_kind"] == "sast" and item.get("optional_support"):
        if terminal_review:
            for support in item["optional_support"]:
                _, local = classify_refs(scan, source_root, repositories,
                    [support["reference"], *support["independent_support"]],
                    owner=rec["artifact_ref"], field="optional_support", affected_item_ids=[rec["id"]])
                issues.extend(local)
        else:
            optional_diagnostics = []
            try:
                if candidate is not None:
                    support = sast_review_support(scan, source_root, repositories, candidate, item, optional_diagnostics)
                    item = {**item, "evidence_refs": support["evidence_refs"]}
                else:
                    item = effective_support(scan, source_root, repositories, item, optional_diagnostics)
            except EvidenceIssue as exc:
                issues.append(diagnostic(exc.code, rec["artifact_ref"], "optional_support", [rec["id"]]))
            else:
                issues.extend({**row, "owner": rec["artifact_ref"], "affected_item_ids": [rec["id"]]}
                              for row in optional_diagnostics)
    refs = list(dict.fromkeys(item.get("evidence_refs", [])))
    navigation = []
    for ref in refs:
        relative = ref.partition(":")[0].partition("#")[0]
        if relative.split("/", 1)[0] in SCAN_NAMESPACES and Path(relative).suffix in {".md", ".txt"}:
            navigation.append(ref)
            try:
                navigation_file(scan, ref)
            except EvidenceIssue as exc:
                issues.append(diagnostic(exc.code, rec["artifact_ref"], "navigation_refs", [rec["id"]]))
    rec["navigation_refs"] = navigation
    refs = [ref for ref in refs if ref not in navigation]
    valid, local = classify_refs(scan, source_root, repositories, refs, owner=rec["artifact_ref"],
                                field="evidence_refs", affected_item_ids=[rec["id"]], historical=historical)
    issues.extend(local)
    files = list(dict.fromkeys([*rec["files"], *(item.get("source_files", []) if rec["source_kind"] == "threat_model" else [])]))
    artifacts = set(validate_evidence_refs(scan, source_root, repositories, valid, owner=rec["artifact_ref"], historical=historical))
    files.extend(ref.split(":", 1)[0] for ref in valid if ref not in artifacts)
    # Artifact references are navigation/provenance, not source anchors.
    files = list(dict.fromkeys(files))
    files, local = classify_refs(scan, source_root, repositories, files, owner=rec["artifact_ref"],
                                field="files", affected_item_ids=[rec["id"]], kind="source", historical=historical)
    issues.extend(local)
    anchors = []
    for anchor in rec["source_anchors"]:
        ref = anchor["file"]
        if anchor.get("start_line"):
            ref += f":{anchor['start_line']}-{anchor.get('end_line', anchor['start_line'])}"
        resolved, local = classify_refs(scan, source_root, repositories, [ref], owner=rec["artifact_ref"],
                                       field="source_anchors", affected_item_ids=[rec["id"]], kind="source", historical=historical)
        issues.extend(local)
        if resolved:
            anchors.append(anchor)
    rec["files"], rec["source_anchors"] = files, anchors
    rec["evidence_refs"] = refs
    rec["evidence_quality"] = "evidence_limited" if rec.get("non_promoted") or any(row["disposition"] == "evidence_limited" for row in issues) else "resolved"
    if rec["evidence_quality"] == "evidence_limited" and rec["disposition"] != "rejected" and not terminal_review:
        rec["disposition"] = "evidence_limited"
    rec["anchor_limitations"] = [] if files else ["No established source anchor; this assertion does not grant planning eligibility."]
    if not files and rec["disposition"] == "promoted":
        rec["disposition"] = "unresolved"
    risk = item if rec["source_kind"] == "threat_model" or (rec["source_kind"] == "sast" and rec["artifact_ref"].split(":", 1)[0] in {"sast/raw-findings.json", "sast/verified-findings.json"}) else {}
    attacker = risk.get("attacker") or {}
    rec["risk_context"] = {
        "actor": str(attacker.get("starting_access", "")) if isinstance(attacker, dict) else str(attacker),
        "reachability": str(risk.get("applicability_reason", "")) if rec["source_kind"] == "threat_model" else "",
        "impact": str(risk.get("impact", "")) if rec["source_kind"] == "sast" else "",
        "priority": {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(
            risk.get("priority") if rec["source_kind"] == "threat_model" else risk.get("severity"), 3)}
    return issues
def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("scan_base",type=Path); p.add_argument("--context",type=Path); a=p.parse_args(); root=Path(__file__).resolve().parent.parent
    context=load(a.context or root/".harness/audit-context.json",{}); run_id=str(context.get("run_id","")); records=[]; primitives=[]; gaps=[]; warnings=[]
    require_active_phase(a.scan_base, context, "campaign-planning")
    source_root=Path(context.get("source_root") or context["repo_path"]); repositories=context["repositories"]; diagnostics=[]
    objectives, questions = load_registry(a.scan_base, through="sast")
    validate_registry(list(objectives.values()), list(questions.values()))
    record_sources = {}
    def record(kind:str,source_id:str,ref:str,disposition:str,summary:str,files:list[str],anchors:list[dict]|None=None,subsystems:list[str]|None=None) -> str:
        files=list(dict.fromkeys(f for f in files if f and f!="None"))
        rid=stable("E-",kind,source_id,ref); records.append({"id":rid,"source_kind":kind,"source_id":source_id,"artifact_ref":ref,"disposition":disposition,"summary":summary[:2000] or source_id,"files":files,"source_anchors":anchors or [],"subsystems":subsystems or [],"anchor_limitations":[] if files else ["No canonical source association is available."]}); return rid
    def primitive(kind:str,trust:str,rid:str,prereq:list[str],capability:str,boundary:str,assets:list[str],conditions:list[str],refs:list[str]) -> None:
        primitives.append({"id":stable("P-",kind,rid,capability),"type":kind,"trust":trust,"source_record_ids":[rid],"prerequisites":prereq or ["Attacker can reach the cited surface."],"capability_gained":capability or "Access to the cited security-relevant surface.","boundary":boundary or "Repository trust boundary","reachable_assets":assets,"conditions":conditions,"evidence_refs":list(dict.fromkeys(refs or [rid])),
                           "capability":{"actor":prereq[0] if prereq else "Actor not yet established","operation":capability or "Investigate cited behavior","resource_scope":"; ".join(assets) or boundary or "Scope not yet established","authority":boundary or "Authority not yet established","conditions":list(dict.fromkeys([*prereq,*conditions])),"evidence_status":"source_established" if trust=="confirmed" else "hypothesized","provenance":list(dict.fromkeys(refs or [rid])),"restrictions":["Capability support does not establish a vulnerability or broader actor access."]}})
    surfaces=load(a.scan_base/"repo-context/security-surfaces.json",{})
    for item in surfaces.get("entry_points",[]) if isinstance(surfaces,dict) else []:
        sid=str(item.get("id")); ref=f"repo-context/security-surfaces.json:{sid}"; rid=record("recon",sid,ref,"promoted",f"{item.get('kind')} entry point at {item.get('path')}",[str(item.get("path"))]); primitive("access","context_only",rid,["Attacker can provide input to this entry point."],f"Influence input at {item.get('path')}",",".join(strings(item.get("trust_boundary_ids"))) or "Entry-point boundary",[str(item.get("path"))],[],[ref])
    for item in surfaces.get("trust_boundaries",[]) if isinstance(surfaces,dict) else []:
        sid=str(item.get("id")); ref=f"repo-context/security-surfaces.json:{sid}"; rid=record("recon",sid,ref,"promoted",str(item.get("description")),[]); primitive("state_transition","context_only",rid,[str(item.get("source_trust"))],str(item.get("target_trust")),str(item.get("description")),[],[],[ref])
    sca=load(a.scan_base/"tool-collection/sca-advisories.json",{})
    if sca.get("advisories"):
        validate_evidence_refs(a.scan_base, source_root, repositories, ["tool-collection/sca-advisories.json"], owner="sca", historical=True)
    for item in sca.get("advisories",[]) if isinstance(sca,dict) else []:
        sid=str(item.get("id")); ref=f"tool-collection/sca-advisories.json:{sid}"; rid=record("sca",sid,ref,"unresolved",f"{item.get('advisory_id')} affects {item.get('package')} {item.get('version')}",[str(item.get("source_lockfile"))]);record_sources[rid]=item
    secrets=load(a.scan_base/"tool-collection/secrets-redacted.json",{})
    if secrets.get("candidates"):
        validate_evidence_refs(a.scan_base, source_root, repositories, ["tool-collection/secrets-redacted.json"], owner="secret", historical=True)
    for item in secrets.get("candidates",[]) if isinstance(secrets,dict) else []:
        # Redacted observations route directly to triage, never to credential grants.
        sid=str(item.get("id")); ref=f"tool-collection/secrets-redacted.json:{sid}"; rid=record("secret",sid,ref,"unresolved",f"Redacted {item.get('type')} candidate",[str(item.get("file"))]);record_sources[rid]=item
    for receipt_name in ("wraith-receipt.json","poltergeist-receipt.json"):
        receipt=load(a.scan_base/"tool-collection"/receipt_name,{})
        for offset,message in enumerate(receipt.get("warnings",[]) if isinstance(receipt,dict) else [],1):
            record("tool_warning",f"{receipt_name}-{offset}",f"tool-collection/{receipt_name}","unresolved",str(message),[])
    dependency_limitations=load(a.scan_base/"tool-collection/dependency-limitations.json",{})
    for item in dependency_limitations.get("limitations",[]) if isinstance(dependency_limitations,dict) else []:
        sid=str(item.get("code"));rid=record("coverage",sid,f"tool-collection/dependency-limitations.json:{sid}","unresolved",str(item.get("message")),strings(item.get("files")));gaps.append(rid)
    verified=load(a.scan_base/"sast/verified-findings.json",[]); verified_ids=set()
    for item in verified if isinstance(verified,list) else []:
        sid=str(item.get("id")); verified_ids.add(sid); ref=f"sast/verified-findings.json:{sid}"; level=str(item.get("verification_level")); disposition="needs_environment" if level=="environment_required" else "promoted"; rid=record("sast",sid,ref,disposition,str(item.get("title")),[str((item.get("root_cause_location") or {}).get("file",""))]); attacker=item.get("attacker") or {}; conditions=[str(x.get("description")) for x in item.get("conditions",[]) if isinstance(x,dict)]; primitive("vulnerability","candidate" if disposition=="needs_environment" else "confirmed",rid,[str(attacker.get("starting_access","Attacker reaches the entry point."))],str(item.get("impact")),str(attacker.get("boundary_crossed","Application boundary")),[str((item.get("root_cause_location") or {}).get("file",""))],conditions,[ref,*strings(item.get("evidence_refs"))])
    dropped=load(a.scan_base/"sast/dropped-findings.json",[])
    for item in dropped if isinstance(dropped,list) else []:
        sid=str(item.get("raw_id") or item.get("id")); status=str(item.get("status")); disposition="evidence_limited" if status=="evidence_limited" else "needs_environment" if status=="deferred" else "rejected"; record("sast",sid,f"sast/dropped-findings.json:{item.get('id')}",disposition,str(item.get("reason")),[])
    validations=load(a.scan_base/"sast/validation-results.json",[])
    for item in validations if isinstance(validations,list) else []:
        sid=str(item.get("id") or item.get("candidate_id")); status=str(item.get("status")); disposition="promoted" if status=="source_verified" else "evidence_limited" if status=="evidence_limited" or item.get("non_promoted", {}).get("disposition")=="evidence_limited" else "needs_environment" if status=="environment_required" else "unresolved" if status=="deferred" else "rejected"; record("sast",sid,f"sast/validation-results.json:{sid}",disposition,str(item.get("closure_reason")),[])
    reproduction_dir=a.scan_base/"sast/reproduction"
    for result_path in sorted(reproduction_dir.glob("*/result.json")) if reproduction_dir.is_dir() else []:
        item=load(result_path,{}); sid=str(item.get("finding_id") or result_path.parent.name); status=str(item.get("status")); disposition="promoted" if status=="dynamic_verified" else "needs_environment" if status in {"environment_required","failed"} else "rejected" if status=="contradicted" else "unresolved"; record("reproduction",sid,str(result_path.relative_to(a.scan_base)),disposition,f"Safe reproduction status: {status}",[])
    raw=load(a.scan_base/"sast/raw-findings.json",[])
    known={r["source_id"] for r in records if r["source_kind"]=="sast"}
    for item in raw if isinstance(raw,list) else []:
        sid=str(item.get("id"));
        if sid not in known: record("sast",sid,f"sast/raw-findings.json:{sid}","unresolved",str(item.get("title")),[str((item.get("root_cause_location") or {}).get("file",""))])
    coverage=load(a.scan_base/"sast/coverage-ledger.json",{})
    hunt=load(a.scan_base/"sast/hunt-plan.json",{})
    threat=load(a.scan_base/"sast/threat-model.json",{})
    hunt_cells={item["id"]:item for item in hunt.get("cells",[])}
    mappings={item["id"]:item for item in threat.get("hunt_mappings",[])}
    entrypoints={item["id"]:item for item in [*surfaces.get("entry_points",[]),*threat.get("entrypoints",[])]}
    for item in threat.get("hunt_mappings", []):
        sid = item["id"]
        record("threat_model", sid, f"sast/threat-model.json:{sid}", "unresolved",
               item.get("security_question") or item.get("applicability_reason", sid), strings(item.get("source_files")),
               subsystems=[item["subsystem_id"]] if item.get("subsystem_id") else [])
    for cell in coverage.get("cells",[]) if isinstance(coverage,dict) else []:
        sid=str(cell.get("id")); mapped=hunt_cells.get(sid,{})
        mapping=mappings.get(mapped.get("mapping_id"),{})
        entry_ids=list(dict.fromkeys([*mapped.get("entrypoint_ids",[]),*mapping.get("entrypoint_ids",[])]))
        anchors=[{"file":entrypoints[eid]["path"],"entrypoint_id":eid} for eid in entry_ids if eid in entrypoints and entrypoints[eid].get("path")]
        files=[*strings(mapped.get("files")),*strings(mapping.get("source_files")),*[anchor["file"] for anchor in anchors]]
        subsystems=list(dict.fromkeys(str(value) for value in [mapped.get("subsystem"),mapping.get("subsystem_id")] if value))
        status=str(cell.get("status")); disposition="closed" if status in {"clean","not_applicable"} else "promoted" if status in {"finding","tool_satisfied"} else "unresolved"; rid=record("coverage",sid,f"sast/coverage-ledger.json:{sid}",disposition,str(cell.get("reason")),files,anchors,subsystems)
        rec = records[-1]
        retain_binding(rec, objectives, questions, mapping, mapped, cell, cell.get("checkpoint") or {})
        for key in ("resolution", "checkpoint"):
            if key in cell:
                rec[key] = cell[key]
        rec["files"] = list(dict.fromkeys([*rec["files"], *(ref.split(":", 1)[0] for ref in cell.get("checkpoint", {}).get("files_reviewed", []))]))
        if disposition=="unresolved": gaps.append(rid)
    for task in coverage.get("tasks",[]) if isinstance(coverage,dict) else []:
        publication = load(a.scan_base / "sast/deepdive" / f"{task['id']}.json", {}) if task.get("artifact_valid") else {}
        rabbits = publication.get("rabbit_holes", task.get("rabbit_holes", []))
        for offset, rabbit in enumerate(rabbits, 1):
            source = rabbit if isinstance(rabbit, dict) else {}
            rid=record("coverage",f"{task.get('id')}-rabbit-{offset}",f"sast/coverage-ledger.json:{task.get('id')}","unresolved",
                       str(source.get("reason", rabbit)), strings(source.get("files", task.get("files_reviewed", []))))
            record_sources[rid] = source
            retain_binding(records[-1], objectives, questions, source)
            gaps.append(rid)
    wishlist=load(a.scan_base/"sast/wishlist.json",{})
    for item in wishlist.get("items",[]) if isinstance(wishlist,dict) else []:
        status=str(item.get("status")); disposition="closed" if status=="resolved" else "needs_environment" if status=="unavailable" else "unresolved"; rid=record("coverage",str(item.get("id")),f"sast/wishlist.json:{item.get('id')}",disposition,f"{item.get('request')}: {item.get('reason')}",[])
        if disposition!="closed":gaps.append(rid)
    for filename,kind in (("hardening-notes.json","hardening"),("positive-patterns.json","positive_pattern")):
        items=load(a.scan_base/"sast"/filename,[])
        for index,item in enumerate(items if isinstance(items,list) else [],1):
            sid = f"{kind}-{index}"
            rid = record(kind,sid,f"sast/{filename}","closed",str(item.get("description") if isinstance(item,dict) else item),[])
            record_sources[rid] = item
    # Retain source associations even when a finding was rejected or deferred.
    candidate_sources={str(item.get("id")):item for item in [*(raw if isinstance(raw,list) else []),*(verified if isinstance(verified,list) else [])]}
    reviews = {f"sast/validation-results.json:{item['id']}": item for item in validations}
    queued_candidates = {row["id"]: row for row in load(a.scan_base / "sast/validation-queue.json", [])}
    verified_candidates = {row["id"]: row for row in verified}
    # IDs are artifact-local: a reviewer may reuse its own or another candidate's ID.
    finding_sources = {}
    for rec in records:
        if rec["source_kind"] not in {"sast", "reproduction"}:
            continue
        review = reviews.get(rec["artifact_ref"]) if rec["source_kind"] == "sast" else None
        if review:
            candidate_id = review["candidate_id"]
            finding_sources[rec["id"]] = verified_candidates.get(candidate_id) or queued_candidates[candidate_id]
        else:
            finding_sources[rec["id"]] = candidate_sources.get(rec["source_id"], {})
    closures = {row["id"]: row for row in coverage.get("non_promoted", [])}
    recon_sources = {str(item["id"]): item for key in ("entry_points", "trust_boundaries") for item in surfaces.get(key, [])}
    for rec in records:
        item = finding_sources.get(rec["id"], {})
        if rec["source_kind"] == "recon":
            item = recon_sources[rec["source_id"]]
            if not item.get("contributors"):
                diagnostics.append(diagnostic("missing_attribution", rec["artifact_ref"], "contributors", [rec["id"]]))
                rec["disposition"] = "evidence_limited"
        review = reviews.get(rec["artifact_ref"]) if rec["source_kind"] == "sast" else None
        closure = closures.get(review["candidate_id"] if review else rec["source_id"]) if rec["source_kind"] == "sast" else None
        if closure:
            rec["non_promoted"] = closure
            rec["disposition"] = "evidence_limited"
        contributors = item.get("contributors", [])
        try:
            if review:
                provenance = validate_provenance(review.get("provenance"), routing_for_artifact(a.scan_base, f"sast/verify/{review['candidate_id']}.json", context.get("model_routing") or {}),
                                                 "vulnops-verify-one", f"sast/verify/{review['candidate_id']}.json")
                contributors = contributor_union(contributors, [provenance])
            if rec["source_kind"] == "reproduction":
                reproduction = load(a.scan_base / rec["artifact_ref"], {})
                provenance = validate_provenance(reproduction.get("provenance"), routing_for_artifact(a.scan_base, rec["artifact_ref"], context.get("model_routing") or {}),
                                                 "vulnops-reproduce-one", f"sast/reproduction/{rec['source_id']}/result.json")
                contributors = contributor_union(contributors, [provenance])
        except ValueError:
            if current_assessment(item, context):
                raise
            diagnostics.append(diagnostic("missing_attribution", rec["artifact_ref"], "contributors", [rec["id"]]))
            rec["disposition"] = "evidence_limited"
        if contributors:
            try:
                resolved = finding_contributors(a.scan_base, {"verification": {"source_validation_refs": [value["artifact_ref"] for value in contributors]}}, context.get("model_routing") or {}, source_root=source_root, repositories=repositories)
                contributors = contributor_union(contributors, resolved)
            except EvidenceIssue as exc:
                diagnostics.append(diagnostic(exc.code, rec["artifact_ref"], "contributors", [rec["id"]]))
                rec["disposition"] = "evidence_limited"
        if rec["source_kind"] == "sast" and rec["disposition"] == "promoted" and not contributors:
            diagnostics.append(diagnostic("missing_attribution", rec["artifact_ref"], "contributors", [rec["id"]]))
            rec["disposition"] = "evidence_limited"
        rec["contributors"] = contributors
    for rec in records:
        if rec["source_kind"] in {"sast", "reproduction"}:
            retain_binding(rec, objectives, questions, finding_sources.get(rec["id"], {}))
        item=entrypoints.get(rec["source_id"],{}) if rec["source_kind"]=="recon" else finding_sources.get(rec["id"],{}) if rec["source_kind"] in {"sast","reproduction"} else {}
        location=(item.get("root_cause_location") or {}) if rec["source_kind"] in {"sast", "reproduction"} else {}
        file=location.get("file") or (item.get("path") if rec["source_kind"]=="recon" else None)
        if file:
            rec["files"]=list(dict.fromkeys([*rec["files"],file]))
            anchor={"file":file}
            if rec["source_kind"]=="recon":anchor["entrypoint_id"]=rec["source_id"]
            if location.get("symbol"):anchor["symbol"]=location["symbol"]
            if location.get("start_line"):anchor["start_line"]=location["start_line"];anchor["end_line"]=location.get("end_line",location["start_line"])
            rec["source_anchors"]=[anchor]
            rec["anchor_limitations"]=[]
    for rec in records:
        local = []
        if rec["source_kind"] in {"sca", "secret"}:
            item = record_sources[rec["id"]]
        else:
            _, local = classify_refs(a.scan_base, source_root, repositories, [rec["artifact_ref"]],
                                     owner=rec["artifact_ref"], field="artifact_ref", affected_item_ids=[rec["id"]], historical=True)
            diagnostics.extend(local)
            try:
                item = artifact_value(a.scan_base, rec["artifact_ref"])
            except EvidenceIssue:
                item = {}
            item = record_sources.get(rec["id"], item)
        if not isinstance(item, dict):
            item = {}
        retain_binding(rec, objectives, questions, item)
        review = reviews.get(rec["artifact_ref"]) if rec["source_kind"] == "sast" else None
        candidate = queued_candidates[review["candidate_id"]] if review is not None else None
        historical = not current_assessment(item, context)
        if item.get("assessment_context"):
            rec["assessment_context"] = item["assessment_context"]
        diagnostics.extend(classify_record(a.scan_base, source_root, repositories, rec, item, candidate=candidate, historical=historical))
        if historical:
            rec["anchor_limitations"].append("Historical observation; inspect current source before relying on this claim.")
        if local and rec["disposition"] != "rejected":
            rec["disposition"] = rec["evidence_quality"] = "evidence_limited"
        if rec["disposition"] in {"unresolved", "evidence_limited"}:
            gaps.append(rec["id"])
    by_record = {rec["id"]: rec for rec in records}
    anchored = []
    for item in primitives:
        owners = [by_record[rid] for rid in item["source_record_ids"]]
        item["contributors"] = contributor_union(*(rec["contributors"] for rec in owners))
        item["evidence_refs"] = list(dict.fromkeys(
            ref for rec in owners for ref in [rec["artifact_ref"], *rec["evidence_refs"]]))
        item["capability"]["provenance"] = list(item["evidence_refs"])
        _, local = classify_refs(a.scan_base, source_root, repositories, item["evidence_refs"],
                                 owner=item["id"], field="evidence_refs", affected_item_ids=item["source_record_ids"],
                                 historical=any(not current_assessment(rec, context) for rec in owners))
        diagnostics.extend(local)
        if any(not current_assessment(rec, context) for rec in owners):
            item["trust"] = "candidate"
            item["capability"]["evidence_status"] = "hypothesized"
        elif owners:
            item["assessment_context"] = owners[0]["assessment_context"]
        if local or any(rec["evidence_quality"] == "evidence_limited" for rec in owners):
            item["trust"] = "candidate"
            item["capability"]["evidence_status"] = "hypothesized"
            for rec in owners:
                rec["disposition"] = rec["evidence_quality"] = "evidence_limited"
                gaps.append(rec["id"])
        if any(rec["files"] for rec in owners):
            anchored.append(item)
    doc={"schema_version":"2.0","run_id":run_id,"attack_objectives":list(objectives.values()),"investigation_questions":list(questions.values()),"records":records,"primitives":anchored,"coverage_gaps":list(dict.fromkeys(gaps)),"warnings":warnings,"evidence_quality":summarize(diagnostics)}; write(a.scan_base/"campaign-planning/evidence-index.json",doc); print(a.scan_base/"campaign-planning/evidence-index.json"); return 0
if __name__=="__main__": raise SystemExit(main())
