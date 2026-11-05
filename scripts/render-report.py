#!/usr/bin/env python3
"""Publish accepted assessment dossiers without repeating source review."""
from __future__ import annotations
import argparse,html,json,os,re,sys
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import quote
from typing import Any
from model_identity import finding_diversity, diversity_summary
from evidence_accounting import summarize
from artifact_policy import DEFAULT_ARTIFACT_LIMIT, artifact_size_limit, publication_content_error
from dossier_contract import dossier_hash, dossier_evidence_groups, validate_publication_schema, ASPECTS
from evidence_refs import _parts, artifact_value, EvidenceIssue, SCAN_NAMESPACES
from run_lifecycle import report_assessment, require_active_phase
SEVERITIES=("critical","high","medium","low","informational")
ORIGINS=("standalone_known","known_impact_expansion","composite_chain","independent_discovery","cross_evidence_discovery")
def checked(value:object,*,size_limit:int|None=DEFAULT_ARTIFACT_LIMIT)->object:
    error=publication_content_error(value,size_limit=size_limit)
    if error:raise ValueError(error)
    return value
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def clean(value:object)->str:
    return str(checked(str(value)))
def sanitized(value:object)->object:
    if isinstance(value,str):return clean(value)
    if isinstance(value,list):return [sanitized(x) for x in value]
    if isinstance(value,dict):return {str(k):sanitized(v) for k,v in value.items()}
    return value
def write(path:Path,value:str)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(value); tmp.replace(path)

def markdown(value:object)->str:
    """Keep target-authored prose literal, including HTML and Markdown headings."""
    text=html.escape(str(value),quote=False)
    text=re.sub(r"([\\`*_{}\[\]()#|~])",r"\\\1",text)
    text=re.sub(r"^(\d+)\.",r"\1\\.",text)
    if text.startswith(("-","+")):text="\\"+text
    return text.replace("\n","<br>")

def evidence_link(scan:Path,ref:str,label:str|None=None,*,required:bool=False)->str:
    relative, identifier = _parts(ref)
    base = scan.resolve()
    path = (base / relative).resolve()
    if (not path.is_relative_to(base) or Path(relative).parts[0] not in SCAN_NAMESPACES
            or path.relative_to(base).parts[0] not in SCAN_NAMESPACES):
        raise ValueError("unauthorized report evidence destination")
    caption = markdown(label or relative)
    suffix = f" (record {markdown(identifier)})" if identifier else ""
    if relative != "report/security-report.json":
        try:
            from advantage_contract import inside, load_value
            inside(base,relative)
            if path.is_file():load_value(path)
            artifact_value(base, relative)
        except (EvidenceIssue,OSError) as exc:
            if required:
                raise ValueError(f"{relative}: required report evidence is unavailable ({getattr(exc,'code','unreadable_content')})") from exc
            return f"{caption}{suffix} (unavailable; consult the owning record)"
    elif path != base / relative:
        raise ValueError("unauthorized report output destination")
    destination = quote(os.path.relpath(path, base / "report"), safe="/")
    return f"[{caption}]({destination}){suffix}"

def details(value:object,indent:int=0)->list[str]:
    """Readable labeled accounting, without exposing JSON as report narrative."""
    prefix="  "*indent
    if isinstance(value,dict):
        lines=[]
        for key in sorted(value):
            item=value[key]
            label=markdown(key.replace("_"," ").capitalize())
            if isinstance(item,(dict,list)):
                lines.append(f"{prefix}- **{label}:**")
                lines.extend(details(item,indent+1))
            else:
                lines.append(f"{prefix}- **{label}:** {markdown(item if item is not None else 'Unknown')}")
        return lines
    if isinstance(value,list):
        lines=[]
        for item in value:
            if isinstance(item,(dict,list)):
                lines.append(f"{prefix}- Record")
                lines.extend(details(item,indent+1))
            else:lines.append(f"{prefix}- {markdown(item)}")
        return lines
    return [f"{prefix}- {markdown(value)}"]

def example_lines(example:dict,cite)->list[str]:
    content=example["content"]
    fence="`"*max(3,1+max((len(match) for match in re.findall(r"`+",content)),default=0))
    lines=[f"##### Example {markdown(example['id'])}: {markdown(example['kind'])}","",
           f"Execution: **{markdown(example['execution_status'])}**.","",fence,content,fence,""]
    if example["evidence_refs"]:lines.extend(["Source attribution: "+cite(example["evidence_refs"]),""])
    if example["substitutions"]:lines.extend(["Synthetic substitutions:",*details(example["substitutions"]),""])
    if example["observation_refs"]:lines.extend(["Contained observation references: "+cite(example["observation_refs"]),""])
    return lines

def location_lines(locations:list[dict],cite)->list[str]:
    return [f"- **{cite([str(row['file'])+':'+str(row['line'])])}** — {markdown(row['scope'])}: "
            f"{markdown(row['mechanism'])}" for row in locations]

def execution_label(finding:dict)->str:
    steps=finding["exploitation"]["steps"]
    if (all(step["evidence_status"]=="source_established" and not step["observed_result"]
            and not step["observation_refs"] for step in steps)
            and all(example["execution_status"]=="not_executed" for example in finding["technical_examples"])):
        return "source-established; not dynamically tested"
    return "step-specific source/contained evidence; no whole-attack execution inferred"

def finding_lines(finding:dict,scan:Path,repositories:list[dict])->list[str]:
    references={}
    def cite(refs):
        return ", ".join(references.setdefault(ref,f"C{len(references)+1}") for ref in dict.fromkeys(refs))
    shared_status=execution_label(finding)=="source-established; not dynamically tested"
    lines=[f'<a id="finding-{html.escape(finding["id"],quote=True)}"></a>',
           f"### {markdown(finding['id'])}: {markdown(finding['title'])}","",
           f"**{markdown(finding['severity'])}** | "
           f"**{markdown(finding['verdict'])}** | Confidence: {markdown(finding['confidence'])}","",
           markdown(finding["attack_summary"]),"",
           "**Execution:** "+execution_label(finding)+".","",
           "#### Affected code and services",""]
    for component in finding["affected_components"]:
        service=component["service"]
        lines.extend([f"**{markdown(component['id'])}: {markdown(component['name'])}**",
                      f"Repository: {markdown(component['repository'])}",*location_lines(component["locations"],cite),
                      f"Entrypoints / jobs: {markdown('; '.join(component['entrypoints']))}",
                      f"Service: **{markdown(service['name']) if service['name'] else 'Not established'}** "
                      f"({markdown(service['binding'])})."])
        if service["limitation"]:lines.append(markdown(service["limitation"]))
        lines.extend(["Supporting evidence: "+cite([*component["evidence_refs"],*service["evidence_refs"]]),""])
    actor=finding["attacker"]
    lines.extend(["#### Starting access and prerequisites","",
                  f"**Attacker:** {markdown(actor['perspective'])}. **Starting access:** {markdown(actor['starting_access'])}.",
                  f"**Boundary crossed:** {markdown(actor['boundary_crossed'])}.",
                  *details(list(dict.fromkeys([*finding["conditions"],*finding["exploitation"]["setup"]]))),"",
                  "**Intended behavior:** "+markdown(finding["intended_behavior"]),"",
                  "#### Root cause and causal path","",*location_lines(finding["root_causes"],cite),"",
                  markdown(finding["exploitation"]["rationale"]),""])
    flow=[f"{markdown(step['scope'])} ({cite([step['file']+':'+str(step['line'])])})" for step in finding["trace"]]
    lines.extend(["Code flow: "+" --> ".join(flow)+".",
                  "Full trace: "+evidence_link(scan,"report/security-report.json","Finding data")+
                  f"; finding {markdown(finding['id'])}, field trace.","","#### Exploitation procedure",""])
    for index,step in enumerate(finding["exploitation"]["steps"],1):
        lines.extend([f'<a id="step-{html.escape(finding["id"],quote=True)}-{html.escape(step["id"],quote=True)}"></a>',
                      f"{index}. **{markdown(step['id'])}: {markdown(step['action'])}**",
                      f"   - Controlled input: {markdown(step['controlled_input'])}",
                      f"   - Components: {markdown(', '.join(step['component_ids']))}",
                      f"   - Why it works: {markdown(step['why_it_works'])}",
                      f"   - Expected result: {markdown(step['expected_result'])}"])
        if not shared_status:
            lines.extend([f"   - Evidence status: **{markdown(step['evidence_status'])}**",
                          f"   - Observed result: {markdown(step['observed_result']) if step['observed_result'] is not None else 'Not executed / no observation claimed.'}"])
        for label,key in (("Proof","evidence_refs"),("Observation evidence","observation_refs")):
            if step[key]:lines.append(f"   - {label}: {cite(step[key])}")
        for label,key in (("Examples","example_ids"),("Chain primitives","primitive_ids")):
            if step[key]:lines.append(f"   - {label}: {markdown(', '.join(step[key]))}")
        repairs=[action for action in finding["remediation"]["actions"] if step["id"] in action["breaks_steps"]]
        if repairs:
            lines.append("   - Interrupted by: "+", ".join(
                f"[{markdown(action['id'])}](#"+quote("fix-"+finding["id"]+"-"+action["id"],safe="")+")"
                for action in repairs))
        lines.append("")
    if finding["primitive_steps"]:
        lines.extend(["**Capability transfers and jointly feasible conditions:**",
                      *details(finding["primitive_steps"]),*details(finding["transitions"]),""])
    for example in finding["technical_examples"]:lines.extend(example_lines(example,cite))
    for key,label in (("dependency","Dependency version, affected use and reachability"),("secret","Redacted location and exposure")):
        if finding.get(key):lines.extend([f"**{label}:**",*details(finding[key]),""])
    lines.extend(["#### Impact and limits","",markdown(finding["impact"]),"",
                  *details(finding["impact_limits"]),"",
                  "**Conclusion:** "+markdown(finding["closure_rationale"]),"","#### Remediation",""])
    remediation=finding["remediation"]
    for action in remediation["actions"]:
        lines.extend([f'<a id="fix-{html.escape(finding["id"],quote=True)}-{html.escape(action["id"],quote=True)}"></a>',
                      f"**{markdown(action['id'])}: {markdown(action['change'])}**","",
                      markdown(action["rationale"]),
                      "- Breaks attack steps: "+", ".join(
                          f"[{markdown(sid)}](#"+quote("step-"+finding["id"]+"-"+sid,safe="")+")"
                          for sid in action["breaks_steps"]),
                      f"- Affected components: {markdown(', '.join(action['component_ids']))}",
                      *location_lines(action["locations"],cite),
                      "Supporting evidence: "+cite(action["evidence_refs"])])
        if action["example_ids"]:lines.append("Examples: "+markdown(", ".join(action["example_ids"])))
        lines.append("")
    for key,label in (("containment","Temporary containment"),("detection","Detection")):
        if remediation[key]:
            lines.append(f"**{label}:**")
            for item in remediation[key]:
                lines.extend([f"- {markdown(item['description'])}",
                              f"  Components: {markdown(', '.join(item['component_ids']))}. Evidence: {cite(item['evidence_refs'])}"])
            lines.append("")
    lines.extend(["**Defensive limitations:**",*details(remediation["limitations"]),""])
    lines.extend(["#### Fix verification","",
                  "Proposed checks are recommendations, not passing tests or verified patches.",""])
    for check in remediation["verification_checks"]:
        lines.extend([f"- **{markdown(check['id'])} — {markdown(check['status'])}:** {markdown(check['description'])}",
                      f"  - Attack rejection: {markdown(check['attack_expected'])}",
                      f"  - Legitimate operation: {markdown(check['legitimate_expected'])}",""])
        if check["evidence_refs"]:lines.extend(["  Evidence: "+cite(check["evidence_refs"]),""])
    lines.extend(["#### Evidence references",""])
    for ref,label in references.items():
        if ref.split("/",1)[0] in SCAN_NAMESPACES:
            destination=evidence_link(scan,ref)
        else:
            destination=markdown(ref)
            for index,repository in enumerate(repositories,1):
                prefix=repository["path"].rstrip("/")+"/"
                if ref.startswith(prefix) and sum(row["path"]==repository["path"] for row in repositories)==1:
                    destination=f"R{index}/"+markdown(ref[len(prefix):])
                    break
        lines.append(f"- **{label}:** {destination}")
    lines.append("")
    lines.extend(["**Canonical finding evidence:**",
                  *[f"- {evidence_link(scan,row['artifact_ref'],required=True)} ({markdown(row['kind'])}: {markdown(row['source_id'])})" for row in finding["source_refs"]],
                  "**Independent review:** "+evidence_link(scan,finding["independent_verification_ref"],required=True),""])
    return lines

def gap_projection(scan: Path, findings: list[dict], context: dict | None = None) -> dict | None:
    from gap_exploration_contract import load_accepted
    from gap_dossier import candidate_references, source_reference
    supplement = load_accepted(scan, context=context)
    if supplement is None:
        return None
    references = {ref for row in supplement["candidates"] for ref in candidate_references(row)}
    accepted_ids = sorted(finding["id"] for finding in findings
                          if any(source_reference(source) in references
                                 for source in finding.get("source_refs", [])))
    return {**supplement["summary"], "status": supplement["status"],
            "limitations": supplement["limitations"], "non_promoted": supplement["non_promoted"],
            "independently_accepted_finding_ids": accepted_ids,
            "independently_accepted": len(accepted_ids)}


def gap_lines(value: dict, evidence: str) -> list[str]:
    lines = ["## Additional attack-path exploration", "",
             "Supplementary work did not replace the original investigation. "
             "Navigation and candidate counts are not confirmed vulnerabilities.", "",
             "| Outcome | Count |", "| --- | ---: |"]
    for label, key in (("Questions examined", "examined_questions"),
                       ("Useful graph queries", "useful_navigation"),
                       ("Supplementary investigations", "investigated_leads"),
                       ("Candidate dossiers", "candidates"),
                       ("Independently accepted findings using supplementary evidence", "independently_accepted"),
                       ("Uninvestigated leads", "uninvestigated_leads")):
        lines.append(f"| {label} | {value[key]} |")
    lines.extend(["", "These cohorts overlap; do not sum them as unique findings. Accepted findings may include "
                  "mixed original and supplementary evidence, not only additional attacker outcomes.",
                  "Full questions, outcomes and limitations: " + evidence + "."])
    if value["limitations"]:
        lines.extend(["", "Limitations:", *details(value["limitations"][:5])])
    lines.append("")
    return lines


def render_markdown(report:dict,scan:Path)->str:
    summary=report["summary"];accounting=report["investigation_accounting"]
    prioritized=sorted(report["findings"],key=lambda row:(SEVERITIES.index(row["severity"]),-row["risk_score"],row["id"]))
    lines=["# Red-team Security Report","",
           f"**Application:** {markdown(report['repository'])} | **Published:** {markdown(report['date'])}","",
           "## Executive attack assessment","",
           "**Assessment:** "+markdown(report["outcome_assessment"]["status"].replace("_"," "))+". "
           "A completed workflow is not proof of exhaustive safety.","",
           f"**Confirmed within assessed scope:** {summary['confirmed']} | "
           f"**Environment required (unconfirmed):** {summary['needs_environment']} | **Rejected:** {summary['rejected']}","",
           " | ".join(f"**{severity.capitalize()}:** {summary[severity]}" for severity in SEVERITIES),"",
           "Publication performs no new source assessment. Later-source applicability is not revalidated. "
           "Source-established outcomes are not executed compromises. Proposed fixes are not passing tests.","",
           "| Assessment scope | Assessment started | Source view |",
           "| --- | --- | --- |"]
    for scope in report["assessment"]["scopes"]:
        lines.append(f"| {markdown(scope['assessment_id'])} | {markdown(scope.get('started_at') or 'Unknown')} | "
                     f"{markdown(scope.get('source_view') or 'Unknown')} |")
    lines.extend(["","| Alias | Repository | Assessed revision | Assessment scopes |","| --- | --- | --- | --- |"])
    for index,repository in enumerate(report["repositories"],1):
        scopes=[scope["assessment_id"] for scope in report["assessment"]["scopes"]
                if repository in (scope.get("repositories") or [])]
        lines.append(f"| R{index} | {markdown(repository['path'])} | {markdown(repository.get('commit') or 'Unknown')} | "
                     f"{markdown(', '.join(scopes) or 'Unknown')} |")
    if not report["repositories"]:
        lines.append("| — | Original repository inventory unknown | Unknown | Unknown |")
    lines.extend(["","| Finding | Severity / disposition | Attacker outcome | Repair | Evidence status |",
                  "| --- | --- | --- | --- | --- |"])
    for finding in prioritized:
        repairs=", ".join(f"[{markdown(action['change'].split('.')[0])}](#"+
                         quote("fix-"+finding["id"]+"-"+action["id"],safe="")+")"
                         for action in finding["remediation"]["actions"])
        lines.append(f"| [{markdown(finding['id'])}](#finding-{quote(finding['id'],safe='')}) | "
                     f"{markdown(finding['severity'])} / {markdown(finding['verdict'])} | "
                     f"{markdown(finding['attack_summary'].split('.')[0])} | {repairs} | {execution_label(finding)} |")
    if prioritized:
        lines.append("\nFirst remediation priorities: "+", ".join(
            f"[{markdown(row['id'])}](#finding-{quote(row['id'],safe='')})" for row in prioritized[:3])+".")
    exclusions=list(dict.fromkeys([*report["limitations"],
        *(component["service"]["limitation"] for finding in prioritized for component in finding["affected_components"]
          if component["service"]["limitation"])]))
    if exclusions:lines.extend(["","**Material exclusions and limits:**",*details(exclusions),""])
    lines.extend(["","## Finding dossiers",""])
    if not report["findings"]:
        lines.extend(["No findings were independently accepted within the recorded scope. This does not establish exhaustive safety.",""])
    for finding in report["findings"]:
        scope=report["assessment"]["record_scopes"].get(finding["id"])
        lines.extend(["Assessed scope: "+markdown(scope or "Unknown")+".",""])
        lines.extend(finding_lines(finding,scan,report["repositories"]))
    lines.extend(["## Prioritized defensive handoff","",
                  "Ordered by accepted severity and risk. Each link names a separate reviewed action; no patch verification is inferred.","",
                  "| Priority | Component | Finding / action | Breaks steps |",
                  "| ---: | --- | --- | --- |"])
    for priority,finding in enumerate(prioritized,1):
        for action in finding["remediation"]["actions"]:
            anchor=quote("fix-"+finding["id"]+"-"+action["id"],safe="")
            lines.append(f"| {priority} | {markdown(', '.join(action['component_ids']))} | "
                         f"[{markdown(finding['id'])} / {markdown(action['id'])}](#{anchor}) | "
                         f"{markdown(', '.join(action['breaks_steps']))} |")
    lines.extend(["","## Objectives and consequential unresolved work","",
                  "Accepted scope and remaining proof are separate. An open sibling neither invalidates an accepted finding "
                  "nor inherits its confirmation.",""])
    rendered_ids = {finding["id"] for finding in report["findings"]}
    for objective in report["objective_assessments"]:
        lines.extend([f'<a id="objective-{html.escape(objective["objective_id"],quote=True)}"></a>',
                      f"### {markdown(objective['objective_id'])} — {markdown(objective['status'])}","",
                      markdown(objective["success_condition"]),markdown(objective["reason"])])
        accepted_ids = [fid for fid in objective["finding_ids"] if fid in rendered_ids]
        other_ids = [fid for fid in objective["finding_ids"] if fid not in rendered_ids]
        if accepted_ids:
            lines.append("Accepted finding scope: "+", ".join(
                f"[{markdown(fid)}](#finding-{quote(fid,safe='')})" for fid in accepted_ids)+".")
        if other_ids:
            lines.append("Other reviewed candidate IDs: "+", ".join(markdown(fid) for fid in other_ids)+
                         "; see "+evidence_link(scan,"final-verification/findings.json","Final verification")+".")
        if objective["remaining_obligations"]:
            lines.extend(["Remaining proof:",*details(list(dict.fromkeys(objective["remaining_obligations"])))])
        for question in objective["question_outcomes"]:
            if question.get("missing_fact") and question.get("next_action"):
                lines.append(f"- Next action ({markdown(question['question_id'])}): {markdown(question['next_action'])}")
        lines.append("")
    seen=set()
    for category,rows in (("evidence_limited",accounting["evidence_limited"]),
                          ("unresolved_paths",accounting["unresolved_paths"][:5])):
        previously_displayed=len(seen)
        lines.extend([f"### {markdown(category.replace('_',' '))}","",
                      f"{len(rows)} entries selected from {accounting['counts'][category] if accounting['counts'][category] is not None else 'unknown total'} records; repeated identical owners are shown once. "
                      "Full records and repair history: "+evidence_link(scan,"report/security-report.json","Report data")+
                      f", field {markdown('investigation_accounting.'+category)}.",""])
        for row in rows:
            resolution=row.get("resolution",{})
            identifier=str(row.get("id",row.get("evidence_id","Unresolved claim")))
            missing=row.get("missing_fact") or resolution.get("missing_fact")
            action=row.get("next_action") or resolution.get("next_action")
            refs=[row["evidence_ref"]] if row.get("evidence_ref") else row.get("input_refs",[])
            identity=(identifier,tuple(refs),missing,action,row.get("disposition",row.get("status")))
            if identity in seen:continue
            seen.add(identity)
            lines.append(f"- **{markdown(identifier)}:** {markdown(row.get('disposition',row.get('status',category)))}")
            if missing:lines.append("  Missing fact: "+markdown(missing))
            else:lines.append("  "+markdown(resolution.get("reason") or row.get("reason","Proof remains incomplete.")))
            if action:lines.append("  Next action: "+markdown(action))
            for objective in report["objective_assessments"]:
                bindings={_parts(ref) for question in objective["question_outcomes"]
                          for ref in [question.get("owner_ref",""),*question.get("evidence_refs",[])]
                          if ref.split("/",1)[0] in SCAN_NAMESPACES and (":" in ref or "#" in ref)}
                if (row.get("objective_id")==objective["objective_id"]
                        or row.get("question_id") in {question["question_id"] for question in objective["question_outcomes"]}
                        or any(_parts(ref) in bindings for ref in row.get("input_refs",[]))):
                    lines.append(f"  Related objective: [{markdown(objective['objective_id'])}](#objective-{quote(objective['objective_id'],safe='')}).")
            if refs:lines.append("  Record / repair history: "+", ".join(evidence_link(scan,ref) for ref in refs)+
                                 f"; record {markdown(identifier)}.")
            lines.append("")
        lines.extend([f"{len(seen)-previously_displayed} records displayed here; "
                      f"{accounting['counts'][category] if accounting['counts'][category] is not None else 'Unknown'} total in this cohort.",""])
    if report.get("gap_exploration") is not None:
        lines.extend(["", *gap_lines(report["gap_exploration"],
                                    evidence_link(scan, "gap-exploration/results.json", "Supplementary investigation"))])
    if report.get("unreviewed"):
        lines.extend(["", "## Unreviewed supplementary claims", "",
                      "These claims have no independent verdict or confirmed severity. Complete closures: "
                      + evidence_link(scan, "report/security-report.json", "Report data") + ", field `unreviewed`.", ""])
        for row in report["unreviewed"][:5]:
            lines.extend([f"- **{markdown(row['id'])}:** {markdown(row['status'])}. {markdown(row['reason'])}",
                          "  Missing proof: " + markdown(row["missing_fact"]),
                          "  Next action: " + markdown(row["next_action"])])
    lines.extend(["","## Evidence and coverage index","",
                  markdown(report["integrity"]["headline"]),"",
                  markdown(report["outcome_assessment"]["headline"]),"",
                  f"Run: {markdown(report['run_id'])}","",
                  "Categories overlap; totals are not a count of unique vulnerabilities. "
                  "Historical deferrals mean not separately scheduled during planning, not current failures.","",
                  "| Accounting category | Total | Omitted from JSON display | Detail |",
                  "| --- | ---: | ---: | --- |"])
    report_link = evidence_link(scan,"report/security-report.json","Report data")
    for key,count in sorted(accounting["counts"].items()):
        field={"prior_run_reconciliation":"prior_run_reconciliation",
               "coverage_cells":"coverage.cells","coverage_tasks":"coverage.tasks"}.get(key,"investigation_accounting."+key)
        omitted=accounting["truncated"].get(key)
        lines.append(f"| {markdown(key.replace('_',' '))} | {count if count is not None else 'Unknown'} | {omitted if omitted is not None else 'Unknown'} | "
                     f"{report_link}: {markdown(field)} |")
    lines.extend(["","### Canonical evidence","",
                  "Deliver this report with its sanitized canonical artifact tree, preserving relative paths. "
                  "Markdown alone is not the complete evidence bundle.","",
                  f"- {report_link}: complete findings, objective assessments, evidence quality, routing, attribution and coverage.",
                  f"- Verification diversity: {report['diversity_counts']['diverse']} diverse; "
                  f"{report['diversity_counts']['same_model']} same-model fresh-context; {report['diversity_counts']['total']} total."])
    for ref in accounting["canonical_refs"]:
        if "*" not in ref:
            lines.append("- "+evidence_link(scan,ref))
    return "\n".join(lines)
def investigation_accounting(scan:Path,coverage:dict,limitations:list|None=None,context:dict|None=None)->dict:
    limitations=limitations if limitations is not None else []
    resolved=[]; unresolved=[]; unscheduled=[]; capabilities=[]; historical=[]
    unavailable=set()
    def optional(ref,collections=()):
        value=optional_document(scan,ref,limitations,context=context,collections=collections)
        if value is None:unavailable.add(ref)
        return value or {}
    index=optional("campaign-planning/evidence-index.json")
    intrusion=optional("intrusion/intrusion-results.json",("results",))
    plan=optional("campaign-planning/campaign-plan.json",("campaigns",))
    triage={row["evidence_id"]:row for row in optional("campaign-planning/discovery.json").get("scanner_triage",[])}
    experiments=[]; graph=[]
    for phase in ("sast","intrusion"):
        from advantage_contract import inside
        for path in sorted(inside(scan,f"{phase}/experiments").glob("*/result.json")):
            relative=path.relative_to(scan).as_posix()
            result=optional(relative)
            request=optional(path.with_name("request.json").relative_to(scan).as_posix())
            if not result or not request:continue
            experiments.append({"id":result.get("experiment_id"),"owner_phase":phase,"obligation":request.get("obligation"),"status":result.get("status"),"resolution":result.get("resolution",{}),"interpretation_boundary":result.get("interpretation_boundary"),"evidence_ref":relative})
    primitives=list(index.get("primitives",[]))
    for row in intrusion.get("results",[]):
        primitives.extend(row.get("primitive_updates",[]))
        receipts=[]
        for ref in row.get("graph_query_receipts",[]):
            receipts.append(optional(ref))
        complete=all(receipts)
        graph.append({"id":row.get("campaign_id"),"limitations":row.get("graph_limitations",[]),"answers":row.get("graph_answers",[]),"useful_receipts":sum(receipt.get("meaningful") is True for receipt in receipts) if complete else None,"failed_receipts":sum(receipt.get("status") not in {"ok",None} or receipt.get("parse_status") not in {"ok",None} for receipt in receipts) if complete else None,"evidence_ref":"intrusion/intrusion-results.json"})
        result=row.get("resolution",{})
        item={"id":row.get("campaign_id"),"resolution":result,"composition":row.get("composition",{}),"evidence_ref":"intrusion/intrusion-results.json","transitions":[edge for candidate in row.get("candidates",[]) for edge in candidate.get("transitions",[])]}
        (resolved if result.get("outcome") in {"established","contradicted"} else unresolved).append(item)
    seen=set()
    for primitive in primitives:
        capability=primitive.get("capability",{})
        if capability.get("evidence_status") in {"source_established","experimentally_observed"} and primitive.get("id") not in seen:
            seen.add(primitive.get("id"));capabilities.append({"primitive_id":primitive.get("id"),"capability":capability})
    for cell in coverage.get("cells",[]):
        item={**cell,"evidence_ref":"sast/coverage-ledger.json"}
        if cell.get("status") in {"deferred","depth_limited"} and not cell.get("task_ids"):unscheduled.append(item)
        elif cell.get("resolution",{}).get("outcome") in {"established","contradicted"}:resolved.append(item)
        else:unresolved.append(item)
    linked_tasks={tid for cell in coverage.get("cells",[]) for tid in cell.get("task_ids",[])}
    for task in coverage.get("tasks",[]):
        if task.get("id") not in linked_tasks and task.get("status") in {"shallow","failed"}:unresolved.append({**task,"evidence_ref":"sast/coverage-ledger.json"})
    campaigns={row["id"]:row for row in plan.get("campaigns",[])}
    investigated={row.get("campaign_id") for row in intrusion.get("results",[])}
    for cid,row in campaigns.items():
        if "intrusion/intrusion-results.json" not in unavailable and cid not in investigated:unscheduled.append({"id":cid,"priority_band":row.get("priority_band"),"reason":"Planned campaign has no completed investigation.","question":row.get("objective",row.get("hypothesis","")),"evidence_ref":"campaign-planning/campaign-plan.json"})
    for row in plan.get("scanner_accounting",[]):
        if row.get("status")=="deferred":unscheduled.append({**row,"triage":triage.get(row["evidence_id"],{}),"next_action":"Investigate source applicability of this scanner observation; it is not an established finding.","evidence_ref":"campaign-planning/campaign-plan.json"})
    for row in plan.get("question_dispositions",[]):
        if row["status"] in {"deferred","evidence_limited"}:
            unscheduled.append({**row,"evidence_ref":"campaign-planning/campaign-plan.json"})
    records={row["id"]:row for row in index.get("records",[])}
    for row in plan.get("evidence_dispositions",[]):
        if row.get("status")=="evidence_limited":
            source=records.get(row["evidence_id"],{})
            historical.append({**row,"risk_context":source.get("risk_context",{}),"source_ref":source.get("artifact_ref",""),"evidence_ref":"campaign-planning/campaign-plan.json"})
    historical.sort(key=lambda row: (row.get("risk_context",{}).get("priority",3) if isinstance(row.get("risk_context"),dict) else 3, row["evidence_id"]))
    paths=optional("repo-context/security-surfaces.json").get("attack_paths",[])
    covered=coverage.get("availability")!="unavailable"
    available=lambda ref:ref not in unavailable
    counts={
        "established_capabilities":len(capabilities) if available("campaign-planning/evidence-index.json") and available("intrusion/intrusion-results.json") else None,
        "resolved_investigations":len(resolved) if covered and available("intrusion/intrusion-results.json") else None,
        "unresolved_paths":len(unresolved) if covered and available("intrusion/intrusion-results.json") else None,
        "unscheduled_work":len(unscheduled) if covered and available("campaign-planning/campaign-plan.json") and available("intrusion/intrusion-results.json") else None,
        "historical_planning_deferrals":len(historical) if available("campaign-planning/campaign-plan.json") else None,
        "actor_to_asset_paths":len(paths) if available("repo-context/security-surfaces.json") else None,
        "experiments":len(experiments) if not any("/experiments/" in ref for ref in unavailable) else None,
        "graph_navigation":len(graph) if available("intrusion/intrusion-results.json") else None}
    return {"established_capabilities":capabilities,"resolved_investigations":resolved,"unresolved_paths":unresolved,"unscheduled_work":unscheduled,"historical_planning_deferrals":historical,"actor_to_asset_paths":paths,"experiments":experiments,"graph_navigation":graph,"counts":counts,"denominators":{"coverage_cells":len(coverage.get("cells",[])) if covered else None,"source_tasks":len(coverage.get("tasks",[])) if covered else None,"planned_campaigns":len(campaigns) if available("campaign-planning/campaign-plan.json") else None,"completed_campaign_questions":len(intrusion.get("results",[])) if available("intrusion/intrusion-results.json") else None,"actor_to_asset_paths":counts["actor_to_asset_paths"],"definition":"Counts refer to recorded cohorts, not exhaustive coverage. Null counts denote unavailable explanation; displayed records remain a partial known cohort. Categories can overlap and are not unique vulnerabilities. Historical planning deferrals do not infer later resolution."}}
def evidence_accounting(scan:Path,final:dict,limitations:list|None=None,context:dict|None=None)->tuple[dict,list[dict]]:
    limitations=limitations if limitations is not None else []
    diagnostics=[];totals={};limited=[];complete=True
    for ref in ("repo-context/repo-context.json","repo-context/security-surfaces.json","sast/coverage-ledger.json","campaign-planning/evidence-index.json","campaign-planning/campaign-plan.json","intrusion/intrusion-results.json","synthesis/findings.json","final-verification/findings.json"):
        doc=final if ref=="final-verification/findings.json" else optional_document(scan,ref,limitations,context=context)
        if doc is None:
            complete=False
            continue
        quality=doc.get("evidence_quality",{})
        if quality:
            diagnostics.extend(quality["diagnostics"]);totals[ref]={key:quality[key] for key in ("total","truncated","affected_item_count")}
    quality=summarize(diagnostics)
    quality["total"]=sum(row["total"] for row in totals.values())
    quality["truncated"]+=sum(row["truncated"] for row in totals.values())
    quality["affected_item_count"]=sum(row["affected_item_count"] for row in totals.values())
    quality["phase_totals"]=totals
    quality["canonical_refs"]=list(totals)
    if not complete:
        for key in ("total","truncated","affected_item_count"):quality[key]=None
    for row in final.get("non_promoted",[]):
        if row["disposition"]=="evidence_limited":limited.append({**{key:value for key,value in row.items() if key!="diagnostics"},"evidence_ref":"final-verification/findings.json"})
    limited.sort(key=lambda row: (row.get("risk_context",{}).get("priority",3) if isinstance(row.get("risk_context"),dict) else 3,
                                 row.get("id",row.get("evidence_id",""))))
    return quality,limited

def required_document(path:Path)->dict:
    from advantage_contract import load_value
    try:value=load_value(path)
    except EvidenceIssue as exc:raise ValueError(f"{path}: required authority is unavailable ({exc.code})") from exc
    if not isinstance(value,dict):raise ValueError(f"{path}: expected object")
    return value

def optional_document(scan:Path,relative:str,limitations:list,*,context:dict|None=None,
                      collections:tuple=(),array:bool=False)->Any:
    """Read bounded explanation without downgrading unsafe data to absence."""
    from advantage_contract import inside, load_value
    _parts(relative)
    path=inside(scan,relative)
    try:
        if not path.is_file():
            raise EvidenceIssue("missing_file","optional report support is absent")
        value=load_value(path)
        if isinstance(value,dict) and context and value.get("run_id",context["run_id"])!=context["run_id"]:
            raise ValueError(f"{relative}: belongs to another execution")
        if isinstance(value,dict):
            for key in ("cells","tasks","campaigns","records","primitives","results","attack_paths",
                        "scanner_triage","scanner_accounting","question_dispositions","evidence_dispositions"):
                if key in value and (not isinstance(value[key],list) or any(not isinstance(row,dict) for row in value[key])):
                    raise EvidenceIssue("unreadable_content","invalid optional collection")
            required_keys={"campaigns":("id",),"records":("id",),"scanner_triage":("evidence_id",),
                           "scanner_accounting":("evidence_id",),"question_dispositions":("status",),
                           "evidence_dispositions":("evidence_id",)}
            if any(any(any(not isinstance(row.get(key),str) for key in keys) for row in value.get(collection,[]))
                   for collection,keys in required_keys.items()):
                raise EvidenceIssue("unreadable_content","invalid optional record")
            quality=value.get("evidence_quality")
            if quality is not None and (not isinstance(quality,dict) or
                    not isinstance(quality.get("diagnostics"),list) or
                    any(not isinstance(quality.get(key),int) for key in ("total","truncated","affected_item_count"))):
                raise EvidenceIssue("unreadable_content","invalid optional quality accounting")
            pending=[value]
            while pending:
                row=pending.pop()
                for key in ("resolution","capability","composition"):
                    if key in row and not isinstance(row[key],dict):
                        raise EvidenceIssue("unreadable_content","invalid optional record detail")
                for key in ("id","campaign_id","status"):
                    if key in row and not isinstance(row[key],str):
                        raise EvidenceIssue("unreadable_content","invalid optional record identity")
                for key in ("task_ids","graph_query_receipts","graph_limitations","graph_answers"):
                    if key in row and not isinstance(row[key],list):
                        raise EvidenceIssue("unreadable_content","invalid optional navigation detail")
                for key in ("cells","tasks","results","primitives","primitive_updates","candidates","transitions"):
                    if key in row:
                        if not isinstance(row[key],list) or any(not isinstance(item,dict) for item in row[key]):
                            raise EvidenceIssue("unreadable_content","invalid optional nested collection")
                        pending.extend(row[key])
        if array:
            valid=isinstance(value,list) and all(isinstance(row,dict) for row in value)
        else:
            valid=isinstance(value,dict) and all(
                isinstance(value.get(key),list) and all(isinstance(row,dict) for row in value[key])
                for key in collections)
        if not valid:
            raise EvidenceIssue("unreadable_content","invalid optional report support shape")
        return value
    except (EvidenceIssue,OSError):
        limitation=f"Historical support {relative} is unavailable; explanatory counts and scope are unknown."
        if limitation not in limitations:limitations.append(limitation)
        return None

def coverage_input(scan:Path,limitations:list|None=None,context:dict|None=None)->dict:
    limitations=limitations if limitations is not None else []
    value=optional_document(scan,"sast/coverage-ledger.json",limitations,context=context,collections=("cells","tasks"))
    return value if value is not None else {"availability":"unavailable",
        "limitation":"Historical support sast/coverage-ledger.json is unavailable; explanatory counts and scope are unknown."}

def assessment_projection(final:dict,context:dict)->dict:
    """Select the exact accepted final cohort, independent of publishing attempt."""
    if final.get("run_id") not in {None,context["run_id"]}:
        raise ValueError("final-verification/findings.json: run_id differs from owning execution")
    for key in ("findings","rejections","objective_assessments"):
        if not isinstance(final.get(key),list):
            raise ValueError(f"final-verification/findings.json: missing or invalid {key}")
    seen=set()
    for key in ("findings","rejections","non_promoted","unreviewed"):
        for row in final.get(key,[]):
            if not isinstance(row,dict) or not isinstance(row.get("id"),str) or not row["id"]:
                raise ValueError(f"final-verification/findings.json: {key}[].id is required")
            if row["id"] in seen:
                raise ValueError("final-verification/findings.json: duplicate disposition ID "+row["id"])
            seen.add(row["id"])
    return {key:final.get(key,[]) for key in ("findings","rejections","non_promoted","unreviewed","objective_assessments")}


def accepted_routing(final:dict,context:dict)->dict|None:
    reference=final.get("assessment_context") or {}
    producer=reference.get("attempt_id") or context.get("phase_attempts",{}).get("final-verification")
    recorded=context.get("attempt_contexts",{}).get(producer,{})
    if isinstance(recorded.get("model_routing"),dict):return recorded["model_routing"]
    if isinstance(final.get("model_routing"),dict):return final["model_routing"]
    if not context.get("attempt_id"):return context.get("model_routing")
    return None


def validate_accepted_authority(scan:Path,final:dict,context:dict)->list[str]:
    """Validate immutable accepted bindings, not today's source or actor mapping."""
    evidence_link(scan,"final-verification/findings.json",required=True)
    projection=assessment_projection(final,context)
    checked(final)
    limitations=[]
    for finding in projection["findings"]:
        validate_publication_schema(finding,"final-findings.schema.json","finding")
        ref=finding["independent_verification_ref"]
        if ref!=f"final-verification/results/{finding['id']}.json":
            raise ValueError(f"{finding['id']}: independent review is not its canonical authority")
        evidence_link(scan,ref,required=True)
        review=required_document(scan/ref)
        try:validate_publication_schema(review,"independent-verification-result.schema.json")
        except ValueError as exc:raise ValueError(f"{ref}: {exc}") from exc
        if review["finding_id"]!=finding["id"]:
            raise ValueError(f"{ref}: independent review finding_id differs from accepted finding")
        if (finding["verdict"]=="confirmed") != (finding["status"]=="verified"):
            raise ValueError(f"{ref}: accepted verdict differs from dossier disposition")
        expected="needs_environment" if finding["verdict"]=="needs_environment" else "confirmed"
        actual="needs_environment" if review["status"]=="needs_environment" else (
            "confirmed" if review["status"] in {"verified","corrected"} else review["status"])
        if actual!=expected:
            raise ValueError(f"{ref}: independent review disposition differs from accepted finding")
        if review["dossier_review"]["dossier_sha256"]!=dossier_hash(finding):
            raise ValueError(f"{ref}: independent dossier review is stale for the effective finding")
        if expected=="confirmed" and any(review["dossier_review"][key]["disposition"]=="unresolved" for key in ASPECTS):
            raise ValueError(f"{ref}: accepted dossier contains an unresolved independent assessment")
        for key in ("attempt_id","assessment_id"):
            accepted=(finding.get("assessment_context") or {}).get(key)
            reviewed=(review.get("assessment_context") or {}).get(key)
            if accepted and reviewed and accepted!=reviewed:
                raise ValueError(f"{ref}: independent review {key} differs from accepted finding")
        producer=(review.get("assessment_context") or {}).get("attempt_id")
        recorded=context.get("attempt_contexts",{}).get(producer,{}).get("model_routing")
        if recorded and recorded.get("agents",{}).get(review["actor"])!=review["model"]:
            raise ValueError(f"{ref}: reviewer differs from recorded producing assignment")
        if review["status"]=="corrected" and dossier_hash(review["corrected_finding"] or {})!=dossier_hash(finding):
            raise ValueError(f"{ref}: corrected finding differs from accepted effective dossier")
        if finding["model_diversity"] is not finding_diversity(finding["contributors"],review["model"]):
            raise ValueError(f"{ref}: finding diversity differs from recorded reviewer and contributors")
        for source in finding["source_refs"]:
            evidence_link(scan,source["artifact_ref"],required=True)
        for field,refs,kind in dossier_evidence_groups(finding):
            for citation in refs:
                relative,_=_parts(citation)
                if kind=="artifact" or kind=="mixed" and relative.split("/",1)[0] in SCAN_NAMESPACES:
                    evidence_link(scan,citation)
                    try:artifact_value(scan,citation)
                    except EvidenceIssue:
                        limitations.append(f"{finding['id']}: retained supporting reference {citation} is unavailable; its accepted review is preserved without replay.")
    for rejection in projection["rejections"]:
        ref=rejection.get("independent_verification_ref","")
        if ref!=f"final-verification/results/{rejection['id']}.json":
            raise ValueError(f"{rejection['id']}: rejection lacks canonical independent review authority")
        evidence_link(scan,ref,required=True)
        review=required_document(scan/ref)
        try:validate_publication_schema(review,"independent-verification-result.schema.json")
        except ValueError as exc:raise ValueError(f"{ref}: {exc}") from exc
        if (review["finding_id"]!=rejection["id"] or review["status"]!="rejected"
                or review["closure_reason"]!=rejection["reason"]):
            raise ValueError(f"{ref}: rejection differs from accepted review")
    return sorted(set(limitations))

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("scan_base",type=Path);a=p.parse_args()
    a.scan_base=a.scan_base.resolve()
    root=Path(__file__).resolve().parent.parent
    context=required_document(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")))
    for key,kind in (("run_id",str),("model_routing",dict),("repositories",list)):
        if not isinstance(context.get(key),kind):raise ValueError(f"audit context: missing or invalid {key}")
    require_active_phase(a.scan_base,context,"report")
    for name in ("security-report.json","security-report.md","phase-manifest.json"):
        if not (a.scan_base/"report"/name).resolve().is_relative_to(a.scan_base):
            raise ValueError(f"unsafe report destination: report/{name}")
    final_path=(a.scan_base/"final-verification/findings.json").resolve()
    if not final_path.is_relative_to(a.scan_base):raise ValueError("unsafe artifact path: final-verification/findings.json")
    final=required_document(final_path)
    support_limitations=validate_accepted_authority(a.scan_base,final,context)
    projection=assessment_projection(final,context)
    findings=projection["findings"];rejections=projection["rejections"]
    gap=gap_projection(a.scan_base, findings, context)
    routing=accepted_routing(final,context);verifier=final.get("verifier_model")
    if not isinstance(verifier,str) or not verifier:
        raise ValueError("final-verification/findings.json: missing recorded verifier_model")
    assessment=report_assessment(context,[*findings,*rejections,*projection["non_promoted"],
                                          *projection["unreviewed"],*projection["objective_assessments"]] or [final])
    aggregate=diversity_summary(findings)
    summary={"total":len(findings),"rejected":len(rejections),"confirmed":sum(x.get("verdict")=="confirmed" for x in findings),"needs_environment":sum(x.get("verdict")=="needs_environment" for x in findings),**{x:0 for x in SEVERITIES},**{x:0 for x in ORIGINS}}
    summary["unreviewed"]=len(projection["unreviewed"])
    rendered=[]
    for finding in findings:
        if finding["verdict"]=="confirmed":
            summary[finding["severity"]]+=1;summary[finding["origin"]]+=1
        rendered.append(dict(finding))
    limitations=[*assessment["limitations"],*support_limitations,
        "Publication performs no new source assessment; accepted verdicts apply to recorded assessed scopes. Later-source applicability and coverage of newly added components are not revalidated."]
    if routing is None:limitations.append("The original aggregate model-routing assignment is unavailable; per-finding contributors and independent-review selectors remain recorded.")
    if not findings:limitations.append("No accepted findings demonstrate model diversity; both diversity counts are zero.")
    elif aggregate["diversity_counts"]["same_model"]:limitations.append("Some findings used same-model fresh-context verification: the reviewer matches at least one relied-upon investigator or candidate reviewer. Synthesis and reasoning effort do not create diversity.")
    if context.get("reproduction_mode")=="off":
        limitations.append("The publishing invocation disables safe reproduction; original execution status remains recorded per dossier." if assessment["retained"] else "Safe reproduction was disabled; dynamic claims are limited to other cited deterministic evidence.")
    if context.get("codegraph_limitation"):
        limitations.append(("Publishing invocation: " if assessment["retained"] else "")+clean(context["codegraph_limitation"]))
    elif context.get("codegraph_mode")=="disabled":
        limitations.append("The publishing invocation has Codegraph disabled; this does not restate earlier graph-assisted coverage." if assessment["retained"] else "Codegraph was disabled; source review and deterministic tools ran without graph-assisted navigation.")
    dependency_limitations=optional_document(a.scan_base,"tool-collection/dependency-limitations.json",limitations,context=context,collections=("limitations",)) or {}
    for item in dependency_limitations.get("limitations",[]) if isinstance(dependency_limitations,dict) else []:
        limitations.append(clean(item.get("message","Offline dependency coverage is limited.")))
    network=context.get("network",{}) if isinstance(context.get("network"),dict) else {}
    if network.get("agent_egress")=="policy_only":
        limitations.append("The publishing invocation uses policy-only agent egress; earlier execution policies are not inferred." if assessment["retained"] else "Agent shell egress was not technically enforced by the harness; network behavior followed the configured runtime policy.")
    package=context.get("offline_package",{}) if isinstance(context.get("offline_package"),dict) else {}
    execution_environment={"network":network,"offline_package":package}
    scans={}
    for phase,directory in (("recon","repo-context"),("tool-collection","tool-collection"),("sast","sast"),("campaign-planning","campaign-planning"),("intrusion","intrusion"),("synthesis","synthesis"),("final-verification","final-verification")):
        manifest=optional_document(a.scan_base,f"{directory}/phase-manifest.json",limitations,context=context) or {}
        scans[phase]={"status":manifest.get("status"),"coverage":manifest.get("coverage")}
        if manifest.get("status")=="degraded":limitations.append(f"{phase} completed in degraded mode; consult its manifest.")
    if gap is not None:
        scans["gap-exploration"]={"status":gap["status"],"coverage":{key:gap[key] for key in
            ("examined_questions","graph_queries","useful_navigation","investigated_leads","candidates")}}
        limitations.extend(gap["limitations"])
    if projection["unreviewed"]:
        limitations.append(f"{len(projection['unreviewed'])} supplementary claims did not complete independent review; "
                           "no verdict or confirmed severity is assigned to those claims.")
    repositories=[]
    for scope in assessment["scopes"]:
        for repository in scope.get("repositories") or []:
            if repository not in repositories:repositories.append(repository)
    repositories=sanitized(repositories)
    coverage=coverage_input(a.scan_base,limitations,context)
    accounting=investigation_accounting(a.scan_base,coverage,limitations,context)
    quality,limited=evidence_accounting(a.scan_base,final,limitations,context)
    accounting["evidence_limited"]=limited
    summary["evidence_limited"]=len(limited)
    summary["evidence_diagnostics"]=quality["total"]
    if limited:limitations.append(f"{len(limited)} final evidence-limited claims remain unresolved; completed execution does not establish these attacker paths or disprove them. These claims may overlap unresolved path records and are not an additional unique-vulnerability count.")
    if accounting["historical_planning_deferrals"]:limitations.append(f"{len(accounting['historical_planning_deferrals'])} historical planning records were not separately scheduled during planning. This is a coverage caveat, not a count of current failed investigations; no later resolution is inferred.")
    for row in [*findings,*rejections]:
        ref=row.get("independent_verification_ref","")
        result=required_document(a.scan_base/ref)
        if row.get("verdict")=="needs_environment":
            accounting["unresolved_paths"].append(sanitized({"id":row["id"],"resolution":result.get("joint_conditions",{}),"transitions":result.get("transition_results",[]),"evidence_ref":ref}))
        elif row in rejections:
            accounting["resolved_investigations"].append(sanitized({"id":row["id"],"status":"rejected","reason":row["reason"],"transitions":result.get("transition_results",[]),"evidence_ref":ref}))
    for key,value in accounting.items():
        if isinstance(value,list):
            if key not in accounting["counts"] or accounting["counts"][key] is not None:
                accounting["counts"][key]=len(value)
    accounting["truncated"]={key:max(0,count-200) if count is not None else None for key,count in accounting["counts"].items()}
    accounting["canonical_refs"]=["sast/coverage-ledger.json","repo-context/security-surfaces.json","campaign-planning/evidence-index.json","campaign-planning/campaign-plan.json","campaign-planning/discovery.json","intrusion/intrusion-results.json","synthesis/findings.json","final-verification/findings.json","sast/experiments/*/result.json","intrusion/experiments/*/result.json"]
    if gap is not None:accounting["canonical_refs"].append("gap-exploration/results.json")
    experiment_open=sum(row.get("resolution",{}).get("outcome") not in {"established","contradicted"} for row in accounting["experiments"])
    summary["unresolved_experiments"]=experiment_open if accounting["counts"]["experiments"] is not None else None
    for label,field in (("graph_useful_receipts","useful_receipts"),("graph_failed_receipts","failed_receipts")):
        summary[label]=sum(row[field] for row in accounting["graph_navigation"]) if accounting["counts"]["graph_navigation"] is not None and all(row[field] is not None for row in accounting["graph_navigation"]) else None
    summary["graph_limitations"]=sum(len(row["limitations"]) for row in accounting["graph_navigation"]) if accounting["counts"]["graph_navigation"] is not None else None
    for key in accounting["counts"]:accounting[key]=accounting[key][:200]
    accounting=sanitized(accounting)
    prior=final.get("prior_run_reconciliation",[])
    accounting["counts"]["prior_run_reconciliation"]=len(prior)
    accounting["truncated"]["prior_run_reconciliation"]=max(0,len(prior)-200)
    for name,field in (("coverage_cells","cells"),("coverage_tasks","tasks")):
        count=len(coverage[field]) if coverage.get("availability")!="unavailable" else None
        accounting["counts"][name]=count
        accounting["truncated"][name]=max(0,count-200) if count is not None else None
    summary["confirmed_standalone"]=sum(x.get("verdict")=="confirmed" and x.get("finding_kind")!="chain" for x in findings)
    summary["confirmed_chains"]=sum(x.get("verdict")=="confirmed" and x.get("finding_kind")=="chain" for x in findings)
    summary.update({key:accounting["counts"][key] for key in ("established_capabilities","resolved_investigations","unresolved_paths","unscheduled_work","historical_planning_deferrals")})
    intact=all(row["status"] in {"ok","degraded","skipped"} for row in scans.values())
    integrity={"status":"phase_artifacts_complete" if intact else "incomplete","headline":"Recorded upstream checkpoints describe finished work; report publication does not replay historical validation." if intact else "Upstream phase detail is unavailable; recorded lifecycle checkpoints remain completion authority."}
    has_open=any((accounting["unresolved_paths"],accounting["unscheduled_work"],summary["needs_environment"],experiment_open,summary["evidence_limited"])) or any(row["status"]=="unresolved" or row["remaining_obligations"] for row in projection["objective_assessments"])
    has_open=has_open or bool(projection["unreviewed"]) or (gap is not None and any(
        row["outcome"] not in {"contradicted","redundant"} for row in gap["non_promoted"]))
    outcome={"status":"substantially_unresolved" if has_open else "resolved_within_recorded_scope","headline":f"{summary['confirmed_standalone']} assessed confirmed standalone findings and {summary['confirmed_chains']} proven chains; {summary['needs_environment']} environment-required dossiers remain unconfirmed. "+("Unresolved hypotheses have no confirmed severity." if has_open else "Recorded investigations are resolved within their stated scope; zero findings is not a claim of exhaustive safety.")}
    if not summary["resolved_investigations"] and not summary["confirmed"] and not has_open:
        outcome={"status":"substantially_unresolved","headline":"No resolved investigation scope is recorded; zero confirmed findings provides no assurance."}
    if summary["historical_planning_deferrals"]:outcome["headline"]+=f" Separately, {summary['historical_planning_deferrals']} historical planning records were not separately scheduled during planning; this coverage caveat does not establish current investigation failures or later resolution."
    def notes(name):
        rows=optional_document(a.scan_base,"sast/"+name,limitations,context=context,array=True) or []
        return sanitized([{key:row[key] for key in ("title","description","evidence_refs") if key in row} for row in rows])
    report={"schema_version":"2.0","run_id":context["run_id"],"repository":str(context.get("repo_name","unknown")),"commit":repositories[0]["commit"] if len(repositories)==1 else "multiple or unknown assessed revisions","repositories":repositories,"date":now(),"summary":summary,"execution_environment":execution_environment,"findings":rendered,"hardening_notes":notes("hardening-notes.json"),"positive_patterns":notes("positive-patterns.json"),"coverage":sanitized({key:value[:200] if isinstance(value,list) else value for key,value in coverage.items()}),"limitations":limitations,"scans":scans}
    report.update({"integrity":integrity,"assessment":assessment,"outcome_assessment":outcome,"investigation_accounting":accounting,"evidence_quality":sanitized(quality),"prior_run_reconciliation":sanitized(prior[:200])})
    report.update(projection)
    report.update({"model_routing":routing,"verifier_model":verifier,**aggregate})
    from report_bundle import publication_metadata
    report["publication"]=publication_metadata({**context,"repository":report["repository"]},execution_kind="audit")
    report["publication"]["repositories"]=repositories
    report["publication"]["model_routing"]=routing or {}
    if gap is not None:report["gap_exploration"]=gap
    checked(report,size_limit=None)
    validate_publication_schema(report,"report.schema.json")
    markdown_text=checked(render_markdown(report,a.scan_base),size_limit=None)
    import hashlib
    report["publication"]["markdown_sha256"]=hashlib.sha256(markdown_text.encode("utf-8")).hexdigest()
    validate_publication_schema(report,"report.schema.json")
    manifest={"phase":"report","status":"degraded" if summary["needs_environment"] else "ok","started_at":now(),"completed_at":now(),"inputs":["final-verification/findings.json"],"outputs":["report/security-report.json","report/security-report.md"],"coverage":summary,"tool_versions":{"renderer":"deterministic-v2"},"warnings":limitations,"errors":[]}
    write(a.scan_base/"report/phase-manifest.json",json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    write(a.scan_base/"report/security-report.md",markdown_text)
    write(a.scan_base/"report/security-report.json",json.dumps(report,indent=2,sort_keys=True)+"\n")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print(f"[render-report] ERROR: {exc}",file=sys.stderr)
        raise SystemExit(1)
