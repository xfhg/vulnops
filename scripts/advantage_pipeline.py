"""Bounded linked investigation: authored proof in, validated canonical artifacts out.

This module never supplies model conclusions. Builders bind ownership and immutable
inputs; finalizers retain supported evidence and disclose unusable work without blocking peers.
"""
from __future__ import annotations

import argparse
import importlib.util
import copy
import hashlib
import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

import advantage_contract as core
from artifact_policy import DEFAULT_ARTIFACT_LIMIT, publication_content_error
from dossier_contract import DossierAuthoringError, dossier_hash, validate_dossier, validate_dossier_review, _validate_source_example
from evidence_accounting import diagnostic, summarize, validate_non_promoted
from evidence_refs import EvidenceIssue, _parts
from model_routing import split_selector
from objective_contract import stable_id, validate_binding
from run_lifecycle import assessment_ref, report_assessment

OUTPUTS = {"planning": "planning/plan.json", "investigation": "investigation/results.json",
           "synthesis": "synthesis/findings.json", "final-verification": "final-verification/findings.json",
           "report": "report/security-report.json"}
UNRESOLVED = {"locally_unresolved", "externally_blocked", "budget_deferred", "execution_failed", "redundant"}


def gap_inputs(context):
    """Accepted supplementary analytical evidence remains distinct from original work."""
    if context.get("_original_synthesis"):
        return None
    from gap_exploration_contract import load_accepted
    return load_accepted(base_of(context), context=context)


def synthesis_inputs(context):
    investigation = read_local(context, OUTPUTS["investigation"])
    schema(investigation, "investigation", context)
    views = {result_path(packet_value): packet_value["assignment"]["source_view"]
             for packet_value in packets(context).values()}
    results = {row["artifact_ref"]: read_local(context, row["artifact_ref"])
               for row in investigation["results"]}
    gap = gap_inputs(context)
    if gap:
        for row in gap["results"]:
            relative = row["ref"]
            result = read_local(context, relative)
            if relative in results:
                raise ValueError("supplementary result overlaps original ownership")
            results[relative] = result
            views[relative] = result["source_view"]
    return results, views


def synthesis_objectives(context):
    objectives = unique(read_local(context, "planning/plan.json")["objectives"])
    gap = gap_inputs(context)
    for objective in gap["objectives"] if gap else []:
        if objective["id"] in objectives and objectives[objective["id"]] != objective:
            raise ValueError("supplementary objective changed original authority")
        objectives[objective["id"]] = objective
    return objectives


def supplementary_finding(context, finding, link):
    """Neither a label nor a supplementary citation can downgrade original proof."""
    from gap_dossier import supplementary_only
    gap = gap_inputs(context)
    if not gap or link["baseline_ids"]:
        return False
    original = {row["artifact_ref"] for row in read_local(context, OUTPUTS["investigation"])["results"]}
    if set(link["result_refs"]) & original:
        return False
    return supplementary_only(finding, gap["candidates"])


def schema(value, name, context):
    core.validate_schema(value, f"advantage-{name}.schema.json")
    if any(value.get(k) != context[k] for k in ("run_id", "execution_kind")):
        raise ValueError("pipeline artifact belongs to another execution")
    error = publication_content_error(value, size_limit=None if name in {"report", "verification"} else DEFAULT_ARTIFACT_LIMIT)
    if error:
        raise ValueError(error)
    pending = [(value, ())]
    while pending:
        node, location = pending.pop()
        # Example bytes and substitution operands are literals, not prose.
        # Keep their size/hygiene checks and all dossier proof checks intact.
        literal = (
            len(location) >= 3 and location[-3] == "technical_examples"
            and isinstance(location[-2], int) and location[-1] == "content"
        ) or (
            len(location) >= 5 and location[-5] == "technical_examples"
            and isinstance(location[-4], int) and location[-3] == "substitutions"
            and isinstance(location[-2], int) and location[-1] in {"original", "replacement"}
        )
        if isinstance(node, str) and (len(node) > 8000 or node and not literal and not node.strip()):
            raise ValueError("pipeline prose exceeds its bound or is whitespace-only")
        if isinstance(node, list):
            if len(node) > (32768 if name == "source-receipts" else 2048):
                raise ValueError("pipeline collection exceeds its finite publication bound")
            pending.extend((item, (*location, index)) for index, item in enumerate(node))
        elif isinstance(node, dict):
            pending.extend((item, (*location, key)) for key, item in node.items())


def base_of(context):
    return Path(context["scan_base"])


def owned(context, phase):
    core.require_active(context, phase)
    core.check_identity(context)
    context["_source_receipts"] = {}
    context["_source_examples"] = {}


def immutable(context, relative, value):
    path = core.inside(base_of(context), relative)
    if path.exists():
        raise ValueError(f"immutable artifact already exists: {relative}")
    core.atomic_json(path, value)
    return path


def read_local(context, relative):
    return core.load(core.inside(base_of(context), relative))


def unique(rows, key="id"):
    result = {row[key]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError(f"duplicate {key} ownership")
    return result


def worker_input(context, phase, identity):
    if phase == "investigation":
        value = packets(context).get(identity)
        if value is None:
            raise ValueError("worker has no immutable investigation packet")
        actor = "vulnops-advantage-investigator"
        digest = core.sha256_file(base_of(context) / f"investigation/packets/{identity}.json")
        return value, actor, digest, result_path(value)
    assignments = verification_assignments(context)
    if read_local(context, "final-verification/assignments.json") != assignments:
        raise ValueError("verification assignments changed")
    value = unique(assignments["assignments"], "finding_id").get(identity)
    if value is None:
        raise ValueError("worker has no independent verification assignment")
    if read_local(context, f"final-verification/packets/{identity}.json") != value:
        raise ValueError("native verification input differs from its immutable assignment")
    return value, value["actor"], core.digest(value), value["result_ref"]


def verification_cohorts(context):
    synthesis = read_local(context, OUTPUTS["synthesis"])
    links = unique(synthesis["links"], "finding_id")
    return {finding["id"]: ("supplementary" if supplementary_finding(context, finding, links[finding["id"]]) else "original")
            for finding in synthesis["findings"]}


def review_budget(context, identity):
    if verification_cohorts(context)[identity] == "supplementary":
        return context["gap_exploration_budget"]
    return context["budget"]





def native_input_sha256(context, phase, identity):
    return core.sha256_file(base_of(context) / f"{phase}/packets/{identity}.json")


def native_workers(context, phase):
    """Execution facts come only from this invocation's native task runtime."""
    actor = {"investigation": "vulnops-advantage-investigator",
             "final-verification": "vulnops-advantage-verify-one"}[phase]
    return [row for row in core.live_call(context)["workers"]
            if row["phase"] == phase and row["actor"] == actor]


def worker_outcomes(context, phase, identity, input_sha256):
    rows = [row for row in native_workers(context, phase) if row["id"] == identity]
    actor = "vulnops-advantage-investigator" if phase == "investigation" else "vulnops-advantage-verify-one"
    if rows and worker_input(context, phase, identity)[2] != input_sha256:
        raise ValueError("native worker differs from requested immutable input")
    native_digest = native_input_sha256(context, phase, identity) if rows else None
    if any(row["actor"] != actor or row["selector"] != context["model_routing"]["agents"][actor]
           or row.get("input_sha256") != native_digest for row in rows):
        raise ValueError("native worker changed immutable input or model ownership")
    rows.sort(key=lambda row: row["attempt"])
    return rows


def native_draft(context, row):
    """Load exactly one immutable publication delivered by the terminal task."""
    drafts = []
    for relative in row["artifacts"]:
        path = core.inside(base_of(context), relative)
        expected = row.get("artifact_sha256", {}).get(relative)
        if not expected or core.sha256_file(path) != expected:
            raise ValueError("native yielded publication changed or lacks byte binding")
        if path.suffix != ".json":
            continue
        value = core.load(path)
        identity = value.get("task_id", value.get("finding_id")) if isinstance(value, dict) else None
        if identity == row["id"]:
            drafts.append(value)
    if len(drafts) != 1:
        raise ValueError("native terminal yield lacks one exact worker publication")
    return drafts[0]


def project_worker_result(context, phase, value, draft):
    if phase == "investigation":
        result = admitted_result(context, value, draft)
    else:
        synthesis = read_local(context, OUTPUTS["synthesis"])
        result = copy.deepcopy(draft)
        identity = result["finding_id"]
        validate_review(context, unique(synthesis["findings"])[identity],
                        unique(synthesis["links"], "finding_id")[identity], value, result)
        result.update(evidence_quality=summarize([]), non_promoted=result.get("non_promoted", []))
    if assessment_ref(context):
        result["assessment_context"] = assessment_ref(context)
    return result


def terminal_worker(context, phase, identity, input_sha256, attempt):
    rows = worker_outcomes(context, phase, identity, input_sha256)
    matching = [row for row in rows if row["attempt"] == attempt]
    if (len(matching) != 1
            or any(row["status"] == "running" for row in rows)
            or attempt != max((row["attempt"] for row in rows), default=0)):
        raise ValueError("canonical result lacks exact terminal native worker admission")
    return matching[0]


def admit_worker_result(context, phase, result):
    owned(context, phase)
    identity = result.get("task_id" if phase == "investigation" else "finding_id") if isinstance(result, dict) else None
    if not isinstance(identity, str) or type(result.get("attempt")) is not int:
        raise ValueError("worker publication lacks authoritative identity or attempt")
    core.component(identity)
    value, _, digest, relative = worker_input(context, phase, identity)
    row = terminal_worker(context, phase, identity, digest, result["attempt"])
    if native_draft(context, row) != result:
        raise ValueError("publication differs from the native terminal yield")
    if phase == "final-verification" and verification_cohorts(context)[identity] == "supplementary":
        from gap_dossier import require_cohort
        require_cohort(context, phase, "supplementary")
    result = project_worker_result(context, phase, value, result)
    immutable(context, relative, result)
    return {"status": "completed", "result_ref": relative,
            "result_sha256": core.sha256_file(base_of(context) / relative)}








def validate_admission(context, phase, identity, result, relative, input_sha256):
    value, _, digest, canonical = worker_input(context, phase, identity)
    if digest != input_sha256 or canonical != relative:
        raise ValueError("canonical result changed immutable worker input")
    row = terminal_worker(context, phase, identity, digest, result["attempt"])
    expected = project_worker_result(context, phase, value, native_draft(context, row))
    if expected != result:
        raise ValueError("canonical result differs from validated native worker publication")


def provenance(context, row, actor, artifact_ref):
    route = context["model_routing"]
    expected = {"execution_id": context["run_id"], "actor": actor,
                "selector": route["agents"][actor], "artifact_ref": artifact_ref}
    if row != expected:
        raise ValueError("wrong actor, route, execution or canonical artifact provenance")


def baseline_findings(context):
    from advantage_baseline import accepted_findings
    return accepted_findings(Path(context["baseline"]["root"]),
                             expected_execution_id=context["baseline"]["execution_id"])




def record_source_receipts(context, phase, *, filename="source-receipts.json"):
    value = core.envelope(context,
        sources=sorted(context.get("_source_receipts", {}).values(), key=lambda r: (r["source_view"], r["reference"])),
        source_examples=sorted(context.get("_source_examples", {}).values(), key=lambda r: (r["source_view"], r["example_sha256"])))
    schema(value, "source-receipts", context)
    immutable(context, f"{phase}/{filename}", value)


def validate_source_example(context, scan, target, repositories, example):
    view = context.get("_source_view", "base")
    key = (view, core.digest(example))
    if context.get("source_root"):
        _validate_source_example(scan, target, repositories, example, evidence_validator=evidence_adapter(context))
        context.setdefault("_source_examples", {})[key] = {"source_view": view, "example_sha256": key[1]}
    else:
        refs(context, example.get("evidence_refs", []))


def resolve_support(context, value, kind):
    try:
        return core.resolve_reference(context, value, kind=kind)
    except EvidenceIssue as exc:
        declaration = context.get("_optional_support", {}).get(value) if isinstance(value, str) else None
        if (kind == "source" or not declaration or not declaration["obligation"].strip()
                or not declaration["rationale"].strip() or value in declaration["independent_support"]):
            raise
        independent = {key: item for key, item in context.items() if key != "_optional_support"}
        refs(independent, declaration["independent_support"], source=True)
        if "_quality_issues" in context:
            context["_quality_issues"].append(diagnostic(exc.code, context["_quality_owner"],
                "optional_support", [context["_quality_item"]], "optional"))
        return None


def refs(context, values, *, source=False, kind="mixed"):
    artifacts = []
    for value in values:
        is_artifact = isinstance(value, dict) or kind == "artifact" or (
            isinstance(value, str) and _parts(value)[0].split("/", 1)[0] in core.PHASES)
        if is_artifact:
            resolved = resolve_support(context, value, kind)
            if resolved is not None:
                artifacts.append(value)
        else:
            view = context.get("_source_view", "base")
            key = (view, value)
            if not context.get("source_root"):
                # Historical source coordinates are provenance, not current proof.
                from advantage_actions import safe_relative
                safe_relative(_parts(value)[0])
                continue
            resolved = resolve_support(context, value, kind)
            if resolved is None:
                continue
            with resolved.open(encoding="utf-8", errors="replace") as handle:
                line_count = sum(1 for _ in handle)
            context.setdefault("_source_receipts", {})[key] = {
                "source_view": view, "reference": value,
                "line_count": line_count}
    if source and (not values or len(artifacts) == len(values)):
        raise EvidenceIssue("missing_record", "proof requires resolved source anchors, not inherited prose")
    return artifacts


def evidence_adapter(context):
    def validate(scan, target, repositories, values, *, owner, kind="mixed", **kwargs):
        try:
            return refs(context, values, kind=kind)
        except EvidenceIssue as exc:
            exc.field = owner
            raise
    return validate


def local_references(context, values, *, owner, field, item_id, source=False, kind="mixed", optional=()):
    """Resolve each reference without treating a surviving citation as sufficiency."""
    valid, issues = [], []
    declarations = {row["reference"]: row for row in optional}
    if len(declarations) != len(optional):
        return [], [diagnostic("ambiguous_record", owner, field + ".optional_support", [item_id])]
    for ref in values:
        try:
            refs(context, [ref], kind=kind)
            valid.append(ref)
        except EvidenceIssue as exc:
            declaration = declarations.get(ref) if isinstance(ref, str) else None
            if declaration:
                if (ref in declaration["independent_support"] or not declaration["obligation"].strip()
                        or not declaration["rationale"].strip()):
                    issues.append(diagnostic("missing_record", owner, field, [item_id]))
                    continue
                try:
                    refs(context, declaration["independent_support"], source=True)
                except EvidenceIssue as support_error:
                    issues.append(diagnostic(support_error.code, owner, field, [item_id]))
                    continue
                # Only the analyst's explicit inspected support is eligible. Never
                # infer equivalent neighboring coordinates or clip the bad range.
                for support in declaration["independent_support"]:
                    if support not in valid:
                        valid.append(support)
                issues.append(diagnostic(exc.code, owner, field, [item_id], "optional"))
            else:
                issues.append(diagnostic(exc.code, owner, field, [item_id]))
    if source:
        try:
            refs(context, valid, source=True, kind=kind)
        except EvidenceIssue as exc:
            issues.append(diagnostic(exc.code, owner, field, [item_id]))
    return valid, issues


def excluded_item(owner, field, issues, *, missing_fact=None):
    """Parser accounting is not an analyst review or a substantive rejection."""
    location = owner + "#/" + field.replace("[", "/").replace("]", "")
    return {"id": location, "input_refs": [location], "disposition": "evidence_limited",
        "reason": "Item withheld because its structure or necessary evidence is unusable.",
        "risk_context": "The owning publication retains the attack question; no security conclusion is inferred.",
        "missing_fact": missing_fact or "Establish the affected claim with attributable inspected evidence.",
        "next_action": "Prioritize the missing security fact against other actionable attack questions.",
        "review": None, "deferral": None, "diagnostics": issues}


def item_errors(name, field, item):
    document = core.load(core.ROOT / "schemas/v2" / f"advantage-{name}.schema.json")
    return core._validator(document, core.ROOT / "schemas/v2").collect(item, document["properties"][field]["items"])


def authored_accounting(context, rows, actor):
    for row in rows:
        validate_non_promoted(row, context["model_routing"], base_of(context),
            Path(context.get("source_root") or "."), context["repositories"], actor=actor)


def unresolved_resolution(question, outcome="locally_unresolved"):
    return {"outcome": outcome, "reason": "No usable proof establishes the assigned obligation.",
        "established_facts": [], "counterevidence": [], "evidence_refs": [],
        "missing_fact": question["proof_obligation"],
        "next_action": "Prioritize this missing security fact within remaining authorized allocation."}


def authored_closure(rows, owner, field, identity):
    location = owner + "#/" + field.replace("[", "/").replace("]", "")
    references = {location}
    if isinstance(identity, str):
        references.update({owner + ":" + identity, owner + "#" + identity})
    matches = [row for row in rows if references.intersection(row["input_refs"])]
    if len(matches) > 1:
        raise ValueError("conflicting authored dispositions for one owned item")
    return matches[0] if matches else None


def admitted_result(context, packet_value, draft):
    """Assess a newly authored publication; historical accepted bytes never pass here."""
    value = copy.deepcopy(draft)
    if not context.get("source_root"):
        raise ValueError("new investigation requires an authorized current source tree")
    task, owner = packet_value["assignment"], result_path(packet_value)
    questions = unique(packet_value["questions"])
    # Strict controls first; only the two analyst item arrays are assessed separately.
    envelope = {**value, "candidates": [], "question_outcomes": [
        {"question_id": qid, "objective_id": questions[qid]["objective_id"],
         "resolution": unresolved_resolution(questions[qid])} for qid in task["question_ids"]]}
    schema(envelope, "result", context)
    provenance(context, value["provenance"], "vulnops-advantage-investigator", owner)
    if (value["task_id"] != task["task_id"] or value["pass_id"] != task["pass_id"] or
            value["packet_sha256"] != core.sha256_file(base_of(context) / f"investigation/packets/{task['task_id']}.json")):
        raise ValueError("result changed task/pass or packet ownership")
    for key, maximum in (("candidates", 512), ("question_outcomes", 64)):
        if not isinstance(value.get(key), list) or len(value[key]) > maximum:
            raise ValueError("publication lacks bounded item arrays")
    # Sanitization and source authorization also cover excluded malformed items.
    if publication_content_error(value):
        raise ValueError("publication contains unsafe content")
    predecessor = packet_value["continuation"]["predecessor_task_id"] if packet_value["continuation"] else None
    view = source_context(context, task["source_view"])
    check_source_paths(view, value)
    for ref in walk_refs(value):
        if isinstance(ref, str) and ref.startswith("investigation/passes/") and ref.split("/results/")[-1].split(".json")[0] != predecessor:
            raise ValueError("fresh passes cannot consume peer results before consolidation")
        if reference_shape(ref):
            try:
                refs(view, [ref])
            except EvidenceIssue:
                pass
    authored_accounting(context, value.get("non_promoted", []), "vulnops-advantage-investigator")
    non_promoted, issues, candidates, outcomes = list(value.get("non_promoted", [])), [], [], {}
    identities = [row.get("id") for row in value["candidates"] if isinstance(row, dict) and isinstance(row.get("id"), str)]
    baseline = baseline_findings(context)
    for index, row in enumerate(value["candidates"]):
        field = f"candidates[{index}]"
        malformed = item_errors("result", "candidates", row)
        duplicate = isinstance(row, dict) and isinstance(row.get("id"), str) and identities.count(row["id"]) > 1
        item_issues = []
        if malformed or duplicate:
            item_issues.append(diagnostic("ambiguous_record" if duplicate else "unreadable_content", owner, field, [field]))
        else:
            row["evidence_refs"], found = local_references(view, row["evidence_refs"], owner=owner,
                field=field + ".evidence_refs", item_id=row["id"], source=True, optional=row.get("optional_support", []))
            item_issues.extend(found)
            _, found = local_references(view, [f"{loc['file']}:{loc['line']}" for loc in row["source_locations"]],
                owner=owner, field=field + ".source_locations", item_id=row["id"], kind="source")
            item_issues.extend(found)
            if not set(row["baseline_ids"]) <= baseline.keys():
                item_issues.append(diagnostic("missing_record", owner, field + ".baseline_ids", [row["id"]]))
        issues.extend(item_issues)
        if any(issue["disposition"] != "optional" for issue in item_issues):
            fact = row.get("terminal_impact") if isinstance(row, dict) else None
            non_promoted.append(excluded_item(owner, field, item_issues,
                missing_fact="Establish inspected source proof for: " + fact[:3900] if isinstance(fact, str) else None))
        elif not authored_closure(value.get("non_promoted", []), owner, field, row["id"]):
            candidates.append(row)
    counts = {}
    for row in value["question_outcomes"]:
        if isinstance(row, dict) and isinstance(row.get("question_id"), str):
            counts[row["question_id"]] = counts.get(row["question_id"], 0) + 1
    for index, row in enumerate(value["question_outcomes"]):
        field = f"question_outcomes[{index}]"
        qid = row.get("question_id") if isinstance(row, dict) else None
        known = isinstance(qid, str) and qid in questions
        if known and "objective_id" in row and row["objective_id"] != questions[qid]["objective_id"]:
            raise ValueError("result changed objective/question ownership")
        malformed = item_errors("result", "question_outcomes", row)
        if malformed or not known or counts.get(qid, 0) != 1:
            found = [diagnostic("unreadable_content", owner, field, [field])]
        else:
            resolution = row["resolution"]
            resolution["evidence_refs"], found = local_references(view, resolution["evidence_refs"], owner=owner,
                field=field + ".evidence_refs", item_id=qid, source=resolution["outcome"] == "established")
            resolution["counterevidence"], counter = local_references(view, resolution["counterevidence"],
                owner=owner, field=field + ".counterevidence", item_id=qid)
            found.extend(counter)
            if resolution["outcome"] in UNRESOLVED and (not resolution["missing_fact"].strip() or not resolution["next_action"].strip()):
                found.append(diagnostic("missing_record", owner, field, [qid]))
        issues.extend(found)
        if found:
            non_promoted.append(excluded_item(owner, field, found))
        elif known:
            closure = authored_closure(value.get("non_promoted", []), owner, field, qid)
            if closure:
                status = "externally_blocked" if (closure.get("deferral") or {}).get("kind") == "external" else "locally_unresolved"
                row["resolution"] = unresolved_resolution(questions[qid], status)
                row["resolution"].update(reason=closure["reason"],
                    missing_fact=closure["missing_fact"] or questions[qid]["proof_obligation"],
                    next_action=closure["next_action"] or "Retain the attributed source review and prioritize the remaining question.")
            outcomes[qid] = row
    for qid in task["question_ids"]:
        if qid not in outcomes:
            if qid not in counts:
                found = [diagnostic("missing_record", owner, "question_outcomes", [qid])]
                issues.extend(found)
                non_promoted.append(excluded_item(owner, f"question_outcomes/{qid}", found,
                                                  missing_fact=questions[qid]["proof_obligation"]))
            outcomes[qid] = {"question_id": qid, "objective_id": questions[qid]["objective_id"],
                             "resolution": unresolved_resolution(questions[qid])}
    value["additional_baseline_refs"], found = local_references(context, value["additional_baseline_refs"],
        owner=owner, field="additional_baseline_refs", item_id=task["task_id"])
    issues.extend(found)
    receipts = []
    for receipt in value.get("graph_receipt_refs", []):
        if core.inside(base_of(context), _parts(receipt)[0]).is_file():
            receipts.append(receipt)
        else:
            issues.append(diagnostic("missing_file", owner, "graph_receipt_refs", [task["task_id"]]))
    if len(receipts) != len(value.get("graph_receipt_refs", [])):
        value["graph_receipt_refs"] = receipts
        value["graph_limitations"] = [*value.get("graph_limitations", []),
            "Graph receipt unavailable; no graph observation was admitted."]
    value.update(candidates=candidates, question_outcomes=list(outcomes.values()),
                 non_promoted=non_promoted, evidence_quality=summarize(issues))
    validate_result(context, packet_value, value)
    return value


def source_context(context, view):
    if view == "base":
        return context
    binding = context.get("patch_binding")
    if not binding:
        raise ValueError("derived source requires an admitted immutable patch")
    context.setdefault("_source_receipts", {})
    context.setdefault("_source_examples", {})
    if not context.get("source_root"):
        return {**context, "_source_view": "derived"}
    from advantage_actions import source_view_context
    return {**source_view_context(context, "derived"), "_source_view": "derived",
            "_source_receipts": context["_source_receipts"], "_source_examples": context["_source_examples"]}


def validate_plan(context, plan, *, allocating=False):
    schema(plan, "plan", context)
    provenance(context, plan["provenance"], "vulnops-advantage-planning", "planning/plan.json")
    if context["mode"] == "actions":
        if plan["status"] != "skipped" or any(plan[k] for k in ("objectives", "questions", "passes", "assignments")):
            raise ValueError("actions mode cannot plan investigation")
        return
    if plan["status"] == "skipped":
        raise ValueError("investigation mode cannot skip planning")
    objectives, questions = unique(plan["objectives"]), unique(plan["questions"])
    for rows, prefix in ((objectives, "OBJ-"), (questions, "Q-")):
        for row in rows.values():
            if row["id"] != stable_id(prefix, "planning/plan.json", row["local_key"]):
                raise ValueError("objective/question identity is not owner-stable")
            _, found = local_references(context, row["evidence_refs"], owner="planning/plan.json",
                field="evidence_refs", item_id=row["id"])
            context.setdefault("_planning_issues", []).extend(found)
    for objective in objectives.values():
        if objective["parent"] is not None:
            try:
                parent = core.resolve_reference(context, objective["parent"])
            except EvidenceIssue as exc:
                context.setdefault("_planning_issues", []).append(diagnostic(exc.code,
                    "planning/plan.json", "parent", [objective["id"]]))
                continue
            required = {"id", "owner", "local_key", "starting_actor", "controlled_material",
                        "resource_scope", "desired_effect", "success_condition"}
            if (not isinstance(parent, dict) or not required <= parent.keys() or
                    parent["id"] != stable_id("OBJ-", parent["owner"], parent["local_key"])):
                raise ValueError("inherited objective link must resolve an original stable objective definition")
    obligations = set()
    for question in questions.values():
        validate_binding({"objective_id": question["objective_id"], "question_id": question["id"]}, objectives, questions)
        obligation = (question["objective_id"], question["route"].strip().casefold(), question["proof_obligation"].strip().casefold())
        if obligation in obligations and question["disposition"] == "admitted":
            raise ValueError("duplicate route/proof obligation")
        obligations.add(obligation)
        for field in ("counterevidence", "baseline_records", "evidence_delta"):
            _, found = local_references(context, question[field], owner="planning/plan.json", field=field, item_id=question["id"])
            context.setdefault("_planning_issues", []).extend(found)
        if question["prior_disposition"] == "rejected" and question["disposition"] == "admitted":
            if (not question["changed_hypothesis"].strip() and not question["evidence_delta"]) or not question["counterevidence"]:
                raise ValueError("unchanged rejected route cannot acquire an assignment")
        for ref in question["baseline_records"]:
            try:
                record = core.resolve_reference(context, ref)
            except EvidenceIssue:
                continue
            prior = record.get("status", record.get("outcome", record.get("verdict"))) if isinstance(record, dict) else None
            if prior in {"rejected", "contradicted"} and question["prior_disposition"] != "rejected":
                raise ValueError("prior rejection must remain explicit")
    passes = unique(plan["passes"])
    expected = context["budget"]["deep_passes"] if context["mode"] == "deep" else 1
    if allocating and plan["assignments"] and len(passes) != expected:
        raise ValueError("incorrect independently owned pass allocation")
    if {task["pass_id"] for task in plan["assignments"]} != set(passes):
        raise ValueError("every fresh pass must receive an explicit bounded assignment")
    if not plan["assignments"] and (passes or plan["status"] != "empty"):
        raise ValueError("empty plan needs explicit empty closure")
    tasks = unique(plan["assignments"], "task_id")
    if allocating and (len(tasks) > context["budget"]["max_tasks"] or sum(len(t["question_ids"]) for t in tasks.values()) > context["budget"]["max_questions"]):
        raise ValueError("global initial task/question allocation exhausted")
    seen, assigned = set(), set()
    priorities = [task["priority"] for task in tasks.values()]
    if priorities != sorted(priorities, reverse=True):
        raise ValueError("initial allocation must be risk-priority ordered")
    for task in tasks.values():
        if task["pass_id"] not in passes:
            raise ValueError("task has no independently initialized pass")
        validate_assignment(context, task, questions)
        for qid in task["question_ids"]:
            owner = (task["pass_id"], qid)
            if owner in seen or questions[qid]["disposition"] != "admitted":
                raise ValueError("duplicate or non-admitted question ownership")
            seen.add(owner)
            assigned.add(qid)
    if assigned != {q["id"] for q in questions.values() if q["disposition"] == "admitted"}:
        raise ValueError("admitted questions require exact terminal ownership")


def validate_assignment(context, task, questions):
    if len(task["question_ids"]) != len(set(task["question_ids"])) or not set(task["question_ids"]) <= questions.keys():
        raise ValueError("assignment references duplicate or unknown questions")
    view = source_context(context, task["source_view"])
    for capability in task["available_capabilities"]:
        if capability["status"] == "conditional":
            valid, found = local_references(view, capability["evidence_refs"], owner="planning/plan.json",
                field="available_capabilities", item_id=task["task_id"])
            context.setdefault("_planning_issues", []).extend(found)
            artifacts = refs(view, valid)
        else:
            artifacts = refs(view, capability["evidence_refs"], source=capability["status"] == "source_established")
        if capability["status"] == "conditional" and not capability["conditions"]:
            raise ValueError("conditional capability must preserve missing conditions")
        for ref in artifacts:
            if isinstance(ref, dict) and ref["execution_id"] != context["run_id"] and capability["status"] != "conditional":
                raise ValueError("historical evidence cannot grant a current capability without fresh investigation and independent review")
            value = core.resolve_reference(view, ref)
            if isinstance(value, dict) and value.get("status", value.get("outcome")) in {"deferred", "budget_deferred", "needs_environment", "rejected", "locally_unresolved", "externally_blocked"} and capability["status"] != "conditional":
                raise ValueError("unresolved baseline knowledge does not grant capability")
        if capability["status"] == "observed_contained":
            for ref in capability["evidence_refs"]:
                observation(context, None, ref, {"source_refs": []})


def packet(context, plan, task, wave=0, continuation=None):
    questions = [q for q in plan["questions"] if q["id"] in task["question_ids"]]
    ids = {q["objective_id"] for q in questions}
    return core.envelope(context, assignment=task, wave=wave,
        baseline_catalog="baseline/catalog.json",
        objectives=[o for o in plan["objectives"] if o["id"] in ids], questions=questions,
        continuation=continuation, permissions={"target_read_only": True, "peer_results": "forbidden",
            "reproduction_mode": context["reproduction_mode"], "network": context["network"]})


def conditional_capabilities(context, assignments, owner):
    """Missing planning support cannot grant a capability or prevent new research."""
    issues = []
    for task in assignments:
        view = source_context(context, task["source_view"])
        for index, capability in enumerate(task["available_capabilities"]):
            if capability["status"] == "conditional":
                continue
            _, found = local_references(view, capability["evidence_refs"], owner=owner,
                field=f"{task['task_id']}.available_capabilities[{index}]", item_id=task["task_id"],
                source=capability["status"] == "source_established")
            if found:
                capability["status"] = "conditional"
                capability["conditions"] = [*capability["conditions"],
                    "Establish the missing capability with current inspected evidence before using it as a prerequisite."]
                issues.extend(found)
    return issues



def build_plan(context, draft):
    owned(context, "planning")
    draft = copy.deepcopy(draft)
    schema(draft, "plan", context)
    context["_planning_issues"] = conditional_capabilities(context, draft["assignments"], "planning/plan.json")
    validate_plan(context, draft, allocating=True)
    draft["evidence_quality"] = summarize(context["_planning_issues"])
    # Packets are deterministic projections; no investigation conclusion is supplied.
    packets = [(t["task_id"], packet(context, draft, t)) for t in draft["assignments"]]
    for _, value in packets:
        schema(value, "packet", context)
    immutable(context, "planning/plan.json", draft)
    for tid, value in packets:
        immutable(context, f"investigation/packets/{tid}.json", value)
    record_source_receipts(context, "planning")
    return core.finalize_phase(base_of(context), "planning", status="skipped" if context["mode"] == "actions" else "ok", context=context)











def packets(context):
    plan = read_local(context, "planning/plan.json")
    expected = {t["task_id"]: packet(context, plan, t) for t in plan["assignments"]}
    previous = 0
    for path in sorted((base_of(context) / "investigation/waves").glob("*.json")):
        wave = core.load(path)
        schema(wave, "wave", context)
        if wave["wave"] != previous + 1 or path.name != f"{wave['wave']:03}.json":
            raise ValueError("noncontiguous continuation wave ownership")
        # Retained waves keep their consumed allocation and local ownership.
        if wave["run_id"] != context["run_id"]:
            raise ValueError("continuation wave belongs to another execution")
        previous = wave["wave"]
        for item in wave["tasks"]:
            task = item["assignment"]
            expected[task["task_id"]] = packet(context, plan, task, wave["wave"], item["continuation"])
    actual = {p.stem for p in (base_of(context) / "investigation/packets").glob("*.json")}
    if actual != set(expected):
        raise ValueError("missing or orphan investigation packets")
    for tid, value in expected.items():
        stored = read_local(context, f"investigation/packets/{tid}.json")
        schema(stored, "packet", context)
        for field in ("assignment", "wave", "objectives", "questions", "continuation", "baseline_catalog"):
            if stored[field] != value[field]:
                raise ValueError("packet differs from owned plan/wave projection")
        expected[tid] = stored
    return expected


def result_path(packet_value):
    task = packet_value["assignment"]
    return f"investigation/passes/{task['pass_id']}/results/{task['task_id']}.json"


def validate_result(context, packet_value, result):
    schema(result, "result", context)
    task = packet_value["assignment"]
    relative = result_path(packet_value)
    provenance(context, result["provenance"], "vulnops-advantage-investigator", relative)
    if result["task_id"] != task["task_id"] or result["pass_id"] != task["pass_id"]:
        raise ValueError("result belongs to another task/pass")
    if result["packet_sha256"] != core.sha256_file(base_of(context) / f"investigation/packets/{task['task_id']}.json"):
        raise ValueError("result consumed a changed packet")
    outcomes = unique(result["question_outcomes"], "question_id")
    if set(outcomes) != set(task["question_ids"]):
        raise ValueError("every assigned question requires exactly one terminal disposition")
    questions = unique(packet_value["questions"])
    view = source_context(context, task["source_view"])
    permitted_predecessor = packet_value["continuation"]["predecessor_task_id"] if packet_value["continuation"] else None
    for value in walk_refs(result):
        if isinstance(value, str) and value.startswith("investigation/passes/"):
            if value.split("/results/")[-1].split(".json")[0] != permitted_predecessor:
                raise ValueError("fresh passes cannot consume peer results before consolidation")
    for qid, outcome in outcomes.items():
        if outcome["objective_id"] != questions[qid]["objective_id"]:
            raise ValueError("result changed objective/question ownership")
        resolution = outcome["resolution"]
        refs(view, resolution["evidence_refs"], source=resolution["outcome"] == "established")
        refs(view, resolution["counterevidence"])
        if resolution["outcome"] in UNRESOLVED and (not resolution["missing_fact"].strip() or not resolution["next_action"].strip()):
            raise ValueError("unresolved question must preserve missing fact and next action")
    unique(result["candidates"])
    for candidate in result["candidates"]:
        refs(view, candidate["evidence_refs"], source=True)
        for location in candidate["source_locations"]:
            refs(view, [f"{location['file']}:{location['line']}"], kind="source")
        if not set(candidate["baseline_ids"]) <= baseline_findings(context).keys():
            raise ValueError("candidate claims unknown inherited primitive")
    refs(context, result["additional_baseline_refs"])
    receipts = result.get("graph_receipt_refs", [])
    if task.get("graph_questions") and not receipts and not result.get("graph_limitations"):
        raise ValueError("unused or unavailable graph questions require an explicit source-only limitation")
    for receipt in receipts:
        from codegraph_contract import validate_linked_receipt
        validate_linked_receipt(context, receipt)


def reference_shape(value):
    return isinstance(value, str) or (isinstance(value, dict)
        and isinstance(value.get("execution_id"), str) and isinstance(value.get("artifact_ref"), str))


def walk_refs(value):
    if isinstance(value, dict):
        if {"execution_id", "artifact_ref"} <= value.keys():
            yield value
            return
        for key, child in value.items():
            if key in {"provenance", "contributors"}:
                continue
            if key in {"evidence_refs", "counterevidence", "additional_baseline_refs", "observation_refs", "source_validation_refs"}:
                if isinstance(child, list):
                    yield from child
            elif key == "artifact_ref":
                yield child
            else:
                yield from walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_refs(child)


def check_source_paths(context, value):
    """Apply source authorization even to source locations in malformed items."""
    if isinstance(value, dict):
        if isinstance(value.get("file"), str):
            try:
                refs(context, [value["file"]], kind="source")
            except EvidenceIssue:
                pass
        for key, child in value.items():
            if key not in {"provenance", "contributors"}:
                check_source_paths(context, child)
    elif isinstance(value, list):
        for child in value:
            check_source_paths(context, child)


def validate_wave(context, wave, previous_packets):
    budget = context["budget"]
    if wave["wave"] > budget["max_continuation_rounds"]:
        raise ValueError("continuation round allocation exhausted")
    initial = len(read_local(context, "planning/plan.json")["assignments"])
    if len(previous_packets) - initial + len(wave["tasks"]) > budget["max_continuation_tasks"]:
        raise ValueError("continuation task/question allocation exhausted")
    seen, signatures = set(previous_packets), set()
    wave_owners = set()
    for prior in previous_packets.values():
        if prior["continuation"]:
            c = prior["continuation"]
            signatures.add((prior["assignment"]["pass_id"], tuple(prior["assignment"]["question_ids"]),
                            c["changed_hypothesis"].strip().casefold(), c["next_proof_obligation"].strip().casefold()))
    questions = unique(read_local(context, "planning/plan.json")["questions"])
    for item in wave["tasks"]:
        task, c = item["assignment"], item["continuation"]
        if task["task_id"] in seen or len(task["question_ids"]) != 1:
            raise ValueError("continuation must allocate exactly one new task/question slot")
        seen.add(task["task_id"])
        owner = (task["pass_id"], task["question_ids"][0])
        if owner in wave_owners:
            raise ValueError("duplicate continuation question ownership within a wave")
        wave_owners.add(owner)
        prior = previous_packets.get(c["predecessor_task_id"])
        if prior is None or prior["wave"] >= wave["wave"] or task["pass_id"] != prior["assignment"]["pass_id"]:
            raise ValueError("continuation requires a prior same-pass owner")
        if not set(task["question_ids"]) <= set(prior["assignment"]["question_ids"]):
            raise ValueError("continuation cannot change inherited question ownership")
        if any(p["assignment"]["pass_id"] == task["pass_id"] and
               task["question_ids"][0] in p["assignment"]["question_ids"] and p["wave"] > prior["wave"]
               for p in previous_packets.values()):
            raise ValueError("continuation must consume the latest validated question outcome")
        path = result_path(prior)
        result = read_local(context, path)
        validate_admission(context, "investigation", result["task_id"], result, path, result["packet_sha256"])
        if core.sha256_file(base_of(context) / path) != c["predecessor_sha256"]:
            raise ValueError("continuation predecessor hash changed")
        if any(o["resolution"]["outcome"] == "externally_blocked" for o in result["question_outcomes"] if o["question_id"] in task["question_ids"]):
            raise ValueError("external blockers cannot trigger blind local retries")
        existing = {core.digest(r) for r in [*walk_refs(result), *walk_refs(prior)]}
        valid, found = local_references(source_context(context, task["source_view"]), c["evidence_delta"],
            owner=f"investigation/waves/{wave['wave']:03}.json", field="evidence_delta", item_id=task["task_id"])
        context.setdefault("_wave_issues", []).extend(found)
        novel = [r for r in valid if core.digest(r) not in existing]
        question = questions[task["question_ids"][0]]
        hypothesis = c["changed_hypothesis"].strip().casefold()
        obligation = c["next_proof_obligation"].strip().casefold()
        prior_hypothesis = prior["continuation"]["changed_hypothesis"] if prior["continuation"] else question["security_question"]
        prior_obligation = prior["continuation"]["next_proof_obligation"] if prior["continuation"] else question["proof_obligation"]
        if not novel and not c["alternative_path"].strip():
            raise ValueError("continuation has no evidence delta or actionable alternative")
        if hypothesis == prior_hypothesis.strip().casefold() or obligation == prior_obligation.strip().casefold():
            raise ValueError("unchanged hypothesis or proof obligation is not continuation progress")
        if not novel and c["alternative_path"].strip().casefold() in {
                question["route"].strip().casefold(), (prior["continuation"] or {}).get("alternative_path", "").strip().casefold()}:
            raise ValueError("renamed task does not establish an alternative route")
        signature = (task["pass_id"], tuple(task["question_ids"]), hypothesis, obligation)
        if signature in signatures:
            raise ValueError("duplicate continuation")
        signatures.add(signature)
        validate_assignment(context, task, questions)


def build_wave(context, draft):
    owned(context, "investigation")
    draft = copy.deepcopy(draft)
    context["_wave_issues"] = []
    schema(draft, "wave", context)
    context["_wave_issues"].extend(conditional_capabilities(context,
        [item["assignment"] for item in draft["tasks"]], f"investigation/waves/{draft['wave']:03}.json"))
    previous = packets(context)
    expected = max((p["wave"] for p in previous.values()), default=0) + 1
    if draft["wave"] != expected:
        raise ValueError("continuation must append exactly the next immutable wave")
    validate_wave(context, draft, previous)
    draft["evidence_quality"] = summarize(context["_wave_issues"])
    plan = read_local(context, "planning/plan.json")
    values = [(i["assignment"]["task_id"], packet(context, plan, i["assignment"], draft["wave"], i["continuation"])) for i in draft["tasks"]]
    for _, value in values:
        schema(value, "packet", context)
    immutable(context, f"investigation/waves/{draft['wave']:03}.json", draft)
    for tid, value in values:
        immutable(context, f"investigation/packets/{tid}.json", value)
    return draft







def unsuccessful_outcome(workers, identity):
    latest = max((row for row in workers if row["id"] == identity),
                 key=lambda row: row["attempt"], default=None)
    return "execution_failed" if latest and latest["status"] in {"failed", "cancelled"} else "locally_unresolved"


def investigation_projection(context):
    plan = read_local(context, "planning/plan.json")
    all_packets = packets(context)
    rows, outcomes, documents = [], [], [plan]
    workers = native_workers(context, "investigation")
    for tid, value in all_packets.items():
        relative = result_path(value)
        try:
            result = read_local(context, relative)
            schema(result, "result", context)
            validate_admission(context, "investigation", tid, result, relative, result["packet_sha256"])
        except (ValueError, OSError, KeyError, TypeError):
            # Unusable worker evidence cannot promote a claim or hold peers hostage.
            for question in value["questions"]:
                outcomes.append({"task_id": tid, "pass_id": value["assignment"]["pass_id"],
                    "question_id": question["id"], "objective_id": question["objective_id"],
                    "resolution": unresolved_resolution(question, unsuccessful_outcome(workers, tid))})
            continue
        rows.append({"task_id": tid, "artifact_ref": relative, "sha256": core.sha256_file(base_of(context) / relative)})
        outcomes.extend({"task_id": tid, "pass_id": result["pass_id"], **row} for row in result["question_outcomes"])
        documents.append(result)
    if any(r["status"] == "running" for r in workers):
        raise ValueError("stop live investigation workers before finalizing their evidence")
    for question in plan["questions"]:
        if question["disposition"] != "admitted":
            outcomes.append({"task_id": "planning", "pass_id": "planning", "question_id": question["id"], "objective_id": question["objective_id"],
                "resolution": {"outcome": "redundant" if question["disposition"] in {"redundant", "not_selected"} else question["disposition"],
                    "reason": question["reason"], "established_facts": [], "counterevidence": question["counterevidence"],
                    "evidence_refs": question["evidence_refs"], "missing_fact": question["proof_obligation"], "next_action": question["reason"]}})
    status = "skipped" if context["mode"] == "actions" else "completed" if rows else "empty"
    return core.envelope(context, status=status, results=rows, question_outcomes=outcomes, reason=plan["reason"],
        **quality_union(documents))


def terminal_outcomes(rows):
    """Resolve the latest analytical outcome for each independently owned question."""
    return list({(row["pass_id"], row["question_id"]): row for row in rows}.values())


def quality_union(documents):
    diagnostics, excluded = {}, {}
    truncated, hidden, affected = 0, 0, 0
    summaries = set()
    for doc in documents:
        quality = doc.get("evidence_quality", summarize([]))
        signature = core.digest(quality)
        if signature not in summaries:
            summaries.add(signature)
            truncated += quality["truncated"]
            hidden += max(0, quality["total"] - sum(row["count"] for row in quality["diagnostics"]))
            affected = max(affected, quality["affected_item_count"])
        for row in quality["diagnostics"]:
            diagnostics[core.digest(row)] = row
        for row in doc.get("non_promoted", []):
            excluded[core.digest(row)] = row
    summary = summarize(diagnostics.values())
    summary["truncated"] += truncated
    summary["total"] += hidden
    summary["affected_item_count"] = max(summary["affected_item_count"], affected)
    return {"evidence_quality": summary, "non_promoted": list(excluded.values())}


def finalize_investigation(context):
    owned(context, "investigation")
    value = investigation_projection(context)
    if context.get("patch_binding") and context["mode"] != "actions":
        from advantage_actions import validate_investigation
        validate_investigation(context)
    schema(value, "investigation", context)
    immutable(context, OUTPUTS["investigation"], value)
    record_source_receipts(context, "investigation")
    limited = [row for row in terminal_outcomes(value["question_outcomes"])
               if row["resolution"]["outcome"] in {"externally_blocked", "execution_failed"}]
    status = "skipped" if value["status"] == "skipped" else "degraded" if limited else "ok"
    warnings = [f"{row['question_id']}: {row['resolution']['outcome']}; exact missing fact in investigation/results.json" for row in limited]
    return core.finalize_phase(base_of(context), "investigation", status=status, warnings=warnings, context=context)


def observation(context, scan, ref, finding, *, fix=False):
    if isinstance(ref, dict):
        core.resolve_reference(context, ref, kind="artifact")
        raise ValueError("historical observation cannot establish current contained behavior")
    if context["reproduction_mode"] != "safe":
        raise ValueError("observation requires safe reproduction authorization")
    if fix:
        raise ValueError("investigation experiments do not verify production fixes")
    from investigation_experiments import validate_result as validate_experiment
    relative = _parts(ref)[0]
    if not relative.startswith("investigation/experiments/") or not relative.endswith("/result.json"):
        raise ValueError("observation must name a contained Advantage experiment")
    core.resolve_reference(context, ref, kind="artifact")
    result = read_local(context, relative)
    request_path = base_of(context) / relative.replace("/result.json", "/request.json")
    request = core.load(request_path)
    scope = validate_experiment(context, request, result, request_path)
    if scope != "current" or result["status"] != "supported":
        raise ValueError("experiment does not support the claimed current behavior")
    return request


def validate_transitions(context, finding, transitions=None, accepted=True, reference_validator=None):
    primitives = [p["primitive_id"] for p in finding["primitive_steps"]]
    if len(primitives) != len(set(primitives)):
        raise EvidenceIssue("ambiguous_record", "duplicate chain primitive")
    transitions = finding["transitions"] if transitions is None else transitions
    expected = list(zip(primitives, primitives[1:]))
    actual = [(t["producer_id"], t["consumer_id"]) for t in transitions]
    if actual != expected or (finding["finding_kind"] == "chain" and len(primitives) < 2):
        raise EvidenceIssue("missing_record", "chain requires every ordered producer-to-consumer transition")
    validate_refs = reference_validator or (lambda values, **kwargs: refs(context, values, **kwargs))
    if accepted or reference_validator is None:
        for primitive in finding["primitive_steps"]:
            validate_refs(primitive["evidence_refs"], source=True)
    for transition in transitions:
        resolution = transition["resolution"]
        validate_refs(resolution["evidence_refs"])
        if accepted and resolution["outcome"] != "established":
            raise EvidenceIssue("missing_record", "unproved transition cannot establish a chain")
        for obligation in transition["obligations"].values():
            validate_refs(obligation["evidence_refs"], source=accepted)
            if accepted and (obligation["outcome"] != "established" or not obligation["source_locations"]):
                raise EvidenceIssue("missing_record", "chain obligation lacks established source proof")
            for loc in obligation["source_locations"]:
                validate_refs([f"{loc['file']}:{loc['start_line']}-{loc['end_line']}"], kind="source")


def finding_key(finding):
    if finding["finding_kind"] == "chain":
        return ("chain", tuple(p["primitive_id"] for p in finding["primitive_steps"]), finding["impact"].strip().casefold())
    return (finding["finding_kind"], tuple(sorted((r["file"], r["line"], r["scope"]) for r in finding["root_causes"])))


def contributor_union(context, finding, link):
    contributors = []
    for baseline_id in link["baseline_ids"]:
        baseline = baseline_findings(context)[baseline_id]
        contributors.extend({"execution_id": context["baseline"]["execution_id"], **p} for p in baseline["contributors"])
    for relative in link["result_refs"]:
        result = read_local(context, relative)
        contributors.append(result["provenance"])
    # Typed support may introduce additional inherited authors even after correction.
    pending = [finding]
    while pending:
        node = pending.pop()
        if isinstance(node, dict) and {"execution_id", "artifact_ref"} <= node.keys():
            record = core.resolve_reference(context, node, kind="artifact")
            if isinstance(record, dict):
                authors = record.get("contributors", [])
                if record.get("provenance"):
                    authors = [*authors, record["provenance"]]
                contributors.extend({"execution_id": node["execution_id"], **p} for p in authors)
                if record.get("verdict") == "confirmed" and record.get("id") not in link["baseline_ids"]:
                    raise ValueError("material inherited finding omitted from baseline provenance")
        elif isinstance(node, dict):
            pending.extend(v for k, v in node.items() if k != "contributors")
        elif isinstance(node, list):
            pending.extend(node)
    for index, source in enumerate(finding["source_refs"]):
        try:
            value = core.resolve_reference(context, source["artifact_ref"], kind="artifact")
            records = value.get("candidates", []) if isinstance(value, dict) else []
            if not isinstance(value, dict) or not (value.get("id") == source["source_id"] or any(r["id"] == source["source_id"] for r in records)):
                raise EvidenceIssue("missing_record", "finding source reference lacks exact source record identity")
        except EvidenceIssue as exc:
            exc.field = f"source_refs[{index}]"
            raise
        if isinstance(source["artifact_ref"], dict):
            execution_id = source["artifact_ref"]["execution_id"]
            if execution_id != context["baseline"]["execution_id"] or source["source_id"] not in link["baseline_ids"]:
                raise ValueError("baseline finding support missing from primitive reconciliation")
        elif _parts(source["artifact_ref"])[0] not in link["result_refs"]:
            raise ValueError("linked source record lacks validated result ownership")
    route = context["model_routing"]
    contributors.append({"execution_id": context["run_id"], "actor": "vulnops-advantage-synthesis",
        "selector": route["agents"]["vulnops-advantage-synthesis"], "artifact_ref": "synthesis/findings.json"})
    return sorted({core.digest(p): p for p in contributors}.values(), key=lambda p: (p["execution_id"], p["artifact_ref"], p["actor"], p["selector"]))


def validate_finding(context, finding, link):
    view = source_context(context, link["source_view"])
    objectives = synthesis_objectives(context)
    if finding.get("optional_support"):
        view = {**view, "_optional_support": {row["reference"]: row for row in finding["optional_support"]}}
    if finding["verification"]["model"] != context["model_routing"]["agents"]["vulnops-advantage-synthesis"]:
        raise ValueError("dossier has wrong synthesis route")
    if finding["contributors"] != contributor_union(context, finding, link):
        raise ValueError("effective dossier contributor union omitted or invented an author")
    validate_dossier(base_of(context), Path(view.get("source_root") or "."), view["repositories"], finding,
        objective_registry=objectives, evidence_validator=evidence_adapter(view),
        observation_validator=lambda scan, ref, row, **kw: observation(context, scan, ref, row, **kw),
        source_example_validator=lambda scan, target, repositories, example: validate_source_example(view, scan, target, repositories, example),
        publication_schema="advantage-verification.schema.json" if "verdict" in finding else "advantage-synthesis.schema.json")
    for location in [*finding["root_causes"], *finding["trace"]]:
        refs(view, [f"{location['file']}:{location['line']}"], kind="source")
    try:
        refs(view, finding["verification"]["source_validation_refs"], source=True)
    except EvidenceIssue as exc:
        exc.field = "verification.source_validation_refs"
        raise
    try:
        validate_transitions(view, finding, accepted=finding["status"] == "verified")
    except EvidenceIssue as exc:
        exc.field = "transitions"
        raise
    for ref in finding["graph_receipt_refs"]:
        from codegraph_contract import validate_linked_receipt
        validate_linked_receipt(context, ref)


def validate_synthesis(context, value):
    schema(value, "synthesis", context)
    provenance(context, value["provenance"], "vulnops-advantage-synthesis", "synthesis/findings.json")
    results, result_views = synthesis_inputs(context)
    known_results = set(results)
    findings, links = unique(value["findings"]), unique(value["links"], "finding_id")
    if set(findings) != set(links):
        raise ValueError("every dossier needs one baseline/result classification")
    if context["mode"] == "actions" and (findings or value["status"] != "skipped"):
        raise ValueError("actions mode cannot synthesize findings")
    baseline = baseline_findings(context)
    reconciliations = unique(value["baseline_reconciliation"], "baseline_id")
    if set(reconciliations) != set(baseline):
        raise ValueError("baseline reconciliation must account for every inherited finding")
    candidate_inputs = {(relative, candidate["id"]): candidate for relative, result in results.items()
                        for candidate in result["candidates"]}
    dispositions = {(r["result_ref"], r["candidate_id"]): r for r in value["candidate_dispositions"]}
    if len(dispositions) != len(value["candidate_dispositions"]) or set(dispositions) != set(candidate_inputs):
        raise ValueError("synthesis must account for every authored candidate exactly once")
    promoted = set()
    for key, row in dispositions.items():
        if not set(row["finding_ids"]) <= set(findings):
            raise ValueError("candidate disposition references an unknown dossier")
        if (row["disposition"] == "promoted") != bool(row["finding_ids"]):
            raise ValueError("only promoted candidates may bind finding authority")
        for fid in row["finding_ids"]:
            if row["result_ref"] not in links[fid]["result_refs"]:
                raise ValueError("promoted dossier omitted its originating investigation")
        if row["disposition"] == "baseline_revalidation":
            candidate = candidate_inputs[key]
            if not candidate["baseline_ids"] or not all(
                    reconciliations[bid]["status"] == "revalidated" and row["result_ref"] in reconciliations[bid]["result_refs"]
                    for bid in candidate["baseline_ids"]):
                raise ValueError("baseline rediscovery requires exact revalidation accounting")
        promoted.update(row["finding_ids"])
    if promoted != set(findings):
        raise ValueError("synthesis cannot invent a finding without an owned investigation candidate")
    keys = set()
    for fid, finding in findings.items():
        link = links[fid]
        if not set(link["baseline_ids"]) <= set(baseline) or not set(link["result_refs"]) <= known_results:
            raise ValueError("finding relies on unknown baseline or unvalidated result")
        if any(result_views[relative] != link["source_view"] for relative in link["result_refs"]):
            raise ValueError("finding source view differs from its owned investigation evidence")
        if link["classification"] in {"impact_expansion", "baseline_correction", "baseline_revalidation"} and not link["baseline_ids"]:
            raise ValueError("extension/correction/revalidation requires exact inherited finding links")
        if link["classification"] == "new_chain" and finding["finding_kind"] != "chain":
            raise ValueError("chain classification requires a complete chain dossier")
        if link["classification"] == "new_root" and finding["finding_kind"] == "chain":
            raise ValueError("a chain cannot be relabeled as a newly discovered standalone root")
        key = finding_key(finding)
        if key in keys:
            raise ValueError("duplicate root/ordered-chain authority; merge sources without losing independent locations")
        keys.add(key)
        for prior in baseline.values():
            if link["classification"] not in {"baseline_correction", "baseline_revalidation"} and key == finding_key(prior) and finding["impact"].strip().casefold() == prior["impact"].strip().casefold():
                raise ValueError("baseline rediscovery requires explicit revalidation, not a new finding classification")
        validate_finding(context, finding, link)
    for row in reconciliations.values():
        if not set(row["finding_ids"]) <= set(findings) or not set(row["result_refs"]) <= known_results:
            raise ValueError("baseline reconciliation has dangling finding/result")
        if row["status"] in {"revalidated", "contradicted"} and not row["result_refs"]:
            raise ValueError("changed baseline claim requires validated investigation evidence")
        if row["status"] == "contradicted" and not any(links[fid]["classification"] == "baseline_correction" and row["baseline_id"] in links[fid]["baseline_ids"] for fid in row["finding_ids"]):
            raise ValueError("baseline contradiction requires independent correction review")
    if not findings and value["status"] not in {"empty", "skipped"}:
        raise ValueError("no candidates require explicit empty synthesis")


def empty_synthesis(context):
    results, _ = synthesis_inputs(context)
    dispositions = [
        {"result_ref": relative, "candidate_id": candidate["id"], "disposition": "unresolved",
         "finding_ids": [], "reason": "No usable synthesis dossier was supplied; the candidate remains unreviewed."}
        for relative, result in results.items() for candidate in result["candidates"]]
    return core.envelope(context, status="skipped" if context["mode"] == "actions" else "empty",
        reason="No independently reviewable dossiers were supplied; unresolved candidates and inherited findings remain separately attributed.",
        provenance={"execution_id": context["run_id"], "actor": "vulnops-advantage-synthesis", "selector": context["model_routing"]["agents"]["vulnops-advantage-synthesis"], "artifact_ref": "synthesis/findings.json"},
        findings=[], links=[], candidate_dispositions=dispositions, baseline_reconciliation=[{"baseline_id": fid, "status": "not_revisited", "finding_ids": [], "result_refs": [], "reason": "No authored finding reconciliation."} for fid in baseline_findings(context)])


def admitted_synthesis(context, draft, *, original=None):
    """Keep supported dossiers; exclude unusable claims without blocking peers."""
    value = copy.deepcopy(draft)
    schema({**value, "findings": [], "links": []}, "synthesis", context)
    owner = OUTPUTS["synthesis"]
    provenance(context, value["provenance"], "vulnops-advantage-synthesis", owner)
    inherited = original if original is not None else read_local(context, OUTPUTS["investigation"])
    retained_accounting = inherited.get("non_promoted", [])
    inherited_ids = {row["id"] for row in retained_accounting}
    authored = []
    for row in value.get("non_promoted", []):
        if row["id"] in inherited_ids:
            if row not in retained_accounting:
                raise DossierAuthoringError("synthesis changed a protected original non_promoted claim")
        else:
            authored.append(row)
    authored_accounting(context, authored, "vulnops-advantage-synthesis")
    value["non_promoted"] = [*retained_accounting, *authored]
    if original is not None:
        preserve_original_synthesis(original, value)
    if not isinstance(value.get("findings"), list) or len(value["findings"]) > 512:
        raise ValueError("synthesis lacks bounded findings")
    if not isinstance(value.get("links"), list) or len(value["links"]) > 512:
        raise ValueError("synthesis lacks bounded evidence links")
    identities = Counter(row.get("id") for row in value["findings"]
                         if isinstance(row, dict) and isinstance(row.get("id"), str))
    malformed = {index for index, finding in enumerate(value["findings"])
                 if item_errors("synthesis", "findings", finding) or identities[finding["id"]] > 1}
    valid_links = [row for row in value["links"] if not item_errors("synthesis", "links", row)]
    link_counts = Counter(row["finding_id"] for row in valid_links)
    value["links"] = [row for row in valid_links if link_counts[row["finding_id"]] == 1]
    links = unique(value["links"], "finding_id")
    results, result_views = synthesis_inputs(context)
    known_results = set(results)
    baseline = baseline_findings(context)
    kept, excluded, issues = [], [], []
    for index, finding in enumerate(value["findings"]):
        field = f"findings[{index}]"
        if index in malformed:
            issues.append(diagnostic("unreadable_content", owner, field,
                [finding["id"]] if isinstance(finding, dict) and isinstance(finding.get("id"), str) else []))
            continue
        found = []
        quality_context = {**context, "_quality_issues": [], "_quality_owner": owner, "_quality_item": finding["id"]}
        try:
            link = links[finding["id"]]
            if publication_content_error(finding):
                raise ValueError("unsafe dossier content")
            if not set(link["result_refs"]) <= known_results:
                raise ValueError("dossier references unvalidated results")
            if any(result_views[relative] != link["source_view"] for relative in link["result_refs"]):
                raise ValueError("dossier source view differs from its evidence")
            view = source_context(context, link["source_view"])
            check_source_paths(view, finding)
            for ref in walk_refs(finding):
                if reference_shape(ref):
                    try:
                        refs(view, [ref])
                    except EvidenceIssue:
                        pass
            if ((link["classification"] == "new_chain" and finding["finding_kind"] != "chain") or
                    (link["classification"] == "new_root" and finding["finding_kind"] == "chain")):
                raise DossierAuthoringError("classification does not match the authored root or chain")
            if link["classification"] in {"impact_expansion", "baseline_correction", "baseline_revalidation"} and not link["baseline_ids"]:
                raise EvidenceIssue("missing_record", "inherited reassessment lacks its exact primitive")
            if not set(links[finding["id"]]["baseline_ids"]) <= baseline.keys():
                raise EvidenceIssue("missing_record", "inherited primitive is unavailable as a usable accepted record")
            validate_finding(quality_context, finding, links[finding["id"]])
        except EvidenceIssue as exc:
            affected = field + "." + getattr(exc, "field", "links")
            found = [diagnostic(exc.code, owner, affected, [finding["id"]])]
            # EvidenceIssue carries controlled resolver/proof messages, not raw
            # schema errors, scanner output or authored values.
            if publication_content_error(str(exc)):
                raise ValueError("unsafe evidence diagnostic") from None
            found[0]["explanation"] = str(exc)
        except (ValueError, OSError, KeyError, TypeError):
            found = [diagnostic("unreadable_content", owner, field, [finding["id"]])]
            found[0]["explanation"] = "The dossier does not establish valid source-backed proof and was excluded."
        issues.extend(quality_context["_quality_issues"])
        if found:
            issues.extend(found)
            excluded.append(excluded_item(owner, field, found,
                missing_fact=f"{found[0]['field']}: {found[0]['explanation']}"))
        else:
            kept.append(finding)
    keyed = {}
    for finding in kept:
        keyed.setdefault(finding_key(finding), []).append(finding)
    ambiguous = {finding["id"] for group in keyed.values() if len(group) > 1 for finding in group}
    if ambiguous:
        for index, finding in enumerate(value["findings"]):
            if isinstance(finding, dict) and isinstance(finding.get("id"), str) and finding["id"] in ambiguous:
                field = f"findings[{index}]"
                found = [diagnostic("ambiguous_record", owner, field, [finding["id"]])]
                issues.extend(found)
                excluded.append(excluded_item(owner, field, found,
                    missing_fact="Establish one unambiguous root or ordered-chain dossier without losing independent source attribution."))
        kept = [finding for finding in kept if finding["id"] not in ambiguous]
    for row in excluded:
        identity = row["diagnostics"][0]["affected_item_ids"][0]
        row["id"] = owner + "#" + identity
        row["input_refs"] = sorted({item["result_ref"] + ":" + item["candidate_id"]
            for item in value["candidate_dispositions"] if identity in item["finding_ids"]})
        if not row["input_refs"]:
            raise ValueError("excluded dossier lacks its originating candidate")
        refs(context, row["input_refs"], kind="artifact")
    retained = {finding["id"] for finding in kept}
    value["findings"] = kept
    value["links"] = [row for row in value["links"] if row["finding_id"] in retained]
    for row in value["candidate_dispositions"]:
        row["finding_ids"] = [fid for fid in row["finding_ids"] if fid in retained]
        if row["disposition"] == "promoted" and not row["finding_ids"]:
            row.update(disposition="unresolved", reason="Dependent dossier lacks usable local proof; no finding was promoted.")
    for row in value["baseline_reconciliation"]:
        removed_support = bool(row["finding_ids"]) and not any(fid in retained for fid in row["finding_ids"])
        row["finding_ids"] = [fid for fid in row["finding_ids"] if fid in retained]
        if row["status"] in {"contradicted", "revalidated"} and removed_support:
            row.update(status="reused", reason="Proposed reassessment lacks an eligible independently reviewable dossier.")
    if not kept and value["status"] != "skipped":
        value["status"] = "empty"
    value.update(quality_union([inherited, value,
                               {"evidence_quality": summarize(issues), "non_promoted": excluded}]))
    validate_synthesis(context, value)
    return value


def preserve_original_synthesis(original, value):
    """Supplementary authoring may add evidence, never replace protected claims."""
    from gap_dossier import preserve_original
    preserve_original(original, value)
    findings = unique(value["findings"])
    links = unique(value["links"], "finding_id")
    for prior in original["findings"]:
        current = findings.get(prior["id"])
        if current is None or any(current.get(key) != item for key, item in prior.items()
                                  if key not in {"source_refs", "contributors"}):
            raise ValueError("supplementary synthesis changed a protected original dossier")
        for field in ("source_refs", "contributors"):
            if any(item not in current[field] for item in prior[field]):
                raise ValueError("supplementary synthesis removed original evidence attribution")
    for prior in original["links"]:
        current = links.get(prior["finding_id"])
        if current is None or any(current.get(key) != item for key, item in prior.items() if key != "result_refs"):
            raise ValueError("supplementary synthesis changed original source classification")
        if not set(prior["result_refs"]) <= set(current["result_refs"]):
            raise ValueError("supplementary synthesis removed original result authority")
    dispositions = {(row["result_ref"], row["candidate_id"]): row for row in value["candidate_dispositions"]}
    if any(dispositions.get((row["result_ref"], row["candidate_id"])) != row for row in original["candidate_dispositions"]):
        raise ValueError("supplementary synthesis changed an original candidate disposition")
    reconciled = unique(value["baseline_reconciliation"], "baseline_id")
    for prior in original["baseline_reconciliation"]:
        if prior["status"] in {"revalidated", "contradicted"} and reconciled.get(prior["baseline_id"]) != prior:
            raise ValueError("supplementary synthesis replaced original baseline reconciliation")


def close_supplementary_synthesis(context, original, reason):
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000 or publication_content_error(reason):
        raise ValueError("supplementary synthesis closure requires a safe exact limitation")
    value = copy.deepcopy(original)
    value["provenance"] = {"execution_id": context["run_id"], "actor": "vulnops-advantage-synthesis",
        "selector": context["model_routing"]["agents"]["vulnops-advantage-synthesis"],
        "artifact_ref": OUTPUTS["synthesis"]}
    accounted = {(row["result_ref"], row["candidate_id"]) for row in value["candidate_dispositions"]}
    results, _ = synthesis_inputs(context)
    for relative, result in results.items():
        for candidate in result["candidates"]:
            if (relative, candidate["id"]) not in accounted:
                value["candidate_dispositions"].append({"result_ref": relative, "candidate_id": candidate["id"],
                    "disposition": "unresolved", "finding_ids": [],
                    "reason": "Supplementary synthesis did not complete; no independent finding authority: " + reason})
    validate_synthesis(context, value)
    return value


def finalize_synthesis(context, draft=None, *, stage=None):
    owned(context, "synthesis")
    supplement_failure = None
    original_path = core.inside(base_of(context), "synthesis/original-findings.json")
    if stage == "original":
        original_context = {**context, "_original_synthesis": True}
        if draft is not None:
            from gap_dossier import require_cohort
            require_cohort(context, "synthesis", "original")
        try:
            value = admitted_synthesis(original_context, empty_synthesis(original_context) if draft is None else draft)
        except (ValueError, OSError, KeyError, TypeError):
            return {"status": "unreviewed", "reason": "Original authoring was unusable; no original dossiers were admitted."}
        if not value["findings"] and any(row["disposition"] == "unresolved" for row in value["candidate_dispositions"]):
            return {"status": "unreviewed", "reason": "Original candidates lack usable dossiers; continue with available supplementary work."}
        immutable(context, "synthesis/original-findings.json", value)
        record_source_receipts(original_context, "synthesis", filename="original-source-receipts.json")
        from gap_dossier import bind_original_draft
        bind_original_draft(context, "synthesis/original-findings.json")
        return {"status": "original_complete", "artifact_ref": "synthesis/original-findings.json"}
    gap = gap_inputs(context)
    if gap and gap["candidates"]:
        from gap_dossier import load_original_draft
        original = load_original_draft(base_of(context), context, "synthesis/original-findings.json")
        if draft is not None:
            from gap_dossier import require_synthesis_publication
            require_synthesis_publication(context, "supplementary")
        else:
            from gap_dossier import cohort_failure
            supplement_failure = cohort_failure(base_of(context), context, "synthesis")["reason"]
        try:
            if draft is None:
                raise ValueError("supplementary authoring was not supplied")
            value = admitted_synthesis(context, draft, original=original)
        except (ValueError, OSError, KeyError, TypeError):
            supplement_failure = supplement_failure or "No usable additional synthesis was supplied; unsupported candidates remain unreviewed."
            value = (close_supplementary_synthesis(context, original, supplement_failure)
                     if original is not None else admitted_synthesis(context, empty_synthesis(context)))
        if original is not None:
            preserve_original_synthesis(original, value)
            value["original_evidence"] = {"ref": "synthesis/original-findings.json",
                                          "sha256": core.sha256_file(original_path)}
    else:
        try:
            value = admitted_synthesis(context, empty_synthesis(context) if draft is None else draft)
        except (ValueError, OSError, KeyError, TypeError):
            supplement_failure = "Synthesis authoring was unusable; candidate evidence remains unreviewed."
            value = admitted_synthesis(context, empty_synthesis(context))
    immutable(context, OUTPUTS["synthesis"], value)
    record_source_receipts(context, "synthesis")
    status = "skipped" if value["status"] == "skipped" else "degraded" if supplement_failure is not None else "ok"
    warnings = [supplement_failure] if supplement_failure else []
    return core.finalize_phase(base_of(context), "synthesis", status=status, warnings=warnings, context=context)


def verification_assignments(context):
    synthesis = read_local(context, OUTPUTS["synthesis"])
    schema(synthesis, "synthesis", context)
    actor = "vulnops-advantage-verify-one"
    value = core.envelope(context, assignments=[{"finding_id": f["id"], "candidate_sha256": dossier_hash(f),
        "actor": actor, "selector": context["model_routing"]["agents"][actor], "fresh_context": True,
        "result_ref": f"final-verification/results/{f['id']}.json"} for f in synthesis["findings"]])
    path = base_of(context) / "final-verification/assignments.json"
    if path.exists() and core.load(path) != value:
        raise ValueError("verification assignments changed exact dossier, owner or model route")
    return value


def prepare_verification(context):
    owned(context, "final-verification")
    value = verification_assignments(context)
    schema(value, "assignments", context)
    if not (base_of(context) / "final-verification/assignments.json").exists():
        immutable(context, "final-verification/assignments.json", value)
    for assignment in value["assignments"]:
        relative = f"final-verification/packets/{assignment['finding_id']}.json"
        immutable(context, relative, assignment)
    return value


def validate_review(context, finding, link, assignment, result):
    schema(result, "verification-result", context)
    actor = "vulnops-advantage-verify-one"
    expected_assignment = {"finding_id": finding["id"], "candidate_sha256": dossier_hash(finding),
        "actor": actor, "selector": context["model_routing"]["agents"][actor], "fresh_context": True,
        "result_ref": f"final-verification/results/{finding['id']}.json"}
    if any(assignment.get(key) != value for key, value in expected_assignment.items()):
        raise ValueError("review assignment changed candidate, owner or native route")
    if result["finding_id"] != finding["id"] or result["assignment_sha256"] != core.digest(assignment):
        raise ValueError("review belongs to a different/stale assignment")
    if result["model"] != assignment["selector"] or result["actor"] != assignment["actor"]:
        raise ValueError("reviewer differs from assigned native route")
    corrected = result["status"] == "corrected"
    if corrected != (result["corrected_finding"] is not None) or corrected != bool(result["corrections"]):
        raise ValueError("correction requires an effective dossier and attributed changes")
    effective = result["corrected_finding"] if corrected else finding
    if effective["id"] != finding["id"] or effective["objective_ids"] != finding["objective_ids"]:
        raise ValueError("review cannot replace finding identity or objective ownership")
    if corrected:
        changes = unique(result["corrections"], "field")
        changed = {key for key in finding if finding[key] != effective.get(key)}
        if set(changes) != changed:
            raise ValueError("corrections must identify every changed effective dossier field")
        for key, change in changes.items():
            before = finding[key] if isinstance(finding[key], str) else json.dumps(finding[key], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            after = effective[key] if isinstance(effective[key], str) else json.dumps(effective[key], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if change["before"] != before or change["after"] != after:
                raise ValueError("correction before/after differs from actual effective dossier")
    accepted = result["status"] in {"verified", "corrected"}
    if accepted:
        validate_finding(context, effective, link)
    if accepted and not context.get("source_root"):
        raise ValueError("new independent confirmation requires an authorized current source tree")
    if accepted and (effective["status"] != "verified" or effective["verification"]["level"] == "environment_required"):
        raise ValueError("environment-dependent claim cannot enter confirmed findings")
    view = source_context(context, link["source_view"])

    def review_refs(values, **kwargs):
        if result["status"] != "evidence_limited":
            return refs(view, values, **kwargs)
        for reference in values:
            try:
                refs(view, [reference], **kwargs)
            except EvidenceIssue:
                pass

    if not accepted:
        # The assigned dossier is challenged evidence, not a fresh affirmative
        # proof obligation. Its paths still cannot escape authorized roots.
        check_source_paths(view, effective)
        for reference in walk_refs(effective):
            try:
                refs(view, [reference])
            except EvidenceIssue:
                pass
        check_source_paths(view, result)
        review_refs(list(walk_refs(result)))
    declarations = list(effective.get("optional_support", []))
    for source in effective["source_refs"]:
        if isinstance(source["artifact_ref"], str) and _parts(source["artifact_ref"])[0] in link["result_refs"]:
            try:
                publication = core.resolve_reference(context, _parts(source["artifact_ref"])[0], kind="artifact")
            except EvidenceIssue:
                if accepted:
                    raise
                continue
            declarations.extend(row for candidate in publication["candidates"] if candidate["id"] == source["source_id"]
                                for row in candidate.get("optional_support", []))
    optional = {row["reference"]: row for row in declarations}
    challenges = unique(result.get("optional_support_reviews", []), "reference")
    if accepted and set(challenges) != set(optional):
        raise EvidenceIssue("missing_record", "independent review must challenge every optional-support sufficiency decision")
    for reference, review in challenges.items():
        if reference not in optional or review["obligation"] != optional[reference]["obligation"]:
            raise ValueError("optional-support review changed its attributed obligation")
        review_refs(review["evidence_refs"], source=accepted)
        if accepted and not review["sufficient"]:
            raise EvidenceIssue("missing_record", "optional support leaves an essential obligation unproved")
    review_refs(result["evidence_refs"], source=accepted)
    validate_dossier_review(base_of(context), Path(view.get("source_root") or "."), view["repositories"], effective, result,
        objective_registry=synthesis_objectives(context), evidence_validator=evidence_adapter(view))
    primitive_results = unique(result["primitive_results"], "primitive_id")
    if set(primitive_results) != {p["primitive_id"] for p in effective["primitive_steps"]}:
        raise ValueError("review must challenge every material inherited primitive")
    for primitive in primitive_results.values():
        review_refs(primitive["evidence_refs"], source=accepted)
        if accepted and primitive["status"] != "verified":
            raise ValueError("unproved inherited primitive cannot establish impact")
    validate_transitions(view, effective, result["transition_results"], accepted=accepted,
                        reference_validator=review_refs)
    review_refs(result["joint_conditions"]["evidence_refs"], source=accepted)
    if accepted and result["joint_conditions"]["outcome"] != "established":
        raise ValueError("incompatible joint conditions cannot establish a chain")
    reviewer = split_selector(result["model"])[:2]
    contributors = contributor_union(context, effective, link) if accepted else effective["contributors"]
    diverse = all(split_selector(p["selector"])[:2] != reviewer for p in contributors)
    if result["model_diversity"] != diverse:
        raise ValueError("model diversity must include effective inherited and linked contributors")
    return effective, accepted


def verification_projection(context):
    synthesis = read_local(context, OUTPUTS["synthesis"])
    expected = verification_assignments(context)
    assignments_path = base_of(context) / "final-verification/assignments.json"
    if expected["assignments"] or assignments_path.exists():
        if read_local(context, "final-verification/assignments.json") != expected:
            raise ValueError("verification assignments changed after synthesis")
    links = unique(synthesis["links"], "finding_id")
    candidates = unique(synthesis["findings"])
    finals, reviews, result_map, unconfirmed = [], [], {}, []
    documents = [synthesis]
    workers = native_workers(context, "final-verification")
    if any(r["status"] == "running" for r in workers):
        raise ValueError("stop live independent reviewers before finalizing their evidence")
    for assignment in expected["assignments"]:
        fid, relative = assignment["finding_id"], assignment["result_ref"]
        try:
            result = read_local(context, relative)
            schema(result, "verification-result", context)
            if result["finding_id"] != fid or result["assignment_sha256"] != core.digest(assignment):
                raise ValueError("review does not bind its dossier assignment")
            validate_admission(context, "final-verification", fid, result, relative, core.digest(assignment))
        except (ValueError, OSError, KeyError, TypeError):
            reason = "No usable independent review was admitted; the finding remains unconfirmed."
            outcome = unsuccessful_outcome(workers, fid)
            unconfirmed.append({"finding_id": fid, "outcome": outcome,
                "reason": reason,
                "assignment_ref": "final-verification/assignments.json"})
            continue
        effective = result["corrected_finding"] if result["status"] == "corrected" else candidates[fid]
        accepted = result["status"] in {"verified", "corrected"}
        result_map[fid] = result
        documents.append(result)
        if not accepted:
            unconfirmed.append({"finding_id": fid, "outcome": "locally_unresolved",
                "reason": result["closure_reason"],
                "assignment_ref": "final-verification/assignments.json"})
        reviews.append({"finding_id": fid, "artifact_ref": relative, "sha256": core.sha256_file(base_of(context) / relative), "status": result["status"]})
        if accepted:
            assessment = result.get("assessment_context")
            final = {**effective, "verdict": "confirmed", "model_diversity": result["model_diversity"], "independent_verification_ref": relative}
            final.pop("assessment_context", None)
            if assessment:
                final["assessment_context"] = assessment
            finals.append(final)
    accepted_ids = {f["id"] for f in finals}
    outcomes = terminal_outcomes(read_local(context, OUTPUTS["investigation"])["question_outcomes"])
    assessments = []
    gap = gap_inputs(context)
    for objective in synthesis_objectives(context).values():
        supported = [(fid, row) for fid, result in result_map.items() if fid in accepted_ids for row in result["objective_results"] if row["objective_id"] == objective["id"] and row["satisfied"]]
        missing = [row["resolution"]["missing_fact"] for row in outcomes if row["objective_id"] == objective["id"] and row["resolution"]["outcome"] in UNRESOLVED]
        if gap:
            missing.extend(row["missing_fact"] for row in gap["non_promoted"] if
                           row["objective_id"] == objective["id"] and row["outcome"] in UNRESOLVED and row["missing_fact"])
        if not supported:
            missing.insert(0, "No independently accepted finding establishes: " + objective["success_condition"])
        evidence = {core.digest(ref): ref for _, row in supported for ref in row["evidence_refs"]}
        assessments.append({"objective_id": objective["id"], "success_condition": objective["success_condition"], "status": "achieved" if supported else "unresolved", "finding_ids": sorted({fid for fid, _ in supported}), "remaining_obligations": list(dict.fromkeys(missing)), "evidence_refs": list(evidence.values())})
    reconciliation = copy.deepcopy(synthesis["baseline_reconciliation"])
    for row in reconciliation:
        reviewed_corrections = {fid for fid in row["finding_ids"] if fid in accepted_ids and
                               links[fid]["classification"] == "baseline_correction" and row["baseline_id"] in links[fid]["baseline_ids"]}
        if row["status"] == "contradicted" and not reviewed_corrections:
            row.update(status="reused", reason="Proposed baseline correction was not independently accepted; original verdict remains attributable.")
        if row["status"] == "revalidated" and not any(
                finding["id"] in row["finding_ids"] and
                links[finding["id"]]["classification"] == "baseline_revalidation"
                for finding in finals):
            row.update(status="reused", reason="Historical finding lacks an independently accepted revalidation dossier.")
    value = core.envelope(context, status="skipped" if context["mode"] == "actions" else "completed" if reviews or unconfirmed else "empty",
        findings=finals, links=[links[f["id"]] for f in finals], reviews=reviews, unconfirmed=unconfirmed,
        objective_assessments=assessments, baseline_reconciliation=reconciliation, **quality_union(documents))
    if assessment_ref(context):
        value["assessment_context"] = assessment_ref(context)
    return value


def finalize_verification(context):
    owned(context, "final-verification")
    value = verification_projection(context)
    schema(value, "verification", context)
    immutable(context, OUTPUTS["final-verification"], value)
    record_source_receipts(context, "final-verification")
    limited = [row for row in value["reviews"] if row["status"] == "needs_environment" or
               read_local(context, row["artifact_ref"])["joint_conditions"]["outcome"] in {"externally_blocked", "execution_failed"}]
    status = "skipped" if value["status"] == "skipped" else "degraded" if limited or value["unconfirmed"] else "ok"
    warnings = [f"{row['finding_id']}: {row['status']}; see {row['artifact_ref']}" for row in limited]
    warnings.extend(f"{row['finding_id']}: {row['outcome']}; see final-verification/assignments.json" for row in value["unconfirmed"])
    return core.finalize_phase(base_of(context), "final-verification", status=status, warnings=warnings, context=context)


def validate_accepted_findings(context, final):
    """Check accepted review authority without re-inspecting source or old routing."""
    findings = unique(final["findings"])
    reviews = unique(final.get("reviews", []), "finding_id")
    assignments_path = base_of(context) / "final-verification/assignments.json"
    assignments = None
    if assignments_path.exists():
        document = read_local(context, "final-verification/assignments.json")
        schema(document, "assignments", context)
        assignments = unique(document["assignments"], "finding_id")
    for identity, finding in findings.items():
        relative = finding["independent_verification_ref"]
        if relative != f"final-verification/results/{identity}.json":
            raise ValueError("accepted finding has a foreign independent review reference")
        review = read_local(context, relative)
        schema(review, "verification-result", context)
        if (review["finding_id"] != identity or review["status"] not in {"verified", "corrected"}
                or review["actor"] != "vulnops-advantage-verify-one"
                or not review["fresh_context"]
                or review["dossier_review"]["dossier_sha256"] != dossier_hash(finding)
                or review["model_diversity"] != finding["model_diversity"]
                or finding["verdict"] != "confirmed" or finding["status"] != "verified"):
            raise ValueError("accepted finding differs from its independent dossier review: " + identity)
        if assignments is not None:
            assignment = assignments.get(identity)
            if (not assignment or assignment["result_ref"] != relative
                    or assignment["selector"] != review["model"]
                    or assignment["actor"] != review["actor"]
                    or review["assignment_sha256"] != core.digest(assignment)):
                raise ValueError("accepted review differs from its recorded assignment: " + identity)
        if reviews:
            receipt = reviews.get(identity)
            if (not receipt or receipt["artifact_ref"] != relative or receipt["status"] != review["status"]
                    or receipt["sha256"] != core.sha256_file(base_of(context) / relative)):
                raise ValueError("accepted review differs from its final receipt: " + identity)


def report_projection(context):
    from advantage_baseline import effective_findings
    from advantage_reporting import _document
    explanation_limits = []
    assessment_context = context
    action_source = None
    if context["mode"] == "actions":
        binding = context["action_source"]
        reference = {"execution_id": binding["execution_id"], "artifact_ref": "final-verification/findings.json"}
        inherited = core.resolve_reference(context, reference)
        action_source = {"reference": reference, "finding_ids": [f["id"] for f in inherited["findings"]]}
        from report_bundle import read_publication
        source_publication = read_publication(Path(binding["root"]), expected_kind="advantage")
        if source_publication["run_id"] != binding["execution_id"]:
            raise ValueError("selected action scope belongs to another execution")
        action_source["assessment"] = source_publication["assessment"]
        final = {"findings": [], "links": [], "objective_assessments": [],
                 "baseline_reconciliation": [{"baseline_id": fid, "status": "not_revisited", "finding_ids": [],
                    "result_refs": [], "reason": "Actions-only execution does not re-investigate the original audit."}
                    for fid in baseline_findings(context)]}
        investigation = {"status": "skipped", "question_outcomes": []}
    else:
        final = read_local(context, OUTPUTS["final-verification"])
        schema(final, "verification", context)
        investigation = _document(context, OUTPUTS["investigation"], limitations=explanation_limits,
                                  collections=("results", "question_outcomes"))
        _document(context, "planning/plan.json", limitations=explanation_limits,
                  collections=("objectives", "questions", "assignments"))
        validate_accepted_findings(context, final)
    investigation_available = investigation is not None
    investigation = investigation or {}
    outcomes = investigation.get("question_outcomes", [])
    terminal = terminal_outcomes(outcomes)
    assessed = final["findings"]
    assessed_ids = {finding["id"] for finding in assessed}
    assessed_links = list(unique(final["links"], "finding_id").values())
    if {link["finding_id"] for link in assessed_links} != assessed_ids:
        raise ValueError("accepted findings lack exact reporting classification")
    historical = [{"execution_id": context["baseline"]["execution_id"], "finding": finding,
                   "assessment_scope": "historical"} for finding in effective_findings(
                       Path(context["baseline"]["root"]),
                       expected_execution_id=context["baseline"]["execution_id"]).values()
                   if (finding.get("verdict"), finding.get("status")) in {
                       ("confirmed", "verified"), ("needs_environment", "needs_environment")}]
    if action_source and binding["execution_id"] != context["baseline"]["execution_id"]:
        historical.extend({"execution_id": binding["execution_id"], "finding": finding, "assessment_scope": "historical"}
                          for finding in inherited["findings"])
    resolved_baseline = {baseline_id for link in assessed_links for baseline_id in link["baseline_ids"]}
    unresolved = [{"execution_id": row["execution_id"], "finding_id": row["finding"]["id"],
                   "reason": "Imported finding has no independently supported reassessment in this execution."}
                  for row in historical if not (row["execution_id"] == context["baseline"]["execution_id"] and row["finding"]["id"] in resolved_baseline)]
    objectives = copy.deepcopy(final["objective_assessments"])
    counts = {"baseline_total": len(final["baseline_reconciliation"]),
        **{f"baseline_{status}": sum(r["status"] == status for r in final["baseline_reconciliation"]) for status in ("reused", "revalidated", "contradicted")},
        **{label: sum(r["classification"] == classification for r in assessed_links) for label, classification in (("new_roots", "new_root"), ("new_chains", "new_chain"), ("impact_expansions", "impact_expansion"), ("baseline_corrections", "baseline_correction"))},
        "unresolved_objectives": sum(r["status"] == "unresolved" for r in objectives),
        "unresolved_questions": sum(r["resolution"]["outcome"] in UNRESOLVED for r in terminal) if investigation_available else None,
        "source_only_findings": sum(f["verification"]["level"] == "source_verified" for f in assessed),
        "dynamically_verified_findings": sum(f["verification"]["level"] == "dynamic_verified" for f in assessed),
        "assessed_confirmed": len(assessed), "historical": len(historical), "unresolved_applicability": len(unresolved)}
    cohorts = {}
    for name, findings in (("assessed", assessed), ("historical", [row["finding"] for row in historical])):
        diverse = sum(bool(f.get("model_diversity")) for f in findings)
        cohorts[name] = {"total": len(findings), "severity": {severity: sum(f["severity"] == severity for f in findings)
            for severity in ("critical", "high", "medium", "low", "info")},
            "confirmed": sum(f.get("verdict") == "confirmed" and f.get("status") == "verified" for f in findings),
            "needs_environment": sum(f.get("verdict") == "needs_environment" for f in findings),
            "diverse": diverse, "same_model": sum(f.get("model_diversity") is False for f in findings),
            "unknown_model_diversity": sum(not isinstance(f.get("model_diversity"), bool) for f in findings),
            "model_diversity": bool(findings) and diverse == len(findings)}
    catalog = _document(context, "baseline/catalog.json", limitations=explanation_limits)
    availability = {"counts_complete": catalog.get("counts_complete", False) if catalog else False,
        "unavailable_cohorts": catalog.get("unavailable_cohorts", []) if catalog else ["baseline/catalog.json"],
        "limitations": catalog.get("limitations", []) if catalog else [
            {"artifact_ref": "baseline/catalog.json", "reason": explanation_limits[-1]}]}
    value = core.envelope(context, baseline={"execution_id": context["baseline"]["execution_id"], "artifact_ref": "final-verification/findings.json"}, mode=context["mode"],
        baseline_availability=availability, unconfirmed=final.get("unconfirmed", []),
        **quality_union([doc for doc in (catalog, final if "evidence_quality" in final else investigation) if doc]),
        findings=assessed, historical_findings=historical, unresolved_applicability=unresolved, cohort_counts=cohorts,
        links=assessed_links, baseline_reconciliation=final["baseline_reconciliation"], objective_assessments=objectives, counts=counts, action_source=action_source,
        coverage={"exhaustive": False, "shared_baseline_assumptions": True, "investigation_status": investigation.get("status"),
            "assessed_findings": bool(assessed), "limitations": ["Accepted conclusions describe their recorded assessed scope; publication does not establish applicability to later source or coverage of newly added components.", *explanation_limits],
            "unresolved_by_outcome": {status: sum(r["resolution"]["outcome"] == status for r in terminal) if investigation_available else None for status in sorted(UNRESOLVED)}},
        ancillary={"question_outcomes": outcomes[:200], "total": len(outcomes) if investigation_available else None, "omitted": max(0, len(outcomes) - 200) if investigation_available else None, "canonical_ref": "handoff/actions.json" if context["mode"] == "actions" else "investigation/results.json"}, actions_ref="handoff/actions.json")
    value["assessment"] = report_assessment(
        assessment_context, assessed, phase="handoff" if context["mode"] == "actions" else "final-verification")
    from gap_exploration_contract import accounting
    supplementary = accounting(base_of(context), context=context) if context["mode"] != "actions" else None
    if supplementary is not None:
        from gap_dossier import candidate_references, source_reference
        gap = gap_inputs(context)
        references = {ref for candidate in gap["candidates"] for ref in candidate_references(candidate)}
        accepted_ids = sorted(finding["id"] for finding in assessed if any(
            isinstance(source["artifact_ref"], str) and source_reference(source) in references
            for source in finding["source_refs"]))
        value["gap_exploration"] = {**supplementary, "independently_accepted": len(accepted_ids),
            "independently_accepted_finding_ids": accepted_ids}
    from report_bundle import publication_metadata
    value["publication"] = publication_metadata(context, execution_kind="advantage",
        producer_routes=context.get("_publication_producer_routes"))
    return value


@lru_cache(maxsize=1)
def audit_renderer():
    """Reuse audited literal-Markdown and evidence-execution presentation rules."""
    spec = importlib.util.spec_from_file_location("advantage_shared_report", core.ROOT / "scripts/render-report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report_markdown(report, context):
    from advantage_reporting import render
    return render(report, context)


def render_report(context):
    owned(context, "report")
    if core.inside(base_of(context), OUTPUTS["report"]).exists():
        raise ValueError("completed report is immutable; report-only publication cannot restart")
    if context["mode"] != "actions":
        for phase in ("planning", "investigation", "synthesis", "final-verification"):
            validate_phase(base_of(context), phase, context)
    from advantage_actions import validate_phase as validate_handoff
    validate_handoff(base_of(context), "handoff", context)
    value = report_projection(context)
    markdown = report_markdown(value, context)
    value["publication"]["markdown_sha256"] = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
    schema(value, "report", context)
    path = core.inside(base_of(context), "report/security-report.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(markdown)
    if path.read_text(encoding="utf-8") != markdown:
        raise ValueError("report Markdown publication differs from validated rendering")
    record_source_receipts(context, "report")
    immutable(context, OUTPUTS["report"], value)
    return {"phase": "report", "status": "ok", "artifact_ref": OUTPUTS["report"]}


def phase_status(context, phase):
    """Summarize validated analytical limitations without storing phase state."""
    value = read_local(context, OUTPUTS[phase])
    if value.get("status") == "skipped":
        return "skipped"
    if phase == "investigation":
        limited = any(row["resolution"]["outcome"] in {"externally_blocked", "execution_failed"}
                      for row in terminal_outcomes(value["question_outcomes"]))
    elif phase == "synthesis":
        limited = any(row["disposition"] == "unresolved" for row in value["candidate_dispositions"])
    elif phase == "final-verification":
        limited = bool(value["unconfirmed"]) or any(
            row["status"] == "needs_environment" or
            read_local(context, row["artifact_ref"])["joint_conditions"]["outcome"] in {"externally_blocked", "execution_failed"}
            for row in value["reviews"])
    else:
        limited = False
    return "degraded" if limited else "ok"


def validate_phase(base, phase, context):
    if Path(base).resolve() != base_of(context).resolve():
        raise ValueError("pipeline phase belongs to another execution root")
    if phase == "gap-exploration":
        from gap_exploration_contract import validate_phase as validate_gap_phase
        return validate_gap_phase(base, context)
    value = read_local(context, OUTPUTS[phase])
    if phase == "planning":
        validate_plan(context, value)
        # Initial packet ownership is checked without requiring future result files.
        for task in value["assignments"]:
            if read_local(context, f"investigation/packets/{task['task_id']}.json") != packet(context, value, task):
                raise ValueError("initial packet changed after planning")
    elif phase == "investigation":
        schema(value, "investigation", context)
        if value != investigation_projection(context):
            raise ValueError("investigation aggregation differs from complete owned results")
        if context.get("patch_binding") and context["mode"] != "actions":
            from advantage_actions import validate_investigation
            validate_investigation(context)
    elif phase == "synthesis":
        validate_synthesis(context, value)
        gap = gap_inputs(context)
        if gap and gap["candidates"]:
            from gap_dossier import load_original_draft
            original = load_original_draft(base_of(context), context, "synthesis/original-findings.json")
            if original is not None:
                validate_synthesis({**context, "_original_synthesis": True}, original)
                preserve_original_synthesis(original, value)
    elif phase == "final-verification":
        schema(value, "verification", context)
        if value != verification_projection(context):
            raise ValueError("final findings differ from complete independent review projection")
    elif phase == "report":
        schema(value, "report", context)
        expected = report_projection(context)
        markdown = report_markdown(expected, context)
        expected["publication"]["markdown_sha256"] = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        if value != expected:
            raise ValueError("linked report JSON projection changed")
        if (base_of(context) / "report/security-report.md").read_text(encoding="utf-8") != markdown:
            raise ValueError("linked report Markdown is not the deterministic complete rendering")
    else:
        raise ValueError("unknown pipeline phase")


def main(command):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context")
    if command in {"plan", "wave", "synthesis"}:
        parser.add_argument("--draft", required=command in {"plan", "wave"})
    if command == "synthesis":
        parser.add_argument("--stage", choices=("original", "supplementary"))
    if command in {"investigation", "verification"}:
        parser.add_argument("--result", metavar="DRAFT")
    if command == "verification":
        parser.add_argument("--prepare", action="store_true")
        parser.add_argument("--cohorts", action="store_true")
    if command == "report":
        parser.add_argument("--retained", type=Path, help="publish only retained, independently reviewed evidence")
        parser.add_argument("--mode", choices=("standard", "deep"), help="operator-selected original mode; checked against retained passes")
        parser.add_argument("--check", action="store_true", help="validate retained publication without writing reports")
    args = parser.parse_args()
    try:
        if command == "report" and args.retained:
            if args.context or not args.mode:
                raise ValueError("--retained requires --mode and forbids native --context")
            from advantage_publication import publish
            print(json.dumps(publish(args.retained, args.mode, check=args.check), sort_keys=True))
            return
        if command == "report" and (args.mode or args.check):
            raise ValueError("--mode/--check require --retained")
        context = core.load_context(args.context)
        draft = None
        if getattr(args, "draft", None):
            if command == "synthesis":
                owned(context, "synthesis")
                try:
                    draft = core.load(args.draft)
                except (ValueError, OSError):
                    pass
            else:
                draft = core.load(args.draft)
        phase = "final-verification" if command == "verification" else "synthesis" if command == "synthesis" else "investigation"
        if getattr(args, "cohorts", False):
            result = verification_cohorts(context)
        elif getattr(args, "result", None):
            owned(context, phase)
            result_path = core.inside(base_of(context), args.result)
            try:
                result = admit_worker_result(context, phase, core.load(result_path))
            except (ValueError, OSError, KeyError, TypeError):
                result = {"status": "not_admitted",
                          "reason": "No usable source-bound worker publication; continue other work."}
        elif command == "plan":
            result = build_plan(context, draft)
        elif command == "wave":
            result = build_wave(context, draft)
        elif command == "investigation":
            result = finalize_investigation(context)
        elif command == "synthesis":
            result = finalize_synthesis(context, draft, stage=args.stage)
        elif command == "verification":
            result = prepare_verification(context) if args.prepare else finalize_verification(context)
        elif command == "report":
            result = render_report(context)
        else:
            raise ValueError("unknown pipeline command")
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, f"Advantage pipeline: {exc}\n")
