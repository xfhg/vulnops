"""Derived Advantage presentation; accepted records remain the only authority.

This module deliberately does not validate earlier phases, inspect target source,
read worker drafts, or persist a second reporting dataset.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import advantage_contract as core
from artifact_policy import publication_content_error
from evidence_refs import EvidenceIssue, _parts

ADDED = frozenset({"new_root", "new_chain", "impact_expansion"})
SEVERITIES = ("critical", "high", "medium", "low", "info", "informational")
OPEN = frozenset({"locally_unresolved", "externally_blocked", "budget_deferred"})


def _document(context, relative, *, limitations=None, collections=(), required=False):
    """Unavailable explanation is local; authority and integrity still fail closed."""
    core.inside(context["scan_base"], relative)
    try:
        value = core.resolve_reference(context, relative, kind="artifact")
        if isinstance(value, dict) and value.get("run_id", context["run_id"]) != context["run_id"]:
            raise ValueError("presentation artifact belongs to another execution")
        error = publication_content_error(value)
        if error:
            raise ValueError(error)
        if not isinstance(value, dict) or any(
                not isinstance(value.get(key), list) or
                any(not isinstance(row, dict) for row in value[key]) for key in collections):
            raise EvidenceIssue("unreadable_content", "invalid explanatory document shape")
        keys = {"objectives": ("id", "desired_effect", "starting_actor", "controlled_material", "resource_scope"),
                "questions": ("id", "objective_id", "route", "disposition"),
                "assignments": ("task_id", "pass_id", "question_ids", "priority", "source_view"),
                "results": ("task_id", "artifact_ref"),
                "question_outcomes": ("task_id", "pass_id", "question_id", "objective_id", "resolution"),
                "tasks": ("assignment", "continuation"), "links": ("finding_id",), "findings": ("id",)}
        if any(any(any(key not in row for key in keys.get(collection, ())) for row in value[collection])
               for collection in collections):
            raise EvidenceIssue("unreadable_content", "invalid explanatory record shape")
        if "question_outcomes" in collections and any(
                not isinstance(row["resolution"], dict) or not isinstance(row["resolution"].get("outcome"), str)
                for row in value["question_outcomes"]):
            raise EvidenceIssue("unreadable_content", "invalid explanatory outcome shape")
        for collection in collections:
            for row in value[collection]:
                for key in ("id", "task_id", "pass_id", "question_id", "objective_id", "finding_id", "artifact_ref"):
                    if key in row and not isinstance(row[key], str):
                        raise EvidenceIssue("unreadable_content", "invalid explanatory identity shape")
                if "question_ids" in row and not isinstance(row["question_ids"], list):
                    raise EvidenceIssue("unreadable_content", "invalid explanatory assignment shape")
                if collection == "tasks" and (not isinstance(row["assignment"], dict) or
                        not isinstance(row["continuation"], dict) or
                        not isinstance(row["assignment"].get("task_id"), str)):
                    raise EvidenceIssue("unreadable_content", "invalid explanatory continuation shape")
    except (EvidenceIssue, OSError):
        if required:
            raise
        if limitations is not None:
            limitation = f"Historical support {relative} is unavailable; explanatory counts and scope are unknown."
            if limitation not in limitations:
                limitations.append(limitation)
        return None
    return value


class Navigation:
    """Authorize input references before generating portable relative destinations."""

    def __init__(self, context, renderer):
        self.context = context
        self.renderer = renderer
        self.base = Path(context["scan_base"]).resolve()

    def reference(self, ref, *, required=False):
        md = self.renderer.markdown
        typed = isinstance(ref, dict)
        raw = ref["artifact_ref"] if typed else ref
        relative, selector = _parts(raw)
        execution = self.context["run_id"]
        owner_root = self.base
        if typed:
            core.validate_schema(ref, "advantage-reference")
            owners = [owner for owner in (self.context["baseline"], self.context.get("action_source"))
                      if owner and owner["execution_id"] == ref["execution_id"]]
            if len(owners) != 1 or ref["execution_id"] == execution:
                raise ValueError("unadmitted or ambiguous cross-execution owner")
            execution = ref["execution_id"]
            owner_root = Path(owners[0]["root"]).resolve()
            # Resolve even unavailable/out-of-bundle references to retain the
            # resolver's namespace, containment, and content safety boundaries.
        elif PurePosixPath(relative).parts[0] not in {*core.PHASES, "advantage-manifest.json", "task-ledger.json"}:
            # Recorded source coordinates survive changed repository inventories.
            # They are not links to, or proof about, today's checkout.
            from advantage_actions import safe_relative
            safe_relative(relative)
            return md(raw) + " (assessed source citation)"
        path = core.inside(owner_root, relative)
        caption = md(f"{execution}: {relative}")
        suffix = f" (record {md(selector)})" if selector else ""
        if not typed and relative == "report/security-report.json":
            if selector:
                raise ValueError("report navigation cannot invent a JSON fragment")
        else:
            try:
                core.resolve_reference(self.context, ref, kind="artifact")
            except (EvidenceIssue, OSError):
                if required and not typed:
                    raise
                return caption + suffix + " (unavailable; consult the owning record)"
        if typed and owner_root.parent != self.base.parent:
            return caption + suffix + " (not included in this delivery layout)"
        destination = quote(os.path.relpath(path, self.base / "report"), safe="/")
        return f"[{caption}]({destination}){suffix}"

    def citations(self, refs):
        unique = {core.digest(ref): ref for ref in refs}
        return "; ".join(self.reference(ref) for ref in unique.values())


def presentation_input(report, context):
    """Join complete terminal outcomes to accepted definitions, never display caps."""
    from advantage_pipeline import terminal_outcomes

    if report["run_id"] != context["run_id"]:
        raise ValueError("report belongs to another execution")
    limitations = list(report.get("coverage", {}).get("limitations", []))
    plan = _document(context, "planning/plan.json", limitations=limitations,
                     collections=("objectives", "questions", "assignments")) if report["mode"] != "actions" else None
    investigation = _document(context, "investigation/results.json", limitations=limitations,
                              collections=("results", "question_outcomes")) if report["mode"] != "actions" else None
    complete = plan is not None and investigation is not None
    plan, investigation = plan or {}, investigation or {}
    final = _document(context, "final-verification/findings.json", required=True) if report["mode"] != "actions" else {}
    objectives = {row["id"]: row for row in plan.get("objectives", [])}
    questions = {row["id"]: row for row in plan.get("questions", [])}
    assignments = {row["task_id"]: row for row in plan.get("assignments", [])}
    continuations = {}
    waves = core.inside(context["scan_base"], "investigation/waves")
    for path in sorted(waves.glob("[0-9][0-9][0-9].json")):
        wave = _document(context, path.relative_to(Path(context["scan_base"]).resolve()).as_posix(),
                         limitations=limitations, collections=("tasks",))
        if wave is None:
            complete = False
            continue
        for item in wave["tasks"]:
            assignment = item["assignment"]
            assignments[assignment["task_id"]] = assignment
            continuations[assignment["task_id"]] = item["continuation"]
    results = {row["task_id"]: row["artifact_ref"] for row in investigation.get("results", [])}
    outcomes = terminal_outcomes(investigation.get("question_outcomes", []))

    # Review qualifies the retained claim; it never deletes the investigation.
    assessments = []
    reviewed_ids = set()
    for record in final.get("reviews", []):
        review = _document(context, record["artifact_ref"], required=True)
        reviewed_ids.add(record["finding_id"])
        if review.get("status") not in {"verified", "corrected"}:
            assessments.append({"finding_id": record["finding_id"], "review": review,
                                "review_ref": record["artifact_ref"]})
    for record in final.get("unconfirmed", []):
        if record["finding_id"] not in reviewed_ids:
            assessments.append({"finding_id": record["finding_id"], "review": None,
                                "unconfirmed": record})
    synthesis = {}
    if assessments:
        synthesis = _document(context, "synthesis/findings.json", limitations=limitations,
                              collections=("links", "findings"))
        if synthesis is None:
            complete = False
            synthesis = {}
    proposed = {row["id"]: row for row in synthesis.get("findings", [])}
    proposed_links = {row["finding_id"]: row for row in synthesis.get("links", [])}

    bindings = []
    eligible = []
    for row in outcomes:
        task = assignments.get(row["task_id"])
        question = questions.get(row["question_id"])
        objective = objectives.get(row["objective_id"])
        if not (task and question and objective and task["pass_id"] == row["pass_id"]
                and row["question_id"] in task["question_ids"]
                and question["objective_id"] == objective["id"]):
            continue
        entry = {"outcome": row, "question": question, "objective": objective, "assignment": task,
                 "continuation": continuations.get(row["task_id"]), "result_ref": results.get(row["task_id"]),
                 "assessments": [],
                 "sort_key": (-task["priority"], objective["id"], row["pass_id"], question["id"])}
        bindings.append(entry)
        resolution = row["resolution"]
        inspected_support = any(isinstance(ref, str) and
                                PurePosixPath(_parts(ref)[0]).parts[0] not in {"baseline", "planning"}
                                for ref in resolution.get("evidence_refs", []))
        if (resolution["outcome"] in OPEN and resolution.get("established_facts")
                and all(isinstance(fact, str) and fact.strip() for fact in resolution["established_facts"])
                and inspected_support and objective.get("desired_effect", "").strip()
                and resolution.get("missing_fact", "").strip() and resolution.get("next_action", "").strip()
                and entry["result_ref"] and question.get("disposition") == "admitted"):
            eligible.append(entry)
    for assessment in assessments:
        finding = proposed.get(assessment["finding_id"])
        link = proposed_links.get(assessment["finding_id"])
        if finding is None or link is None:
            limitations.append("An unconfirmed claim lacks readable synthesis context; see final-verification/findings.json.")
            continue
        assessment.update(finding=finding, link=link)
        review = assessment["review"] or {}
        assessment["contradicted"] = (
            review.get("joint_conditions", {}).get("outcome") == "contradicted" or
            any(row.get("resolution", {}).get("outcome") == "contradicted" or
                any(item.get("outcome") == "contradicted" for item in row.get("obligations", {}).values())
                for row in review.get("transition_results", [])))
        related = [entry for entry in bindings if entry["result_ref"] in link["result_refs"]
                   and entry["objective"]["id"] in finding["objective_ids"]]
        review_refs = {core.digest(ref) for ref in review.get("evidence_refs", [])}
        matches = [entry for entry in related if entry in eligible and
                   (len(related) == 1 or review_refs.intersection(
                       core.digest(ref) for ref in entry["outcome"]["resolution"].get("evidence_refs", [])))]
        if matches:
            for entry in matches:
                entry["assessments"].append(assessment)
        else:
            # A source-established candidate can remain unconfirmed even when
            # investigation itself recorded success rather than an open question.
            priority = max((entry["assignment"]["priority"] for entry in related), default=0)
            eligible.append({"assessments": [assessment],
                             "sort_key": (-priority, finding["objective_ids"][0], "", finding["id"])})
    eligible.sort(key=lambda entry: entry["sort_key"])
    links = {row["finding_id"]: row for row in report["links"]}
    added, corrections = [], []
    for finding in report["findings"]:
        link = links.get(finding["id"])
        if not link:
            raise ValueError("accepted finding lacks exact reporting classification")
        if link["classification"] not in ADDED | {"baseline_correction"} or report["mode"] == "actions":
            continue
        entry = {"finding": finding, "link": link, "questions": [row for row in bindings
                 if row["result_ref"] in link["result_refs"] and row["objective"]["id"] in finding["objective_ids"]]}
        (added if link["classification"] in ADDED else corrections).append(entry)
    order = lambda entry: (SEVERITIES.index(entry["finding"]["severity"]), -entry["finding"]["risk_score"], entry["finding"]["id"])
    added.sort(key=order)
    corrections.sort(key=order)
    if any(row["resolution"]["outcome"] in {"execution_failed", "externally_blocked", "budget_deferred"} for row in outcomes) or report.get("unconfirmed"):
        limitations.append("Some investigation or independent review could not establish its intended scope; unexamined or unconfirmed routes are not evidence of safety.")
    if not plan and report["mode"] != "actions":
        limitations.append("Accepted planning context is unavailable; investigation intent and prior-coverage comparisons cannot be reconstructed.")
    if report.get("baseline_availability", {}).get("limitations"):
        limitations.append("Some inherited evidence is unavailable; baseline comparisons are limited to the explicitly supported records.")
    limitations.extend(report.get("gap_exploration", {}).get("limitations", []))
    actions_required = report["mode"] == "actions" or any(context.get("options", {}).get(key)
        for key in ("verify_fix", "assess_patch_risk", "hardening", "track_findings"))
    actions = _document(context, "handoff/actions.json", limitations=limitations,
                        required=actions_required) or {}
    return {"added": added, "corrections": corrections, "routes": eligible[:5] if complete else [],
            "eligible_count": len(eligible) if complete else None,
            "limitations": limitations, "actions": actions}


def _anchor(kind, *identities):
    return kind + "-" + core.digest(list(identities))[:16]


def _bullets(values, md):
    return ["- " + md(value) for value in dict.fromkeys(values) if value]


def _finding_lines(entry, report, nav, renderer, *, confirmed=True):
    finding, link = entry["finding"], entry["link"]
    md, cite = renderer.markdown, nav.citations
    anchor = _anchor("finding", report["run_id"], finding["id"])
    classification = "Material assessment correction" if link["classification"] == "baseline_correction" else link["classification"].replace("_", " ")
    lines = [f'<a id="{anchor}"></a>', f"### {md(finding['title'])}", "",
             f"**{md(finding['severity'])} — {md(classification)}{' (unconfirmed; proposed severity)' if not confirmed else ''}** · {md(report['run_id'])}: {md(finding['id'])}", "",
             md(finding["attack_summary"]), "", "**Evidence:** " + renderer.execution_label(finding) + ".", "",
             "**Source view:** " + md(link["source_view"]) +
             (" (proposed patch view, not unchanged deployed source)." if link["source_view"] == "derived" else "."), ""]
    scope = report.get("assessment", {}).get("record_scopes", {}).get(finding["id"])
    lines.extend(["**Assessment scope:** " + md(scope or "Unknown recorded scope") + ".", ""])
    if confirmed:
        lines.extend(["**Review:** Fresh-context independent review; " +
                      ("different model from recorded contributors." if finding["model_diversity"] else
                       "same-model review, not model diversity."), ""])
    else:
        lines.extend(["**Review:** Unconfirmed retained dossier; not an accepted finding or established attacker outcome.", ""])
    if link["classification"] == "baseline_correction":
        lines.extend(["This changes the material assessment; it is not counted as an additional attacker capability.", ""])
    if link["baseline_ids"]:
        lines.append("**Inherited opening (historical, not a grant of current access):**")
        for identity in link["baseline_ids"]:
            reference = {"execution_id": report["baseline"]["execution_id"], "artifact_ref": "final-verification/findings.json#" + identity}
            lines.append("- " + nav.reference(reference))
        lines.extend(["Only the reviewed explanation below supports a difference; a prior-coverage comparison is otherwise not established. Inherited identity alone does not establish current capability.", ""])
    else:
        lines.extend(["**Baseline comparison:** No explicit inherited dependency or prior-coverage comparison is established. This report does not claim the operation was previously unexplored.", ""])
    if entry["questions"]:
        lines.append("**Investigation purpose (planning intent, not proof of novelty):**")
        seen = set()
        for binding in entry["questions"]:
            question = binding["question"]
            text = (question["security_question"], question["novelty_reason"], question["proof_obligation"])
            if text not in seen:
                seen.add(text)
                lines.append(f"- {md(text[0])} Intent: {md(text[1])} Proof obligation: {md(text[2])}")
        lines.append("")
    actor = finding["attacker"]
    lines.extend(["#### Opening and causal progression", "",
                  f"**Attacker:** {md(actor['perspective'])}. **Starting access:** {md(actor['starting_access'])}.",
                  f"**Boundary:** {md(actor['boundary_crossed'])}.",
                  *_bullets([*finding["conditions"], *finding["exploitation"]["setup"]], md), "",
                  "**Intended behavior:** " + md(finding["intended_behavior"]), ""])
    if finding["exploitation"]["rationale"] != finding["attack_summary"]:
        lines.extend([md(finding["exploitation"]["rationale"]), ""])
    for component in finding["affected_components"]:
        service = component["service"]
        lines.extend([f"**{md(component['id'])}: {md(component['name'])}** — repository {md(component['repository'])}.",
                      *renderer.location_lines(component["locations"], cite),
                      "Entrypoints / jobs: " + md("; ".join(component["entrypoints"])),
                      f"Service: {md(service['name']) if service['name'] else 'Not established'} ({md(service['binding'])})."])
        if service["limitation"]:
            lines.append(md(service["limitation"]))
        if component["evidence_refs"] or service["evidence_refs"]:
            lines.append("Evidence: " + cite([*component["evidence_refs"], *service["evidence_refs"]]))
        lines.append("")
    lines.extend(["**Failed controls / root causes:**", *renderer.location_lines(finding["root_causes"], cite), ""])
    for trace in finding["trace"]:
        lines.append(f"- {md(trace['kind'])}: {md(trace['scope'])} — {md(trace['description'])} "
                     f"({cite([str(trace['file']) + ':' + str(trace['line'])])})")
    lines.append("")
    for index, step in enumerate(finding["exploitation"]["steps"], 1):
        lines.extend([f'<a id="{_anchor("step", report["run_id"], finding["id"], step["id"])}"></a>',
                      f"{index}. **{md(step['id'])}: {md(step['action'])}**",
                      f"   - Controlled input: {md(step['controlled_input'])}",
                      f"   - Components: {md(', '.join(step['component_ids']))}",
                      f"   - Why it works: {md(step['why_it_works'])}",
                      f"   - Expected result: {md(step['expected_result'])}",
                      f"   - Evidence status: **{md(step['evidence_status'])}**",
                      "   - Observed result: " + (md(step["observed_result"]) if step["observed_result"] is not None else "Not executed / no observation claimed.")])
        for key, label in (("evidence_refs", "Proof"), ("observation_refs", "Contained observation")):
            if step[key]:
                lines.append(f"   - {label}: {cite(step[key])}")
        for key, label in (("example_ids", "Examples"), ("primitive_ids", "Capability primitives")):
            if step[key]:
                lines.append(f"   - {label}: {md(', '.join(step[key]))}")
        repairs = [action for action in finding["remediation"]["actions"] if step["id"] in action["breaks_steps"]]
        if repairs:
            lines.append("   - Defensive interruption: " + "; ".join(
                f"[{md(action['id'])}](#{_anchor('fix', report['run_id'], finding['id'], action['id'])})"
                for action in repairs))
        lines.append("")
    for primitive in finding["primitive_steps"]:
        lines.extend([f"**Capability {md(primitive['primitive_id'])}:** {md(primitive['input_capability'])} → {md(primitive['output_capability'])}.",
                      "Boundary: " + md(primitive["boundary_crossed"]) + ". Evidence: " + cite(primitive["evidence_refs"]), ""])
    for transition in finding["transitions"]:
        resolution = transition["resolution"]
        lines.extend([f"**Transition {md(transition['producer_id'])} → {md(transition['consumer_id'])}:** {md(resolution['outcome'])}.",
                      md(resolution["reason"])])
        obligations = {}
        for label, obligation in transition["obligations"].items():
            obligations.setdefault(core.digest(obligation), (obligation, []))[1].append(label.replace("_", " "))
        for obligation, labels in obligations.values():
            lines.append(f"- **{md(', '.join(labels))} ({md(obligation['outcome'])}):** {md(obligation['reason'])}")
            references = [*obligation["evidence_refs"],
                          *(f"{location['file']}:{location['start_line']}-{location['end_line']}"
                            for location in obligation["source_locations"])]
            if references:
                lines.append("  Evidence: " + cite(references))
        for field, label in (("missing_fact", "Remaining proof"), ("next_action", "Next action")):
            if resolution.get(field):
                lines.append(f"{label}: {md(resolution[field])}")
        if resolution.get("evidence_refs"):
            lines.append("Transition evidence: " + cite(resolution["evidence_refs"]))
        lines.append("")
    for example in finding["technical_examples"]:
        lines.extend(renderer.example_lines(example, cite))
    if finding.get("dependency"):
        row = finding["dependency"]
        lines.extend([f"**Dependency:** {md(row['package'])} {md(row['installed_version'])}; {md(row['advisory_id'])}. "
                      f"Affected use: {md(row['affected_use'])}. Reachability: {md(row['reachability'])}.", ""])
    if finding.get("secret"):
        row = finding["secret"]
        lines.extend([f"**Redacted exposure:** {md(row['type'])} at {cite([str(row['file']) + ':' + str(row['line'])])}. "
                      f"{md(row['exposure_path'])}. Validity: {md(row['validity'])}.", ""])
    lines.extend(["#### Impact and limits", "", md(finding["impact"]), "", *_bullets(finding["impact_limits"], md), "",
                  "**Conclusion:** " + md(finding["closure_rationale"]), "", "#### Defensive interruption", ""])
    remediation = finding["remediation"]
    for action in remediation["actions"]:
        lines.extend([f'<a id="{_anchor("fix", report["run_id"], finding["id"], action["id"])}"></a>',
                      f"**{md(action['change'])}**", "", md(action["rationale"]),
                      "Breaks attack steps: " + ", ".join(
                          f"[{md(step)}](#{_anchor('step', report['run_id'], finding['id'], step)})"
                          for step in action["breaks_steps"]),
                      "Components: " + md(", ".join(action["component_ids"])),
                      *renderer.location_lines(action["locations"], cite)])
        if action["evidence_refs"]:
            lines.append("Evidence: " + cite(action["evidence_refs"]))
        if action["example_ids"]:
            lines.append("Examples: " + md(", ".join(action["example_ids"])))
        lines.append("")
    for key, label in (("containment", "Temporary containment"), ("detection", "Detection")):
        for item in remediation[key]:
            lines.append(f"**{label}:** {md(item['description'])} Components: {md(', '.join(item['component_ids']))}. Evidence: {cite(item['evidence_refs'])}")
    lines.extend(_bullets(remediation["limitations"], md))
    lines.extend(["", "**Proposed fix checks — not applied fixes or passing tests:**", ""])
    for check in remediation["verification_checks"]:
        lines.extend([f"- **{md(check['description'])}** ({md(check['status'])})",
                      "  - Attack rejection: " + md(check["attack_expected"]),
                      "  - Legitimate operation: " + md(check["legitimate_expected"])])
        if check["evidence_refs"]:
            lines.append("  - Evidence: " + cite(check["evidence_refs"]))
    lines.extend(["", "**Canonical finding evidence:**"])
    for source in finding["source_refs"]:
        lines.append("- " + nav.reference(source["artifact_ref"], required=True) + " — " + md(source["source_id"]))
    if confirmed:
        lines.extend(["Independent review: " + nav.reference(finding["independent_verification_ref"], required=True), ""])
    else:
        lines.extend(["Review disposition: " + nav.reference("final-verification/findings.json") + "; record " + md(finding["id"]), ""])
    return lines


def _action_lines(actions, nav, renderer):
    md = renderer.markdown
    lines = []
    labels = (("verify_fix", "Fix verification"), ("patch_risk", "Patch risk"), ("hardening", "Hardening assessment"),
              ("tracking", "Offline tracking"), ("diff_review", "Diff assessment"))
    for key, label in labels:
        section = actions.get(key, {})
        if section.get("status") != "completed":
            continue
        lines.extend(["### " + label, ""])
        if not section.get("records"):
            lines.extend(["No supported assessment record was established for this selected action.", ""])
        for row in section.get("records", []):
            identities = row.get("finding_ids", row.get("reviewed_finding_ids", [row["finding_id"]] if "finding_id" in row else []))
            if identities:
                lines.append("Finding context (not a discovery): " + md(row["finding_execution_id"] + ": " + ", ".join(identities)))
            for field, caption in (("assessment_status", "Evidence assessment"), ("outcome", "Conclusion"), ("assessment", "Assessment"),
                                   ("rationale", "Reason"), ("proposal", "Proposed control"), ("falsifiable_invariant", "Falsifiable invariant"),
                                   ("original_path", "Original attack path"), ("alternate_routes", "Alternate routes"),
                                   ("legitimate_behavior", "Legitimate behavior"), ("impact", "Patch impact"),
                                   ("likelihood", "Likelihood"), ("recoverability", "Recoverability"), ("confidence", "Confidence"),
                                   ("assessment_scope", "Assessment scope"), ("publication", "Publication"),
                                   ("disclosure_limitations", "Disclosure limits"), ("limitation", "Limitation")):
                if row.get(field):
                    lines.append(f"**{caption}:** {md(row[field])}")
            for field, caption in (("attack_transitions", "Interrupted transitions"), ("assumptions", "Assumptions"),
                                   ("tradeoffs", "Tradeoffs"), ("limitations", "Limitations")):
                if row.get(field):
                    lines.extend([f"**{caption}:**", *_bullets(row[field], md)])
            if row.get("path"):
                lines.append("Changed path: " + md(row["path"]) + " (base / derived comparison)")
            for check in row.get("checks", []):
                lines.append(f"- Check {md(check['name'])}: **{md(check['status'])}**. {md(check['limitation'])}")
                if check.get("experiment_ref"):
                    lines.append("  Contained evidence: " + nav.reference(check["experiment_ref"]))
            for citation in [*row.get("citations", []), *row.get("affected_consumers", [])]:
                relative = citation["path"] if citation["repository"] == "." else citation["repository"] + "/" + citation["path"]
                lines.append(f"- {md(citation['view'])} source: "
                             + nav.reference(f"{relative}:{citation['start_line']}-{citation['end_line']}"))
            if row.get("finding_ref"):
                lines.append("Owning finding: " + nav.reference(row["finding_ref"]))
            lines.append("")
    return lines


def render(report, context):
    from advantage_pipeline import audit_renderer

    renderer = audit_renderer()
    error = publication_content_error(report, size_limit=None)
    if error:
        raise ValueError(error)
    data = presentation_input(report, context)
    nav, md = Navigation(context, renderer), renderer.markdown
    lines = ["# Advantage security report", "",
             f"Execution: {md(report['run_id'])} · Mode: {md(report['mode'])} · Baseline: {md(report['baseline']['execution_id'])}.", "",
             "Confirmed attack outcomes require independent review. Assessment-specific evidence status applies; source-established procedures are not claims of live compromise.", "",
             "## Assessed scope", ""]
    assessment = report["assessment"]
    if report.get("publication", {}).get("published_at"):
        lines.extend(["Publication time: " + md(report["publication"]["published_at"]) +
                      " (publication only; not a new assessment).", ""])
    for scope in assessment["scopes"]:
        repositories = "; ".join(
            str(row.get("path", "unknown")) + " @ " + str(row.get("revision") or row.get("commit") or "unknown revision")
            for row in scope.get("repositories") or [])
        lines.extend([f"- **{md(scope['assessment_id'])}** — assessed {md(scope.get('started_at') or 'date unknown')}; "
                      f"view {md(scope.get('source_view') or 'unknown')}; {md(repositories or 'repository scope unknown')}."])
        if scope.get("patch_ref"):
            lines.append("  Recorded patch relationship: " + md(scope["patch_ref"]) + ".")
    lines.extend(["", "Publication attempt: " + md(assessment["publication_attempt_id"] or "unknown") + ". "
                  "Publication does not revalidate later source or establish coverage of newly added components.",
                  *_bullets(assessment["limitations"], md), "",
                  "Fresh-context review is not model diversity when author and reviewer use the same model.", "",
                  "## Attacker advancement", ""])
    if report["action_source"]:
        source = report["action_source"]
        lines.extend(["### Selected finding assessment", "",
                      "The selected dossiers retain their original assessment; this action does not re-investigate them."])
        for scope in source["assessment"]["scopes"]:
            lines.append(f"- {md(scope['assessment_id'])}: {md(scope.get('started_at') or 'date unknown')}; "
                         f"source view {md(scope.get('source_view') or 'unknown')}.")
        lines.extend([*_bullets(source["assessment"]["limitations"], md),
                      nav.reference(source["reference"]), ""])
    if report["mode"] == "actions":
        lines.extend(["No discovery pass occurred. This execution reports only selected follow-on assessments, not new vulnerabilities.", ""])
    elif not data["added"]:
        lines.extend(["No additional attacker outcome was confirmed. This is not a clean assessment or evidence that the application is safe.", ""])
    else:
        counts = {severity: sum(entry["finding"]["severity"] == severity for entry in data["added"]) for severity in SEVERITIES}
        lines.extend(["**Additional attack outcomes:** " + ", ".join(f"{count} {severity}" for severity, count in counts.items() if count) + ".", "",
                      "| Additional outcome | Severity | Evidence | Attack / repair overview |", "| --- | --- | --- | --- |"])
        for entry in data["added"]:
            finding = entry["finding"]
            repairs = finding["remediation"]["actions"]
            repair = ("[Repair " + md(repairs[0]["id"]) + "](#" +
                      _anchor("fix", report["run_id"], finding["id"], repairs[0]["id"]) + "): " +
                      md(repairs[0]["change"])) if repairs else "No specific repair recorded."
            lines.append(f"| [{md(finding['title'])}](#{_anchor('finding', report['run_id'], finding['id'])}) | {md(finding['severity'])} | {renderer.execution_label(finding)} | {md(finding['attack_summary'])} {repair} |")
        lines.append("")
    if data["corrections"]:
        lines.extend([f"{len(data['corrections'])} material assessment correction(s), separate from additional attack totals.", ""])
        for entry in data["corrections"]:
            finding = entry["finding"]
            lines.append(f"- [Assessment correction: {md(finding['title'])}](#{_anchor('finding', report['run_id'], finding['id'])})")
        lines.append("")
    lines.extend(_bullets(data["limitations"], md))
    lines.extend(["Coverage is not exhaustive; execution completion is not security assurance.", "",
                  "## Added attack narratives and material assessment changes", ""])
    for entry in [*data["added"], *data["corrections"]]:
        lines.extend(_finding_lines(entry, report, nav, renderer))
    if not data["added"] and not data["corrections"]:
        lines.extend(["No added attack narrative or material assessment correction was independently established.", ""])
    lines.extend(["## Unconfirmed and challenged attack possibilities", ""])
    if report["mode"] == "actions":
        lines.extend(["No investigation was requested; this execution makes no new-route assessment.", ""])
    elif data["eligible_count"] is None:
        lines.extend(["Unfinished-route selection is unavailable; the eligible route count is unknown.", ""])
    else:
        lines.extend([f"Selected {len(data['routes'])} of {data['eligible_count']} eligible routes (at most five; recorded investigation priority, not confirmed severity). "
                      + nav.reference("investigation/results.json") + ". Complete claims and assessments: "
                      + nav.reference("synthesis/findings.json") + "; "
                      + nav.reference("final-verification/findings.json") + ".", ""])
    for entry in data["routes"]:
        if "outcome" in entry:
            objective, question, resolution = entry["objective"], entry["question"], entry["outcome"]["resolution"]
            label = "Reviewed possibility" if entry["assessments"] else "Unconfirmed"
            lines.extend(["### " + label + ": " + md(question["route"]), "",
                          "**Objective / conditional extension:** " + md(objective["desired_effect"]),
                          "**Starting actor:** " + md(objective["starting_actor"]),
                          "**Controlled material:** " + md(objective["controlled_material"]),
                          "**Resource scope:** " + md(objective["resource_scope"]),
                          "**Source view:** " + md(entry["assignment"]["source_view"]),
                          "Recorded investigation progress is not independent confirmation of the conditional terminal impact.",
                          "**Investigation progress:**", *_bullets(resolution["established_facts"], md),
                          "**Investigation's missing proof:** " + md(resolution["missing_fact"]),
                          "**Investigation's next action:** " + md(resolution["next_action"]),
                          "Progress evidence: " + nav.citations(resolution["evidence_refs"])])
            if resolution.get("counterevidence"):
                lines.append("Counterevidence / limits: " + nav.citations(resolution["counterevidence"]))
            lines.extend(["Owning outcome: " + nav.reference(entry["result_ref"]) + "; question " + md(question["id"]), ""])
        else:
            finding = entry["assessments"][0]["finding"]
            lines.extend(["### Unconfirmed claim: " + md(finding["title"]), ""])
        for assessment in entry["assessments"]:
            finding, review = assessment["finding"], assessment["review"]
            status = review["status"] if review else "unreviewed"
            lines.extend(["**Attack rationale:** " + md(finding["attack_summary"]),
                          "**Source view:** " + md(assessment["link"]["source_view"]),
                          "**Independent assessment:** " + md(status) + "."])
            if assessment["contradicted"]:
                lines.append("**Contradicted route:** retained with counterevidence, not an established attack opportunity.")
            if review:
                if review.get("closure_reason"):
                    lines.append(md(review["closure_reason"]))
                joint = review.get("joint_conditions", {})
                for key, label in (("reason", "Joint conditions"), ("missing_fact", "Missing proof"), ("next_action", "Next action")):
                    if joint.get(key):
                        lines.append("**" + label + ":** " + md(joint[key]))
                for primitive in review.get("primitive_results", []):
                    if primitive["status"] == "rejected":
                        lines.append("**Primitive assessment:** " + md(primitive["reason"]) + " " +
                                     nav.citations(primitive["evidence_refs"]))
                for transition in review.get("transition_results", []):
                    for obligation in transition["obligations"].values():
                        if obligation["outcome"] == "contradicted":
                            lines.append("**Transition counterevidence:** " + md(obligation["reason"]) + " " +
                                         nav.citations(obligation["evidence_refs"]))
                for objective in review.get("objective_results", []):
                    if objective.get("reason"):
                        lines.append("**Objective assessment:** " + md(objective["reason"]))
                if review.get("evidence_refs"):
                    lines.append("Review evidence: " + nav.citations(review["evidence_refs"]))
                lines.append("Review: " + nav.reference(assessment["review_ref"]))
            else:
                closure = assessment["unconfirmed"]
                lines.append(md(closure["reason"]))
                lines.append("Review assignment: " + nav.reference(closure["assignment_ref"]))
            lines.extend(["Claim: " + nav.reference("synthesis/findings.json") + "; record " + md(finding["id"]),
                          "Retained for investigation context; not counted as confirmed.", ""])
    if not data["routes"] and data["eligible_count"] is not None and report["mode"] != "actions":
        lines.extend(["No evidence-grounded unfinished route qualifies for this selection; execution failures and untouched inherited findings are not attack opportunities.", ""])
    if report.get("unconfirmed_dossiers"):
        lines.extend(["## Complete unconfirmed dossiers", "",
                      "Retained claims below have no confirmed severity or independently established outcome.", ""])
        synthesis = _document(context, "synthesis/findings.json", required=True)
        links = {item["finding_id"]: item for item in synthesis["links"]}
        for finding in report["unconfirmed_dossiers"]:
            link = links[finding["id"]]
            lines.extend(_finding_lines({"finding": finding, "link": link, "questions": []},
                                        report, nav, renderer, confirmed=False))
    lines.extend(["## Defensive priorities", ""])
    for entry in [*data["added"], *data["corrections"]]:
        finding = entry["finding"]
        for action in finding["remediation"]["actions"]:
            lines.append(f"- [{md(finding['title'])} — repair {md(action['id'])}](#{_anchor('fix', report['run_id'], finding['id'], action['id'])}): "
                         + "interrupts steps " + md(", ".join(action["breaks_steps"])) + ".")
    actions = _action_lines(data["actions"], nav, renderer)
    if actions:
        lines.extend(["", "Selected assessments do not imply a deployed patch or a passing check unless their recorded evidence explicitly establishes it.", "", *actions])
    elif not data["added"] and not data["corrections"]:
        lines.extend(["No additional confirmed attack or selected action assessment establishes a new defensive priority.", ""])
    if report.get("gap_exploration") is not None:
        lines.extend(renderer.gap_lines(report["gap_exploration"], nav.reference("gap-exploration/results.json")))
    lines.extend(["", "---", "", "Evidence: " + nav.reference("report/security-report.json") + ". "
                  "Canonical JSON retains complete findings, historical attribution and accounting omitted from this human view.", ""])
    if actions:
        lines.extend(["Selected action evidence: " + nav.reference("handoff/actions.json"), ""])
    return "\n".join(lines)
