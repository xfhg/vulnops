"""Local evidence accounting; integrity errors deliberately remain fatal."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from evidence_refs import EvidenceIssue, artifact_value, validate_evidence_refs
from dossier_contract import dossier_evidence_groups, dossier_reference_fields

LIMIT = 200
CODES = {"missing_file", "missing_record", "ambiguous_record", "ambiguous_namespace",
         "unsupported_selector", "invalid_range", "unreadable_content"}


def diagnostic(code, owner, field, affected_item_ids, disposition="evidence_limited"):
    if code not in CODES or disposition not in {"evidence_limited", "optional"}:
        raise ValueError("invalid evidence diagnostic classification")
    safe = lambda value: re.sub(r"[^A-Za-z0-9_./:#\[\]-]", "?", str(value))[:240]
    return {"code": code, "owner": safe(owner), "field": safe(field),
            "disposition": disposition, "affected_item_ids": sorted({safe(x) for x in affected_item_ids}),
            "count": 1, "explanation": "Evidence could not establish this obligation; inspect the owning record."}


def classify_refs(scan, source_root, repositories, refs, *, owner, field,
                  affected_item_ids, disposition="evidence_limited", kind="mixed", historical=False):
    if not isinstance(refs, list):
        raise ValueError("evidence references must be an array")
    valid, issues, counts = [], [], {}
    for ref in refs:
        try:
            validate_evidence_refs(scan, source_root, repositories, [ref], owner=field,
                                   kind=kind, line_counts=counts, historical=historical)
            valid.append(ref)
        except EvidenceIssue as exc:
            issues.append(diagnostic(exc.code, owner, field, affected_item_ids, disposition))
    return valid, issues


def claim_reference_groups(claim):
    """Declared proof fields shared by accounting and evidence-closure consumers."""
    groups = [("evidence_refs", claim.get("evidence_refs", []), "mixed"),
              ("source_refs", [row["artifact_ref"] for row in claim.get("source_refs", [])], "artifact"),
              ("verification.source_validation_refs", claim.get("verification", {}).get("source_validation_refs", []), "mixed")]
    for name in ("resolution", "joint_conditions", "composition"):
        groups.append((name + ".evidence_refs", claim.get(name, {}).get("evidence_refs", []), "mixed"))
    for name in ("primitive_steps", "primitive_results"):
        groups.extend((f"{name}[{i}].evidence_refs", row.get("evidence_refs", []), "mixed")
                      for i, row in enumerate(claim.get(name, [])))
    for name in ("transitions", "transition_results"):
        for index, edge in enumerate(claim.get(name, [])):
            for label, proof in [("resolution", edge.get("resolution", {})), *edge.get("obligations", {}).items()]:
                field = f"{name}[{index}].{label}"
                groups.append((field + ".evidence_refs", proof.get("evidence_refs", []), "mixed"))
                groups.append((field + ".source_locations", [
                    f"{row['file']}:{row['start_line']}-{row['end_line']}" for row in proof.get("source_locations", [])], "source"))
    for name in ("root_causes", "trace"):
        groups.append((name, [f"{row['file']}:{row['line']}" for row in claim.get(name, [])], "source"))
    groups.extend(dossier_evidence_groups(claim))
    return groups


def claim_diagnostics(scan, source_root, repositories, claim, *, owner, item_id, historical=False):
    """Inspect every declared proof field, even after an earlier local failure."""
    issues = []
    for field, refs, kind in claim_reference_groups(claim):
        _, rows = classify_refs(scan, source_root, repositories, refs, owner=owner, field=field,
                                affected_item_ids=[item_id], kind=kind, historical=historical)
        issues.extend(rows)
    return issues


def summarize(diagnostics):
    grouped = {}
    affected = set()
    for row in diagnostics:
        key = (row["owner"], row["field"], row["code"], row["disposition"])
        affected.update(row["affected_item_ids"])
        if key not in grouped:
            grouped[key] = {**row, "affected_item_ids": set(), "count": 0}
        grouped[key]["affected_item_ids"].update(row["affected_item_ids"])
        grouped[key]["count"] += row["count"]
    rows = [{**row, "affected_item_ids": sorted(row["affected_item_ids"])}
            for _, row in sorted(grouped.items())]
    return {"diagnostics": rows[:LIMIT], "total": sum(row["count"] for row in rows),
            "truncated": max(0, len(rows) - LIMIT), "affected_item_count": len(affected)}


def validate_non_promoted(row, routing, scan, source_root, repositories, *, actor=None, historical=False):
    """Require an accountable investigation, never infer a rejection from a parser error."""
    if row.get("disposition") not in {"rejected", "evidence_limited"}:
        raise ValueError("invalid non-promoted disposition")
    for key in ("id", "reason", "risk_context"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError("non-promoted claim lacks " + key)
    if not row.get("input_refs"):
        raise ValueError("non-promoted claim lacks input ownership")
    review, deferral = row.get("review"), row.get("deferral")
    if row["disposition"] == "evidence_limited":
        if not all(isinstance(row.get(key), str) and row[key].strip() for key in ("missing_fact", "next_action")):
            raise ValueError("evidence-limited claim requires missing fact and next action")
        if not review and not deferral:
            raise ValueError("targeted source review or precise budget/priority/external deferral required")
    if row["disposition"] == "rejected" and not review:
        raise ValueError("substantive rejection requires attributed review")
    if review:
        if actor is not None and review.get("actor") != actor:
            raise ValueError("source-review actor differs from current owner")
        if routing["agents"].get(review.get("actor")) != review.get("selector"):
            raise ValueError("source-review attribution differs from assigned route")
        if not all(isinstance(review.get(key), str) and review[key].strip() for key in ("action", "result")) or not review.get("evidence_refs"):
            raise ValueError("targeted review requires action, result and inspected evidence")
        artifacts = validate_evidence_refs(scan, source_root, repositories, review["evidence_refs"],
                                          owner="targeted_review", historical=historical)
        if len(artifacts) == len(review["evidence_refs"]):
            raise ValueError("targeted source review must cite at least one inspected source location")
    if deferral:
        if deferral.get("kind") not in {"budget", "priority", "external"} or not isinstance(deferral.get("reason"), str) or len(deferral["reason"].strip()) < 20:
            raise ValueError("deferral requires a precise allocation, priority or external blocker")
    repair = row.get("correction_repair")
    if repair is not None:
        if (row["disposition"] != "evidence_limited" or not deferral or deferral.get("kind") != "budget" or
                not isinstance(repair, dict) or not isinstance(repair.get("attempted"), str) or
                not repair["attempted"].strip() or not isinstance(repair.get("diagnostics"), list) or
                not repair["diagnostics"] or
                not all(isinstance(message, str) and message.strip() for message in repair["diagnostics"])):
            raise ValueError("correction repair requires exact diagnostics, attempted bounded repair and exhausted allocation")


def effective_support(scan, source_root, repositories, finding, diagnostics=None, *, used_optional=None):
    """Read-time optional-support projection; the published evidence bytes stay intact."""
    result = copy.deepcopy(finding)
    optional = {}
    for row in finding.get("optional_support", []):
        ref = row["reference"]
        if ref in optional or not row["obligation"].strip() or not row["rationale"].strip() or not row["independent_support"]:
            raise ValueError("optional support requires unique citation, obligation and sufficient-support rationale")
        if ref in row["independent_support"]:
            raise ValueError("optional support cannot establish itself")
        artifacts = validate_evidence_refs(scan, source_root, repositories, row["independent_support"], owner="optional_support.independent_support")
        if len(artifacts) == len(row["independent_support"]):
            raise ValueError("optional-support rationale must identify independently inspected source")
        optional[ref] = row
    used = used_optional if used_optional is not None else set()
    def refs(value, key, field):
        if key not in value:
            return
        output = []
        for ref in value[key]:
            try:
                validate_evidence_refs(scan, source_root, repositories, [ref], owner=field)
                output.append(ref)
            except EvidenceIssue as exc:
                if ref not in optional:
                    raise
                used.add(ref)
                output.extend(optional[ref]["independent_support"])
                if diagnostics is not None:
                    diagnostics.append(diagnostic(exc.code, finding.get("id", "claim"), field,
                                                  [finding.get("id", "claim")], "optional"))
        value[key] = list(dict.fromkeys(output))
    refs(result, "evidence_refs", "evidence_refs")
    refs(result.get("verification", {}), "source_validation_refs", "verification.source_validation_refs")
    for index, step in enumerate(result.get("primitive_steps", [])):
        refs(step, "evidence_refs", f"primitive_steps[{index}].evidence_refs")
    refs(result.get("resolution", {}), "evidence_refs", "resolution.evidence_refs")
    refs(result.get("composition", {}), "evidence_refs", "composition.evidence_refs")
    refs(result.get("capability", {}), "provenance", "capability.provenance")
    for index, edge in enumerate(result.get("transitions", [])):
        refs(edge.get("resolution", {}), "evidence_refs", f"transitions[{index}].resolution.evidence_refs")
        for name, proof in edge.get("obligations", {}).items():
            refs(proof, "evidence_refs", f"transitions[{index}].obligations.{name}.evidence_refs")
    for value, key, field, kind in dossier_reference_fields(result):
        if key == "observation_refs":
            # Observation authority cannot be replaced by merely valid source.
            validate_evidence_refs(scan, source_root, repositories, value.get(key, []), owner=field, kind=kind)
        else:
            refs(value, key, field)
    if used_optional is None and set(optional) != used:
        raise ValueError("optional-support declaration must name an unusable relied-upon citation")
    return result


def input_reference(ref):
    """One claim identity for owner publications and their Intrusion aggregate."""
    ref = ref.replace("#", ":", 1)
    path, separator, identifier = ref.partition(":")
    if separator and path.startswith("intrusion/results/"):
        return "intrusion/intrusion-results.json:" + identifier
    if separator and path.startswith("gap-exploration/results/"):
        return "gap-exploration/results.json:" + identifier
    return ref


def synthesis_inputs(scan, *, include_supplementary=True):
    inputs = {}
    for relative, key in (("sast/verified-findings.json", None), ("intrusion/intrusion-results.json", "results")):
        path = scan / relative
        if not path.is_file():
            raise ValueError("missing synthesis input publication")
        doc = json.loads(path.read_text())
        rows = doc if key is None else [item for result in doc[key] for item in result.get("candidates", [])]
        for row in rows:
            ref = relative + ":" + row["id"]
            if ref in inputs:
                raise ValueError("duplicate synthesis input identity")
            inputs[ref] = row
    if include_supplementary:
        from gap_dossier import accepted_candidates
        for row in accepted_candidates(scan):
            ref = "gap-exploration/results.json:" + row["id"]
            if ref in inputs:
                raise ValueError("duplicate supplementary synthesis input identity")
            inputs[ref] = row
    closures = []
    coverage = scan / "sast/coverage-ledger.json"
    if coverage.is_file():
        closures.extend(json.loads(coverage.read_text()).get("non_promoted", []))
    intrusion = json.loads((scan / "intrusion/intrusion-results.json").read_text())
    closures.extend(row for result in intrusion.get("results", []) for row in result.get("non_promoted", []))
    for row in closures:
        if row["disposition"] != "evidence_limited":
            continue
        for ref in row["input_refs"]:
            ref = input_reference(ref)
            if ref not in inputs:
                try:
                    inputs[ref] = artifact_value(scan, ref)
                except EvidenceIssue:
                    inputs[ref] = row
    return inputs


def account_inputs(inputs, findings, non_promoted, supplied=None, *, unreviewed=()):
    """Require exactly one disposition for every original claim, including deduplicated roots."""
    assignments = {}
    for row in unreviewed:
        for ref in row["input_refs"]:
            assignments.setdefault(input_reference(ref), []).append(("unreviewed", [], row["reason"]))
    for row in non_promoted:
        for ref in row["input_refs"]:
            assignments.setdefault(input_reference(ref), []).append((row["disposition"], [], row["reason"]))
    for finding in findings:
        for source in finding.get("source_refs", []):
            ref = input_reference(source["artifact_ref"])
            if ":" not in ref:
                ref += ":" + source["source_id"]
            if ref in inputs:
                assignments.setdefault(ref, []).append(("eligible", [finding["id"]], "Retained for independent verification."))
    if supplied:
        for row in supplied:
            ref = input_reference(row["input_ref"])
            if ref not in assignments and row["disposition"] == "eligible":
                ids = {finding["id"] for finding in findings}
                if not row["finding_ids"] or not set(row["finding_ids"]).issubset(ids):
                    raise ValueError("input claim references unknown finding")
                assignments[ref] = [("eligible", row["finding_ids"], row["reason"])]
    if set(assignments) != set(inputs):
        raise ValueError("every input claim requires an explicit eligible, rejected or evidence-limited disposition")
    output = []
    for ref, rows in sorted(assignments.items()):
        if len({row[0] for row in rows}) != 1 or rows[0][0] != "eligible" and len(rows) != 1:
            raise ValueError("input claim has conflicting dispositions")
        output.append({"input_ref": ref, "disposition": rows[0][0],
                       "finding_ids": sorted({fid for row in rows for fid in row[1]}), "reason": rows[0][2]})
    return output
