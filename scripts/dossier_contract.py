"""Declared dossier proof, effective-review binding and objective accounting.

No narrative is generated here. Local missing evidence remains EvidenceIssue;
invalid identities, unsafe citations and false execution claims remain fatal.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shlex
from pathlib import Path, PurePosixPath

from artifact_policy import DEFAULT_ARTIFACT_LIMIT, publication_content_error
from evidence_refs import EvidenceIssue, _parts, artifact_value, source_file, validate_evidence_refs
from run_lifecycle import current_assessment

ASPECTS = ("affected_scope", "exploitation", "technical_examples", "impact_limits", "remediation")
FINAL_FIELDS = {"verdict", "model_diversity", "independent_verification_ref", "assessment_context"}


class DossierAuthoringError(ValueError):
    """Repairable presentation is not a substantive evidence exclusion."""


def dossier_hash(finding):
    """Bind all synthesis fields; deterministic final projection metadata is excluded."""
    return hashlib.sha256(json.dumps({k: v for k, v in finding.items() if k not in FINAL_FIELDS},
                                     sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def validate_publication_schema(value, schema_name, definition=None):
    """Reject unsafe content and invalid schemas before deterministic publication."""
    root = Path(__file__).resolve().parent.parent
    limit = None if schema_name == "report.schema.json" and definition is None else DEFAULT_ARTIFACT_LIMIT
    error = publication_content_error(value, size_limit=limit)
    if error:
        raise ValueError(error)
    spec = importlib.util.spec_from_file_location("dossier_schema", root / "scripts/validate-json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = json.loads((root / "schemas/v2" / schema_name).read_text())
    errors = module.Validator(schema, size_limit=limit).collect(value, schema["$defs"][definition] if definition else schema)
    if errors:
        raise ValueError("invalid dossier publication: " + "; ".join(errors[:8]))


def dossier_references(finding):
    """All newly declared dossier citations, including source locations."""
    return sorted({ref for _, refs, _ in dossier_evidence_groups(finding) for ref in refs})


def dossier_locations(finding):
    """Exact new source locations for linked-remediation evidence closure."""
    return [location for row in finding.get("affected_components", [])
            for location in row["locations"]] + [
                location for row in finding.get("remediation", {}).get("actions", [])
                for location in row["locations"]]


def dossier_reference_fields(finding):
    """Yield mutable containers for declared citations only (never prose traversal)."""
    for i, component in enumerate(finding.get("affected_components", [])):
        yield component, "evidence_refs", f"affected_components[{i}].evidence_refs", "mixed"
        yield component["service"], "evidence_refs", f"affected_components[{i}].service.evidence_refs", "mixed"
    for label, rows in (("exploitation.steps", finding.get("exploitation", {}).get("steps", [])),
                        ("technical_examples", finding.get("technical_examples", []))):
        for i, row in enumerate(rows):
            yield row, "evidence_refs", f"{label}[{i}].evidence_refs", "mixed"
            yield row, "observation_refs", f"{label}[{i}].observation_refs", "artifact"
    remediation = finding.get("remediation", {})
    if isinstance(remediation, dict):
        for label in ("actions", "containment", "detection", "verification_checks"):
            for i, row in enumerate(remediation.get(label, [])):
                yield row, "evidence_refs", f"remediation.{label}[{i}].evidence_refs", "mixed"
    for aspect in ASPECTS:
        row = finding.get("dossier_review", {}).get(aspect)
        if row is not None:
            yield row, "evidence_refs", f"dossier_review.{aspect}.evidence_refs", "mixed"
    for i, row in enumerate(finding.get("objective_results", [])):
        yield row, "evidence_refs", f"objective_results[{i}].evidence_refs", "mixed"


def dossier_evidence_groups(finding):
    for row, key, field, kind in dossier_reference_fields(finding):
        yield field, row.get(key, []), kind
    for i, row in enumerate(finding.get("affected_components", [])):
        yield f"affected_components[{i}].locations", [f"{loc['file']}:{loc['line']}" for loc in row["locations"]], "source"
    remediation = finding.get("remediation", {})
    if isinstance(remediation, dict):
        for i, row in enumerate(remediation.get("actions", [])):
            yield f"remediation.actions[{i}].locations", [f"{loc['file']}:{loc['line']}" for loc in row["locations"]], "source"


def _ids(rows, label):
    result = {row["id"]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError(f"duplicate {label} identity")
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key) for key in result):
        raise ValueError(f"invalid {label} identity")
    return result


def _bound(ids, registry, label, *, nonempty=False):
    if (nonempty and not ids) or len(ids) != len(set(ids)) or not set(ids) <= set(registry):
        raise ValueError(f"dangling or duplicate {label} binding")


def _source_excerpt(target, repositories, ref):
    path = source_file(target, repositories, ref)
    _, selector = _parts(ref)
    if not selector:
        raise DossierAuthoringError("source example requires an explicit line range")
    lines = path.read_text(encoding="utf-8").splitlines()
    chunks = []
    for part in selector.split(","):
        bounds = part.strip().split("-")
        start, end = int(bounds[0]), int(bounds[-1])
        chunks.extend(lines[start - 1:end])
    return "\n".join(chunks)


def _validate_source_example(scan, target, repositories, example, *, evidence_validator=None):
    validator = evidence_validator or validate_evidence_refs
    artifacts = validator(scan, target, repositories, example["evidence_refs"], owner="technical_example")
    sources = [ref for ref in example["evidence_refs"] if ref not in artifacts]
    if not sources:
        raise DossierAuthoringError("source example lacks source attribution")
    originals = [row["original"] for row in example["substitutions"]]
    if len(originals) != len(set(originals)):
        raise DossierAuthoringError("duplicate source substitution")
    excerpts = [_source_excerpt(target, repositories, citation) for citation in sources]
    if len(excerpts) > 1:
        excerpts.append("\n".join(excerpts))
    for excerpt in excerpts:
        applicable = True
        for substitution in example["substitutions"]:
            original, replacement = substitution["original"], substitution["replacement"]
            if original not in excerpt or original == replacement or not substitution["reason"].strip():
                applicable = False
                break
            excerpt = excerpt.replace(original, replacement)
        if applicable and excerpt == example["content"].rstrip("\n"):
            return
    raise DossierAuthoringError("source example differs from its cited range and declared substitutions")


def _observation(scan, ref, finding, *, fix=False):
    """Validate approved observation metadata, not just existence or an exit code."""
    value = artifact_value(scan, ref)
    relative = re.split(r"[:#]", ref, maxsplit=1)[0]
    manifest = artifact_value(scan, "run-manifest.json")
    if manifest.get("reproduction_mode") != "safe":
        raise ValueError("observation requires authorized safe reproduction")
    if re.fullmatch(r"(?:sast|intrusion)/experiments/[A-Za-z0-9_-]+/result.json", relative):
        if fix:
            raise ValueError("isolated investigative experiments never verify a fix")
        from investigation_experiments import validate_result
        request_ref = relative.rsplit("/", 1)[0] + "/request.json"
        request = artifact_value(scan, request_ref)
        if validate_result({**manifest, "scan_base": str(scan)}, request, value, scan / request_ref) != "current":
            raise EvidenceIssue("unreadable_content", "historical experiment cannot establish a current observation")
        if value["status"] != "supported":
            raise ValueError("observation does not support the claimed behavior")
        return request
    if not re.fullmatch(r"sast/reproduction/[A-Za-z0-9][A-Za-z0-9_.-]*/result.json", relative):
        raise ValueError("observation must cite an approved contained result")
    validate_publication_schema(value, "reproduction-result.schema.json")
    if not current_assessment(value, manifest):
        raise EvidenceIssue("unreadable_content", "historical reproduction cannot establish a current observation")
    if relative != f"sast/reproduction/{value['finding_id']}/result.json" or value["provenance"]["artifact_ref"] != relative:
        raise ValueError("reproduction observation differs from its canonical finding owner")
    if (value.get("status") != "dynamic_verified" or value.get("sandbox") != "bubblewrap" or
            value.get("before", {}).get("status") != "expected_failure" or
            value.get("after", {}).get("status") != "passed" or value.get("errors") or
            type(value["before"]["exit_code"]) is not int or value["before"]["exit_code"] == 0 or
            value["after"]["exit_code"] != 0):
        raise ValueError("reproduction lacks successful contained before/after evidence")
    source_ids = {row["source_id"] for row in finding.get("source_refs", [])}
    if value.get("finding_id") not in source_ids:
        raise ValueError("reproduction belongs to an unrelated finding")
    for key in ("test", "patch"):
        cited = value.get(key + "_ref")
        if not isinstance(cited, str) or ":" in cited or "#" in cited:
            raise ValueError("reproduction lacks its exact test/patch binding")
        path = (scan / cited).resolve()
        if PurePosixPath(cited).is_absolute() or ".." in PurePosixPath(cited).parts or not path.is_relative_to(scan.resolve()):
            raise ValueError("unsafe reproduction input")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != value.get("hashes", {}).get(key + "_sha256"):
            raise ValueError("reproduction test/patch hash mismatch")
    return value


def validate_dossier(scan: Path, target: Path, repositories: list[dict], finding: dict, *,
                     objective_registry=None, evidence_validator=None,
                     observation_validator=None, publication_schema=None,
                     source_example_validator=None):
    """Validate full dossier proof; linked executions inject explicit authorities."""
    validate_refs = evidence_validator or validate_evidence_refs
    observation_for = observation_validator or _observation
    validate_publication_schema(finding, publication_schema or (
        "final-findings.schema.json" if "verdict" in finding else "synthesis-findings.schema.json"), "finding")
    pending = [finding]
    while pending:
        value = pending.pop()
        if isinstance(value, str) and len(value) > 8000:
            raise ValueError("required dossier field exceeds 8000 characters; return to active owner without clipping")
        if isinstance(value, list):
            if len(value) > 2048:
                raise ValueError("required dossier array exceeds its publication bound")
            pending.extend(value)
        elif isinstance(value, dict):
            pending.extend(value.values())
    from objective_contract import load_objectives
    objectives = load_objectives(scan) if objective_registry is None else objective_registry
    _bound(finding["objective_ids"], objectives, "objective", nonempty=True)
    components = _ids(finding["affected_components"], "component")
    examples = _ids(finding["technical_examples"], "example")
    steps = _ids(finding["exploitation"]["steps"], "step")
    remediation = finding["remediation"]
    _ids(remediation["actions"], "remediation action")
    _ids(remediation["verification_checks"], "verification check")
    prefixes = {row["path"] for row in repositories}
    for component in components.values():
        prefix = component["repository"]
        if prefix not in prefixes or any(prefix != "." and not PurePosixPath(loc["file"]).is_relative_to(prefix) for loc in component["locations"]):
            raise ValueError("component locations differ from authorized repository binding")
        service = component["service"]
        if service["binding"] == "unknown":
            if service["name"] is not None or not service["limitation"].strip():
                raise ValueError("unknown service binding requires null name and exact limitation")
        elif not service["name"] or not service["evidence_refs"]:
            raise ValueError("established service requires name and inspected evidence")
    affected_locations = {(loc["file"], loc["line"]) for component in components.values() for loc in component["locations"]}
    if any((loc["file"], loc["line"]) not in affected_locations for loc in finding["root_causes"]):
        raise ValueError("affected components must map every effective root-cause location")
    primitive_ids = [row["primitive_id"] for row in finding["primitive_steps"]]
    mapped = []
    for step in steps.values():
        _bound(step["component_ids"], components, "step component", nonempty=True)
        _bound(step["example_ids"], examples, "step example")
        _bound(step["primitive_ids"], primitive_ids, "step primitive")
        for pid in step["primitive_ids"]:
            if not mapped or mapped[-1] != pid:
                mapped.append(pid)
        if step["evidence_status"] == "observed_contained":
            if not step["observed_result"] or not step["observation_refs"]:
                raise ValueError("observed step requires bounded observation and approved evidence")
            for ref in step["observation_refs"]:
                observation = observation_for(scan, ref, finding)
                if "experiment_id" in observation:
                    if step["action"] != observation["behavior"] or step["observed_result"] != observation["supports"]:
                        raise ValueError("isolated observation does not bind this step's behavior and result")
                elif step["observed_result"] != observation["sanitized_summary"]:
                    raise ValueError("observed summary differs from approved reproduction scope")
        elif step["observed_result"] is not None or step["observation_refs"]:
            raise ValueError("unexecuted step cannot claim an observation")
        if step["evidence_status"] == "environment_required" and finding["status"] != "needs_environment":
            raise ValueError("unresolved required step cannot establish a confirmed finding")
    if finding["verification"]["level"] == "dynamic_verified":
        ref = finding["verification"]["reproduction_ref"]
        if not ref or "experiment_id" in observation_for(scan, ref, finding):
            raise ValueError("dynamic finding requires finding-scoped reproduction, not an isolated experiment")
        if not any(ref in step["observation_refs"] for step in steps.values()):
            raise ValueError("dynamic finding reproduction is not mapped to an observed procedure step")
    if mapped != primitive_ids:
        raise ValueError("procedure does not map the effective primitive sequence in order")
    for example in examples.values():
        if example["kind"] == "source":
            if source_example_validator is None:
                _validate_source_example(scan, target, repositories, example, evidence_validator=validate_refs)
            else:
                source_example_validator(scan, target, repositories, example)
        if example["execution_status"] == "observed_contained":
            if not example["observation_refs"]:
                raise ValueError("executed example requires approved observation")
            for ref in example["observation_refs"]:
                observation = observation_for(scan, ref, finding)
                if (example["kind"] != "command" or "command" not in observation or
                        example["content"] != shlex.join(observation["command"])):
                    raise ValueError("observation does not establish execution of this exact example")
        elif example["observation_refs"]:
            raise ValueError("unexecuted example cannot claim observation evidence")
    for action in remediation["actions"]:
        _bound(action["component_ids"], components, "remediation component", nonempty=True)
        _bound(action["breaks_steps"], steps, "remediation break point", nonempty=True)
        _bound(action["example_ids"], examples, "remediation example")
        if any(not set(steps[sid]["component_ids"]) & set(action["component_ids"]) for sid in action["breaks_steps"]):
            raise ValueError("remediation break point has no affected component binding")
        action_prefixes = [components[cid]["repository"] for cid in action["component_ids"]]
        if any(not any(prefix == "." or PurePosixPath(loc["file"]).is_relative_to(prefix) for prefix in action_prefixes)
               for loc in action["locations"]):
            raise ValueError("remediation locations differ from their affected component repositories")
    for label in ("containment", "detection"):
        if not remediation[label] and not remediation["limitations"]:
            raise ValueError("unavailable defensive guidance requires an applicability limitation")
        for row in remediation[label]:
            _bound(row["component_ids"], components, label + " component", nonempty=True)
    for check in remediation["verification_checks"]:
        if check["status"] == "executed":
            if not check["evidence_refs"]:
                raise ValueError("executed fix check requires approved reproduction")
            for ref in check["evidence_refs"]:
                observation_for(scan, ref, finding, fix=True)
    for field, refs, kind in dossier_evidence_groups(finding):
        validate_refs(scan, target, repositories, refs, owner=field, kind=kind)


def validate_dossier_review(scan, target, repositories, finding, result, *,
                            objective_registry=None, evidence_validator=None):
    validate_refs = evidence_validator or validate_evidence_refs
    review = result["dossier_review"]
    if review["dossier_sha256"] != dossier_hash(finding):
        raise ValueError("independent dossier review is stale for the effective finding")
    accepted = result["status"] in {"verified", "corrected"}
    for aspect in ASPECTS:
        row = review[aspect]
        if not row["reason"].strip() or not row["evidence_refs"]:
            raise ValueError("independent dossier assessment lacks inspected evidence")
        if accepted and row["disposition"] == "unresolved":
            raise ValueError("accepted dossier contains an unresolved independent assessment")
        if row["disposition"] == "corrected" and result["status"] != "corrected":
            raise ValueError("corrected dossier assessment requires a corrected finding")
        if result["status"] != "evidence_limited":
            validate_refs(scan, target, repositories, row["evidence_refs"], owner="dossier_review." + aspect)
    from objective_contract import load_objectives
    objectives = load_objectives(scan) if objective_registry is None else objective_registry
    rows = result["objective_results"]
    if len(rows) != len(finding.get("objective_ids",[])) or {row["objective_id"] for row in rows} != set(finding.get("objective_ids",[])):
        raise ValueError("independent objective results differ from effective objective bindings")
    for row in rows:
        objective = objectives.get(row["objective_id"])
        if objective is None or row["success_condition"] != objective["success_condition"]:
            raise ValueError("independent objective result changed the canonical success condition")
        if row["satisfied"] and (not accepted or finding["status"] != "verified"):
            raise ValueError("unaccepted or environment-limited finding cannot achieve an objective")
        if not row["reason"].strip() or not row["evidence_refs"]:
            raise ValueError("objective success reasoning requires inspected evidence")
        if result["status"] != "evidence_limited":
            artifacts = validate_refs(scan, target, repositories, row["evidence_refs"], owner="objective_results")
            if row["satisfied"] and len(artifacts) == len(row["evidence_refs"]):
                raise ValueError("objective success requires inspected source, not artifact identities alone")


def objective_assessments(scan, findings, *, results=None, candidates=()):
    """Derive complete, non-exhaustive closure from owned questions and fresh review."""
    from objective_contract import load_objectives, load_question_outcomes
    objectives = load_objectives(scan)
    outcomes = load_question_outcomes(scan)
    effective_candidates = {}
    for candidate in candidates:
        result = (results or {}).get(candidate["id"], {})
        effective_candidates[candidate["id"]] = result["corrected_finding"] if result.get("status") == "corrected" else candidate
    effective_candidates.update({finding["id"]: finding for finding in findings})
    for finding in effective_candidates.values():
        _bound(finding.get("objective_ids",[]), objectives, "objective",
               nonempty=finding.get("verdict") == "confirmed" or results is None)
    output = []
    for oid, objective in sorted(objectives.items()):
        questions = [row for row in outcomes if row["objective_id"] == oid]
        linked = [finding for finding in effective_candidates.values() if oid in finding.get("objective_ids",[])]
        supported = []
        if results is not None:
            for finding in linked:
                result = results.get(finding["id"])
                if finding.get("verdict") != "confirmed" or not result or result["status"] not in {"verified", "corrected"}:
                    continue
                if result["dossier_review"]["dossier_sha256"] != dossier_hash(finding):
                    raise ValueError("objective assessment cannot inherit stale dossier review")
                if any(not row["reason"].strip() or not row["evidence_refs"] for row in result["objective_results"]):
                    raise ValueError("objective assessment requires substantive independent success evidence")
                supported.extend(row for row in result["objective_results"] if row["objective_id"] == oid and
                                 row["success_condition"] == objective["success_condition"] and row["satisfied"])
        unresolved = [row["missing_fact"] or row["reason"] for row in questions
                      if row["outcome"] not in {"established", "contradicted"}]
        if not supported:
            unresolved.insert(0, "No independently accepted finding establishes success condition: " + objective["success_condition"])
        output.append({"objective_id": oid, "success_condition": objective["success_condition"],
                       "status": "achieved" if supported else "unresolved",
                       "finding_ids": sorted(row["id"] for row in linked), "question_outcomes": questions,
                       "reason": "\n".join(row["reason"] for row in supported) if supported else
                                 "Success is not independently established; recorded route outcomes do not exclude other routes.",
                       "remaining_obligations": list(dict.fromkeys(unresolved)),
                       "evidence_refs": sorted({ref for row in supported for ref in row["evidence_refs"]})})
    return output
