"""Shared in-memory synthesis admission and source-independent draft validation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from artifact_policy import publication_content_error
from codegraph_contract import followup_questions, validate_query_receipt
from dossier_contract import validate_dossier
from evidence_accounting import effective_support
from evidence_refs import EvidenceIssue, _parts, artifact_value
from intrusion_contract import primitive_updates_view, validate_transitions
from model_identity import finding_contributors
from run_lifecycle import routing_for_artifact


class InvalidSynthesisStructure(ValueError):
    """The finding document itself is invalid, not its ownership or evidence."""


def validate_synthesis_structure(doc: dict, *, linked: bool = False) -> None:
    """Check schema and intrinsic semantics without inspecting historical evidence."""
    # Safety failures must never become permission to discard a protected draft.
    error = publication_content_error(doc)
    if error:
        raise ValueError(error)
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("synthesis_schema", root / "scripts/validate-json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema_name = "advantage-synthesis.schema.json" if linked else "synthesis-findings.schema.json"
    schema = json.loads((root / "schemas/v2" / schema_name).read_text())
    schema_errors = module.Validator(schema).collect(doc, schema)
    if schema_errors:
        raise InvalidSynthesisStructure("invalid dossier publication: " + "; ".join(schema_errors[:8]))
    errors = []
    ids = []
    for finding in doc["findings"]:
        fid = finding["id"]
        ids.append(fid)
        trace = finding["trace"]
        if not trace or trace[0].get("kind") != "entrypoint" or trace[-1].get("kind") != "sink":
            errors.append(f"{fid} trace must run from entrypoint to sink")
        if any(step.get("kind") != "propagation" for step in trace[1:-1]):
            errors.append(f"{fid} intermediate trace steps must be propagation")
        steps = finding["primitive_steps"]
        if finding["finding_kind"] == "chain":
            if finding["origin"] != "composite_chain" or len(steps) < 2:
                errors.append(f"{fid} chain requires composite origin and at least two steps")
        elif steps or finding["transitions"]:
            errors.append(f"{fid} non-chain finding must not contain primitive steps or transitions")
        dependency = finding["dependency"]
        secret = finding["secret"]
        if finding["finding_kind"] == "dependency":
            if not isinstance(dependency, dict) or dependency.get("reachability") != "reachable":
                errors.append(f"{fid} dependency finding requires proven reachable affected use")
        elif dependency is not None:
            errors.append(f"{fid} non-dependency finding must use dependency: null")
        if finding["finding_kind"] == "secret":
            if not isinstance(secret, dict) or secret.get("redaction") != "<redacted>" or secret.get("validity") not in {"confirmed_format", "likely"}:
                errors.append(f"{fid} secret finding requires exact redaction and supported validity")
        elif secret is not None:
            errors.append(f"{fid} non-secret finding must use secret: null")
        if finding["status"] == "needs_environment" and finding["verification"].get("level") != "environment_required":
            errors.append(f"{fid} needs_environment status requires environment_required verification")
    if len(ids) != len(set(ids)):
        errors.append("synthesis finding IDs must be unique")
    if errors:
        raise InvalidSynthesisStructure("; ".join(errors))


def _load(path: Path, errors: list[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"cannot read {path}: {exc}")
    return None


def _artifact(scan: Path, ref: str) -> Path | None:
    relative, _ = _parts(ref)
    path = (scan / relative).resolve()
    if not path.is_relative_to(scan.resolve()):
        raise ValueError("unauthorized synthesis artifact")
    try:
        artifact_value(scan, ref)
    except EvidenceIssue:
        return None
    return path


def _target_file(target: Path, relative: str) -> bool:
    path = (target / relative).resolve()
    return path.is_relative_to(target.resolve()) and path.is_file()


def semantic_synthesis(scan: Path, target: Path, doc: dict, index: dict, intrusion: dict,
                       primary: str, errors: list[str], context: dict) -> None:
    """Validate a candidate in memory using the same rules as the final phase gate."""
    # Recovery imports the structural validator; do not introduce a module cycle.
    from gap_dossier import accepted, candidate_references, source_reference, synthesis_selector

    try:
        validate_synthesis_structure(doc)
    except ValueError as exc:
        errors.append(str(exc))
        return
    primitives = {x.get("id"): x for x in index.get("primitives", []) if isinstance(x, dict)}
    evidence_sources = {(str(x.get("source_kind")), str(x.get("source_id"))) for x in index.get("records", []) if isinstance(x, dict)}
    plan_doc = _load(scan / "campaign-planning/campaign-plan.json", errors) or {}
    campaign_ids = {str(x.get("id")) for x in plan_doc.get("campaigns", []) if isinstance(x, dict)}
    intrusion_ids = {str(x.get("campaign_id")) for x in intrusion.get("results", []) if isinstance(x, dict)}
    primitives.update({x["id"]: x for result in intrusion.get("results", []) for x in primitive_updates_view(scan, context, result)})
    graph_questions = {f"intrusion/codegraph-runs/{campaign['id']}/{q['id']}/receipt.json": (campaign["id"], q) for campaign in plan_doc.get("campaigns", []) for q in campaign.get("graph_questions", [])}
    for owner in intrusion_ids:
        try:
            for question in followup_questions(scan, context, owner):
                graph_questions[f"intrusion/codegraph-runs/{owner}/{question['id']}/receipt.json"] = (owner, question)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            errors.append(f"invalid graph follow-up: {exc}")
    allowed_graph = {ref for result in intrusion.get("results", []) for ref in result.get("graph_evidence_refs", [])}
    supplement = accepted(scan, context=context)
    gap_sources = {ref for row in (supplement or {}).get("candidates", []) for ref in candidate_references(row)}
    if supplement:
        from gap_exploration_contract import graph_question
        for record in supplement["results"]:
            result = _load(scan / record["ref"], errors) or {}
            for ref in result.get("graph_receipt_refs", []):
                parts = ref.split("/")
                try:
                    owner = parts[2]
                    graph_questions[ref] = (owner, graph_question(context, owner, parts[3], active=False))
                    allowed_graph.add(ref)
                except (ValueError, OSError, KeyError, IndexError) as exc:
                    errors.append(f"invalid supplementary graph support: {exc}")
    for finding in doc["findings"]:
        fid = str(finding["id"])
        try:
            routing = routing_for_artifact(scan, "synthesis/findings.json", context["model_routing"])
            if finding["verification"].get("actor") != "vulnops-synthesis" or finding["verification"]["model"] != synthesis_selector(scan, context, finding):
                raise ValueError("synthesizer differs from assigned route")
            if finding.get("contributors") != finding_contributors(scan, finding, routing, primitives, source_root=target, repositories=context["repositories"]):
                raise ValueError("contributors differ from effective evidence")
        except (ValueError, OSError, KeyError, TypeError) as exc:
            errors.append(f"{fid}: {exc}")
        try:
            effective = effective_support(scan, target, context["repositories"], finding, used_optional=set())
            validate_dossier(scan, target, context["repositories"], effective)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            errors.append(f"{fid}: {exc}")
            continue
        for location in [*finding.get("root_causes", []), *finding.get("trace", [])]:
            if not _target_file(target, str(location.get("file", ""))):
                errors.append(f"{fid} source file does not exist: {location.get('file')}")
        for source in finding.get("source_refs", []):
            if _artifact(scan, str(source.get("artifact_ref", ""))) is None:
                errors.append(f"{fid} unresolved source reference: {source.get('artifact_ref')}")
            kind = str(source.get("kind"))
            source_id = str(source.get("source_id"))
            if kind in {"recon", "sca", "secret", "sast", "reproduction"} and (kind, source_id) not in evidence_sources:
                errors.append(f"{fid} source ID does not resolve in evidence index: {kind}:{source_id}")
            if kind == "campaign" and source_id not in campaign_ids:
                errors.append(f"{fid} references unknown campaign: {source_id}")
            if kind == "intrusion" and source_id not in intrusion_ids | {candidate["id"] for result in intrusion.get("results", []) for candidate in result.get("candidates", [])}:
                errors.append(f"{fid} references unknown intrusion result or candidate: {source_id}")
            if kind == "gap-exploration" and source_reference(source) not in gap_sources:
                errors.append(f"{fid} references unaccepted supplementary evidence")
        for ref in finding.get("graph_receipt_refs", []):
            if _artifact(scan, str(ref)) is None:
                errors.append(f"{fid} unresolved graph reference: {ref}")
        for ref in finding.get("graph_receipt_refs", []):
            if ref not in allowed_graph or ref not in graph_questions:
                errors.append(f"{fid} graph receipt is not owning campaign evidence: {ref}")
                continue
            owner, question = graph_questions[ref]
            try:
                graph = validate_query_receipt(scan, target, context, "gap-exploration" if ref.startswith("gap-exploration/") else "intrusion", owner, question, ref)
                if not graph["meaningful"]:
                    errors.append(f"{fid} cites non-meaningful graph receipt")
            except (ValueError, OSError) as exc:
                errors.append(f"{fid}: {exc}")
        if finding["finding_kind"] == "chain":
            steps = finding["primitive_steps"]
            for step in steps:
                if step.get("primitive_id") not in primitives:
                    errors.append(f"{fid} chain references unknown primitive {step.get('primitive_id')}")
            try:
                validate_transitions(scan, target, [step.get("primitive_id") for step in steps], effective.get("transitions", []), primitives, require_established=finding.get("status") != "needs_environment")
            except (ValueError, OSError, KeyError, TypeError) as exc:
                errors.append(f"{fid}: {exc}")
