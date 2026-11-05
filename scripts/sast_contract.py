#!/usr/bin/env python3
"""Shared semantic checks for contextual SAST hunt worker results."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from model_identity import validate_provenance, contributor_union, finding_contributors
from evidence_refs import EvidenceIssue, validate_evidence_refs
from evidence_accounting import classify_refs, effective_support, validate_non_promoted
from objective_contract import validate_registry, validate_binding
from run_lifecycle import current_assessment, routing_for_artifact


def producing_attempt(scan: Path, artifact_ref: str) -> str | None:
    """Resolve coordinator-owned task provenance, never a worker's claimed scope."""
    relative = artifact_ref.split("#", 1)[0].split(":", 1)[0]
    ledger_path = Path(scan) / "sast/coverage-ledger.json"
    ledger = json.loads(ledger_path.read_text()) if ledger_path.is_file() else {}
    if relative.startswith("sast/deepdive/") and relative.endswith(".json"):
        identity = Path(relative).stem
        row = next((row for row in ledger.get("tasks", []) if row["id"] == identity), {})
        if row.get("attempt_id"):
            return row["attempt_id"]
        if row.get("artifact_valid"):
            return "legacy"
        packet_path = Path(scan) / f"sast/hunt-tasks/{identity}.json"
        if packet_path.is_file():
            return json.loads(packet_path.read_text()).get("task", {}).get("attempt_id")
    legacy = "legacy" if "review_attempts" not in ledger and any(
        row.get("artifact_valid") and not row.get("attempt_id") for row in ledger.get("tasks", [])) else None
    if relative.startswith("sast/verify/"):
        return ledger.get("review_attempts", {}).get(Path(relative).stem, legacy)
    if relative.startswith("sast/reproduction/"):
        return ledger.get("review_attempts", {}).get(Path(relative).parent.name, legacy)
    return None


def sast_review_support(scan, source_root, repositories, candidate, review, diagnostics=None):
    """Project reviewer support in its original or complete corrected candidate scope."""
    source = review.get("corrected_candidate") or candidate
    return effective_support(scan, source_root, repositories, {
        "id": candidate["id"],
        "evidence_refs": list(dict.fromkeys([
            *source.get("evidence_refs", []), *review.get("evidence_refs", [])])),
        "optional_support": review.get("optional_support", [])}, diagnostics)


def correction_contributors(scan: Path, routing: dict, review: dict, *, source_root: Path, repositories: list[dict]) -> list[dict]:
    classify_refs(scan, source_root, repositories, review.get("evidence_refs", []),
                  owner=review["provenance"]["artifact_ref"], field="evidence_refs",
                  affected_item_ids=[review.get("candidate_id")])
    corrected = review.get("corrected_candidate")
    if not isinstance(corrected, dict) or not isinstance(corrected.get("evidence_refs", []), list):
        return []
    refs, _ = classify_refs(scan, source_root, repositories, corrected.get("evidence_refs", []),
                            owner=review["provenance"]["artifact_ref"], field="corrected_candidate.evidence_refs",
                            affected_item_ids=[review.get("candidate_id")])
    if not review.get("corrections") or not refs:
        return []
    return finding_contributors(scan, {"verification": {"source_validation_refs": [review["provenance"]["artifact_ref"], *refs]}},
                                routing, source_root=source_root, repositories=repositories)

def validate_recon_provenance(scan: Path, routing: dict) -> None:
    owners = {"overview": "vulnops-recon-overview", "trust-boundaries": "vulnops-recon-trust", "input-surfaces": "vulnops-recon-inputs"}
    provenance = []
    for worker, actor in owners.items():
        ref = f"repo-context/research/{worker}.json"
        item = json.loads((scan / ref).read_text())
        provenance.append(validate_provenance(item.get("provenance"), routing_for_artifact(scan, ref, routing), actor, ref))
    surfaces = json.loads((scan / "repo-context/security-surfaces.json").read_text())
    for item in [*surfaces.get("entry_points", []), *surfaces.get("trust_boundaries", [])]:
        contributors = item.get("contributors", [])
        if not contributors or contributors != contributor_union(contributors) or any(value not in provenance for value in contributors):
            raise ValueError("Recon surface requires canonical validated research contributors")


def validate_sast_provenance(scan: Path, routing: dict, *, source_root: Path, repositories: list[dict]) -> None:
    def load(relative):
        return json.loads((scan / relative).read_text())
    context = load("run-manifest.json")
    def validate_candidate(candidate):
        classify_refs(scan, source_root, repositories, candidate.get("evidence_refs", []),
                      owner=candidate.get("id"), field="evidence_refs", affected_item_ids=[candidate.get("id")],
                      historical=not current_assessment(candidate, context))
    raw = {item["id"]: item for item in load("sast/raw-findings.json")}
    for candidate in raw.values():
        validate_candidate(candidate)
        ref = f"sast/deepdive/{candidate['task_id']}.json"
        owner = load(ref)
        provenance = validate_provenance(owner.get("provenance"), routing_for_artifact(scan, ref, routing), "vulnops-deepdive-chunk", ref)
        if candidate.get("contributors") != [provenance]:
            raise ValueError("raw candidate differs from its investigator provenance")
    expected = {key: item["contributors"] for key, item in raw.items()}
    for cluster in load("sast/dedup-clusters.json")["clusters"]:
        expected[cluster["canonical_id"]] = contributor_union(*(raw[key]["contributors"] for key in cluster["member_ids"]))
    queue = {item["id"]: item for item in load("sast/validation-queue.json")}
    for key, candidate in queue.items():
        validate_candidate(candidate)
        if candidate.get("contributors") != expected.get(key):
            raise ValueError("validation queue lost deduplicated investigator provenance")
    reviews = {}
    corrections = {}
    for review in load("sast/validation-results.json"):
        ref = f"sast/verify/{review['candidate_id']}.json"
        validate_provenance(review.get("provenance"), routing_for_artifact(scan, ref, routing), "vulnops-verify-one", ref)
        if review != load(ref):
            raise ValueError("candidate review differs from its source-owned publication")
        if review["candidate_id"] in reviews:
            raise ValueError("duplicate candidate review provenance")
        reviews[review["candidate_id"]] = review
        corrections[review["candidate_id"]] = (
            [] if context.get("attempt_id") and producing_attempt(scan, ref) != context["attempt_id"] else
            correction_contributors(scan, routing, review, source_root=source_root, repositories=repositories))
    reproductions = {}
    for path in sorted((scan / "sast/reproduction").glob("*/result.json")):
        item = json.loads(path.read_text())
        ref = f"sast/reproduction/{item['finding_id']}/result.json"
        if path.relative_to(scan).as_posix() != ref:
            raise ValueError("reproduction finding differs from canonical owner")
        reproductions[item["finding_id"]] = validate_provenance(item.get("provenance"), routing_for_artifact(scan, ref, routing), "vulnops-reproduce-one", ref)
        expected_reproduction = contributor_union(queue[item["finding_id"]]["contributors"],
                                                  [reviews[item["finding_id"]]["provenance"], reproductions[item["finding_id"]]],
                                                  corrections[item["finding_id"]])
        if (not context.get("attempt_id") or producing_attempt(scan, ref) == context["attempt_id"]) and item.get("contributors") != expected_reproduction:
            raise ValueError("reproduction lost investigator or reviewer provenance")
    for candidate in load("sast/verified-findings.json"):
        if context.get("attempt_id") and not current_assessment(candidate, context):
            continue
        validate_evidence_refs(scan, source_root, repositories, candidate.get("evidence_refs", []),
                               owner=f"{candidate.get('id')}.verified.evidence_refs")
        key = candidate["id"]
        review = reviews[key]
        source = review.get("corrected_candidate") or queue[key]
        support = sast_review_support(scan, source_root, repositories, queue[key], review)
        expected_refs = support["evidence_refs"] if review.get("optional_support") else source.get("evidence_refs", [])
        if (candidate.get("evidence_refs") != expected_refs or
                review.get("status") not in {"source_verified", "environment_required"}):
            raise ValueError("verified candidate does not retain independently established reviewer support")
        contributors = contributor_union(queue[key]["contributors"], [review["provenance"]], corrections[key])
        if key in reproductions:
            contributors = contributor_union(contributors, [reproductions[key]])
        if candidate.get("contributors") != contributors or candidate.get("validation") != review_projection(review):
            raise ValueError("verified candidate lost investigator or reviewer provenance")

def validate_sast_evidence_accounting(scan: Path, routing: dict, *, source_root: Path,
                                      repositories: list[dict]) -> None:
    """Re-derive finalized accounting without modifying any publication."""
    validate_sast_provenance(scan, routing, source_root=source_root, repositories=repositories)
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("vulnops_sast_accounting", root / "scripts/finalize-sast.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.finalize(root, source_root, scan, validate_only=True)



def review_projection(review: dict) -> dict:
    """Keep descriptive extensions in the owner publication, not strict derived findings."""
    fields = {"schema_version", "id", "candidate_id", "status", "confidence", "closure_reason",
              "evidence_refs", "corrections", "corrected_candidate", "mechanical_checks", "provenance",
              "optional_support", "non_promoted", "assessment_context"}
    projected = {key: value for key, value in review.items() if key in fields}
    projected["corrections"] = [
        {key: value for key, value in row.items() if key in {"field", "before", "after", "reason"}}
        for row in review.get("corrections", [])
    ]
    return projected


def hunt_evidence_diagnostics(scan: Path, repo: Path, repositories: list[dict], result: dict) -> list[dict]:
    """Classify only declared evidence fields; unknown prose is never evidence."""
    owner = f"sast/deepdive/{result['task_id']}.json"
    diagnostics = []
    def check(refs, field, ids, kind="mixed"):
        _, issues = classify_refs(scan, repo, repositories, refs, owner=owner, field=field,
                                  affected_item_ids=ids, kind=kind)
        diagnostics.extend(issues)
    for index, row in enumerate(result.get("cell_results", [])):
        ids = [row["cell_id"]]
        prefix = f"cell_results[{index}]"
        check(row.get("evidence_refs", []), prefix + ".evidence_refs", ids)
        resolution = row.get("resolution", {})
        try:
            effective_support(scan, repo, repositories, {"id": row["cell_id"], **resolution}, diagnostics)
        except EvidenceIssue:
            check(resolution.get("evidence_refs", []), prefix + ".resolution.evidence_refs", ids)
        check(row.get("files_reviewed", []), prefix + ".files_reviewed", ids, "source")
        check(row.get("checkpoint", {}).get("files_reviewed", []), prefix + ".checkpoint.files_reviewed", ids, "source")
        for offset, expansion in enumerate(row.get("source_expansions", [])):
            check([expansion["source"], expansion["predecessor"]],
                  f"{prefix}.source_expansions[{offset}]", ids, "source")
    for key in ("candidates", "positive_patterns", "hardening_notes", "rabbit_holes", "wishlist_items"):
        for index, item in enumerate(result.get(key, [])):
            identity = item.get("id", f"{owner}:{key}-{index}")
            check(item.get("evidence_refs", []), f"{key}[{index}].evidence_refs", [identity])
    for index, amendment in enumerate(result.get("model_amendments", [])):
        prefix = f"model_amendments[{index}]"
        check(amendment["source_refs"], prefix + ".source_refs", [amendment["id"]], "source")
        entity = amendment["entity"]
        for key in ("files", "source_files", "source_refs", "evidence_refs"):
            kind = "mixed" if key == "evidence_refs" and amendment["kind"] in {"objective", "question"} else "source"
            check(entity.get(key, []), prefix + ".entity." + key, [amendment["id"]], kind)
        if "path" in entity:
            check([entity["path"]], prefix + ".entity.path", [amendment["id"]], "source")
    return diagnostics


def _validator_module(root: Path):
    spec = importlib.util.spec_from_file_location("vulnops_validate_json_sast", root / "scripts/validate-json.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load validate-json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_errors(root: Path, repo: Path, candidate: object, *, scan: Path, repositories: list[dict]) -> list[str]:
    """Share strict candidate checks; unsafe declared sources are never format errors."""
    module = _validator_module(root)
    schema_path = root / "schemas/v2/candidate-finding.schema.json"
    schema = json.loads(schema_path.read_text())
    if isinstance(candidate, dict):
        if isinstance(candidate.get("evidence_refs"), list):
            classify_refs(scan, repo, repositories, candidate["evidence_refs"],
                          owner=candidate.get("id"), field="evidence_refs", affected_item_ids=[candidate.get("id")])
        locations = [candidate.get("root_cause_location")]
        if isinstance(candidate.get("trace"), list):
            locations.extend(candidate["trace"])
        for location in locations:
            if isinstance(location, dict) and isinstance(location.get("file"), str):
                classify_refs(scan, repo, repositories, [location["file"]],
                              owner=candidate.get("id"), field="candidate.source", affected_item_ids=[candidate.get("id")],
                              kind="source")
    errors = module.Validator(schema, schema_path.parent).collect(candidate, schema)
    if not errors:
        errors.extend(module.semantic_errors(candidate, "candidate", repo))
    return errors


def corrected_candidate_errors(root: Path, repo: Path, candidate: dict, review: dict, *,
                               scan: Path, repositories: list[dict]) -> list[str]:
    corrected = review.get("corrected_candidate")
    errors = []
    if isinstance(corrected, dict):
        # Check safety even when another field is malformed.
        errors = candidate_errors(root, repo, corrected, scan=scan, repositories=repositories)
        for key in ("id", "task_id", "cell_ids", "objective_id", "question_id", "contributors"):
            if corrected.get(key) != candidate.get(key):
                raise ValueError(f"corrected candidate changed required ownership/provenance field {key}")
    if review.get("corrections") and not isinstance(corrected, dict) and review.get("status") in {"source_verified", "environment_required", "evidence_limited"}:
        errors.append("$.corrected_candidate is required when corrections are recorded")
    if not review.get("corrections") and corrected is not None:
        errors.append("$.corrected_candidate must be null when corrections is empty")
    return errors[:8]


def validate_review_result(root: Path, repo: Path, candidate: dict, review: object, *,
                           scan: Path, repositories: list[dict], routing: dict) -> list[str]:
    """Return repair diagnostics, but raise on safety, ownership or provenance failure."""
    if not isinstance(review, dict):
        raise ValueError("candidate review lacks required owner/provenance")
    owner = f"sast/verify/{candidate['id']}.json"
    validate_provenance(review.get("provenance"), routing, "vulnops-verify-one", owner)
    if review.get("candidate_id") != candidate["id"]:
        raise ValueError("candidate review changed required candidate ownership")
    manifest_path = scan / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    if manifest.get("attempt_id") and not current_assessment(review, manifest):
        raise ValueError("current candidate review requires its assigned assessment attempt")
    module = _validator_module(root)
    schema_path = root / "schemas/v2/validation-result.schema.json"
    schema = json.loads(schema_path.read_text())
    if module.Validator(schema, schema_path.parent).collect(review.get("id"), schema["properties"]["id"]):
        raise ValueError("candidate review lacks a safe required review ID")
    errors = module.Validator(schema, schema_path.parent).collect(review, schema)
    if isinstance(review.get("evidence_refs"), list):
        classify_refs(scan, repo, repositories, review["evidence_refs"],
                      owner=owner, field="evidence_refs", affected_item_ids=[candidate["id"]])
    for support in review.get("optional_support", []) if isinstance(review.get("optional_support", []), list) else []:
        if isinstance(support, dict):
            refs = ([support["reference"]] if isinstance(support.get("reference"), str) else [])
            if isinstance(support.get("independent_support"), list):
                refs.extend(support["independent_support"])
            classify_refs(scan, repo, repositories, refs, owner=owner,
                          field="optional_support", affected_item_ids=[candidate["id"]])
    correction_errors = corrected_candidate_errors(root, repo, candidate, review, scan=scan, repositories=repositories)
    if isinstance(review.get("evidence_refs"), list):
        correction_contributors(scan, routing, review, source_root=repo, repositories=repositories)
    if isinstance(review.get("mechanical_checks"), dict) and review["mechanical_checks"].get("target_unchanged") is False:
        raise ValueError("candidate review reports target integrity failure")
    if errors:
        return errors + correction_errors
    closure = review.get("non_promoted")
    if review["status"] == "evidence_limited":
        if not isinstance(closure, dict):
            return ["evidence-limited review requires its owned non-promoted closure"]
        if (closure.get("id") != candidate["id"] or
                closure.get("input_refs") != [f"sast/validation-queue.json:{candidate['id']}"]):
            raise ValueError("evidence-limited closure changed required candidate ownership")
        if closure.get("disposition") != "evidence_limited":
            return ["evidence-limited review requires its owned non-promoted closure"]
        validate_non_promoted(closure, routing, scan, repo, repositories, actor="vulnops-verify-one")
        if correction_errors:
            repair = closure.get("correction_repair", {})
            if repair.get("diagnostics") != correction_errors or (closure.get("deferral") or {}).get("kind") != "budget":
                return correction_errors
        return []
    return correction_errors


def _source_path(value: str) -> str:
    return value.split(":", 1)[0].split("#", 1)[0]


def _entrypoint_id(value: str) -> str:
    return value.split(":", 1)[0].strip()


def _ordered_union(rows: list[dict], key: str) -> list[str]:
    return list(dict.fromkeys(str(item) for row in rows for item in row.get(key, [])))


def authorized_source_file(module: Any, repo: Path, relative: str, repositories: list[dict] | None = None) -> Path | None:
    path = module.safe_repo_file(repo, relative)
    if path is None or not path.is_file():
        return None
    if repositories is not None:
        for repository in repositories:
            prefix = str(repository.get("path", ""))
            if not prefix or Path(prefix).is_absolute() or ".." in Path(prefix).parts:
                continue
            boundary = (repo / prefix).resolve()
            if boundary.is_relative_to(repo.resolve()) and path.is_relative_to(boundary) and (
                    prefix == "." or Path(relative).is_relative_to(Path(prefix))):
                return path
        return None
    return None


def effective_threat_model(threat: dict, amendments: list[dict]) -> dict:
    """Extend a phase-local view; never mutate the sealed initial model."""
    keys = {"entrypoint": "entrypoints", "boundary": "trust_boundaries", "subsystem": "subsystems",
            "surface": "security_surfaces", "asset": "assets", "threat": "threats",
            "objective": "attack_objectives", "question": "investigation_questions"}
    result = {key: list(value) if isinstance(value, list) else value for key, value in threat.items()}
    for amendment in amendments:
        key = keys.get(amendment.get("kind"))
        entity = amendment.get("entity", {})
        if key and isinstance(entity, dict):
            existing = next((row for row in result.get(key, []) if row.get("id") == entity.get("id")), None)
            if existing is not None and existing != entity:
                raise ValueError("phase-local amendment cannot overwrite an inherited definition")
            if existing is None:
                result.setdefault(key, []).append(entity)
    return result


def validate_source_expansions(module: Any, repo: Path, cell: dict, row: dict, repositories: list[dict] | None = None) -> tuple[set[str], list[str]]:
    reachable = set()
    errors = []
    for source in cell.get("files", []):
        if authorized_source_file(module, repo, str(source), repositories) is None:
            errors.append(f"initial source anchor {source!r} is missing or unauthorized")
        else:
            reachable.add(str(source))
    for expansion in row.get("source_expansions", []):
        source = _source_path(str(expansion.get("source", "")))
        predecessor = _source_path(str(expansion.get("predecessor", "")))
        path = authorized_source_file(module, repo, source, repositories)
        if path is None or not path.is_file():
            errors.append(f"source expansion references missing or unauthorized source {source!r}")
        elif predecessor not in reachable or not str(expansion.get("reason", "")).strip():
            errors.append(f"source expansion {source!r} lacks a reachable predecessor and relevance")
        else:
            reachable.add(source)
    for value in [*row.get("files_reviewed", []), *(row.get("checkpoint") or {}).get("files_reviewed", [])]:
        relative = _source_path(str(value))
        path = authorized_source_file(module, repo, relative, repositories)
        if relative not in reachable or path is None or not path.is_file():
            errors.append(f"reviewed source {relative!r} is unauthorized, missing, or unattributed")
    return reachable, errors


def validate_retained_hunt(task: dict, cells: list[dict], result: dict) -> list[str]:
    """Read accepted work by ownership, without replaying its source assessment."""
    if result.get("task_id") != task["id"]:
        raise ValueError("retained hunt result changes its task owner")
    rows = result.get("cell_results", [])
    if [row.get("cell_id") for row in rows] != [cell["id"] for cell in cells]:
        raise ValueError("retained hunt result changes assigned cells")
    for cell, row in zip(cells, rows):
        if any(row.get(key) != cell[key] for key in ("objective_id", "question_id")):
            raise ValueError("retained hunt result changes objective/question ownership")
    candidates = {candidate["id"]: candidate for candidate in result.get("candidates", [])}
    if len(candidates) != len(result.get("candidates", [])):
        raise ValueError("duplicate retained candidate ownership")
    for cell, row in zip(cells, rows):
        expected = [key for key, candidate in candidates.items() if cell["id"] in candidate["cell_ids"]]
        if row.get("candidate_ids") != expected:
            raise ValueError("retained hunt candidate/cell accounting differs")
    return []


def validate_hunt_result(root: Path, repo: Path, task: dict, cells: list[dict], result: Any, threat: dict | None = None, repositories: list[dict] | None = None, routing: dict | None = None, *, scan: Path | None = None, raise_integrity: bool = False) -> list[str]:
    """Return worker acceptance errors; finalization must propagate integrity failures."""
    try:
        return _validate_hunt_result(root, repo, task, cells, result, threat, repositories, routing, scan=scan)
    except ValueError as exc:
        if raise_integrity:
            raise
        return [str(exc)]


def _validate_hunt_result(root: Path, repo: Path, task: dict, cells: list[dict], result: Any, threat: dict | None = None, repositories: list[dict] | None = None, routing: dict | None = None, *, scan: Path | None = None) -> list[str]:
    module = _validator_module(root)
    if scan is not None and (scan / "run-manifest.json").is_file():
        manifest = json.loads((scan / "run-manifest.json").read_text())
        if manifest.get("attempt_id") and not current_assessment(result, manifest):
            raise ValueError("current hunt result requires its assigned assessment attempt")
    schema = json.loads((root / "schemas/v2/hunt-result.schema.json").read_text(encoding="utf-8"))
    errors = module.Validator(schema).collect(result, schema)
    if not repositories:
        errors.append("authorized repository inventory is required")
    if not isinstance(result, dict):
        return errors
    task_id = str(task.get("id", ""))
    try:
        validate_provenance(result.get("provenance"), routing or {}, "vulnops-deepdive-chunk", f"sast/deepdive/{task_id}.json")
    except ValueError as exc:
        errors.append(f"$.provenance: {exc}")
    if result.get("task_id") != task_id:
        errors.append(f"$.task_id must match assigned task {task_id!r}")
    expected_ids = [str(cell.get("id")) for cell in cells]
    cell_map = {str(cell.get("id")): cell for cell in cells}
    rows = [row for row in result.get("cell_results", []) if isinstance(row, dict)]
    row_ids = [str(row.get("cell_id", "")) for row in rows]
    if len(row_ids) != len(set(row_ids)):
        errors.append("$.cell_results contains duplicate cell IDs")
    if set(row_ids) != set(expected_ids) or len(row_ids) != len(expected_ids):
        errors.append("$.cell_results must contain exactly one result for every assigned cell")
    elif row_ids != expected_ids:
        errors.append("$.cell_results must preserve assigned cell order")

    if errors:
        return errors
    amendments = result.get("model_amendments", [])
    objectives, questions = validate_registry(
        (threat or {}).get("attack_objectives", []), (threat or {}).get("investigation_questions", []))
    new_objectives = [item["entity"] for item in amendments if item["kind"] == "objective"]
    new_questions = [item["entity"] for item in amendments if item["kind"] == "question"]
    for entity in [*new_objectives, *new_questions]:
        if entity.get("owner") != f"sast/deepdive/{task_id}.json":
            raise ValueError("objective/question amendment must belong to the assigned worker")
    objectives, questions = validate_registry(new_objectives, new_questions,
        inherited_objectives=objectives, inherited_questions=questions,
        scan=scan, target=repo, repositories=repositories)
    for cell in cells:
        validate_binding(cell, objectives, questions)
    for field in ("objective", "question"):
        if task.get(field + "_ids") != list(dict.fromkeys(cell[field + "_id"] for cell in cells)):
            raise ValueError("task objective/question union differs from assigned cells")
    for amendment in amendments:
        validate_binding(amendment, objectives, questions)
    known_ids = {str(entity.get("id")) for values in (threat or {}).values() if isinstance(values, list)
                 for entity in values if isinstance(entity, dict)}
    for index, amendment in enumerate(amendments):
        entity = amendment.get("entity", {})
        identity = str(amendment.get("id", ""))
        if identity in known_ids or entity.get("id") != identity:
            errors.append(f"$.model_amendments[{index}] must introduce a unique matching entity ID")
        known_ids.add(identity)
        if amendment["kind"] == "objective" and entity.get("id") != amendment["objective_id"]:
            errors.append(f"$.model_amendments[{index}] objective differs from its binding")
        if amendment["kind"] == "question" and (
                entity.get("id") != amendment["question_id"] or entity.get("objective_id") != amendment["objective_id"]):
            errors.append(f"$.model_amendments[{index}] question differs from its binding")
        entity_sources = [entity["path"]] if "path" in entity else []
        for key in ("files", "source_files", "source_refs", "evidence_refs"):
            values = entity.get(key, [])
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                errors.append(f"$.model_amendments[{index}].entity.{key} must be source references")
                continue
            entity_sources.extend(values)
        anchors, _ = classify_refs(scan, repo, repositories, amendment.get("source_refs", []),
                                  owner=f"sast/deepdive/{task_id}.json",
                                  field=f"model_amendments[{index}].source_refs",
                                  affected_item_ids=[identity], kind="source")
        classify_refs(scan, repo, repositories, entity_sources,
                      owner=f"sast/deepdive/{task_id}.json", field=f"model_amendments[{index}].entity",
                      affected_item_ids=[identity], kind="mixed" if amendment["kind"] in {"objective", "question"} else "source")
        if not anchors:
            errors.append(f"$.model_amendments[{index}] requires a resolved source anchor before changing model control")
    threat = effective_threat_model(threat or {}, amendments)
    reachable_by_cell = {}
    for row in rows:
        cell_id = str(row.get("cell_id", ""))
        cell = cell_map[cell_id]
        for value in (row, row["checkpoint"]):
            validate_binding(value, objectives, questions)
            if any(value[key] != cell[key] for key in ("objective_id", "question_id")):
                raise ValueError("hunt result/checkpoint changed the assigned objective/question")
        reachable, source_errors = validate_source_expansions(module, repo, cell_map.get(cell_id, {}), row, repositories)
        reachable_by_cell[cell_id] = reachable
        errors.extend(f"$.cell_results[{cell_id}]: {error}" for error in source_errors)
        resolution = row.get("resolution", {})
        outcome = resolution.get("outcome")
        allowed = {"finding": {"established"}, "clean": {"contradicted"}, "not_applicable": {"contradicted"},
                   "shallow": {"locally_unresolved", "externally_blocked", "budget_deferred"}, "failed": {"execution_failed"}}
        if outcome not in allowed.get(row.get("status"), set()):
            errors.append(f"$.cell_results[{cell_id}] lifecycle and resolution disagree")
        if outcome == "externally_blocked" and not str(resolution.get("missing_fact", "")).strip():
            errors.append(f"$.cell_results[{cell_id}] externally_blocked requires the exact missing fact")
        if outcome in {"established", "contradicted"} and not resolution.get("evidence_refs"):
            errors.append(f"$.cell_results[{cell_id}] resolved claim requires evidence")
        checkpoint = row.get("checkpoint", {})
        if outcome in {"locally_unresolved", "externally_blocked", "budget_deferred"} and (
                not str(checkpoint.get("remaining_question", "")).strip() or not str(checkpoint.get("next_step", "")).strip()):
            errors.append(f"$.cell_results[{cell_id}] unresolved work requires an actionable checkpoint")
    candidates = [item for item in result.get("candidates", []) if isinstance(item, dict)]
    candidate_schema = json.loads((root / "schemas/v2/candidate-finding.schema.json").read_text(encoding="utf-8"))
    candidate_validator = module.Validator(candidate_schema)
    for index, candidate in enumerate(candidates):
        errors.extend(message.replace("$", f"$.candidates[{index}]", 1) for message in candidate_validator.collect(candidate, candidate_schema))
        errors.extend(message.replace("$", f"$.candidates[{index}]", 1) for message in module.semantic_errors(candidate, "candidate", repo))
        classify_refs(scan, repo, repositories, candidate.get("evidence_refs", []),
                      owner=f"sast/deepdive/{task_id}.json", field=f"candidates[{index}].evidence_refs",
                      affected_item_ids=[candidate.get("id")])
    candidate_ids = [str(item.get("id", "")) for item in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        errors.append("$.candidates contains duplicate worker-local IDs")
    candidate_map = {str(item.get("id", "")): item for item in candidates}
    for index, candidate in enumerate(candidates):
        if candidate.get("task_id") != task_id:
            errors.append(f"$.candidates[{index}].task_id must match the assigned task")
        validate_binding(candidate, objectives, questions)
        referenced = [str(item) for item in candidate.get("cell_ids", [])]
        if not referenced or any(cell_id not in cell_map for cell_id in referenced):
            errors.append(f"$.candidates[{index}].cell_ids must resolve within the assigned task")
            continue
        for cell_id in referenced:
            if any(candidate[key] != cell_map[cell_id][key] for key in ("objective_id", "question_id")):
                raise ValueError("candidate changed its source cell objective/question")
            if candidate.get("attack_class_id") != cell_map[cell_id].get("attack_class_id"):
                errors.append(f"$.candidates[{index}].attack_class_id does not match cell {cell_id!r}")
        referenced_cells = [cell_map[cell_id] for cell_id in referenced if cell_id in cell_map]
        expected_domain = referenced_cells[0].get("domain") if referenced_cells else None
        expected_methods = list(dict.fromkeys(str(ref) for cell in referenced_cells for ref in cell.get("methodology_refs", [])))
        expected_lenses = list(dict.fromkeys(str(ref) for cell in referenced_cells for ref in cell.get("lenses", [])))
        if candidate.get("domain") != expected_domain:
            errors.append(f"$.candidates[{index}].domain does not match its cells")
        if candidate.get("methodology_refs") != expected_methods:
            errors.append(f"$.candidates[{index}].methodology_refs do not match its cells")
        if candidate.get("lenses") != expected_lenses:
            errors.append(f"$.candidates[{index}].lenses do not match its cells")
        assigned_files = set().union(*(reachable_by_cell.get(cell_id, set()) for cell_id in referenced))
        locations = [candidate.get("root_cause_location", {}), *candidate.get("trace", [])]
        for location in locations:
            if isinstance(location, dict) and str(location.get("file", "")) not in assigned_files:
                errors.append(f"$.candidates[{index}] cites an unattributed source location")

    for index, row in enumerate(rows):
        cell_id = str(row.get("cell_id", ""))
        cell = cell_map.get(cell_id)
        if cell is None:
            continue
        expected_candidates = [
            candidate_id
            for candidate_id, candidate in candidate_map.items()
            if cell_id in {str(item) for item in candidate.get("cell_ids", [])}
        ]
        if row.get("candidate_ids") != expected_candidates:
            errors.append(f"$.cell_results[{index}].candidate_ids do not match candidates for {cell_id!r}")
        status = row.get("status")
        if expected_candidates and status != "finding":
            errors.append(f"$.cell_results[{index}].status must be finding when candidates reference the cell")
        if not expected_candidates and status == "finding":
            errors.append(f"$.cell_results[{index}].status cannot be finding without a candidate")
        assigned_entrypoints = {str(item) for item in cell.get("entrypoint_ids", [])}
        assigned_entrypoints.update(str(item["id"]) for item in threat.get("entrypoints", []))
        for traced in row.get("entrypoints_traced", []):
            entrypoint = _entrypoint_id(str(traced))
            if entrypoint not in assigned_entrypoints:
                errors.append(f"$.cell_results[{index}] traced entrypoint {entrypoint!r} needs a source-backed local amendment")
        if status in {"finding", "clean"}:
            for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"):
                if not row.get(key):
                    errors.append(f"$.cell_results[{index}].{key} is required for {status}")
        if status == "not_applicable":
            if not row.get("files_reviewed") or not row.get("entrypoints_traced"):
                errors.append(f"$.cell_results[{index}] not_applicable requires source and entrypoint review")
            if len(str(row.get("reason", "")).strip()) < 12:
                errors.append(f"$.cell_results[{index}] not_applicable requires a substantive source-backed reason")

    for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"):
        if result.get(key) != _ordered_union(rows, key):
            errors.append(f"$.{key} must equal the ordered union of cell_results.{key}")
    statuses = {str(row.get("status")) for row in rows}
    expected_status = "failed" if "failed" in statuses else "shallow" if "shallow" in statuses else "ok"
    if result.get("status") != expected_status:
        errors.append(f"$.status must be {expected_status!r} for its cell results")
    attributed = set().union(*reachable_by_cell.values())
    for amendment in amendments:
        if not {_source_path(ref) for ref in amendment["source_refs"]}.intersection(attributed):
            errors.append(f"model amendment {amendment['id']!r} lacks an attributed source anchor")
        if amendment["kind"] in {"objective", "question"} and not {
                _source_path(ref) for ref in amendment["entity"]["evidence_refs"]}.intersection(attributed):
            errors.append(f"model amendment {amendment['id']!r} definition lacks an attributed source anchor")
    if isinstance(threat, dict):
        classes = {str(item.get("id")): item for item in threat.get("attack_classes", []) if isinstance(item, dict)}
        subsystems = {str(item.get("id")): item for item in threat.get("subsystems", []) if isinstance(item, dict)}
        threats = {str(item.get("id")): item for item in threat.get("threats", []) if isinstance(item, dict)}
        assets = {str(item.get("id")) for item in threat.get("assets", []) if isinstance(item, dict)}
        entrypoints = {str(item.get("id")): item for item in threat.get("entrypoints", []) if isinstance(item, dict)}
        boundaries = {str(item.get("id")) for item in threat.get("trust_boundaries", []) if isinstance(item, dict)}
        surfaces = {str(item.get("id")) for item in threat.get("security_surfaces", []) if isinstance(item, dict)}
        surfaces.update(str(value) for subsystem in subsystems.values() for value in subsystem.get("security_surface_ids", []))
        for index, rabbit in enumerate(result.get("rabbit_holes", [])):
            if not isinstance(rabbit, dict):
                continue
            validate_binding(rabbit, objectives, questions)
            if questions[rabbit["question_id"]].get("equivalent_to"):
                errors.append(f"$.rabbit_holes[{index}] equivalent question cannot obtain duplicate work")
            if rabbit["security_question"] != questions[rabbit["question_id"]]["security_question"]:
                errors.append(f"$.rabbit_holes[{index}] differs from its registered question")
            attack_id = str(rabbit.get("attack_class_id", ""))
            subsystem_id = str(rabbit.get("subsystem", ""))
            attack_class = classes.get(attack_id)
            subsystem = subsystems.get(subsystem_id)
            if attack_class is None or attack_class.get("owner") != "sast":
                errors.append(f"$.rabbit_holes[{index}] must reference a SAST-owned attack class")
            if subsystem is None:
                errors.append(f"$.rabbit_holes[{index}] references an unknown subsystem")
                continue
            if not set(rabbit.get("surface_ids", [])).issubset(surfaces):
                errors.append(f"$.rabbit_holes[{index}] references an unknown surface")
            files = {str(item) for item in rabbit.get("files", [])}
            if not files.intersection(attributed):
                errors.append(f"$.rabbit_holes[{index}] lacks an attributed discovery anchor")
            for relative in files:
                path = authorized_source_file(module, repo, relative, repositories)
                if path is None or not path.is_file():
                    errors.append(f"$.rabbit_holes[{index}] references missing target file {relative!r}")
            rabbit_entrypoints = {str(item) for item in rabbit.get("entrypoint_ids", [])}
            for entrypoint_id in rabbit_entrypoints:
                entrypoint = entrypoints.get(entrypoint_id)
                if entrypoint is None:
                    errors.append(f"$.rabbit_holes[{index}] entrypoint requires a local model amendment")
            rabbit_boundaries = {str(item) for item in rabbit.get("boundary_ids", [])}
            if not rabbit_boundaries.issubset(boundaries):
                errors.append(f"$.rabbit_holes[{index}] references an unknown boundary")
            cited_threats = [threats.get(str(item)) for item in rabbit.get("threat_ids", [])]
            if any(item is None for item in cited_threats):
                errors.append(f"$.rabbit_holes[{index}] references an unknown threat")
            if not set(str(item) for item in rabbit.get("asset_ids", [])).issubset(assets):
                errors.append(f"$.rabbit_holes[{index}] references an unknown asset")
    hunt_evidence_diagnostics(scan, repo, repositories, result)
    return errors


__all__ = ["validate_hunt_result", "effective_threat_model", "validate_source_expansions"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_path", type=Path)
    parser.add_argument("packet", type=Path)
    parser.add_argument("result", type=Path)
    parser.add_argument("--review", action="store_true", help="validate a reviewer return against the validation queue")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
        result = json.loads(args.result.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[sast-contract] ERROR: {exc}", file=sys.stderr)
        return 1
    scan = args.packet.parent.parent if args.review else args.packet.parent.parent.parent
    try:
        context = json.loads((scan / "run-manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[sast-contract] ERROR: authorized repository inventory unavailable: {exc}", file=sys.stderr)
        return 2
    if args.review:
        try:
            if args.packet.resolve() != (scan / "sast/validation-queue.json").resolve() or not isinstance(packet, list):
                raise ValueError("review input must be the canonical validation queue")
            candidates = [item for item in packet if isinstance(item, dict) and item.get("id") == result.get("candidate_id")]
            if len(candidates) != 1:
                raise ValueError("review must own exactly one queued candidate")
            if args.result.resolve() != (scan / f"sast/verify/{candidates[0]['id']}.json").resolve():
                raise ValueError("review publication is outside its canonical owner path")
            errors = validate_review_result(root, args.repo_path.resolve(), candidates[0], result,
                                           scan=scan, repositories=context.get("repositories", []),
                                           routing=context.get("model_routing", {}))
        except (ValueError, KeyError, TypeError) as exc:
            print(f"[sast-contract] INTEGRITY: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            threat = json.loads((scan / "sast/threat-model.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            threat = {}
        current_ids = {item.get("id") for item in result.get("model_amendments", []) if isinstance(item, dict)}
        threat = effective_threat_model(threat, [item for item in packet.get("model_amendments", []) if item.get("id") not in current_ids])
        errors = validate_hunt_result(root, args.repo_path.resolve(), packet.get("task", {}), packet.get("cells", []), result, threat,
                                      context.get("repositories", []), context.get("model_routing"), scan=scan)
    if errors:
        for message in errors:
            print(f"[sast-contract] ERROR: {message}", file=sys.stderr)
        return 1
    print("[sast-contract] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
