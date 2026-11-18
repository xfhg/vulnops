"""Owner-bound attacker goals and proof questions, never inferred capabilities."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from evidence_refs import SCAN_NAMESPACES, EvidenceIssue, validate_evidence_refs


OWNER = re.compile(r"(?:sast/threat-model\.json|sast/deepdive/[A-Za-z0-9][A-Za-z0-9_.-]*\.json|campaign-planning/discovery\.json|intrusion/waves/[0-9]{3}\.json|gap-exploration/plan\.json)\Z")


def stable_id(prefix: str, owner: str, local_key: str) -> str:
    return prefix + hashlib.sha256("\0".join((owner, local_key)).encode()).hexdigest()[:12].upper()


def validate_registry(objectives, questions, *, inherited_objectives=None, inherited_questions=None,
                      scan=None, target=None, repositories=None):
    """Validate explicit definitions and extend, but never overwrite, inherited identities."""
    result = []
    for rows, inherited, prefix, fields in (
        (objectives, inherited_objectives, "OBJ-", ("starting_actor", "controlled_material", "resource_scope", "desired_effect", "success_condition")),
        (questions, inherited_questions, "Q-", ("objective_id", "security_question", "route", "proof_obligation", "novelty_reason")),
    ):
        known = dict(inherited or {})
        seen = set()
        if not isinstance(rows, list):
            raise ValueError("objective and question definitions must be arrays")
        for row in rows:
            if not isinstance(row, dict) or any(not isinstance(row.get(key), str) or not row[key].strip()
                                               for key in ("id", "owner", "local_key", *fields)):
                raise ValueError("objective/question requires explicit owner, identity and scoped goal/proof fields")
            identity = row["id"]
            if not OWNER.fullmatch(row["owner"]) or ".." in row["owner"]:
                raise ValueError("unknown objective/question owning authority")
            if identity != stable_id(prefix, row["owner"], row["local_key"]):
                raise ValueError("objective/question ID differs from its stable owner/local key")
            if identity in seen or identity in known and known[identity] != row:
                raise ValueError("duplicate or conflicting objective/question definition")
            seen.add(identity)
            refs = row.get("evidence_refs")
            if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs):
                raise ValueError("objective/question requires source anchors")
            source_refs = [ref for ref in refs if ref.split("/", 1)[0] not in SCAN_NAMESPACES]
            if not source_refs:
                raise ValueError("artifact-only objective/question cannot acquire scheduling authority")
            if target is not None and identity not in known:
                anchored = False
                for ref in refs:
                    try:
                        artifacts = validate_evidence_refs(scan, Path(target), repositories or [], [ref], owner=row["owner"])
                        anchored = anchored or ref not in artifacts
                    except EvidenceIssue:
                        # Local citation gaps remain accounted by owning phase diagnostics.
                        continue
                if not anchored:
                    raise ValueError("objective/question requires a resolved authorized source anchor")
            known[identity] = row
        result.append(known)
    objective_map, question_map = result
    for row in objective_map.values():
        parent = row.get("parent_objective_id")
        if parent is not None and (parent not in objective_map or parent == row["id"]):
            raise ValueError("new objective requires a distinct registered parent")
        ancestry = {row["id"]}
        while parent is not None:
            if parent not in objective_map:
                raise ValueError("objective ancestry references an unknown parent")
            if parent in ancestry:
                raise ValueError("objective ancestry cannot cycle")
            ancestry.add(parent)
            parent = objective_map[parent].get("parent_objective_id")
    obligations = {}
    for row in question_map.values():
        if row["objective_id"] not in objective_map:
            raise ValueError("question references an unknown objective")
        equivalent = row.get("equivalent_to")
        if equivalent is not None and (equivalent not in question_map or equivalent == row["id"] or
                                      question_map[equivalent]["objective_id"] != row["objective_id"] or
                                      question_map[equivalent].get("equivalent_to")):
            raise ValueError("equivalent question must bind a canonical question of the same objective")
        obligation = (row["objective_id"], row["route"].strip().casefold(), row["proof_obligation"].strip().casefold())
        if not equivalent and obligation in obligations:
            raise ValueError("repeated objective route/proof obligation requires explicit equivalent disposition")
        if not equivalent:
            obligations[obligation] = row["id"]
    return objective_map, question_map


def validate_binding(row, objectives, questions):
    question = questions.get(row.get("question_id"))
    if row.get("objective_id") not in objectives or question is None or question["objective_id"] != row["objective_id"]:
        raise ValueError("unknown or mismatched objective/question binding")


def validate_investigation_document(scan, target, repositories, document, kind):
    """Shared ThreatModel/hunt semantic gate; descriptive text never grants identity."""
    objectives, questions = validate_registry(document["attack_objectives"], document["investigation_questions"],
        scan=scan, target=target if kind == "threat-model" else None, repositories=repositories)
    if kind == "threat-model":
        if any(row["owner"] != "sast/threat-model.json" for row in [*objectives.values(), *questions.values()]):
            raise ValueError("initial objectives/questions must belong to ThreatModel")
        rows = document["hunt_mappings"]
    elif kind == "hunt-plan":
        if scan is None:
            raise ValueError("hunt-plan objective validation requires its scan authority")
        initial = _read(scan, "sast/threat-model.json")
        if initial is None:
            raise ValueError("hunt plan requires its initial threat model")
        expected_objectives, expected_questions = validate_registry(
            initial["attack_objectives"], initial["investigation_questions"])
        added_objectives, added_questions = _definitions({"model_amendments": document.get("model_amendments", [])})
        expected_objectives, expected_questions = validate_registry(added_objectives, added_questions,
            inherited_objectives=expected_objectives, inherited_questions=expected_questions)
        if objectives != expected_objectives or questions != expected_questions:
            raise ValueError("hunt registry differs from immutable threat model and attributed amendments")
        for row in [*added_objectives, *added_questions]:
            if not row["owner"].startswith("sast/deepdive/"):
                raise ValueError("SAST objective/question amendments require worker ownership")
            owner = _read(scan, row["owner"])
            if owner is None or row not in sum(_definitions(owner), []):
                raise ValueError("hunt amendment differs from its worker publication")
        rows = document["cells"]
        cells = {row["id"]: row for row in rows}
        for task in document["tasks"]:
            assigned = [cells[identity] for identity in task["cell_ids"]]
            for field in ("objective", "question"):
                if task[field + "_ids"] != list(dict.fromkeys(row[field + "_id"] for row in assigned)):
                    raise ValueError("hunt task objective/question union differs from assigned cells")
            for continuation in task.get("continuations", []):
                cell = cells[continuation["cell_id"]]
                for value in (continuation, continuation["checkpoint"]):
                    if any(value[key] != cell[key] for key in ("objective_id", "question_id")):
                        raise ValueError("hunt continuation changed its assigned objective/question")
    else:
        raise ValueError("unknown investigation document kind")
    for row in rows:
        validate_binding(row, objectives, questions)
        question = questions[row["question_id"]]
        if question.get("equivalent_to"):
            raise ValueError("equivalent questions cannot acquire duplicate hunt ownership")
        if row["security_question"] != question["security_question"]:
            raise ValueError("hunt question differs from registered proof obligation")
    identities = [(row["objective_id"], row["question_id"]) for row in rows]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate hunt objective/question ownership")
    return objectives, questions

def _read(scan, relative):
    path = Path(scan) / relative
    if not path.exists():
        return None
    if path.is_symlink() or not path.resolve().is_relative_to(Path(scan).resolve()):
        raise ValueError("objective authority escapes scan")
    return json.loads(path.read_text(encoding="utf-8"))


def _definitions(document, *, gap=False):
    collections = [list(document.get("objectives" if gap else "attack_objectives", [])),
                   list(document.get("questions" if gap else "investigation_questions", []))]
    for amendment in document.get("model_amendments", []):
        if amendment.get("kind") in {"objective", "question"}:
            collection = collections[amendment["kind"] == "question"]
            entity = amendment["entity"]
            existing = next((row for row in collection if row["id"] == entity["id"]), None)
            if existing is not None and existing != entity:
                raise ValueError("amendment conflicts with inherited objective/question definition")
            if existing is None:
                collection.append(entity)
    return collections


def load_registry(scan: Path, *, through: str = "intrusion", include_supplementary: bool = False):
    if through not in {"sast", "campaign", "intrusion"}:
        raise ValueError("unknown objective registry phase boundary")
    scan = Path(scan)
    paths = ["sast/threat-model.json", "sast/hunt-plan.json"]
    ledger = _read(scan, "sast/coverage-ledger.json") or {}
    paths.extend(f"sast/deepdive/{row['id']}.json" for row in ledger.get("tasks", []) if row.get("artifact_valid"))
    if through in {"campaign", "intrusion"}:
        paths.extend(("campaign-planning/evidence-index.json", "campaign-planning/discovery.json", "campaign-planning/campaign-plan.json"))
    if through == "intrusion":
        paths.extend(str(path.relative_to(scan)) for path in sorted((scan / "intrusion/waves").glob("[0-9][0-9][0-9].json")))
    objectives, questions = {}, {}
    for relative in paths:
        document = _read(scan, relative)
        if document is None:
            continue
        new_objectives, new_questions = _definitions(document)
        objectives, questions = validate_registry(new_objectives, new_questions,
            inherited_objectives=objectives, inherited_questions=questions)
    if include_supplementary:
        from gap_dossier import accepted
        supplement = accepted(scan)
        if supplement:
            objectives, questions = validate_registry(supplement["objectives"], supplement["questions"],
                inherited_objectives=objectives, inherited_questions=questions)
    for row in [*objectives.values(), *questions.values()]:
        owner = _read(scan, row["owner"])
        if owner is None:
            raise ValueError("objective/question defining authority is missing")
        owner_objectives, owner_questions = _definitions(owner, gap=row["owner"]=="gap-exploration/plan.json")
        if row not in [*owner_objectives, *owner_questions]:
            raise ValueError("objective/question does not match its owning definition")
    return objectives, questions


def load_objectives(scan: Path) -> dict[str, dict]:
    return load_registry(scan, include_supplementary=True)[0]


def load_questions(scan: Path) -> dict[str, dict]:
    return load_registry(scan, include_supplementary=True)[1]


def _published_ref_cap() -> int:
    """Synthesis publication caps projected question_outcome evidence_refs; owner_ref keeps the full record."""
    root = Path(__file__).resolve().parent.parent
    schema = json.loads((root / "schemas/v2" / "synthesis-findings.schema.json").read_text())
    item = schema["$defs"]["objectiveAssessment"]["properties"]["question_outcomes"]["items"]
    return int(item["properties"]["evidence_refs"]["maxItems"])


def load_question_outcomes(scan: Path) -> list[dict]:
    """Project source-owned obligations, retaining mixed routes rather than declaring goal closure."""
    objectives, questions = load_registry(scan, include_supplementary=True)
    rows = []
    for relative, collection in (("sast/coverage-ledger.json", "cells"), ("intrusion/intrusion-results.json", "results")):
        document = _read(scan, relative) or {}
        for row in document.get(collection, []):
            if "question_id" not in row:
                continue
            validate_binding(row, objectives, questions)
            resolution = row.get("resolution", {})
            if resolution:
                rows.append({"objective_id": row["objective_id"], "question_id": row["question_id"],
                             **{key: resolution[key] for key in ("outcome", "reason", "evidence_refs", "missing_fact", "next_action")},
                             "owner_ref": f"{relative}:{row.get('id', row.get('campaign_id'))}"})
    from gap_dossier import accepted
    supplement = accepted(scan)
    if supplement:
        for record in supplement["results"]:
            result = _read(scan, record["ref"])
            validate_binding(result, objectives, questions)
            resolution = result["resolution"]
            rows.append({"objective_id": result["objective_id"], "question_id": result["question_id"],
                         **{key: resolution[key] for key in ("outcome", "reason", "missing_fact", "next_action")},
                         "evidence_refs": resolution["source_refs"], "owner_ref": record["ref"]})
        covered_gap = {row["question_id"] for row in rows}
        for closure in supplement["non_promoted"]:
            if closure.get("question_id") not in questions or closure["question_id"] in covered_gap:
                continue
            rows.append({"objective_id": closure["objective_id"], "question_id": closure["question_id"],
                         **{key: closure[key] for key in ("outcome", "reason", "missing_fact", "next_action")},
                         "evidence_refs": questions[closure["question_id"]]["evidence_refs"],
                         "owner_ref": "gap-exploration/results.json"})
            covered_gap.add(closure["question_id"])
    covered = {row["question_id"] for row in rows}
    plan = _read(scan, "campaign-planning/campaign-plan.json") or {}
    dispositions = {row.get("question_id"): row for row in plan.get("question_dispositions", [])}
    for question in questions.values():
        if question["id"] in covered:
            continue
        disposition = dispositions.get(question["id"], {})
        rows.append({"objective_id": question["objective_id"], "question_id": question["id"], "outcome": "not_investigated",
                     "reason": disposition.get("reason", "No source-owned question resolution was published."),
                     "evidence_refs": question["evidence_refs"], "missing_fact": question["proof_obligation"],
                     "next_action": question["security_question"], "owner_ref": f"{question['owner']}:{question['id']}"})
    cap = _published_ref_cap()
    for row in rows:
        row["evidence_refs"] = list(dict.fromkeys(row["evidence_refs"]))[:cap]
    return rows
