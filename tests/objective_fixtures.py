"""Explicit source-backed objective records for disposable synthetic test inputs."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from objective_contract import stable_id


def objective_registry(evidence_refs, *, local_key, starting_actor, controlled_material,
                       resource_scope, desired_effect, success_condition, security_question,
                       route, proof_obligation, novelty_reason, owner="sast/threat-model.json"):
    objective = {"id": stable_id("OBJ-", owner, local_key), "owner": owner, "local_key": local_key,
                 "starting_actor": starting_actor, "controlled_material": controlled_material,
                 "resource_scope": resource_scope, "desired_effect": desired_effect,
                 "success_condition": success_condition, "evidence_refs": list(evidence_refs)}
    question = {"id": stable_id("Q-", owner, local_key), "owner": owner, "local_key": local_key,
                "objective_id": objective["id"], "security_question": security_question,
                "route": route, "proof_obligation": proof_obligation, "novelty_reason": novelty_reason,
                "evidence_refs": list(evidence_refs)}
    return {"attack_objectives": [objective], "investigation_questions": [question]}


def objective_binding(registry):
    question = registry["investigation_questions"][0]
    return {"objective_id": question["objective_id"], "question_id": question["id"]}


def record_read_registry(*, owner="sast/threat-model.json", local_key="tenant-record-read"):
    return objective_registry(
        ["gateway/handler.py:1", "service/implementation.py:1", "shared/dto.py:1"],
        owner=owner, local_key=local_key, starting_actor="authenticated tenant user",
        controlled_material="record reference supplied to handler",
        resource_scope="records owned by another tenant in service storage",
        desired_effect="read another tenant's record without ownership authorization",
        success_condition="handler returns a different tenant's record selected by the caller",
        security_question="Can a tenant user read another tenant's record?",
        route="gateway handler dispatches to service read_record through shared Record DTO",
        proof_obligation="establish caller-controlled record selection and missing ownership enforcement before return",
        novelty_reason="initial record-read ownership obligation across the handler, DTO and storage consumer")
