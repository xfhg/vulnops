"""Synthetic source-only gap fixtures; no target execution, network or model calls."""
from copy import deepcopy
import json
from pathlib import Path

import gap_exploration_contract as gap
from harness_contract import DEFAULT_GAP_EXPLORATION_BUDGETS
from objective_contract import stable_id

SOURCE = """def alternate_route(request, store):
    key = request.path_parameter('key')
    actor = request.authenticated_user
    if actor is None:
        return 'denied'
    return store.read(key)

def guarded_route(request, store):
    key = request.path_parameter('key')
    if store.owner(key) != request.authenticated_user:
        return 'denied'
    return store.read(key)
"""


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class GapFixture:
    def __init__(self, root, *, linked=False):
        self.root = Path(root).resolve()
        self.base = self.root / "run"
        self.source = self.root / "source"
        self.base.mkdir(parents=True)
        self.source.mkdir()
        (self.source / "routes.py").write_text(SOURCE)
        self.context = {"run_id": "gap-fixture", "attempt_id": "attempt-1", "scan_base": str(self.base),
            "source_root": str(self.source), "repo_path": str(self.source), "repositories": [{"path": ".", "name": "fixture"}],
            "mode": "ordinary", "status": "incomplete", "paths": {"gap_exploration": str(self.base / "gap-exploration")},
            "gap_exploration_budget": {"enabled": True, **DEFAULT_GAP_EXPLORATION_BUDGETS["balanced"]},
            "intrusion_budget": {"continuation_tasks": 0}, "budget": {"max_tasks": 0, "max_attempts": 1},
            "model_routing": {"agents": {"vulnops-gap-exploration": "fixture/explorer:high", "vulnops-gap-investigator": "fixture/investigator:high",
                "vulnops-advantage-gap-exploration": "fixture/explorer:high", "vulnops-advantage-gap-investigator": "fixture/investigator:high"}}}
        self.manifest_name = "advantage-manifest.json" if linked else "run-manifest.json"
        if linked:
            self.context.update(execution_kind="advantage", source_run_id="baseline", mode="scan", baseline={"execution_id": "baseline", "root": str(self.root / "baseline"), "catalog_ref": "baseline/catalog.json"})
            self.context["phases"] = {"baseline": "ok", "planning": "ok", "investigation": "ok", "gap-exploration": "running", "synthesis": "pending"}
            save(self.base / "baseline/catalog.json", {"schema_version": "2.0", "run_id": "gap-fixture", "records": []})
            save(self.base / "planning/plan.json", {"schema_version": "2.0", "run_id": "gap-fixture", "assignments": []})
            self.predecessor = "investigation/results.json"
        else:
            self.context["phases"] = {"recon": "ok", "tool-collection": "ok", "sast": "ok", "campaign-planning": "ok", "intrusion": "ok", "gap-exploration": "running", "synthesis": "pending"}
            save(self.base / "tool-collection/collection.json", {"schema_version": "2.0", "run_id": "gap-fixture", "findings": []})
            self.predecessor = "intrusion/intrusion-results.json"
        save(self.base / self.predecessor, {"schema_version": "2.0", "run_id": "gap-fixture", "results": [], "attack_objectives": [], "investigation_questions": []})
        self.persist()

    def persist(self):
        if not gap.linked(self.context):
            save(self.base / self.manifest_name, self.context)
        save(self.root / "context.json", self.context)

    def accepted(self, status):
        self.context["phases"]["gap-exploration"] = status
        self.persist()

    def failed_coordinator(self, reason):
        self.context["phases"]["gap-exploration"] = "failed"
        attempts = self.context["gap_exploration_budget"]["max_attempts"]
        row = {"id": gap.coordinator(self.context), "phase": "gap-exploration", "status": "failed",
            "attempts": attempts, "attempt_id": self.context["attempt_id"], "artifact": None,
            "error": reason, "failure_kind": "execution_failed",
            "failure_history": [{"attempt": attempts, "attempt_id": self.context["attempt_id"],
                "kind": "execution_failed", "error": reason}]}
        if gap.linked(self.context):
            row["generation"] = 0
            row["failure_history"][0]["generation"] = 0
        save(self.base / "task-ledger.json", {"schema_version": "2.0", "run_id": self.context["run_id"], "tasks": [row]})
        self.persist()

    def plan(self, tasks=("GapA",)):
        prepared = gap.prepare_inputs(self.context)
        owner = "gap-exploration/plan.json"
        objective = {"id": stable_id("OBJ-", owner, "read-other-object"), "owner": owner, "local_key": "read-other-object",
            "starting_actor": "Authenticated ordinary account", "controlled_material": "Object path key", "resource_scope": "Another account's stored object",
            "desired_effect": "Read another account's object", "success_condition": "The alternate route returns the selected object's contents without checking ownership",
            "evidence_refs": ["routes.py:1-6"]}
        result = gap.envelope(self.context, inputs=prepared["inputs"], budget=prepared["budget"], objectives=[objective] if tasks else [], questions=[], seeds=[], assignments=[], graph_questions=[])
        for task in tasks:
            question = {"id": stable_id("Q-", owner, task), "owner": owner, "local_key": task, "objective_id": objective["id"],
                "security_question": "Does the alternate caller enforce object ownership before reading?", "route": "alternate_route/" + task,
                "proof_obligation": "Establish actor control and object ownership enforcement before store.read", "novelty_reason": "The sibling guarded route does not cover this alternate caller", "evidence_refs": ["routes.py:1-12"]}
            seed = {"id": "Seed-" + task, "objective_id": objective["id"], "question_id": question["id"], "actor": "Authenticated account", "source_view": "base",
                "source_refs": ["routes.py:1-6"], "input_refs": [self.predecessor], "missing_fact": question["proof_obligation"], "prior_outcome": "locally_unresolved",
                "changed_hypothesis": "", "counterevidence_response": "", "external_blocker": "", "local_answer": "", "expected_value": "Resolve whether another entrypoint bypasses ownership",
                "stop_condition": "Stop after proving either ownership enforcement or its absence on the actual caller", "next_action": "Inspect both callers and store invocation", "disposition": "selected"}
            assignment = {"task_id": task, "seed_id": seed["id"], "objective_id": objective["id"], "question_id": question["id"], "source_view": "base", "proof_obligation": question["proof_obligation"], "expected_outcome": "Source-established alternate caller candidate or exact defeated route"}
            result["questions"].append(question)
            result["seeds"].append(seed)
            result["assignments"].append(assignment)
        return result

    def result(self, task="GapA", *, outcome="established", candidates=1, dispatch=None):
        if dispatch is None:
            dispatch = gap.dispatch_worker(self.context, task)
        assigned = dispatch["packet"]["assignment"]
        provenance = {"actor": gap.actor(self.context, True), "selector": dispatch["selector"], "artifact_ref": f"gap-exploration/results/{task}.json"}
        if gap.linked(self.context):
            provenance["execution_id"] = self.context["run_id"]
        value = gap.envelope(self.context, task_id=task, objective_id=assigned["objective_id"], question_id=assigned["question_id"], source_view="base", attempt=dispatch["attempt"],
            provenance=provenance, resolution={"outcome": outcome, "reason": "Source traces the selected actor and read to the actual ownership decision", "missing_fact": "" if outcome in {"established", "contradicted"} else "Deployment authority is not available locally", "next_action": "" if outcome in {"established", "contradicted"} else "Obtain the authorized deployment policy", "source_refs": ["routes.py:1-12"]}, candidates=[], graph_receipt_refs=[], limitations=[])
        reasons = {"actor_control": "The path parameter selects the storage key at line 2", "reachability": "Authenticated accounts enter the route and call read at line 6", "security_boundary": "The sibling operation explicitly treats object ownership as a boundary at line 10", "impact": "The selected object's read result is returned directly at line 6", "intervening_controls": "The only alternate-route guard checks authentication, unlike the sibling's owner guard", "conditions_compatible": "The same authenticated account and selected key reach the read without identity conversion"}
        for index in range(candidates):
            value["candidates"].append({"id": f"GC-{task}-{index + 1}", "classification": "new_root", "baseline_ids": [], "root_cause_key": "routes.py:6:object-ownership", "terminal_impact": "Authenticated cross-account object read", "reason": "An alternate caller checks authentication but omits the sibling's ownership guard", "evidence_refs": ["routes.py:1-12"], "source_locations": [{"file": "routes.py", "line": 6}], "objective_ids": [assigned["objective_id"]], "question_id": assigned["question_id"], "source_view": "base", "proof": {name: {"outcome": "established", "reason": reason, "source_refs": ["routes.py:1-12"]} for name, reason in reasons.items()}, "causal_trace": [{"step": "Attacker selects the object key in the path", "source_refs": ["routes.py:1-3"]}, {"step": "Authenticated route returns the selected object without checking owner", "source_refs": ["routes.py:4-6"]}], "inspected_controls": [{"control": "Authentication guard and sibling owner check", "effect": "Authentication gates entry but alternate route never calls the owner guard", "source_refs": ["routes.py:3-12"]}], "conditions": ["Attacker has an authenticated account and another object's key"]})
        return value
