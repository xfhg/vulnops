from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from sast_contract import validate_hunt_result, effective_threat_model
from objective_fixtures import objective_binding, objective_registry, record_read_registry
from objective_contract import stable_id
ROUTING = {"agents": {"vulnops-deepdive-chunk": "test/red:high", "vulnops-verify-one": "test/red:high"}}


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


planner = load_module("source_hunt_plan", "build-hunt-plan.py")
finalizer = load_module("source_finalizer", "finalize-sast.py")


def fixture():
    binding = objective_binding(record_read_registry())
    cell = {**binding, "id": "CELL-1", "mapping_id": "MAP-1", "subsystem": "SUB-1", "domain": "general",
            "attack_class_id": "access_control", "methodology_refs": ["skill://vulnops-attack-general"],
            "lenses": ["skill://vulnops-access-control"], "files": ["gateway/handler.py"],
            "entrypoint_ids": ["EP-1"], "boundary_ids": ["B-1"], "surface_ids": ["B-1"],
            "threat_ids": [], "asset_ids": [], "attacker": "tenant user", "priority": "critical",
            "security_question": "Can a tenant user read another tenant's record?", "stop_conditions": ["Ownership rejects the supplied record"],
            "applicability_reason": "User supplied record crosses ownership boundary", "evidence_refs": ["gateway/handler.py:1"],
            "owner": "sast", "status": "planned", "lead_key": None, "disposition_reason": "source question"}
    task = planner.make_task("H001", [cell], 1, 0)
    provenance = {"actor": "vulnops-deepdive-chunk", "selector": ROUTING["agents"]["vulnops-deepdive-chunk"], "artifact_ref": "sast/deepdive/H001.json"}
    files = ["gateway/handler.py", "service/implementation.py", "shared/dto.py"]
    expansions = [{"source": files[1], "predecessor": files[0], "reason": "handler dispatches to implementation"},
                  {"source": files[2], "predecessor": files[1], "reason": "implementation deserializes record DTO without owner binding"}]
    candidate = {**binding, "schema_version": "2.0", "id": "LOCAL-1", "task_id": task["id"], "cell_ids": [cell["id"]],
                 "finding_kind": "code", "title": "Tenant record read bypasses ownership", "category": "authorization",
                 "attack_class_id": "access_control", "domain": "general", "methodology_refs": cell["methodology_refs"],
                 "severity": "high", "confidence": "high", "lenses": cell["lenses"],
                 "attacker": {"perspective": "tenant user", "starting_access": "authenticated tenant", "boundary_crossed": "record ownership"},
                 "intended_behavior": "Only the record owner can read the record", "root_cause": "Implementation reads the DTO record without binding caller ownership",
                 "root_cause_location": {"file": files[1], "line": 1, "scope": "read_record", "mechanism": "missing ownership check"},
                 "trace": [{"kind": "entrypoint", "file": files[0], "line": 1, "scope": "handler", "description": "tenant supplies record reference"},
                           {"kind": "propagation", "file": files[2], "line": 1, "scope": "Record", "description": "DTO retains supplied record reference"},
                           {"kind": "sink", "file": files[1], "line": 1, "scope": "read_record", "description": "implementation reads record without ownership"}],
                 "conditions": [], "impact": "Read another tenant's record", "remediation": "Bind record ownership to caller", "evidence_refs": [f + ":1" for f in files],
                 "mitigations_checked": ["No record ownership binding before read"]}
    candidate["contributors"] = [provenance]
    row = {**binding, "cell_id": cell["id"], "status": "finding", "reason": "Complete source trace establishes missing ownership",
           "files_reviewed": files, "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["read_record"],
           "mitigations_checked": ["ownership binding"], "candidate_ids": ["LOCAL-1"], "evidence_refs": candidate["evidence_refs"],
           "source_expansions": expansions,
           "resolution": {"outcome": "established", "reason": "Ownership omitted in complete trace", "next_action": "independent source verification", "evidence_refs": candidate["evidence_refs"], "missing_fact": ""},
           "checkpoint": {**binding, "established_facts": ["service/implementation.py:1 omits caller ownership"], "contradicted_paths": [], "remaining_question": "", "files_reviewed": files, "next_step": "", "expected_results": []}}
    result = {"schema_version": "2.0", "task_id": task["id"], "status": "ok", "cell_results": [row], "candidates": [candidate],
              "model_amendments": [], "hardening_notes": [], "positive_patterns": [], "rabbit_holes": [], "wishlist_items": [], "warnings": [], "errors": []}
    result["provenance"] = provenance
    for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"):
        result[key] = row[key]
    return cell, task, result


class SourceInvestigationTests(unittest.TestCase):
    def test_source_provenance_rejects_forged_owner_selector_and_reference(self):
        cell, task, result = fixture()
        for key, value in (("actor", "vulnops-verify-one"), ("selector", "test/red:low"),
                           ("artifact_ref", "sast/deepdive/OTHER.json")):
            forged = copy.deepcopy(result)
            forged["provenance"][key] = value
            errors = validate_hunt_result(ROOT, ROOT, task, [cell], forged, record_read_registry(), routing=ROUTING)
            self.assertTrue(any("$.provenance" in error for error in errors), errors)

    def test_complete_same_question_three_repository_trace_and_local_amendment(self):
        # A01/A02: implementation and DTO remain in the handler's investigation.
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for name, text in {"gateway/handler.py": "def handler(record): return read_record(record)\n",
                               "service/implementation.py": "def read_record(record): return storage[Record(record).id]\n",
                               "shared/dto.py": "class Record:\n    def __init__(self, record): self.id = record\n    def write(self, value): storage[self.id] = value\n"}.items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            repositories = [{"path": name} for name in ("gateway", "service", "shared")]
            cell, task, result = fixture()
            self.assertEqual(validate_hunt_result(ROOT, repo, task, [cell], result, record_read_registry(), repositories, ROUTING), [])
            no_remediation = copy.deepcopy(result)
            del no_remediation["candidates"][0]["remediation"]
            self.assertEqual(validate_hunt_result(ROOT, repo, task, [cell], no_remediation, record_read_registry(), repositories, ROUTING), [])
            for field in ("attacker", "root_cause", "impact", "mitigations_checked", "trace"):
                unsupported = copy.deepcopy(no_remediation)
                del unsupported["candidates"][0][field]
                self.assertTrue(validate_hunt_result(ROOT, repo, task, [cell], unsupported, record_read_registry(), repositories, ROUTING), field)
            binding = objective_binding(record_read_registry())
            self.assertEqual(task["objective_ids"], [binding["objective_id"]])
            self.assertEqual(task["question_ids"], [binding["question_id"]])
            for location in ("candidate", "cell_result", "checkpoint"):
                denied = copy.deepcopy(result)
                bound = denied["candidates"][0] if location == "candidate" else denied["cell_results"][0]
                if location == "checkpoint":
                    bound = bound["checkpoint"]
                bound["question_id"] = "Q-UNKNOWN"
                self.assertTrue(validate_hunt_result(ROOT, repo, task, [cell], denied, record_read_registry(), repositories, ROUTING), location)
            # A03: discover a new entrypoint without rewriting the initial model.
            initial = {**record_read_registry(), "entrypoints": []}
            original = copy.deepcopy(initial)
            result["model_amendments"] = [{**binding, "id": "EP-NEW", "kind": "entrypoint", "question": cell["security_question"],
                                           "source_refs": ["shared/dto.py:1"], "entity": {"id": "EP-NEW", "path": "shared/dto.py"}}]
            result["cell_results"][0]["entrypoints_traced"].append("EP-NEW")
            self.assertEqual(validate_hunt_result(ROOT, repo, task, [cell], result, initial, repositories, ROUTING), [])
            self.assertEqual(initial, original)
            self.assertEqual(effective_threat_model(initial, result["model_amendments"])["entrypoints"][0]["id"], "EP-NEW")
            # The lead is admitted before asset/threat/boundary taxonomy is complete.
            initial["attack_classes"] = [{"id": "access_control", "owner": "sast"}]
            result["model_amendments"].append({**binding, "id": "SUB-NEW", "kind": "subsystem",
                "question": "Can a second consumer bypass record ownership?", "source_refs": ["shared/dto.py:1"],
                "entity": {"id": "SUB-NEW", "files": ["shared/dto.py"]}})
            discovered = objective_registry(
                ["shared/dto.py:1-3"], owner="sast/deepdive/H001.json", local_key="second-consumer-write",
                starting_actor="authenticated tenant user", controlled_material="shared record DTO reference",
                resource_scope="another tenant's record consumed by the second implementation",
                desired_effect="alter another tenant's stored record",
                success_condition="second consumer commits caller-selected changes to a record owned by a different tenant",
                security_question="Can a second consumer bypass record ownership?",
                route="shared DTO passed to the second record consumer",
                proof_obligation="establish whether the second consumer binds record ownership before writing",
                novelty_reason="new unauthorized-write effect, distinct from the initial unauthorized-read goal")
            discovered["attack_objectives"][0]["parent_objective_id"] = cell["objective_id"]
            discovered_binding = objective_binding(discovered)
            for kind, key in (("objective", "attack_objectives"), ("question", "investigation_questions")):
                entity = discovered[key][0]
                result["model_amendments"].append({**discovered_binding, "id": entity["id"], "kind": kind,
                    "question": discovered["investigation_questions"][0]["security_question"],
                    "source_refs": ["shared/dto.py:1-3"], "entity": entity})
            result["rabbit_holes"] = [{**discovered_binding, "subsystem": "SUB-NEW", "attack_class_id": "access_control",
                "surface_ids": [], "threat_ids": [], "asset_ids": [], "boundary_ids": [], "attacker": "tenant user",
                "entrypoint_ids": ["EP-NEW"], "security_question": "Can a second consumer bypass record ownership?",
                "stop_conditions": ["consumer enforces owner"], "priority": "high", "reason": "shared DTO exposes a second consumer",
                "expected_added_value": "resolve an independent ownership boundary", "files": ["shared/dto.py"], "evidence_refs": ["shared/dto.py:1-3"]}]
            self.assertEqual(validate_hunt_result(ROOT, repo, task, [cell], result, initial, repositories, ROUTING), [])
            self.assertEqual(initial["entrypoints"], [])
            effective = effective_threat_model(initial, result["model_amendments"])
            self.assertEqual(effective["attack_objectives"], initial["attack_objectives"] + discovered["attack_objectives"])
            self.assertEqual(effective["investigation_questions"], initial["investigation_questions"] + discovered["investigation_questions"])
            for kind in ("objective", "question"):
                denied = copy.deepcopy(result)
                denied["model_amendments"] = [row for row in denied["model_amendments"] if row["kind"] != kind]
                self.assertTrue(validate_hunt_result(ROOT, repo, task, [cell], denied, initial, repositories, ROUTING), kind)
            denied = copy.deepcopy(result)
            denied["model_amendments"][-1]["entity"]["owner"] = "sast/deepdive/OTHER.json"
            self.assertTrue(validate_hunt_result(ROOT, repo, task, [cell], denied, initial, repositories, ROUTING))
            # A04: missing attribution, unregistered siblings, traversal and escaping links fail.
            denied = copy.deepcopy(result)
            denied["cell_results"][0]["source_expansions"] = []
            self.assertTrue(validate_hunt_result(ROOT, repo, task, [cell], denied, initial, repositories, ROUTING))
            (repo / "unregistered").mkdir()
            (repo / "unregistered/extra.py").write_text("pass\n")
            with tempfile.TemporaryDirectory() as outside:
                external = Path(outside) / "secret.py"
                external.write_text("pass\n")
                (repo / "gateway/link.py").symlink_to(external)
                for unsafe in ("gateway/link.py", "../secret.py", "unregistered/extra.py", "shared/missing.py"):
                    denied = copy.deepcopy(result)
                    denied["cell_results"][0]["source_expansions"].append({"source": unsafe, "predecessor": "gateway/handler.py", "reason": "follow dependency"})
                    self.assertTrue(validate_hunt_result(ROOT, repo, task, [cell], denied, initial, repositories, ROUTING), unsafe)
                    if unsafe != "shared/missing.py":
                        with self.assertRaises(ValueError):
                            validate_hunt_result(ROOT, repo, task, [cell], denied, initial, repositories,
                                                 ROUTING, raise_integrity=True)

    def test_gapfill_continues_checkpoint_before_equal_impact_new_branch_and_preserves_resolution(self):
        cell, task, result = fixture()
        row = result["cell_results"][0]
        row["status"] = "shallow"
        result["status"] = "shallow"
        result["candidates"] = []
        row["candidate_ids"] = []
        row["resolution"]["outcome"] = "locally_unresolved"
        row["checkpoint"]["remaining_question"] = "Does the storage policy bind owner?"
        row["checkpoint"]["next_step"] = "inspect storage policy binding"
        row["checkpoint"]["expected_results"] = ["binding contradicts claim", "no binding completes trace"]
        limits = {"max_hunt_tasks": 2, "max_hunt_questions": 3, "max_gapfill_rounds": 1, "max_attempts": 2, "max_concurrency": 1, "context_packet_bytes": 65536}
        registry = record_read_registry()
        next_question = {**registry["investigation_questions"][0],
                         "id": stable_id("Q-", "sast/threat-model.json", "alternate-record-route"),
                         "local_key": "alternate-record-route", "security_question": "Does the alternate entrypoint bind record ownership?",
                         "route": "other/branch.py alternate entrypoint to the shared record consumer",
                         "proof_obligation": "establish owner enforcement for the alternate entrypoint",
                         "novelty_reason": "independent alternate entrypoint, not the unfinished storage-policy trace",
                         "evidence_refs": ["other/branch.py:1"]}
        registry["investigation_questions"].append(next_question)
        new_cell = {**cell, "id": "CELL-NEW", "mapping_id": "MAP-NEW", "files": ["other/branch.py"], "entrypoint_ids": ["EP-OTHER"], "status": "deferred",
                    "question_id": next_question["id"], "security_question": next_question["security_question"],
                    "evidence_refs": next_question["evidence_refs"]}
        plan = {**registry, "schema_version": "2.0", "run_id": "run", "budget": limits, "cells": [cell, new_cell], "tasks": [task]}
        with tempfile.TemporaryDirectory() as temporary:
            scan = Path(temporary)
            (scan / "sast/deepdive").mkdir(parents=True)
            (scan / "sast/deepdive/H001.json").write_text(json.dumps(result))
            (scan / "sast/coverage-ledger.json").write_text(json.dumps({"tasks": [{"id": "H001", "status": "shallow"}], "cells": [{"id": cell["id"], "status": "shallow"}]}))
            planned = planner.gapfill(ROOT, plan, scan, registry)
            continuation = planned["tasks"][-1]
            self.assertEqual(continuation["cell_ids"], [cell["id"]])
            self.assertEqual(continuation["continuations"][0]["checkpoint"], row["checkpoint"])
            self.assertEqual(continuation["objective_ids"], task["objective_ids"])
            self.assertEqual(continuation["question_ids"], task["question_ids"])
            self.assertEqual(planned["attack_objectives"], registry["attack_objectives"])
            self.assertEqual(planned["investigation_questions"], registry["investigation_questions"])
            self.assertIn("budget deferred", new_cell["disposition_reason"])
            ledger = {"cells": [{"status": "shallow", "resolution": row["resolution"], "checkpoint": row["checkpoint"]}]}
            finalizer.close_depth_limited_cells(ledger)
            self.assertEqual(ledger["cells"][0]["resolution"]["outcome"], "locally_unresolved")
            self.assertEqual(ledger["cells"][0]["checkpoint"], row["checkpoint"])
            # External facts do not receive a blind local-source continuation.
            plan = {**registry, "budget": limits, "cells": [cell], "tasks": [task]}
            row["resolution"]["outcome"] = "externally_blocked"
            row["resolution"]["missing_fact"] = "production storage policy"
            (scan / "sast/deepdive/H001.json").write_text(json.dumps(result))
            self.assertEqual(len(planner.gapfill(ROOT, plan, scan, registry)["tasks"]), 1)


if __name__ == "__main__":
    unittest.main()
