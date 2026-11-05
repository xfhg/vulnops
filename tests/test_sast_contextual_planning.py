from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_run_lifecycle import activate_publisher


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
sys.path.insert(0, str(ROOT / "scripts"))
from model_routing import audit_routing, load_routing
from model_identity import contributor_union
from sast_contract import validate_hunt_result, validate_sast_evidence_accounting
from objective_contract import stable_id
from objective_fixtures import objective_binding, objective_registry
ROUTING = audit_routing(load_routing(ROOT))


def hunt_provenance(task_id: str) -> dict:
    actor = "vulnops-deepdive-chunk"
    return {"actor": actor, "selector": ROUTING["agents"][actor], "artifact_ref": f"sast/deepdive/{task_id}.json"}


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False, env=merged)


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def mapping_registry(mapping_id: str, class_id: str, source_file: str = "app.py") -> dict:
    return objective_registry(
        [f"{source_file}:1"], local_key=mapping_id, starting_actor="remote caller",
        controlled_material="value passed to the public entry function",
        resource_scope=f"trusted service operation behind the {class_id} boundary",
        desired_effect=f"invoke the trusted service operation without satisfying {class_id} controls",
        success_condition=f"caller-controlled input reaches the protected operation despite the required {class_id} check",
        security_question=f"Can remote input violate the {class_id} boundary?",
        route=f"{source_file} entry function to the trusted service consumer",
        proof_obligation=f"establish reachability and enforcement of the {class_id} check before consumption",
        novelty_reason=f"initial {class_id} proof obligation for contextual mapping {mapping_id}")


def threat_model(files: list[str], mappings: list[dict], classes: list[dict], surfaces: list[str] | None = None) -> dict:
    surfaces = surfaces or ["TB-1"]
    registries = [mapping_registry(row["id"], row["attack_class_id"], row["source_files"][0]) for row in mappings]
    return {
        "schema_version": "2.0",
        "attack_objectives": [row for registry in registries for row in registry["attack_objectives"]],
        "investigation_questions": [row for registry in registries for row in registry["investigation_questions"]],
        "repository_profile": {"kinds": ["backend"], "tags": [], "comparable": {"name": None, "basis": "fixture", "confidence": "not_applicable"}},
        "assets": [{"id": "A-1", "name": "service integrity", "sensitivity": "high", "description": "trusted service behavior", "evidence_refs": [f"{files[0]}:1"]}],
        "trust_boundaries": [
            {"id": surface, "source_trust": "remote", "target_trust": "service", "description": f"boundary {surface}", "evidence_refs": [f"{files[0]}:1"]}
            for surface in surfaces
        ],
        "entrypoints": [{"id": "EP-1", "path": files[0], "kind": "http", "subsystem_ids": ["SUB-1"], "trust_boundary_ids": surfaces, "evidence_refs": [f"{files[0]}:1"]}],
        "subsystems": [{"id": "SUB-1", "name": "service", "files": files, "entrypoints": ["EP-1"], "security_surface_ids": surfaces, "risk": "critical", "evidence_refs": [f"{files[0]}:1"]}],
        "attack_classes": classes,
        "threats": [{"id": "TH-1", "title": "remote misuse", "attacker": "remote caller", "asset_ids": ["A-1"], "entrypoint_ids": ["EP-1"], "attack_class_ids": [item["id"] for item in classes], "description": "remote input crosses a service boundary", "evidence_refs": [f"{files[0]}:1"]}],
        "hunt_mappings": mappings,
        "assumptions": [],
        "evidence_refs": [f"{files[0]}:1"],
        "warnings": [],
        "errors": [],
    }


def attack_class(class_id: str, lens: str) -> dict:
    return {
        "id": class_id,
        "title": class_id.replace("_", " ").title(),
        "domain": "general",
        "owner": "sast",
        "methodology_ref": f"skill://vulnops-attack-general#{class_id.replace('_', '-')}",
        "lenses": [lens],
        "reason": "A concrete remote source flow requires this specialist lens.",
        "evidence_refs": ["app.py:1"],
        "custom": False,
    }


def mapping(mapping_id: str, class_id: str, surface: str = "TB-1", source_file: str = "app.py") -> dict:
    return {
        **objective_binding(mapping_registry(mapping_id, class_id, source_file)),
        "id": mapping_id,
        "attack_class_id": class_id,
        "subsystem_id": "SUB-1",
        "surface_ids": [surface],
        "threat_ids": ["TH-1"],
        "asset_ids": ["A-1"],
        "attacker": "remote caller",
        "entrypoint_ids": ["EP-1"],
        "boundary_ids": [surface],
        "source_files": [source_file],
        "security_question": f"Can remote input violate the {class_id} boundary?",
        "stop_conditions": ["The assigned source flow cannot reach a security-sensitive sink"],
        "priority": "critical",
        "applicability_reason": "The assigned entrypoint and boundary expose a concrete source flow.",
        "evidence_refs": [f"{source_file}:1"],
    }


def clean_result(task_id: str, cell_id: str, rabbits: list[dict], binding: dict) -> dict:
    row = {**binding, "cell_id": cell_id, "status": "clean", "reason": "The cited source control defeats this specific path.",
           "files_reviewed": ["app.py"], "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["return"],
           "mitigations_checked": ["constant return"], "candidate_ids": [], "evidence_refs": ["app.py:1"],
           "source_expansions": [],
           "resolution": {"outcome": "contradicted", "reason": "Constant return does not consume input", "next_action": "close this path",
                          "evidence_refs": ["app.py:1"], "missing_fact": ""},
           "checkpoint": {**binding, "established_facts": [], "contradicted_paths": ["app.py:1 constant return"], "remaining_question": "",
                          "files_reviewed": ["app.py"], "next_step": "", "expected_results": []}}
    result = {"schema_version": "2.0", "task_id": task_id, "status": "ok", "cell_results": [row], "candidates": [],
              "model_amendments": [], "rabbit_holes": rabbits, "hardening_notes": [], "positive_patterns": [],
              "wishlist_items": [], "warnings": [], "errors": []}
    result["provenance"] = hunt_provenance(task_id)
    for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"):
        result[key] = row[key]
    return result


class ContextualPlanningTests(unittest.TestCase):
    def test_selected_attack_class_without_contextual_mapping_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry(value):\n    return value\n")
            classes = [attack_class("access_control", "skill://vulnops-access-control"), attack_class("business_logic", "skill://vulnops-logic-bug")]
            document = threat_model(["app.py"], [mapping("HM-ACCESS", "access_control")], classes)
            path = base / "threat-model.json"; write(path, document)
            validated = run(PYTHON, "scripts/validate-json.py", "schemas/v2/threat-model.schema.json", str(path), "--semantic", "threat-model", "--target", str(target))
            self.assertNotEqual(validated.returncode, 0)
            self.assertIn("has no contextual hunt mapping", validated.stderr)

    def test_planner_does_not_cross_product_classes_over_unmapped_surfaces(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry(value):\n    return value\n")
            scan = base / "scan"; context = base / "context.json"
            write(context, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan), "model_routing": ROUTING, "repositories": [{"path": "."}]})
            classes = [attack_class("access_control", "skill://vulnops-access-control")]
            write(scan / "sast/threat-model.json", threat_model(["app.py"], [mapping("HM-SSH", "access_control", "TB-SSH")], classes, ["TB-SSH", "TB-REPORT", "TB-FILESYSTEM"]))
            validated = run(PYTHON, "scripts/validate-json.py", "schemas/v2/threat-model.schema.json", str(scan / "sast/threat-model.json"), "--semantic", "threat-model", "--target", str(target))
            self.assertEqual(validated.returncode, 0, validated.stderr)
            result = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context))
            self.assertEqual(result.returncode, 0, result.stderr)
            plan_validated = run(PYTHON, "scripts/validate-json.py", "schemas/v2/hunt-plan.schema.json", str(scan / "sast/hunt-plan.json"), "--semantic", "hunt-plan", "--target", str(target))
            self.assertEqual(plan_validated.returncode, 0, plan_validated.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(len(plan["cells"]), 1)
            self.assertEqual(plan["cells"][0]["surface_ids"], ["TB-SSH"])
            packet = json.loads(next((scan / "sast/hunt-tasks").glob("*.json")).read_text())
            model = json.loads((scan / "sast/threat-model.json").read_text())
            for key in ("attack_objectives", "investigation_questions"):
                self.assertEqual(plan[key], model[key])
                self.assertEqual(packet[key], model[key])
            binding = objective_binding(model)
            self.assertEqual({key: plan["cells"][0][key] for key in binding}, binding)
            self.assertEqual(plan["tasks"][0]["objective_ids"], [binding["objective_id"]])
            self.assertEqual(plan["tasks"][0]["question_ids"], [binding["question_id"]])
            self.assertEqual(packet["cells"], plan["cells"])
            self.assertNotIn("TB-REPORT", json.dumps(packet))
            self.assertNotIn("TB-FILESYSTEM", json.dumps(packet))

    def test_two_task_allocation_round_robins_subsystems(self) -> None:
        spec = importlib.util.spec_from_file_location("hunt_plan", ROOT / "scripts/build-hunt-plan.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        mappings = [
            {**mapping("A1", "access_control", "BA1", "a1.py"), "subsystem_id": "A", "entrypoint_ids": ["EA1"]},
            {**mapping("A2", "business_logic", "BA2", "a2.py"), "subsystem_id": "A", "entrypoint_ids": ["EA2"]},
            {**mapping("B1", "access_control", "BB1", "b1.py"), "subsystem_id": "B", "entrypoint_ids": ["EB1"]},
        ]
        threat = threat_model(["a1.py", "a2.py", "b1.py"], mappings,
                              [attack_class("access_control", "access"), attack_class("business_logic", "logic")])
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory)
            context = {"run_id": "allocation", "depth": "quick",
                       "sast_budget": {"max_hunt_tasks": 2, "max_hunt_questions": 3,
                                       "max_gapfill_rounds": 0, "max_attempts": 2,
                                       "max_concurrency": 1, "context_packet_bytes": 65536}}
            plan = module.initial_plan(ROOT, scan, context, threat)
            self.assertEqual([task["subsystem"] for task in plan["tasks"]], ["A", "B"])
            cells = {cell["mapping_id"]: cell for cell in plan["cells"]}
            self.assertEqual([cells[key]["status"] for key in ("A1", "B1", "A2")],
                             ["planned", "planned", "deferred"])
            module.publish_task_packets(scan, plan, json.dumps(plan).encode())
            packets = [json.loads((scan / f"sast/hunt-tasks/{task['id']}.json").read_text())
                       for task in plan["tasks"]]
            self.assertEqual([packet["cells"][0]["mapping_id"] for packet in packets], ["A1", "B1"])

    def test_per_cell_contract_prevents_task_wide_finding_promotion(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry(value):\n    return sink(value)\ndef sink(value):\n    return value\n")
            scan = base / "scan"; context = base / "context.json"
            write(context, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan), "model_routing": ROUTING, "repositories": [{"path": "."}]})
            write(scan / "run-manifest.json", {"repositories": [{"path": "."}], "model_routing": ROUTING})
            environment = patch.dict(os.environ, activate_publisher(scan, json.loads(context.read_text()), "sast",
                                     {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context)}))
            environment.start()
            self.addCleanup(environment.stop)
            classes = [
                attack_class("access_control", "skill://vulnops-access-control"),
                attack_class("business_logic", "skill://vulnops-logic-bug"),
            ]
            write(scan / "sast/threat-model.json", threat_model(["app.py"], [mapping("HM-ACCESS", "access_control"), mapping("HM-LOGIC", "business_logic")], classes))
            built = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context))
            self.assertEqual(built.returncode, 0, built.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text()); task = plan["tasks"][0]; first, second = [next(cell for cell in plan["cells"] if cell["id"] == cell_id) for cell_id in task["cell_ids"]]
            candidate = {
                "objective_id": first["objective_id"], "question_id": first["question_id"],
                "schema_version": "2.0", "id": "LOCAL-1", "task_id": task["id"], "cell_ids": [first["id"]], "finding_kind": "code", "title": "Caller crosses the assigned authorization boundary", "category": "authorization", "attack_class_id": first["attack_class_id"], "domain": "general", "methodology_refs": first["methodology_refs"], "severity": "low", "confidence": "high",
                "attacker": {"perspective": "remote caller", "starting_access": "public input", "boundary_crossed": "service authorization"}, "intended_behavior": "Only authorized callers reach the sink.", "root_cause": "The entrypoint forwards input without the required authorization check.", "root_cause_location": {"file": "app.py", "line": 1, "scope": "entry", "mechanism": "missing authorization"},
                "trace": [{"kind": "entrypoint", "file": "app.py", "line": 1, "scope": "entry", "description": "caller input enters"}, {"kind": "sink", "file": "app.py", "line": 2, "scope": "sink", "description": "trusted sink receives input"}], "conditions": [], "impact": "Unauthorized use of the trusted sink.", "remediation": "Enforce authorization before dispatch.", "evidence_refs": ["app.py:1"], "lenses": first["lenses"], "mitigations_checked": ["No authorization guard exists before dispatch"]
            }
            row1 = {"cell_id": first["id"], "status": "finding", "reason": "A source-backed candidate exists.", "files_reviewed": ["app.py:1-2"], "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["sink"], "mitigations_checked": ["authorization guard"], "candidate_ids": ["LOCAL-1"], "evidence_refs": ["app.py:1"]}
            row2 = {"cell_id": second["id"], "status": "clean", "reason": "The workflow invariant holds.", "files_reviewed": ["app.py:1-2"], "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["sink"], "mitigations_checked": ["workflow invariant"], "candidate_ids": [], "evidence_refs": ["app.py:1"]}
            result = {"schema_version": "2.0", "task_id": task["id"], "status": "ok", "cell_results": [row1, row2], "files_reviewed": ["app.py:1-2"], "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["sink"], "mitigations_checked": ["authorization guard", "workflow invariant"], "candidates": [candidate], "hardening_notes": [], "positive_patterns": [], "rabbit_holes": [], "wishlist_items": [], "warnings": [], "errors": []}
            result["model_amendments"] = []
            result["provenance"] = hunt_provenance(task["id"])
            candidate["contributors"] = [result["provenance"]]
            for row in result["cell_results"]:
                assigned = next(cell for cell in (first, second) if cell["id"] == row["cell_id"])
                row.update(objective_id=assigned["objective_id"], question_id=assigned["question_id"])
                row["source_expansions"] = []
                row["resolution"] = {"outcome": "established" if row["status"] == "finding" else "contradicted",
                                     "reason": row["reason"], "next_action": "verify candidate or close the specific path",
                                     "evidence_refs": row["evidence_refs"], "missing_fact": ""}
                row["checkpoint"] = {"objective_id": row["objective_id"], "question_id": row["question_id"],
                                     "established_facts": [], "contradicted_paths": [], "remaining_question": "",
                                     "files_reviewed": row["files_reviewed"], "next_step": "", "expected_results": []}
            result_path = scan / "sast/deepdive" / f"{task['id']}.json"; write(result_path, result)
            checked = run(PYTHON, "scripts/sast_contract.py", str(target), str(scan / "sast/hunt-tasks" / f"{task['id']}.json"), str(result_path))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            aggregated = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan))
            self.assertEqual(aggregated.returncode, 0, aggregated.stderr)
            ledger = json.loads((scan / "sast/coverage-ledger.json").read_text()); statuses = {item["id"]: item["status"] for item in ledger["cells"]}
            self.assertEqual(statuses[first["id"]], "finding")
            self.assertEqual(statuses[second["id"]], "clean")
            for ref in ("app/app.py:1", "app.py:0", "app.py:5", "sast/deepdive/missing.json"):
                with self.subTest(original_ref=ref):
                    invalid = copy.deepcopy(result)
                    invalid["candidates"][0]["evidence_refs"] = [ref]
                    write(result_path, invalid)
                    rejected = run(PYTHON, "scripts/sast_contract.py", str(target), str(scan / "sast/hunt-tasks" / f"{task['id']}.json"), str(result_path))
                    self.assertEqual(rejected.returncode, 0, rejected.stderr)
                    aggregated = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan))
                    self.assertEqual(aggregated.returncode, 0, aggregated.stderr)
                    self.assertEqual(len(json.loads((scan / "sast/raw-findings.json").read_text())), 1)
                    self.assertEqual(len(json.loads((scan / "sast/validation-queue.json").read_text())), 1)
                    limited = json.loads((scan / "sast/coverage-ledger.json").read_text())
                    self.assertGreater(limited["evidence_quality"]["total"], 0)
                    self.assertEqual(next(row["status"] for row in limited["cells"] if row["id"] == second["id"]), "clean")
            write(result_path, result)
            aggregated = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan))
            self.assertEqual(aggregated.returncode, 0, aggregated.stderr)

            mixed = copy.deepcopy(result)
            mixed["candidates"][0]["evidence_refs"].append("sast/threat-model.json")
            self.assertEqual(validate_hunt_result(ROOT, target, task, [first, second], mixed, plan, repositories=[{"path": "."}],
                                                 routing=ROUTING, scan=scan), [])
            self.assertTrue(validate_hunt_result(ROOT, target, task, [first, second], mixed, plan,
                                                repositories=[{"path": "."}], routing=ROUTING))
            self.assertTrue(validate_hunt_result(ROOT, target, task, [first, second], result, plan, routing=ROUTING, scan=scan))

            queued = json.loads((scan / "sast/validation-queue.json").read_text())[0]
            reviewer = {"actor": "vulnops-verify-one", "selector": ROUTING["agents"]["vulnops-verify-one"],
                        "artifact_ref": f"sast/verify/{queued['id']}.json"}
            review = {"schema_version": "2.0", "id": "V-1", "candidate_id": queued["id"], "status": "source_verified",
                      "confidence": "high", "closure_reason": "Source trace establishes the missing check.",
                      "evidence_refs": ["app.py:1-2"], "provenance": reviewer,
                      "mechanical_checks": {key: True for key in ("schema", "paths", "lines", "trace_order", "target_unchanged")}}
            for ref in ("app/app.py:1", "app.py:2-1", "app.py:5", "sast/deepdive/missing.json"):
                with self.subTest(corrected_ref=ref):
                    review["corrections"] = [{"field": "evidence_refs", "before": "app.py:1", "after": ref, "reason": "correct source citation"}]
                    review["corrected_candidate"] = {**queued, "evidence_refs": [ref]}
                    write(scan / reviewer["artifact_ref"], review)
                    write(scan / "sast/validation-results.json", [review])
                    accepted = run(PYTHON, "scripts/validate-json.py", "schemas/v2/validation-result.schema.json",
                                   str(scan / reviewer["artifact_ref"]), "--semantic", "validation-result", "--target", str(target),
                                   env={"VULNOPS_AUDIT_CONTEXT": str(context)})
                    self.assertEqual(accepted.returncode, 0, accepted.stderr)
                    rejected = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), "--finalize",
                                   env={"VULNOPS_AUDIT_CONTEXT": str(context)})
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("evidence-limited source-review/deferral record", rejected.stderr)
                    self.assertFalse((scan / "sast/verified-findings.json").exists())
                    self.assertFalse((scan / "sast/phase-manifest.json").exists())
            review["corrections"] = [{"field": "evidence_refs", "before": "app.py:1", "after": "app.py:1-2", "reason": "include the sink"}]
            review["corrected_candidate"] = {**queued, "evidence_refs": ["app.py:1-2"]}
            review["extra_context"] = {"evidence_refs": ["../../inert"]}
            review["corrections"][0]["explanation_note"] = "Preserved only in the source-owned review"
            write(scan / reviewer["artifact_ref"], review)
            write(scan / "sast/validation-results.json", [review])
            accepted = run(PYTHON, "scripts/validate-json.py", "schemas/v2/validation-result.schema.json",
                           str(scan / reviewer["artifact_ref"]), "--semantic", "validation-result", "--target", str(target),
                           env={"VULNOPS_AUDIT_CONTEXT": str(context)})
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            finalized = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), "--finalize",
                            env={"VULNOPS_AUDIT_CONTEXT": str(context)})
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            verified = json.loads((scan / "sast/verified-findings.json").read_text())
            self.assertEqual(verified[0]["evidence_refs"], ["app.py:1-2"])
            self.assertEqual(verified[0]["contributors"], contributor_union([result["provenance"]], [reviewer]))
            before = {path: path.read_bytes() for path in scan.rglob("*") if path.is_file()}
            validate_sast_evidence_accounting(scan, ROUTING, source_root=target, repositories=[{"path": "."}])
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            accounting_path = scan / "sast/coverage-ledger.json"
            accounting = json.loads(accounting_path.read_text())
            empty_accounting = {key: value for key, value in accounting.items()
                                if key not in {"evidence_quality", "non_promoted"}}
            write(accounting_path, empty_accounting)
            validate_sast_evidence_accounting(scan, ROUTING, source_root=target, repositories=[{"path": "."}])
            accounting["evidence_quality"]["total"] += 1
            write(accounting_path, accounting)
            with self.assertRaisesRegex(ValueError, "evidence_quality differs"):
                validate_sast_evidence_accounting(scan, ROUTING, source_root=target, repositories=[{"path": "."}])
            accounting_path.write_bytes(before[accounting_path])
            forged = copy.deepcopy(verified)
            forged[0]["evidence_refs"] = ["missing.py:1"]
            write(scan / "sast/verified-findings.json", forged)
            with self.assertRaises(ValueError):
                validate_sast_evidence_accounting(scan, ROUTING, source_root=target, repositories=[{"path": "."}])
            (scan / "sast/verified-findings.json").write_bytes(before[scan / "sast/verified-findings.json"])
            invalid_optional = copy.deepcopy(review)
            invalid_optional["optional_support"] = [{
                "reference": "app.py:1-2", "obligation": "Authorization bypass",
                "independent_support": ["app.py:2"], "rationale": "This claims a resolved citation is unusable."}]
            write(scan / reviewer["artifact_ref"], invalid_optional)
            write(scan / "sast/validation-results.json", [invalid_optional])
            with self.assertRaises(ValueError):
                validate_sast_evidence_accounting(scan, ROUTING, source_root=target, repositories=[{"path": "."}])
            (scan / reviewer["artifact_ref"]).write_bytes(before[scan / reviewer["artifact_ref"]])
            (scan / "sast/validation-results.json").write_bytes(before[scan / "sast/validation-results.json"])
            equivalent = copy.deepcopy(result)
            equivalent["positive_patterns"] = [{"title": "Unrelated guard", "description": "A separate source observation",
                                                 "evidence_refs": ["missing.py:1"], "extra_context": "not evidence: ../../inert"}]
            equivalent["extra_context"] = {"evidence_refs": ["../../inert"]}
            write(result_path, equivalent)
            finalized = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), "--finalize",
                            env={"VULNOPS_AUDIT_CONTEXT": str(context)})
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            self.assertEqual(json.loads((scan / "sast/verified-findings.json").read_text()), verified)
            quality = json.loads((scan / "sast/coverage-ledger.json").read_text())["evidence_quality"]
            self.assertEqual(quality["total"], 1)
            unsafe = copy.deepcopy(result)
            unsafe["positive_patterns"] = [{"title": "Unsafe", "description": "Escaping declared reference", "evidence_refs": ["../escape.py:1"]}]
            self.assertTrue(validate_hunt_result(ROOT, target, task, [first, second], unsafe, plan,
                                                repositories=[{"path": "."}], routing=ROUTING, scan=scan))
            with self.assertRaises(ValueError):
                validate_hunt_result(ROOT, target, task, [first, second], unsafe, plan, repositories=[{"path": "."}],
                                     routing=ROUTING, scan=scan, raise_integrity=True)
            limited_review = copy.deepcopy(review)
            limited_review["status"] = "deferred"
            limited_review["corrected_candidate"]["evidence_refs"] = ["missing.py:1"]
            limited_review["corrections"][0]["after"] = "missing.py:1"
            limited_review["non_promoted"] = {
                "id": queued["id"], "input_refs": [f"sast/validation-queue.json:{queued['id']}"],
                "disposition": "evidence_limited", "reason": "Targeted review could not establish the downstream privileged effect.",
                "risk_context": "Remote input reaches the authorization boundary; downstream effect remains unknown.",
                "missing_fact": "Whether the downstream consumer performs the privileged effect.",
                "next_action": "Inspect the downstream consumer implementation.",
                "review": {"actor": reviewer["actor"], "selector": reviewer["selector"],
                           "action": "Trace the source entrypoint to the claimed privileged consumer.",
                           "result": "The available entrypoint does not establish the downstream effect.",
                           "evidence_refs": ["app.py:1-2"]}, "deferral": None}
            write(result_path, result)
            for disposition in ("review", "budget"):
                if disposition == "budget":
                    limited_review["non_promoted"]["review"] = None
                    limited_review["non_promoted"]["deferral"] = {
                        "kind": "budget", "reason": "The assigned verifier source-review allocation is exhausted after tracing the entrypoint."}
                write(scan / reviewer["artifact_ref"], limited_review)
                write(scan / "sast/validation-results.json", [limited_review])
                finalized = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), "--finalize",
                                env={"VULNOPS_AUDIT_CONTEXT": str(context)})
                self.assertEqual(finalized.returncode, 0, finalized.stderr)
                self.assertEqual(json.loads((scan / "sast/verified-findings.json").read_text()), [])
                accounting = json.loads((scan / "sast/coverage-ledger.json").read_text())
                self.assertEqual(accounting["non_promoted"][0]["id"], queued["id"])
                self.assertEqual(accounting["non_promoted"][0]["disposition"], "evidence_limited")
                self.assertEqual(len(json.loads((scan / "sast/validation-queue.json").read_text())), 1)

            result["cell_results"][1]["files_reviewed"] = ["outside.py:1"]
            write(result_path, result)
            rejected = run(PYTHON, "scripts/sast_contract.py", str(target), str(scan / "sast/hunt-tasks" / f"{task['id']}.json"), str(result_path))
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("unauthorized, missing, or unattributed", rejected.stderr)

    def test_gapfill_ranks_consequential_leads_and_preserves_exhausted_leads(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry():\n    return 1\n"); (target / "other.py").write_text("def other():\n    return 2\n")
            scan = base / "scan"; context = base / "context.json"
            write(context, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan), "model_routing": ROUTING, "repositories": [{"path": "."}]})
            write(scan / "run-manifest.json", {"repositories": [{"path": "."}], "model_routing": ROUTING})
            environment = patch.dict(os.environ, activate_publisher(scan, json.loads(context.read_text()), "sast",
                                     {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context)}))
            environment.start()
            self.addCleanup(environment.stop)
            classes = [attack_class("access_control", "skill://vulnops-access-control"), attack_class("business_logic", "skill://vulnops-logic-bug")]
            mappings = [mapping("HM-ACCESS", "access_control", source_file="app.py"), mapping("HM-LOGIC", "business_logic", source_file="other.py")]
            mappings[1]["priority"] = "low"
            write(scan / "sast/threat-model.json", threat_model(["app.py", "other.py"], mappings, classes))
            built = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context), env={"VULNOPS_SAST_QUICK_MAX_HUNT_TASKS": "2"})
            self.assertEqual(built.returncode, 0, built.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text()); self.assertEqual(len(plan["tasks"]), 1)
            settings = json.loads(context.read_text())
            settings["sast_budget"] = plan["budget"]
            write(context, settings)
            active_cell = plan["tasks"][0]["cell_ids"][0]
            write(scan / "sast/coverage-ledger.json", {"cells": [{"id": active_cell, "status": "clean"}], "tasks": [{"id": plan["tasks"][0]["id"], "status": "ok"}]})
            rabbit = {"subsystem": "SUB-1", "attack_class_id": "access_control", "surface_ids": ["TB-1"], "threat_ids": ["TH-1"], "asset_ids": ["A-1"], "attacker": "remote caller", "entrypoint_ids": ["EP-1"], "boundary_ids": ["TB-1"], "security_question": "Can the adjacent authorization consumer be bypassed?", "stop_conditions": ["The adjacent consumer is unreachable"], "priority": "critical", "reason": "The assigned source exposes an adjacent authorization consumer.", "expected_added_value": "Validate a distinct downstream authorization transition.", "files": ["app.py"], "evidence_refs": ["app.py:1"]}
            rabbit["evidence_refs"].append("missing.py:1")
            assigned = next(cell for cell in plan["cells"] if cell["id"] == active_cell)
            binding = {key: assigned[key] for key in ("objective_id", "question_id")}
            owner = f"sast/deepdive/{plan['tasks'][0]['id']}.json"
            question = {"id": stable_id("Q-", owner, "adjacent-consumer"), "owner": owner, "local_key": "adjacent-consumer",
                        "objective_id": binding["objective_id"], "security_question": rabbit["security_question"],
                        "route": "app.py entry to the adjacent authorization consumer",
                        "proof_obligation": "establish whether the adjacent consumer enforces authorization before consumption",
                        "novelty_reason": "separate downstream authorization transition not resolved by the initial entrypoint check",
                        "evidence_refs": ["app.py:1"]}
            rabbit.update(objective_id=question["objective_id"], question_id=question["id"])
            initial_result = clean_result(plan["tasks"][0]["id"], active_cell, [rabbit], binding)
            initial_result["model_amendments"] = [{"id": question["id"], "kind": "question", "entity": question,
                "objective_id": question["objective_id"], "question_id": question["id"],
                "question": question["security_question"], "source_refs": ["app.py:1"]}]
            write(scan / owner, initial_result)
            aggregated = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan))
            self.assertEqual(aggregated.returncode, 0, aggregated.stderr)
            self.assertEqual(json.loads((scan / "sast/coverage-ledger.json").read_text())["evidence_quality"]["total"], 1)
            gapfilled = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context), "--gapfill")
            self.assertEqual(gapfilled.returncode, 0, gapfilled.stderr)
            updated = json.loads((scan / "sast/hunt-plan.json").read_text()); self.assertEqual(len(updated["tasks"]), 2)
            self.assertTrue(updated["tasks"][-1]["cell_ids"][0].startswith("CELL-RABBIT-"))
            deferred = [cell for cell in updated["cells"] if cell["mapping_id"] in {"HM-ACCESS", "HM-LOGIC"} and cell["status"] == "deferred"]
            self.assertEqual(len(deferred), 1)
            later_rabbit = {**rabbit, "security_question": "Can a second adjacent authorization transition be bypassed?", "expected_added_value": "Record the distinct lead even after the scheduling round is exhausted."}
            owner = f"sast/deepdive/{updated['tasks'][-1]['id']}.json"
            later_question = {**question, "id": stable_id("Q-", owner, "second-transition"),
                              "owner": owner, "local_key": "second-transition",
                              "security_question": later_rabbit["security_question"],
                              "route": "app.py second adjacent consumer transition",
                              "proof_obligation": "establish authorization at the second downstream transition",
                              "novelty_reason": "a second consumer has its own independent ownership enforcement"}
            later_rabbit.update(question_id=later_question["id"])
            later_result = clean_result(updated["tasks"][-1]["id"], updated["tasks"][-1]["cell_ids"][0], [later_rabbit],
                                        {"objective_id": question["objective_id"], "question_id": question["id"]})
            later_result["model_amendments"] = [{"id": later_question["id"], "kind": "question", "entity": later_question,
                "objective_id": later_question["objective_id"], "question_id": later_question["id"],
                "question": later_question["security_question"], "source_refs": ["app.py:1"]}]
            write(scan / owner, later_result)
            aggregated = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan))
            self.assertEqual(aggregated.returncode, 0, aggregated.stderr)
            accepted = json.loads((scan / "sast/coverage-ledger.json").read_text())
            self.assertTrue(next(row for row in accepted["tasks"]
                                 if row["id"] == updated["tasks"][-1]["id"])["artifact_valid"])
            terminal = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context), "--gapfill")
            self.assertEqual(terminal.returncode, 0, terminal.stderr)
            exhausted = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(len(exhausted["tasks"]), 2)
            recorded = [cell for cell in exhausted["cells"] if cell.get("lead_key")]
            self.assertEqual(len(recorded), 2)
            self.assertEqual(recorded[-1]["status"], "deferred")

    def test_interrupted_packet_reservation_survives_without_ledger_publication(self) -> None:
        from test_recovery import PHASES, DIRS, TASKS
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "source"
            target.mkdir()
            (target / "app.py").write_text("def entry():\n    return 1\n")
            scan = base / "scan"
            context = base / "context.json"
            settings = {"run_id": "run", "attempt_id": "original", "depth": "quick",
                        "scan_base": str(scan), "repo_path": str(target), "source_root": str(target),
                        "repositories": [{"path": "."}]}
            write(context, settings)
            write(scan / "sast/threat-model.json", threat_model(
                ["app.py"], [mapping("HM-ACCESS", "access_control")],
                [attack_class("access_control", "skill://vulnops-access-control")]))
            first = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context))
            self.assertEqual(first.returncode, 0, first.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text())
            packets = {path: path.read_bytes() for path in (scan / "sast/hunt-tasks").glob("*.json")}
            write(scan / "run-manifest.json", {
                "schema_version": "2.0", "run_id": "run", "status": "incomplete",
                "phases": {phase: "ok" if index < 2 else "running" if index == 2 else "pending"
                           for index, phase in enumerate(PHASES)}})
            top_tasks = []
            for phase in PHASES[:2]:
                artifact = f"{DIRS[phase]}/accepted.json"
                write(scan / artifact, {"phase": phase})
                top_tasks.append({"id": TASKS[phase], "phase": phase, "status": "ok",
                                  "attempts": 1, "artifact": artifact, "updated_at": "before", "error": None})
            write(scan / "task-ledger.json", {"schema_version": "2.0", "run_id": "run", "tasks": top_tasks})
            (target / "app.py").write_text("def entry():\n    return 'changed source'\n")
            settings.update(attempt_id="resumed", sast_budget={**plan["budget"], "max_hunt_tasks": 1, "max_hunt_questions": 1})
            write(context, settings)
            recovered = run(PYTHON, "scripts/recover-run.py", str(scan), str(context), "quick",
                            env={"VULNOPS_RUNTIME_ROOT": str(base / "runtime")})
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertTrue(recovered.stdout.startswith("sast\t2\t6"), recovered.stdout)
            resumed = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context))
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            retained = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(retained["tasks"], plan["tasks"])
            self.assertEqual(retained["deferred_task_ids"], [task["id"] for task in plan["tasks"]])
            self.assertEqual({path: path.read_bytes() for path in packets}, packets)
            self.assertFalse((scan / "sast/coverage-ledger.json").exists())

    def test_lowered_resume_budget_preserves_accepted_checkpoint_and_packets(self) -> None:
        spec = importlib.util.spec_from_file_location("retained_hunt_builder", ROOT / "scripts/build-hunt-plan.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            scan, target = base / "scan", base / "source"
            target.mkdir()
            (target / "app.py").write_text("def entry(value):\n    return value\n")
            threat = threat_model(["app.py"], [mapping("HM-ACCESS", "access_control")],
                                  [attack_class("access_control", "skill://vulnops-access-control")])
            context = {"run_id": "run", "depth": "quick", "source_root": str(target),
                       "repo_path": str(target), "scan_base": str(scan),
                       "repositories": [{"path": "."}], "model_routing": ROUTING}
            context_path = base / "context.json"
            write(context_path, context)
            write(scan / "sast/threat-model.json", threat)
            plan = builder.initial_plan(ROOT, scan, context, threat)
            write(scan / "sast/hunt-plan.json", plan)
            builder.publish_task_packets(scan, plan, (scan / "sast/hunt-plan.json").read_bytes())
            packets = {path: path.read_bytes() for path in (scan / "sast/hunt-tasks").glob("*.json")}
            task, cell = plan["tasks"][0], plan["cells"][0]
            binding = {key: cell[key] for key in ("objective_id", "question_id")}
            result = clean_result(task["id"], cell["id"], [], binding)
            result["status"] = "shallow"
            row = result["cell_results"][0]
            row["status"] = "shallow"
            row["reason"] = "Entrypoint inspected; downstream ownership remains unresolved."
            row["resolution"] = {"outcome": "locally_unresolved", "reason": row["reason"],
                                 "next_action": "Inspect downstream ownership enforcement",
                                 "evidence_refs": ["app.py:1"], "missing_fact": "Downstream ownership enforcement"}
            row["checkpoint"].update(established_facts=["app.py:1 accepts caller input"],
                                     contradicted_paths=[], remaining_question="Is downstream ownership enforced?",
                                     next_step="Inspect downstream ownership enforcement",
                                     expected_results=["ownership check defeats path", "missing check establishes path"])
            write(scan / f"sast/deepdive/{task['id']}.json", result)
            environment = activate_publisher(scan, context, "sast",
                                            {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path)})
            accepted = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), env=environment)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            ledger = json.loads((scan / "sast/coverage-ledger.json").read_text())
            self.assertTrue(ledger["tasks"][0]["artifact_valid"])
            self.assertEqual(ledger["cells"][0]["status"], "shallow")
            plan["budget"].update(max_hunt_tasks=1, max_hunt_questions=1, max_attempts=1, max_gapfill_rounds=0)
            updated = builder.gapfill(ROOT, plan, scan, threat)
            self.assertEqual(updated["tasks"], [task])
            self.assertIn("per-question attempt ceiling exhausted", updated["cells"][0]["disposition_reason"])
            builder.publish_task_packets(scan, updated, json.dumps(updated).encode())
            self.assertEqual({path: path.read_bytes() for path in packets}, packets)


if __name__ == "__main__":
    unittest.main()
