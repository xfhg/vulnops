from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False, env=merged)


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def threat_model(files: list[str], mappings: list[dict], classes: list[dict], surfaces: list[str] | None = None) -> dict:
    surfaces = surfaces or ["TB-1"]
    return {
        "schema_version": "2.0",
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


class ContextualPlanningTests(unittest.TestCase):
    def test_bounded_sast_coverage_is_ok_not_degraded(self) -> None:
        spec = importlib.util.spec_from_file_location("finalize_sast", ROOT / "scripts/finalize-sast.py")
        assert spec and spec.loader
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        finally:
            sys.path.pop(0)
        ledger = {
            "cells": [
                *({"id": f"S-{index}", "status": "shallow"} for index in range(66)),
                *({"id": f"D-{index}", "status": "deferred"} for index in range(44)),
                {"id": "F-1", "status": "finding"},
            ],
            "funnel": {"environment_required": 0},
        }
        self.assertEqual(module.close_depth_limited_cells(ledger), 110)
        self.assertTrue(all(cell["status"] not in {"shallow", "deferred"} for cell in ledger["cells"]))
        self.assertEqual(sum(cell["status"] == "depth_limited" for cell in ledger["cells"]), 110)
        self.assertEqual(module.close_depth_limited_cells(ledger), 0)
        self.assertEqual(module.sast_phase_status(ledger), "ok")
        ledger["cells"].append({"id": "FAILED-1", "status": "failed"})
        self.assertEqual(module.sast_phase_status(ledger), "degraded")
        ledger["cells"].pop()
        ledger["funnel"]["environment_required"] = 1
        self.assertEqual(module.sast_phase_status(ledger), "degraded")

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
            write(context, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan)})
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
            self.assertEqual(packet["cells"], plan["cells"])
            self.assertNotIn("TB-REPORT", json.dumps(packet))
            self.assertNotIn("TB-FILESYSTEM", json.dumps(packet))

    def test_batch_order_round_robins_subsystems_before_repeating_one(self) -> None:
        spec = importlib.util.spec_from_file_location("hunt_plan", ROOT / "scripts/build-hunt-plan.py")
        assert spec and spec.loader
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        finally:
            sys.path.pop(0)
        def cell(cell_id: str, subsystem: str, class_id: str, file: str, entrypoint: str) -> dict:
            return {"id": cell_id, "subsystem": subsystem, "domain": "general", "attack_class_id": class_id, "priority": "critical", "files": [file], "entrypoint_ids": [entrypoint], "boundary_ids": [f"B-{cell_id}"], "surface_ids": [f"B-{cell_id}"]}
        batches = module.contextual_batches([
            cell("A1", "A", "access_control", "a1.py", "EA1"),
            cell("A2", "A", "business_logic", "a2.py", "EA2"),
            cell("B1", "B", "access_control", "b1.py", "EB1"),
        ])
        self.assertEqual([batch[0]["subsystem"] for batch in batches], ["A", "B", "A"])

    def test_per_cell_contract_prevents_task_wide_finding_promotion(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry(value):\n    return sink(value)\ndef sink(value):\n    return value\n")
            scan = base / "scan"; context = base / "context.json"
            write(context, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan)})
            classes = [
                attack_class("access_control", "skill://vulnops-access-control"),
                attack_class("business_logic", "skill://vulnops-logic-bug"),
            ]
            write(scan / "sast/threat-model.json", threat_model(["app.py"], [mapping("HM-ACCESS", "access_control"), mapping("HM-LOGIC", "business_logic")], classes))
            built = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context))
            self.assertEqual(built.returncode, 0, built.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text()); task = plan["tasks"][0]; first, second = [next(cell for cell in plan["cells"] if cell["id"] == cell_id) for cell_id in task["cell_ids"]]
            candidate = {
                "schema_version": "2.0", "id": "LOCAL-1", "task_id": task["id"], "cell_ids": [first["id"]], "finding_kind": "code", "title": "Caller crosses the assigned authorization boundary", "category": "authorization", "attack_class_id": first["attack_class_id"], "domain": "general", "methodology_refs": first["methodology_refs"], "severity": "low", "confidence": "high",
                "attacker": {"perspective": "remote caller", "starting_access": "public input", "boundary_crossed": "service authorization"}, "intended_behavior": "Only authorized callers reach the sink.", "root_cause": "The entrypoint forwards input without the required authorization check.", "root_cause_location": {"file": "app.py", "line": 1, "scope": "entry", "mechanism": "missing authorization"},
                "trace": [{"kind": "entrypoint", "file": "app.py", "line": 1, "scope": "entry", "description": "caller input enters"}, {"kind": "sink", "file": "app.py", "line": 2, "scope": "sink", "description": "trusted sink receives input"}], "conditions": [], "impact": "Unauthorized use of the trusted sink.", "remediation": "Enforce authorization before dispatch.", "evidence_refs": ["app.py:1"], "lenses": first["lenses"], "mitigations_checked": ["No authorization guard exists before dispatch"]
            }
            row1 = {"cell_id": first["id"], "status": "finding", "reason": "A source-backed candidate exists.", "files_reviewed": ["app.py:1-2"], "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["sink"], "mitigations_checked": ["authorization guard"], "candidate_ids": ["LOCAL-1"], "evidence_refs": ["app.py:1"]}
            row2 = {"cell_id": second["id"], "status": "clean", "reason": "The workflow invariant holds.", "files_reviewed": ["app.py:1-2"], "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["sink"], "mitigations_checked": ["workflow invariant"], "candidate_ids": [], "evidence_refs": ["app.py:1"]}
            result = {"schema_version": "2.0", "task_id": task["id"], "status": "ok", "cell_results": [row1, row2], "files_reviewed": ["app.py:1-2"], "entrypoints_traced": ["EP-1"], "sinks_reviewed": ["sink"], "mitigations_checked": ["authorization guard", "workflow invariant"], "candidates": [candidate], "hardening_notes": [], "positive_patterns": [], "rabbit_holes": [], "wishlist_items": [], "warnings": [], "errors": []}
            result_path = scan / "sast/deepdive" / f"{task['id']}.json"; write(result_path, result)
            checked = run(PYTHON, "scripts/sast_contract.py", str(target), str(scan / "sast/hunt-tasks" / f"{task['id']}.json"), str(result_path))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            aggregated = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan))
            self.assertEqual(aggregated.returncode, 0, aggregated.stderr)
            ledger = json.loads((scan / "sast/coverage-ledger.json").read_text()); statuses = {item["id"]: item["status"] for item in ledger["cells"]}
            self.assertEqual(statuses[first["id"]], "finding")
            self.assertEqual(statuses[second["id"]], "clean")

            result["cell_results"][1]["files_reviewed"] = ["outside.py:1"]
            write(result_path, result)
            rejected = run(PYTHON, "scripts/sast_contract.py", str(target), str(scan / "sast/hunt-tasks" / f"{task['id']}.json"), str(result_path))
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("reviewed unassigned file", rejected.stderr)

    def test_gapfill_prioritizes_contextual_rabbit_holes_over_deferred_initial_cells(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry():\n    return 1\n"); (target / "other.py").write_text("def other():\n    return 2\n")
            scan = base / "scan"; context = base / "context.json"
            write(context, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan)})
            classes = [attack_class("access_control", "skill://vulnops-access-control"), attack_class("business_logic", "skill://vulnops-logic-bug")]
            mappings = [mapping("HM-ACCESS", "access_control", source_file="app.py"), mapping("HM-LOGIC", "business_logic", source_file="other.py")]
            write(scan / "sast/threat-model.json", threat_model(["app.py", "other.py"], mappings, classes))
            built = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context), env={"VULNOPS_SAST_QUICK_MAX_HUNT_TASKS": "2"})
            self.assertEqual(built.returncode, 0, built.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text()); self.assertEqual(len(plan["tasks"]), 1)
            active_cell = plan["tasks"][0]["cell_ids"][0]
            write(scan / "sast/coverage-ledger.json", {"cells": [{"id": active_cell, "status": "clean"}], "tasks": [{"id": plan["tasks"][0]["id"], "status": "ok"}]})
            rabbit = {"subsystem": "SUB-1", "attack_class_id": "access_control", "surface_ids": ["TB-1"], "threat_ids": ["TH-1"], "asset_ids": ["A-1"], "attacker": "remote caller", "entrypoint_ids": ["EP-1"], "boundary_ids": ["TB-1"], "security_question": "Can the adjacent authorization consumer be bypassed?", "stop_conditions": ["The adjacent consumer is unreachable"], "priority": "critical", "reason": "The assigned source exposes an adjacent authorization consumer.", "expected_added_value": "Validate a distinct downstream authorization transition.", "files": ["app.py"], "evidence_refs": ["app.py:1"]}
            write(scan / "sast/deepdive" / f"{plan['tasks'][0]['id']}.json", {"rabbit_holes": [rabbit]})
            gapfilled = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context), "--gapfill")
            self.assertEqual(gapfilled.returncode, 0, gapfilled.stderr)
            updated = json.loads((scan / "sast/hunt-plan.json").read_text()); self.assertEqual(len(updated["tasks"]), 2)
            self.assertTrue(updated["tasks"][-1]["cell_ids"][0].startswith("CELL-RABBIT-"))
            deferred = [cell for cell in updated["cells"] if cell["mapping_id"] in {"HM-ACCESS", "HM-LOGIC"} and cell["status"] == "deferred"]
            self.assertEqual(len(deferred), 1)
            later_rabbit = {**rabbit, "security_question": "Can a second adjacent authorization transition be bypassed?", "expected_added_value": "Record the distinct lead even after the scheduling round is exhausted."}
            write(scan / "sast/deepdive" / f"{updated['tasks'][-1]['id']}.json", {"rabbit_holes": [later_rabbit]})
            ledger = json.loads((scan / "sast/coverage-ledger.json").read_text()); ledger["tasks"].append({"id": updated["tasks"][-1]["id"], "status": "ok"}); write(scan / "sast/coverage-ledger.json", ledger)
            terminal = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context), "--gapfill")
            self.assertEqual(terminal.returncode, 0, terminal.stderr)
            exhausted = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(len(exhausted["tasks"]), 2)
            recorded = [cell for cell in exhausted["cells"] if cell.get("lead_key")]
            self.assertEqual(len(recorded), 2)
            self.assertEqual(recorded[-1]["status"], "deferred")


if __name__ == "__main__":
    unittest.main()
