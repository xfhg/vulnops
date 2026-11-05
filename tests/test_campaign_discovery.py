from __future__ import annotations

from contextlib import closing
import importlib.util
import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("campaign_builder", ROOT / "scripts/build-campaign-plan.py")
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)
evidence_spec = importlib.util.spec_from_file_location("evidence_builder", ROOT / "scripts/build-evidence-index.py")
evidence_builder = importlib.util.module_from_spec(evidence_spec)
evidence_spec.loader.exec_module(evidence_builder)
import campaign_contract as contract
import codegraph_contract as graph_contract
from model_routing import audit_routing, load_routing
from objective_contract import stable_id
from test_run_lifecycle import activate_publisher
ROUTING = audit_routing(load_routing(ROOT))


class DiscoveryTests(unittest.TestCase):
    def definitions(self, key, file, owner="sast/threat-model.json", objective=None):
        objective = objective or {
            "id": stable_id("OBJ-", owner, key), "owner": owner, "local_key": key,
            "starting_actor": "Authenticated tenant member", "controlled_material": "Requested resource identifier",
            "resource_scope": f"Tenant resources handled by {file}", "desired_effect": "Read another tenant's resource",
            "success_condition": "A tenant member can obtain a resource owned by a different tenant.",
            "evidence_refs": [f"{file}:1-2"]}
        question = {"id": stable_id("Q-", owner, key), "owner": owner, "local_key": key,
                    "objective_id": objective["id"], "security_question": f"Does {file} enforce resource ownership?",
                    "route": file, "proof_obligation": f"Trace the tenant ownership guard in {file}.",
                    "novelty_reason": f"Inspect this separately owned route: {key}.", "evidence_refs": [f"{file}:1-2"]}
        return objective, question

    def bind_relationship(self, discovery, relationship, file):
        objective, question = self.definitions(relationship["id"], file, "campaign-planning/discovery.json")
        question["proof_obligation"] = "Prove the explicit producer-to-consumer authority transfer."
        discovery["attack_objectives"].append(objective)
        discovery["investigation_questions"].append(question)
        discovery["question_inputs"].append({
            "objective_id": objective["id"], "question_id": question["id"],
            "evidence_ids": relationship["evidence_ids"], "primitive_ids": relationship["primitive_ids"],
            "relationship_ids": [relationship["id"]], "lane": "primitive_led",
            "priority_band": "source_hypothesis", "reason": "Review the sourced capability transfer and its missing prerequisite."})

    def fixture(self, directory, count=6, mode="disabled", depth="quick"):
        root = Path(directory).resolve()
        scan, target = root / "scan", root / "source"
        (scan / "campaign-planning").mkdir(parents=True)
        records, primitives, objectives, questions = [], [], [], []
        for i in range(count):
            file = f"{'alpha' if i < count - 1 else 'beta'}/source{i}.py"
            (target / file).parent.mkdir(parents=True, exist_ok=True)
            (target / file).write_text("def entry():\n    return 1\n")
            rid, pid = f"E-{i:012X}", f"P-{i:012X}"
            records.append({"id": rid, "source_kind": "sast", "source_id": str(i), "artifact_ref": f"sast/verified-findings.json:{i}", "disposition": "promoted", "summary": "Source candidate", "files": [file], "source_anchors": [], "subsystems": [], "anchor_limitations": []})
            objective, question = self.definitions(str(i), file)
            objectives.append(objective)
            questions.append(question)
            records[-1].update(objective_id=objective["id"], question_id=question["id"])
            primitives.append({"id": pid, "type": "vulnerability", "trust": "confirmed", "source_record_ids": [rid], "prerequisites": ["Attacker input"], "capability_gained": "Read", "boundary": "application", "reachable_assets": ["shared"] if i >= count - 2 else [f"asset{i}"], "conditions": [], "evidence_refs": [rid]})
            provenance = {"actor": "vulnops-deepdive-chunk", "selector": ROUTING["agents"]["vulnops-deepdive-chunk"], "artifact_ref": f"sast/deepdive/{i}.json"}
            planner.write(scan / provenance["artifact_ref"], {"provenance": provenance})
            records[-1]["contributors"] = [provenance]
            primitives[-1]["contributors"] = [provenance]
        index = {"schema_version": "2.0", "run_id": "test", "records": records, "primitives": primitives,
                 "attack_objectives": objectives, "investigation_questions": questions, "coverage_gaps": [], "warnings": []}
        planner.write(scan / "sast/threat-model.json", {"attack_objectives": objectives, "investigation_questions": questions})
        planner.write(scan / "campaign-planning/evidence-index.json", index)
        context = {"run_id": "test", "scan_base": str(scan), "source_root": str(target), "repo_path": str(target), "depth": depth, "codegraph_mode": mode, "repositories": [{"path": "alpha"}, {"path": "beta"}], "paths": {}}
        context["model_routing"] = ROUTING
        return scan, target, context, index

    def activate(self, scan, context):
        environment = patch.dict(os.environ, activate_publisher(scan, context, "campaign-planning",
                                 {**os.environ, "VULNOPS_RUNTIME_ROOT": str(scan.parent / "runtime")}))
        environment.start()
        self.addCleanup(environment.stop)

    def seal(self, scan, context, index):
        discovery = contract.prepare_discovery(scan, context, index)
        planner.close_discovery(scan, discovery)
        planner.write(scan / "campaign-planning/discovery.json", discovery)
        return discovery

    def test_later_reviewed_pair_displaces_standalone_and_is_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory)
            discovery = self.seal(scan, context, index)
            baseline = contract.selected_candidates(index, discovery)
            rel = next(r for r in discovery["relationships"] if r["primitive_ids"] == ["P-000000000003", "P-000000000004"])
            rel.update(disposition="source-supported", kind="producer_consumer", producer_id=rel["primitive_ids"][0], consumer_id=rel["primitive_ids"][1], reason="Reviewed producer capability reaches consumer.")
            rel["source_locations"] = [{"file": index["records"][i]["files"][0], "start_line": 1, "end_line": 2} for i in (3, 4)]
            self.bind_relationship(discovery, rel, index["records"][3]["files"][0])
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            contract.validate_discovery(scan, target, context)
            selected = contract.selected_candidates(index, discovery)
            self.assertNotEqual(selected, baseline)
            self.assertEqual(selected[0]["relationship_ids"], [rel["id"]])
            self.assertEqual(selected, contract.selected_candidates(copy.deepcopy(index), copy.deepcopy(discovery)))
            rel["disposition"] = "contradicted"
            self.assertTrue(all(rel["id"] not in row["relationship_ids"] for row in contract.selected_candidates(index, discovery)))

    def test_handoff_requires_mapping_not_equal_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=2)
            discovery = self.seal(scan, context, index)
            rel = discovery["relationships"][0]
            locations = [{"file": rec["files"][0], "start_line": 1, "end_line": 2} for rec in index["records"]]
            rel.update(disposition="source-supported", kind="handoff", producer_id=rel["primitive_ids"][0], consumer_id=rel["primitive_ids"][1], source_locations=locations)
            rel["handoff"] = {"type": "queue", "producer_contract": {"topic": "jobs", "broker": "broker"}, "consumer_contract": {"topic": "jobs", "broker": "broker"}, "producer_deployment": "prod", "consumer_deployment": "other", "producer_location": locations[0], "consumer_location": locations[1]}
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            with self.assertRaisesRegex(ValueError, "mapping evidence"):
                contract.validate_discovery(scan, target, context)
            rel["disposition"] = "inconclusive"
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            contract.validate_discovery(scan, target, context)
            rel["disposition"] = "source-supported"
            rel["handoff"]["mapping_evidence"] = {key: "Source configuration establishes this scoped transition." for key in ("binding", "actor_control", "resource_scope", "authority", "transformations", "guards", "compatible_conditions")}
            rel["handoff"]["mapping_evidence"]["source_locations"] = locations
            self.bind_relationship(discovery, rel, index["records"][0]["files"][0])
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            contract.validate_discovery(scan, target, context)
            self.assertEqual(contract.selected_candidates(index, discovery)[0]["relationship_ids"], [rel["id"]])

    def test_round_robin_and_depth_bounds(self):
        for depth, budget in contract.DISCOVERY_BUDGETS.items():
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as directory:
                scan, target, context, index = self.fixture(directory, count=100, mode="enabled", depth=depth)
                with patch.object(contract, "graph_question", side_effect=lambda record, project: {"type": "callers", "subject": record["files"][0], "reason": "Inspect source callers"}):
                    discovery = contract.prepare_discovery(scan, context, index)
                self.assertEqual(len(discovery["questions"]), budget["questions"])
                self.assertEqual(discovery["questions"][1]["evidence_ids"], ["E-000000000063"])
                self.assertEqual(len(discovery["relationships"]), budget["pairs"])
                self.assertGreater(discovery["counters"]["pairs_deferred"], 0)
                self.assertGreater(discovery["counters"]["questions_deferred"], 0)
                self.assertEqual(discovery["relationships"][0]["primitive_ids"], ["P-000000000062", "P-000000000063"])

    def test_prepare_only_and_source_only_final_sealing(self):
        for mode, count in (("disabled", 3), ("enabled", 0), ("enabled", 3)):
            with self.subTest(mode=mode, count=count), tempfile.TemporaryDirectory() as directory:
                scan, target, context, index = self.fixture(directory, count=count, mode=mode)
                self.activate(scan, context)
                context_path = Path(directory) / "context.json"
                planner.write(context_path, context)
                evidence_before = (scan / "campaign-planning/evidence-index.json").read_bytes()
                argv = ["planner", str(scan), "--context", str(context_path)]
                with patch.object(sys, "argv", argv + ["--prepare-discovery"]):
                    self.assertEqual(planner.main(), 0)
                self.assertFalse((scan / "campaign-planning/campaign-plan.json").exists())
                self.assertFalse((scan / "campaign-planning/phase-manifest.json").exists())
                with patch.object(sys, "argv", argv):
                    self.assertEqual(planner.main(), 0)
                plan = json.loads((scan / "campaign-planning/campaign-plan.json").read_text())
                contract.validate_selection(scan, target, context, plan)
                self.assertEqual((scan / "campaign-planning/evidence-index.json").read_bytes(), evidence_before)
                if count:
                    plan["campaigns"][0]["starting_evidence"] = []
                    with self.assertRaises(ValueError):
                        contract.validate_selection(scan, target, context, plan)
                else:
                    self.assertEqual(plan["campaigns"], [])

    def test_orphan_receipt_and_pending_question_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory)
            discovery = self.seal(scan, context, index)
            discovery["graph_evidence_refs"] = ["intrusion/codegraph-runs/CAM-001/Q-1/receipt.json"]
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            with self.assertRaisesRegex(ValueError, "orphan discovery graph receipt"):
                contract.validate_discovery(scan, target, context)
            discovery["graph_evidence_refs"] = []
            record = index["records"][0]
            subject = record["files"][0]
            discovery["questions"] = [{
                "id": contract.stable("DQ-", record["id"], "callers", subject),
                "type": "callers", "subject": subject, "reason": "Inspect callers",
                "evidence_ids": [record["id"]], "disposition": "pending", "reason_closed": ""}]
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            with self.assertRaisesRegex(ValueError, "lacks terminal disposition"):
                contract.validate_discovery(scan, target, context)
            discovery["questions"][0].update(disposition="inconclusive", reason_closed="Source-only review remains inconclusive.")
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            contract.validate_discovery(scan, target, context)

    def test_retained_selection_survives_source_settings_and_missing_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=8, depth="full")
            context["attempt_id"] = "original"
            discovery = self.seal(scan, context, index)
            plan = planner.build_plan(scan, context, index, discovery)
            planner.write(scan / "campaign-planning/campaign-plan.json", plan)
            retained = {path: path.read_bytes() for path in (scan / "campaign-planning").glob("*.json")}
            for record in index["records"]:
                (target / record["files"][0]).unlink(missing_ok=True)
            context.update(attempt_id="resumed", depth="quick", codegraph_mode="disabled", repositories=[{"path": "new"}])
            contract.validate_selection(scan, target, context, plan)
            current = planner.build_plan(scan, context, index, discovery)
            self.assertEqual(len(current["campaigns"]), 4)
            self.assertEqual(sum(row["status"] == "deferred" for row in current["question_dispositions"]), 4)
            self.assertEqual({path: path.read_bytes() for path in retained}, retained)

    def test_budget_reservation_and_actual_elapsed(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, mode="enabled")
            context["attempt_id"] = "attempt-one"
            planner.write(scan / "run-manifest.json", {"run_id": context["run_id"], "attempt_id": "attempt-one",
                                                     "status": "incomplete", "phases": {"campaign-planning": "running"}})
            context["paths"]["codegraph_project"] = str(target)
            with patch.object(contract, "graph_question", side_effect=lambda rec, project: {"type": "callers", "subject": rec["files"][0], "reason": "Inspect callers"}):
                discovery = contract.prepare_discovery(scan, context, index)
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            context_path = Path(directory) / "context.json"
            planner.write(context_path, context)
            with patch.object(graph_contract, "current_navigation", return_value=target), patch.object(graph_contract, "resolve_subject", return_value=[]):
                first = graph_contract.audit_request(context_path, "campaign-planning", "discovery", discovery["questions"][0]["id"])
                self.assertEqual(first["timeout_seconds"], 120)
                graph_contract.finish_discovery_query(first, 100)
                second = graph_contract.audit_request(context_path, "campaign-planning", "discovery", discovery["questions"][1]["id"])
                self.assertEqual(second["timeout_seconds"], 20)
                with self.assertRaisesRegex(ValueError, "exhausted"):
                    graph_contract.audit_request(context_path, "campaign-planning", "discovery", discovery["questions"][2]["id"])
                discovery["status"] = "sealed"
                planner.write(scan / "campaign-planning/discovery.json", discovery)
                with self.assertRaisesRegex(ValueError, "after sealing"):
                    graph_contract.audit_request(context_path, "campaign-planning", "discovery", discovery["questions"][2]["id"])

    def test_coverage_mapping_retains_prefixed_source(self):
        spec = importlib.util.spec_from_file_location("evidence_builder", ROOT / "scripts/build-evidence-index.py")
        evidence_builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(evidence_builder)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            scan = root / "scan"
            context = root / "context.json"
            source = root / "source"
            source.mkdir()
            for relative in ("api/handler.py", "worker/consumer.py"):
                (source / relative).parent.mkdir(parents=True, exist_ok=True)
                (source / relative).write_text("source\nsource\n")
            objective, question = self.definitions("coverage", "api/handler.py")
            authority = {"run_id": "test", "model_routing": ROUTING, "scan_base": str(scan),
                         "source_root": str(source), "repositories": [{"path": "api"}, {"path": "worker"}]}
            self.activate(scan, authority)
            planner.write(context, authority)
            planner.write(scan / "sast/coverage-ledger.json", {"cells": [{"id": "C1", "status": "deferred", "reason": "Missing review"}, {"id": "C2", "status": "deferred", "reason": "No mapping"}]})
            planner.write(scan / "sast/hunt-plan.json", {"attack_objectives": [objective], "investigation_questions": [question], "cells": [{"id": "C1", "mapping_id": "M1", "objective_id": objective["id"], "question_id": question["id"], "files": ["api/handler.py"], "entrypoint_ids": ["ENTRY"], "subsystem": "http"}]})
            planner.write(scan / "sast/threat-model.json", {"attack_objectives": [objective], "investigation_questions": [question], "hunt_mappings": [{"id": "M1", "objective_id": objective["id"], "question_id": question["id"], "source_files": ["worker/consumer.py"], "entrypoint_ids": ["ENTRY"]}], "entrypoints": [{"id": "ENTRY", "path": "api/handler.py"}]})
            with patch.object(sys, "argv", ["evidence", str(scan), "--context", str(context)]):
                self.assertEqual(evidence_builder.main(), 0)
            doc = json.loads((scan / "campaign-planning/evidence-index.json").read_text())
            rows = {r["source_id"]: r for r in doc["records"]}
            self.assertEqual(rows["C1"]["files"], ["api/handler.py", "worker/consumer.py"])
            self.assertEqual(rows["C1"]["source_anchors"][0]["entrypoint_id"], "ENTRY")
            self.assertEqual(rows["C1"]["disposition"], "unresolved")
            self.assertEqual(rows["C2"]["files"], [])
            self.assertTrue(rows["C2"]["anchor_limitations"])

    def test_reference_variants_and_inert_notes_preserve_source_questions(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=2)
            rec = index["records"][0]
            rec["source_kind"] = "recon"
            file = rec["files"][0]
            variants = []
            for refs, extra in (([file + ":1-2"], {}), ([file + ":1, 2,1-2"], {
                    "attacker": "invented admin", "priority": "critical", "impact": "invented",
                    "applicability_reason": "untrusted extension", "source_files": ["outside.py"]})):
                row = copy.deepcopy(rec)
                issues = evidence_builder.classify_record(scan, target, context["repositories"], row, {"evidence_refs": refs, **extra})
                self.assertEqual(issues, [])
                variants.append(row)
            for key in ("files", "source_anchors", "risk_context", "disposition", "evidence_quality"):
                self.assertEqual(variants[0][key], variants[1][key])

    def test_missing_support_remains_local_and_optional_requires_reasoning(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=2)
            file = index["records"][0]["files"][0]
            rec = copy.deepcopy(index["records"][0])
            item = {"id": "C", "evidence_refs": [file + ":1", "alpha/missing.py:1"]}
            issues = evidence_builder.classify_record(scan, target, context["repositories"], rec, item)
            self.assertEqual(rec["disposition"], "evidence_limited")
            self.assertEqual(rec["files"], [file])
            self.assertEqual(issues[0]["code"], "missing_file")
            item["optional_support"] = [{"reference": "alpha/missing.py:1", "obligation": "entrypoint",
                                        "independent_support": [file + ":1"], "rationale": "The inspected source independently establishes the same entrypoint; the missing note is redundant."}]
            rec = copy.deepcopy(index["records"][0])
            issues = evidence_builder.classify_record(scan, target, context["repositories"], rec, item)
            self.assertEqual(rec["disposition"], "promoted")
            self.assertEqual(issues[0]["disposition"], "optional")
            item["evidence_refs"] = ["../escape.py:1"]
            item.pop("optional_support")
            with self.assertRaises(ValueError):
                evidence_builder.classify_record(scan, target, context["repositories"], rec, item)

    def test_consequential_incomplete_question_beats_easy_gap_without_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=3)
            index["primitives"] = []
            for offset, rec in enumerate(index["records"]):
                rec["disposition"] = "evidence_limited" if offset == 2 else "unresolved"
                rec["risk_context"] = {"actor": "remote caller", "reachability": "Source anchor", "impact": "", "priority": 1 if offset == 2 else 4}
            index["coverage_gaps"] = [r["id"] for r in index["records"]]
            discovery = self.seal(scan, context, index)
            plan = planner.build_plan(scan, context, index, discovery)
            self.assertEqual(plan["campaigns"][0]["starting_evidence"], [index["records"][2]["id"]])
            self.assertEqual(plan["campaigns"][0]["primitive_ids"], [])
            self.assertIn("Not established", plan["campaigns"][0]["attacker_capability"])
            deferred = [row for row in plan["evidence_dispositions"] if row["status"] == "evidence_limited"]
            self.assertEqual(len(deferred), 0)
            self.assertEqual(len(plan["campaigns"]), 3)
            contract.validate_selection_decisions(index, discovery, plan)
            for rec in index["records"]:
                rec["files"] = []
            discovery = self.seal(scan, context, index)
            plan = planner.build_plan(scan, context, index, discovery)
            self.assertEqual(plan["campaigns"], [])
            self.assertEqual(len(plan["evidence_dispositions"]), 3)
            self.assertTrue(all("No established source anchor" in row["deferral_reason"] for row in plan["evidence_dispositions"]))

    def test_discovery_missing_relationship_proof_is_local_but_escape_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=2)
            discovery = self.seal(scan, context, index)
            rel = discovery["relationships"][0]
            rel.update(disposition="source-supported", source_locations=[
                {"file": "alpha/missing.py", "start_line": 1, "end_line": 1}])
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            resolved = contract.validate_discovery(scan, target, context)
            self.assertEqual(resolved["relationships"][0]["disposition"], "inconclusive")
            self.assertEqual(resolved["evidence_quality"]["total"], 1)
            self.assertEqual(json.loads((scan / "campaign-planning/discovery.json").read_text())["relationships"][0]["disposition"], "source-supported")
            rel["source_locations"][0]["file"] = "../escape.py"
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            with self.assertRaises(ValueError):
                contract.validate_discovery(scan, target, context)

    def test_builders_preserve_historical_questions_without_promoting_old_citations(self):
        outputs = []
        for selector in ("1-2", "1, 2,1-2", "1,9"):
            with tempfile.TemporaryDirectory() as directory:
                scan, target, context, _ = self.fixture(directory, count=1)
                self.activate(scan, context)
                objective, question = self.definitions("mapping", "beta/source0.py")
                mapping = {"id": "M1", "source_files": ["beta/source0.py"], "attacker": "remote caller",
                           "objective_id": objective["id"], "question_id": question["id"],
                           "subsystem_id": "api", "priority": "high",
                           "applicability_reason": "Investigate attacker-controlled input at the mapped boundary.",
                           "evidence_refs": [f"beta/source0.py:{selector}", "repo-context/repo.md"]}
                planner.write(scan / "sast/threat-model.json", {"attack_objectives": [objective], "investigation_questions": [question], "hunt_mappings": [mapping]})
                (scan / "repo-context").mkdir()
                (scan / "repo-context/repo.md").write_text("# Navigation only\n")
                context_path = Path(directory) / "context.json"
                planner.write(context_path, context)
                with patch.object(sys, "argv", ["evidence", str(scan), "--context", str(context_path)]):
                    self.assertEqual(evidence_builder.main(), 0)
                with patch.object(sys, "argv", ["planner", str(scan), "--context", str(context_path)]):
                    self.assertEqual(planner.main(), 0)
                index = json.loads((scan / "campaign-planning/evidence-index.json").read_text())
                plan = json.loads((scan / "campaign-planning/campaign-plan.json").read_text())
                self.assertEqual(index["primitives"], [])
                self.assertEqual(index["records"][0]["navigation_refs"], ["repo-context/repo.md"])
                self.assertEqual(len(plan["campaigns"]), 1)
                self.assertEqual(plan["campaigns"][0]["primitive_ids"], [])
                outputs.append((index, plan))
        self.assertEqual(outputs[0][1]["campaigns"], outputs[1][1]["campaigns"])
        self.assertEqual(outputs[0][0]["evidence_quality"], outputs[1][0]["evidence_quality"])
        self.assertEqual(outputs[2][0]["records"][0]["disposition"], "unresolved")
        self.assertTrue(any("Historical observation" in note for note in outputs[2][0]["records"][0]["anchor_limitations"]))
        self.assertEqual(outputs[2][1]["campaigns"][0]["starting_evidence"], outputs[0][1]["campaigns"][0]["starting_evidence"])
        self.assertEqual(outputs[2][1]["evidence_dispositions"][0]["status"], "selected")

    def test_graph_answer_source_gap_projects_inconclusive_with_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=2, mode="enabled")
            discovery = self.seal(scan, context, index)
            rec = index["records"][0]
            qid = contract.stable("DQ-", rec["id"], "callers", rec["files"][0])
            receipt = f"campaign-planning/codegraph-runs/{qid}/receipt.json"
            discovery["questions"] = [{"id": qid, "type": "callers", "subject": rec["files"][0],
                                       "reason": "Inspect callers", "evidence_ids": [rec["id"]],
                                       "disposition": "source-supported", "reason_closed": "Source inspected"}]
            discovery["counters"]["questions_deferred"] = 1
            discovery["graph_evidence_refs"] = [receipt]
            discovery["graph_answers"] = [{"question_id": qid, "receipt_ref": receipt,
                                          "observation": "Inspect inbound flow", "disposition": "supported",
                                          "source_locations": [{"file": "alpha/missing.py", "start_line": 1, "end_line": 1}],
                                          "limitations": [], "conclusion_effect": "Claimed source support",
                                          "investigation_note": "Preserve as inert context"}]
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            # Receipt authenticity is outside this projection test; only source support is evaluated.
            with patch.object(contract, "validate_query_receipt", return_value={"meaningful": True}):
                resolved = contract.validate_discovery(scan, target, context)
            self.assertEqual(resolved["questions"][0]["evidence_quality"], "evidence_limited")
            self.assertEqual(resolved["graph_answers"][0]["disposition"], "inconclusive")
            self.assertEqual(resolved["graph_answers"][0]["investigation_note"], "Preserve as inert context")
            plan = planner.build_plan(scan, context, index, resolved)
            self.assertEqual(plan["evidence_dispositions"][0]["evidence_id"], rec["id"])

    def test_eight_source_gaps_use_shared_pool_and_publish_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=8)
            self.activate(scan, context)
            index["primitives"] = []
            for rec in index["records"]:
                rec["disposition"] = "unresolved"
            index["coverage_gaps"] = [rec["id"] for rec in index["records"]]
            planner.write(scan / "campaign-planning/evidence-index.json", index)
            context_path = Path(directory) / "context.json"
            planner.write(context_path, context)
            source_before = {file: (target / file).read_bytes() for rec in index["records"] for file in rec["files"]}
            evidence_before = (scan / "campaign-planning/evidence-index.json").read_bytes()
            for flags in (["--prepare-discovery"], []):
                with patch.object(sys, "argv", ["planner", str(scan), "--context", str(context_path), *flags]):
                    self.assertEqual(planner.main(), 0)
            plan = json.loads((scan / "campaign-planning/campaign-plan.json").read_text())
            contract.validate_selection(scan, target, context, plan)
            self.assertEqual(plan["budget"], {"max_campaigns": 4})
            self.assertEqual(len(plan["campaigns"]), 4)
            self.assertTrue(all(row["lane"] == "gap_driven" for row in plan["campaigns"]))
            self.assertEqual(sum(row["status"] == "deferred" for row in plan["question_dispositions"]), 4)
            self.assertEqual(len(plan["attack_objectives"]), 8)
            self.assertEqual((scan / "campaign-planning/evidence-index.json").read_bytes(), evidence_before)
            self.assertEqual({file: (target / file).read_bytes() for file in source_before}, source_before)

    def test_distinct_goals_share_evidence_and_duplicate_owners_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=1)
            discovery = self.seal(scan, context, index)
            objective, question = self.definitions("write", index["records"][0]["files"][0], "campaign-planning/discovery.json")
            objective.update(desired_effect="Change another tenant's resource",
                             success_condition="A tenant member can persist a change to a resource belonging to another tenant.")
            discovery["attack_objectives"].append(objective)
            discovery["investigation_questions"].append(question)
            discovery["question_inputs"].append({**discovery["question_inputs"][0],
                                                 "objective_id": objective["id"], "question_id": question["id"]})
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            plan = planner.build_plan(scan, context, index, discovery)
            contract.validate_selection(scan, target, context, plan)
            self.assertEqual(len(plan["campaigns"]), 2)
            self.assertEqual(plan["campaigns"][0]["starting_evidence"], plan["campaigns"][1]["starting_evidence"])
            plan["campaigns"][1] = {**plan["campaigns"][0], "id": "CAM-002"}
            with self.assertRaisesRegex(ValueError, "duplicate"):
                contract.validate_selection_decisions(index, discovery, plan)

    def test_equivalent_work_is_accounted_without_another_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=1)
            discovery = self.seal(scan, context, index)
            original = discovery["investigation_questions"][0]
            duplicate = {**original, "id": stable_id("Q-", "campaign-planning/discovery.json", "equivalent"),
                         "owner": "campaign-planning/discovery.json", "local_key": "equivalent",
                         "equivalent_to": original["id"], "novelty_reason": "Equivalent phrasing; reuse the original obligation."}
            discovery["investigation_questions"].append(duplicate)
            discovery["question_inputs"].append({**discovery["question_inputs"][0], "question_id": duplicate["id"]})
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            plan = planner.build_plan(scan, context, index, discovery)
            contract.validate_selection(scan, target, context, plan)
            self.assertEqual(len(plan["campaigns"]), 1)
            self.assertEqual(plan["question_dispositions"][1]["status"], "equivalent")
            self.assertEqual(plan["question_dispositions"][1]["equivalent_to"], original["id"])
            self.assertEqual(plan["question_dispositions"][1]["campaign_ids"], [])
            duplicate.pop("equivalent_to")
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            with self.assertRaisesRegex(ValueError, "equivalent disposition"):
                contract.validate_discovery(scan, target, context)

    def test_unmapped_lead_has_missing_facts_without_invented_objective(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=1)
            index["attack_objectives"] = []
            index["investigation_questions"] = []
            index["records"][0].pop("objective_id")
            index["records"][0].pop("question_id")
            planner.write(scan / "sast/threat-model.json", {"attack_objectives": [], "investigation_questions": []})
            planner.write(scan / "campaign-planning/evidence-index.json", index)
            discovery = self.seal(scan, context, index)
            plan = planner.build_plan(scan, context, index, discovery)
            contract.validate_selection(scan, target, context, plan)
            self.assertEqual(plan["campaigns"], [])
            self.assertEqual(plan["attack_objectives"], [])
            row = plan["evidence_dispositions"][0]
            self.assertIn("objective/question", row["missing_fact"])
            self.assertTrue(row["next_action"])
            self.assertTrue(row["deferral_reason"])

    def test_scanner_risk_cannot_remove_all_source_work(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=12)
            index["primitives"] = []
            for offset, rec in enumerate(index["records"]):
                rec["source_kind"] = "sast" if offset == 0 else "sca"
                rec["risk_context"] = {"actor": "Tenant member", "reachability": "Cited source",
                                       "impact": "Cross-tenant resource access", "priority": 4 if offset == 0 else 1}
            planner.write(scan / "campaign-planning/evidence-index.json", index)
            discovery = self.seal(scan, context, index)
            plan = planner.build_plan(scan, context, index, discovery)
            contract.validate_selection(scan, target, context, plan)
            self.assertEqual(len(plan["campaigns"]), 4)
            self.assertTrue(any(index["records"][0]["id"] in c["starting_evidence"] for c in plan["campaigns"]))
            self.assertEqual(len(plan["scanner_accounting"]), 11)
            self.assertEqual(sum(row["status"] == "selected" for row in plan["scanner_accounting"]), 3)
            unbound_ids = {f"E-{i + 1000:012X}" for i in range(500)}
            index["records"].extend({
                "id": rid, "source_kind": "sca", "source_id": rid,
                "artifact_ref": f"tool-collection/observations.json:{rid}",
                "disposition": "unresolved", "summary": "Unbound dependency observation",
                "files": ["alpha/source0.py"], "source_anchors": [], "subsystems": [],
                "anchor_limitations": [], "contributors": []} for rid in sorted(unbound_ids))
            planner.write(scan / "campaign-planning/evidence-index.json", index)
            discovery = self.seal(scan, context, index)
            expanded = planner.build_plan(scan, context, index, discovery)
            contract.validate_selection(scan, target, context, expanded)
            self.assertEqual(expanded["campaigns"], plan["campaigns"])
            accounting = {row["evidence_id"]: row for row in expanded["scanner_accounting"]}
            self.assertEqual(len(accounting), 511)
            self.assertTrue(all(accounting[rid]["status"] == "deferred" and
                                not accounting[rid]["campaign_ids"] for rid in unbound_ids))

    def test_total_bound_and_question_precise_selection_revisions(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=5)
            discovery = self.seal(scan, context, index)
            plan = planner.build_plan(scan, context, index, discovery)
            reason_only = copy.deepcopy(plan)
            campaign = reason_only["campaigns"][0]
            campaign["selection_reason"] = "Ownership path resolves a consequential privilege boundary now."
            with self.assertRaisesRegex(ValueError, "attributable"):
                contract.validate_selection(scan, target, context, reason_only)
            reason_only["selection_revisions"] = [{
                "author": "campaign-planning", "reason": "Reviewed ownership flow takes priority.",
                "evidence_ids": campaign["starting_evidence"], "question_ids": [campaign["question_id"]]}]
            contract.validate_selection(scan, target, context, reason_only)
            reason_only["selection_revisions"][0]["evidence_ids"] = ["E-FFFFFFFFFFFF"]
            with self.assertRaisesRegex(ValueError, "approved evidence"):
                contract.validate_selection(scan, target, context, reason_only)
            overflow = copy.deepcopy(plan)
            extra = next(row for row in contract.candidate_demand(index, discovery)
                         if row["question_id"] not in {c["question_id"] for c in plan["campaigns"]})
            overflow["campaigns"].append({**plan["campaigns"][0], **extra, "id": "CAM-005"})
            with self.assertRaisesRegex(ValueError, "total budget"):
                contract.validate_selection_decisions(index, discovery, overflow)
            displaced = plan["campaigns"][-1]
            plan["campaigns"][-1] = {**displaced, **extra}
            plan["question_dispositions"] = contract.question_dispositions(index, discovery, plan["campaigns"])
            with self.assertRaisesRegex(ValueError, "attributable revision"):
                contract.validate_selection_decisions(index, discovery, plan)
            revision = {"author": "campaign-planning", "reason": "Source review prioritizes the alternate route.",
                        "question_ids": [extra["question_id"]],
                        "evidence_ids": sorted(set(extra["starting_evidence"] + displaced["starting_evidence"]))}
            plan["selection_revisions"] = [revision]
            with self.assertRaisesRegex(ValueError, "selected questions"):
                contract.validate_selection_decisions(index, discovery, plan)
            revision["question_ids"].append(displaced["question_id"])
            contract.validate_selection_decisions(index, discovery, plan)

    def test_inherited_objectives_cannot_be_rewritten_and_unanchored_additions_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=1)
            discovery = self.seal(scan, context, index)
            discovery["attack_objectives"][0]["success_condition"] = "Invented stronger effect"
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            with self.assertRaises(ValueError):
                contract.validate_discovery(scan, target, context)
            discovery = self.seal(scan, context, index)
            objective, question = self.definitions("unsupported", "alpha/missing.py", "campaign-planning/discovery.json")
            discovery["attack_objectives"].append(objective)
            discovery["investigation_questions"].append(question)
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            with self.assertRaises(ValueError):
                contract.validate_discovery(scan, target, context)

    def test_actionable_proof_and_flow_fairness_follow_risk(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = self.fixture(directory, count=6)
            index["primitives"] = []
            discovery = self.seal(scan, context, index)
            for item in discovery["question_inputs"]:
                item["priority_band"] = "source_hypothesis"
            ordered = sorted(discovery["investigation_questions"], key=lambda q: (q["objective_id"], q["id"]))
            for question in ordered:
                question["route"] = "shared-flow"
                question["proof_obligation"] += question["local_key"]
            ordered[-1]["route"] = "other-flow"
            selected = contract.selected_candidates(index, discovery)
            self.assertIn(ordered[-1]["id"], {row["question_id"] for row in selected[:2]})
            best = next(row for row in discovery["question_inputs"] if row["question_id"] == ordered[-2]["id"])
            best["priority_band"] = "proof_obligation"
            self.assertEqual(contract.selected_candidates(index, discovery)[0]["question_id"], best["question_id"])
            urgent = next(row for row in discovery["question_inputs"] if row["question_id"] == ordered[-3]["id"])
            next(rec for rec in index["records"] if rec["id"] == urgent["evidence_ids"][0])["risk_context"] = {"priority": 1}
            self.assertEqual(contract.selected_candidates(index, discovery)[0]["question_id"], urgent["question_id"])


class GraphQuestionTests(unittest.TestCase):
    def test_question_intent_and_missing_dependency_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "service").mkdir()
            (project / "service/app.go").write_text("package main\nfunc entry() {}\n")
            (project / "service/go.sum").write_text("")
            (project / ".codegraph").mkdir()
            with closing(sqlite3.connect(project / ".codegraph/codegraph.db")) as db, db:
                db.execute("CREATE TABLE nodes (id TEXT, name TEXT, qualified_name TEXT, file_path TEXT, start_line INTEGER, kind TEXT)")
                db.execute("INSERT INTO nodes VALUES ('entry', 'entry', 'entry', 'service/app.go', 2, 'function')")
            entry = {"source_kind": "recon", "files": ["service/app.go"]}
            sink = {"source_kind": "sast", "files": ["service/app.go"]}
            self.assertEqual(planner.graph_question(entry, project)["type"], "callees")
            self.assertEqual(planner.graph_question(sink, project)["type"], "callers")
            self.assertEqual(planner.graph_question(sink, project, "impact")["type"], "impact")
            self.assertEqual(planner.graph_question(entry, project, "affected")["type"], "affected")
            self.assertEqual(planner.graph_question({**entry, "symbol": "entry"}, project, "query")["subject"], "entry")
            self.assertIsNone(planner.graph_question({"source_kind": "sca", "files": ["service/go.sum"]}, project))
            self.assertIsNone(planner.graph_question({"source_kind": "coverage", "files": []}, project))


if __name__ == "__main__":
    unittest.main()
