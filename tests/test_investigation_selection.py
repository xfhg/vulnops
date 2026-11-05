"""Behavior checks for A05–A07 and accountable source-first selection."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_campaign_discovery as discovery_tests
from intrusion_contract import OBLIGATIONS, available_primitives, build_wave, reference, validate_transitions
from test_run_lifecycle import activate_publisher

planner, contract = discovery_tests.planner, discovery_tests.contract


class InvestigationSelectionTests(unittest.TestCase):
    def fixture(self, directory, scanner_count=0, secret=False):
        scan, target, context, index = discovery_tests.DiscoveryTests().fixture(directory, count=2)
        for i in range(scanner_count):
            index["records"].append({"id": f"E-{i + 1000:012X}", "source_kind": "secret" if secret else "sca",
                "source_id": str(i), "artifact_ref": f"tool-collection/observations.json:{i}",
                "disposition": "unresolved", "summary": "Redacted observation" if secret else "Dependency observation",
                "files": [f"locks/{i}.lock"], "source_anchors": [], "subsystems": [], "anchor_limitations": [], "contributors": []})
        planner.write(scan / "campaign-planning/evidence-index.json", index)
        discovery = discovery_tests.DiscoveryTests().seal(scan, context, index)
        return scan, target, context, index, discovery

    def test_a06_secret_only_has_explicit_route_without_credential_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, _ = discovery_tests.DiscoveryTests().fixture(directory, count=2)
            file = "alpha/token.conf"
            (target / file).write_text("role=record-reader\ncredential=<redacted>\n")
            planner.write(scan / "tool-collection/secrets-redacted.json", {
                "schema_version": "2.0", "tool": "poltergeist", "match_count": 1,
                "candidate_count": 1, "candidates": [{
                    "id": "SEC-000000000001", "type": "token", "file": file,
                    "exposure_path": "repository source requires validation"}]})
            environment = activate_publisher(scan, context, "campaign-planning",
                {**os.environ, "VULNOPS_RUNTIME_ROOT": str(scan.parent / "runtime")})
            context_path = scan.parent / "context.json"
            planner.write(context_path, context)
            with patch.dict(os.environ, environment), patch.object(sys, "argv", [
                    "build-evidence-index.py", str(scan), "--context", str(context_path)]):
                self.assertEqual(discovery_tests.evidence_builder.main(), 0)
            index = json.loads((scan / "campaign-planning/evidence-index.json").read_text())
            self.assertEqual([row["source_kind"] for row in index["records"]], ["secret"])
            self.assertEqual(index["primitives"], [])
            discovery = contract.prepare_discovery(scan, context, index)
            objective, question = discovery_tests.DiscoveryTests().definitions("secret-exposure", file, "campaign-planning/discovery.json")
            objective.update(starting_actor="Source distribution reader", controlled_material="Distributed configuration",
                             desired_effect="Acquire unintended record-read authority",
                             success_condition="The exposed material grants the reader unauthorized record access.")
            question.update(security_question="Does the redacted material carry unintended record-read authority?",
                            proof_obligation="Establish exposure and material role without credential use.")
            discovery["attack_objectives"].append(objective)
            discovery["investigation_questions"].append(question)
            discovery["question_inputs"].append({"objective_id": objective["id"], "question_id": question["id"],
                "evidence_ids": [index["records"][0]["id"]], "primitive_ids": [], "relationship_ids": [],
                "lane": "direct_validation", "priority_band": "scanner_triage",
                "reason": "Inspect exposed material role without claiming credential validity."})
            planner.close_discovery(scan, discovery)
            planner.write(scan / "campaign-planning/discovery.json", discovery)
            plan = planner.build_plan(scan, context, index, discovery)
            contract.validate_selection(scan, target, context, plan)
            self.assertEqual(plan["scanner_accounting"][0]["status"], "selected")
            self.assertEqual(plan["campaigns"][0]["primitive_ids"], [])
            self.assertEqual(plan["campaigns"][0]["attacker_capability"],
                             "Not established; investigate attacker access from the cited source.")

    def test_a07_contextual_capability_is_considered_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            scan, target, context, index = discovery_tests.DiscoveryTests().fixture(directory, count=1)
            index["primitives"][0]["trust"] = "context_only"
            index["primitives"][0]["capability"] = {"actor": "Tenant owner", "operation": "write",
                "resource_scope": "Own tenant queue", "authority": "Tenant ownership", "conditions": ["Authenticated owner"],
                "evidence_status": "source_established", "provenance": ["repo-context/security-surfaces.json:queue"],
                "restrictions": ["Does not grant another tenant's authority"]}
            planner.write(scan / "campaign-planning/evidence-index.json", index)
            discovery = discovery_tests.DiscoveryTests().seal(scan, context, index)
            primitive_id = index["primitives"][0]["id"]
            plan = planner.build_plan(scan, context, index, discovery)
            contract.validate_selection(scan, target, context, plan)
            selected = next(c for c in plan["campaigns"] if primitive_id in c["primitive_ids"])
            self.assertEqual(selected["attacker_capability"],
                             "Unconfirmed source question: " + index["primitives"][0]["capability_gained"])
            planner.write(scan / "campaign-planning/campaign-plan.json", plan)
            planner.write(scan / "run-manifest.json", {
                "run_id": context["run_id"], "status": "incomplete", "phases": {"intrusion": "running"}})
            wave = build_wave(scan, target, context)
            owner = selected["id"]
            result = {"campaign_id": owner, "wave": wave["wave"], "input_snapshot": reference(scan, wave),
                      "primitive_updates": [], "candidates": [],
                      "provenance": {"actor": "vulnops-intrusion-campaign",
                          "selector": context["model_routing"]["agents"]["vulnops-intrusion-campaign"],
                          "artifact_ref": f"intrusion/results/{owner}.json"}}
            known = available_primitives(scan, context, index, result)
            self.assertEqual(known[primitive_id]["trust"], "candidate")
            self.assertEqual(known[primitive_id]["capability"]["evidence_status"], "hypothesized")
            # Scheduling this contextual observation does not establish a downstream transition.
            proof = {"outcome": "established", "reason": "Authored consumer mapping",
                     "evidence_refs": ["campaign-planning/campaign-plan.json"],
                     "source_locations": [{"file": index["records"][0]["files"][0], "start_line": 1, "end_line": 2}]}
            transition = {"producer_id": primitive_id, "consumer_id": "consumer",
                          "resolution": {"outcome": "established", "reason": "Claimed scheduled authority",
                              "next_action": "", "missing_fact": "",
                              "evidence_refs": ["campaign-planning/campaign-plan.json"]},
                          "obligations": {key: copy.deepcopy(proof) for key in OBLIGATIONS}}
            known["consumer"] = {"capability": {"evidence_status": "source_established"}}
            established = copy.deepcopy(known)
            established[primitive_id]["capability"]["evidence_status"] = "source_established"
            validate_transitions(scan, target, [primitive_id, "consumer"], [transition], established)
            with self.assertRaisesRegex(ValueError, "unestablished capability"):
                validate_transitions(scan, target, [primitive_id, "consumer"], [transition], known)


if __name__ == "__main__":
    unittest.main()
