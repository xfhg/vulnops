from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from artifact_policy import DEFAULT_ARTIFACT_LIMIT, contains_raw_secret, publication_content_error
from test_sast_contextual_planning import attack_class, clean_result, mapping, threat_model
import test_campaign_discovery as discovery_fixtures
from campaign_contract import selected_candidates
from objective_fixtures import objective_binding


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator_module = load_module("exploration_validator", "validate-json.py")
hunt_builder = load_module("exploration_hunt_builder", "build-hunt-plan.py")
NOTE = {"explanation": ["Additional untrusted context", {"source_refs": ["not-evidence.py:999"],
        "status": "confirmed", "owner": "not-an-owner", "priority": 999}], "confidence_note": None}


def inventory():
    """Exact allowlist of extensible schema objects; control objects are not inferred."""
    provenance = {"actor": "vulnops-deepdive-chunk", "selector": "fixture/model", "artifact_ref": "sast/deepdive/T-1.json"}
    entry = {"id": "EP-1", "path": "app.py", "kind": "http", "evidence_refs": ["app.py:1"]}
    comparable = {"name": None, "basis": "Source-backed comparison", "confidence": "not_applicable"}
    observation = {"id": "O-1", "category": "source", "title": "Entry", "description": "Entry description", "evidence_refs": ["app.py:1"]}
    research = {"schema_version": "2.0", "worker": "overview", "status": "ok", "started_at": "now", "completed_at": "now",
                "observations": [observation], "warnings": [], "errors": [], "provenance": provenance}
    project = {"id": "P-1", "type": "backend", "base_path": "", "languages": ["python"], "frameworks": [],
               "dependency_files": [], "entry_points": [entry], "trust_boundary_ids": [], "ignore_patterns": [], "evidence_refs": ["app.py:1"]}
    actor = {"id": "ACT-1", "name": "caller", "trust_level": "untrusted", "evidence_refs": ["app.py:1"]}
    attack_path = {"id": "AP-1", "starting_actor": "caller", "entry_surface_ids": ["EP-1"], "controlled_material": ["input"],
                   "authority_decisions": [], "identity_propagation": [], "sensitive_effect": "return", "handoff_evidence": [], "unknowns": [], "source_refs": ["app.py:1"]}
    boundary = {"id": "TB-1", "project_id": "P-1", "source_trust": "caller", "target_trust": "service",
                "description": "Service boundary", "evidence_refs": ["app.py:1"], "contributors": [provenance]}
    threat = threat_model(["app.py"], [mapping("HM-1", "injection")], [attack_class("injection", "dataflow")])
    hunt = clean_result("T-1", "CELL-1", [], objective_binding(threat))
    note = {"title": "Control", "description": "Source control", "evidence_refs": ["app.py:1"]}
    correction = {"field": "title", "before": "Old", "after": "New", "reason": "More precise description"}
    review = {"schema_version": "2.0", "id": "V-1", "candidate_id": "C-1", "status": "rejected", "confidence": "high",
              "closure_reason": "Control defeats the path", "evidence_refs": ["app.py:1"], "corrections": [correction], "corrected_candidate": None,
              "mechanical_checks": dict.fromkeys(("schema", "paths", "lines", "trace_order", "target_unchanged"), True),
              "provenance": {**provenance, "actor": "vulnops-verify-one"}}
    answer = {"question_id": "Q-1", "receipt_ref": "receipt.json", "observation": "Graph navigation only", "disposition": "inconclusive",
              "source_locations": [], "limitations": [], "conclusion_effect": "No proof established"}
    relationship = {"id": "REL-000000000001", "primitive_ids": ["P-000000000001", "P-000000000002"], "evidence_ids": [],
                    "kind": "producer_consumer", "producer_id": None, "consumer_id": None, "disposition": "inconclusive",
                    "source_locations": [], "question_ids": [], "handoff": None, "reason": "Requires source investigation"}
    result = {"schema_version": "2.0", "campaign_id": "CAM-001", "status": "closed", "conclusion": "Reviewed source",
              **objective_binding(threat),
              "evidence_refs": ["app.py:1"], "graph_query_receipts": [], "graph_evidence_refs": [], "graph_answers": [answer],
              "graph_limitations": [], "primitive_updates": [], "candidates": [], "input_snapshot": {"ref": "intrusion/waves/000.json", "sha256": "a" * 64},
              "wave": 0, "resolution": hunt["cell_results"][0]["resolution"], "provenance": provenance,
              "composition": {"outcome": "none_actionable", "reason": "No demonstrated composition", "evidence_refs": [], "primitive_ids": []}}
    rows = [
        ("recon-research", "", research), ("recon-research", "properties/observations/items", observation),
        ("repo-context", "properties/comparable", comparable), ("repo-context", "properties/projects/items", project),
        ("repo-context", "properties/projects/items/properties/entry_points/items", entry), ("repo-context", "properties/actors/items", actor),
        ("security-surfaces", "properties/attack_paths/items", attack_path),
        ("security-surfaces", "properties/entry_points/items", {**entry, "project_id": "P-1", "trust_boundary_ids": [], "contributors": [provenance]}),
        ("security-surfaces", "properties/trust_boundaries/items", boundary),
        ("security-surfaces", "properties/security_relevant_files/items", {"path": "app.py", "categories": ["entry_point"], "evidence_refs": ["app.py:1"]}),
        ("threat-model", "properties/repository_profile", threat["repository_profile"]),
        ("threat-model", "properties/repository_profile/properties/comparable", comparable),
        *[("threat-model", f"properties/{name}/items", threat[name][0]) for name in ("assets", "trust_boundaries", "entrypoints", "subsystems", "threats")],
        ("hunt-result", "", hunt), ("hunt-result", "properties/cell_results/items", hunt["cell_results"][0]),
        ("hunt-result", "properties/hardening_notes/items", note), ("hunt-result", "properties/positive_patterns/items", note),
        ("validation-result", "", review), ("validation-result", "properties/corrections/items", correction),
        ("campaign-discovery", "properties/scanner_triage/items", {"evidence_id": "E-000000000001", "status": "uninvestigated", "reason": "Source review required", "evidence_refs": [], "missing_fact": "Reachability"}),
        ("campaign-discovery", "$defs/relationship", relationship), ("campaign-discovery", "$defs/answer", answer),
        ("intrusion-results", "$defs/result", result), ("intrusion-results", "$defs/graphAnswer", answer),
    ]
    return rows


def schema_at(name, pointer):
    root = json.loads((ROOT / "schemas/v2" / f"{name}.schema.json").read_text())
    schema = root
    for part in pointer.split("/") if pointer else []:
        schema = schema[part]
    return root, schema


class ExplorationExtensionTests(unittest.TestCase):
    def test_extensions_preserve_required_fields_and_reject_control_overrides(self):
        # Complete producer artifacts, rather than an inventory of schema locations.
        for name, pointer, baseline in inventory():
            if pointer or name not in {"recon-research", "hunt-result", "validation-result"}:
                continue
            with self.subTest(schema=name, object=pointer):
                root, schema = schema_at(name, pointer)
                validator = validator_module.Validator(root)
                self.assertEqual(validator.collect(baseline, schema), [])
                enriched = copy.deepcopy(baseline)
                enriched["investigative_note"] = copy.deepcopy(NOTE)
                before = copy.deepcopy(enriched)
                self.assertEqual(validator.collect(enriched, schema), [])
                self.assertEqual(enriched, before)
                required = schema["required"][0]
                typo = copy.deepcopy(enriched)
                typo[required + "_typo"] = typo.pop(required)
                self.assertTrue(any("missing required field" in error for error in validator.collect(typo, schema)))
                wrong_type = copy.deepcopy(enriched)
                wrong_type[required] = {} if isinstance(baseline[required], list) else []
                self.assertTrue(validator.collect(wrong_type, schema))

                for control, value in baseline.items():
                    if control not in {"provenance", "mechanical_checks"}:
                        continue
                    invalid = copy.deepcopy(enriched)
                    invalid[control]["invented_control"] = "override"
                    self.assertTrue(any("unexpected field 'invented_control'" in error
                                        for error in validator.collect(invalid, schema)))

    def test_extension_bounds_and_hygiene_are_enforced_without_echoing_secrets(self):
        root, schema = schema_at("recon-research", "properties/observations/items")
        validator = validator_module.Validator(root)
        record = inventory()[1][2]
        for extra in ("x" * 16385, list(range(129)), {f"k{i}": i for i in range(65)}, {"k" * 129: "value"}, {"control\x00key": "value"}):
            with self.subTest(extra_type=type(extra).__name__):
                self.assertTrue(validator.collect({**record, "note": extra}, schema))
        self.assertTrue(validator.collect({**record, **{f"note_{i}": i for i in range(65)}}, schema))
        self.assertTrue(validator.collect({**record, "k" * 129: "value"}, schema))
        for secret in ("-----BEGIN PRIVATE KEY-----", "ghp_" + "A" * 24, "AKIA" + "A" * 16, "sk-" + "A" * 24):
            self.assertTrue(contains_raw_secret(secret))
            for extra in ({"nested": [secret]}, {secret: "value"}):
                errors = validator.collect({**record, "note": extra}, schema)
                self.assertTrue(any("possible raw secret" in error for error in errors))
                self.assertNotIn(secret, "\n".join(errors))
        deep = "leaf"
        for _ in range(65):
            deep = [deep]
        self.assertIn("nesting bound", publication_content_error(deep))
        self.assertIn("size policy", publication_content_error("x" * DEFAULT_ARTIFACT_LIMIT))
        self.assertIn("non-finite", publication_content_error(float("nan")))
        self.assertIsNone(publication_content_error({"redacted": "ghp_<redacted>", "note": NOTE}))

    def test_notes_do_not_change_hunt_or_campaign_selection(self):
        threat = threat_model(["app.py"], [mapping("HM-1", "injection")], [attack_class("injection", "dataflow")])
        enriched = copy.deepcopy(threat)
        for name in ("assets", "trust_boundaries", "entrypoints", "subsystems", "threats"):
            enriched[name][0]["investigative_note"] = copy.deepcopy(NOTE)
        enriched["repository_profile"]["investigative_note"] = copy.deepcopy(NOTE)
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory)
            context = {"depth": "quick", "run_id": "test"}
            baseline = hunt_builder.initial_plan(ROOT, scan, context, threat)
            self.assertEqual(hunt_builder.initial_plan(ROOT, scan, context, enriched), baseline)
        with tempfile.TemporaryDirectory() as directory:
            fixtures = discovery_fixtures.DiscoveryTests()
            scan, target, context, index = fixtures.fixture(directory)
            discovery = fixtures.seal(scan, context, index)
            relationship = next(row for row in discovery["relationships"]
                                if row["primitive_ids"] == ["P-000000000003", "P-000000000004"])
            relationship.update(disposition="source-supported", kind="producer_consumer",
                                producer_id=relationship["primitive_ids"][0],
                                consumer_id=relationship["primitive_ids"][1],
                                reason="Reviewed producer capability reaches consumer.")
            relationship["source_locations"] = [
                {"file": index["records"][i]["files"][0], "start_line": 1, "end_line": 2}
                for i in (3, 4)]
            fixtures.bind_relationship(discovery, relationship, index["records"][3]["files"][0])
            for disposition in ("source-supported", "contradicted"):
                with self.subTest(disposition=disposition):
                    relationship["disposition"] = disposition
                    relationship.pop("investigative_note", None)
                    baseline = selected_candidates(index, discovery)
                    self.assertEqual(any(relationship["id"] in row["relationship_ids"] for row in baseline),
                                     disposition == "source-supported")
                    relationship["investigative_note"] = copy.deepcopy(NOTE)
                    root, schema = schema_at("campaign-discovery", "")
                    self.assertEqual(validator_module.Validator(root).collect(discovery, schema), [])
                    self.assertEqual(selected_candidates(index, discovery), baseline)


if __name__ == "__main__":
    unittest.main()
