from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from objective_fixtures import objective_binding, record_read_registry
from objective_contract import load_objectives, load_questions, stable_id, validate_binding, validate_registry


class ObjectiveContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.target, self.scan = self.base / "target", self.base / "scan"
        for name, source in {
            "gateway/handler.py": "def handler(record): return read_record(record)\n",
            "service/implementation.py": "def read_record(record): return storage[Record(record).id]\n",
            "shared/dto.py": "class Record: pass\n",
        }.items():
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        self.repositories = [{"path": name} for name in ("gateway", "service", "shared")]
        self.registry = record_read_registry()

    def validate(self, registry, **kwargs):
        return validate_registry(registry["attack_objectives"], registry["investigation_questions"],
                                 scan=self.scan, target=self.target, repositories=self.repositories, **kwargs)

    def publish(self, path, value):
        path = self.scan / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_stable_identity_is_owner_and_local_key_bound_not_evidence_bound(self):
        objectives, questions = self.validate(self.registry)
        binding = objective_binding(self.registry)
        validate_binding(binding, objectives, questions)
        # Persisted owner/key vector: changing ID derivation must not rename existing records.
        self.assertEqual(binding, {"objective_id": "OBJ-2B4893F8A528", "question_id": "Q-2B4893F8A528"})
        inherited = self.validate(copy.deepcopy(self.registry), inherited_objectives=objectives,
                                  inherited_questions=questions)
        self.assertEqual(inherited, (objectives, questions))
        other = record_read_registry(owner="sast/deepdive/H001.json")
        self.assertEqual(other["attack_objectives"][0]["evidence_refs"], self.registry["attack_objectives"][0]["evidence_refs"])
        self.assertNotEqual(objective_binding(other), binding)
        self.assertNotEqual(stable_id("Q-", "sast/threat-model.json", "second-route"), binding["question_id"])
        changed = copy.deepcopy(self.registry)
        changed["attack_objectives"][0]["desired_effect"] = "alter another tenant's stored record"
        self.assertEqual(changed["attack_objectives"][0]["id"], binding["objective_id"])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.validate(changed, inherited_objectives=objectives, inherited_questions=questions)

    def test_unknown_ownership_ids_and_bindings_are_rejected(self):
        for collection in ("attack_objectives", "investigation_questions"):
            for field, value in (("owner", "recon/surface.json"), ("id", "FORGED"), ("local_key", "different-key")):
                with self.subTest(collection=collection, field=field):
                    invalid = copy.deepcopy(self.registry)
                    invalid[collection][0][field] = value
                    with self.assertRaises(ValueError):
                        self.validate(invalid)
        objectives, questions = self.validate(self.registry)
        other = record_read_registry(owner="sast/deepdive/H001.json")
        objectives, questions = self.validate(other, inherited_objectives=objectives, inherited_questions=questions)
        binding = objective_binding(self.registry)
        for invalid in ({}, {**binding, "objective_id": "OBJ-UNKNOWN"}, {**binding, "question_id": "Q-UNKNOWN"},
                        {**binding, "question_id": objective_binding(other)["question_id"]}):
            with self.subTest(binding=invalid), self.assertRaises(ValueError):
                validate_binding(invalid, objectives, questions)

    def test_missing_or_artifact_only_source_cannot_acquire_authority(self):
        self.publish("sast/threat-model.json", self.registry)
        for collection in ("attack_objectives", "investigation_questions"):
            for refs in ([], ["sast/threat-model.json"], ["gateway/missing.py:1"], ["unknown/handler.py:1"]):
                with self.subTest(collection=collection, refs=refs):
                    invalid = copy.deepcopy(self.registry)
                    invalid[collection][0]["evidence_refs"] = refs
                    with self.assertRaises(ValueError):
                        self.validate(invalid)
        invalid = copy.deepcopy(self.registry)
        invalid["investigation_questions"][0]["objective_id"] = "OBJ-UNKNOWN"
        with self.assertRaises(ValueError):
            self.validate(invalid)

    def test_resolved_source_retains_identity_with_broken_secondary_citation(self):
        registry = copy.deepcopy(self.registry)
        for collection in ("attack_objectives", "investigation_questions"):
            registry[collection][0]["evidence_refs"].append("gateway/missing.py:1")
        before = copy.deepcopy(registry)
        objectives, questions = self.validate(registry)
        binding = objective_binding(registry)
        validate_binding(binding, objectives, questions)
        self.assertEqual(objectives[binding["objective_id"]], registry["attack_objectives"][0])
        self.assertEqual(questions[binding["question_id"]], registry["investigation_questions"][0])
        self.assertEqual(binding, objective_binding(self.registry))
        self.assertEqual(registry, before)
        for collection in ("attack_objectives", "investigation_questions"):
            unsafe = copy.deepcopy(registry)
            unsafe[collection][0]["evidence_refs"].append("../escape.py:1")
            with self.subTest(collection=collection), self.assertRaises(ValueError):
                self.validate(unsafe)

    def test_inherited_definitions_and_cross_repository_anchors_survive_load(self):
        self.publish("sast/threat-model.json", self.registry)
        self.publish("sast/hunt-plan.json", self.registry)
        self.publish("campaign-planning/evidence-index.json", self.registry)
        before = {path: path.read_bytes() for path in self.scan.rglob("*.json")}
        objectives, questions = self.validate(self.registry)
        self.assertEqual(load_objectives(self.scan), objectives)
        self.assertEqual(load_questions(self.scan), questions)
        self.assertEqual(next(iter(objectives.values()))["evidence_refs"],
                         ["gateway/handler.py:1", "service/implementation.py:1", "shared/dto.py:1"])
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        conflicting = copy.deepcopy(self.registry)
        conflicting["investigation_questions"][0]["proof_obligation"] = "a replacement obligation not approved by the owner"
        self.publish("sast/hunt-plan.json", conflicting)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            load_questions(self.scan)
        self.publish("sast/hunt-plan.json", self.registry)
        for collection in ("attack_objectives", "investigation_questions"):
            duplicate = copy.deepcopy(self.registry)
            duplicate[collection].append(copy.deepcopy(duplicate[collection][0]))
            with self.subTest(collection=collection), self.assertRaises(ValueError):
                self.validate(duplicate)
            conflicting = copy.deepcopy(self.registry)
            changed = copy.deepcopy(conflicting[collection][0])
            changed["evidence_refs"] = ["gateway/handler.py:1"]
            conflicting[collection].append(changed)
            self.publish("sast/threat-model.json", conflicting)
            with self.subTest(collection=collection), self.assertRaises(ValueError):
                load_objectives(self.scan)

    def test_derived_registry_requires_matching_canonical_owner(self):
        self.publish("sast/hunt-plan.json", self.registry)
        with self.assertRaisesRegex(ValueError, "authority is missing"):
            load_objectives(self.scan)
        self.publish("sast/threat-model.json", {"attack_objectives": [], "investigation_questions": []})
        with self.assertRaisesRegex(ValueError, "owning definition"):
            load_questions(self.scan)



if __name__ == "__main__":
    unittest.main()
