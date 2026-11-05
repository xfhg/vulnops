"""Source-backed index bindings; synthetic files are inspected, never executed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from objective_contract import stable_id
from test_run_lifecycle import activate_publisher


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class EvidenceObjectives(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.scan = self.base / "scan"
        self.target = self.base / "source"
        self.target.mkdir()
        (self.target / "store.py").write_text(
            "def write_row(rows, tenant, value):\n    rows[tenant] = value\n"
            "def read_row(rows, tenant):\n    return rows[tenant]\n")
        self.builder = module("build-evidence-index")
        self.origin = {"actor": "vulnops-deepdive-chunk", "selector": "p/source:high",
                       "artifact_ref": "sast/deepdive/T.json"}
        authority = {"run_id": "objective-index", "source_root": str(self.target), "scan_base": str(self.scan),
                     "repositories": [{"path": "."}], "model_routing": {"agents": {self.origin["actor"]: self.origin["selector"]}}}
        self.context = self.save("context.json", authority)
        environment = patch.dict(os.environ, activate_publisher(self.scan, authority, "campaign-planning", os.environ))
        environment.start()
        self.addCleanup(environment.stop)
        self.objective, self.question = self.definition("sast/threat-model.json", "write", "store.py:1-2",
            "Change another tenant's stored row", "A caller-selected tenant key changes a row outside the caller's tenant",
            "Can caller-selected tenant keys bypass the write authorization boundary?")
        self.added_objective, self.added_question = self.definition("sast/deepdive/T.json", "read", "store.py:3-4",
            "Read another tenant's stored row", "A caller-selected tenant key returns a row outside the caller's tenant",
            "Does the adjacent read consumer enforce the caller's tenant scope?")
        self.added_objective["parent_objective_id"] = self.objective["id"]
        self.binding = {"objective_id": self.objective["id"], "question_id": self.question["id"]}
        self.added_binding = {"objective_id": self.added_objective["id"], "question_id": self.added_question["id"]}
        self.save("sast/threat-model.json", {"attack_objectives": [self.objective], "investigation_questions": [self.question],
            "hunt_mappings": [{"id": "HM-1", **self.binding, "source_files": ["store.py"],
                "security_question": self.question["security_question"], "evidence_refs": ["store.py:1-2"]}]})
        self.save("sast/hunt-plan.json", {"cells": [{"id": "CELL-1", "mapping_id": "HM-1", **self.binding, "files": ["store.py"]}]})
        self.checkpoint = {**self.binding, "established_facts": ["The write accepts a tenant key."], "contradicted_paths": [],
            "remaining_question": "Is caller scope checked before the write?", "files_reviewed": ["store.py:1-2"],
            "next_step": "Inspect callers of write_row for tenant authorization.", "expected_results": []}
        self.save("sast/coverage-ledger.json", {"cells": [{"id": "CELL-1", **self.binding, "status": "locally_unresolved",
            "reason": "The caller-side authorization check is not yet established.", "evidence_refs": ["store.py:1-2"],
            "checkpoint": self.checkpoint, "resolution": {"outcome": "locally_unresolved", "reason": "Caller check unresolved",
                "evidence_refs": ["store.py:1-2"], "missing_fact": "Caller tenant authorization", "next_action": "Inspect callers"}}],
            "tasks": [{"id": "T", "artifact_valid": True, "files_reviewed": ["store.py"], "rabbit_holes": ["Adjacent read requires review"]}]})
        self.save(self.origin["artifact_ref"], {"provenance": self.origin,
            "model_amendments": [{"id": entity["id"], "kind": kind, **self.added_binding, "entity": entity,
                "question": self.added_question["security_question"], "source_refs": ["store.py:3-4"]}
                for kind, entity in (("objective", self.added_objective), ("question", self.added_question))],
            "rabbit_holes": [{**self.added_binding, "reason": "Adjacent read requires review", "files": ["store.py"],
                "evidence_refs": ["store.py:3-4"]}]})
        candidate = {**self.binding, "title": "Caller-selected tenant write", "root_cause_location": {"file": "store.py", "start_line": 2},
                     "evidence_refs": ["store.py:1-2"], "contributors": [self.origin]}
        self.save("sast/raw-findings.json", [{"id": "C-RAW", **candidate}, {"id": "C-REJECT", **candidate},
            {"id": "C-UNANCHORED", "title": "Unknown caller effect", "evidence_refs": ["missing.py:1"]}])
        self.save("sast/dropped-findings.json", [{"id": "D-1", "raw_id": "C-REJECT", "status": "rejected", "reason": "The inspected route is guarded."}])
        self.save("sast/verified-findings.json", [{"id": "C-VERIFIED", **candidate, "verification_level": "source_verified",
            "attacker": {"starting_access": "Caller of write_row", "boundary_crossed": "Tenant write authorization"},
            "impact": "A caller-selected tenant row can change."}])

    def definition(self, owner, key, ref, effect, success, question):
        objective = {"id": stable_id("OBJ-", owner, key), "owner": owner, "local_key": key,
            "starting_actor": "Caller of the tenant store API", "controlled_material": "Tenant key passed to the store function",
            "resource_scope": "Rows indexed by tenant key in the supplied store", "desired_effect": effect,
            "success_condition": success, "evidence_refs": [ref]}
        inquiry = {"id": stable_id("Q-", owner, key + "-authorization"), "owner": owner, "local_key": key + "-authorization",
            "objective_id": objective["id"], "security_question": question, "route": key + "_row caller to store operation",
            "proof_obligation": "Establish whether the caller's tenant authority gates the selected row",
            "novelty_reason": "Inspect the " + key + " effect and its separate caller authorization obligation", "evidence_refs": [ref]}
        return objective, inquiry

    def save(self, relative, value):
        path = self.scan / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def build(self):
        with patch.object(sys, "argv", ["build-evidence-index", str(self.scan), "--context", str(self.context)]):
            self.assertEqual(self.builder.main(), 0)
        return json.loads((self.scan / "campaign-planning/evidence-index.json").read_text())

    def test_retains_source_owned_goals_checkpoints_and_rejections(self):
        before = {path: path.read_bytes() for path in (self.scan / "sast").rglob("*.json")}
        index = self.build()
        self.assertEqual(index["attack_objectives"], [self.objective, self.added_objective])
        self.assertEqual(index["investigation_questions"], [self.question, self.added_question])
        records = {row["source_id"]: row for row in index["records"]}
        for source_id in ("HM-1", "CELL-1", "C-RAW", "C-REJECT", "C-VERIFIED"):
            self.assertEqual({key: records[source_id][key] for key in self.binding}, self.binding)
        self.assertEqual(records["CELL-1"]["checkpoint"], self.checkpoint)
        self.assertEqual(records["CELL-1"]["resolution"]["outcome"], "locally_unresolved")
        self.assertEqual(records["C-REJECT"]["disposition"], "rejected")
        self.assertEqual(records["C-REJECT"]["contributors"], [self.origin])
        self.assertEqual(records["C-VERIFIED"]["contributors"], [self.origin])
        self.assertEqual({key: records["T-rabbit-1"][key] for key in self.added_binding}, self.added_binding)
        unanchored = records["C-UNANCHORED"]
        self.assertNotIn("objective_id", unanchored)
        self.assertNotIn("question_id", unanchored)
        self.assertEqual(unanchored["files"], ["missing.py"])
        self.assertTrue(any("Historical observation" in limitation for limitation in unanchored["anchor_limitations"]))
        self.assertFalse(any(primitive["capability"]["evidence_status"] == "source_established"
                             for primitive in index["primitives"] if unanchored["id"] in primitive["source_record_ids"]))
        self.assertIn(unanchored["id"], index["coverage_gaps"])
        self.assertTrue(unanchored["anchor_limitations"])
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        schema = json.loads((ROOT / "schemas/v2/evidence-index.schema.json").read_text())
        validator = module("validate-json").Validator(schema)
        self.assertEqual(validator.collect(index, schema), [])
        incomplete = copy.deepcopy(index)
        del incomplete["records"][0]["question_id"]
        self.assertTrue(validator.collect(incomplete, schema))

    def test_rejects_partial_unknown_and_conflicting_bindings(self):
        path = self.scan / "sast/raw-findings.json"
        original = json.loads(path.read_text())
        for invalid in ({"objective_id": self.objective["id"]},
                        {"question_id": self.question["id"]},
                        {"objective_id": "OBJ-000000000000", "question_id": self.question["id"]},
                        {"objective_id": self.objective["id"], "question_id": self.added_question["id"]}):
            with self.subTest(binding=invalid):
                rows = copy.deepcopy(original)
                rows[0] = {key: value for key, value in rows[0].items() if key not in self.binding}
                rows[0].update(invalid)
                self.save("sast/raw-findings.json", rows)
                with self.assertRaisesRegex(ValueError, "binding"):
                    self.build()
        self.save("sast/raw-findings.json", original)
        ledger_path = self.scan / "sast/coverage-ledger.json"
        ledger = json.loads(ledger_path.read_text())
        ledger["cells"][0]["checkpoint"].update(self.added_binding)
        self.save("sast/coverage-ledger.json", ledger)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.build()

    def test_rebuild_does_not_import_downstream_objectives(self):
        before = self.build()
        objective, question = self.definition("campaign-planning/discovery.json", "caller-write", "store.py:1-2",
            "Alter tenant rows through an exposed caller", "A reachable caller forwards an unauthorized tenant key",
            "Which externally reachable caller forwards the selected tenant key?")
        self.save("campaign-planning/discovery.json",
                  {"attack_objectives": [objective], "investigation_questions": [question]})
        self.assertEqual(self.build(), before)

if __name__ == "__main__":
    unittest.main()

