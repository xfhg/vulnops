from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_run_lifecycle import activate_publisher

from test_investigation_source import ROOT, ROUTING, fixture, finalizer, load_module, planner
from sast_contract import validate_review_result
from evidence_accounting import synthesis_inputs
from objective_contract import stable_id
from objective_fixtures import record_read_registry


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class SastOutcomeLabelsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name).resolve()
        self.repo, self.scan = base / "target", base / "scan"
        for name, source in {
            "gateway/handler.py": "def handler(record): return read_record(record)\n",
            "service/implementation.py": "def read_record(record): return storage[Record(record).id]\n",
            "shared/dto.py": "class Record: pass\n",
        }.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        self.repositories = [{"path": name} for name in ("gateway", "service", "shared")]
        self.routing = {"agents": {**ROUTING["agents"], "vulnops-synthesis": "test/red:high"}}
        self.context = {"run_id": "outcomes", "repo_path": str(self.repo), "source_root": str(self.repo),
                        "scan_base": str(self.scan), "repositories": self.repositories,
                        "model_routing": self.routing, "reproduction_mode": "off"}
        self.context["attempt_id"] = "current-source-review"
        self.context["phase_attempts"] = {"sast": self.context["attempt_id"]}
        self.context["attempt_contexts"] = {"current-source-review": {
            "model_routing": self.routing, "repositories": self.repositories,
            "source_root": str(self.repo), "started_at": "fixture"}}
        self.context_path = base / "context.json"
        write(self.context_path, self.context)
        write(self.scan / "run-manifest.json", self.context)
        environment = patch.dict(os.environ, activate_publisher(self.scan, self.context, "sast",
                                 {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.context_path)}))
        environment.start()
        self.addCleanup(environment.stop)
        cell, task, result = fixture()
        result["assessment_context"] = {"attempt_id": self.context["attempt_id"]}
        self.registry = record_read_registry()
        second_question = {**self.registry["investigation_questions"][0],
                           "id": stable_id("Q-", "sast/threat-model.json", "dto-owner-binding"),
                           "local_key": "dto-owner-binding",
                           "security_question": "Does DTO construction retain an owner binding before the storage read?",
                           "route": "shared/dto.py Record construction to service/implementation.py storage access",
                           "proof_obligation": "establish whether the DTO supplies a trusted owner restriction independently of the handler",
                           "novelty_reason": "separate DTO-construction enforcement obligation, not the handler authorization check"}
        self.registry["investigation_questions"].append(second_question)
        second_cell = {**cell, "id": "CELL-2", "mapping_id": "MAP-2", "question_id": second_question["id"],
                       "security_question": second_question["security_question"]}
        second_task = planner.make_task("H002", [second_cell], 1, 0)
        second = copy.deepcopy(result)
        second["task_id"] = "H002"
        second["provenance"]["artifact_ref"] = "sast/deepdive/H002.json"
        candidate = second["candidates"][0]
        candidate.update(id="LOCAL-2", task_id="H002", cell_ids=["CELL-2"], contributors=[second["provenance"]],
                         question_id=second_question["id"])
        candidate["root_cause_location"]["mechanism"] = "distinct synthetic ownership obligation"
        second["cell_results"][0].update(cell_id="CELL-2", candidate_ids=["LOCAL-2"], question_id=second_question["id"])
        second["cell_results"][0]["checkpoint"]["question_id"] = second_question["id"]
        self.plan = {**self.registry, "schema_version": "2.0", "run_id": "outcomes", "cells": [cell, second_cell],
                     "tasks": [task, second_task], "budget": {"max_hunt_tasks": 8, "max_hunt_questions": 12,
                     "max_gapfill_rounds": 3, "max_attempts": 2}, "warnings": [], "errors": []}
        write(self.scan / "sast/hunt-plan.json", self.plan)
        write(self.scan / "sast/threat-model.json", self.registry)
        write(self.scan / "sast/deepdive/H001.json", result)
        write(self.scan / "sast/deepdive/H002.json", second)
        self.queue, _, _ = finalizer.aggregate(ROOT, self.repo, self.scan)
        self.candidate = next(row for row in self.queue if row["task_id"] == "H001")
        self.other = next(row for row in self.queue if row["task_id"] == "H002")

    def review(self, candidate=None):
        candidate = candidate or self.candidate
        return {"schema_version": "2.0", "id": "V-" + candidate["task_id"],
                "assessment_context": {"attempt_id": self.context["attempt_id"]},
                "candidate_id": candidate["id"], "status": "source_verified", "confidence": "high",
                "closure_reason": "Source trace establishes the claimed ownership bypass.",
                "evidence_refs": ["gateway/handler.py:1", "service/implementation.py:1"],
                "corrections": [{"field": "trace", "before": "initial trace", "after": "reviewed trace",
                                 "reason": "Explicitly record the reviewed propagation."}],
                "corrected_candidate": copy.deepcopy(candidate),
                "mechanical_checks": dict.fromkeys(("schema", "paths", "lines", "trace_order", "target_unchanged"), True),
                "provenance": {"actor": "vulnops-verify-one", "selector": self.routing["agents"]["vulnops-verify-one"],
                               "artifact_ref": f"sast/verify/{candidate['id']}.json"}}

    def check_review(self, review):
        write(self.scan / review["provenance"]["artifact_ref"], review)
        return validate_review_result(ROOT, self.repo, self.candidate, review, scan=self.scan,
                                      repositories=self.repositories, routing=self.routing)

    def limited_review(self):
        review = self.review()
        review["corrected_candidate"]["trace"][1]["kind"] = "sink"
        errors = self.check_review(review)
        self.assertEqual(errors, ["$.trace[1].kind must be 'propagation'"])
        closure = {"id": self.candidate["id"], "input_refs": [f"sast/validation-queue.json:{self.candidate['id']}"],
                   "disposition": "evidence_limited", "reason": "Correction remains malformed: " + errors[0],
                   "risk_context": "Tenant input reaches a record read without established ownership proof.",
                   "missing_fact": "A valid reviewed propagation trace establishing the ownership bypass.",
                   "next_action": "Repair the reviewer-owned trace from inspected source before promotion.",
                   "review": None, "deferral": {"kind": "budget", "reason": "The existing reviewer repair attempt allowance was exhausted after the returned trace remained malformed."},
                   "correction_repair": {"attempted": "Returned the exact trace diagnostic to the same reviewer; its bounded repair still used an interior sink.",
                                         "diagnostics": errors}}
        review.update(status="evidence_limited", non_promoted=closure, closure_reason=closure["reason"])
        self.assertEqual(self.check_review(review), [])
        return review

    def optional_review(self, status="evidence_limited", corrected=False):
        activate_publisher(self.scan, self.context, "sast", os.environ)
        path = self.scan / "sast/deepdive/H001.json"
        source = json.loads(path.read_text())
        missing = "gateway/handler.py:1-3"
        source["candidates"][0]["evidence_refs"].append(missing)
        write(path, source)
        self.queue, _, _ = finalizer.aggregate(ROOT, self.repo, self.scan)
        self.candidate = next(row for row in self.queue if row["task_id"] == "H001")
        review = self.review()
        if corrected:
            replacement = "service/implementation.py:1-3"
            review["corrected_candidate"]["evidence_refs"] = [
                ref for ref in self.candidate["evidence_refs"] if ref != missing] + [replacement]
            missing = replacement
        else:
            review.update(corrected_candidate=None, corrections=[])
        review["optional_support"] = [{
            "reference": missing, "obligation": "Effect-side ownership restriction",
            "independent_support": ["service/implementation.py:1"],
            "rationale": "The inspected storage access independently shows the missing owner predicate; the oversized duplicate selector adds no proof."}]
        review["status"] = status
        if status == "evidence_limited":
            closure = {
                "id": self.candidate["id"],
                "input_refs": [f"sast/validation-queue.json:{self.candidate['id']}"],
                "disposition": "evidence_limited", "reason": "Review repair allowance exhausted.",
                "risk_context": "Caller-controlled record selection reaches a storage consumer.",
                "missing_fact": "Complete reviewed effect-side ownership proof.",
                "next_action": "Inspect the storage authority and return a complete correction.",
                "review": None,
                "deferral": {"kind": "budget", "reason": "Both assigned review attempts were consumed investigating the effect-side ownership obligation."},
                "correction_repair": {"attempted": "Returned bounded source selectors during the final repair attempt.",
                                      "diagnostics": ["The original source selector extends beyond the file."]}}
            review.update(non_promoted=closure, closure_reason=closure["reason"])
            review["mechanical_checks"]["lines"] = False
        write(self.scan / review["provenance"]["artifact_ref"], review)
        return review

    def publish_reviews(self, review):
        activate_publisher(self.scan, self.context, "sast", os.environ)
        other = self.review(self.other)
        write(self.scan / other["provenance"]["artifact_ref"], other)
        write(self.scan / review["provenance"]["artifact_ref"], review)
        write(self.scan / "sast/validation-results.json", [review, other])
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/finalize-sast.py"), str(self.repo), str(self.scan), "--finalize"],
            env={**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.context_path)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads((self.scan / "sast/verified-findings.json").read_text())

    def campaign_errors(self, index):
        validator = load_module("outcome_phase_validator", "validate-phase-v2.py")
        write(self.scan / "tool-collection/sca-advisories.json", {"advisories": []})
        write(self.scan / "tool-collection/secrets-redacted.json", {"candidates": []})
        plan = {"campaigns": [], "coverage": {"evidence_records": len(index["records"]),
                "primitives": len(index["primitives"]), "campaigns": 0}}
        errors = []
        validator.semantic_campaign(self.scan, self.repo, index, plan, errors, self.context)
        return errors

    def test_optional_repair_history_survives_index_with_valid_peer(self):
        review = self.optional_review()
        verified = self.publish_reviews(review)
        self.assertEqual([row["id"] for row in verified], [self.other["id"]])
        before = {path: path.read_bytes() for path in (self.scan / "sast").rglob("*") if path.is_file()}
        activate_publisher(self.scan, self.context, "campaign-planning", os.environ)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/build-evidence-index.py"), str(self.scan), "--context", str(self.context_path)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        index = json.loads((self.scan / "campaign-planning/evidence-index.json").read_text())
        records = [row for row in index["records"] if row["source_id"] in {self.candidate["id"], review["id"]}]
        self.assertEqual({row["source_id"] for row in records}, {self.candidate["id"], review["id"]})
        for row in records:
            self.assertEqual(row["disposition"], "evidence_limited")
            self.assertEqual(row["non_promoted"], review["non_promoted"])
            self.assertEqual(row["objective_id"], self.candidate["objective_id"])
            self.assertEqual(row["question_id"], self.candidate["question_id"])
        limited_ids = {row["id"] for row in records}
        self.assertFalse(any(limited_ids.intersection(row["source_record_ids"]) for row in index["primitives"]))
        self.assertTrue(any(row["source_id"] == self.other["id"] and row["disposition"] == "promoted" for row in index["records"]))
        self.assertEqual(self.campaign_errors(index), [])
        review_record = next(row for row in records if row["source_id"] == review["id"])
        for actor in ("vulnops-deepdive-chunk", "vulnops-verify-one"):
            altered = copy.deepcopy(index)
            row = next(row for row in altered["records"] if row["id"] == review_record["id"])
            row["contributors"] = [item for item in row["contributors"] if item["actor"] != actor]
            self.assertTrue(self.campaign_errors(altered), actor)
        altered = copy.deepcopy(index)
        row = next(row for row in altered["records"] if row["id"] == review_record["id"])
        peer = next(row for row in index["records"] if row["source_id"] == "V-" + self.other["task_id"])
        row["contributors"] = sorted([*row["contributors"], peer["contributors"][-1]],
                                    key=lambda item: (item["actor"], item["selector"], item["artifact_ref"]))
        self.assertTrue(self.campaign_errors(altered))
        for candidate_id in (self.other["id"], "C-MISSING"):
            path = self.scan / "sast/validation-results.json"
            original = path.read_bytes()
            changed = json.loads(original)
            next(row for row in changed if row["id"] == review["id"])["candidate_id"] = candidate_id
            try:
                write(path, changed)
                self.assertTrue(self.campaign_errors(index), candidate_id)
            finally:
                path.write_bytes(original)
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_successful_optional_support_uses_original_or_corrected_owner(self):
        for corrected in (False, True):
            with self.subTest(corrected=corrected):
                review = self.optional_review("source_verified", corrected=corrected)
                verified = self.publish_reviews(review)
                accepted = next(row for row in verified if row["id"] == self.candidate["id"])
                before = {path: path.read_bytes() for path in (self.scan / "sast").rglob("*") if path.is_file()}
                activate_publisher(self.scan, self.context, "campaign-planning", os.environ)
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/build-evidence-index.py"), str(self.scan), "--context", str(self.context_path)],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                index = json.loads((self.scan / "campaign-planning/evidence-index.json").read_text())
                record = next(row for row in index["records"] if row["source_id"] == review["id"])
                self.assertEqual(record["disposition"], "promoted")
                self.assertEqual(record["evidence_refs"], accepted["evidence_refs"])
                self.assertEqual(record["contributors"], accepted["contributors"])
                self.assertNotIn(review["optional_support"][0]["reference"], record["evidence_refs"])
                self.assertEqual(self.campaign_errors(index), [])
                self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_review_ids_are_local_to_the_validation_artifact(self):
        for limited in (False, True):
            with self.subTest(limited=limited):
                review = self.limited_review() if limited else self.review()
                review["id"] = self.other["id"] if limited else self.candidate["id"]
                verified = self.publish_reviews(review)
                before = {path: path.read_bytes() for path in (self.scan / "sast").rglob("*") if path.is_file()}
                activate_publisher(self.scan, self.context, "campaign-planning", os.environ)
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/build-evidence-index.py"), str(self.scan),
                     "--context", str(self.context_path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                index = json.loads((self.scan / "campaign-planning/evidence-index.json").read_text())
                records = {row["artifact_ref"]: row for row in index["records"]}
                review_record = records[f"sast/validation-results.json:{review['id']}"]
                accepted = {row["id"]: row for row in verified}
                collision_record = records[f"sast/verified-findings.json:{review['id']}"]
                self.assertNotEqual(review_record["id"], collision_record["id"])
                self.assertEqual(review_record["source_id"], collision_record["source_id"])
                self.assertEqual(review_record["question_id"], self.candidate["question_id"])
                self.assertEqual(collision_record["question_id"], accepted[review["id"]]["question_id"])
                self.assertEqual(collision_record["contributors"], accepted[review["id"]]["contributors"])
                self.assertEqual(collision_record["disposition"], "promoted")
                self.assertNotIn("non_promoted", collision_record)
                self.assertEqual(review_record["disposition"], "evidence_limited" if limited else "promoted")
                self.assertIn(review["provenance"], review_record["contributors"])
                if limited:
                    self.assertEqual(review_record["non_promoted"], review["non_promoted"])
                    self.assertNotIn(review["provenance"], collision_record["contributors"])
                self.assertEqual(self.campaign_errors(index), [])
                self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_terminal_optional_history_cannot_hide_unsafe_sources(self):
        builder = load_module("outcome_evidence_builder", "build-evidence-index.py")
        review = self.optional_review()
        for status, disposition in (("evidence_limited", "evidence_limited"), ("source_verified", "evidence_limited"),
                                    ("rejected", "rejected"), ("deferred", "unresolved")):
            with self.subTest(status=status):
                row = {**review, "status": status}
                record = {"id": "E-review", "source_kind": "sast", "artifact_ref": f"sast/validation-results.json:{row['id']}",
                          "disposition": disposition, "files": [], "source_anchors": []}
                if disposition == "evidence_limited":
                    record["non_promoted"] = row["non_promoted"]
                issues = builder.classify_record(self.scan, self.repo, self.repositories, record, row, candidate=self.candidate)
                self.assertEqual(record["disposition"], disposition)
                self.assertEqual(issues[0]["code"], "invalid_range")
                for field in ("reference", "independent_support"):
                    unsafe = copy.deepcopy(row)
                    unsafe["optional_support"][0][field] = "../escape.py:1" if field == "reference" else ["../escape.py:1"]
                    with self.assertRaises(ValueError):
                        builder.classify_record(self.scan, self.repo, self.repositories, copy.deepcopy(record), unsafe, candidate=self.candidate)

    def test_active_optional_contract_and_review_ownership_remain_strict(self):
        builder = load_module("outcome_evidence_builder", "build-evidence-index.py")
        review = self.optional_review("source_verified")
        record = {"id": "E-review", "source_kind": "sast", "artifact_ref": f"sast/validation-results.json:{review['id']}",
                  "disposition": "promoted", "files": [], "source_anchors": []}
        unused = copy.deepcopy(review)
        unused["optional_support"][0]["reference"] = "gateway/handler.py:1"
        candidate = {**self.candidate, "evidence_refs": ["gateway/handler.py:1", "service/implementation.py:1"]}
        with self.assertRaises(ValueError):
            builder.classify_record(self.scan, self.repo, self.repositories, record, unused, candidate=candidate)
        missing = copy.deepcopy(review)
        missing["optional_support"][0]["independent_support"] = ["service/missing.py:1"]
        limited = copy.deepcopy(record)
        builder.classify_record(self.scan, self.repo, self.repositories, limited, missing, candidate=self.candidate)
        self.assertEqual(limited["disposition"], "evidence_limited")
        for key, value in (("candidate_id", self.other["id"]), ("provenance", {**review["provenance"], "selector": "wrong/model:high"})):
            forged = {**review, key: value}
            with self.assertRaises(ValueError):
                validate_review_result(ROOT, self.repo, self.candidate, forged, scan=self.scan,
                                       repositories=self.repositories, routing=self.routing)
        self.publish_reviews(review)
        queue_path = self.scan / "sast/validation-queue.json"
        write(queue_path, [row for row in self.queue if row["id"] != self.candidate["id"]])
        activate_publisher(self.scan, self.context, "campaign-planning", os.environ)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/build-evidence-index.py"), str(self.scan), "--context", str(self.context_path)],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.scan / "campaign-planning/evidence-index.json").exists())

    def test_return_gate_valid_malformed_repaired_and_declared_repair_history(self):
        review = self.review()
        self.assertEqual(self.check_review(review), [])
        review["corrected_candidate"]["trace"][1]["kind"] = "sink"
        self.assertEqual(self.check_review(review), ["$.trace[1].kind must be 'propagation'"])
        self.assertEqual(review["corrected_candidate"]["trace"][1]["kind"], "sink")
        command = [sys.executable, str(ROOT / "scripts/sast_contract.py"), str(self.repo),
                   str(self.scan / "sast/validation-queue.json"), str(self.scan / review["provenance"]["artifact_ref"]), "--review"]
        invalid = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 1, invalid.stderr)
        self.assertIn("[sast-contract] ERROR: $.trace[1].kind must be 'propagation'", invalid.stderr)
        review["corrected_candidate"]["trace"][1]["kind"] = "propagation"
        self.assertEqual(self.check_review(review), [])
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        review = self.limited_review()
        # This admits supplied repair history; it does not execute retry orchestration.
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        del review["non_promoted"]["correction_repair"]
        self.assertEqual(self.check_review(review), ["$.trace[1].kind must be 'propagation'"])

    def test_malformed_correction_cannot_hide_integrity_failure(self):
        review = self.limited_review()
        for key in ("id", "task_id", "contributors", "cell_ids", "objective_id", "question_id"):
            with self.subTest(owner_field=key):
                forged = copy.deepcopy(review)
                del forged["corrected_candidate"][key]
                with self.assertRaisesRegex(ValueError, "ownership/provenance"):
                    self.check_review(forged)
        for field in ("trace", "root_cause_location", "evidence_refs"):
            for path in ("../escape.py", "unregistered/file.py"):
                with self.subTest(field=field, path=path):
                    forged = copy.deepcopy(review)
                    if field == "trace":
                        forged["corrected_candidate"][field][0]["file"] = path
                    elif field == "root_cause_location":
                        forged["corrected_candidate"][field]["file"] = path
                    else:
                        forged["corrected_candidate"][field] = [path]
                    with self.assertRaises(ValueError):
                        self.check_review(forged)
        forged = copy.deepcopy(review)
        forged["provenance"]["selector"] = "wrong/model:high"
        write(self.scan / review["provenance"]["artifact_ref"], forged)
        blocked = subprocess.run([sys.executable, str(ROOT / "scripts/sast_contract.py"), str(self.repo),
                                  str(self.scan / "sast/validation-queue.json"),
                                  str(self.scan / review["provenance"]["artifact_ref"]), "--review"], capture_output=True, text=True)
        self.assertEqual(blocked.returncode, 2, blocked.stderr)
        self.assertIn("INTEGRITY", blocked.stderr)

    def test_unrepaired_claim_survives_index_and_synthesis_with_valid_peer(self):
        limited = self.limited_review()
        other = self.review(self.other)
        write(self.scan / other["provenance"]["artifact_ref"], other)
        write(self.scan / "sast/validation-results.json", [limited, other])
        environment = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.context_path)}
        finalized = subprocess.run([sys.executable, str(ROOT / "scripts/finalize-sast.py"), str(self.repo), str(self.scan), "--finalize"],
                                   env=environment, capture_output=True, text=True)
        self.assertEqual(finalized.returncode, 0, finalized.stderr)
        verified = json.loads((self.scan / "sast/verified-findings.json").read_text())
        self.assertEqual([row["id"] for row in verified], [self.other["id"]])
        self.assertEqual(verified[0]["objective_id"], self.other["objective_id"])
        self.assertEqual(verified[0]["question_id"], self.other["question_id"])
        ledger = json.loads((self.scan / "sast/coverage-ledger.json").read_text())
        self.assertEqual(ledger["non_promoted"], [limited["non_promoted"]])
        self.assertEqual(ledger["funnel"]["adversarially_rejected"], 0)
        self.assertEqual(ledger["funnel"]["environment_required"], 0)
        self.assertEqual(next(row["status"] for row in ledger["cells"] if row["id"] == "CELL-1"), "locally_unresolved")
        dropped = json.loads((self.scan / "sast/dropped-findings.json").read_text())
        self.assertEqual(dropped[0]["status"], "evidence_limited")
        activate_publisher(self.scan, self.context, "campaign-planning", os.environ)
        indexed = subprocess.run([sys.executable, str(ROOT / "scripts/build-evidence-index.py"), str(self.scan), "--context", str(self.context_path)],
                                 capture_output=True, text=True)
        self.assertEqual(indexed.returncode, 0, indexed.stderr)
        index = json.loads((self.scan / "campaign-planning/evidence-index.json").read_text())
        self.assertEqual(index["attack_objectives"], self.registry["attack_objectives"])
        self.assertEqual(index["investigation_questions"], self.registry["investigation_questions"])
        records = [row for row in index["records"] if row["source_kind"] == "sast" and row["source_id"] in {self.candidate["id"], limited["id"]}]
        self.assertTrue(records)
        self.assertTrue(all(row["disposition"] == "evidence_limited" and row["non_promoted"] == limited["non_promoted"] for row in records))
        self.assertTrue(all(row["objective_id"] == self.candidate["objective_id"] and
                            row["question_id"] == self.candidate["question_id"] for row in records))
        write(self.scan / "intrusion/intrusion-results.json", {"results": []})
        inputs = synthesis_inputs(self.scan)
        self.assertIn(limited["non_promoted"]["input_refs"][0], inputs)
        self.assertIn(f"sast/verified-findings.json:{self.other['id']}", inputs)
        other_closure = {"id": "OTHER", "input_refs": [f"sast/verified-findings.json:{self.other['id']}"],
                         "disposition": "rejected", "reason": "Synthetic subsequent source review contradicts this separate claim.",
                         "risk_context": "Separate ownership claim", "missing_fact": "", "next_action": "",
                         "deferral": None, "review": {"actor": "vulnops-synthesis", "selector": "test/red:high",
                         "action": "Inspect separate ownership obligation", "result": "Synthetic control defeats separate claim",
                         "evidence_refs": ["service/implementation.py:1"]}}
        document = {"findings": [], "non_promoted": [limited["non_promoted"], other_closure]}
        synthesis = load_module("outcome_synthesis", "finalize-synthesis.py")
        activate_publisher(self.scan, self.context, "synthesis", os.environ)
        output = synthesis.finalize_document(self.scan, self.context, copy.deepcopy(document))
        self.assertEqual(output["non_promoted"][0], limited["non_promoted"])
        self.assertEqual([row["disposition"] for row in output["input_claims"]], ["evidence_limited", "rejected"])
        assessment = output["objective_assessments"][0]
        self.assertEqual(assessment["objective_id"], self.candidate["objective_id"])
        self.assertEqual(assessment["status"], "unresolved")
        self.assertEqual(assessment["finding_ids"], [])
        self.assertTrue(assessment["remaining_obligations"])
        del document["non_promoted"][0]["correction_repair"]
        with self.assertRaisesRegex(ValueError, "retain source-owned correction repair"):
            synthesis.finalize_document(self.scan, self.context, document)

    def test_supported_candidate_without_early_remediation_is_promoted(self):
        path = self.scan / "sast/deepdive/H001.json"
        result = json.loads(path.read_text())
        del result["candidates"][0]["remediation"]
        write(path, result)
        queue, _, _ = finalizer.aggregate(ROOT, self.repo, self.scan)
        self.candidate = next(row for row in queue if row["task_id"] == "H001")
        self.assertNotIn("remediation", self.candidate)
        review = self.review()
        self.assertEqual(self.check_review(review), [])
        other = self.review(self.other)
        write(self.scan / other["provenance"]["artifact_ref"], other)
        write(self.scan / "sast/validation-results.json", [review, other])
        finalizer.finalize(ROOT, self.repo, self.scan)
        verified = json.loads((self.scan / "sast/verified-findings.json").read_text())
        promoted = next(row for row in verified if row["id"] == self.candidate["id"])
        self.assertNotIn("remediation", promoted)
        self.assertEqual(promoted["objective_id"], self.candidate["objective_id"])
        self.assertEqual(promoted["question_id"], self.candidate["question_id"])
        for field in ("attacker", "root_cause", "impact", "mitigations_checked", "trace"):
            unsupported = self.review()
            del unsupported["corrected_candidate"][field]
            self.assertTrue(self.check_review(unsupported), field)

    def test_terminal_labels_use_reasons_and_actual_allocation(self):
        rows = []
        for name, outcome in (("EXTERNAL", "externally_blocked"), ("LOCAL", "locally_unresolved"),
                              ("FAILED", "execution_failed"), ("UNALLOCATED", "budget_deferred")):
            rows.append({"id": name, "status": "shallow", "reason": "Unfinished investigation",
                         "resolution": {"outcome": outcome, "reason": "Recorded reason", "missing_fact": "Storage definition",
                                        "next_action": "Inspect storage definition", "evidence_refs": []},
                         "checkpoint": {"remaining_question": "Does storage enforce ownership?"}})
        ledger = {"cells": copy.deepcopy(rows)}
        finalizer.close_depth_limited_cells(ledger, self.plan)
        self.assertEqual([row["status"] for row in ledger["cells"]],
                         ["externally_blocked", "locally_unresolved", "failed", "locally_unresolved"])
        self.assertEqual([row["resolution"] for row in ledger["cells"]], [row["resolution"] for row in rows])
        self.assertEqual(finalizer.sast_phase_status({"cells": [ledger["cells"][0]]}), "degraded")
        self.assertEqual(finalizer.sast_phase_status({"cells": [ledger["cells"][1]]}), "ok")
        exhausted = copy.deepcopy(self.plan)
        exhausted["budget"]["max_hunt_tasks"] = len(exhausted["tasks"])
        ledger = {"cells": copy.deepcopy(rows)}
        finalizer.close_depth_limited_cells(ledger, exhausted)
        self.assertEqual([row["status"] for row in ledger["cells"]],
                         ["externally_blocked", "depth_limited", "failed", "depth_limited"])
        self.assertIn("hunt tasks 2/2", ledger["cells"][1]["reason"])
        self.assertEqual(finalizer.close_depth_limited_cells(ledger, exhausted), 0)
        self.assertEqual(finalizer.sast_phase_status({"cells": [{"status": "depth_limited"}]}), "ok")
        self.assertEqual(finalizer.sast_phase_status({"cells": [{"status": "failed"}]}), "degraded")
        self.assertEqual(finalizer.sast_phase_status({
            "cells": [{"status": "depth_limited"}], "funnel": {"environment_required": 1}}), "degraded")
        bounded = {"cells": [{"id": "S", "status": "shallow", "reason": "Remaining local proof"},
                             {"id": "D", "status": "deferred", "reason": "Unallocated question"},
                             {"id": "F", "status": "finding"}]}
        self.assertEqual(finalizer.close_depth_limited_cells(
            bounded, {"budget": {"max_gapfill_rounds": 0}, "tasks": []}), 2)
        self.assertEqual([row["status"] for row in bounded["cells"]],
                         ["depth_limited", "depth_limited", "finding"])
        self.assertEqual(finalizer.close_depth_limited_cells(bounded), 0)


if __name__ == "__main__":
    unittest.main()
