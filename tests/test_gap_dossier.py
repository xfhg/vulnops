"""Downstream gap isolation fixtures; no models, network or target execution."""
from __future__ import annotations

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
import gap_dossier as gap
from evidence_accounting import account_inputs, synthesis_inputs
from evidence_refs import artifact_value
from test_dossiers import sample_finding, seed_objective


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class ProtectedGapDossiers(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve() / "scan"
        self.target = Path(temporary.name).resolve() / "source"
        self.base.mkdir(); self.target.mkdir()
        environment = patch.dict(os.environ, {
            "VULNOPS_RUNTIME_ROOT": str(self.base.parent / "runtime"),
            "VULNOPS_LAUNCHER_PID": str(os.getpid()),
            "VULNOPS_LAUNCHER_SESSION_ID": "gap-dossier-fixture"})
        environment.start()
        self.addCleanup(environment.stop)
        from run_lifecycle import claim_run
        claim_run(self.base)
        (self.target / "source.py").write_text("def lookup(record_id):\n    return records[record_id]\n")
        self.objective, self.question = seed_objective(self.base)
        self.routing = {"agents": {"vulnops-synthesis": "fixture/synthesis:high",
            "vulnops-deepdive-chunk": "fixture/investigator:high",
            "vulnops-gap-investigator": "fixture/gap:high",
            "vulnops-independent-verify-one": "fixture/reviewer:high"}}
        self.context = {"run_id": "gap-dossier-fixture", "attempt_id": "attempt-one",
            "source_root": str(self.target), "repo_path": str(self.target), "repositories": [{"path": "."}],
            "scan_base": str(self.base), "paths": {"scan_base": str(self.base), "gap_exploration": str(self.base / "gap-exploration")},
            "depth": "quick", "model_routing": self.routing,
            "orchestration": {"phase_timeout_seconds": {"synthesis": 1200, "final-verification": 1200}},
            "gap_exploration_budget": {"enabled": True, "max_attempts": 2, "max_concurrency": 2,
                "synthesis_timeout_seconds": 300, "verification_timeout_seconds": 900}}
        self.manifest = {"status": "incomplete", "run_id": self.context["run_id"], "attempt_id": self.context["attempt_id"],
            "model_routing": self.routing, "phases": {"synthesis": "running", "final-verification": "pending"}}
        self.save("run-manifest.json", self.manifest)
        self.provenance = {"actor": "vulnops-gap-investigator", "selector": "fixture/gap:high",
                           "artifact_ref": "gap-exploration/results/GapTask01.json"}
        self.candidate = {"id": "GC-GapTask01-1", "artifact_ref": "gap-exploration/results/GapTask01.json:GC-GapTask01-1",
                          "contributors": [self.provenance], "provenance": self.provenance,
                          "objective_ids": [self.objective["id"]], "evidence_refs": ["source.py:1-2"]}
        self.aggregate = {"candidates": [self.candidate], "objectives": [], "questions": [], "results": [], "non_promoted": []}
        self.finding = sample_finding()
        self.save("sast/deepdive/task.json", {"provenance": self.finding["contributors"][0]})
        self.save("sast/verified-findings.json", [{"id": "C-001", "contributors": self.finding["contributors"], "evidence_refs": ["source.py:1-2"]}])
        self.save("intrusion/intrusion-results.json", {"results": [], "composition": {"status": "resolved"}})
        self.save("campaign-planning/evidence-index.json", {"primitives": []})

    def save(self, relative, document):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document))
        if relative == "run-manifest.json":
            self.save("task-ledger.json", {"schema_version": "2.0", "run_id": document["run_id"],
                "tasks": [{"id": "Synthesis" if phase=="synthesis" else "FinalVerification",
                           "phase": phase, "status": status, "attempts": 1,
                           "attempt_id": document["attempt_id"]}
                          for phase,status in document["phases"].items()]})
        return path

    def accepted(self):
        # Isolate the downstream consumer boundary; core admission has its own fixtures.
        return patch.object(gap, "accepted", return_value=self.aggregate)

    def supplemental_finding(self):
        result = copy.deepcopy(self.finding)
        result.update(id="F-002", contributors=[self.provenance],
            source_refs=[{"kind": "gap-exploration", "source_id": self.candidate["id"],
                          "artifact_ref": self.candidate["artifact_ref"]}])
        return result

    def prepare_original(self):
        document = {"schema_version": "2.0", "run_id": self.context["run_id"],
                    "findings": [], "objective_assessments": []}
        self.save("synthesis/original-findings.json", document)
        gap.bind_original_draft(self.context, "synthesis/original-findings.json")
        return document

    def verification_phase(self):
        self.manifest["phases"].update(synthesis="ok", **{"final-verification": "running"})
        self.save("run-manifest.json", self.manifest)
        gap.begin_cohort(self.context, "final-verification", "original")
        gap.finish_cohort(self.context, "final-verification", "original")
        gap.begin_cohort(self.context, "final-verification", "supplementary")

    def test_legacy_loose_files_are_not_inputs_and_originals_remain_mandatory(self):
        self.save("gap-exploration/results.json", self.aggregate)
        import gap_exploration_contract
        self.assertIsNone(gap_exploration_contract.load_accepted(self.base))
        self.assertEqual(set(synthesis_inputs(self.base)), {"sast/verified-findings.json:C-001"})
        (self.base / "sast/verified-findings.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing synthesis input"):
            synthesis_inputs(self.base)


    def test_empty_original_does_not_bypass_useful_supplement_or_unresolved_composition(self):
        import gap_exploration_contract
        from gap_fixture import GapFixture, save
        empty = module("empty-synthesis")
        for name, supplement, unresolved in (
                ("supplement", True, False), ("empty", False, False), ("composition", False, True)):
            with self.subTest(case=name):
                fixture = GapFixture(self.base.parent / name)
                save(fixture.base / "sast/verified-findings.json", [])
                intrusion = {"results": [{"candidates": [], "composition": {"outcome": "unresolved"}}] if unresolved else []}
                save(fixture.base / "intrusion/intrusion-results.json", intrusion)
                plan = fixture.plan(("GapA",) if supplement else ())
                gap_exploration_contract.admit_plan(fixture.context, plan)
                if supplement:
                    gap_exploration_contract.admit_worker(fixture.context, "GapA", fixture.result())
                result = gap_exploration_contract.finalize_phase(fixture.context)
                fixture.accepted(result["status"])
                self.assertEqual(empty.requires_synthesis(fixture.base, [], intrusion), supplement or unresolved)

    def test_cohort_is_provenance_derived_and_mixed_claim_remains_protected(self):
        finding = self.supplemental_finding()
        self.assertTrue(gap.supplementary_only(finding, [self.candidate]))
        finding["cohort"] = "supplementary"
        finding["source_refs"].extend(self.finding["source_refs"])
        self.assertFalse(gap.supplementary_only(finding, [self.candidate]))
        self.assertEqual(gap.review_cohorts([self.finding, finding], [self.candidate]),
                         {"original": ["F-001", "F-002"], "supplementary": []})
        finding = self.supplemental_finding()
        finding["contributors"].extend(self.finding["contributors"])
        self.assertFalse(gap.supplementary_only(finding, [self.candidate]))
        finding = self.supplemental_finding()
        finding["source_refs"][0]["artifact_ref"] = {"kind": "baseline", "id": "B-001"}
        self.assertFalse(gap.supplementary_only(finding, [self.candidate]))

        finding = self.supplemental_finding()
        finding["source_refs"][0]["artifact_ref"] = self.provenance["artifact_ref"] + "#/candidates/0"
        finding["contributors"].append({"actor": "vulnops-advantage-synthesis", "selector": "fixture/publisher:high",
                                        "artifact_ref": "synthesis/findings.json"})
        self.assertTrue(gap.supplementary_only(finding, [self.candidate]))

    def test_authored_gap_reference_resolves_exact_candidate_and_rejects_unknown_id(self):
        self.save("gap-exploration/results.json", self.aggregate)
        self.save(self.provenance["artifact_ref"], {"candidates": [self.candidate]})
        self.assertEqual(artifact_value(self.base, self.candidate["artifact_ref"]), self.candidate)
        with self.assertRaises(ValueError):
            artifact_value(self.base, "gap-exploration/results.json:unknown")

    def test_original_dossier_claims_and_order_cannot_be_replaced(self):
        original = {"findings": [self.finding], "non_promoted": [], "input_claims": []}
        expanded = copy.deepcopy(original)
        expanded["findings"][0]["source_refs"].extend(self.supplemental_finding()["source_refs"])
        gap.preserve_original(original, expanded)
        for mutate in (
                lambda doc: doc["findings"].clear(),
                lambda doc: doc["findings"][0].update(severity="low"),
                lambda doc: doc["findings"][0]["trace"].reverse(),
                lambda doc: doc["findings"][0].update(conditions=[])):
            altered = copy.deepcopy(expanded)
            mutate(altered)
            with self.assertRaisesRegex(ValueError, "protected original"):
                gap.preserve_original(original, altered)

    def test_original_preparation_is_not_controller_completion(self):
        gap.begin_cohort(self.context, "synthesis", "original")
        with self.assertRaises((ValueError, OSError)):
            gap.finish_cohort(self.context, "synthesis", "original")
        self.prepare_original()
        dispatch = json.loads((self.base / "synthesis/dispatch.json").read_text())
        self.assertEqual(dispatch["cohorts"]["original"]["status"], "running")
        checkpoint = gap.recovery_checkpoint(self.base, "synthesis", self.context)
        self.assertNotIn("synthesis/original-findings.json", checkpoint["files"])
        self.assertNotIn("original", checkpoint["documents"]["synthesis/dispatch.json"]["cohorts"])
        gap.finish_cohort(self.context, "synthesis", "original")
        self.assertIn("synthesis/original-findings.json",
                      gap.recovery_checkpoint(self.base, "synthesis", self.context)["files"])


    def test_inherited_closure_uses_producing_scope_and_exact_failure(self):
        self.context["assessment_id"] = "scope-one"
        self.manifest["assessment_scopes"] = {"scope-one": {
            "run_id": self.context["run_id"], "attempt_id": self.context["attempt_id"]}}
        self.save("run-manifest.json", self.manifest)
        with self.accepted():
            gap.begin_cohort(self.context, "synthesis", "original")
            original = self.prepare_original()
            gap.finish_cohort(self.context, "synthesis", "original")
            gap.begin_cohort(self.context, "synthesis", "supplementary")
            gap.fail_cohort(self.context, "synthesis", "supplementary", "Native authoring exhausted.")
            row = gap.close_supplementary_draft(self.base, self.context, original)["unreviewed"][0]
            before = copy.deepcopy(row)
            resumed = copy.deepcopy(self.context)
            resumed.update(attempt_id="attempt-two", assessment_id="scope-two")
            resumed["gap_exploration_budget"].update(enabled=False, max_attempts=0)
            with patch.object(gap, "unreviewed_row", side_effect=AssertionError("current closure replay")), \
                    patch.object(gap, "_cohort_deadline", side_effect=AssertionError("current budget replay")):
                gap.validate_unreviewed(self.base, resumed, [row], [self.candidate], "synthesis")
            self.assertEqual(row, before)
            for field, value in (("task_ref", "synthesis/dispatch.json:foreign"),
                                 ("assessment_context", {"attempt_id": "foreign", "assessment_id": "scope-one"}),
                                 ("reason", "Invented failure")):
                forged = {**row, field: value}
                with self.subTest(field=field), self.assertRaises(ValueError):
                    gap.validate_unreviewed(self.base, resumed, [forged], [self.candidate], "synthesis")

    def test_inherited_failed_review_uses_producing_attempt_budget(self):
        finding = self.supplemental_finding()
        self.save("synthesis/findings.json", {"findings": [finding]})
        self.manifest["attempt_contexts"] = {self.context["attempt_id"]: {
            "gap_exploration_budget": copy.deepcopy(self.context["gap_exploration_budget"])}}
        with self.accepted():
            self.verification_phase()
            for _ in range(2):
                gap.review_worker(self.context, finding["id"], "begin")
                gap.review_worker(self.context, finding["id"], "fail", "Reviewer terminal output was malformed.")
            row = gap.unreviewed_row(self.base, self.context, finding, phase="final-verification",
                                     input_refs=["synthesis/findings.json:F-002"])
            before = copy.deepcopy(row)
            resumed = copy.deepcopy(self.context)
            resumed["attempt_id"] = "attempt-two"
            resumed["gap_exploration_budget"]["max_attempts"] = 100
            gap.validate_unreviewed(self.base, resumed, [row], [finding], "final-verification")
            self.assertEqual(row, before)
            dispatch = json.loads((self.base / "final-verification/dispatch.json").read_text())
            dispatch["workers"][-1]["attempt_id"] = "foreign"
            self.save("final-verification/dispatch.json", dispatch)
            with self.assertRaisesRegex(ValueError, "producing review authority"):
                gap.validate_unreviewed(self.base, resumed, [row], [finding], "final-verification")

    def test_legacy_completed_supplement_can_publish_or_close_without_reallocation(self):
        with self.accepted():
            gap.begin_cohort(self.context, "synthesis", "original")
            original = self.prepare_original()
            gap.finish_cohort(self.context, "synthesis", "original")
            before = gap.begin_cohort(self.context, "synthesis", "supplementary")
            dispatch = json.loads((self.base / "synthesis/dispatch.json").read_text())
            dispatch["cohorts"]["supplementary"].update(status="completed", completed_at=before["started_at"])
            self.save("synthesis/dispatch.json", dispatch)
            self.context["gap_exploration_budget"]["synthesis_timeout_seconds"] = 0
            row = gap.require_synthesis_publication(self.context, "supplementary")
            self.assertEqual(row["deadline_at"], before["deadline_at"])
            with self.assertRaises(ValueError):
                gap.require_cohort(self.context, "synthesis", "supplementary")
            gap.fail_cohort(self.context, "synthesis", "supplementary", "Union was never admitted.")
            closure = gap.close_supplementary_draft(self.base, self.context, original)
            self.assertEqual(closure["unreviewed"][0]["reason"], "Union was never admitted.")
            self.assertEqual(gap.begin_cohort(self.context, "synthesis", "supplementary")["deadline_at"],
                             before["deadline_at"])

    def test_supplementary_cannot_start_before_original_and_cannot_reset_clock(self):
        with self.accepted():
            with self.assertRaisesRegex(ValueError, "original cohort"):
                gap.begin_cohort(self.context, "synthesis", "supplementary")
            gap.begin_cohort(self.context, "synthesis", "original")
            self.prepare_original()
            gap.finish_cohort(self.context, "synthesis", "original")
            first = gap.begin_cohort(self.context, "synthesis", "supplementary")
            second = gap.begin_cohort(self.context, "synthesis", "supplementary")
            self.assertEqual(first["deadline_at"], second["deadline_at"])
            self.context["gap_exploration_budget"]["synthesis_timeout_seconds"] = 0
            self.assertEqual(gap.begin_cohort(self.context, "synthesis", "supplementary")["started_at"], first["started_at"])
            with self.assertRaisesRegex(ValueError, "lowered current"):
                gap.require_cohort(self.context, "synthesis", "supplementary")
            self.context["gap_exploration_budget"]["synthesis_timeout_seconds"] = 300
            dispatch = json.loads((self.base / "synthesis/dispatch.json").read_text())
            dispatch["cohorts"]["supplementary"]["deadline_at"] = "2000-01-01T00:00:00+00:00"
            self.save("synthesis/dispatch.json", dispatch)
            with self.assertRaisesRegex(ValueError, "allowance"):
                gap.require_cohort(self.context, "synthesis", "supplementary")

    def test_zero_additional_allocation_closes_without_fabricated_native_failure(self):
        self.context["gap_exploration_budget"]["synthesis_timeout_seconds"] = 0
        with self.accepted():
            gap.begin_cohort(self.context, "synthesis", "original")
            self.prepare_original()
            gap.finish_cohort(self.context, "synthesis", "original")
            row = gap.begin_cohort(self.context, "synthesis", "supplementary")
            self.assertEqual(row["failure_kind"], "budget_deferred")
            self.assertEqual(row["started_at"], row["completed_at"])
            result = gap.close_supplementary_draft(self.base, self.context, {"findings": []})
            self.assertEqual(result["unreviewed"][0]["status"], "budget_deferred")
            self.assertIn("no native execution was launched", result["unreviewed"][0]["reason"])
            with self.assertRaises(ValueError):
                gap.require_cohort(self.context, "synthesis", "supplementary")


    def test_original_retry_requires_actual_canonical_attempt_and_never_resets_supplement(self):
        with self.accepted():
            gap.begin_cohort(self.context, "synthesis", "original")
            gap.fail_cohort(self.context, "synthesis", "original", "Original native execution failed.")
            self.assertEqual(gap.begin_cohort(self.context, "synthesis", "original")["status"], "failed")
            path = self.save("synthesis/original-findings.json", {"interrupted": True})
            ledger = json.loads((self.base/"task-ledger.json").read_text())
            ledger["tasks"][0]["attempts"] = 2
            self.save("task-ledger.json", ledger)
            retried = gap.begin_cohort(self.context, "synthesis", "original")
            self.assertEqual(retried["status"], "running")
            self.assertNotIn("output_ref", retried)
            self.assertFalse(path.exists())
            self.prepare_original()
            gap.finish_cohort(self.context, "synthesis", "original")
            first = gap.begin_cohort(self.context, "synthesis", "supplementary")
            gap.fail_cohort(self.context, "synthesis", "supplementary", "Optional native execution failed.")
            ledger["tasks"][0]["attempts"] = 3
            self.save("task-ledger.json", ledger)
            resumed = gap.begin_cohort(self.context, "synthesis", "supplementary")
            self.assertEqual(resumed["status"], "failed")
            self.assertEqual(resumed["deadline_at"], first["deadline_at"])
            self.assertEqual(gap.remaining_ms(self.context,"synthesis","supplementary"),0)

    def test_missing_or_competing_authoritative_owner_stops_original_cohort(self):
        (self.base/"task-ledger.json").unlink()
        with self.assertRaises(ValueError):
            gap.begin_cohort(self.context,"synthesis","original")
        self.manifest["phases"]["final-verification"]="running"
        self.save("run-manifest.json",self.manifest)
        with self.assertRaisesRegex(ValueError,"competing"):
            gap.begin_cohort(self.context,"synthesis","original")

    def test_supplementary_failure_preserves_real_validated_original(self):
        finalizer = module("finalize-synthesis")
        with self.accepted():
            gap.begin_cohort(self.context, "synthesis", "original")
            original = finalizer.finalize_document(self.base, self.context,
                {"schema_version": "2.0", "run_id": self.context["run_id"], "findings": [copy.deepcopy(self.finding)]},
                include_supplementary=False)
            path = self.save("synthesis/original-findings.json", original)
            gap.bind_original_draft(self.context, "synthesis/original-findings.json")
            before = path.read_bytes()
            gap.finish_cohort(self.context, "synthesis", "original")
            gap.begin_cohort(self.context, "synthesis", "supplementary")
            gap.fail_cohort(self.context, "synthesis", "supplementary", "Native supplementary synthesis timed out after its separate allowance.")
            combined = finalizer.finalize_document(self.base, self.context,
                gap.close_supplementary_draft(self.base, self.context, original))
            gap.preserve_original(original, combined)
            self.assertEqual(combined["findings"], original["findings"])
            self.assertEqual(combined["unreviewed"][0]["status"], "execution_failed")
            self.assertNotIn("review", combined["unreviewed"][0])
            self.assertNotIn("verdict", combined["unreviewed"][0])
            self.assertEqual(before, path.read_bytes())
            self.assertEqual(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"), original)
            altered = copy.deepcopy(original); altered["findings"] = []
            self.save("synthesis/original-findings.json", altered)
            with self.assertRaisesRegex(ValueError, "protected original draft changed"):
                gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json")

    def test_missing_original_review_is_fatal_even_with_failed_optional_cohort(self):
        finalizer = module("finalize-verification")
        with self.accepted():
            synthesis = module("finalize-synthesis")
            document = synthesis.finalize_document(self.base, self.context,
                {"schema_version": "2.0", "run_id": self.context["run_id"], "findings": [copy.deepcopy(self.finding)]},
                include_supplementary=False)
            self.save("synthesis/findings.json", document)
            self.verification_phase()
            gap.fail_cohort(self.context, "final-verification", "supplementary", "Optional reviewer native execution failed.")
            context_path = self.save("fixture-context.json", self.context)
            with patch.dict(os.environ, {"VULNOPS_AUDIT_CONTEXT": str(context_path)}), patch.object(sys, "argv",
                    ["finalize-verification", str(self.target), str(self.base)]):
                self.assertNotEqual(finalizer.main(), 0)
            self.assertFalse((self.base / "final-verification/findings.json").exists())
            forged = self.supplemental_finding()
            forged["source_refs"].extend(self.finding["source_refs"])
            with self.assertRaisesRegex(ValueError, "original or mixed"):
                gap.validate_unreviewed(self.base, self.context, [{"id": forged["id"]}], [forged], "final-verification")

    def test_exhausted_optional_reviewer_is_unreviewed_and_original_input_survives(self):
        finding = self.supplemental_finding()
        self.save("synthesis/findings.json", {"findings": [self.finding, finding]})
        with self.accepted():
            self.verification_phase()
            for number in range(2):
                gap.review_worker(self.context, finding["id"], "begin")
                bad = self.save("final-verification/results/F-002.json", {"partial": True})
                gap.review_worker(self.context, finding["id"], "fail", "Native optional reviewer returned malformed output.")
                self.assertFalse(bad.exists())
                if number == 0:
                    with self.assertRaises(ValueError):
                        gap.unreviewed_row(self.base, self.context, finding, phase="final-verification",
                            input_refs=["synthesis/findings.json:F-002"])
            row = gap.unreviewed_row(self.base, self.context, finding, phase="final-verification",
                                     input_refs=["synthesis/findings.json:F-002"])
            gap.validate_unreviewed(self.base, self.context, [row], [finding], "final-verification")
            self.assertEqual(row["task_ref"], "final-verification/dispatch.json:F-002")
            self.assertNotIn("independent_verification_ref", row)
            self.assertNotIn("review", row)
            self.assertEqual(json.loads((self.base / "synthesis/findings.json").read_text())["findings"][0], self.finding)
            with self.assertRaisesRegex(ValueError, "exhausted"):
                gap.review_worker(self.context, finding["id"], "begin")

    def test_failure_cannot_close_live_reviewers_or_unknown_claims(self):
        finding = self.supplemental_finding()
        self.save("synthesis/findings.json", {"findings": [finding]})
        with self.accepted():
            self.verification_phase()
            gap.review_worker(self.context, finding["id"], "begin")
            with self.assertRaisesRegex(ValueError, "active reviewers"):
                gap.fail_cohort(self.context, "final-verification", "supplementary", "Coordinator timeout.")
            with self.assertRaisesRegex(ValueError, "duplicate or unknown"):
                gap.validate_unreviewed(self.base, self.context, [{"id": "F-999"}], [finding], "final-verification")

    def test_canonical_accounting_keeps_unreviewed_separate_from_reviewed_dispositions(self):
        reference = "gap-exploration/results.json:" + self.candidate["id"]
        row = {"id": self.candidate["id"], "input_refs": [reference], "status": "execution_failed", "reason": "Native optional work exhausted."}
        accounting = account_inputs({reference: self.candidate}, [], [], unreviewed=[row])
        self.assertEqual(accounting[0]["disposition"], "unreviewed")
        self.assertEqual(accounting[0]["finding_ids"], [])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            account_inputs({reference: self.candidate}, [self.supplemental_finding()], [], unreviewed=[row])

    def test_recovery_keeps_bound_original_and_actual_interruption_not_scratch(self):
        finalizer = module("finalize-synthesis")
        with self.accepted():
            gap.begin_cohort(self.context, "synthesis", "original")
            original = finalizer.finalize_document(self.base, self.context,
                {"schema_version": "2.0", "run_id": self.context["run_id"], "findings": [copy.deepcopy(self.finding)]},
                include_supplementary=False)
            self.save("synthesis/original-findings.json", original)
            gap.bind_original_draft(self.context, "synthesis/original-findings.json")
            gap.finish_cohort(self.context, "synthesis", "original")
            gap.begin_cohort(self.context, "synthesis", "supplementary")
            self.save("synthesis/supplementary-draft.json", {"partial": True})
            # An ancestor alias (like macOS /var) is not an artifact redirection.
            parent_alias = self.base.parent / "scan-parent"
            parent_alias.symlink_to(self.base.parent, target_is_directory=True)
            checkpoint = gap.recovery_checkpoint(parent_alias / self.base.name, "synthesis", self.context)
            self.assertEqual(checkpoint["files"], ["synthesis/dispatch.json", "synthesis/original-findings.json"])
            self.assertEqual(checkpoint["documents"]["synthesis/dispatch.json"]["cohorts"]["supplementary"]["status"], "failed")
            self.assertTrue((self.base / "synthesis/supplementary-draft.json").exists())  # Projection is read-only.
            recovery = module("recover-run")
            original_bytes = (self.base / "synthesis/original-findings.json").read_bytes()
            operation = recovery.unfinished_work(self.base, "synthesis", self.context)
            recovery.reconcile_work(self.base, "synthesis", operation)
            self.assertFalse((self.base / "synthesis/supplementary-draft.json").exists())
            self.assertEqual((self.base / "synthesis/original-findings.json").read_bytes(), original_bytes)
            dispatch = json.loads((self.base / "synthesis/dispatch.json").read_text())
            self.assertEqual(gap.retained_original(self.base, self.context, dispatch), "synthesis/original-findings.json")

    def test_recovery_rejects_redirected_authorized_root(self):
        gap.begin_cohort(self.context, "synthesis", "original")
        redirected = self.base.parent / "redirected-scan"
        redirected.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "authorized root may not be a symlink"):
            gap.recovery_checkpoint(redirected, "synthesis", self.context)



class NativeProtectedGapDossiers(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        (self.base / "synthesis").mkdir()
        self.context = {"execution_kind": "advantage", "run_id": "native-dossier",
                        "attempt_id": "assessment-one", "scan_base": str(self.base),
                        "model_routing": {"agents": {"vulnops-advantage-synthesis": "fixture/synthesis:high"}},
                        "gap_exploration_budget": {"enabled": True, "synthesis_timeout_seconds": 60,
                                                   "verification_timeout_seconds": 60}}
        self.original = {"run_id": "native-dossier", "findings": [{"id": "F-001", "reason": "Original proof retained."}]}
        self.original_path = self.base / "synthesis/original-findings.json"
        self.original_path.write_text(json.dumps(self.original))
        self.original_worker = {"id": "AdvantageSynthesisOriginal", "runtime_id": "original",
                                "phase": "synthesis", "status": "completed", "yield_valid": True,
                                "actor": "vulnops-advantage-synthesis", "selector": "fixture/synthesis:high",
                                "artifact_sha256": {"synthesis/original-findings.json": gap.core.sha256_file(self.original_path)}}
        self.call = {"workers": [self.original_worker], "caller": {"id": "finalizer"}}
        authority = patch.object(gap.core, "live_call", return_value=self.call)
        authority.start()
        self.addCleanup(authority.stop)

    def test_native_original_is_protected_without_dispatch_files(self):
        self.assertEqual(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"), self.original)
        self.assertFalse((self.base / "synthesis/dispatch.json").exists())
        self.original_path.write_text(json.dumps({**self.original, "findings": []}))
        with self.assertRaisesRegex(ValueError, "exact native terminal"):
            gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json")

    def test_missing_supplement_closes_unreviewed_without_inventing_execution(self):
        failure = gap.cohort_failure(self.base, self.context, "synthesis")
        self.assertEqual(failure["failure_kind"], "locally_unresolved")
        self.assertIn("not launched", failure["reason"])
        self.call["workers"].append({"id": "AdvantageSynthesisSupplementary", "runtime_id": "supplement",
                                     "phase": "synthesis", "status": "failed", "error": "Native author stopped."})
        failure = gap.cohort_failure(self.base, self.context, "synthesis")
        self.assertEqual(failure["failure_kind"], "execution_failed")
        self.assertEqual(failure["reason"], "Native author stopped.")
        self.assertEqual(json.loads(self.original_path.read_text()), self.original)
        self.assertFalse((self.base / "synthesis/dispatch.json").exists())

    def test_disabled_supplement_does_not_invent_execution(self):
        self.context["gap_exploration_budget"]["synthesis_timeout_seconds"] = 0
        failure = gap.cohort_failure(self.base, self.context, "synthesis")
        self.assertEqual(failure["failure_kind"], "budget_deferred")
        self.assertIn("no native execution", failure["reason"])

    def test_unlaunched_reviewer_remains_distinct_from_actual_native_failure(self):
        provenance = {"actor": "vulnops-advantage-gap-investigator", "selector": "fixture/gap:high",
                      "artifact_ref": "gap-exploration/results/Gap1.json"}
        candidate = {"id": "GC-Gap1-1", "artifact_ref": provenance["artifact_ref"] + ":GC-Gap1-1",
                     "provenance": provenance}
        finding = {"id": "F-002", "source_refs": [{"artifact_ref": candidate["artifact_ref"],
                    "source_id": candidate["id"]}], "contributors": [provenance]}
        self.call["workers"] = []
        with patch.object(gap, "accepted_candidates", return_value=[candidate]), \
                patch("advantage_pipeline.verification_cohorts", return_value={}):
            reason, _, status = gap.review_failure(self.base, self.context, finding)
            self.assertEqual(status, "locally_unresolved")
            self.assertIn("not launched", reason)
            self.call["workers"].append({"id": "AdvantageReviewSupplementary", "runtime_id": "review-coordinator",
                "phase": "final-verification", "status": "failed", "error": "Native coordinator stopped."})
            reason, reference, status = gap.review_failure(self.base, self.context, finding)
            self.assertEqual(status, "locally_unresolved")
            self.assertIn("not launched", reason)
            self.assertEqual(reference, "synthesis/findings.json:F-002")
            self.call["workers"].append({"id": "F-002", "runtime_id": "actual-review",
                "phase": "final-verification", "status": "failed", "error": "Actual native reviewer stopped."})
            reason, _, status = gap.review_failure(self.base, self.context, finding)
            self.assertEqual(status, "execution_failed")
            self.assertEqual(reason, "Actual native reviewer stopped.")
            for yield_valid in (False, True):
                with self.subTest(yield_valid=yield_valid):
                    self.call["workers"][-1].update(status="completed", yield_valid=yield_valid)
                    reason, reference, status = gap.review_failure(self.base, self.context, finding)
                    self.assertEqual(status, "locally_unresolved")
                    self.assertIn("no admitted independent review", reason)
                    self.assertEqual(reference, "synthesis/findings.json:F-002")
            self.call["workers"][-1]["status"] = "running"
            with self.assertRaisesRegex(ValueError, "stop native supplementary reviewer"):
                gap.review_failure(self.base, self.context, finding)

    def test_terminal_or_missing_original_review_does_not_block_supplementary_work(self):
        with patch("advantage_pipeline.verification_cohorts", return_value={"F-001": "original"}):
            self.call["workers"] = []
            gap.require_original_reviews_closed(self.context, self.call)
            for status in ("completed", "failed", "cancelled"):
                with self.subTest(status=status):
                    self.call["workers"] = [{"id": "F-001", "runtime_id": "original-review",
                                            "phase": "final-verification", "status": status,
                                            "yield_valid": False}]
                    before = copy.deepcopy(self.call)
                    gap.require_original_reviews_closed(self.context, self.call)
                    self.assertEqual(self.call, before)
            self.call["workers"][0]["status"] = "running"
            with self.assertRaisesRegex(ValueError, "stop native original reviewer"):
                gap.require_original_reviews_closed(self.context, self.call)

    def test_unadmitted_supplement_preserves_original_without_failure_quota(self):
        self.call["workers"].append({"id": "AdvantageSynthesisSupplementary", "runtime_id": "supplement",
                                     "phase": "synthesis", "status": "completed", "yield_valid": False})
        failure = gap.cohort_failure(self.base, self.context, "synthesis")
        self.assertEqual(failure["failure_kind"], "locally_unresolved")
        self.assertEqual(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"),
                         self.original)

    def test_terminal_author_failure_does_not_discard_byte_bound_original(self):
        self.original_worker.update(status="failed", yield_valid=False, error="Coordinator stopped.")
        self.assertEqual(gap.require_synthesis_publication(self.context, "original"), self.original_worker)
        self.assertEqual(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"),
                         self.original)
        self.original_worker["selector"] = "foreign/route"
        with self.assertRaisesRegex(ValueError, "exact route"):
            gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json")

    def test_missing_or_unbound_original_does_not_invent_protected_evidence(self):
        self.original_worker.update(status="failed", artifact_sha256={})
        self.assertIsNone(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"))
        self.original_path.unlink()
        self.assertIsNone(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"))
        self.call["workers"].append({"id": "AdvantageSynthesisSupplementary", "runtime_id": "supplement",
            "phase": "synthesis", "status": "running", "yield_valid": False,
            "actor": "vulnops-advantage-synthesis", "selector": "fixture/synthesis:high"})
        with patch.object(gap, "accepted_candidates", return_value=[{"id": "GC-Supplement-1"}]):
            self.assertEqual(gap.native_cohort(self.context, "synthesis", "supplementary")["status"], "running")

    def test_running_original_author_still_blocks_supplementary_work(self):
        self.original_worker["status"] = "running"
        with self.assertRaisesRegex(ValueError, "stop native original author"):
            gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json")

    def test_mutable_cohort_commands_are_unsupported_for_advantage(self):
        with self.assertRaisesRegex(ValueError, "native tasks"):
            gap.begin_cohort(self.context, "synthesis", "original")
        with self.assertRaisesRegex(ValueError, "native terminal"):
            gap.fail_cohort(self.context, "synthesis", "supplementary", "Invented failed worker")

    def test_empty_original_requires_exact_deterministic_analysis(self):
        self.call["workers"] = []
        expected = {"run_id": self.context["run_id"], "findings": []}
        with patch("advantage_pipeline.empty_synthesis", return_value=expected), \
                patch("advantage_pipeline.admitted_synthesis", return_value=expected):
            self.assertIsNone(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"))
            self.original_path.write_text(json.dumps(expected))
            self.assertEqual(gap.load_original_draft(self.base, self.context, "synthesis/original-findings.json"), expected)


if __name__ == "__main__":
    unittest.main()
