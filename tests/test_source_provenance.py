"""Source publications retain investigators and reviewers through aggregation."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model_identity import contributor_union
from sast_contract import correction_contributors, validate_sast_provenance
from evidence_accounting import classify_refs


class SourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.scan = base / "scan"
        self.source = base / "source"
        self.repositories = [{"path": "gateway"}, {"path": "service"}]
        for repository in self.repositories:
            path = self.source / repository["path"] / "app.py"
            path.parent.mkdir(parents=True)
            path.write_text("source fixture\nsecond line\n")
        self.routing = {"agents": {"vulnops-deepdive-chunk": "p/red:high", "vulnops-verify-one": "p/red:high",
                                   "vulnops-recon-overview": "p/blue:high"}}
        self.investigator = {"actor": "vulnops-deepdive-chunk", "selector": "p/red:high", "artifact_ref": "sast/deepdive/H001.json"}
        self.reviewer = {"actor": "vulnops-verify-one", "selector": "p/red:high", "artifact_ref": "sast/verify/C-1.json"}
        self.researcher = {"actor": "vulnops-recon-overview", "selector": "p/blue:high", "artifact_ref": "repo-context/research/overview.json"}
        self.candidate = {"id": "C-1", "task_id": "H001", "contributors": [self.investigator],
                          "evidence_refs": ["gateway/app.py:1-2", "service/app.py:2"]}
        self.candidate["assessment_context"] = {"attempt_id": "current-source-review"}
        self.review = {
            "schema_version": "2.0", "id": "V-1", "candidate_id": "C-1", "provenance": self.reviewer,
            "assessment_context": {"attempt_id": "current-source-review"},
            "status": "source_verified", "confidence": "high",
            "closure_reason": "Inspected the gateway entrypoint and downstream service implementation.",
            "evidence_refs": ["gateway/app.py:1-2", "service/app.py:2"],
            "corrections": [], "corrected_candidate": None,
            "mechanical_checks": {key: True for key in ("schema", "paths", "lines", "trace_order", "target_unchanged")},
        }
        self.verified = {**self.candidate, "validation": self.review,
                         "contributors": contributor_union([self.investigator], [self.reviewer])}
        self.documents = {"sast/deepdive/H001.json": {"task_id": "H001", "provenance": self.investigator},
                          "repo-context/research/overview.json": {"provenance": self.researcher},
                          "sast/raw-findings.json": [self.candidate], "sast/validation-queue.json": [self.candidate],
                          "sast/dedup-clusters.json": {"clusters": [{"canonical_id": "C-1", "member_ids": ["C-1"]}]},
                          "sast/verify/C-1.json": self.review, "sast/validation-results.json": [self.review],
                          "sast/verified-findings.json": [self.verified]}
        self.documents["run-manifest.json"] = {
            "run_id": "source-provenance", "status": "incomplete", "attempt_id": "current-source-review",
            "repositories": self.repositories, "source_root": str(self.source), "model_routing": self.routing,
            "phase_attempts": {"sast": "current-source-review", "recon": "current-source-review"},
            "attempt_contexts": {"current-source-review": {
                "model_routing": self.routing, "repositories": self.repositories,
                "source_root": str(self.source), "started_at": "fixture"}}}
        self.documents["sast/coverage-ledger.json"] = {
            "tasks": [{"id": "H001", "artifact_valid": True, "attempt_id": "current-source-review"}],
            "review_attempts": {"C-1": "current-source-review"}}
        self.documents["sast/deepdive/H001.json"]["assessment_context"] = {"attempt_id": "current-source-review"}

    def publish(self):
        for relative, value in self.documents.items():
            path = self.scan / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))

    def validate(self):
        validate_sast_provenance(self.scan, self.routing, source_root=self.source, repositories=self.repositories)

    def test_aggregate_rejects_erased_or_forged_source_attribution(self):
        self.publish()
        self.validate()
        from model_identity import finding_contributors
        for status in ("source_verified", "environment_required", "rejected", "deferred"):
            for refs in (["gateway/app.py:1,2"], ["gateway/app.py:1", "gateway/app.py:2"]):
                with self.subTest(status=status, refs=refs):
                    self.review.update(status=status, evidence_refs=refs)
                    self.documents["sast/verified-findings.json"] = (
                        [self.verified] if status in {"source_verified", "environment_required"} else [])
                    self.publish()
                    self.assertEqual(correction_contributors(self.scan, self.routing, self.review,
                        source_root=self.source, repositories=self.repositories), [])
                    self.validate()
                    self.assertEqual(finding_contributors(self.scan, {"verification": {
                        "source_validation_refs": [self.reviewer["artifact_ref"]]}},
                        self.routing, source_root=self.source, repositories=self.repositories), [self.reviewer])
        self.review.update(status="source_verified", evidence_refs=["gateway/app.py:1-2", "service/app.py:2"])
        self.documents["sast/verified-findings.json"] = [self.verified]
        forged = copy.deepcopy(self.verified)
        forged["contributors"] = [self.reviewer]
        self.documents["sast/verified-findings.json"] = [forged]
        self.publish()
        with self.assertRaisesRegex(ValueError, "investigator or reviewer"):
            self.validate()
        self.documents["sast/verified-findings.json"] = [self.verified]
        self.documents["sast/validation-results.json"] = [{**self.review, "provenance": {**self.reviewer, "selector": "p/red:low"}}]
        self.publish()
        with self.assertRaisesRegex(ValueError, "route"):
            self.validate()

    def test_local_raw_quality_is_tolerated_but_promoted_proof_is_required(self):
        baseline = copy.deepcopy(self.documents)
        local_refs = ("gateway/gateway/app.py:1", "gateway/app.py:0", "service/app.py:3",
                      "service/app.py:2-1", "service/app.py:no-line", "sast/deepdive/missing.json")
        for ref in local_refs:
            with self.subTest(raw_ref=ref):
                self.documents = copy.deepcopy(baseline)
                self.documents["sast/raw-findings.json"][0] = {**self.candidate, "evidence_refs": [ref]}
                self.publish()
                self.validate()
                resolved, issues = classify_refs(self.scan, self.source, self.repositories, [ref],
                    owner="sast/raw-findings.json", field="evidence_refs", affected_item_ids=["C-1"])
                self.assertEqual(resolved, [])
                self.assertEqual(issues[0]["disposition"], "evidence_limited")
            for location in ("sast/validation-queue.json", "sast/verified-findings.json", "correction"):
                with self.subTest(required_proof=location, ref=ref):
                    self.documents = copy.deepcopy(baseline)
                    if location == "correction":
                        review = self.documents["sast/validation-results.json"][0]
                        review["corrections"] = [{"field": "evidence_refs", "before": "", "after": ref,
                                                  "reason": "Attempted source citation replacement"}]
                        review["corrected_candidate"] = {**self.candidate, "evidence_refs": [ref]}
                    else:
                        self.documents[location][0] = {**self.documents[location][0], "evidence_refs": [ref]}
                    self.publish()
                    with self.assertRaises(ValueError):
                        self.validate()
        self.documents = copy.deepcopy(baseline)
        self.documents["sast/raw-findings.json"][0] = {**self.candidate, "evidence_refs": ["app.py:1"]}
        self.publish()
        with self.assertRaises(ValueError):
            self.validate()


    def test_mixed_corrections_preserve_exact_contributor_union(self):
        corrected = {**self.candidate, "evidence_refs": [*self.candidate["evidence_refs"], self.researcher["artifact_ref"]]}
        self.review.update({"corrections": [{"field": "evidence_refs", "before": "", "after": "research", "reason": "additional evidence"}],
                            "corrected_candidate": corrected})
        self.verified.update({"evidence_refs": corrected["evidence_refs"],
                              "contributors": contributor_union([self.investigator], [self.reviewer], [self.researcher])})
        self.publish()
        self.assertEqual(correction_contributors(self.scan, self.routing, self.review, source_root=self.source, repositories=self.repositories),
                         contributor_union([self.reviewer], [self.researcher]))
        self.validate()
        corrected["evidence_refs"] = list(self.candidate["evidence_refs"])
        self.verified.update({"evidence_refs": corrected["evidence_refs"],
                              "contributors": contributor_union([self.investigator], [self.reviewer])})
        self.publish()
        self.validate()
        self.assertEqual(correction_contributors(self.scan, self.routing, self.review,
                         source_root=self.source, repositories=self.repositories), [self.reviewer])


class CurrentVerificationTests(unittest.TestCase):
    def setUp(self):
        from test_dossiers import sample_finding, seed_objective, review_dossier
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        self.scan, self.source = base / "scan", base / "source"
        self.environment = patch.dict(os.environ, {
            "VULNOPS_RUNTIME_ROOT": str(base / "runtime"),
            "VULNOPS_LAUNCHER_PID": str(os.getpid()),
            "VULNOPS_LAUNCHER_SESSION_ID": "verification-fixture",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.source.mkdir()
        (self.source / "source.py").write_text("request = record_id\nreturn lookup(record_id)\n")
        self.current = "current-attempt"
        old_route = {"agents": {"vulnops-synthesis": "fixture/synthesis:high",
                               "vulnops-deepdive-chunk": "fixture/investigator:high"}}
        route = {"agents": {**old_route["agents"], "vulnops-synthesis": "fixture/new-synthesis:high",
                            "vulnops-independent-verify-one": "fixture/reviewer:high"}}
        self.context = {"run_id": "fixture", "attempt_id": self.current, "model_routing": route,
                        "scan_base": str(self.scan), "status": "incomplete",
                        "phases": {"synthesis": "ok", "final-verification": "running"},
                        "source_root": str(self.source), "repo_path": str(self.source), "repositories": [{"path": "."}]}
        self.publish("run-manifest.json", {**self.context,
            "phase_attempts": {"sast": "old-attempt", "synthesis": "old-attempt"},
            "attempt_contexts": {"old-attempt": {"model_routing": old_route},
                                 self.current: {"model_routing": route}}})
        self.publish("task-ledger.json", {"run_id": "fixture", "tasks": [{
            "id": "FinalVerification", "phase": "final-verification", "status": "running",
            "attempt_id": self.current, "attempts": 1}]})
        from run_lifecycle import claim_run
        claim_run(self.scan)
        seed_objective(self.scan)
        self.retained = sample_finding()
        self.retained = json.loads(json.dumps(self.retained).replace("source.py", "removed.py"))
        self.current_finding = sample_finding()
        self.current_finding["id"] = "F-002"
        contributor = self.current_finding["contributors"][0]
        self.publish(contributor["artifact_ref"], {"provenance": contributor})
        self.publish("sast/verified-findings.json", [{"id": "C-001", "contributors": [contributor],
                                                     "evidence_refs": ["removed.py:200"]}])
        self.publish("synthesis/findings.json", {"schema_version": "2.0", "run_id": "fixture",
            "findings": [self.retained, self.current_finding], "objective_assessments": []})
        self.publish("campaign-planning/evidence-index.json", {"primitives": []})
        self.publish("intrusion/intrusion-results.json", {"results": []})
        for finding, status in ((self.retained, "rejected"), (self.current_finding, "verified")):
            result = review_dossier(finding, {
                "assessment_context": {"attempt_id": self.current},
                "schema_version": "2.0", "finding_id": finding["id"], "status": status,
                "closure_reason": "Current source no longer contains the old vulnerable component." if status == "rejected"
                                  else "Independent source review confirms the effective flow.",
                "evidence_refs": ["source.py:1-2"], "primitive_results": [], "transition_results": [],
                "joint_conditions": {"outcome": "contradicted" if status == "rejected" else "established",
                    "reason": "Inspected the currently available source flow.", "evidence_refs": [contributor["artifact_ref"]],
                    "missing_fact": "", "next_action": ""},
                "corrections": [], "corrected_finding": None, "actor": "vulnops-independent-verify-one",
                "model": route["agents"]["vulnops-independent-verify-one"], "model_diversity": True})
            for review in result["dossier_review"].values():
                if isinstance(review, dict):
                    review["evidence_refs"] = ["source.py:1-2"]
            for review in result["objective_results"]:
                review["evidence_refs"] = ["source.py:1-2"]
            self.publish(f"final-verification/results/{finding['id']}.json", result)
        self.context_path = base / "context.json"
        self.context_path.write_text(json.dumps(self.context))

    def publish(self, relative, value):
        path = self.scan / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def finalize(self):
        root = Path(__file__).resolve().parents[1]
        return subprocess.run([sys.executable, str(root / "scripts/finalize-verification.py"),
                               str(self.source), str(self.scan)], capture_output=True, text=True,
                              env={**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.context_path)})

    def test_removed_historical_claim_does_not_block_unrelated_current_confirmation(self):
        synthesis = self.scan / "synthesis/findings.json"
        before = synthesis.read_bytes()
        reviewer_bytes = {path: path.read_bytes() for path in (self.scan / "final-verification/results").glob("*.json")}
        result = self.finalize()
        self.assertEqual(result.returncode, 0, result.stderr)
        final = json.loads((self.scan / "final-verification/findings.json").read_text())
        self.assertEqual([row["id"] for row in final["findings"]], ["F-002"])
        self.assertEqual([row["id"] for row in final["rejections"]], ["F-001"])
        for row in [*final["findings"], *final["rejections"]]:
            self.assertEqual(row["assessment_context"], {"attempt_id": self.current})
        self.assertEqual(final["findings"][0]["contributors"], self.current_finding["contributors"])
        self.assertEqual(final["findings"][0]["verification"]["model"], "fixture/synthesis:high")
        self.assertEqual(synthesis.read_bytes(), before)
        self.assertEqual({path: path.read_bytes() for path in reviewer_bytes}, reviewer_bytes)

    def test_execution_root_alias_keeps_canonical_publication(self):
        canonical = self.scan
        alias = canonical.parent / "execution-alias"
        alias.symlink_to(canonical.parent, target_is_directory=True)
        self.scan = alias / canonical.name
        result = self.finalize()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads((canonical / "final-verification/findings.json").read_text())
        self.assertEqual([row["id"] for row in output["findings"]], ["F-002"])
        self.assertEqual([row["id"] for row in output["rejections"]], ["F-001"])

    def test_redirected_phase_directory_cannot_receive_publication(self):
        directory = self.scan / "final-verification"
        redirected = self.scan.parent / "redirected-results"
        directory.rename(redirected)
        directory.symlink_to(redirected, target_is_directory=True)
        before = {path: path.read_bytes() for path in redirected.rglob("*") if path.is_file()}
        result = self.finalize()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual({path: path.read_bytes() for path in redirected.rglob("*") if path.is_file()}, before)

    def test_fatal_aggregate_preserves_published_output_and_reviews(self):
        path = self.scan / "final-verification/results/F-002.json"
        valid_review = json.loads(path.read_text())
        for published in (False, True):
            with self.subTest(published=published):
                self.publish("final-verification/results/F-002.json", valid_review)
                if published:
                    accepted = self.finalize()
                    self.assertEqual(accepted.returncode, 0, accepted.stderr)
                forged = {**valid_review, "model": "foreign/unassigned:high"}
                self.publish("final-verification/results/F-002.json", forged)
                before = {item: item.read_bytes() for item in (self.scan / "final-verification").rglob("*")
                          if item.is_file()}
                rejected = self.finalize()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("assigned route", rejected.stderr)
                self.assertEqual({item: item.read_bytes() for item in before}, before)
                self.assertEqual((self.scan / "final-verification/findings.json").exists(), published)

    def test_completed_or_stale_publisher_cannot_change_outputs(self):
        self.assertEqual(self.finalize().returncode, 0)
        manifest_path = self.scan / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        before = {path: path.read_bytes() for path in (self.scan / "final-verification").rglob("*") if path.is_file()}
        for changes in ({"status": "complete"}, {"attempt_id": "another-attempt"},
                        {"phases": {"final-verification": "ok"}}):
            with self.subTest(changes=changes):
                self.publish("run-manifest.json", {**manifest, **changes})
                rejected = self.finalize()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("active execution", rejected.stderr)
                self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_unowned_publisher_cannot_create_output(self):
        from run_lifecycle import release_run
        release_run(self.scan)
        rejected = self.finalize()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("live owning session", rejected.stderr)
        self.assertFalse((self.scan / "final-verification/findings.json").exists())

    def test_retained_review_is_not_automatically_promoted(self):
        path = self.scan / "final-verification/results/F-002.json"
        baseline = json.loads(path.read_text())
        for stamp in ({"attempt_id": "old-attempt"}, None):
            with self.subTest(stamp=stamp):
                retained = copy.deepcopy(baseline)
                retained.pop("assessment_context", None)
                if stamp is not None:
                    retained["assessment_context"] = stamp
                self.publish("final-verification/results/F-002.json", retained)
                result = self.finalize()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("current independent review", result.stderr)
                self.assertFalse((self.scan / "final-verification/findings.json").exists())
                self.assertEqual(json.loads(path.read_text()), retained)

    def test_unattributed_legacy_candidate_can_be_rejected_locally(self):
        from dossier_contract import dossier_hash
        path = self.scan / "synthesis/findings.json"
        source = json.loads(path.read_text())
        del source["findings"][0]["contributors"]
        self.publish("synthesis/findings.json", source)
        result_path = self.scan / "final-verification/results/F-001.json"
        review = json.loads(result_path.read_text())
        review["model_diversity"] = False
        review["dossier_review"]["dossier_sha256"] = dossier_hash(source["findings"][0])
        self.publish("final-verification/results/F-001.json", review)
        result = self.finalize()
        self.assertEqual(result.returncode, 0, result.stderr)
        final = json.loads((self.scan / "final-verification/findings.json").read_text())
        self.assertEqual([row["id"] for row in final["findings"]], ["F-002"])
        self.assertEqual([row["id"] for row in final["rejections"]], ["F-001"])
        self.assertGreater(final["evidence_quality"]["total"], 0)

    def test_current_confirmation_still_requires_complete_dossier(self):
        from dossier_contract import dossier_hash
        path = self.scan / "synthesis/findings.json"
        source = json.loads(path.read_text())
        del source["findings"][1]["remediation"]
        self.publish("synthesis/findings.json", source)
        result_path = self.scan / "final-verification/results/F-002.json"
        review = json.loads(result_path.read_text())
        review["dossier_review"]["dossier_sha256"] = dossier_hash(source["findings"][1])
        self.publish("final-verification/results/F-002.json", review)
        result = self.finalize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remediation", result.stderr)



if __name__ == "__main__":
    unittest.main()
