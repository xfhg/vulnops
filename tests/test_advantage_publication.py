"""Retained report publication uses saved proof, never a revived native session."""
import copy
import hashlib
import json
import shutil
import unittest
from unittest.mock import patch

import test_advantage_pipeline as fixtures
from test_advantage_pipeline import authored_plan, authored_result, core, pipeline, put
import advantage_publication as publication
from advantage_actions import empty_actions
from report_bundle import read_publication
import gap_exploration_contract as gap


class RetainedPublicationTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.AdvantagePipelineTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture, self.base = fixture, fixture.base
        context = fixture.context
        context.update(run_id=self.base.name, source_run_id="audit", assessment_id="scope-fixture")
        context["baseline"]["execution_id"] = "audit"
        fixture.plan = authored_plan(context)
        put(self.base / "planning/plan.json", fixture.plan)
        fixture.packet = pipeline.packet(context, fixture.plan, fixture.plan["assignments"][0])
        put(self.base / "investigation/packets/TASK-001.json", fixture.packet)
        fixture.result = authored_result(context, fixture.packet)
        fixture.call["run_id"] = context["run_id"]
        put(self.base / "gap-exploration/results.json", gap.aggregate(context))
        put(self.base / "baseline/catalog.json", core.envelope(context, source_run_id="audit",
            repositories=[], files=[{"artifact_ref": "report/security-report.json"}], records=[], counts={}, file_count=1, record_count=0))
        baseline = self.base.parent / "audit"
        markdown = "# Historical fixture\n"
        (baseline / "report/security-report.md").write_text(markdown)
        put(baseline / "report/security-report.json", {"schema_version": "2.0", "run_id": "audit",
            "findings": [], "summary": {"total": 0}, "publication": {
                "execution_kind": "audit", "repository": "fixture", "repositories": [],
                "model_routing": {}, "producer_routes": {},
                "markdown_sha256": hashlib.sha256(markdown.encode()).hexdigest()}})
        fixture.report_fixture()
        put(self.base / "handoff/actions.json", empty_actions(context))
        pipeline.record_source_receipts(context, "synthesis")
        pipeline.record_source_receipts(context, "final-verification")
        # The saved assessment identity, not today's source or a recreated session.
        for relative in ("synthesis/findings.json", "final-verification/findings.json"):
            value = core.load(self.base / relative)
            value["assessment_context"] = {"attempt_id": context["attempt_id"], "assessment_id": "scope-fixture"}
            put(self.base / relative, value)
        shutil.rmtree(self.base.parent / "source")
        self.no_native = patch.object(core, "live_call", side_effect=AssertionError("native state must not be read"))
        self.no_native.start()
        self.addCleanup(self.no_native.stop)

    def test_publication_preserves_dossier_scope_and_is_immutable(self):
        before = {str(p.relative_to(self.base)): p.read_bytes() for p in self.base.rglob("*") if p.is_file()}
        result = publication.publish(self.base, "standard")
        self.assertEqual(result["counts"]["assessed_confirmed"], 1)
        report = read_publication(self.base, expected_kind="advantage", validate_evidence=True)["report"]
        self.assertEqual(report["findings"], core.load(self.base / "final-verification/findings.json")["findings"])
        self.assertIsNone(report["assessment"]["scopes"][0]["started_at"])
        self.assertTrue(report["publication"]["published_at"])
        for relative, data in before.items():
            self.assertEqual((self.base / relative).read_bytes(), data)
        with self.assertRaisesRegex(ValueError, "already exists"):
            publication.publish(self.base, "standard")

    def test_changed_review_and_missing_assignment_cannot_publish(self):
        path = self.base / "final-verification/results/F-001.json"
        original = path.read_bytes()
        review = json.loads(original)
        review["closure_reason"] = "Changed after final aggregation."
        put(path, review)
        with self.assertRaisesRegex(ValueError, "hash binding differs"):
            publication.publish(self.base, "standard")
        self.assertFalse((self.base / "report/security-report.json").exists())
        path.write_bytes(original)
        (self.base / "final-verification/packets/F-001.json").unlink()
        with self.assertRaisesRegex(ValueError, "packets/F-001.json"):
            publication.publish(self.base, "standard")

    def test_check_does_not_publish_and_mode_cannot_relabel_passes(self):
        self.assertEqual(publication.publish(self.base, "standard", check=True)["status"], "validated")
        self.assertFalse((self.base / "report/security-report.json").exists())
        with self.assertRaisesRegex(ValueError, "pass structure"):
            publication.publish(self.base, "deep", check=True)

    def test_companion_write_failure_never_commits_json(self):
        with patch.object(publication.os, "link", side_effect=OSError("disk unavailable")):
            with self.assertRaisesRegex(OSError, "disk unavailable"):
                publication.publish(self.base, "standard")
        self.assertFalse(any((self.base / "report").iterdir()))

    def test_publication_hash_detects_evidence_and_markdown_changes(self):
        publication.publish(self.base, "standard")
        markdown = self.base / "report/security-report.md"
        original = markdown.read_bytes()
        markdown.write_bytes(original + b"changed\n")
        with self.assertRaisesRegex(ValueError, "Markdown differs"):
            read_publication(self.base, validate_evidence=True)
        markdown.write_bytes(original)
        plan = core.load(self.base / "planning/plan.json")
        plan["reason"] = "Changed retained planning."
        put(self.base / "planning/plan.json", plan)
        with self.assertRaisesRegex(ValueError, "evidence changed"):
            read_publication(self.base, validate_evidence=True)


    def test_unreviewed_dossier_remains_complete_and_unconfirmed(self):
        synthesis = core.load(self.base / "synthesis/findings.json")
        finding = copy.deepcopy(synthesis["findings"][0])
        finding.update(id="F-002", title="Unconfirmed alternative", severity="critical")
        synthesis["findings"].append(finding)
        synthesis["links"].append({**synthesis["links"][0], "finding_id": "F-002"})
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = core.load(self.base / "final-verification/assignments.json")
        assignment = {**assignments["assignments"][0], "finding_id": "F-002",
                      "candidate_sha256": fixtures.dossier_hash(finding),
                      "result_ref": "final-verification/results/F-002.json"}
        assignments["assignments"].append(assignment)
        put(self.base / "final-verification/assignments.json", assignments)
        put(self.base / "final-verification/packets/F-002.json", assignment)
        final = core.load(self.base / "final-verification/findings.json")
        final["unconfirmed"].append({"finding_id": "F-002", "outcome": "locally_unresolved",
            "assignment_ref": "final-verification/assignments.json", "reason": "No usable review was retained."})
        put(self.base / "final-verification/findings.json", final)
        publication.publish(self.base, "standard")
        report = read_publication(self.base, validate_evidence=True)["report"]
        self.assertEqual(report["unconfirmed_dossiers"], [finding])
        self.assertEqual(report["counts"]["assessed_confirmed"], 1)
        self.assertFalse(any(row["severity"] == "critical" for row in report["findings"]))
        markdown = (self.base / "report/security-report.md").read_text()
        self.assertIn(finding["technical_examples"][0]["content"], markdown)
        self.assertIn("unconfirmed; proposed severity", markdown)

    def test_competing_live_owner_blocks_publication(self):
        publication.claim_run(self.base, "competing-owner")
        self.addCleanup(publication.release_run, self.base, "competing-owner")
        with self.assertRaises(ValueError):
            publication.publish(self.base, "standard")
        self.assertFalse((self.base / "report/security-report.json").exists())

if __name__ == "__main__":
    unittest.main()
