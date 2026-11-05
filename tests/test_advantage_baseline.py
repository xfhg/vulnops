"""Fallible historical intelligence and strict typed-reference authority boundaries."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import advantage_baseline as baseline
import advantage_contract as core
from evidence_refs import EvidenceIssue


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def accepted(identifier):
    return {"id": identifier, "status": "verified", "verdict": "confirmed",
            "finding_kind": "code", "title": "Historical fixture", "severity": "high",
            "impact": "Historical bounded impact",
            "contributors": [{"actor": "vulnops-synthesis", "selector": "fixture/model",
                              "artifact_ref": "synthesis/findings.json"}],
            "root_causes": [{"file": "app.py", "line": 1, "scope": "fixture"}]}


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="advantage-baseline-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.scan = root / "audit-001"
        self.base = root / "advantage-001"
        self.source = root / "source"
        self.base.mkdir()
        self.source.mkdir()
        self.run = {"run_id": self.scan.name, "execution_kind": "audit", "status": "complete",
                    "repository": "fixture", "repositories": [{"path": "."}]}
        put(self.scan / "run-manifest.json", self.run)
        put(self.scan / "task-ledger.json", {"tasks": []})
        put(self.scan / "report/security-report.json", {"findings": []})
        put(self.scan / "final-verification/findings.json", {"findings": [accepted("F-001")], "unreviewed": []})
        (self.source / "app.py").write_text("first\nsecond\n", encoding="utf-8")
        self.context = {"run_id": self.base.name, "source_run_id": self.scan.name,
                        "scan_base": str(self.base), "source_root": str(self.source),
                        "repositories": [{"path": "."}],
                        "baseline": {"execution_id": self.scan.name, "root": str(self.scan),
                                     "catalog_ref": "baseline/catalog.json"}}

    def snapshot(self):
        return {p.relative_to(self.scan).as_posix(): p.read_bytes()
                for p in self.scan.rglob("*") if p.is_file()}

    def typed(self, relative):
        return {"execution_id": self.scan.name, "artifact_ref": relative}

    def assert_issue(self, code, reference, kind="mixed"):
        with self.assertRaises(EvidenceIssue) as caught:
            core.resolve_reference(self.context, reference, kind)
        self.assertEqual(caught.exception.code, code)

    def assert_hard_failure(self, callback):
        with self.assertRaises(ValueError) as caught:
            callback()
        self.assertNotIsInstance(caught.exception, EvidenceIssue)


    def test_old_historical_report_cannot_hide_complete_final_dispositions(self):
        confirmed = accepted("F-001")
        confirmed["assessment_context"] = {"attempt_id": "original-assessor"}
        environment = {**accepted("F-002"), "status": "needs_environment", "verdict": "needs_environment"}
        rejected = {"id": "F-003", "status": "rejected", "verdict": "rejected"}
        final = {"run_id": self.scan.name, "findings": [confirmed, environment],
                 "rejections": [rejected], "non_promoted": []}
        put(self.scan / "final-verification/findings.json", final)
        put(self.scan / "report/security-report.json", {
            "run_id": self.scan.name, "findings": [], "historical_findings": [confirmed, environment],
            "historical_rejections": [rejected]})
        before = self.snapshot()
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertEqual(baseline.effective_findings(self.scan), {"F-001": confirmed, "F-002": environment})
        self.assertEqual(baseline.accepted_findings(self.scan), {"F-001": confirmed})
        records = {row["id"]: row for row in catalog["records"] if row["record_type"] in {"findings", "rejections"}}
        self.assertEqual({key: row["status"] for key, row in records.items()},
                         {"F-001": "confirmed", "F-002": "needs_environment", "F-003": "rejected"})
        self.assertEqual(core.resolve_reference(self.context, records["F-002"]["reference"]), environment)
        self.assertEqual(self.snapshot(), before)

    def test_baseline_repositories_follow_assessed_not_publication_inventory(self):
        original = [{"path": "assessed-component", "revision": "original-revision"}]
        self.run.update(repositories=[{"path": "later-component", "revision": "later-revision"}],
                        attempt_id="publisher", attempt_contexts={"producer": {
                            "repositories": original, "started_at": "2025-01-01T00:00:00Z",
                            "source_view": "base", "source_root": "/recorded/original"}},
                        phase_attempts={"final-verification": "producer"})
        put(self.scan / "run-manifest.json", self.run)
        finding = accepted("F-001")
        finding["assessment_context"] = {"attempt_id": "producer"}
        put(self.scan / "final-verification/findings.json", {"findings": [finding]})
        before = self.snapshot()
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertEqual(catalog["repositories"], original)
        self.assertEqual(self.snapshot(), before)

    def test_large_ordinary_reports_remain_readable_historical_inputs(self):
        # Reader-level fixture: each record and prose field is bounded, while
        # the aggregate exceeds both former report and generic hygiene caps.
        findings = []
        for number in range(1, 41):
            finding = accepted(f"F-{number:03d}")
            finding["impact_limits"] = [
                f"{finding['id']} historical limitation {index:02d}: " +
                ("Historical source-only evidence; no current verification or target execution. " * 100)[:7000]
                for index in range(64)
            ]
            findings.append(finding)
        report = {"run_id": self.scan.name, "findings": findings}
        json_path = self.scan / "report/security-report.json"
        markdown_path = self.scan / "report/security-report.md"
        put(json_path, report)
        markdown = "# Historical security report\n\n" + "\n".join(
            f"## {finding['id']}\n" + "\n".join(finding["impact_limits"])
            for finding in findings)
        markdown_path.write_text(markdown, encoding="utf-8")
        for path in (json_path, markdown_path):
            self.assertGreater(path.stat().st_size, 16 * 1024 * 1024)
        before = self.snapshot()

        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertTrue(catalog["counts_complete"])
        self.assertEqual(catalog["unavailable_cohorts"], [])
        self.assertEqual(catalog["evidence_quality"]["total"], 0)
        self.assertTrue({"report/security-report.json", "report/security-report.md"}.issubset(
            {row["artifact_ref"] for row in catalog["files"]}))
        # Report content does not manufacture accepted baseline findings.
        self.assertEqual(baseline.accepted_findings(self.scan), {"F-001": accepted("F-001")})
        self.assertEqual({row["id"] for row in catalog["records"]}, {"F-001"})
        self.assertEqual(core.load(json_path), report)
        self.assertEqual(core.resolve_reference(self.context, self.typed("report/security-report.json")), report)
        self.assertEqual(core.resolve_reference(
            self.context, self.typed("report/security-report.json#/findings/39")), findings[-1])
        self.assertEqual(core.resolve_reference(
            self.context, self.typed("report/security-report.md")), markdown_path.resolve())
        self.assertEqual(markdown_path.read_text(encoding="utf-8"), markdown)
        self.assertEqual(self.snapshot(), before)

        # Safety failures beyond the former byte boundary remain hard failures,
        # not optional-history diagnostics or a silently skipped cohort.
        for relative in ("report/security-report.json", "report/security-report.md"):
            path = self.scan / relative
            with self.subTest(relative=relative):
                try:
                    if path.suffix == ".json":
                        unsafe = copy.deepcopy(report)
                        unsafe["findings"][-1]["impact_limits"][-1] += " ghp_" + "x" * 24
                        put(path, unsafe)
                    else:
                        path.write_text(markdown + "\nghp_" + "x" * 24, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "secret"):
                        baseline.build_catalog(self.context, self.scan)
                    with self.assertRaisesRegex(ValueError, "secret"):
                        core.resolve_reference(self.context, self.typed(relative))
                finally:
                    path.write_bytes(before[relative])
        self.assertEqual(self.snapshot(), before)
        path = self.scan / "final-verification/findings.json"
        for content in ('{"raw_output": "not publishable"}', '{"secret": "ghp_' + 'x' * 24):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                self.assert_hard_failure(lambda: baseline.build_catalog(self.context, self.scan))
                self.assert_hard_failure(lambda: core.resolve_reference(self.context, self.typed("final-verification/findings.json")))

    def test_malformed_optional_json_preserves_neighbors_and_original_bytes(self):
        put(self.scan / "sast/support.json", {"records": [{"id": "usable", "status": "deferred"}]})
        broken = self.scan / "intrusion/intrusion-results.json"
        broken.parent.mkdir()
        broken.write_text('{"results": [ malformed private parser text', encoding="utf-8")
        before = self.snapshot()
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(set(baseline.accepted_findings(self.scan)), {"F-001"})
        self.assertEqual({row["id"] for row in catalog["records"]}, {"F-001", "usable"})
        self.assertFalse(catalog["counts_complete"])
        self.assertEqual(catalog["unavailable_cohorts"], ["intrusion/intrusion-results.json"])
        self.assertEqual(catalog["evidence_quality"]["total"], 1)
        self.assertNotIn("private parser text", json.dumps(catalog))
        self.assertNotIn("intrusion/intrusion-results.json", {row["artifact_ref"] for row in catalog["files"]})

    def test_duplicate_missing_and_invalid_final_ids_are_excluded_locally(self):
        rows = [accepted("F-001"), accepted("F-002"), accepted("F-002"),
                {"status": "verified", "verdict": "confirmed"}, accepted(""),
                accepted("wrong-format"), accepted("../F-009"), accepted(8), None,
                {"id": "F-003", "status": "rejected", "verdict": "confirmed"},
                {"id": "F-004", "status": "verified", "verdict": "rejected"}]
        put(self.scan / "final-verification/findings.json", {"findings": rows})
        before = self.snapshot()
        diagnostics, unavailable = [], set()
        result = baseline.accepted_findings(self.scan, diagnostics=diagnostics, unavailable_cohorts=unavailable)
        self.assertEqual(result, {"F-001": rows[0]})
        self.assertEqual(len(diagnostics), 8)
        self.assertEqual({row["code"] for row in diagnostics},
                         {"ambiguous_record", "missing_record", "unreadable_content"})
        self.assertTrue(all(not row["affected_item_ids"] for row in diagnostics))
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertEqual({row["id"] for row in catalog["records"]}, {"F-001", "F-003", "F-004"})
        self.assertEqual(catalog["counts"]["findings"], 3)
        self.assertFalse(catalog["counts_complete"])
        self.assertEqual(catalog["record_count"], sum(catalog["counts"].values()))
        self.assertEqual(before, self.snapshot())
        # Invalid historical rows remain bounded without losing exact totals.
        put(self.scan / "final-verification/findings.json", {"findings": [{} for _ in range(251)], "unreviewed": []})
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertEqual(len(catalog["limitations"]), 200)
        self.assertEqual(len(catalog["evidence_quality"]["diagnostics"]), 200)
        self.assertEqual(catalog["evidence_quality"]["total"], 251)
        self.assertEqual(catalog["evidence_quality"]["truncated"], 51)
        self.assertEqual(len(catalog["unavailable_cohorts"]), 251)

    def test_available_empty_cohort_differs_from_missing_or_unreadable(self):
        path = self.scan / "final-verification/findings.json"
        put(path, {"findings": [], "unreviewed": []})
        complete = baseline.build_catalog(self.context, self.scan)
        self.assertTrue(complete["counts_complete"])
        self.assertEqual(complete["counts"]["findings"], 0)
        self.assertEqual(complete["unavailable_cohorts"], [])
        for content in (None, "{", "null", '{"findings": {}}', '[]'):
            with self.subTest(content=content):
                if content is None:
                    path.unlink()
                else:
                    path.write_text(content, encoding="utf-8")
                diagnostics, unavailable = [], set()
                self.assertEqual(baseline.accepted_findings(self.scan, diagnostics=diagnostics,
                                                            unavailable_cohorts=unavailable), {})
                self.assertTrue(unavailable)
                self.assertTrue(diagnostics)
                catalog = baseline.build_catalog(self.context, self.scan)
                self.assertFalse(catalog["counts_complete"])
                self.assertNotIn("findings", catalog["counts"])
        path.write_bytes(b"\xff")
        self.assert_issue("unreadable_content", self.typed("final-verification/findings.json"))
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertEqual(catalog["unavailable_cohorts"], ["final-verification/findings.json"])
        self.assertFalse(catalog["counts_complete"])
        for document in ({"findings": []}, {"findings": [], "unreviewed": {}}):
            with self.subTest(document=document):
                put(path, document)
                catalog = baseline.build_catalog(self.context, self.scan)
                self.assertFalse(catalog["counts_complete"])
                self.assertNotIn("unreviewed", catalog["counts"])
                self.assertIn("final-verification/findings.json#/unreviewed", catalog["unavailable_cohorts"])

    def test_duplicate_owned_records_do_not_destroy_repeated_reference_rows(self):
        relative = "sast/support.json"
        put(self.scan / relative, {"records": [{"id": "duplicate"}, {"id": "valid"}, {"id": "duplicate"}],
                                  "question_outcomes": [{"question_id": "Q-001"}, {"question_id": "Q-001"}]})
        diagnostics = []
        records, counts = baseline.catalog_records(self.scan, self.scan.name, [{"artifact_ref": relative}],
                                                    diagnostics=diagnostics)
        self.assertEqual([r["id"] for r in records if r["record_type"] == "records"], ["valid"])
        self.assertEqual(counts, {"records": 1, "question_outcomes": 2})
        self.assertEqual(len(diagnostics), 2)
        self.assertEqual(len({r["pointer"] for r in records}), 3)

    def test_nested_prose_and_identifier_lists_do_not_reduce_catalogue_completeness(self):
        finding = accepted("F-001")
        finding["remediation"] = {"limitations": ["Deployment is not available."]}
        put(self.scan / "final-verification/findings.json", {"findings": [finding], "unreviewed": []})
        put(self.scan / "sast/hunt-plan.json", {
            "tasks": [{"id": "TASK-001", "entrypoints": ["ENTRY-001"]}]})
        put(self.scan / "campaign-planning/evidence-index.json", {
            "records": [{"id": "REC-001", "subsystems": ["SUB-001"]}]})
        put(self.scan / "sast/threat-model.json", {
            "entrypoints": [{"id": "ENTRY-001"}],
            "subsystems": [{"id": "SUB-001", "entrypoints": ["ENTRY-001"]}]})
        put(self.scan / "gap-exploration/results.json", {
            "limitations": ["No dynamic execution was performed."], "candidates": []})
        before = self.snapshot()
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertTrue(catalog["counts_complete"])
        self.assertEqual(catalog["unavailable_cohorts"], [])
        self.assertEqual(catalog["counts"]["findings"], 1)
        self.assertEqual(catalog["counts"]["entrypoints"], 1)
        self.assertEqual(catalog["counts"]["subsystems"], 1)
        self.assertEqual(self.snapshot(), before)

    def test_owned_duplicates_are_local_to_their_defining_collection(self):
        relative = "sast/support.json"
        put(self.scan / relative, {"records": [
            {"id": "A", "evidence": {"records": [{"id": "shared"}]}},
            {"id": "B", "evidence": {"records": [{"id": "shared"}, "malformed"]}}]})
        diagnostics, unavailable = [], set()
        records, counts = baseline.catalog_records(self.scan, self.scan.name, [{"artifact_ref": relative}],
            diagnostics=diagnostics, unavailable_cohorts=unavailable)
        self.assertEqual(counts["records"], 4)
        self.assertEqual([row["pointer"] for row in records if row["id"] == "shared"],
                         ["/records/0/evidence/records/0", "/records/1/evidence/records/0"])
        self.assertEqual(unavailable, {relative + "#/records/1/evidence/records/1"})

    def test_source_completion_and_identity_remain_hard_prerequisites(self):
        for changes in ({"status": "running"}, {"run_id": None}, {"run_id": "../foreign"},
                        {"repository": ""}, {"execution_kind": "advantage"}):
            with self.subTest(changes=changes):
                self.assert_hard_failure(lambda: baseline.validate_source_audit(self.scan, {**self.run, **changes}))
        self.assert_hard_failure(lambda: baseline.build_catalog({**self.context, "source_run_id": "foreign"}, self.scan))
        (self.scan / "run-manifest.json").write_text("{", encoding="utf-8")
        with self.assertRaises(ValueError):
            baseline.build_catalog(self.context, self.scan)

    def test_retained_catalog_absence_does_not_create_current_assessment(self):
        catalog = baseline.build_catalog(self.context, self.scan)
        for name in ("counts_complete", "unavailable_cohorts", "evidence_quality"):
            catalog.pop(name)
        put(self.base / "baseline/catalog.json", catalog)
        before = (self.base / "baseline/catalog.json").read_bytes()
        baseline.validate_baseline(self.base, self.context)
        self.assertEqual((self.base / "baseline/catalog.json").read_bytes(), before)
        self.assertNotIn("counts_complete", core.load(self.base / "baseline/catalog.json"))

    def test_typed_resolver_local_categories(self):
        relative = "final-verification/findings.json"
        self.assert_issue("missing_file", self.typed("sast/absent.json"))
        self.assert_issue("missing_record", self.typed(relative + "#F-999"))
        self.assert_issue("missing_record", self.typed(relative + "#/findings/8"))
        self.assert_issue("unsupported_selector", self.typed(relative + "#/findings/00"))
        self.assert_issue("unsupported_selector", self.typed(relative + "#/findings/~2"))
        self.assert_issue("unsupported_selector", self.typed(relative + "#"))
        put(self.scan / relative, {"findings": [accepted("F-001"), accepted("F-001")]})
        self.assert_issue("ambiguous_record", self.typed(relative + "#F-001"))
        (self.scan / relative).write_text("{", encoding="utf-8")
        self.assert_issue("unreadable_content", self.typed(relative + "#/findings/0"))
        self.assert_issue("invalid_range", "app.py:1-3")
        self.assert_issue("invalid_range", "app.py:2-1")
        self.assert_issue("unsupported_selector", "app.py#1")
        self.assert_issue("missing_file", "missing.py:1")
        self.assertEqual((self.source / "app.py").read_text(), "first\nsecond\n")
        put(self.base / "synthesis/findings.json", {"findings": []})
        put(self.source / "synthesis/findings.json", {})
        self.assert_issue("ambiguous_namespace", "synthesis/findings.json")
        self.assert_issue("missing_file", "investigation/missing.json", "artifact")

    def test_foreign_ownership_paths_and_authorization_are_not_evidence_issues(self):
        for ref in ({"execution_id": "foreign", "artifact_ref": "final-verification/findings.json"},
                    {"execution_id": self.base.name, "artifact_ref": "final-verification/findings.json"},
                    self.typed("../outside.json"), self.typed("/outside.json"), self.typed("other/file.json"),
                    "../outside.py"):
            with self.subTest(ref=ref):
                self.assert_hard_failure(lambda: core.resolve_reference(self.context, ref))
        restricted = {**self.context, "repositories": [{"path": "authorized"}]}
        self.assert_hard_failure(lambda: core.resolve_reference(restricted, "app.py:1"))
        ambiguous = {**self.context, "action_source": self.context["baseline"]}
        self.assert_hard_failure(lambda: core.resolve_reference(ambiguous, self.typed("final-verification/findings.json")))
        for root in (None, str(self.source / "missing")):
            context = {**self.context, "source_root": root}
            self.assert_hard_failure(lambda: core.resolve_reference(context, "app.py:1"))
        relative = "final-verification/findings.json"
        put(self.scan / relative, {"run_id": "foreign", "findings": [accepted("F-001")]})
        self.assert_hard_failure(lambda: baseline.accepted_findings(
            self.scan, expected_execution_id=self.scan.name))
        self.assert_hard_failure(lambda: baseline.build_catalog(self.context, self.scan))
        self.assert_hard_failure(lambda: core.resolve_reference(self.context, self.typed(relative + "#F-001")))
        outside = self.scan.parent / "outside.json"
        put(outside, {"findings": []})
        (self.scan / "final-verification/escape.json").symlink_to(outside)
        self.assert_hard_failure(lambda: core.resolve_reference(self.context, self.typed("final-verification/escape.json")))
        self.assert_hard_failure(lambda: baseline.canonical_inventory(self.scan))


    def test_unusable_accepted_record_shapes_remain_local(self):
        good = accepted("F-001")
        for changes in ({"contributors": None}, {"contributors": ["unknown"]},
                        {"contributors": [{}]}, {"finding_kind": None}, {"severity": []},
                        {"impact": None}, {"title": None}, {"root_causes": [{}]},
                        {"root_causes": [{"file": "app.py", "line": "1", "scope": "fixture"}]},
                        {"finding_kind": "chain", "primitive_steps": [{}]}):
            with self.subTest(changes=changes):
                bad = {**accepted("F-002"), **changes}
                put(self.scan / "final-verification/findings.json", {"findings": [good, bad], "unreviewed": []})
                self.assertEqual(baseline.accepted_findings(self.scan), {"F-001": good})
                catalog = baseline.build_catalog(self.context, self.scan)
                self.assertEqual(catalog["counts"]["findings"], 1)
                self.assertFalse(catalog["counts_complete"])
                self.assertEqual(catalog["evidence_quality"]["total"], 1)

    def test_new_action_selection_requires_readable_accepted_membership(self):
        source = self.scan.parent / "completed-advantage"
        source.mkdir()
        manifest = {"run_id": source.name, "source_run_id": self.scan.name, "status": "complete",
                    "mode": "standard", "repository": "fixture"}
        put(source / "advantage-manifest.json", manifest)
        put(source / "report/security-report.json", {"run_id": source.name, "counts": {}, "findings": []})
        (source / "report/security-report.md").write_text("# Legacy completed assessment\n")
        context = {**self.context, "mode": "actions", "options": {"verify_fix": ["F-999"], "track_findings": []}}
        with self.assertRaisesRegex((ValueError, OSError), "final-verification/findings.json"):
            baseline.admit_action_source(source, context)
        for document in ({"findings": []}, {"findings": [accepted("F-001")],
                                          "rejections": [{"id": "F-999", "verdict": "rejected"}]},
                         {"findings": [], "unreviewed": [{"id": "F-999", "status": "execution_failed"}]},
                         {"findings": [{**accepted("F-999"), "verdict": "rejected"}]},
                         {"findings": [{**accepted("F-999"), "verdict": "rejected"}, {}]}):
            put(source / "final-verification/findings.json", document)
            with self.assertRaisesRegex(ValueError, "not accepted"):
                baseline.admit_action_source(source, context)
        finding = accepted("F-999")
        finding["assessment_context"] = {"attempt_id": "historical-producer"}
        put(source / "final-verification/findings.json", {"findings": [finding]})
        before = (source / "final-verification/findings.json").read_bytes()
        binding = baseline.admit_action_source(source, context)
        self.assertEqual(binding["selected_findings"], [{"id": "F-999"}])
        self.assertEqual((source / "final-verification/findings.json").read_bytes(), before)
        context["action_source"] = binding
        (source / "final-verification/findings.json").unlink()
        baseline.validate_action_source_binding(self.base, context)
        changed = copy.deepcopy(context)
        changed["options"]["verify_fix"] = ["F-001"]
        self.assert_hard_failure(lambda: baseline.validate_action_source_binding(self.base, changed))
        manifest["source_run_id"] = "foreign"
        put(source / "advantage-manifest.json", manifest)
        put(source / "final-verification/findings.json", {"findings": [finding]})
        self.assert_hard_failure(lambda: baseline.admit_action_source(source, context))

    def test_unreviewed_catalog_is_complete_without_confirmed_capabilities(self):
        rows = [{"id": f"G-{index:03d}", "status": "execution_failed",
                 "reason": "Supplementary review did not complete.",
                 "missing_fact": "Independent source review remains unavailable.",
                 "next_action": "Complete bounded independent review before promotion.",
                 "counterevidence": ["Prior route did not establish an attacker-controlled authority transition."],
                 "provenance": {"actor": "vulnops-final-verification",
                                "selector": "openai-codex/gpt-daybreak-red-latest:high",
                                "artifact_ref": "final-verification/findings.json"},
                 "input_refs": [f"synthesis/findings.json:G-{index:03d}"],
                 "task_ref": "final-verification/phase-manifest.json"}
                for index in range(251)]
        put(self.scan / "final-verification/findings.json", {"findings": [], "unreviewed": rows})
        put(self.scan / "report/security-report.json", {
            "run_id": self.scan.name, "summary": {}, "findings": [], "unreviewed": rows[:10],
            "publication": {"execution_kind": "audit", "repository": "fixture",
                            "repositories": [{"path": "."}], "model_routing": {}, "producer_routes": {}},
        })
        (self.scan / "report/security-report.md").write_text("# Completed bounded assessment\n")
        (self.scan / "run-manifest.json").unlink()
        (self.scan / "task-ledger.json").unlink()
        before = self.snapshot()
        catalog = baseline.build_catalog(self.context, self.scan)
        self.assertTrue(catalog["counts_complete"])
        self.assertEqual(catalog["counts"]["findings"], 0)
        self.assertEqual(catalog["counts"]["unreviewed"], len(rows))
        self.assertEqual(baseline.accepted_findings(self.scan), {})
        records = [row for row in catalog["records"] if row["record_type"] == "unreviewed"]
        self.assertEqual([row["id"] for row in records], [row["id"] for row in rows])
        for index, record in enumerate(records):
            self.assertEqual(record["status"], "execution_failed")
            self.assertEqual(record["pointer"], f"/unreviewed/{index}")
            self.assertEqual(core.resolve_reference(self.context, record["reference"]), rows[index])
        self.assertEqual(core.resolve_reference(
            self.context, self.typed("final-verification/findings.json:G-250")), rows[-1])
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
