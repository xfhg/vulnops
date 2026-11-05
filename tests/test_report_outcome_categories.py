"""Synthetic renderer regressions; no audit or target execution."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from model_identity import diversity_summary
from model_routing import GROUP_AGENTS, audit_routing, resolve_routing
from offline_package import network_identity, package_identity
from test_evidence_accounting import DEPENDENCY_LIMITATIONS
from test_run_lifecycle import activate_publisher


def report_context(run_id="synthetic", routing=None):
    context={"run_id": run_id, "attempt_id": "current-report-attempt", "model_routing": routing or audit_routing(resolve_routing({
        "routing": {group: "fixture/reviewer:high" for group in GROUP_AGENTS}})),
        "repositories": [{"name": "fixture", "path": ".", "remote_url": "local", "commit": "fixture"}],
        "network": network_identity("policy_only"), "offline_package": package_identity(ROOT)}
    context["attempt_contexts"]={context["attempt_id"]:{
        "repositories":context["repositories"], "model_routing":context["model_routing"],
        "started_at":"2026-01-02T03:04:05Z","source_view":"base"}}
    context["phase_attempts"]={"final-verification":context["attempt_id"]}
    return context


class ReportOutcomeCategories(unittest.TestCase):
    def render(self, history_count, limited_count, unresolved_count, dependency_limitations=(), *, resumed=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        scan = Path(temporary.name)

        def save(ref, value):
            path = scan / ref
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))

        context = report_context()
        verifier = context["model_routing"]["agents"]["vulnops-independent-verify-one"]
        save("context.json", context)
        if dependency_limitations:
            save("tool-collection/dependency-limitations.json",
                 {"schema_version": "2.0", "limitations": list(dependency_limitations)})
        save("final-verification/findings.json", {
            "findings": [], "rejections": [], "verifier_model": verifier, "objective_assessments": [],
            "assessment_context": {"attempt_id": context["attempt_id"]},
            **diversity_summary([]),
            "non_promoted": [{"id": f"F-{i:03d}", "disposition": "evidence_limited",
                "reason": "Local impact proof remains insufficient", "missing_fact": "Effect-side authority",
                "assessment_context": {"attempt_id": context["attempt_id"]},
                "next_action": "Inspect the privileged write", "input_refs": [f"sast/verified-findings.json:C-{i}"]}
                for i in range(limited_count)]})
        save("sast/coverage-ledger.json", {"cells": [
            {"id": "resolved", "status": "clean", "task_ids": ["T-resolved"],
             "resolution": {"outcome": "contradicted"}},
            *[{"id": f"path-{i}", "status": "shallow", "task_ids": [f"T-{i}"],
               "resolution": {"outcome": "locally_unresolved", "missing_fact": "Effect-side authority",
                              "next_action": "Inspect the privileged write"}} for i in range(unresolved_count)]],
            "tasks": []})
        save("intrusion/intrusion-results.json", {"results": []})
        save("campaign-planning/evidence-index.json", {"records": [
            {"id": f"E-{i:012X}", "artifact_ref": f"sast/verified-findings.json:C-{i}",
             "risk_context": {"priority": 2, "actor": "Remote caller"}}
            for i in range(history_count)]})
        save("campaign-planning/campaign-plan.json", {"campaigns": [], "evidence_dispositions": [
            {"evidence_id": f"E-{i:012X}", "status": "evidence_limited", "campaign_ids": [],
             "missing_fact": "Effect-side authority", "attempted_resolution": "Source anchor inspected",
             "next_action": "Inspect the privileged write", "deferral_reason": "Not separately allocated",
             "priority_reason": "Higher-priority work selected"} for i in range(history_count)] + [
            {"evidence_id": "E-FFFFFFFFFFFF", "status": "selected", "campaign_ids": ["CAM-001"]}]})
        if resumed:
            context["attempt_id"]="publication-only"
            context["repositories"]=[{"name":"later","path":"later","remote_url":"local","commit":"unassessed"}]
            save("context.json",context)
        env = activate_publisher(scan, context, "report",
            {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(scan / "context.json")})
        save("context.json", context)
        before = {path: path.read_bytes() for path in scan.rglob("*") if path.is_file()}
        subprocess.run([sys.executable, str(ROOT / "scripts/render-report.py"), str(scan)],
                       env=env,
                       check=True, capture_output=True, text=True)
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        return (json.loads((scan / "report/security-report.json").read_text()),
                (scan / "report/security-report.md").read_text())

    def test_dependency_inventory_gaps_remain_report_limitations_not_findings(self):
        report, markdown = self.render(0, 0, 0, DEPENDENCY_LIMITATIONS)
        self.assertEqual(report["findings"], [])
        for key in ("total", "confirmed", "needs_environment", "confirmed_standalone", "confirmed_chains"):
            self.assertEqual(report["summary"][key], 0)
        for limitation in DEPENDENCY_LIMITATIONS:
            self.assertIn(limitation["message"], report["limitations"])
            self.assertIn(limitation["message"], markdown)

    def test_history_claims_and_paths_remain_separate(self):
        report, markdown = self.render(21, 6, 8)
        accounting = report["investigation_accounting"]
        for key, count in (("historical_planning_deferrals", 21), ("evidence_limited", 6), ("unresolved_paths", 8)):
            self.assertEqual(report["summary"][key], count)
            self.assertEqual(accounting["counts"][key], count)
            self.assertEqual(len(accounting[key]), count)
            self.assertEqual(accounting["truncated"][key], 0)
        self.assertEqual(report["outcome_assessment"]["status"], "substantially_unresolved")
        self.assertTrue(all(row["evidence_ref"] == "final-verification/findings.json" for row in accounting["evidence_limited"]))
        historical = accounting["historical_planning_deferrals"][0]
        self.assertEqual(historical["evidence_ref"], "campaign-planning/campaign-plan.json")
        self.assertEqual(historical["source_ref"], "sast/verified-findings.json:C-0")
        self.assertEqual(historical["missing_fact"], "Effect-side authority")
        self.assertEqual(historical["next_action"], "Inspect the privileged write")
        self.assertIn("campaign-planning/campaign-plan.json", accounting["canonical_refs"])
        self.assertIn("campaign-planning/evidence-index.json", accounting["canonical_refs"])

    def test_retained_local_dispositions_keep_original_cohorts_after_resume(self):
        report, markdown = self.render(3, 6, 8, resumed=True)
        self.assertEqual(report["summary"]["confirmed"],0)
        self.assertEqual(report["summary"]["evidence_limited"],6)
        self.assertEqual(len(report["non_promoted"]),6)
        self.assertEqual(report["investigation_accounting"]["counts"]["historical_planning_deferrals"],3)
        self.assertEqual(report["investigation_accounting"]["counts"]["unresolved_paths"],8)
        self.assertTrue(report["assessment"]["retained"])
        self.assertEqual({row["assessment_context"]["attempt_id"] for row in report["non_promoted"]},
                         {"current-report-attempt"})
        self.assertNotIn("unassessed",markdown)

    def test_history_only_is_bounded_coverage_caveat_not_current_failure(self):
        for count in (21, 205):
            with self.subTest(history_count=count):
                report, markdown = self.render(count, 0, 0)
                accounting = report["investigation_accounting"]
                self.assertEqual(report["outcome_assessment"]["status"], "resolved_within_recorded_scope")
                self.assertEqual(report["summary"]["historical_planning_deferrals"], count)
                for key in ("evidence_limited", "unresolved_paths", "unscheduled_work"):
                    self.assertEqual(report["summary"][key], 0)
                self.assertEqual(accounting["counts"]["historical_planning_deferrals"], count)
                self.assertEqual(len(accounting["historical_planning_deferrals"]), min(count, 200))
                self.assertEqual(accounting["truncated"]["historical_planning_deferrals"], max(0, count - 200))
                self.assertNotIn("E-000000000000", markdown)
                self.assertNotIn("Not separately allocated", markdown)
                self.assertIn("[campaign-planning/campaign-plan.json](../campaign-planning/campaign-plan.json)", markdown)
                if count == 21:
                    small_line_count = len(markdown.splitlines())
                else:
                    self.assertEqual(len(markdown.splitlines()), small_line_count)
                self.assertTrue(all(row["status"] == "evidence_limited" for row in accounting["historical_planning_deferrals"]))


if __name__ == "__main__":
    unittest.main()
