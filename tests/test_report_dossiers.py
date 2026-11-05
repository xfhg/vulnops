"""Renderer/publication checks with authored final reviews, not native audit runs."""
from __future__ import annotations

import copy
import html
import importlib.util
import re
from urllib.parse import unquote
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_dossiers import sample_finding, seed_objective, review_dossier
from test_report_outcome_categories import report_context
from test_run_lifecycle import activate_publisher
from dossier_contract import objective_assessments
from model_identity import diversity_summary
from model_routing import GROUP_AGENTS, audit_routing, resolve_routing
from artifact_policy import DEFAULT_ARTIFACT_LIMIT, artifact_size_limit, oversized_artifacts

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("report_renderer", ROOT / "scripts/render-report.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
scan_spec = importlib.util.spec_from_file_location("report_scan_reader", ROOT / "scripts/validate-scan-v2.py")
scan_reader = importlib.util.module_from_spec(scan_spec)
scan_spec.loader.exec_module(scan_reader)


class ReportDossiers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.scan, self.source = self.base / "scan", self.base / "source"
        self.scan.mkdir(); self.source.mkdir()
        self.code = "def lookup(record_id):\n    return records[record_id]\n"
        (self.source / "source.py").write_text(self.code)
        seed_objective(self.scan)
        routing = {group: "fixture/reviewer:high" for group in GROUP_AGENTS}
        routing.update(sast="fixture/investigator:high", synthesis="fixture/synthesis:high")
        self.context = report_context(routing=audit_routing(resolve_routing({"routing": routing})))
        self.context.update(repo_path=str(self.source), source_root=str(self.source), reproduction_mode="off")
        self.context["attempt_contexts"] = {self.context["attempt_id"]: {
            "repositories": copy.deepcopy(self.context["repositories"]), "source_root": str(self.source),
            "source_view": "base", "started_at": "2026-01-02T03:04:05Z",
            "model_routing": copy.deepcopy(self.context["model_routing"])}}
        self.save("context.json", self.context)
        self.finding = sample_finding()
        self.finding.update(verdict="confirmed", model_diversity=True,
                            independent_verification_ref="final-verification/results/F-001.json")
        self.finding["assessment_context"] = {"attempt_id": self.context["attempt_id"]}
        origin = self.finding["contributors"][0]
        self.save(origin["artifact_ref"], {"provenance": origin})
        self.save("sast/verified-findings.json", [{"id": "C-001", "contributors": [origin],
                                                 "evidence_refs": ["source.py:1-2"]}])
        self.finding["technical_examples"] = [{"id": "code", "kind": "source", "content": self.code.rstrip(),
            "evidence_refs": ["source.py:1-2"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []},
            {"id": "request", "kind": "request", "content": "GET /records/OTHER_TENANT_RECORD HTTP/1.1\nAuthorization: Bearer <redacted>",
             "evidence_refs": ["source.py:1-2"], "substitutions": [{"original": "record_id", "replacement": "OTHER_TENANT_RECORD",
             "reason": "Synthetic identifier; an ordinary authenticated account is required."}], "execution_status": "not_executed", "observation_refs": []}]
        self.finding["exploitation"]["steps"][0]["example_ids"] = ["code", "request"]

    def save(self, ref, value):
        path = self.scan / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def render(self, finding=None, *, review_status="verified", findings=None):
        findings = findings if findings is not None else [finding or self.finding]
        reviews = {}
        for finding in findings:
            status="needs_environment" if finding["verdict"]=="needs_environment" else review_status
            candidate={key:value for key,value in finding.items()
                       if key not in {"verdict","model_diversity","independent_verification_ref","assessment_context"}}
            review = review_dossier(finding, {
                "schema_version": "2.0", "finding_id": finding["id"], "status": status,
                "closure_reason": finding["closure_rationale"], "evidence_refs": ["source.py:1-2"],
                "primitive_results": [], "transition_results": [],
                "joint_conditions": {"outcome": "externally_blocked" if status=="needs_environment" else "established",
                    "reason": finding["closure_rationale"], "evidence_refs": ["source.py:1-2"],
                    "missing_fact": "Deployment binding" if status=="needs_environment" else "", "next_action": ""},
                "corrections": [], "corrected_finding": candidate if status=="corrected" else None,
                "actor": "vulnops-independent-verify-one",
                "model": self.context["model_routing"]["agents"]["vulnops-independent-verify-one"],
                "model_diversity": finding["model_diversity"]})
            if finding.get("assessment_context"):
                review["assessment_context"] = finding["assessment_context"]
            self.save(finding["independent_verification_ref"], review)
            reviews[finding["id"]] = review
        final = {"schema_version": "2.0", "run_id": "synthetic", "findings": findings, "rejections": [],
                 "assessment_context": findings[0].get("assessment_context"),
                 "verifier_model": self.context["model_routing"]["agents"]["vulnops-independent-verify-one"],
                 **diversity_summary(findings),
                 "objective_assessments": objective_assessments(self.scan, findings, results=reviews)}
        self.save("final-verification/findings.json", final)
        self.env = activate_publisher(self.scan, self.context, "report",
            {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.scan / "context.json")})
        self.save("context.json", self.context)
        before = {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file() and "report" not in path.parts}
        result = self.publish()
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        return result

    def publish(self):
        return subprocess.run([sys.executable, str(ROOT / "scripts/render-report.py"), str(self.scan)],
            env=self.env,
            capture_output=True, text=True)

    def test_evidence_links_preserve_records_and_reject_unsafe_destinations(self):
        self.save("sast/a (review).json", {"id": "C-1"})
        link = renderer.evidence_link(self.scan, "sast/a (review).json#C-1", "Review [record]")
        destination = re.search(r"\]\(([^)]+)\)", link).group(1)
        self.assertEqual((self.scan / "report" / unquote(destination)).resolve(),
                         (self.scan / "sast/a (review).json").resolve())
        self.assertIn("C-1", link)
        self.assertNotIn("#", destination)
        self.assertEqual(renderer.evidence_link(self.scan, "report/security-report.json"),
                         "[report/security-report.json](security-report.json)")
        for ref in ("sast/missing.json", "sast/experiments/*/result.json"):
            self.assertNotRegex(renderer.evidence_link(self.scan, ref), r"\]\(")
            with self.assertRaises(ValueError):
                renderer.evidence_link(self.scan, ref, required=True)
        outside = self.base / "outside.json"
        outside.write_text("{}")
        (self.scan / "sast/escape.json").symlink_to(outside)
        for ref in ("../outside.json", str(outside), "https://example.invalid/evidence",
                    "file:///outside.json", "sast/escape.json", "recovery-archives/old.json"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                renderer.evidence_link(self.scan, ref)

    def test_opening_preserves_scope_priority_and_evidence_status(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.scan / "report/security-report.json").read_text())
        report["repositories"].append({"path": "second/service", "commit": "revision-two"})
        second = copy.deepcopy(report["findings"][0])
        second.update(id="F-002", severity="critical", risk_score=99)
        report["findings"].append(second)
        report["summary"]["critical"] += 1
        report["summary"]["confirmed"] += 1
        snapshot = copy.deepcopy(report)
        text = renderer.render_markdown(report, self.scan)
        opening = text.split("## Finding dossiers", 1)[0]
        self.assertIn(report["date"], opening)
        self.assertIn("second/service", opening)
        self.assertIn("revision-two", opening)
        self.assertIn("**Critical:** 1", opening)
        self.assertLess(opening.index("[F-002]"), opening.index("[F-001]"))
        self.assertIn("not dynamically tested", opening)
        self.assertNotIn("99/100", text)
        self.assertEqual(report, snapshot)

    def test_complete_causal_dossier_survives_both_outputs(self):
        self.finding["title"] = "Tenant record disclosure <script>alert(1)</script>"
        self.finding["attack_summary"] = "~~~"
        content = "# ```\n# forged heading\n# `````"
        (self.source / "example.py").write_text(content + "\n")
        self.finding["technical_examples"].append({"id": "fences", "kind": "source", "content": content,
            "evidence_refs": ["example.py:1-3"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []})
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.scan / "report/security-report.json").read_text())
        self.assertEqual(report["findings"], [self.finding])
        markdown = (self.scan / "report/security-report.md").read_text()
        self.assertIn(self.code.rstrip(), markdown)
        self.assertIn(self.finding["technical_examples"][1]["content"], markdown)
        self.assertNotIn("<script>", markdown)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertNotIn("\n~~~\n", markdown)
        self.assertIn(r"\~\~\~", markdown)
        self.assertIn("``````\n" + content + "\n``````", markdown)
        dossier = markdown.split("## Finding dossiers", 1)[1].split("## Prioritized defensive handoff", 1)[0]
        self.assertIn("Reject another tenant", dossier)
        self.assertIn("authenticated tenant", dossier)
        self.assertTrue(report["objective_assessments"][0]["finding_ids"])

    def test_open_claims_keep_explicit_ownership_without_inheriting_success(self):
        self.assertEqual(self.render().returncode, 0)
        report = json.loads((self.scan / "report/security-report.json").read_text())
        objective = report["objective_assessments"][0]
        objective["remaining_obligations"] = ["Authorization of queued writes remains unproven."]
        claim = {"id": "OPEN-1", "objective_id": objective["objective_id"], "disposition": "evidence_limited",
                 "missing_fact": "Authority at the queued consumer", "next_action": "Inspect the queue consumer",
                 "evidence_ref": "final-verification/findings.json", "correction_repair": {"diagnostics": ["Historical selector error"]}}
        unbound = {key: value for key, value in claim.items() if key != "objective_id"}
        unbound["id"] = "OPEN-2"
        report["investigation_accounting"]["evidence_limited"] = [claim, copy.deepcopy(claim), unbound]
        report["investigation_accounting"]["counts"]["evidence_limited"] = 3
        snapshot = copy.deepcopy(report)
        text = renderer.render_markdown(report, self.scan)
        self.assertEqual(text.count("**OPEN-1:**"), 1)
        self.assertEqual(text.count("**OPEN-2:**"), 1)
        self.assertEqual(text.count("Related objective:"), 1)
        self.assertIn(objective["remaining_obligations"][0], text)
        self.assertIn(claim["missing_fact"], text)
        self.assertIn(claim["next_action"], text)
        self.assertNotIn("Historical selector error", text)
        self.assertIn("(../final-verification/findings.json)", text)
        for action in report["findings"][0]["remediation"]["actions"]:
            self.assertIn("#fix-F-001-" + action["id"], text)
            self.assertIn(action["change"], text)
        self.assertEqual(report, snapshot)

    def test_mixed_observation_does_not_mark_the_whole_procedure_executed(self):
        rendered = self.render()
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        # Formatting only: this authored status artifact is not execution authority.
        finding = copy.deepcopy(self.finding)
        observed = copy.deepcopy(finding["exploitation"]["steps"][0])
        observed.update(id="isolated", action="Exercise the isolated fixture lookup.", evidence_status="observed_contained",
                        observed_result="The isolated fixture lookup returned one record.",
                        observation_refs=["sast/experiments/isolated/result.json"])
        finding["exploitation"]["steps"].append(observed)
        self.save(observed["observation_refs"][0], {"status": "supported"})
        text = "\n".join(renderer.finding_lines(finding, self.scan, self.context["repositories"]))
        self.assertIn("observed\\_contained", text)
        self.assertIn("source\\_established", text)
        self.assertIn(observed["observed_result"], text)
        self.assertIn("(../sast/experiments/isolated/result.json)", text)
        self.assertNotIn("**Execution:** source-established; not dynamically tested", text)
        self.assertIn(finding["exploitation"]["steps"][0]["expected_result"], text)
        self.assertIn("**Execution:** step-specific source/contained evidence; no whole-attack execution inferred.", text)
        source_section, observed_section = text.split('<a id="step-F-001-isolated"></a>', 1)
        source_section = source_section.split('<a id="step-F-001-step-1"></a>', 1)[1]
        observed_section = observed_section.split("#### Technical examples", 1)[0]
        self.assertIn("Not executed / no observation claimed.", source_section)
        self.assertNotIn(observed["observed_result"], source_section)
        self.assertNotIn("Observation evidence:", source_section)
        self.assertIn(observed["action"], observed_section)
        self.assertIn(observed["observed_result"], observed_section)
        self.assertIn("Observation evidence:", observed_section)

    def test_environment_and_corrected_effective_dossiers_keep_their_distinctions(self):
        for status in ("needs_environment", "corrected"):
            with self.subTest(status=status):
                finding = copy.deepcopy(self.finding)
                if status == "needs_environment":
                    finding.update(status="needs_environment", verdict="needs_environment")
                    finding["verification"]["level"] = "environment_required"
                    finding["impact_limits"] = ["The configured deployment binding is still required to establish exposure."]
                else:
                    finding["impact"] = "Disclosure is limited to the single selected record; bulk export is not established."
                result = self.render(finding, review_status=status)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads((self.scan / "report/security-report.json").read_text())
                self.assertEqual(report["findings"], [finding])
                self.assertEqual(report["summary"]["confirmed"], int(status == "corrected"))
                self.assertEqual(report["summary"]["needs_environment"], int(status == "needs_environment"))
                self.assertEqual(report["objective_assessments"][0]["status"], "achieved" if status == "corrected" else "unresolved")
                self.assertIn(finding["impact"], (self.scan / "report/security-report.md").read_text())

    def test_in_limit_multistep_procedure_is_not_clipped(self):
        step = self.finding["exploitation"]["steps"][0]
        step["why_it_works"] = "Source-derived explanation: " + "x" * (8000 - len("Source-derived explanation: "))
        second = {**copy.deepcopy(step), "id": "step-2", "action": "Inspect the selected record without issuing additional requests.",
                  "controlled_input": "The record returned by step-1.", "why_it_works": "The lookup returns the selected record directly.",
                  "expected_result": "The returned record belongs to the other tenant, not the authenticated tenant.",
                  "example_ids": []}
        self.finding["exploitation"]["steps"].append(second)
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.scan / "report/security-report.json").read_text())
        self.assertEqual(report["findings"][0]["exploitation"], self.finding["exploitation"])
        markdown = (self.scan / "report/security-report.md").read_text()
        self.assertIn(step["why_it_works"], markdown)
        self.assertIn(second["expected_result"], markdown)


    def test_unsafe_example_fails_without_persisting_or_echoing_material(self):
        value = "synthetic-credential-" + "x" * 24
        self.finding["technical_examples"][1]["content"] = "Authorization: Bearer " + value
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(value, result.stdout + result.stderr)
        self.assertFalse((self.scan / "report/security-report.json").exists())
        self.assertFalse((self.scan / "report/security-report.md").exists())

    def test_report_only_resume_preserves_assessment_after_source_and_route_changes(self):
        self.assertEqual(self.render().returncode, 0)
        final_path = self.scan / "final-verification/findings.json"
        final_bytes = final_path.read_bytes()
        old_review = (self.scan / self.finding["independent_verification_ref"]).read_bytes()
        self.context["attempt_id"] = "report-only-resume"
        self.context["model_routing"] = audit_routing(resolve_routing({
            "routing": {group: "fixture/new-reviewer:high" for group in GROUP_AGENTS}}))
        self.context.update(scan_base=str(self.scan), workflow="canonical-redteam-v2")
        self.env = activate_publisher(self.scan, self.context, "report", self.env)
        self.save("context.json", self.context)
        (self.source / "source.py").unlink()
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.scan / "report/security-report.json").read_text())
        self.assertEqual(report["findings"], [self.finding])
        self.assertEqual(report["summary"]["confirmed"], 1)
        self.assertEqual(report["summary"]["high"], 1)
        self.assertEqual(report["diversity_counts"], {"total": 1, "diverse": 1, "same_model": 0})
        self.assertTrue(report["model_diversity"])
        self.assertTrue(report["assessment"]["retained"])
        self.assertEqual(report["verifier_model"], "fixture/reviewer:high")
        self.assertEqual(report["model_routing"], self.context["attempt_contexts"]["current-report-attempt"]["model_routing"])
        self.assertTrue(report["objective_assessments"])
        self.assertEqual(report["coverage"]["availability"], "unavailable")
        self.assertNotIn("cells", report["coverage"])
        self.assertIn(report["coverage"]["limitation"], report["limitations"])
        self.assertIn("sast/coverage-ledger.json", report["coverage"]["limitation"])
        text=(self.scan / "report/security-report.md").read_text()
        self.assertIn("Later-source applicability is not revalidated", text)
        self.assertIn("2026-01-02T03:04:05Z", text)
        self.assertIn(self.finding["technical_examples"][1]["content"], text)
        self.assertIn(self.code.rstrip(), text)
        self.assertIn(self.finding["remediation"]["actions"][0]["change"], text)
        self.assertEqual(final_path.read_bytes(), final_bytes)
        self.assertEqual((self.scan / self.finding["independent_verification_ref"]).read_bytes(), old_review)
        validation = subprocess.run([sys.executable, str(ROOT / "scripts/validate-phase-v2.py"),
            str(ROOT), str(self.scan), "report"],
            env={**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.scan / "context.json")},
            capture_output=True, text=True)
        self.assertEqual(validation.returncode, 0, validation.stderr)
        report["summary"]["high"] = 0
        self.save("report/security-report.json", report)
        invalid = subprocess.run([sys.executable, str(ROOT / "scripts/validate-phase-v2.py"),
            str(ROOT), str(self.scan), "report"],
            env={**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.scan / "context.json")},
            capture_output=True, text=True)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("summary.high differs from accepted assessment projection", invalid.stderr)

    def test_legacy_findings_keep_verdicts_with_explicit_unknown_scope(self):
        self.finding.pop("assessment_context")
        self.context.pop("phase_attempts",None)
        self.context.pop("attempt_contexts",None)
        self.save("context.json",self.context)
        self.assertEqual(self.render().returncode, 0)
        report = json.loads((self.scan / "report/security-report.json").read_text())
        self.assertEqual(report["findings"], [self.finding])
        self.assertEqual(report["summary"]["total"], 1)
        self.assertEqual(report["assessment"]["scopes"][0]["repositories"], [])
        self.assertTrue(report["assessment"]["limitations"])


    def test_resumed_large_cohort_keeps_totals_full_dossiers_and_navigation(self):
        original=self.context["attempt_contexts"][self.context["attempt_id"]]
        original["repositories"] += [{"name": f"service-{i}", "path": f"service-{i}",
            "remote_url": "local", "commit": f"assessed-{i}"} for i in range(1,31)]
        self.save("context.json",self.context)
        findings=[]
        for index in range(24):
            finding=copy.deepcopy(self.finding)
            finding["id"]=f"F-{index+1:03}"
            finding["independent_verification_ref"]=f"final-verification/results/{finding['id']}.json"
            finding["severity"]="critical" if index<9 else "high" if index<21 else "medium"
            if index>=22:
                finding.update(status="needs_environment",verdict="needs_environment")
                finding["verification"]["level"]="environment_required"
            findings.append(finding)
        result=self.render(findings=findings)
        self.assertEqual(result.returncode,0,result.stderr)
        before={path:path.read_bytes() for path in (self.scan/"final-verification").rglob("*.json")}
        self.context.update(attempt_id="publication-only",repositories=[
            {"name":"later","path":"later","remote_url":"local","commit":"not-assessed"}])
        self.context["model_routing"]=audit_routing(resolve_routing({
            "routing":{group:"fixture/changed:high" for group in GROUP_AGENTS}}))
        self.env = activate_publisher(self.scan, self.context, "report", self.env)
        self.save("context.json",self.context)
        (self.source/"source.py").unlink()
        result=self.publish()
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads((self.scan/"report/security-report.json").read_text())
        self.assertEqual(report["findings"],findings)
        self.assertEqual({key:report["summary"][key] for key in
            ("total","confirmed","needs_environment","critical","high","medium")},
            {"total":24,"confirmed":22,"needs_environment":2,"critical":9,"high":12,"medium":1})
        self.assertEqual(len(report["repositories"]),31)
        self.assertEqual(report["diversity_counts"],{"total":24,"diverse":24,"same_model":0})
        self.assertEqual(report["verifier_model"],"fixture/reviewer:high")
        text=(self.scan/"report/security-report.md").read_text()
        anchors=set(re.findall(r'<a id="([^"]+)"></a>',text))
        local_links={unquote(value) for value in re.findall(r'\]\(#([^)]+)\)',text)}
        self.assertLessEqual(local_links,anchors)
        for finding in findings:
            self.assertIn("finding-"+finding["id"],anchors)
            for step in finding["exploitation"]["steps"]:
                self.assertIn("step-"+finding["id"]+"-"+step["id"],anchors)
                self.assertIn(step["expected_result"],text)
            for action in finding["remediation"]["actions"]:
                self.assertIn("#fix-"+finding["id"]+"-"+action["id"],text)
                for step in action["breaks_steps"]:
                    self.assertIn("#step-"+finding["id"]+"-"+step,text)
            for example in finding["technical_examples"]:self.assertIn(example["content"],text)
        self.assertNotIn("not-assessed",text)
        self.assertEqual({path:path.read_bytes() for path in before},before)


    def test_optional_retained_support_is_a_limitation_not_dossier_loss(self):
        ref="sast/experiments/removed/result.json"
        self.finding["remediation"]["actions"][0]["evidence_refs"].append(ref)
        result=self.render()
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads((self.scan/"report/security-report.json").read_text())
        self.assertEqual(report["findings"],[self.finding])
        self.assertTrue(any(ref in limitation for limitation in report["limitations"]))
        self.assertIn("unavailable",(self.scan/"report/security-report.md").read_text())

    def test_recorded_reviewer_cannot_be_replaced_by_publisher_route(self):
        self.assertEqual(self.render().returncode,0)
        review=json.loads((self.scan/self.finding["independent_verification_ref"]).read_text())
        review["model"]="fixture/replacement:high"
        self.save(self.finding["independent_verification_ref"],review)
        self.context["model_routing"]["agents"]["vulnops-independent-verify-one"]=review["model"]
        self.save("context.json",self.context)
        result=self.publish()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("reviewer differs from recorded producing assignment",result.stderr)

    def test_accepted_dossier_mutation_cannot_bypass_review_binding(self):
        self.assertEqual(self.render().returncode,0)
        final=json.loads((self.scan/"final-verification/findings.json").read_text())
        final["findings"][0]["exploitation"]["steps"][0]["controlled_input"]="Different unreviewed authority"
        self.save("final-verification/findings.json",final)
        result=self.publish()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("independent dossier review is stale",result.stderr)

    def test_foreign_final_execution_and_review_identity_are_rejected(self):
        self.assertEqual(self.render().returncode,0)
        final=json.loads((self.scan/"final-verification/findings.json").read_text())
        final["run_id"]="foreign-run"
        self.save("final-verification/findings.json",final)
        result=self.publish()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("run_id differs",result.stderr)
        final["run_id"]=self.context["run_id"]
        self.save("final-verification/findings.json",final)
        review=json.loads((self.scan/self.finding["independent_verification_ref"]).read_text())
        review["finding_id"]="F-999"
        self.save(self.finding["independent_verification_ref"],review)
        result=self.publish()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("finding_id differs",result.stderr)

    def test_rejected_disposition_survives_publication_resume(self):
        self.assertEqual(self.render().returncode,0)
        final=json.loads((self.scan/"final-verification/findings.json").read_text())
        rejection={"id":self.finding["id"],"reason":"Source authority contradicts the claim.",
            "independent_verification_ref":self.finding["independent_verification_ref"],
            "assessment_context":self.finding["assessment_context"]}
        final.update(findings=[],rejections=[rejection],objective_assessments=[],**diversity_summary([]))
        self.save("final-verification/findings.json",final)
        review=json.loads((self.scan/self.finding["independent_verification_ref"]).read_text())
        review.update(status="rejected",closure_reason=rejection["reason"])
        self.save(self.finding["independent_verification_ref"],review)
        self.context["attempt_id"]="publication-only"
        self.env = activate_publisher(self.scan, self.context, "report", self.env)
        self.save("context.json",self.context)
        result=self.publish()
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads((self.scan/"report/security-report.json").read_text())
        self.assertEqual(report["rejections"],[rejection])
        self.assertEqual(report["summary"]["rejected"],1)
        self.assertEqual(report["summary"]["confirmed"],0)


    def test_optional_absence_and_corruption_preserve_dossiers_counts_and_scopes(self):
        self.assertEqual(self.render().returncode, 0)
        final_bytes=(self.scan/"final-verification/findings.json").read_bytes()
        review_bytes=(self.scan/self.finding["independent_verification_ref"]).read_bytes()
        baseline=json.loads((self.scan/"report/security-report.json").read_text())
        refs=("sast/coverage-ledger.json","campaign-planning/campaign-plan.json",
              "intrusion/intrusion-results.json","repo-context/security-surfaces.json")
        # Publishing retained authority must not require today's source.
        (self.source/"source.py").write_text("changed after accepted review\n")
        for ref in refs:
            path=self.scan/ref
            path.parent.mkdir(parents=True,exist_ok=True)
            path.unlink(missing_ok=True)
            reports=[]
            for content in (None,"{broken",json.dumps({"cells":"invalid","tasks":[]})):
                with self.subTest(reference=ref,content=content):
                    if content is not None:path.write_text(content)
                    result=self.publish()
                    self.assertEqual(result.returncode,0,result.stderr)
                    report=json.loads((self.scan/"report/security-report.json").read_text())
                    for key in ("findings","rejections","objective_assessments","assessment","summary"):
                        self.assertEqual(report[key],baseline[key])
                    self.assertTrue(any(ref in item and "unavailable" in item for item in report["limitations"]))
                    self.assertIsNone(report["investigation_accounting"]["counts"]["coverage_cells"])
                    reports.append(report)
            self.assertEqual(reports[0]["limitations"],reports[1]["limitations"])
            path.unlink()
        self.assertEqual((self.scan/"final-verification/findings.json").read_bytes(),final_bytes)
        self.assertEqual((self.scan/self.finding["independent_verification_ref"]).read_bytes(),review_bytes)

    def test_optional_integrity_failures_leave_existing_reports_unchanged(self):
        self.assertEqual(self.render().returncode,0)
        path=self.scan/"sast/coverage-ledger.json"
        path.parent.mkdir(parents=True,exist_ok=True)
        before={p:p.read_bytes() for p in (self.scan/"report").iterdir()}
        secret="synthetic-credential-"+"x"*24
        for content in (json.dumps({"run_id":"foreign","cells":"malformed"}),
                        '{"broken":"Authorization: Bearer '+secret+'"',
                        json.dumps({"cells":[],"tasks":[],"stdout":"forbidden output"})):
            with self.subTest(content_kind=content[:15]):
                path.write_text(content)
                result=self.publish()
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn(secret,result.stderr)
                self.assertEqual({p:p.read_bytes() for p in before},before)
        path.unlink()
        outside=self.base/"outside.json"
        outside.write_text("{}")
        path.symlink_to(outside)
        self.assertNotEqual(self.publish().returncode,0)
        self.assertEqual({p:p.read_bytes() for p in before},before)

    def test_invalid_required_authority_never_replaces_publication(self):
        self.assertEqual(self.render().returncode, 0)
        before = {p: p.read_bytes() for p in (self.scan / "report").iterdir()}
        for ref in (self.finding["independent_verification_ref"], "final-verification/findings.json"):
            path = self.scan / ref
            saved = path.read_bytes()
            for damage in ("missing", "malformed", "missing_field"):
                with self.subTest(authority=ref, damage=damage):
                    if damage == "missing":
                        path.unlink()
                    elif damage == "malformed":
                        path.write_text("{broken")
                    else:
                        value = json.loads(saved)
                        del value["findings" if ref == "final-verification/findings.json" else "finding_id"]
                        path.write_text(json.dumps(value))
                    result = self.publish()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(ref, result.stderr)
                    if damage == "missing_field" and ref == "final-verification/findings.json":
                        self.assertIn("missing or invalid findings", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual({p: p.read_bytes() for p in (self.scan / "report").iterdir()}, before)
                    path.write_bytes(saved)

    def test_navigation_unavailability_has_unknown_counts_without_losing_known_results(self):
        ref="intrusion/graph/receipt.json"
        self.save("intrusion/intrusion-results.json", {"results":[{
            "campaign_id":"CAM-known","resolution":{"outcome":"contradicted"},
            "graph_query_receipts":[ref]}]})
        self.save("campaign-planning/campaign-plan.json", {"campaigns":[]})
        self.save("campaign-planning/evidence-index.json", {"records":[],"primitives":[]})
        self.save("sast/coverage-ledger.json", {"cells":[],"tasks":[]})
        self.assertEqual(self.render().returncode,0)
        first=json.loads((self.scan/"report/security-report.json").read_text())
        self.save(ref,{})
        (self.scan/ref).write_text("{broken")
        result=self.publish()
        self.assertEqual(result.returncode,0,result.stderr)
        second=json.loads((self.scan/"report/security-report.json").read_text())
        for key in ("findings","summary","assessment","investigation_accounting","limitations"):
            self.assertEqual(first[key],second[key])
        self.assertEqual(second["investigation_accounting"]["counts"]["resolved_investigations"],1)
        self.assertIsNone(second["summary"]["graph_useful_receipts"])
        self.assertIsNone(second["summary"]["graph_failed_receipts"])
        self.assertTrue(any(ref in item for item in second["limitations"]))


    def test_late_publishers_refuse_unowned_stale_and_foreign_commands_without_mutation(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.save("intrusion/intrusion-results.json", {"results": [], "retained": True})
        self.save("intrusion/phase-manifest.json", {"phase": "intrusion", "status": "ok"})
        (self.scan / "intrusion/summary.md").write_text("Retained intrusion summary.\n")
        original_context = copy.deepcopy(self.context)
        for phase, script in (("report", "render-report.py"), ("intrusion", "finalize-intrusion.py")):
            for invalid in ("complete", "phase_complete", "task_complete", "stale_context",
                            "stale_task", "foreign_run", "foreign_ledger", "foreign_destination",
                            "missing_manifest", "missing_ledger", "unowned", "foreign_owner"):
                with self.subTest(phase=phase, authority=invalid):
                    context = copy.deepcopy(original_context)
                    env = activate_publisher(self.scan, context, phase, self.env)
                    manifest = json.loads((self.scan / "run-manifest.json").read_text())
                    ledger = json.loads((self.scan / "task-ledger.json").read_text())
                    if invalid == "complete":
                        manifest["status"] = "complete"
                    elif invalid == "phase_complete":
                        manifest["phases"][phase] = "ok"
                    elif invalid == "task_complete":
                        ledger["tasks"][0]["status"] = "ok"
                    elif invalid == "stale_context":
                        context["attempt_id"] = "stale-attempt"
                    elif invalid == "stale_task":
                        ledger["tasks"][0]["attempt_id"] = "stale-attempt"
                    elif invalid == "foreign_run":
                        manifest["run_id"] = "another-execution"
                    elif invalid == "foreign_ledger":
                        ledger["run_id"] = "another-execution"
                    elif invalid == "foreign_destination":
                        context["scan_base"] = str(self.source)
                    elif invalid == "unowned":
                        env["VULNOPS_RUNTIME_ROOT"] = str(self.base / "unowned-runtime")
                    elif invalid == "foreign_owner":
                        env["VULNOPS_LAUNCHER_SESSION_ID"] = "another-session"
                    self.save("run-manifest.json", manifest)
                    self.save("task-ledger.json", ledger)
                    self.save("context.json", context)
                    if invalid == "missing_manifest":
                        (self.scan / "run-manifest.json").unlink()
                    elif invalid == "missing_ledger":
                        (self.scan / "task-ledger.json").unlink()
                    before = {path.relative_to(self.scan): path.read_bytes()
                              for path in self.scan.rglob("*") if path.is_file()}
                    result = subprocess.run([sys.executable, str(ROOT / "scripts" / script), str(self.scan)],
                                            env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual({path.relative_to(self.scan): path.read_bytes()
                                      for path in self.scan.rglob("*") if path.is_file()}, before)

    def test_invalid_required_dossier_text_still_fails_without_clipping(self):
        for field in ("attack_summary", "action"):
            with self.subTest(field=field):
                finding = copy.deepcopy(self.finding)
                container = finding if field == "attack_summary" else finding["exploitation"]["steps"][0]
                container[field] = "x" * 8001
                snapshot = copy.deepcopy(finding)
                result = self.render(finding)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("8000", result.stderr)
                self.assertEqual(finding, snapshot)
                retained = json.loads((self.scan / "final-verification/findings.json").read_text())
                self.assertEqual(retained["findings"], [snapshot])
                self.assertFalse((self.scan / "report/security-report.json").exists())
                self.assertFalse((self.scan / "report/security-report.md").exists())

    def test_oversized_complete_reports_publish_and_all_report_gates_consume_them(self):
        # Each finding stays within dossier cardinality/text bounds and the combined
        # final-verification artifact remains below its unchanged 16 MiB limit.
        findings = []
        for index in range(20):
            finding = copy.deepcopy(self.finding)
            finding["id"] = f"F-{index + 1:03}"
            finding["independent_verification_ref"] = f"final-verification/results/{finding['id']}.json"
            template = finding["exploitation"]["steps"][0]
            finding["exploitation"]["steps"] = []
            for step_index in range(60):
                step = copy.deepcopy(template)
                step["id"] = f"step-{step_index + 1}"
                # Literal angle brackets also exercise Markdown expansion beyond
                # 16 MiB without making any individual source artifact oversized.
                step["why_it_works"] = f"Finding {index + 1}, step {step_index + 1}: " + "<id> " * 1580
                finding["exploitation"]["steps"].append(step)
            findings.append(finding)
        notes = [{"title": f"Retained note {index}", "description": "Source-derived context: " + "x" * 7900,
                  "evidence_refs": ["source.py:1-2"]} for index in range(1100)]
        self.save("sast/hardening-notes.json", notes)
        self.context.update(scan_base=str(self.scan), workflow="canonical-redteam-v2")
        self.save("context.json", self.context)
        # Earlier phase states and terminal tasks below are authored reader fixtures;
        # successful gates do not attest execution of those workflow phases.
        phases = {phase: "ok" for phase in ("recon", "tool-collection", "sast",
                  "campaign-planning", "intrusion", "synthesis", "final-verification", "report")}
        phases["report"] = "running"
        run = {"run_id": self.context["run_id"], "status": "incomplete",
               "workflow": "canonical-redteam-v2", "phases": phases,
               "model_routing": self.context["model_routing"]}
        self.save("run-manifest.json", run)

        result = self.render(findings=findings)
        self.assertEqual(result.returncode, 0, result.stderr)
        for relative in ("final-verification/findings.json", "sast/hardening-notes.json"):
            path = self.scan / relative
            self.assertLess(path.stat().st_size, artifact_size_limit(Path(relative)))
        self.assertEqual(oversized_artifacts(self.scan), [])
        json_path = self.scan / "report/security-report.json"
        markdown_path = self.scan / "report/security-report.md"
        for path in (json_path, markdown_path):
            self.assertGreater(path.stat().st_size, DEFAULT_ARTIFACT_LIMIT)
        report = json.loads(json_path.read_text())
        self.assertEqual(report["findings"], findings)
        self.assertEqual(report["hardening_notes"], notes)
        markdown = markdown_path.read_text()
        retained_explanations = re.findall(r"^   - Why it works: (.*)$", markdown, re.MULTILINE)
        self.assertEqual(retained_explanations, [
            html.escape(step["why_it_works"], quote=False)
            for finding in findings for step in finding["exploitation"]["steps"]])
        self.assertEqual(scan_reader.read_publication(self.scan), report)

        env = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.scan / "context.json")}
        for command in (
            ["validate-json.py", str(ROOT / "schemas/v2/report.schema.json"), str(json_path)],
            ["validate-phase-v2.py", str(ROOT), str(self.scan), "report"],
        ):
            with self.subTest(gate=command[0]):
                validation = subprocess.run([sys.executable, str(ROOT / "scripts" / command[0]), *command[1:]],
                                            env=env, capture_output=True, text=True)
                self.assertEqual(validation.returncode, 0, validation.stderr)
        phases["report"] = "ok"
        self.save("run-manifest.json", run)
        self.save("task-ledger.json", {"tasks": [{"phase": phase, "status": "ok"} for phase in phases]})
        validation = subprocess.run([sys.executable, str(ROOT / "scripts/validate-scan-v2.py"),
                                     str(ROOT), str(self.scan)], env=env, capture_output=True, text=True)
        self.assertEqual(validation.returncode, 0, validation.stderr)

    def test_completed_report_preserves_attribution_without_controls_or_source(self):
        from report_bundle import read_publication, retire_controls
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        original = json.loads((self.scan / "report/security-report.json").read_text())
        retire_controls(self.scan, self.context["run_id"])
        self.assertFalse((self.scan / "run-manifest.json").exists())
        self.assertFalse((self.scan / "task-ledger.json").exists())
        (self.scan / "context.json").unlink()
        (self.source / "source.py").unlink()
        self.source.rmdir()
        bundle = read_publication(self.scan, expected_kind="audit", validate_evidence=True)
        self.assertEqual(bundle["report"], original)
        self.assertEqual(bundle["report"]["findings"], [self.finding])
        self.assertEqual(bundle["repositories"], original["repositories"])
        review_ref = self.finding["independent_verification_ref"]
        route = bundle["producer_routes"][review_ref]
        self.assertEqual(route["agents"]["vulnops-independent-verify-one"],
                         self.context["model_routing"]["agents"]["vulnops-independent-verify-one"])
        review = json.loads((self.scan / review_ref).read_text())
        review["model"] = "fixture/foreign-reviewer:high"
        self.save(review_ref, review)
        with self.assertRaisesRegex(ValueError, "producing route"):
            read_publication(self.scan, validate_evidence=True)

    def test_control_retirement_refuses_changed_final_dossier(self):
        from report_bundle import retire_controls
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        final = json.loads((self.scan / "final-verification/findings.json").read_text())
        final["findings"][0]["title"] = "Changed after accepted publication"
        self.save("final-verification/findings.json", final)
        with self.assertRaisesRegex(ValueError, "canonical final authority"):
            retire_controls(self.scan, self.context["run_id"])
        self.assertTrue((self.scan / "run-manifest.json").is_file())
        self.assertTrue((self.scan / "task-ledger.json").is_file())


if __name__ == "__main__":
    unittest.main()
