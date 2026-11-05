"""Consumer-visible Advantage report behavior using disposable authored evidence.

These fixtures render admitted-record shapes; they do not investigate or execute
source. CLI admission/publication coverage lives in test_advantage_integration.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from urllib.parse import unquote, urlsplit

import test_advantage_pipeline as fixtures

core = fixtures.core
pipeline = fixtures.pipeline
put = fixtures.put


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def markdown_links(markdown):
    """Generated navigation destinations, not inline code or example contents."""
    prose = []
    fence = None
    for line in markdown.splitlines():
        match = re.match(r"^\s*(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None:
            prose.append(line)
    return re.findall(r"(?<!!)\[[^\]\n]*\]\(([^)\n]+)\)", "\n".join(prose))


class AdvantageReportingTests(unittest.TestCase):
    def setUp(self):
        # Composition avoids rediscovering the entire pipeline suite through an
        # inherited TestCase or an imported TestCase alias.
        self.fixture = fixtures.AdvantagePipelineTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.context = self.fixture.context
        self.base = self.fixture.base
        self.finding = self.fixture.report_fixture(current=True)
        self.final = core.load(self.base / "final-verification/findings.json")
        self.plan = self.fixture.plan
        self.investigation = core.load(self.base / "investigation/results.json")

    def save(self):
        # These are authored presentation fixtures. Bind every edited dossier
        # before publishing the synthetic accepted checkpoint.
        assignments = []
        for finding in self.final["findings"]:
            path = self.base / finding["independent_verification_ref"]
            review = core.load(path)
            fixtures.review_dossier(finding, review)
            assignment = {"finding_id": finding["id"], "candidate_sha256": pipeline.dossier_hash(finding),
                          "actor": review["actor"], "selector": review["model"], "fresh_context": True,
                          "result_ref": finding["independent_verification_ref"]}
            review["assignment_sha256"] = core.digest(assignment)
            assignments.append(assignment)
            put(self.base / f"final-verification/packets/{finding['id']}.json", assignment)
            put(path, review)
            receipts = self.final["reviews"]
            receipts[:] = [row for row in receipts if row["finding_id"] != finding["id"]]
            receipts.append({"finding_id": finding["id"], "artifact_ref": finding["independent_verification_ref"],
                             "sha256": core.sha256_file(path), "status": review["status"]})
        put(self.base / "final-verification/assignments.json", core.envelope(self.context, assignments=assignments))
        put(self.base / "planning/plan.json", self.plan)
        put(self.base / "final-verification/findings.json", self.final)
        put(self.base / "investigation/results.json", self.investigation)

    def render(self):
        self.save()
        report = pipeline.report_projection(self.context)
        return report, pipeline.report_markdown(report, self.context)

    def add_finding(self, identity, classification, summary):
        finding = copy.deepcopy(self.finding)
        finding.update(id=identity, title=summary, attack_summary=summary,
                       independent_verification_ref=f"final-verification/results/{identity}.json")
        link = {**copy.deepcopy(self.final["links"][0]), "finding_id": identity,
                "classification": classification}
        self.final["findings"].append(finding)
        self.final["links"].append(link)
        review = core.load(self.base / self.finding["independent_verification_ref"])
        review["finding_id"] = identity
        put(self.base / finding["independent_verification_ref"], review)
        return finding, link

    def add_route(self, number, *, priority=50, outcome="locally_unresolved", pass_id="PASS-001"):
        objective = copy.deepcopy(self.plan["objectives"][0])
        objective.update(id=f"OBJ-ROUTE-{number:03d}", local_key=f"route-{number}",
                         desired_effect=f"Reach protected consumer route {number:03d}.")
        question = copy.deepcopy(self.plan["questions"][0])
        question.update(id=f"Q-ROUTE-{number:03d}", local_key=f"route-{number}",
                        objective_id=objective["id"], route=f"producer to consumer {number:03d}")
        assignment = copy.deepcopy(self.plan["assignments"][0])
        assignment.update(task_id=f"TASK-ROUTE-{number:03d}", pass_id=pass_id,
                          question_ids=[question["id"]], priority=priority)
        progress = fixtures.resolution(outcome, "app.py:11-15")
        progress.update(established_facts=[f"Inspected producer accepts controlled token {number:03d}."],
                        missing_fact=f"Consumer authorization for token {number:03d} is unproved.",
                        next_action=f"Inspect the authorized consumer for token {number:03d}.")
        row = {"task_id": assignment["task_id"], "pass_id": pass_id,
               "question_id": question["id"], "objective_id": objective["id"], "resolution": progress}
        relative = f"investigation/passes/{pass_id}/results/{assignment['task_id']}.json"
        put(self.base / relative, core.envelope(self.context, question_outcomes=[row]))
        self.investigation["results"].append({"task_id": assignment["task_id"], "artifact_ref": relative,
                                              "sha256": core.sha256_file(self.base / relative)})
        self.investigation["question_outcomes"].append(row)
        self.plan["objectives"].append(objective)
        self.plan["questions"].append(question)
        self.plan["assignments"].append(assignment)
        return row, objective, question, assignment, relative

    def test_typed_baseline_support_survives_publication_and_strict_bundle_read(self):
        from report_bundle import read_publication

        baseline = copy.deepcopy(self.finding)
        baseline["id"] = "F-100"
        baseline_root = Path(self.context["baseline"]["root"])
        put(baseline_root / "final-verification/findings.json", {"findings": [baseline]})
        inherited = {"execution_id": self.context["baseline"]["execution_id"],
                     "artifact_ref": "final-verification/findings.json#F-100"}
        self.final["findings"][0]["source_refs"].append(
            {"kind": "sast", "source_id": "F-100", "artifact_ref": inherited})
        self.final["findings"][0]["contributors"].append({
            "execution_id": self.context["baseline"]["execution_id"],
            "actor": "vulnops-synthesis", "selector": "fixture/historical:high",
            "artifact_ref": "synthesis/findings.json"})
        self.final["links"][0]["baseline_ids"] = ["F-100"]
        report, markdown = self.render()
        before = snapshot(self.base / "final-verification")
        baseline_before = snapshot(baseline_root)
        pipeline.schema(report, "report", self.context)
        report["publication"]["markdown_sha256"] = hashlib.sha256(markdown.encode()).hexdigest()
        target = self.base / "report/security-report.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(markdown, encoding="utf-8")
        pipeline.immutable(self.context, "report/security-report.json", report)
        bundle = read_publication(self.base, expected_kind="advantage", validate_evidence=True)
        self.assertEqual(bundle["final"]["findings"], self.final["findings"])
        self.assertEqual(bundle["report"]["findings"][0]["source_refs"][-1]["artifact_ref"], inherited)
        self.assertNotIn("final-verification/findings.json", report["publication"]["producer_routes"])
        self.assertEqual(snapshot(self.base / "final-verification"), before)
        self.assertEqual(snapshot(baseline_root), baseline_before)

    def test_large_report_publication_and_admission_preserve_complete_evidence(self):
        from test_dossiers import review_dossier

        # Grow schema-bounded records, not individual fields or ancillary views.
        # Each authoritative cohort remains below the non-report 16 MiB bound;
        # their combined report crosses both the old 2 MiB and hygiene 16 MiB caps.
        for number in range(2, 33):
            self.add_finding(f"F-{number:03d}", "new_chain",
                             f"Source-established synthetic route {number:03d}.")
        for finding in self.final["findings"]:
            finding["impact_limits"] = [
                f"{finding['id']} limitation {number:02d}: " +
                ("Synthetic source-only assessment; no target execution or deployment claim. " * 100)[:7000]
                for number in range(40)
            ]
            review_path = self.base / finding["independent_verification_ref"]
            review = core.load(review_path)
            review_dossier(finding, review)
            put(review_path, review)
        historical = copy.deepcopy(self.final["findings"])
        baseline_root = Path(self.context["baseline"]["root"])
        put(baseline_root / "final-verification/findings.json", {"findings": historical})
        self.save()
        core.atomic_json(self.base / "final-verification/findings.json", self.final)
        for path in (self.base / "final-verification/findings.json",
                     baseline_root / "final-verification/findings.json"):
            self.assertLess(path.stat().st_size, 16 * 1024 * 1024)
        final_before = snapshot(self.base / "final-verification")
        baseline_before = snapshot(baseline_root)
        source_before = snapshot(Path(self.context["source_root"]))

        report = pipeline.report_projection(self.context)
        self.assertGreater(len(json.dumps(report).encode("utf-8")), 16 * 1024 * 1024)
        pipeline.schema(report, "report", self.context)
        markdown = pipeline.report_markdown(report, self.context)
        self.assertGreater(len(markdown.encode("utf-8")), 2 * 1024 * 1024)
        report["publication"]["markdown_sha256"] = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        markdown_path = self.base / "report/security-report.md"
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        with markdown_path.open("x", encoding="utf-8") as handle:
            handle.write(markdown)
        json_path = pipeline.immutable(self.context, "report/security-report.json", report)

        self.assertEqual(core.load(json_path), report)
        self.assertEqual(report["findings"], self.final["findings"])
        self.assertEqual([row["finding"] for row in report["historical_findings"]], historical)
        self.assertEqual(report["counts"]["assessed_confirmed"], 32)
        self.assertEqual(report["counts"]["historical"], 32)
        self.assertEqual(report["ancillary"]["omitted"], 0)
        self.assertEqual(core.resolve_reference(self.context, "report/security-report.md"), markdown_path.resolve())
        self.assertEqual(markdown_path.read_text(encoding="utf-8"), markdown)
        for finding in self.final["findings"]:
            limits = "\n".join("- " + limitation for limitation in finding["impact_limits"])
            self.assertEqual(markdown.count(limits), 1)
        pipeline.validate_phase(self.base, "report", self.context)

        # Unlimited report size does not bypass content hygiene or overwrite a
        # valid publication with unsafe bytes.
        published = json_path.read_bytes()
        unsafe = copy.deepcopy(report)
        unsafe["findings"][-1]["impact_limits"][-1] += " ghp_" + "x" * 24
        with self.assertRaisesRegex(ValueError, "secret"):
            pipeline.schema(unsafe, "report", self.context)
        with self.assertRaisesRegex(ValueError, "secret"):
            core.atomic_json(json_path, unsafe)
        self.assertEqual(json_path.read_bytes(), published)
        try:
            markdown_path.write_text(markdown + "\nghp_" + "x" * 24, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "secret"):
                core.resolve_reference(self.context, "report/security-report.md")
        finally:
            markdown_path.write_text(markdown, encoding="utf-8")
        self.assertEqual(snapshot(self.base / "final-verification"), final_before)
        self.assertEqual(snapshot(baseline_root), baseline_before)
        self.assertEqual(snapshot(Path(self.context["source_root"])), source_before)

    def test_classifications_select_added_value_without_changing_authoritative_cohorts(self):
        root, _ = self.add_finding("F-002", "new_root", "Independent export exposes tenant secrets.")
        expansion, _ = self.add_finding("F-003", "impact_expansion", "Queue access now reaches another resource class.")
        correction, _ = self.add_finding("F-004", "baseline_correction", "The worker denies persistence previously attributed to this path.")
        repeated, _ = self.add_finding("F-005", "baseline_revalidation", "Repeated inherited disclosure has no changed impact.")
        report, markdown = self.render()
        before = copy.deepcopy(report)
        self.assertEqual(pipeline.report_markdown(report, self.context), markdown)
        self.assertEqual(report, before)
        self.assertEqual(report["counts"]["assessed_confirmed"], 5)
        self.assertEqual(len(report["findings"]), 5)
        for finding in (self.finding, root, expansion, correction):
            self.assertIn(finding["attack_summary"], markdown)
        self.assertNotIn(repeated["attack_summary"], markdown)
        from advantage_reporting import presentation_input
        view = presentation_input(report, self.context)
        self.assertEqual({row["finding"]["id"] for row in view["added"]}, {"F-001", "F-002", "F-003"})
        self.assertEqual({row["finding"]["id"] for row in view["corrections"]}, {"F-004"})
        self.assertEqual(report, before)
        for revalidation in (False, True):
            with self.subTest(revalidation=revalidation):
                if revalidation:
                    self.final["findings"] = [self.finding]
                    self.final["links"] = [{"finding_id": "F-001", "classification": "baseline_revalidation",
                                            "baseline_ids": [], "result_refs": [pipeline.result_path(self.fixture.packet)],
                                            "source_view": "base"}]
                else:
                    self.final["findings"] = []
                    self.final["links"] = []
                report, markdown = self.render()
                self.assertEqual(report["counts"]["assessed_confirmed"], int(revalidation))
                self.assertNotIn(self.finding["attack_summary"], markdown)
                self.assertRegex(markdown.lower(), r"no (?:additional|new) attacker outcome.{0,30}confirmed")
                self.assertRegex(markdown.lower(), r"(?:not a clean assessment|not security assurance|does not establish.{0,50}safe)")
                if not revalidation:
                    self.assertNotRegex(markdown.lower(), r"(?:all evidence|evidence is) independently (?:reviewed|verified)")

    def test_baseline_environment_dossiers_remain_complete_without_added_counts(self):
        baseline = copy.deepcopy(self.finding)
        environment = copy.deepcopy(self.finding)
        environment.update(id="F-002", status="needs_environment", verdict="needs_environment",
                           attack_summary="Inherited environment-dependent outcome remains unconfirmed.")
        put(Path(self.context["baseline"]["root"]) / "final-verification/findings.json",
            {"findings": [baseline, environment]})
        report, markdown = self.render()
        self.assertEqual([row["finding"] for row in report["historical_findings"]], [baseline, environment])
        self.assertEqual(report["cohort_counts"]["historical"]["total"], 2)
        self.assertEqual(report["cohort_counts"]["historical"]["confirmed"], 1)
        self.assertEqual(report["cohort_counts"]["historical"]["needs_environment"], 1)
        self.assertEqual(report["counts"]["assessed_confirmed"], 1)
        self.assertEqual(report["counts"]["new_chains"], 1)
        self.assertNotIn(environment["attack_summary"], markdown)
        pipeline.schema(report, "report", self.context)

    def test_historical_literal_examples_survive_report_validation_unchanged(self):
        historical = []
        for number, literal in enumerate((" \t\n", "\r\n \t"), 27):
            finding = copy.deepcopy(self.finding)
            finding["id"] = f"F-{number:03d}"
            finding["technical_examples"][0]["content"] = literal
            historical.append(finding)
        baseline_root = Path(self.context["baseline"]["root"])
        put(baseline_root / "final-verification/findings.json", {"findings": historical})
        before = snapshot(baseline_root)
        report, _ = self.render()
        pipeline.schema(report, "report", self.context)
        self.assertEqual([row["finding"] for row in report["historical_findings"]], historical)
        self.assertEqual(report["findings"], self.final["findings"])
        self.assertEqual(report["counts"]["assessed_confirmed"], 1)
        self.assertEqual(report["counts"]["historical"], 2)
        self.assertEqual(snapshot(baseline_root), before)

    def test_current_literal_examples_and_substitution_operands_are_not_prose(self):
        example = self.final["findings"][0]["technical_examples"][0]
        example.update(kind="request", content=" \t\r\n", substitutions=[
            {"original": "\t", "replacement": " ", "reason": "Represent a tab as one space."}])
        report, markdown = self.render()
        before = copy.deepcopy(report)
        pipeline.schema(self.final, "verification", self.context)
        pipeline.schema(report, "report", self.context)
        self.assertEqual(report, before)
        self.assertIn(example["content"], markdown)

    def test_literal_exception_does_not_relax_prose_or_hygiene(self):
        report, _ = self.render()
        for field in ("title", "attack_summary", "impact"):
            with self.subTest(field=field):
                invalid = copy.deepcopy(report)
                invalid["findings"][0][field] = " \t\n"
                with self.assertRaisesRegex(ValueError, "whitespace-only"):
                    pipeline.schema(invalid, "report", self.context)
        for field in ("reason", "original", "replacement"):
            with self.subTest(substitution=field):
                invalid = copy.deepcopy(report)
                substitution = {"original": "a", "replacement": "b", "reason": "Replace the fixture operand."}
                substitution[field] = " \t\n" if field == "reason" else "ghp_" + "x" * 24
                invalid["findings"][0]["technical_examples"][0]["substitutions"] = [substitution]
                with self.assertRaisesRegex(ValueError, "whitespace-only|secret"):
                    pipeline.schema(invalid, "report", self.context)
        invalid = copy.deepcopy(report)
        invalid["findings"][0]["technical_examples"][0]["content"] = "ghp_" + "x" * 24
        with self.assertRaisesRegex(ValueError, "secret"):
            pipeline.schema(invalid, "report", self.context)

    def test_historical_literal_fields_keep_bounds_and_do_not_exempt_arbitrary_content(self):
        historical = copy.deepcopy(self.finding)
        put(Path(self.context["baseline"]["root"]) / "final-verification/findings.json",
            {"findings": [historical]})
        report, _ = self.render()
        invalid = copy.deepcopy(report)
        invalid["historical_findings"][0]["finding"]["technical_examples"][0]["content"] = " " * 8001
        with self.assertRaisesRegex(ValueError, "exceeds its bound"):
            pipeline.schema(invalid, "report", self.context)
        invalid = copy.deepcopy(report)
        invalid["historical_findings"][0]["finding"]["content"] = " \t\n"
        with self.assertRaisesRegex(ValueError, "whitespace-only"):
            pipeline.schema(invalid, "report", self.context)

    def test_unrelated_historical_backlog_does_not_expand_the_human_report(self):
        _, before = self.render()
        historical = []
        for number in range(75):
            finding = copy.deepcopy(self.finding)
            finding.update(id=f"F-{number + 100:03d}", title=f"Unrelated inherited disclosure {number}",
                           attack_summary="Historical dossier material. " * 150)
            historical.append(finding)
        put(Path(self.context["baseline"]["root"]) / "final-verification/findings.json", {"findings": historical})
        report, after = self.render()
        self.assertEqual(len(report["historical_findings"]), 75)
        self.assertEqual(after, before)

    def test_matching_titles_do_not_invent_baseline_dependencies(self):
        historical = copy.deepcopy(self.finding)
        historical["attack_summary"] = "Historical lookup has a separate authority boundary."
        put(Path(self.context["baseline"]["root"]) / "final-verification/findings.json", {"findings": [historical]})
        report, markdown = self.render()
        self.assertEqual(report["links"][0]["baseline_ids"], [])
        self.assertNotIn(historical["attack_summary"], markdown)
        self.assertRegex(markdown.lower(), r"(?:baseline|prior).{0,140}(?:not established|unavailable|unknown|no explicit)")
        self.assertNotRegex(markdown.lower(), r"(?:never|not previously) (?:explored|investigated|covered)")


    def test_multi_repository_progression_examples_and_repair_remain_cohesive(self):
        finding = self.final["findings"][0]
        first = finding["affected_components"][0]
        first.update(repository="api", name="Tenant API producer")
        second = copy.deepcopy(first)
        second.update(id="component-2", repository="consumer", name="Operation queue reader")
        second["locations"] = [{"file": "consumer/queue.py", "line": 8, "scope": "consume",
                                "mechanism": "Consumer trusts producer authority without a tenant decision."}]
        finding["affected_components"].append(second)
        step = copy.deepcopy(finding["exploitation"]["steps"][0])
        step.update(id="step-2", component_ids=["component-2"], action="Pass the queued record identifier to the consumer.",
                    controlled_input="The same tenant-b identifier survives serialization.",
                    why_it_works="Consumer trusts the producer authority without rechecking tenant scope.",
                    expected_result="The consumer receives the cross-tenant operation.")
        finding["exploitation"]["steps"].append(step)
        finding["transitions"][0]["resolution"]["reason"] = "The same actor and tenant-b resource cross both repository boundaries."
        finding["transitions"][0]["obligations"]["conditions_compatible"]["reason"] = "Both services must share the operation queue and identifier namespace."
        finding["technical_examples"].append({"id": "request-example", "kind": "request",
            "content": '{"route":"/records/update","record_id":"tenant-b"}', "evidence_refs": ["app.py:13-15"],
            "substitutions": [], "execution_status": "not_executed", "observation_refs": []})
        self.save()
        before = snapshot(self.base.parent)
        report = pipeline.report_projection(self.context)
        original = copy.deepcopy(report)
        markdown = pipeline.report_markdown(report, self.context)
        self.assertEqual(report, original)
        self.assertEqual(snapshot(self.base.parent), before)
        for value in (finding["attacker"]["starting_access"], *finding["exploitation"]["setup"],
                      first["name"], second["name"], "consumer/queue.py", step["controlled_input"], step["why_it_works"],
                      finding["transitions"][0]["resolution"]["reason"],
                      finding["transitions"][0]["obligations"]["conditions_compatible"]["reason"],
                      first["service"]["limitation"], finding["impact"], *finding["impact_limits"],
                      *[example["content"] for example in finding["technical_examples"]]):
            self.assertIn(value, markdown)
        self.assertLess(markdown.index(finding["exploitation"]["steps"][0]["action"]), markdown.index(step["action"]))
        repair = finding["remediation"]["actions"][0]
        self.assertIn(repair["change"], markdown)
        for value in (repair["rationale"], finding["remediation"]["verification_checks"][0]["attack_expected"],
                      finding["remediation"]["verification_checks"][0]["legitimate_expected"]):
            self.assertIn(value, markdown)
        self.assertNotIn('"primitive_steps":', markdown)
        self.assertNotIn('"baseline_reconciliation":', markdown)

    def test_completed_bundle_keeps_full_dossier_and_bidirectional_step_repair_links(self):
        from advantage_reporting import _anchor
        from report_bundle import read_publication
        report, markdown = self.render()
        report["publication"]["markdown_sha256"] = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        put(self.base / "report/security-report.json", report)
        (self.base / "report/security-report.md").write_text(markdown)
        expected_assessment = copy.deepcopy(report["assessment"])
        before = snapshot(self.base / "final-verification")
        shutil.rmtree(Path(self.context["source_root"]))
        self.context["repositories"] = [{"path": "replacement"}]
        self.context["model_routing"]["agents"]["vulnops-advantage-verify-one"] = "fixture/new-reviewer:high"
        report = read_publication(self.base, validate_evidence=True)["report"]
        markdown = (self.base / "report/security-report.md").read_text()
        self.assertEqual(report["findings"], self.final["findings"])
        self.assertEqual(report["assessment"], expected_assessment)
        self.assertIn("does not revalidate later source", markdown)
        for step in self.finding["exploitation"]["steps"]:
            anchor = _anchor("step", report["run_id"], self.finding["id"], step["id"])
            self.assertIn(f'<a id="{anchor}"></a>', markdown)
            self.assertIn(step["why_it_works"], markdown)
            if any(step["id"] in action["breaks_steps"] for action in self.finding["remediation"]["actions"]):
                self.assertIn(f"](#{anchor})", markdown)
        for action in self.finding["remediation"]["actions"]:
            anchor = _anchor("fix", report["run_id"], self.finding["id"], action["id"])
            self.assertIn(f'<a id="{anchor}"></a>', markdown)
            self.assertIn(f"](#{anchor})", markdown)
        self.assertEqual(snapshot(self.base / "final-verification"), before)

    def test_mixed_evidence_and_derived_source_do_not_become_live_exploitation(self):
        self.context["mode"] = "diff"
        self.final["links"][0]["source_view"] = "derived"
        finding = self.final["findings"][0]
        observed = copy.deepcopy(finding["exploitation"]["steps"][0])
        observed.update(id="step-observed", action="Inspect the isolated queue observation.", evidence_status="observed_contained",
                        observed_result="The contained fixture recorded exactly one queue append.",
                        observation_refs=["reproduction/queue-observation.json"])
        finding["exploitation"]["steps"].append(observed)
        put(self.base / "reproduction/queue-observation.json", {"run_id": self.context["run_id"], "observed": "one append"})
        _, markdown = self.render()
        self.assertIn(observed["observed_result"], markdown)
        self.assertRegex(markdown.lower(), r"(?:source.established|source.only|source.verified)")
        self.assertIn("derived", markdown.lower())
        self.assertIn("not executed", markdown.lower())
        self.assertIn("proposed", markdown.lower())
        self.assertNotIn("dynamically exploited", markdown.lower())
        self.final["links"][0]["source_view"] = "base"
        _, base_markdown = self.render()
        self.assertNotEqual(base_markdown, markdown)
        self.assertIn("base", base_markdown.lower())

    def test_hostile_markdown_and_example_fences_never_create_active_destinations(self):
        finding = self.final["findings"][0]
        finding["attack_summary"] = "Untrusted [open](javascript:alert(1)) <img src=x onerror=alert(1)> and ![leak](https://evil.invalid/x)."
        example = 'literal request\n```\n[escape](https://evil.invalid/escape)\n~~~~\n{"record_id":"tenant-b"}'
        finding["technical_examples"][0]["content"] = example
        _, markdown = self.render()
        self.assertIn(example, markdown)
        self.assertNotIn("<img src=x", markdown)
        for destination in markdown_links(markdown):
            self.assertFalse(urlsplit(destination).scheme, destination)
            self.assertNotIn("evil.invalid", destination)
        self.assertIn("tenant-b", markdown)

    def test_priority_selection_uses_complete_terminal_results_not_ancillary_cap(self):
        for number in range(201):
            row, *_ = self.add_route(number, outcome="execution_failed")
            row["resolution"]["established_facts"] = []
        eligible = []
        for number in range(201, 208):
            eligible.append(self.add_route(number, priority=number - 200)[0])
        report, markdown = self.render()
        self.assertEqual(len(report["ancillary"]["question_outcomes"]), 200)
        self.assertGreater(report["ancillary"]["omitted"], 0)
        from advantage_reporting import presentation_input
        view = presentation_input(report, self.context)
        self.assertEqual(view["eligible_count"], 7)
        self.assertEqual(len(view["routes"]), 5)
        selected = list(reversed(eligible[2:]))
        for row in selected:
            for field in ("established_facts", "missing_fact", "next_action"):
                value = row["resolution"][field]
                self.assertIn(value[0] if isinstance(value, list) else value, markdown)
        positions = [markdown.index(row["resolution"]["missing_fact"]) for row in selected]
        self.assertEqual(positions, sorted(positions))
        for row in eligible[:2]:
            self.assertNotIn(row["resolution"]["missing_fact"], markdown)
        self.assertRegex(markdown.lower(), r"(?:selected\s+5\s+of\s+7|5\s+of\s+7.{0,30}selected)")

    def test_terminal_continuations_supersede_only_the_exact_owned_question(self):
        stale, _, _, assignment, _ = self.add_route(1, priority=99)
        peer, *_ = self.add_route(2, priority=98)
        successor = copy.deepcopy(stale)
        successor["task_id"] = "TASK-CONTINUED"
        successor["resolution"] = fixtures.resolution("established", "app.py:11-15")
        self.investigation["question_outcomes"].append(successor)
        continuation = copy.deepcopy(assignment)
        continuation["task_id"] = successor["task_id"]
        put(self.base / "investigation/waves/001.json", core.envelope(self.context, wave=1, tasks=[{
            "assignment": continuation, "continuation": {"predecessor_task_id": stale["task_id"]}}]))
        from advantage_reporting import presentation_input
        for same_prose in (False, True):
            with self.subTest(same_prose=same_prose):
                if same_prose:
                    peer["resolution"] = copy.deepcopy(stale["resolution"])
                report, markdown = self.render()
                self.assertEqual(presentation_input(report, self.context)["eligible_count"], 1)
                self.assertIn(peer["resolution"]["missing_fact"], markdown)
                if not same_prose:
                    self.assertNotIn(stale["resolution"]["missing_fact"], markdown)
                self.investigation["question_outcomes"].remove(successor)
                (self.base / "investigation/waves/001.json").unlink()
                report, markdown = self.render()
                self.assertEqual(presentation_input(report, self.context)["eligible_count"], 2)
                self.assertEqual(markdown.count(stale["resolution"]["missing_fact"]), 2 if same_prose else 1)
                self.investigation["question_outcomes"].append(successor)
                put(self.base / "investigation/waves/001.json", core.envelope(self.context, wave=1, tasks=[{
                    "assignment": continuation, "continuation": {"predecessor_task_id": stale["task_id"]}}]))

    def test_unfinished_continuation_uses_its_own_priority_and_latest_proof_gap(self):
        stale, _, _, assignment, _ = self.add_route(1, priority=10)
        peer, *_ = self.add_route(2, priority=90)
        successor = copy.deepcopy(stale)
        successor["task_id"] = "TASK-CONTINUED"
        successor["resolution"].update(
            missing_fact="The continuation still lacks consumer-side tenant authority.",
            next_action="Inspect the consumer tenant predicate identified by the continuation.")
        relative = "investigation/passes/PASS-001/results/TASK-CONTINUED.json"
        put(self.base / relative, core.envelope(self.context, question_outcomes=[successor]))
        self.investigation["results"].append({"task_id": successor["task_id"], "artifact_ref": relative,
                                              "sha256": core.sha256_file(self.base / relative)})
        self.investigation["question_outcomes"].append(successor)
        continuation = {**assignment, "task_id": successor["task_id"], "priority": 99}
        put(self.base / "investigation/waves/001.json", core.envelope(self.context, wave=1, tasks=[{
            "assignment": continuation, "continuation": {"predecessor_task_id": stale["task_id"]}}]))
        report, markdown = self.render()
        from advantage_reporting import presentation_input
        self.assertEqual(presentation_input(report, self.context)["eligible_count"], 2)
        self.assertNotIn(stale["resolution"]["missing_fact"], markdown)
        self.assertIn(successor["resolution"]["next_action"], markdown)
        self.assertLess(markdown.index(successor["resolution"]["missing_fact"]),
                        markdown.index(peer["resolution"]["missing_fact"]))


    def test_missing_progress_or_proof_does_not_promote_worker_failure(self):
        failed, *_ = self.add_route(1, outcome="execution_failed")
        failed["resolution"]["established_facts"] = ["Unadmitted diagnostics suggest remote administrator access."]
        incomplete, *_ = self.add_route(2)
        incomplete["resolution"]["missing_fact"] = ""
        valid, *_ = self.add_route(3)
        report, markdown = self.render()
        from advantage_reporting import presentation_input
        self.assertEqual(presentation_input(report, self.context)["eligible_count"], 1)
        self.assertNotIn(failed["resolution"]["established_facts"][0], markdown)
        self.assertNotIn(incomplete["resolution"]["established_facts"][0], markdown)
        self.assertIn(valid["resolution"]["missing_fact"], markdown)

    def test_contradicted_claim_retains_rationale_assessment_and_healthy_route(self):
        contradicted, objective, _, _, relative = self.add_route(1, priority=99)
        survivor, *_ = self.add_route(2, priority=98)
        candidate = copy.deepcopy(self.finding)
        candidate.update(id="F-REJECTED", objective_ids=[objective["id"]])
        link = {"finding_id": candidate["id"], "classification": "new_chain", "baseline_ids": [],
                "result_refs": [relative], "source_view": "base"}
        put(self.base / "synthesis/findings.json", core.envelope(self.context, findings=[candidate], links=[link]))
        review_ref = "final-verification/results/F-REJECTED.json"
        review = {"finding_id": candidate["id"], "status": "rejected", "objective_results": [{
            "objective_id": objective["id"], "satisfied": False,
            "reason": "The inspected consumer rejects the claimed authority transition."}],
            "joint_conditions": {"outcome": "contradicted"}}
        put(self.base / review_ref, core.envelope(self.context, **review))
        self.final["reviews"].append({"finding_id": candidate["id"], "status": "rejected", "artifact_ref": review_ref,
                                       "sha256": core.sha256_file(self.base / review_ref)})
        report, markdown = self.render()
        self.assertIn(contradicted["resolution"]["missing_fact"], markdown)
        self.assertIn(survivor["resolution"]["missing_fact"], markdown)
        self.assertIn(candidate["attack_summary"], markdown)
        self.assertIn(review["objective_results"][0]["reason"], markdown)
        self.assertIn("Contradicted route", markdown)
        self.assertIn("../" + review_ref, markdown)
        self.assertEqual(report["counts"]["assessed_confirmed"], 1)
        self.assertEqual(report["objective_assessments"], self.final["objective_assessments"])

    def test_established_investigation_survives_inconclusive_disagreeing_and_exhausted_review(self):
        _, objective, _, _, relative = self.add_route(1, outcome="established")
        candidate = copy.deepcopy(self.finding)
        candidate.update(id="F-POSSIBLE", objective_ids=[objective["id"]],
                         attack_summary="Controlled producer input may reach a privileged consumer.")
        link = {"finding_id": candidate["id"], "classification": "new_chain", "baseline_ids": [],
                "result_refs": [relative], "source_view": "base"}
        put(self.base / "synthesis/findings.json", core.envelope(self.context, findings=[candidate], links=[link]))
        self.final.update(findings=[], links=[], reviews=[], unconfirmed=[])
        for status in ("evidence_limited", "rejected", "unreviewed"):
            with self.subTest(status=status):
                self.final["reviews"] = []
                review_ref = "final-verification/results/F-POSSIBLE.json"
                reason = "Consumer authority remains unproved; producer-side control is supported."
                if status != "unreviewed":
                    review = {"finding_id": candidate["id"], "status": status, "closure_reason": reason,
                              "primitive_results": [{"primitive_id": "consumer", "status": "rejected",
                                  "reason": reason, "evidence_refs": ["app.py:11-15"]}],
                              "joint_conditions": {"outcome": "locally_unresolved",
                                  "missing_fact": "Consumer-side tenant authority is not established.",
                                  "next_action": "Inspect the authorized consumer tenant predicate."}}
                    put(self.base / review_ref, core.envelope(self.context, **review))
                    self.final["reviews"] = [{"finding_id": candidate["id"], "status": status,
                        "artifact_ref": review_ref, "sha256": core.sha256_file(self.base / review_ref)}]
                else:
                    reason = "Independent verifier exhausted its attempts without an admitted review."
                self.final["unconfirmed"] = [{"finding_id": candidate["id"],
                    "outcome": "execution_failed" if status == "unreviewed" else "locally_unresolved",
                    "reason": reason, "assignment_ref": "final-verification/assignments.json"}]
                report, markdown = self.render()
                self.assertIn(candidate["attack_summary"], markdown)
                self.assertIn(reason, markdown)
                self.assertNotIn("Contradicted route", markdown)
                self.assertEqual(report["counts"]["assessed_confirmed"], 0)
                self.assertEqual(report["findings"], [])
                self.assertEqual(report["unconfirmed"], self.final["unconfirmed"])
                if status != "unreviewed":
                    self.assertIn(review["joint_conditions"]["missing_fact"], markdown)
                    self.assertIn(review["joint_conditions"]["next_action"], markdown)

    def test_optional_absence_and_corruption_preserve_exact_accepted_authority(self):
        from advantage_reporting import presentation_input
        self.add_finding("F-002", "new_root", "Independent source review establishes bounded export access.")
        self.save()
        baseline=pipeline.report_projection(self.context)
        source=Path(self.context["source_root"])
        for path in source.rglob("*.py"):
            path.write_text("changed after independent review\n")
        authority={path:path.read_bytes() for path in (self.base/"final-verification").rglob("*.json")}
        for ref in ("planning/plan.json","investigation/results.json","baseline/catalog.json"):
            path=self.base/ref
            saved=path.read_bytes()
            path.unlink()
            unavailable=[]
            for content in (None,"{broken","[]"):
                with self.subTest(reference=ref,content=content):
                    if content is not None:path.write_text(content)
                    report=pipeline.report_projection(self.context)
                    markdown=pipeline.report_markdown(report,self.context)
                    for key in ("findings","links","historical_findings","cohort_counts","assessment","objective_assessments"):
                        self.assertEqual(report[key],baseline[key])
                    for key in ("assessed_confirmed","new_roots","new_chains","impact_expansions","baseline_corrections"):
                        self.assertEqual(report["counts"][key],baseline["counts"][key])
                    self.assertTrue(any(ref in item for item in report["coverage"]["limitations"]))
                    for finding in self.final["findings"]:
                        self.assertIn(finding["attack_summary"],markdown)
                    if ref!="baseline/catalog.json":
                        self.assertIsNone(presentation_input(report,self.context)["eligible_count"])
                    if ref=="investigation/results.json":
                        self.assertIsNone(report["ancillary"]["total"])
                        self.assertIsNone(report["counts"]["unresolved_questions"])
                    if ref=="baseline/catalog.json":
                        availability=report["baseline_availability"]
                        self.assertFalse(availability["counts_complete"])
                        self.assertEqual(availability["unavailable_cohorts"],[ref])
                        self.assertEqual([item["artifact_ref"] for item in availability["limitations"]],[ref])
                        self.assertTrue(all(item["reason"] for item in availability["limitations"]))
                    pipeline.schema(report,"report",self.context)
                    unavailable.append(report)
            self.assertEqual(unavailable[0],unavailable[1])
            self.assertEqual(unavailable[1],unavailable[2])
            path.write_bytes(saved)
        self.assertEqual({path:path.read_bytes() for path in authority},authority)

    def test_optional_integrity_is_not_treated_as_availability(self):
        self.save()
        path=self.base/"planning/plan.json"
        saved=path.read_bytes()
        secret="synthetic-credential-"+"x"*24
        for content in (json.dumps({"run_id":"foreign","objectives":"malformed"}),
                        '{"broken":"Authorization: Bearer '+secret+'"',
                        json.dumps({"stdout":"forbidden output"})):
            with self.subTest(content_kind=content[:15]):
                path.write_text(content)
                with self.assertRaises(ValueError) as error:
                    pipeline.report_projection(self.context)
                self.assertNotIn(secret,str(error.exception))
        path.unlink()
        outside=self.base.parent/"outside.json"
        put(outside,{})
        path.symlink_to(outside)
        with self.assertRaises(ValueError):
            pipeline.report_projection(self.context)
        path.unlink()
        path.write_bytes(saved)

    def test_missing_or_malformed_required_authority_never_becomes_optional(self):
        self.save()
        expected = pipeline.report_projection(self.context)
        self.assertEqual(expected["findings"], self.final["findings"])
        for ref in ("final-verification/findings.json", self.finding["independent_verification_ref"]):
            path = self.base / ref
            saved = path.read_bytes()
            for content, reason in ((None, "missing or unsafe JSON artifact"), ("{broken", "artifact is not readable bounded JSON")):
                with self.subTest(reference=ref, reason=reason):
                    if content is None:
                        path.unlink()
                    else:
                        path.write_text(content)
                    try:
                        with self.assertRaises(ValueError) as error:
                            pipeline.report_projection(self.context)
                        self.assertIn(reason, str(error.exception))
                        if content is None:
                            self.assertIn(ref, str(error.exception))
                    finally:
                        path.write_bytes(saved)
            self.assertEqual(pipeline.report_projection(self.context), expected)


    def test_execution_qualified_navigation_survives_linked_and_current_only_relocation(self):
        historical = copy.deepcopy(self.finding)
        historical["attack_summary"] = "Historical context must not become a second attack dossier."
        baseline = Path(self.context["baseline"]["root"])
        put(baseline / "final-verification/findings.json", {"run_id": self.context["baseline"]["execution_id"], "findings": [historical]})
        self.final["links"][0]["baseline_ids"] = [self.finding["id"]]
        report, markdown = self.render()
        put(self.base / "report/security-report.json", report)
        (self.base / "report/security-report.md").write_text(markdown)
        self.assertIn(self.context["baseline"]["execution_id"], markdown)
        self.assertIn(self.context["run_id"], markdown)
        self.assertNotIn(historical["attack_summary"], markdown)
        destinations = markdown_links(markdown)
        self.assertTrue(any("security-report.json" in destination for destination in destinations))
        self.assertTrue(any("audit/" in unquote(destination) for destination in destinations))
        self.assertFalse(any(".json#" in destination for destination in destinations))
        self.assertNotIn(str(self.base.parent), markdown)
        with tempfile.TemporaryDirectory() as directory:
            relocated = Path(directory) / "delivered"
            shutil.copytree(self.base.parent, relocated)
            for destination in destinations:
                parsed = urlsplit(destination)
                if parsed.path:
                    self.assertTrue((relocated / "advantage/report" / unquote(parsed.path)).is_file(), destination)
            shutil.rmtree(relocated / "audit")
            current_only = copy.deepcopy(self.context)
            current_only["scan_base"] = str(relocated / "advantage")
            current_only["baseline"]["root"] = str(relocated / "audit")
            text = pipeline.report_markdown(report, current_only)
            self.assertIn(self.context["baseline"]["execution_id"], text)
            self.assertFalse(any("audit/" in unquote(destination) for destination in markdown_links(text)))
            for destination in markdown_links(text):
                parsed = urlsplit(destination)
                if parsed.path:
                    self.assertTrue((relocated / "advantage/report" / unquote(parsed.path)).is_file(), destination)

    def test_unsafe_or_foreign_evidence_never_becomes_navigation(self):
        from advantage_reporting import Navigation
        navigation = Navigation(self.context, pipeline.audit_renderer())
        outside = self.base.parent / "private.json"
        put(outside, {"private": "not delivered"})
        (self.base / "final-verification/escaped.json").symlink_to(outside)
        unsafe = [
            "../private.json", str(outside),
            "final-verification/escaped.json",
            {"execution_id": "unrelated-execution", "artifact_ref": "final-verification/findings.json"},
            {"execution_id": self.context["baseline"]["execution_id"], "artifact_ref": "../private.json"},
        ]
        for reference in unsafe:
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                navigation.reference(reference)
        self.assertEqual(markdown_links(navigation.reference("javascript:alert(1)")), [])


    def test_actions_only_selected_assessment_is_not_a_discovery_or_placeholder(self):
        previous = self.base.parent / "previous"
        self.save()
        previous_report = pipeline.report_projection(self.context)
        previous_report["run_id"] = "previous-advantage"
        for scope in previous_report["assessment"]["scopes"]:
            scope["run_id"] = "previous-advantage"
        put(previous / "report/security-report.json", previous_report)
        (previous / "report/security-report.md").write_text("# Completed selected assessment\n")
        self.context.update(mode="actions", action_source={"execution_id": "previous-advantage",
                                                          "root": str(previous)})
        put(previous / "final-verification/findings.json", {"run_id": "previous-advantage",
                                                           "findings": [self.finding]})
        self.context["options"] = {"verify_fix": ["F-001"], "assess_patch_risk": False,
                                   "hardening": False, "track_findings": []}
        rationale = "The derived guard rejects the original route, but the separate queue consumer is unavailable."
        gap = "Consumer-side ownership after queue delivery remains unproved."
        actions = core.envelope(self.context, verify_fix={"status": "completed", "records": [{
            "finding_id": "F-001", "finding_execution_id": "previous-advantage",
            "outcome": "inconclusive", "assessment_status": "locally_unresolved", "rationale": rationale,
            "limitations": [gap], "citations": [], "checks": []}]},
            patch_risk={"status": "not_selected", "records": []}, hardening={"status": "not_selected", "records": []},
            tracking={"status": "not_selected", "records": []}, diff_review={"status": "not_selected", "records": []})
        put(self.base / "handoff/actions.json", actions)
        report, markdown = self.render()
        self.assertEqual(report["findings"], [])
        self.assertIn(rationale, markdown)
        self.assertIn(gap, markdown)
        self.assertIn("inconclusive", markdown.lower())
        self.assertNotIn(self.finding["attack_summary"], markdown)
        self.assertRegex(markdown.lower(), r"(?:no discovery|no investigation|does not investigate|did not investigate)")
        self.assertNotIn("investigation/results.json", markdown)
        self.assertNotRegex(markdown.lower(), r"(?:all evidence|evidence is) independently (?:reviewed|verified)")
        self.assertNotIn("not_selected", markdown)
        self.assertNotIn("not selected", markdown.lower())


if __name__ == "__main__":
    unittest.main()
