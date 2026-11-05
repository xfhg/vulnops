"""Linked admission against a complete real deterministic audit, not target execution."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_redteam_workflow import ROOT, exercise_pipeline
from advantage_native_fixture import native_call, native_controller


def file_snapshot(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.rglob("*") if path.is_file()
    }


def exercise_continuity_cli(context_path, *, negative_control=False, repeat_validation=False):
    """Exercise deep passes, local failures and deterministic publication through CLIs.

    Findings/reviews are authored synthetic fixtures, not model or attack output.
    The caller supplies a disposable deep/full context and secondary.py fixture.
    """
    import advantage_contract as core
    import advantage_pipeline as pipeline
    from objective_contract import stable_id
    from test_advantage_pipeline import (author, authored_plan, authored_result, candidate,
                                        authored_chain, authored_review, put)
    from test_dossiers import sample_finding, add_dossier, review_dossier
    from advantage_native_fixture import native_call, native_worker, NativeFixture

    context_path = Path(context_path)
    context = core.load(context_path)
    linked = Path(context["scan_base"])
    commands = []
    phase = "planning"
    native = NativeFixture(context)
    workers = native.workers

    def command(script, *args):
        authority = (patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": ""})
                     if "--portable" in args or script == "advantage-status.py"
                     else native_call(context, phase, workers=workers))
        with authority:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / script), *map(str, args)],
                cwd=ROOT, capture_output=True, text=True, check=False, timeout=60)
        commands.append({"script": script, "returncode": result.returncode})
        if result.returncode:
            raise AssertionError(f"{script}: {result.stderr}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    def begin(name):
        nonlocal phase
        phase = name
        native.select_phase(name)

    def finish(name):
        command("validate-advantage.py", linked, "--context", context_path, "--phase", name)

    def delivered(identity, draft):
        native.observe(identity, artifacts=[str(draft)])

    def revalidate_aggregate(name):
        if not repeat_validation:
            return
        accepted = file_snapshot(linked)
        finish(name)
        if accepted != file_snapshot(linked):
            raise AssertionError("aggregate validation changed immutable analytical evidence")

    with tempfile.TemporaryDirectory(prefix="fixture-drafts-", dir=linked) as temporary, native:
        drafts = Path(temporary)
        begin("planning")
        plan = authored_plan(context, "app.py:11-15")
        if len(plan["assignments"]) < 4:
            raise AssertionError("continuity fixture requires four independent passes")
        objective = copy.deepcopy(plan["objectives"][0])
        objective.update(id=stable_id("OBJ-", "planning/plan.json", "secondary-read"),
                         local_key="secondary-read", desired_effect="Read another tenant's secondary record.",
                         success_condition="Read another tenant's secondary record using an ordinary account.",
                         resource_scope="secondary tenant records", evidence_refs=["secondary.py:1-2"])
        question = copy.deepcopy(plan["questions"][0])
        question.update(id=stable_id("Q-", "planning/plan.json", "secondary-guard"),
                        local_key="secondary-guard", objective_id=objective["id"],
                        security_question="Does the independent secondary lookup enforce tenant ownership?",
                        route="secondary lookup", proof_obligation="Establish the secondary tenant ownership decision.",
                        evidence_refs=["secondary.py:1-2"])
        plan["objectives"].append(objective)
        plan["questions"].append(question)
        plan["assignments"][2]["question_ids"] = [question["id"]]
        put(drafts / "plan.json", plan)
        command("build-advantage-plan.py", "--context", context_path, "--draft", drafts / "plan.json")
        finish("planning")
        planning_before = file_snapshot(linked / "planning")
        begin("investigation")
        assignments = plan["assignments"]
        packets = {row["task_id"]: core.load(linked / f"investigation/packets/{row['task_id']}.json")
                   for row in assignments}
        first_id, failed_id, active_id = (row["task_id"] for row in assignments[:3])
        first_packet = packets[first_id]
        first = authored_result(context, first_packet, source="app.py:11-15")
        first["candidates"] = [candidate("C-CHAIN", "new_chain"),
                               candidate("C-BAD", "new_root", source="app.py:999-1001")]
        put(drafts / "first.json", first)
        delivered(first_id, drafts / "first.json")
        command("finalize-advantage-investigation.py", "--context", context_path, "--result", drafts / "first.json")
        first_ref = pipeline.result_path(first_packet)
        accepted_bytes = (linked / first_ref).read_bytes()
        active_worker = native_worker(context, phase, active_id, status="running", yield_valid=False)
        workers.append(active_worker)
        for attempt in range(1, context["budget"]["max_attempts"] + 1):
            workers.append(native_worker(
                context, phase, failed_id, status="failed", attempt=attempt,
                yield_valid=False, error="Synthetic worker exhausted result admission."))
        if active_worker["status"] != "running":
            raise AssertionError("unrelated active worker was cancelled")
        active = authored_result(context, packets[active_id], source="secondary.py:1-2")
        active["candidates"] = [candidate("C-ROOT", "new_root", source="secondary.py:1-2")]
        active["candidates"][0].update(
            root_cause_key="Secondary lookup omits tenant ownership", terminal_impact="Cross-tenant secondary record read",
            source_locations=[{"file": "secondary.py", "line": 2}],
            reason="The secondary lookup returns a caller-selected record without the tenant predicate.")
        put(drafts / "active.json", active)
        workers.remove(active_worker)
        delivered(active_id, drafts / "active.json")
        command("finalize-advantage-investigation.py", "--context", context_path, "--result", drafts / "active.json")
        active_ref = pipeline.result_path(packets[active_id])
        active_bytes = (linked / active_ref).read_bytes()
        if ((linked / first_ref).read_bytes() != accepted_bytes or
                (linked / active_ref).read_bytes() != active_bytes or
                file_snapshot(linked / "planning") != planning_before):
            raise AssertionError("local failure rewrote healthy accepted research")
        for assignment in assignments[3:]:
            identity = assignment["task_id"]
            result = authored_result(context, packets[identity], "locally_unresolved", "app.py:11-15")
            put(drafts / f"{identity}.json", result)
            delivered(identity, drafts / f"{identity}.json")
            command("finalize-advantage-investigation.py", "--context", context_path,
                    "--result", drafts / f"{identity}.json")
        command("finalize-advantage-investigation.py", "--context", context_path)
        finish("investigation")
        from test_advantage_lifecycle import empty_gap_phase
        empty_gap_phase(context)
        investigation = core.load(linked / "investigation/results.json")

        begin("synthesis")
        chain, chain_link = authored_chain(context, plan["objectives"][0], first_ref)
        root = sample_finding()
        root.update(id="F-002", origin="independent_discovery", title="Secondary tenant record disclosure",
                    source_refs=[{"kind": "advantage", "source_id": "C-ROOT", "artifact_ref": active_ref}])
        for location in root["root_causes"] + root["trace"]:
            location["file"] = "secondary.py"
        root["verification"].update(actor="vulnops-advantage-synthesis",
                                    model=context["model_routing"]["agents"]["vulnops-advantage-synthesis"],
                                    source_validation_refs=["secondary.py:1-2"])
        add_dossier(root, objective_id=objective["id"], source="secondary.py:1-2")
        root_link = {"finding_id": root["id"], "classification": "new_root", "baseline_ids": [],
                     "result_refs": [active_ref], "source_view": "base"}
        root["contributors"] = pipeline.contributor_union(context, root, root_link)
        if negative_control:
            chain["transitions"][0]["obligations"]["consumer_authority"]["evidence_refs"] = ["app.py:999"]
            chain["transitions"][0]["obligations"]["consumer_authority"]["source_locations"] = [
                {"file": "app.py", "start_line": 999, "end_line": 999}]
        synthesis = core.envelope(
            context, status="completed", reason="Supported roots survive independent local worker and evidence defects.",
            provenance=author(context, "vulnops-advantage-synthesis", "synthesis/findings.json"),
            findings=[chain, root], links=[chain_link, root_link],
            candidate_dispositions=[
                {"result_ref": ref, "candidate_id": cid, "disposition": "promoted", "finding_ids": [fid],
                 "reason": "Complete source-backed dossier requires independent review."}
                for ref, cid, fid in ((first_ref, "C-CHAIN", chain["id"]), (active_ref, "C-ROOT", root["id"]))],
            baseline_reconciliation=[
                {"baseline_id": identity, "status": "not_revisited", "finding_ids": [], "result_refs": [],
                 "reason": "Prior root retained as historical intelligence; not current proof."}
                for identity in pipeline.baseline_findings(context)])
        put(drafts / "synthesis.json", synthesis)
        command("finalize-advantage-synthesis.py", "--context", context_path, "--draft", drafts / "synthesis.json")
        revalidate_aggregate("synthesis")
        finish("synthesis")

        begin("final-verification")
        assignments = command("finalize-advantage-verification.py", "--context", context_path, "--prepare")
        effective = {row["id"]: row for row in core.load(linked / "synthesis/findings.json")["findings"]}
        for assignment in assignments["assignments"]:
            identity = assignment["finding_id"]
            finding = effective[identity]
            review = authored_review(context, finding, assignment)
            if identity == "F-002":
                review["evidence_refs"] = ["secondary.py:1-2"]
                review["joint_conditions"]["evidence_refs"] = ["secondary.py:1-2"]
                review_dossier(finding, review, success_condition=objective["success_condition"], satisfied=True)
            put(drafts / f"review-{identity}.json", review)
            delivered(identity, drafts / f"review-{identity}.json")
            command("finalize-advantage-verification.py", "--context", context_path,
                    "--result", drafts / f"review-{identity}.json")
        command("finalize-advantage-verification.py", "--context", context_path)
        revalidate_aggregate("final-verification")
        finish("final-verification")
        begin("handoff")
        command("finalize-advantage-handoff.py", linked, "--context", context_path)
        revalidate_aggregate("handoff")
        finish("handoff")
        begin("report")
        command("render-advantage-report.py", "--context", context_path)
        revalidate_aggregate("report")
        finish("report")
        command("advantage-cleanup.py", "--context", context_path)
        assert not context_path.exists()
        command("validate-advantage.py", linked, "--portable")
        status = command("advantage-status.py", linked)
        report = core.load(linked / "report/security-report.json")
        failed = [row for row in investigation["question_outcomes"]
                  if row["resolution"]["outcome"] == "execution_failed"]
        if (status["status"] != "complete" or pipeline.phase_status(context, "investigation") != "degraded"
                or {row["task_id"] for row in failed} != {failed_id}
                or report["coverage"]["unresolved_by_outcome"]["execution_failed"] != len(failed)):
            raise AssertionError("publication lost accepted local investigation failure limitations")
        return {"context": context, "report": report,
                "investigation": investigation, "failed_task": failed_id,
                "commands": commands, "status": status}


class AdvantageAdmissionIntegrationTests(unittest.TestCase):
    def test_complete_baseline_admission_and_drift_preserve_audit(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as directory:
            base = Path(directory)
            baseline = exercise_pipeline(base, git_identity=True)
            original = file_snapshot(baseline["scan"])
            source = file_snapshot(baseline["source"])
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "synthetic-admission-session",
                "VULNOPS_LAUNCHER_PID": str(os.getpid()),
                "VULNOPS_RUNTIME_ROOT": str(base / "runtime"),
            }

            def command(name, *arguments):
                with patch.dict(os.environ, environment), native_controller("synthetic-admission-session"):
                    return subprocess.run(
                        [sys.executable, str(ROOT / "scripts" / name), *map(str, arguments)],
                        cwd=ROOT, text=True, capture_output=True, check=False,
                    )

            admitted = command("init-advantage.py", baseline["scan"],
                               "--source-root", baseline["source"], "--mode", "deep", "--depth", "full")
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            context = json.loads(admitted.stdout)
            context_path = Path(context["input_path"])
            linked = Path(context["scan_base"])
            self.assertTrue(linked.is_relative_to(ROOT / "scans"))
            self.assertNotEqual(linked, baseline["scan"])
            try:
                self.assertEqual(context["execution_kind"], "advantage")
                self.assertEqual(context["source_run_id"], "redteam-fixture")
                self.assertFalse((linked / "report/security-report.json").exists())
                self.assertFalse((linked / "advantage-manifest.json").exists())
                self.assertEqual(file_snapshot(baseline["scan"]), original)
                self.assertEqual(file_snapshot(baseline["source"]), source)
                self.assertFalse((linked / "run-manifest.json").exists())

                # Source drift starts a distinct invocation and leaves abandoned evidence untouched.
                with (baseline["source"] / "app.py").open("a") as handle:
                    handle.write("\n# changed after audit\n")
                abandoned = linked
                abandoned_before = file_snapshot(abandoned)
                changed = command("init-advantage.py", baseline["scan"],
                                  "--source-root", baseline["source"], "--mode", "deep", "--depth", "full")
                self.assertEqual(changed.returncode, 0, changed.stderr)
                fresh = json.loads(changed.stdout)
                self.assertNotEqual(fresh["run_id"], context["run_id"])
                self.assertEqual(file_snapshot(abandoned), abandoned_before)
                with patch.dict(os.environ, environment), native_call(context, "planning"):
                    cleaned = subprocess.run(
                        [sys.executable, str(ROOT / "scripts/advantage-cleanup.py"), "--context", str(context_path)],
                        cwd=ROOT, text=True, capture_output=True, check=False)
                self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
                context = fresh
                context_path = Path(context["input_path"])
                linked = Path(context["scan_base"])
                self.assertEqual(file_snapshot(baseline["scan"]), original)
                from test_advantage_pipeline import exercise_linked_cli
                changed_source = file_snapshot(baseline["source"])
                with patch.dict(os.environ, environment):
                    result = exercise_linked_cli(context_path)
                self.assertFalse((linked / "advantage-manifest.json").exists())
                self.assertEqual(len(result["report"]["findings"]), 1)
                import advantage_pipeline as pipeline
                published_json = (linked / "report/security-report.json").read_bytes()
                published_markdown = (linked / "report/security-report.md").read_bytes()
                self.assertEqual(json.loads(published_json), result["report"])
                self.assertEqual(published_markdown.decode(),
                                 pipeline.report_markdown(result["report"], result["context"]))
                portable = command("validate-advantage.py", linked, "--portable")
                self.assertEqual(portable.returncode, 0, portable.stderr)
                history = result["report"]["ancillary"]["question_outcomes"]
                first_pass = [row for row in history if row["pass_id"] == "PASS-001"
                              and row["task_id"] in {"TASK-001", "TASK-002"}]
                self.assertEqual([row["resolution"]["outcome"] for row in first_pass],
                                 ["locally_unresolved", "established"])
                plan = pipeline.read_local(result["context"], "planning/plan.json")
                self.assertEqual(result["report"]["coverage"]["unresolved_by_outcome"]["locally_unresolved"],
                                 len(plan["passes"]) - 1)
                retained = linked / "investigation/passes/PASS-001/results/TASK-001.json"
                self.assertEqual(json.loads(retained.read_text())["question_outcomes"][0]["resolution"]["outcome"],
                                 "locally_unresolved")
                final_before = file_snapshot(linked / "final-verification")
                plan_before = file_snapshot(linked / "planning")
                # Alter only this disposable publication, then restore its exact
                # bytes. Portable validation still rejects unsupported publication text.
                try:
                    (linked / "report/security-report.md").write_bytes(
                        published_markdown + b"\nThe attacker achieved production administrator access.\n")
                    tampered = command("validate-advantage.py", linked, "--portable")
                    self.assertNotEqual(tampered.returncode, 0)
                finally:
                    (linked / "report/security-report.md").write_bytes(published_markdown)
                self.assertEqual((linked / "report/security-report.json").read_bytes(), published_json)
                self.assertEqual(file_snapshot(linked / "final-verification"), final_before)
                self.assertEqual(file_snapshot(linked / "planning"), plan_before)
                self.assertEqual(file_snapshot(baseline["source"]), changed_source)
                self.assertEqual(file_snapshot(baseline["scan"]), original)
            finally:
                # Only the exact disposable linked execution created by this test.
                shutil.rmtree(linked)
                if linked.parent.is_dir() and not any(linked.parent.iterdir()):
                    linked.parent.rmdir()

    def test_completed_actions_and_remediation_preserve_both_source_bundles(self):
        from test_advantage_actions import exercise_actions_cli, exercise_advantage_remediation_cli
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as directory:
            base = Path(directory)
            baseline = exercise_pipeline(base, git_identity=True)
            before = {name: file_snapshot(baseline[name]) for name in ("source", "scan")}
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "synthetic-followon-session",
                "VULNOPS_LAUNCHER_PID": str(os.getpid()),
                "VULNOPS_RUNTIME_ROOT": str(base / "runtime"),
            }
            with patch.dict(os.environ, environment), native_controller("synthetic-followon-session"):
                admitted = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/init-advantage.py"), str(baseline["scan"]),
                     "--source-root", str(baseline["source"]), "--mode", "standard"],
                    cwd=ROOT, text=True, capture_output=True, check=False,
                )
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            context_path = Path(json.loads(admitted.stdout)["input_path"])
            action_fixture = base / "selected-action-inputs"
            source_base = Path(json.loads(admitted.stdout)["scan_base"])
            result = None
            try:
                with patch.dict(os.environ, environment):
                    result = exercise_actions_cli(context_path, fixture_root=action_fixture)
                self.assertEqual(result["report"]["findings"], [])
                self.assertEqual(result["report"]["coverage"]["investigation_status"], "skipped")
                self.assertEqual(result["actions"]["verify_fix"]["records"][0]["outcome"], "inconclusive")
                self.assertEqual(result["actions"]["tracking"]["records"][0]["publication"], "offline_only")
                import advantage_pipeline as pipeline
                action_markdown = (Path(result["context"]["scan_base"]) / "report/security-report.md").read_text()
                self.assertEqual(action_markdown, pipeline.report_markdown(result["report"], result["context"]))
                for selected in ("verify_fix", "patch_risk", "hardening"):
                    for record in result["actions"][selected]["records"]:
                        self.assertIn(pipeline.audit_renderer().markdown(record["rationale"]), action_markdown)
                self.assertRegex(action_markdown.lower(), r"(?:no discovery|no investigation|does not investigate|did not investigate)")
                self.assertNotRegex(action_markdown.lower(), r"(?:all evidence|evidence is) independently (?:reviewed|verified)")
                self.assertNotIn("not_selected", action_markdown)
                remediation = exercise_advantage_remediation_cli(source_base, baseline["source"])
                self.assertTrue(remediation["manual_required"])
                self.assertEqual({row["variant"] for row in remediation["rejected_source_variants"]},
                                 {"historical-or-mixed-attempt-source"})
                self.assertTrue(result["source_snapshots_unchanged"])
                self.assertTrue(remediation["source_snapshots_unchanged"])
                self.assertEqual(before, {name: file_snapshot(baseline[name]) for name in ("source", "scan")})
            finally:
                context = result["context"] if result else None
                if context:
                    self.assertTrue(Path(context["scan_base"]).is_relative_to(base))
                    shutil.rmtree(ROOT / "work/advantage" / context["run_id"], ignore_errors=True)

    def test_diff_derived_evidence_remains_portable_without_runtime(self):
        import difflib
        from test_advantage_actions import exercise_derived_fixture_cli
        with tempfile.TemporaryDirectory(prefix="advantage-diff-", dir=ROOT / "scans") as directory:
            fixture = Path(directory)
            baseline = exercise_pipeline(fixture, git_identity=True)
            before = {name: file_snapshot(baseline[name]) for name in ("source", "scan")}
            original = (baseline["source"] / "app.py").read_text()
            patch_path = fixture / "comment.patch"
            patch_path.write_text("".join(difflib.unified_diff(
                original.splitlines(keepends=True),
                (original + "# Source-only diff fixture.\n").splitlines(keepends=True),
                fromfile="a/app.py", tofile="b/app.py")))
            environment = {
                "PYTHONDONTWRITEBYTECODE": "1",
                "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "synthetic-diff-session",
                "VULNOPS_LAUNCHER_PID": str(os.getpid()),
                "VULNOPS_RUNTIME_ROOT": str(fixture / "runtime"),
            }
            with patch.dict(os.environ, environment), native_controller("synthetic-diff-session"):
                initialized = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/init-advantage.py"), str(baseline["scan"]),
                     "--source-root", str(baseline["source"]), "--mode", "diff",
                     "--patch", str(patch_path), "--depth", "quick"],
                    cwd=ROOT, capture_output=True, text=True, check=False, timeout=60)
                self.assertEqual(initialized.returncode, 0, initialized.stderr)
                context = json.loads(initialized.stdout)
                result = exercise_derived_fixture_cli(context["input_path"])
            linked = Path(context["scan_base"])
            self.assertFalse(Path(context["input_path"]).exists())
            self.assertEqual(result["context"]["mode"], "diff")
            self.assertEqual(before, {name: file_snapshot(baseline[name]) for name in ("source", "scan")})
            portable = fixture / "portable"
            portable.mkdir()
            relocated = portable / linked.name
            shutil.copytree(linked, relocated)
            shutil.copytree(baseline["scan"], portable / context["source_run_id"])
            for script in ("validate-advantage.py", "advantage-status.py"):
                arguments = ["--portable"] if script == "validate-advantage.py" else []
                checked = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / script), str(relocated), *arguments],
                    cwd=portable, capture_output=True, text=True, check=False, timeout=60)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                self.assertEqual(json.loads(checked.stdout)["status"], "complete")
            self.assertEqual(file_snapshot(linked), file_snapshot(relocated))

    def test_local_defects_and_new_clean_invocation_report_only_supported_outcomes(self):
        with tempfile.TemporaryDirectory(prefix="advantage-continuity-", dir=ROOT / "scans") as directory:
            fixture = Path(directory)
            baseline = exercise_pipeline(fixture, git_identity=True)
            (baseline["source"] / "secondary.py").write_text(
                "def lookup(record_id):\n    return records[record_id]\n", encoding="utf-8")
            original = file_snapshot(baseline["scan"])
            source = file_snapshot(baseline["source"])
            reports = []
            executions = []
            for negative in (False, True):
                with self.subTest(essential_transition_missing=negative):
                    environment = {
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "synthetic-continuity-session",
                        "VULNOPS_LAUNCHER_PID": str(os.getpid()),
                        "VULNOPS_RUNTIME_ROOT": str(fixture / "runtime"),
                    }
                    with patch.dict(os.environ, environment), native_controller("synthetic-continuity-session"):
                        initialized = subprocess.run(
                            [sys.executable, str(ROOT / "scripts/init-advantage.py"), str(baseline["scan"]),
                             "--source-root", str(baseline["source"]), "--mode", "deep", "--depth", "full"],
                            cwd=ROOT, capture_output=True, text=True, check=False, timeout=60)
                        self.assertEqual(initialized.returncode, 0, initialized.stderr)
                        context_path = Path(json.loads(initialized.stdout)["input_path"])
                        result = exercise_continuity_cli(
                            context_path, negative_control=negative, repeat_validation=not negative)
                    linked = Path(result["context"]["scan_base"])
                    self.assertFalse((linked / "advantage-manifest.json").exists())
                    self.assertNotIn(result["context"]["run_id"], executions)
                    executions.append(result["context"]["run_id"])
                    self.assertEqual({row["id"] for row in result["report"]["findings"]},
                                     {"F-002"} if negative else {"F-001", "F-002"})
                    markdown = (linked / "report/security-report.md").read_text()
                    independent_root = next(row for row in result["report"]["findings"] if row["id"] == "F-002")
                    self.assertIn(independent_root["attack_summary"], markdown)
                    if negative:
                        self.assertNotIn("Cross-tenant queued operation", markdown)
                    failed = [row for row in result["investigation"]["question_outcomes"]
                              if row["resolution"]["outcome"] == "execution_failed"]
                    self.assertEqual({row["task_id"] for row in failed}, {result["failed_task"]})
                    self.assertFalse(any(row["resolution"]["outcome"] == "budget_deferred"
                                         for row in result["investigation"]["question_outcomes"]))
                    self.assertFalse((linked / "run-manifest.json").exists())
                    reports.append(result["report"])
                    self.assertEqual(file_snapshot(baseline["scan"]), original)
                    self.assertEqual(file_snapshot(baseline["source"]), source)
            independent = [next(finding for finding in report["findings"] if finding["id"] == "F-002")
                           for report in reports]
            for field in ("root_causes", "impact", "severity", "status", "objective_ids", "verdict"):
                self.assertEqual(independent[0][field], independent[1][field])
            contributions = lambda finding: {
                (row["actor"], row["selector"], row["artifact_ref"]) for row in finding["contributors"]}
            self.assertEqual(contributions(independent[0]), contributions(independent[1]))


if __name__ == "__main__":
    unittest.main()
