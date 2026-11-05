from __future__ import annotations

import importlib.util
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from argparse import Namespace

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("audit_recovery", ROOT / "scripts/recover-run.py")
RECOVERY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RECOVERY)
# Retain explicit pre-add-on fixtures for legacy continuation coverage.
PHASES = tuple(phase for phase in RECOVERY.PHASES if phase != "gap-exploration")
DIRS = RECOVERY.PHASE_DIRS
TASKS = {phase: task for task, phase in RECOVERY.TASK_PHASE.items()}


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")


def recover_campaign_fixture(scan: Path, context_path: Path) -> dict:
    context = json.loads(context_path.read_text())
    prefix = {path: path.read_bytes() for phase in PHASES[:3] for path in (scan / DIRS[phase]).rglob("*") if path.is_file()}
    result = subprocess.run([PYTHON, str(ROOT / "scripts/recover-run.py"), str(scan), str(context_path), context["depth"]], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    owned = json.loads((scan / "run-manifest.json").read_text())["phases"]
    assert result.stdout.startswith(f"campaign-planning\t3\t{len(owned) - 3}"), result.stdout
    manifest = json.loads((scan / "run-manifest.json").read_text())
    assert manifest["status"] == "incomplete"
    assert prefix == {path: path.read_bytes() for path in prefix}
    assert all(manifest["phases"][phase] == "pending" for phase in PHASES[3:])
    return {"restart": "campaign-planning", "retained_files": len(prefix)}


def synthesis_retry_resume_smoke() -> dict:
    """Exercise both canonical transitions entirely inside disposable fixtures."""
    results = {}
    for resume in (False, True):
        fixture = RecoveryTests()
        fixture.setUp()
        try:
            fixture.staged_synthesis()
            results["resume" if resume else "retry"] = fixture.repair_staged_synthesis(resume=resume)
        finally:
            fixture.doCleanups()
    return results


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.scan = self.base / "scan"
        self.target = self.base / "source"
        self.target.mkdir()
        (self.target / "app.py").write_text("old\n")
        self.context_path = self.base / "context.json"
        self.manifest = {"schema_version": "2.0", "workflow": "canonical-redteam-v2", "run_id": "fixture", "status": "failed", "phases": {phase: "ok" if index < 5 else "failed" if index == 5 else "pending" for index, phase in enumerate(PHASES)}, "recovery_count": 0, "recovery_history": [], "target_fingerprint": "obsolete", "phase_seals": {"recon": {"obsolete": True}}}
        self.ledger = {"schema_version": "2.0", "run_id": "fixture", "tasks": [{"id": TASKS[phase], "phase": phase, "status": "ok" if index < 5 else "failed", "attempts": 1, "artifact": f"{DIRS[phase]}/original.json" if index < 5 else None, "updated_at": "before", "error": None if index < 5 else "interrupted", "attempt_id": "old-attempt"} for index, phase in enumerate(PHASES[:6])]}
        self.context = {"run_id": "fixture", "scan_base": str(self.scan), "repo_path": str(self.target), "source_root": str(self.target), "depth": "balanced"}
        for phase in PHASES:
            write(self.scan / DIRS[phase] / "original.json", {"phase": phase})
        self.publish()
        self.env = {**os.environ, "VULNOPS_RUNTIME_ROOT": str(self.base / "runtime"), "VULNOPS_LAUNCHER_PID": str(os.getpid()), "VULNOPS_LAUNCHER_SESSION_ID": "recovery-fixture"}

    def publish(self):
        write(self.scan / "run-manifest.json", self.manifest)
        write(self.scan / "task-ledger.json", self.ledger)
        write(self.context_path, self.context)

    def recover(self, *options):
        return subprocess.run([PYTHON, str(ROOT / "scripts/recover-run.py"), str(self.scan), str(self.context_path), "quick", *options], capture_output=True, text=True, env=self.env)

    def snapshot(self, directory=None):
        return {str(path.relative_to(directory or self.scan)): path.read_bytes() for path in (directory or self.scan).rglob("*") if path.is_file()}

    def interrupt_phase(self, phase):
        index = PHASES.index(phase)
        self.manifest["phases"] = {name: "ok" if offset < index else "running" if offset == index else "pending"
                                   for offset, name in enumerate(PHASES)}
        self.ledger["tasks"] = [row for row in self.ledger["tasks"] if PHASES.index(row["phase"]) <= index]
        for row in self.ledger["tasks"]:
            row["status"] = "running" if row["phase"] == phase else "ok"
        self.publish()

    def partial_sast(self):
        self.interrupt_phase("sast")
        write(self.scan / "sast/hunt-plan.json", {"run_id": "fixture", "tasks": [
            {"id": "H001", "attempt_id": "old", "cell_ids": ["CELL-1"]},
            {"id": "H002", "attempt_id": "old", "cell_ids": ["CELL-2"]}]})
        write(self.scan / "sast/coverage-ledger.json", {"tasks": [
            {"id": "H001", "status": "closed", "artifact_valid": True, "candidate_ids": ["C-1"], "attempt_id": "old"},
            {"id": "H002", "status": "failed", "artifact_valid": False, "candidate_ids": [], "attempt_id": "old"}],
            "review_attempts": {"C-1": "old"}})
        for relative in ("hunt-tasks/H001.json", "hunt-tasks/H002.json", "deepdive/H001.json",
                         "deepdive/H002.json", "verify/C-1.json", "verify/C-2.json", "experiments/request.json"):
            write(self.scan / "sast" / relative, {"owner": relative})
        write(self.scan / "sast/raw-findings.json", [{"id": "C-1"}, {"id": "C-2"}])
        write(self.scan / "sast/validation-queue.json", [{"id": "C-1"}, {"id": "C-2"}])
        write(self.scan / "sast/validation-results.json", [{"candidate_id": "C-1"}, {"candidate_id": "C-2"}])
        write(self.scan / "sast/verified-findings.json", [{"id": "C-1"}, {"id": "C-2"}])
        write(self.scan / "sast/phase-manifest.json", {"phase": "sast", "status": "ok"})

    def update_synthesis(self, status, *, increment=False):
        command = [PYTHON, str(ROOT / "scripts/update-run-state.py"), str(self.scan),
                   "--phase", "synthesis", "--phase-status", status,
                   "--task", "Synthesis", "--task-phase", "synthesis"]
        if increment:
            command.append("--increment-attempt")
        if status == "failed":
            command.extend(["--error", "Synthesis publication rejected or was interrupted before phase acceptance."])
        return subprocess.run(command, capture_output=True, text=True, env=self.env)

    def staged_synthesis(self, *, valid=False):
        import gap_dossier as gap
        from model_routing import audit_routing, load_routing
        from run_lifecycle import claim_run, release_run
        from test_dossiers import sample_finding
        environment = patch.dict(os.environ, self.env)
        environment.start()
        self.addCleanup(environment.stop)
        phases = tuple(RECOVERY.PHASES)
        index = phases.index("synthesis")
        self.manifest.update(status="incomplete", attempt_id="old-attempt",
            phases={phase: "ok" if offset < index else "running" if offset == index else "pending"
                    for offset, phase in enumerate(phases)})
        self.context.update(attempt_id="old-attempt", depth="quick", model_routing=audit_routing(load_routing(ROOT)),
            orchestration={"phase_timeout_seconds": {"synthesis": 1200}},
            paths={"gap_exploration": str((self.scan / "gap-exploration").resolve())},
            gap_exploration_budget={"enabled": True, "max_attempts": 2, "max_concurrency": 1,
                                   "synthesis_timeout_seconds": 300, "verification_timeout_seconds": 300})
        self.manifest["gap_exploration_budget"] = copy.deepcopy(self.context["gap_exploration_budget"])
        self.ledger["tasks"] = [
            {"id": TASKS[phase], "phase": phase, "status": "ok" if offset < index else "running",
             "attempts": 1, "invocation_attempts": 1, "attempt_id": "old-attempt",
             "artifact": f"{DIRS[phase]}/original.json" if offset < index else None, "error": None}
            for offset, phase in enumerate(phases[:index + 1])]
        for phase in phases[:index]:
            write(self.scan / DIRS[phase] / "original.json", {"phase": phase, "accepted": True})
        self.publish()
        gap.begin_cohort(self.context, "synthesis", "original")
        finding = sample_finding()
        from synthesis_contract import InvalidSynthesisStructure, validate_synthesis_structure
        document = {"schema_version": "2.0", "run_id": "fixture",
                    "findings": [finding], "objective_assessments": []}
        validate_synthesis_structure(document)
        if not valid:
            finding["primitive_steps"] = [{"primitive_id": "P-001", "input_capability": "record ID",
                "output_capability": "record", "boundary_crossed": "tenant",
                "evidence_refs": ["source.py:2"]}]
        write(self.scan / "synthesis/original-findings.json", document)
        gap.bind_original_draft(self.context, "synthesis/original-findings.json")
        gap.finish_cohort(self.context, "synthesis", "original")
        with patch.object(gap, "accepted_candidates", return_value=[{"id": "GC-fixture"}]):
            gap.begin_cohort(self.context, "synthesis", "supplementary")
        write(self.scan / "synthesis/findings.json", document)
        gap.finish_cohort(self.context, "synthesis", "supplementary")
        write(self.scan / "synthesis/supplementary-draft.json", document)
        write(self.scan / "synthesis/phase-manifest.json", {"phase": "synthesis", "status": "ok"})
        if not valid:
            with self.assertRaises(InvalidSynthesisStructure):
                validate_synthesis_structure(document)
        failed = self.update_synthesis("failed")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        return document

    def repair_staged_synthesis(self, *, resume):
        import gap_dossier as gap
        dispatch_path = self.scan / "synthesis/dispatch.json"
        old = json.loads(dispatch_path.read_text())
        consumed = copy.deepcopy(old["cohorts"]["supplementary"])
        budget = copy.deepcopy(self.context["gap_exploration_budget"])
        prefix = {path: path.read_bytes() for phase in RECOVERY.PHASES
                  if phase not in {"synthesis", "final-verification", "report"}
                  for path in (self.scan / DIRS[phase]).rglob("*") if path.is_file()}
        if resume:
            # Exhaust the former invocation; recovery must not compare its phase_attempt
            # with the newly created canonical task's first attempt.
            ledger = json.loads((self.scan / "task-ledger.json").read_text())
            owner = next(row for row in ledger["tasks"] if row["phase"] == "synthesis")
            owner.update(attempts=2, invocation_attempts=2)
            write(self.scan / "task-ledger.json", ledger)
            old["cohorts"]["original"]["phase_attempt"] = 2
            write(dispatch_path, old)
            recovered = self.recover()
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
        started = self.update_synthesis("running", increment=True)
        self.assertEqual(started.returncode, 0, started.stderr)
        original = gap.begin_cohort(self.context, "synthesis", "original")
        self.assertEqual(original["status"], "running")
        self.assertEqual(original["phase_attempt"], 1 if resume else 2)
        self.assertNotIn("output_ref", original)
        self.assertNotIn("output_sha256", original)
        for name in ("original-findings.json", "findings.json", "supplementary-draft.json", "phase-manifest.json"):
            self.assertFalse((self.scan / "synthesis" / name).exists(), name)
        repaired = json.loads(dispatch_path.read_text())["cohorts"]["supplementary"]
        self.assertEqual(repaired["status"], "failed")
        self.assertEqual(repaired["failure_kind"], "execution_failed")
        self.assertIn("unaccepted original", repaired["reason"])
        for key in ("attempt_id", "phase_attempt", "started_at", "deadline_at"):
            self.assertEqual(repaired[key], consumed[key])
        self.assertEqual(self.context["gap_exploration_budget"], budget)
        self.assertEqual(json.loads((self.scan / "run-manifest.json").read_text())["gap_exploration_budget"], budget)
        self.assertEqual({path: path.read_bytes() for path in prefix}, prefix)
        self.assertEqual(gap.begin_cohort(self.context, "synthesis", "supplementary"), repaired)
        # Reauthoring can now bind different bytes without restoring the discarded union.
        write(self.scan / "synthesis/original-findings.json",
              {"schema_version": "2.0", "run_id": "fixture", "findings": [], "objective_assessments": []})
        gap.bind_original_draft(self.context, "synthesis/original-findings.json")
        gap.finish_cohort(self.context, "synthesis", "original")
        with patch.object(gap, "accepted_candidates", return_value=[{"id": "GC-fixture"}]):
            closed = gap.close_supplementary_draft(self.scan, self.context, {"findings": []})
        self.assertEqual(closed["unreviewed"][0]["status"], "execution_failed")
        self.assertFalse((self.scan / "synthesis/findings.json").exists())
        return {"retained_predecessor_files": len(prefix), "original_attempt": original["phase_attempt"],
                "supplementary_status": repaired["status"]}

    def test_structurally_invalid_original_retries_through_canonical_task(self):
        self.staged_synthesis()
        self.repair_staged_synthesis(resume=False)

    def test_structurally_invalid_original_resumes_after_exhausted_invocation(self):
        self.staged_synthesis()
        self.repair_staged_synthesis(resume=True)

    def test_valid_drafts_survive_retry_and_sourceless_resume(self):
        import gap_dossier as gap
        self.staged_synthesis(valid=True)
        before = self.snapshot(self.scan / "synthesis")
        for resume in (False, True):
            with self.subTest(resume=resume):
                if resume:
                    failed = self.update_synthesis("failed")
                    self.assertEqual(failed.returncode, 0, failed.stderr)
                    (self.target / "app.py").unlink()
                    recovered = self.recover()
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                started = self.update_synthesis("running", increment=True)
                self.assertEqual(started.returncode, 0, started.stderr)
                # This trap covers only the in-process cohort admission, not the recovery child.
                with patch("synthesis_contract.semantic_synthesis", side_effect=AssertionError("fresh source validation")):
                    row = gap.begin_cohort(self.context, "synthesis", "original")
                self.assertEqual(row["status"], "completed")
                if resume:
                    self.assertEqual((self.scan / "synthesis/original-findings.json").read_bytes(),
                                     before["original-findings.json"])
                else:
                    self.assertEqual(self.snapshot(self.scan / "synthesis"), before)


    def test_unaccepted_valid_original_is_discarded_without_source_replay(self):
        self.staged_synthesis(valid=True)
        dispatch_path = self.scan / "synthesis/dispatch.json"
        dispatch = json.loads(dispatch_path.read_text())
        dispatch["cohorts"]["original"].update(status="running", completed_at=None)
        write(dispatch_path, dispatch)
        with patch("synthesis_contract.semantic_synthesis", side_effect=AssertionError("fresh source validation")):
            self.repair_staged_synthesis(resume=True)

    def test_recovery_retains_exact_closure_for_later_assessment(self):
        import gap_dossier as gap
        document = self.staged_synthesis(valid=True)
        dispatch_path = self.scan / "synthesis/dispatch.json"
        dispatch = json.loads(dispatch_path.read_text())
        dispatch["cohorts"]["supplementary"].update(
            status="failed", reason="Supplementary authoring interrupted after original admission.")
        write(dispatch_path, dispatch)
        candidate = {"id": "GC-fixture"}
        with patch.object(gap, "accepted_candidates", return_value=[candidate]):
            closure = gap.close_supplementary_draft(self.scan, self.context, document)["unreviewed"]
            before = copy.deepcopy(closure)
            recovered = self.recover()
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            consumer = copy.deepcopy(self.context)
            consumer["attempt_id"] = "later-review-attempt"
            consumer["gap_exploration_budget"].update(enabled=False, max_attempts=0)
            with patch.object(gap, "unreviewed_row", side_effect=AssertionError("new closure replay")):
                gap.validate_unreviewed(self.scan, consumer, closure, [candidate], "synthesis")
            self.assertEqual(closure, before)
            closure[0]["task_ref"] = "synthesis/dispatch.json:foreign"
            with self.assertRaisesRegex(ValueError, "foreign task"):
                gap.validate_unreviewed(self.scan, consumer, closure, [candidate], "synthesis")
    def test_corrupt_bound_original_is_fatal_without_deletion(self):
        import gap_dossier as gap
        self.staged_synthesis()
        path = self.scan / "synthesis/original-findings.json"
        path.write_text(path.read_text() + "\n")
        with self.subTest(entrypoint="recovery"):
            before = self.snapshot()
            result = self.recover()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("protected original draft changed", result.stderr)
            self.assertEqual(self.snapshot(), before)
        with self.subTest(entrypoint="retry"):
            started = self.update_synthesis("running", increment=True)
            self.assertEqual(started.returncode, 0, started.stderr)
            before = self.snapshot()
            with self.assertRaisesRegex(ValueError, "protected original draft changed"):
                gap.begin_cohort(self.context, "synthesis", "original")
            self.assertEqual(self.snapshot(), before)

    def test_invalid_original_cleanup_rejects_accepted_phase_and_competing_owner(self):
        import gap_dossier as gap
        self.staged_synthesis()
        manifest = json.loads((self.scan / "run-manifest.json").read_text())
        for change in ({"synthesis": "ok"}, {"final-verification": "running"}):
            with self.subTest(change=change):
                modified = copy.deepcopy(manifest)
                modified["phases"].update(change)
                write(self.scan / "run-manifest.json", modified)
                before = self.snapshot()
                with self.assertRaisesRegex(ValueError, "disposable canonical phase owner"):
                    gap.recovery_checkpoint(self.scan, "synthesis", self.context)
                self.assertEqual(self.snapshot(), before)
        write(self.scan / "run-manifest.json", manifest)
        from run_lifecycle import claim_run
        claim_run(self.scan, "competing-fixture")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "another active session"):
            gap.recovery_checkpoint(self.scan, "synthesis", self.context)
        self.assertEqual(self.snapshot(), before)

    def test_original_path_escape_is_not_structural_cleanup_authority(self):
        import gap_dossier as gap
        self.staged_synthesis()
        path = self.scan / "synthesis/dispatch.json"
        dispatch = json.loads(path.read_text())
        dispatch["cohorts"]["original"]["output_ref"] = "synthesis/../sast/original.json"
        write(path, dispatch)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "unsafe original draft path"):
            gap.recovery_checkpoint(self.scan, "synthesis", self.context)
        self.assertEqual(self.snapshot(), before)

    def test_partial_sast_retains_accepted_work_and_consumed_allocation(self):
        self.partial_sast()
        retained = ("hunt-plan.json", "coverage-ledger.json", "hunt-tasks/H001.json", "hunt-tasks/H002.json",
                    "deepdive/H001.json", "verify/C-1.json", "experiments/request.json")
        before = {name: (self.scan / "sast" / name).read_bytes() for name in retained}
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({name: (self.scan / "sast" / name).read_bytes() for name in retained}, before)
        self.assertFalse((self.scan / "sast/deepdive/H002.json").exists())
        self.assertFalse((self.scan / "sast/verify/C-2.json").exists())
        self.assertFalse((self.scan / "sast/phase-manifest.json").exists())
        self.assertEqual(json.loads((self.scan / "sast/validation-results.json").read_text()), [{"candidate_id": "C-1"}])
        self.assertEqual(json.loads((self.scan / "run-manifest.json").read_text())["phases"]["sast"], "pending")

    def test_partial_sast_without_acceptance_ledger_retains_reservations_not_results(self):
        self.partial_sast()
        (self.scan / "sast/coverage-ledger.json").unlink()
        plan = (self.scan / "sast/hunt-plan.json").read_bytes()
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.scan / "sast/hunt-plan.json").read_bytes(), plan)
        self.assertTrue((self.scan / "sast/hunt-tasks/H001.json").exists())
        self.assertFalse((self.scan / "sast/deepdive/H001.json").exists())
        self.assertFalse((self.scan / "sast/verify/C-1.json").exists())
        self.assertEqual(json.loads((self.scan / "sast/verified-findings.json").read_text()), [])

    def test_partial_intrusion_preserves_wave_acceptance_not_unaccepted_results(self):
        self.interrupt_phase("intrusion")
        import hashlib
        write(self.scan / "intrusion/waves/000.json", {"wave": 0, "results": {}, "assignments": {"CAM-1": {}, "CAM-2": {}}})
        write(self.scan / "intrusion/results/CAM-1.json", {"campaign_id": "CAM-1"})
        write(self.scan / "intrusion/waves/001.json", {"wave": 1, "results": {
            "CAM-1": {"ref": "intrusion/results/CAM-1.json", "sha256": hashlib.sha256((self.scan / "intrusion/results/CAM-1.json").read_bytes()).hexdigest()}},
            "assignments": {"CAM-2": {}}, "continuations": [{"id": "consumed-continuation"}]})
        write(self.scan / "intrusion/results/CAM-2.json", {"campaign_id": "CAM-2"})
        write(self.scan / "intrusion/phase-manifest.json", {"phase": "intrusion", "status": "ok"})
        kept = [self.scan / "intrusion/waves/000.json", self.scan / "intrusion/waves/001.json",
                self.scan / "intrusion/results/CAM-1.json"]
        before = {path: path.read_bytes() for path in kept}
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({path: path.read_bytes() for path in kept}, before)
        self.assertFalse((self.scan / "intrusion/results/CAM-2.json").exists())
        self.assertFalse((self.scan / "intrusion/phase-manifest.json").exists())
        self.assertEqual(json.loads((self.scan / "run-manifest.json").read_text())["phases"]["intrusion"], "pending")

    def test_partial_work_transaction_replays_without_losing_consumption(self):
        self.partial_sast()
        ledger_before = (self.scan / "sast/coverage-ledger.json").read_bytes()
        accepted_before = (self.scan / "sast/deepdive/H001.json").read_bytes()
        args = Namespace(scan_base=self.scan, context=self.context_path, depth="quick", dry_run=False, invalidate_phase=None, reason=None)
        reconcile = RECOVERY.reconcile_work
        def interrupted(scan, phase, operation):
            reconcile(scan, phase, operation)
            raise OSError("interrupted after partial work reconciliation")
        with patch.object(RECOVERY, "reconcile_work", side_effect=interrupted):
            with self.assertRaises(OSError):
                RECOVERY.recover(args)
        self.assertTrue((self.scan / ".recovery-invalidation.json").exists())
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.scan / "sast/coverage-ledger.json").read_bytes(), ledger_before)
        self.assertEqual((self.scan / "sast/deepdive/H001.json").read_bytes(), accepted_before)
        self.assertFalse((self.scan / ".recovery-invalidation.json").exists())

    def test_changed_source_and_policy_retain_completed_prefix_bytes(self):
        before = {phase: self.snapshot(self.scan / DIRS[phase]) for phase in PHASES[:5]}
        (self.target / "app.py").write_text("changed\n")
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "synthesis\t5\t3")
        manifest = json.loads((self.scan / "run-manifest.json").read_text())
        self.assertEqual(manifest["status"], "incomplete")
        for phase in PHASES[:5]:
            self.assertEqual(self.snapshot(self.scan / DIRS[phase]), before[phase])
        for phase in PHASES[5:]:
            self.assertEqual(manifest["phases"][phase], "pending")
            self.assertFalse((self.scan / DIRS[phase] / "original.json").exists())
        self.assertEqual(len(json.loads((self.scan / "task-ledger.json").read_text())["tasks"]), 5)

    def test_report_only_recovery_preserves_verification(self):
        self.manifest["phases"] = {phase: "ok" if phase != "report" else "running" for phase in PHASES}
        self.ledger["tasks"] = [{"id": TASKS[phase], "phase": phase, "status": "ok", "attempts": 1, "artifact": f"{DIRS[phase]}/original.json", "error": None, "updated_at": "before"} for phase in PHASES[:-1]]
        self.publish()
        before = self.snapshot(self.scan / "final-verification")
        result = self.recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "report\t7\t1")
        self.assertEqual(self.snapshot(self.scan / "final-verification"), before)

    def test_dry_run_preserves_every_scan_byte(self):
        before = self.snapshot()
        result = self.recover("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_completed_run_is_never_reset(self):
        self.manifest["status"] = "complete"
        self.publish()
        before = self.snapshot()
        result = self.recover()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("completed", result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_retained_ledger_and_symlink_refuse_before_reset(self):
        original = list(self.ledger["tasks"])
        self.ledger["tasks"] = original[1:]
        self.publish()
        before = self.snapshot()
        result = self.recover()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("task-ledger.json", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.ledger["tasks"] = original
        self.publish()
        (self.scan / "synthesis/source-link").symlink_to(self.target / "app.py")
        result = self.recover()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe", result.stderr)
        self.assertEqual((self.target / "app.py").read_text(), "old\n")

    def test_explicit_reason_is_required_and_archives_preserved(self):
        for options in (("--invalidate-phase", "sast"), ("--reason", "reason"), ("--invalidate-phase", "sast", "--reason", " bad ")):
            result = self.recover(*options)
            self.assertNotEqual(result.returncode, 0)
        old_sast = self.snapshot(self.scan / "sast")
        result = self.recover("--invalidate-phase", "sast", "--reason", "Operator requested upstream review")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "sast\t2\t6")
        self.assertEqual(self.snapshot(self.scan / "recovery-archives/generation-1/sast"), old_sast)

    def test_interrupted_destructive_transaction_requires_original_operation(self):
        args = Namespace(scan_base=self.scan, context=self.context_path, depth="quick", dry_run=False, invalidate_phase="sast", reason="Explicit source review")
        reset = RECOVERY.reset_directory
        count = 0
        def interrupt(scan, phase):
            nonlocal count
            reset(scan, phase)
            count += 1
            if count == 1:
                raise OSError("fixture interruption")
        with patch.object(RECOVERY, "reset_directory", side_effect=interrupt):
            with self.assertRaisesRegex(OSError, "fixture interruption"):
                RECOVERY.recover(args)
        journal = self.scan / ".recovery-invalidation.json"
        self.assertTrue(journal.is_file())
        archive_before = self.snapshot(self.scan / "recovery-archives")
        refused = self.recover()
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("original reason", refused.stderr)
        resumed = self.recover("--invalidate-phase", "sast", "--reason", args.reason)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertFalse(journal.exists())
        self.assertEqual(self.snapshot(self.scan / "recovery-archives"), archive_before)

    def test_legacy_pending_journal_hash_metadata_is_inert(self):
        args = Namespace(scan_base=self.scan, context=self.context_path, depth="quick", dry_run=False, invalidate_phase="sast", reason="Explicit legacy review")
        with patch.object(RECOVERY, "preserve_diagnostics", side_effect=OSError("archive interrupted")):
            with self.assertRaises(OSError):
                RECOVERY.recover(args)
        journal_path = self.scan / ".recovery-invalidation.json"
        journal = json.loads(journal_path.read_text())
        journal["event"].update(from_contract_sha256="old", to_contract_sha256="old")
        journal["event"]["invalidation"]["receipt_sha256"] = "old"
        journal["replacement"]["run-manifest.json"]["status"] = "initialized"
        journal["receipt"] = {"run_id": "fixture", "context_path": str(self.context_path), "original_files": {"run-manifest.json": "old"}}
        write(journal_path, journal)
        resumed = self.recover("--invalidate-phase", "sast", "--reason", args.reason)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(json.loads((self.scan / "run-manifest.json").read_text())["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
