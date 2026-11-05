from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_lifecycle import assessment_ref, current_assessment, report_assessment, routing_for_artifact, start_attempt
from model_identity import validate_provenance

def activate_publisher(scan, context, phase, env):
    """Supply existing lifecycle authority for isolated publisher command fixtures."""
    from run_lifecycle import AUDIT_TASK_PHASES, claim_run
    scan = Path(scan).resolve()
    scan.mkdir(parents=True, exist_ok=True)
    context["scan_base"] = str(scan)
    manifest_path = scan / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else dict(context)
    manifest.setdefault("workflow", "canonical-redteam-v2")
    phases = {key: "ok" if value == "running" else value
              for key, value in manifest.get("phases", {}).items()}
    phases[phase] = "running"
    manifest.update(run_id=context["run_id"], attempt_id=context.get("attempt_id"),
                    status="incomplete", phases=phases)
    manifest_path.write_text(json.dumps(manifest))
    task_id = next(task for task, owner in AUDIT_TASK_PHASES.items() if owner == phase)
    (scan / "task-ledger.json").write_text(json.dumps({"run_id": context["run_id"], "tasks": [{
        "id": task_id, "phase": phase, "status": "running", "attempts": 1,
        "attempt_id": context.get("attempt_id")}]}))
    environment = {**env, "VULNOPS_RUNTIME_ROOT": env.get("VULNOPS_RUNTIME_ROOT", str(scan.parent / "runtime")),
                   "VULNOPS_LAUNCHER_PID": str(os.getpid())}
    with patch.dict(os.environ, environment):
        claim_run(scan)
    return environment



class RunOwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.scan = self.root / "selected-run"
        self.scan.mkdir()
        self.env = {**os.environ, "PYTHONPATH": str(ROOT / "scripts"),
                    "VULNOPS_RUNTIME_ROOT": str(self.root / "runtime")}
        self.env.pop("VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID", None)
        self.env.pop("VULNOPS_LAUNCHER_SESSION_ID", None)

    def launcher(self):
        process = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def close():
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            process.stdin.close()
        self.addCleanup(close)
        return process

    def operation(self, name, launcher, session):
        code = (
            "import sys\nfrom pathlib import Path\n"
            f"from run_lifecycle import {name}\n"
            "try:\n"
            f"    {name}(Path(sys.argv[1]), sys.argv[2])\n"
            "except ValueError as error:\n"
            "    print(error, file=sys.stderr)\n    sys.exit(2)\n"
        )
        return subprocess.run([sys.executable, "-c", code, str(self.scan), session],
                              env={**self.env, "VULNOPS_LAUNCHER_PID": str(launcher.pid)},
                              capture_output=True, text=True, timeout=10)

    def test_claim_outlives_initializer_and_dead_launcher_can_be_replaced(self):
        owner, competitor = self.launcher(), self.launcher()
        first = self.operation("claim_run", owner, "first-session")
        self.assertEqual(first.returncode, 0, first.stderr)
        # The initializer exited, but its launcher is still alive.
        denied = self.operation("claim_run", competitor, "second-session")
        self.assertEqual(denied.returncode, 2)
        self.assertIn("active owner", denied.stderr)
        owner.terminate()
        owner.wait(timeout=5)
        resumed = self.operation("claim_run", competitor, "second-session")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)

    def test_foreign_cleanup_cannot_release_active_owner(self):
        owner, competitor = self.launcher(), self.launcher()
        self.assertEqual(self.operation("claim_run", owner, "first-session").returncode, 0)
        self.assertEqual(self.operation("release_run", competitor, "second-session").returncode, 0)
        denied = self.operation("assert_owner", competitor, "second-session")
        self.assertEqual(denied.returncode, 2)
        released = self.operation("release_run", owner, "first-session")
        self.assertEqual(released.returncode, 0, released.stderr)
        acquired = self.operation("claim_run", competitor, "second-session")
        self.assertEqual(acquired.returncode, 0, acquired.stderr)

    def test_simultaneous_claimants_cannot_both_own_one_run(self):
        owners = [self.launcher(), self.launcher()]
        code = ("import sys\nfrom pathlib import Path\nfrom run_lifecycle import claim_run\n"
                "sys.stdin.readline()\n"
                "try:\n    claim_run(Path(sys.argv[1]), sys.argv[2])\n"
                "except ValueError:\n    sys.exit(2)\n")
        processes = [subprocess.Popen(
            [sys.executable, "-c", code, str(self.scan), f"session-{index}"],
            env={**self.env, "VULNOPS_LAUNCHER_PID": str(owner.pid)},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) for index, owner in enumerate(owners)]
        try:
            for process in processes:
                process.stdin.write("claim\n")
                process.stdin.flush()
            outcomes = []
            for process in processes:
                _, error = process.communicate(timeout=10)
                self.assertFalse(error, error)
                outcomes.append(process.returncode)
            self.assertEqual(sorted(outcomes), [0, 2])
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()


class AttemptAssessmentTests(unittest.TestCase):
    def test_resume_keeps_old_assignment_but_rejects_forged_current_attribution(self):
        actor = "vulnops-deepdive-chunk"
        old_route = {"agents": {actor: "provider/old:high"}}
        new_route = {"agents": {actor: "provider/new:high"}}
        manifest = {"run_id": "run", "status": "failed", "model_routing": old_route,
                    "repositories": [{"path": "old-component"}], "phases": {"sast": "ok", "intrusion": "failed"}}
        context = {"model_routing": new_route, "repositories": [{"path": "current-component"}]}
        start_attempt(manifest, context)
        manifest["model_routing"] = new_route
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory)
            (scan / "run-manifest.json").write_text(json.dumps(manifest))
            provenance = {"actor": actor, "selector": "provider/old:high", "artifact_ref": "sast/deepdive/old.json"}
            retained = routing_for_artifact(scan, provenance["artifact_ref"], new_route)
            self.assertEqual(validate_provenance(provenance, retained), provenance)
            with self.assertRaisesRegex(ValueError, "assigned route"):
                validate_provenance(provenance, new_route)

    def test_publication_preserves_scope_without_reassessing_changed_checkout(self):
        manifest = {"run_id": "run", "status": "incomplete", "phases": {}}
        first = {"run_id": "run", "repositories": [{"path": "service", "commit": "reviewed"}],
                 "source_root": "/original"}
        start_attempt(manifest, first)
        finding = {"id": "F-001", "assessment_context": assessment_ref(first), "verdict": "confirmed"}
        self.assertTrue(current_assessment(finding, first))
        original = json.dumps(finding, sort_keys=True)
        manifest["phases"]["final-verification"] = "degraded"
        manifest["phase_attempts"]["final-verification"] = first["attempt_id"]
        resumed = {"run_id": "run", "repositories": [{"path": "replacement", "commit": "unreviewed"}],
                   "source_root": "/later"}
        start_attempt(manifest, resumed)
        self.assertIsNone(resumed["assessment_id"])
        assessment = report_assessment(resumed, [finding])
        self.assertTrue(assessment["retained"])
        self.assertEqual(assessment["record_scopes"]["F-001"], first["assessment_id"])
        self.assertEqual(assessment["scopes"][0]["repositories"], first["repositories"])
        self.assertEqual(assessment["scopes"][0]["source_root"], "/original")
        self.assertEqual(json.dumps(finding, sort_keys=True), original)
        for record, expected in ((finding, False), ({}, False),
                                 ({"assessment_context": assessment_ref(resumed)}, True)):
            with self.subTest(record=record):
                self.assertEqual(current_assessment(record, resumed), expected)

    def test_active_scope_cannot_be_forged_or_imported(self):
        manifest = {"run_id": "run", "status": "incomplete", "phases": {}}
        context = {"run_id": "run"}
        start_attempt(manifest, context)
        forged = {"assessment_context": {**assessment_ref(context), "assessment_id": "foreign"}}
        self.assertFalse(current_assessment(forged, context))
        with self.assertRaisesRegex(ValueError, "unknown accepted assessment"):
            report_assessment(context, [forged])
        foreign_scope = context["assessment_scopes"][context["assessment_id"]]
        foreign_scope["run_id"] = "other-run"
        with self.assertRaisesRegex(ValueError, "another execution"):
            report_assessment(context, [{"assessment_context": assessment_ref(context)}])

    def test_legacy_unknown_scope_never_uses_publishing_repositories(self):
        context = {"run_id": "run", "attempt_id": "publishing",
                   "repositories": [{"path": "not-reviewed"}],
                   "phase_attempts": {"final-verification": "old"},
                   "attempt_contexts": {"publishing": {"repositories": [{"path": "not-reviewed"}]}}}
        finding = {"id": "F-001", "assessment_context": {"attempt_id": "old"}}
        assessment = report_assessment(context, [finding])
        self.assertEqual(assessment["scopes"][0]["repositories"], [])
        self.assertIsNone(assessment["scopes"][0]["started_at"])
        self.assertIn("Original assessed repository scope is unavailable.", assessment["limitations"])

    def test_fresh_investigation_allocates_scope_without_overwriting_old_observations(self):
        manifest = {"run_id": "run", "status": "incomplete", "phases": {}}
        first = {"run_id": "run", "repositories": [{"path": "original"}]}
        start_attempt(manifest, first)
        manifest["phases"]["sast"] = "ok"
        manifest["phase_attempts"]["sast"] = first["attempt_id"]
        next_context = {"run_id": "run", "repositories": [{"path": "changed"}]}
        start_attempt(manifest, next_context)
        self.assertNotEqual(first["assessment_id"], next_context["assessment_id"])
        self.assertEqual(next_context["assessment_scopes"][first["assessment_id"]]["repositories"],
                         [{"path": "original"}])
        self.assertEqual(next_context["assessment_scopes"][next_context["assessment_id"]]["repositories"],
                         [{"path": "changed"}])

    def test_old_advantage_author_route_is_not_reinterpreted_by_current_mapping(self):
        from model_routing import GROUP_AGENTS, advantage_routing, resolve_routing, validate_routing
        groups = {group: "fixture/red:high" for group in GROUP_AGENTS}
        groups["advantage_lead"] = "fixture/astra:high"
        current = advantage_routing(resolve_routing({"routing": groups}))
        old = json.loads(json.dumps(current))
        old["agents"]["vulnops-advantage-synthesis"] = groups["advantage_lead"]
        with self.assertRaisesRegex(ValueError, "ownership"):
            validate_routing(old, "advantage")
        manifest = {"run_id": "advantage", "status": "incomplete",
                    "model_routing": old, "phases": {"synthesis": "ok"}}
        start_attempt(manifest, {"run_id": "advantage", "model_routing": current})
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory)
            (scan / "advantage-manifest.json").write_text(json.dumps(manifest))
            retained = routing_for_artifact(scan, "synthesis/findings.json", current)
            self.assertEqual(retained["agents"]["vulnops-advantage-synthesis"], "fixture/astra:high")
            self.assertEqual(current["controllers"]["advantage"], "fixture/astra:high")


if __name__ == "__main__":
    unittest.main()
