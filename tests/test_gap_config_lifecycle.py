from __future__ import annotations

import argparse
import copy
import importlib.util
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
from harness_contract import (DEFAULT_GAP_EXPLORATION_BUDGETS, resolve_gap_exploration_budget,
                              resolved_gap_exploration_budget)
from model_routing import GROUP_AGENTS, audit_routing, advantage_routing, resolve_routing, validate_routing
from run_lifecycle import AUDIT_PHASE_DIRS, AUDIT_TASK_PHASES


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


UPDATER = module("gap_lifecycle_updater", "update-run-state.py")
RECOVERY = module("gap_lifecycle_recovery", "recover-run.py")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class GapBudgetTests(unittest.TestCase):
    def config(self, settings):
        return {"harness": {"scans": {"gap_exploration": settings}}}


    def test_lower_limits_and_explicit_disable(self):
        config = self.config({"enabled": False, "budget": {"full": {"max_tasks": 1, "max_questions": 0, "max_attempts": 1}}})
        result = resolve_gap_exploration_budget(config, "full")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["max_candidates"], 2)
        self.assertEqual(result["max_questions"], 0)
        self.assertEqual(result["max_attempts"], 1)

    def test_strict_configuration_checks_all_depths(self):
        cases = [True, {"enabled": "false"}, {"enabled": 1}, {"unknown": 1},
                 {"budget": []}, {"budget": {"deep": {}}}, {"budget": {"full": []}}]
        for key in DEFAULT_GAP_EXPLORATION_BUDGETS["quick"]:
            for bad in (True, -1, 1.5, "2", 2147484):
                cases.append({"budget": {"full": {key: bad}}})
        cases.extend([{"budget": {"quick": {"max_attempts": 3}}},
                      {"budget": {"quick": {"max_tasks": 1, "max_candidates": 3}}},
                      {"budget": {"quick": {"other": 1}}}])
        for settings in cases:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                resolve_gap_exploration_budget(self.config(settings), "quick")

    def test_file_resolver_and_shell_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            routes = "\n".join(f'{key} = "fixture/{key}:high"' for key in GROUP_AGENTS)
            (root / "config.toml").write_text(
                '[llm.routing]\n' + routes +
                '\n[harness.scans.gap_exploration]\nenabled = false\n'
                '[harness.scans.gap_exploration.budget.quick]\nmax_tasks = 1\nmax_questions = 0\n'
                '[harness.advantage.budget.full]\ndeep_passes = 16\n')
            result = subprocess.run([sys.executable, str(ROOT / "scripts/parse-config.py"), str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Evaluate exactly as the shell launcher does, then decode the exported JSON.
            consumed = subprocess.run(
                ["bash", "-c", result.stdout + '\nprintf "%s" "$VULNOPS_GAP_EXPLORATION_BUDGETS"'],
                capture_output=True, text=True)
            self.assertEqual(consumed.returncode, 0, consumed.stderr)
            budgets = json.loads(consumed.stdout)
            self.assertEqual(set(budgets), {"quick", "balanced", "full"})
            for depth, tasks, questions, candidates in (
                    ("quick", 1, 0, 2), ("balanced", 4, 8, 8), ("full", 8, 12, 16)):
                with self.subTest(depth=depth):
                    self.assertFalse(budgets[depth]["enabled"])
                    self.assertEqual(budgets[depth]["max_tasks"], tasks)
                    self.assertEqual(budgets[depth]["max_questions"], questions)
                    self.assertEqual(budgets[depth]["max_candidates"], candidates)
                    self.assertEqual(budgets[depth], resolved_gap_exploration_budget(root, depth))

    def test_routes_are_exact_and_missing_actor_cannot_fallback(self):
        groups = {group: f"fixture/{group}:high" for group in GROUP_AGENTS}
        routing = resolve_routing({"routing": groups})
        for scope, scoped, prefix, group in (("audit", audit_routing(routing), "vulnops-", "intrusion"),
                                             ("advantage", advantage_routing(routing), "vulnops-advantage-", "advantage")):
            for suffix in ("gap-exploration", "gap-investigator"):
                actor = prefix + suffix
                self.assertEqual(scoped["agents"][actor], groups[group])
                missing = copy.deepcopy(scoped)
                del missing["agents"][actor]
                with self.assertRaises(ValueError):
                    validate_routing(missing, scope)



class GapLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.scan = self.base / "run"
        self.scan.mkdir()
        self.context_path = self.base / "context.json"
        self.budget = resolve_gap_exploration_budget({}, "quick")
        phases = {phase: "ok" if index < 5 else "failed" if index == 5 else "pending"
                  for index, phase in enumerate(AUDIT_PHASE_DIRS)}
        self.manifest = {"run_id": "r", "status": "incomplete", "attempt_id": "attempt", "phases": phases,
                         "gap_exploration_budget": self.budget, "recovery_history": []}
        self.task = {"id": "GapExploration", "phase": "gap-exploration", "status": "failed", "attempts": 2,
                     "artifact": None, "error": "coordinator timeout", "failure_kind": "deadline_exceeded",
                     "attempt_id": "attempt", "failure_history": [{"attempt": 2, "attempt_id": "attempt", "kind": "deadline_exceeded", "error": "coordinator timeout"}]}
        self.ledger = {"run_id": "r", "tasks": [self.task]}
        self.context = {"run_id": "r", "attempt_id": "attempt", "scan_base": str(self.scan), "gap_exploration_budget": self.budget}
        self.publish()
        self.args = argparse.Namespace(phase="gap-exploration", task="GapExploration", task_phase="gap-exploration",
                                      context=self.context_path, phase_status=None, phase_manifest=None, run_status=None,
                                      task_status=None, artifact=None, error=None, failure_kind=None, increment_attempt=False)

    def publish(self):
        write(self.scan / "run-manifest.json", self.manifest)
        write(self.scan / "task-ledger.json", self.ledger)
        write(self.context_path, self.context)

    def close(self):
        return UPDATER.close_optional_failure(self.scan, self.manifest, self.ledger, self.args, argparse.ArgumentParser())


    def test_closure_rejects_other_phases_unexhausted_and_running_work(self):
        for change in ("other_phase", "attempts", "running", "integrity", "predecessor", "identity"):
            with self.subTest(change=change):
                original_manifest, original_task = copy.deepcopy(self.manifest), copy.deepcopy(self.task)
                if change == "other_phase":
                    self.args.phase = "intrusion"
                    self.task["optional_closure"] = {
                        "phase": "gap-exploration", "status": "degraded",
                        "artifact": "gap-exploration/results.json", "failure_reason": self.task["error"]}
                if change == "attempts": self.task["attempts"] = 1
                if change == "running": self.manifest["phases"]["synthesis"] = "running"
                if change == "integrity": self.task["failure_kind"] = None
                if change == "predecessor": self.manifest["phases"]["intrusion"] = "failed"
                if change == "identity": self.context["attempt_id"] = "foreign"; write(self.context_path, self.context)
                with self.assertRaises(SystemExit): self.close()
                self.manifest = original_manifest
                self.task.clear(); self.task.update(original_task)
                self.args.phase = "gap-exploration"
                self.context["attempt_id"] = "attempt"; write(self.context_path, self.context)

    def test_redirected_and_unreadable_controls_remain_fatal(self):
        alternate = self.base / "matching-context.json"
        write(alternate, self.context)
        before = {name: (self.scan / name).read_bytes() for name in ("run-manifest.json", "task-ledger.json")}
        self.context_path.unlink()
        self.context_path.symlink_to(alternate)
        with self.assertRaises(SystemExit): self.close()
        self.assertEqual(json.loads(alternate.read_text()), self.context)
        self.context_path.unlink(); self.context_path.write_text("not json")
        with self.assertRaises(SystemExit): self.close()
        self.assertEqual({name: (self.scan / name).read_bytes() for name in before}, before)
        with self.assertRaises(ValueError): RECOVERY.work_path(self.scan, "gap-exploration", "intrusion/results/peer.json")


    def transition(self, phase, *options):
        identity = next(identity for identity, owner in AUDIT_TASK_PHASES.items() if owner == phase)
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts/update-run-state.py"), str(self.scan),
             "--phase", phase, "--task", identity, "--task-phase", phase, *options],
            capture_output=True, text=True,
            env={**os.environ, "VULNOPS_RUNTIME_ROOT": str(self.base / "runtime"),
                 "VULNOPS_LAUNCHER_PID": str(os.getpid()), "VULNOPS_LAUNCHER_SESSION_ID": "gap-fixture"},
        )

    def test_real_updater_enforces_predecessor_and_stable_attempt_limit(self):
        self.task["attempts"] = 1
        self.publish()
        self.manifest["phases"]["intrusion"] = "failed"
        self.publish()
        denied = self.transition("gap-exploration", "--phase-status", "running", "--increment-attempt")
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("prior phase", denied.stderr)
        self.manifest["phases"]["intrusion"] = "ok"
        self.publish()
        started = self.transition("gap-exploration", "--phase-status", "running", "--increment-attempt")
        self.assertEqual(started.returncode, 0, started.stderr)
        competing = self.transition("synthesis", "--phase-status", "running", "--increment-attempt")
        self.assertNotEqual(competing.returncode, 0)
        self.assertIn("active phase", competing.stderr)
        failed = self.transition("gap-exploration", "--phase-status", "failed", "--error", "worker exhausted",
                                 "--failure-kind", "execution_failed")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        ledger = json.loads((self.scan / "task-ledger.json").read_text())
        self.assertEqual(ledger["tasks"][0]["attempts"], 2)
        self.assertEqual(ledger["tasks"][0]["failure_history"][-1]["error"], "worker exhausted")
        exhausted = self.transition("gap-exploration", "--phase-status", "running", "--increment-attempt")
        self.assertNotEqual(exhausted.returncode, 0)
        self.assertIn("attempt limit", exhausted.stderr)

    def test_legacy_updater_cannot_start_unowned_phase(self):
        del self.manifest["phases"]["gap-exploration"]
        self.ledger["tasks"] = []
        self.publish()
        denied = self.transition("gap-exploration", "--phase-status", "running", "--increment-attempt")
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("not owned", denied.stderr)
        started = self.transition("synthesis", "--phase-status", "running", "--increment-attempt")
        self.assertEqual(started.returncode, 0, started.stderr)
        manifest = json.loads((self.scan / "run-manifest.json").read_text())
        self.assertEqual(manifest["phases"]["synthesis"], "running")
        self.assertNotIn("gap-exploration", manifest["phases"])


    def test_recovery_rejects_redirected_retained_output(self):
        import gap_exploration_contract as gap
        outside = self.base / "outside"
        outside.mkdir()
        (self.scan / "gap-exploration").symlink_to(outside, target_is_directory=True)
        with patch.object(gap, "recovery_checkpoint") as checkpoint, self.assertRaises(ValueError):
            RECOVERY.unfinished_work(self.scan, "gap-exploration", self.context)
        checkpoint.assert_not_called()



if __name__ == "__main__":
    unittest.main()
