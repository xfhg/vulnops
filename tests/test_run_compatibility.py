from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from model_routing import GROUP_AGENTS
from run_lifecycle import AUDIT_PHASE_DIRS, release_run
from test_codegraph_callers import assert_process_stopped, prepare_graph_fixture, stop_process, wait_for_file

spec = importlib.util.spec_from_file_location("audit_resume", ROOT / "scripts/resume-run.py")
RESUME = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RESUME)


class RunCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.target = self.root / "source"
        self.target.mkdir()
        (self.target / "app.py").write_text("old source\n")
        self.scan = self.root / "scans/application/runs/old"
        self.context = self.root / "context.json"
        self.routes = {group: "p/model:high" for group in GROUP_AGENTS}
        self.write_config()
        self.env = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.context), "VULNOPS_RUNTIME_ROOT": str(self.root / ".harness"), "VULNOPS_LAUNCHER_PID": str(os.getpid()), "VULNOPS_LAUNCHER_SESSION_ID": "fixture"}
        self.depth = "balanced"
        self.commit = "abc"
        self.initialize()

    def write_config(self):
        (self.root / "config.toml").write_text("[llm.routing]\n" + "".join(f'{key} = "{value}"\n' for key, value in self.routes.items()))

    def command(self, script, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, args)], capture_output=True, text=True, env=self.env)

    def initialization_args(self, resume=False, inventory=None, options=(), run_id="old"):
        args = ["--harness-root", self.root, "--repo-path", self.target, "--scan-base", self.scan, "--run-id", run_id, "--repo-name", "fixture", "--remote-url", "fixture", "--repo-id", "fixture", "--commit", self.commit, "--depth", self.depth, "--reproduction-mode", "off", "--codegraph-mode", "disabled", "--network-mode", "policy_only"]
        if resume:
            args.append("--resume")
        if inventory:
            args.extend(["--repositories-file", inventory])
        args.extend(options)
        return args

    def initialize(self, resume=False, inventory=None, options=(), run_id="old"):
        args = self.initialization_args(resume, inventory, options, run_id)
        result = self.command("init-run.py", *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def select(self, *options):
        return self.command("resume-run.py", self.context, *options)

    def release(self):
        with patch.dict(os.environ, self.env, clear=True):
            release_run(self.scan)

    def test_legacy_resume_does_not_retrofit_optional_phase_or_path(self):
        path = self.scan / "run-manifest.json"
        manifest = json.loads(path.read_text())
        del manifest["phases"]["gap-exploration"]
        manifest.pop("gap_exploration_budget")
        path.write_text(json.dumps(manifest))
        selected = self.select()
        self.assertEqual(selected.returncode, 0, selected.stderr)
        context = self.initialize(True)
        self.assertNotIn("gap-exploration", json.loads(path.read_text())["phases"])
        self.assertNotIn("gap_exploration", context["paths"])
        self.assertNotIn("gap_exploration_budget", context)
        self.assertNotIn("gap-exploration", context["orchestration"]["phase_timeout_seconds"])

    def test_explicit_disable_is_recorded_without_changing_original_allowances(self):
        old = json.loads(self.context.read_text())
        with (self.root / "config.toml").open("a") as stream:
            stream.write("\n[harness.scans.gap_exploration]\nenabled = false\n")
        current = self.initialize(True)
        self.assertFalse(current["gap_exploration_budget"]["enabled"])
        for key in ("sast_budget", "intrusion_budget", "experiment_budget"):
            self.assertEqual(current[key], old[key])
        self.assertEqual(current["orchestration"], old["orchestration"])

    def test_lower_gap_limits_preserve_prior_attempt_allowance(self):
        old = json.loads(self.context.read_text())
        manifest = json.loads((self.scan / "run-manifest.json").read_text())
        self.assertEqual(manifest["phases"]["gap-exploration"], "pending")
        self.assertEqual(old["paths"]["gap_exploration"], str(self.scan / "gap-exploration"))
        self.assertEqual(old["gap_exploration_budget"]["max_tasks"], 4)
        self.assertEqual(old["orchestration"]["phase_timeout_seconds"]["gap-exploration"], 2700)
        self.assertEqual(manifest["attempt_contexts"][old["attempt_id"]]["gap_exploration_budget"],
                         old["gap_exploration_budget"])
        # Seed accepted predecessors; consume the optional coordinator allowance
        # through real start/failure commands before the policy is lowered.
        for phase in AUDIT_PHASE_DIRS:
            if phase == "gap-exploration":
                break
            manifest["phases"][phase] = "ok"
        (self.scan / "run-manifest.json").write_text(json.dumps(manifest))
        task_args = (self.scan, "--phase", "gap-exploration",
                     "--task", "GapExploration", "--task-phase", "gap-exploration")
        started = self.command("update-run-state.py", *task_args, "--phase-status", "running", "--increment-attempt")
        self.assertEqual(started.returncode, 0, started.stderr)
        failed = self.command("update-run-state.py", *task_args, "--phase-status", "failed",
                              "--error", "Fixture coordinator interrupted before publication")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        ledger_before = (self.scan / "task-ledger.json").read_bytes()
        with (self.root / "config.toml").open("a") as stream:
            stream.write("\n[harness.scans.gap_exploration.budget.balanced]\nmax_tasks = 1\nmax_attempts = 1\n")
        current = self.initialize(True)
        self.assertEqual(current["gap_exploration_budget"]["max_tasks"], 1)
        self.assertEqual(current["gap_exploration_budget"]["max_candidates"], 2)
        self.assertEqual(current["attempt_contexts"][old["attempt_id"]]["gap_exploration_budget"], old["gap_exploration_budget"])
        self.assertEqual((self.scan / "task-ledger.json").read_bytes(), ledger_before)
        exhausted = self.command("update-run-state.py", *task_args, "--phase-status", "running", "--increment-attempt")
        self.assertNotEqual(exhausted.returncode, 0)
        self.assertIn("top-level task attempt limit is 1", exhausted.stderr)
        self.assertEqual((self.scan / "task-ledger.json").read_bytes(), ledger_before)

    def test_removed_selected_directory_starts_new_initialization(self):
        shutil.rmtree(self.scan)
        selected = self.select()
        self.assertEqual((selected.returncode, selected.stdout), (0, ""), selected.stderr)
        self.assertIn("no longer exists", selected.stderr)
        self.assertEqual(len(selected.stderr.splitlines()), 1)
        self.assertLess(len(selected.stderr), 200)
        self.assertFalse(self.context.exists())
        self.assertFalse(self.scan.exists())
        self.scan = self.scan.parent / "new"
        current = self.initialize(run_id="new")
        self.assertEqual(current["run_id"], "new")
        self.assertEqual(json.loads(self.context.read_text())["scan_base"], str(self.scan))

    def test_fresh_preserves_old_artifacts_and_initializes_new_inventory(self):
        self.release()
        old_scan = self.scan
        evidence = old_scan / "retained.json"
        evidence.write_text('{"evidence":"keep"}\n')
        before = {path: path.read_bytes() for path in old_scan.rglob("*") if path.is_file()}
        original_context = self.context.read_bytes()
        self.env["VULNOPS_LAUNCHER_SESSION_ID"] = "new-launcher"
        self.target = self.root / "new-source"
        self.target.mkdir()
        (self.target / "service.py").write_text("new application\n")
        inventory = self.root / "new-inventory.json"
        repositories = [{"name": "replacement", "path": ".", "remote_url": "new", "commit": "def"}]
        self.commit = "def"
        inventory.write_text(json.dumps({"source_root": str(self.target), "application_name": "fixture", "application_id": "fixture", "revision": self.commit, "remote_url": "fixture", "repositories": repositories}))
        selected = self.select("--fresh")
        self.assertEqual((selected.returncode, selected.stdout), (0, ""), selected.stderr)
        self.assertEqual(self.context.read_bytes(), original_context)
        self.scan = self.root / "scans/replacement/runs/new"
        current = self.initialize(inventory=inventory, run_id="new")
        self.assertEqual(current["repositories"], repositories)
        self.assertEqual(current["source_root"], str(self.target))
        self.assertEqual(current["run_id"], "new")
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        self.assertEqual({path for path in old_scan.rglob("*") if path.is_file()}, set(before))
        for _ in range(2):
            selected = self.select("--fresh")
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(selected.stdout.strip().split("\t"), ["new", str(self.scan), "resume"])
            self.initialize(resume=True, inventory=inventory, run_id="new")
        self.assertEqual([path.name for path in self.scan.parent.iterdir()], ["new"])

    def test_fresh_requires_both_launcher_session_and_live_ownership(self):
        self.release()
        before = self.context.read_bytes()
        with self.subTest(case="matching session without live ownership"):
            selected = self.select("--fresh")
            self.assertEqual((selected.returncode, selected.stdout), (0, ""), selected.stderr)
            self.assertEqual(self.context.read_bytes(), before)
        with self.subTest(case="owned run without launcher session"):
            self.env.pop("VULNOPS_LAUNCHER_SESSION_ID")
            self.initialize(resume=True)
            before = self.context.read_bytes()
            selected = self.select("--fresh")
            self.assertEqual((selected.returncode, selected.stdout), (0, ""), selected.stderr)
            self.assertEqual(self.context.read_bytes(), before)

    def test_fresh_can_abandon_missing_or_corrupt_manifest_without_changing_it(self):
        self.release()
        self.env["VULNOPS_LAUNCHER_SESSION_ID"] = "fresh-launcher"
        manifest = self.scan / "run-manifest.json"
        for contents in (None, b"not JSON"):
            with self.subTest(contents=contents):
                if contents is None:
                    manifest.unlink()
                else:
                    manifest.write_bytes(contents)
                before = self.context.read_bytes()
                selected = self.select("--fresh")
                self.assertEqual((selected.returncode, selected.stdout), (0, ""), selected.stderr)
                self.assertEqual(self.context.read_bytes(), before)
                self.assertEqual(manifest.read_bytes() if manifest.exists() else None, contents)

    def test_foreign_live_owner_blocks_fresh_even_with_missing_manifest(self):
        manifest = self.scan / "run-manifest.json"
        manifest.unlink()
        before = self.context.read_bytes()
        self.env["VULNOPS_LAUNCHER_SESSION_ID"] = "competitor"
        selected = self.select("--fresh")
        self.assertNotEqual(selected.returncode, 0)
        self.assertEqual(selected.stdout, "")
        self.assertIn("another active session", selected.stderr)
        self.assertEqual(self.context.read_bytes(), before)
        self.assertFalse(manifest.exists())

    def test_unsafe_selection_is_not_treated_as_removed_or_fresh(self):
        context = json.loads(self.context.read_text())
        link = self.scan.parent / "linked"
        dangling = self.scan.parent / "dangling"
        link.symlink_to(self.scan, target_is_directory=True)
        dangling.symlink_to(self.scan.parent / "absent", target_is_directory=True)
        linked_parent = self.root / "scans/linked-parent"
        linked_parent.symlink_to(self.scan.parent, target_is_directory=True)
        regular = self.scan.parent / "file"
        regular.write_text("not a directory")
        for selected in (link, dangling, linked_parent / "absent", regular,
                         self.root / "outside", self.root / "scans/../outside"):
            for options in ((), ("--fresh",)):
                with self.subTest(selected=selected, options=options):
                    context["scan_base"] = str(selected)
                    self.context.write_text(json.dumps(context))
                    result = self.select(*options)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("no longer exists", result.stderr)

    def test_symlinked_context_or_manifest_is_not_resumed(self):
        for path in (self.context, self.scan / "run-manifest.json"):
            with self.subTest(path=path):
                contents = path.read_bytes()
                saved = path.with_suffix(".saved")
                path.rename(saved)
                path.symlink_to(saved)
                result = self.select()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("unsafe audit record", result.stderr)
                path.unlink()
                path.write_bytes(contents)

    def test_inaccessible_selected_directory_is_not_treated_as_removed(self):
        original_lstat = Path.lstat

        def inaccessible(path, *args, **kwargs):
            if path == self.scan:
                raise PermissionError("fixture directory is inaccessible")
            return original_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", inaccessible):
            with self.assertRaisesRegex(PermissionError, "inaccessible"):
                RESUME.selected_directory(str(self.scan), self.root)

    def test_source_routing_budget_and_membership_changes_resume_same_checkpoints(self):
        old = json.loads(self.context.read_text())
        prefix = self.scan / "repo-context/record.json"
        prefix.parent.mkdir()
        prefix.write_text('{"historical": true}\n')
        manifest_path = self.scan / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["phases"]["recon"] = "ok"
        manifest_path.write_text(json.dumps(manifest))
        ledger_path = self.scan / "task-ledger.json"
        ledger = json.loads(ledger_path.read_text())
        ledger["tasks"] = [{"id": "Recon", "phase": "recon", "status": "ok", "attempts": 1, "artifact": "repo-context/record.json", "error": None, "updated_at": "before", "attempt_id": old["attempt_id"]}]
        ledger_path.write_text(json.dumps(ledger))
        before = prefix.read_bytes()
        (self.target / "app.py").write_text("changed source\n")
        (self.target / "new-component").mkdir()
        self.routes["recon"] = "p/other:xhigh"
        self.write_config()
        self.depth, self.commit = "quick", "def"
        inventory = self.root / "inventory.json"
        repositories = [{"name": "new", "path": "new-component", "remote_url": "new", "commit": "new"}]
        inventory.write_text(json.dumps({"source_root": str(self.target), "application_name": "fixture", "application_id": "fixture", "revision": self.commit, "remote_url": "fixture", "repositories": repositories}))
        selected = self.select()
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(selected.stdout.strip().split("\t")[:2], ["old", str(self.scan)])
        current = self.initialize(True, inventory)
        self.assertEqual(current["run_id"], old["run_id"])
        self.assertNotEqual(current["attempt_id"], old["attempt_id"])
        self.assertEqual(current["repositories"], repositories)
        self.assertEqual(current["model_routing"]["groups"]["recon"], "p/other:xhigh")
        self.assertEqual(current["attempt_contexts"][old["attempt_id"]]["model_routing"], old["model_routing"])
        self.assertEqual(prefix.read_bytes(), before)
        self.assertEqual(json.loads(manifest_path.read_text())["phases"]["recon"], "ok")

    def test_legacy_failed_identity_fields_are_inert(self):
        path = self.scan / "run-manifest.json"
        manifest = json.loads(path.read_text())
        manifest.update(status="failed", target_fingerprint="obsolete", artifact_compatibility_id="old", phase_seals={"recon": {"invalid": True}})
        path.write_text(json.dumps(manifest))
        selected = self.select()
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertTrue(selected.stdout.startswith("old\t"))
        self.initialize(True)
        self.assertEqual(json.loads(path.read_text())["status"], "incomplete")

    def test_selected_missing_or_malformed_records_name_input_without_replacement(self):
        manifest = self.scan / "run-manifest.json"
        original = manifest.read_bytes()
        for data in (None, b"not JSON", b'{"run_id":"old"}'):
            if data is None:
                manifest.unlink()
            else:
                manifest.write_bytes(data)
            result = self.select()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertTrue("run-manifest.json" in result.stderr or "status" in result.stderr)
            manifest.write_bytes(original)
        self.assertEqual([path.name for path in self.scan.parent.iterdir()], ["old"])

    def test_completed_selection_is_read_only_and_not_reopened(self):
        manifest = self.scan / "run-manifest.json"
        document = json.loads(manifest.read_text())
        document.update(status="complete", harness_contract_sha256="obsolete")
        manifest.write_text(json.dumps(document))
        before = {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()}
        self.release()
        for options in ((), ("--fresh",)):
            with self.subTest(options=options):
                selected = self.select(*options)
                self.assertEqual((selected.returncode, selected.stdout), (0, ""), selected.stderr)
                self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_ordinary_resume_does_not_persist_or_require_prior_report_selection(self):
        prior = self.scan.parent / "prior"
        (prior / "report").mkdir(parents=True)
        (prior / "run-manifest.json").write_text(json.dumps({"run_id": "prior", "status": "complete", "target_fingerprint": "obsolete", "repositories": []}))
        report = prior / "report/security-report.json"
        report.write_text('{"historical": true}\n')
        before = report.read_bytes()
        manifest_path = self.scan / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["prior_reports"] = [{"path": str(report), "run_id": "prior"}]
        manifest_path.write_text(json.dumps(manifest))
        (self.target / "app.py").write_text("changed after the historical report\n")
        current = self.initialize(True)
        self.assertNotIn("prior_reports", current)
        self.assertNotIn("prior_reports", json.loads(manifest_path.read_text()))
        self.assertEqual(report.read_bytes(), before)
        report.unlink()
        current = self.initialize(True)
        self.assertNotIn("prior_reports", current)
        self.assertNotIn("prior_reports", json.loads(manifest_path.read_text()))

    def test_optional_failure_without_diagnostic_receipt_still_publishes(self):
        prepare_graph_fixture(self.root)
        (self.root / "scripts/setup-codegraph.sh").write_text("#!/bin/bash\nexit 1\n")
        current = self.initialize(True, options=("--codegraph-mode", "enabled", "--prepare-codegraph"))
        self.assertEqual(current["codegraph_mode"], "disabled")
        self.assertEqual(current["codegraph_limitation"],
                         "Codegraph preparation failed; graph-assisted coverage was not performed.")

    def test_real_graph_timeout_publishes_selected_current_session_once(self):
        prepare_graph_fixture(self.root)
        foreign_context = self.context.read_bytes()
        self.scan = self.scan.parent / "current"
        ready = self.root / "graph-ready"
        self.env.update(CALLER_GRAPH_MODE="wait", CALLER_GRAPH_READY=str(ready),
                        CODEGRAPH_INIT_TIMEOUT_SECONDS="3", VULNOPS_LAUNCHER_SESSION_ID="current-session")
        started = time.monotonic()
        current = self.initialize(options=("--codegraph-mode", "enabled", "--prepare-codegraph"), run_id="current")
        self.assertLess(time.monotonic() - started, 15)
        self.assertNotEqual(self.context.read_bytes(), foreign_context)
        self.assertEqual(json.loads(self.context.read_text()), current)
        self.assertEqual(current["run_id"], "current")
        self.assertEqual(current["launcher_session_id"], "current-session")
        self.assertEqual(current["codegraph_mode"], "disabled")
        self.assertIn("timeout", current["codegraph_limitation"])
        manifest = json.loads((self.scan / "run-manifest.json").read_text())
        ledger = json.loads((self.scan / "task-ledger.json").read_text())
        self.assertEqual(manifest["run_id"], "current")
        self.assertEqual(manifest["status"], "incomplete")
        self.assertEqual(len(manifest["attempt_contexts"]), 1)
        self.assertEqual(ledger["tasks"], [])
        self.assertTrue(all(value == "pending" for value in manifest["phases"].values()))
        runtime = self.root / ".harness/codegraph/current"
        self.assertFalse((runtime / "project").exists())
        self.assertEqual(json.loads((runtime / "index-receipt.json").read_text())["status"], "failed")
        self.assertTrue(ready.exists(), "real indexer never started")
        assert_process_stopped(int(ready.read_text()))
        time.sleep(.1)
        self.assertFalse((runtime / "project").exists())
        self.assertEqual((self.target / "app.py").read_text(), "old source\n")

    def test_real_optional_failure_preserves_resume_identity_records_and_attempts(self):
        prepare_graph_fixture(self.root)
        old_context = json.loads(self.context.read_text())
        manifest_path = self.scan / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["phases"]["recon"] = "ok"
        manifest["phase_attempts"]["recon"] = old_context["attempt_id"]
        manifest_path.write_text(json.dumps(manifest))
        accepted = self.scan / "repo-context/accepted.json"
        accepted.parent.mkdir(exist_ok=True)
        accepted.write_text('{"accepted":"preserved"}\n')
        ledger_path = self.scan / "task-ledger.json"
        ledger = json.loads(ledger_path.read_text())
        ledger["tasks"] = [
            {"id": "Recon", "phase": "recon", "status": "ok", "attempts": 2,
             "artifact": "repo-context/accepted.json", "attempt_id": old_context["attempt_id"]},
            {"id": "ToolCollection", "phase": "tool-collection", "status": "failed", "attempts": 2},
        ]
        ledger_path.write_text(json.dumps(ledger))
        accepted_bytes = accepted.read_bytes()
        self.env["CALLER_GRAPH_MODE"] = "fail"
        runtime = self.root / ".harness/codegraph/old/project"
        runtime.mkdir(parents=True)
        (runtime / "stale-index").write_text("previous attempt")
        selected = self.select()
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(selected.stdout.strip().split("\t")[:2], ["old", str(self.scan)])
        current = self.initialize(True, options=("--codegraph-mode", "enabled", "--prepare-codegraph"))
        self.assertEqual(current["run_id"], "old")
        self.assertEqual(current["scan_base"], str(self.scan))
        self.assertEqual(current["codegraph_mode"], "disabled")
        self.assertIn("preparation failed", current["codegraph_limitation"])
        self.assertIn("exit 9", current["codegraph_limitation"])
        self.assertEqual(json.loads(manifest_path.read_text())["codegraph_mode"], "disabled")
        self.assertFalse(runtime.exists())
        self.assertEqual(json.loads(ledger_path.read_text()), ledger)
        self.assertEqual(accepted.read_bytes(), accepted_bytes)
        resumed = json.loads(manifest_path.read_text())
        self.assertEqual(resumed["phases"]["recon"], "ok")
        self.assertEqual(resumed["phase_attempts"]["recon"], old_context["attempt_id"])
        self.assertEqual(resumed["attempt_contexts"][old_context["attempt_id"]], manifest["attempt_contexts"][old_context["attempt_id"]])
        self.assertEqual([path.name for path in self.scan.parent.iterdir()], ["old"])

    def test_initialization_failures_never_replace_foreign_context_or_publish_run(self):
        prepare_graph_fixture(self.root)
        foreign = self.context.read_bytes()
        parent = self.scan.parent
        for cause in ("fatal-graph", "invalid-config"):
            with self.subTest(cause=cause):
                self.scan = parent / cause
                if cause == "fatal-graph":
                    self.env.update(CODEGRAPH_INIT_TIMEOUT_SECONDS="nan",
                                    VULNOPS_LAUNCHER_SESSION_ID="rejected-session")
                    options = ("--codegraph-mode", "enabled", "--prepare-codegraph")
                else:
                    (self.root / "config.toml").write_text("[invalid\n")
                    options = ()
                result = self.command("init-run.py", *self.initialization_args(options=options, run_id=cause))
                if cause == "fatal-graph":
                    self.assertEqual(result.returncode, 2, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(self.context.read_bytes(), foreign)
                self.assertFalse((self.scan / "run-manifest.json").exists())
                self.assertFalse((self.scan / "task-ledger.json").exists())

    def test_initializer_cancellation_preserves_unpublished_selected_run(self):
        prepare_graph_fixture(self.root)
        original_scan = self.scan
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                foreign = self.context.read_bytes()
                run_id = f"cancel-{sig}"
                self.scan = original_scan.parent / run_id
                ready = self.root / f"ready-{sig}"
                environment = {**self.env, "CALLER_GRAPH_MODE": "wait", "CALLER_GRAPH_READY": str(ready),
                               "CODEGRAPH_INIT_TIMEOUT_SECONDS": "30"}
                args = self.initialization_args(options=("--codegraph-mode", "enabled", "--prepare-codegraph"), run_id=run_id)
                process = subprocess.Popen([sys.executable, str(ROOT / "scripts/init-run.py"), *map(str, args)],
                    env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.addCleanup(stop_process, process)
                wait_for_file(ready, process)
                process.send_signal(sig)
                stdout, stderr = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 128 + sig, stderr)
                self.assertEqual(stdout, "")
                self.assertEqual(self.context.read_bytes(), foreign)
                self.assertFalse((self.scan / "run-manifest.json").exists())
                self.assertFalse((self.scan / "task-ledger.json").exists())
                runtime = self.root / ".harness/codegraph" / run_id
                self.assertFalse((runtime / "project").exists())
                assert_process_stopped(int(ready.read_text()))
                time.sleep(.1)
                self.assertFalse((runtime / "project").exists())

    def test_disabled_and_report_only_initialization_bypass_real_setup(self):
        prepare_graph_fixture(self.root)
        self.env["CODEGRAPH_INIT_TIMEOUT_SECONDS"] = "nan"
        disabled = self.initialize(True, options=("--prepare-codegraph",))
        self.assertEqual(disabled["codegraph_mode"], "disabled")
        manifest_path = self.scan / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["phases"]["final-verification"] = "ok"
        manifest_path.write_text(json.dumps(manifest))
        current = self.initialize(True, options=("--codegraph-mode", "enabled", "--prepare-codegraph"))
        self.assertEqual(current["phases"]["final-verification"], "ok")
        self.assertFalse((self.root / ".harness/codegraph/old").exists())


if __name__ == "__main__":
    unittest.main()
