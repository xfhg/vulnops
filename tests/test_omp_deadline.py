from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/set-omp-deadline.py"
spec = importlib.util.spec_from_file_location("omp_deadline", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.path.insert(0, str(ROOT / "scripts"))
from harness_contract import resolved_recon_timeout
from model_routing import GROUP_AGENTS


class DeadlineTests(unittest.TestCase):
    def test_recon_configuration_and_repository_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.toml"
            config.write_text("")
            for depth, expected in (("quick", 1800), ("balanced", 2700), ("full", 5400)):
                self.assertEqual(resolved_recon_timeout(root, depth, 1), expected)
                self.assertEqual(resolved_recon_timeout(root, depth, 12), max(expected, 4200))
            config.write_text("[harness.scans.recon.timeout_seconds]\nbalanced = 3600\n")
            self.assertEqual(resolved_recon_timeout(root, "balanced", 1), 3600)
            self.assertEqual(resolved_recon_timeout(root, "balanced", 12), 4200)
            for invalid in ("0", "-1", "true", '"2700"', "1.5", "inf", "2147484"):
                config.write_text(f"[harness.scans.recon.timeout_seconds]\nbalanced = {invalid}\n")
                with self.assertRaises(ValueError):
                    resolved_recon_timeout(root, "balanced", 1)
            for invalid in (
                "[harness.scans.recon.timeout_seconds]\nbalnced = 2700\n",
                "[harness.scans.recon]\ntimeout_seconds = 2700\n",
                "[harness.scans.recon]\ntimeout_second = 2700\n",
            ):
                config.write_text(invalid)
                with self.assertRaises(ValueError):
                    resolved_recon_timeout(root, "balanced", 1)

    def test_phase_depth_and_remediation_deadlines_reject_invalid_values(self):
        context = {"depth": "full", "orchestration": {
            "phase_timeout_seconds": {"recon": 900, "sast": {"quick": 3600, "full": 14400}},
            "timeout_seconds": 7200,
        }}
        self.assertEqual(module.deadline_ms(context, "sast"), 14400000)
        self.assertEqual(module.deadline_ms(context, "recon"), 900000)
        self.assertEqual(module.deadline_ms(context, "remediation"), 7200000)
        for invalid in (0, -1, True, "900", 1.5):
            context["orchestration"]["phase_timeout_seconds"]["recon"] = invalid
            with self.assertRaises(ValueError):
                module.deadline_ms(context, "recon")
        with self.assertRaises(KeyError):
            module.deadline_ms(context, "unknown")

    def test_initialized_repository_budget_propagates_to_overlay_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            (base / "config.toml").write_text("[llm.routing]\n" + "\n".join(
                f'{group} = "fixture/controller:high"' for group in GROUP_AGENTS))
            source = base / "source"
            source.mkdir()
            for depth, count, expected in (
                ("quick", 1, 1800000), ("balanced", 1, 2700000),
                ("full", 1, 5400000), ("balanced", 12, 4200000),
            ):
                repositories = []
                for number in range(count):
                    name = f"repo-{number:02d}"
                    (source / name).mkdir(exist_ok=True)
                    repositories.append({"name": name, "path": name, "remote_url": "local", "commit": "abc"})
                inventory = {"source_root": str(source), "application_name": "fixture",
                             "application_id": "fixture", "revision": "abc", "remote_url": "local",
                             "repositories": repositories}
                inventory_path = base / "inventory.json"
                inventory_path.write_text(json.dumps(inventory))
                context = base / "context.json"
                command = [sys.executable, str(ROOT / "scripts/init-run.py"),
                           "--harness-root", str(base), "--repo-path", str(source),
                           "--scan-base", str(base / "scans" / f"run-{depth}-{count}"), "--run-id", f"run-{depth}-{count}",
                           "--repo-name", "fixture", "--repo-id", "fixture", "--remote-url", "local",
                           "--commit", "abc", "--depth", depth,
                           "--repositories-file", str(inventory_path), "--reproduction-mode", "off",
                           "--codegraph-mode", "disabled"]
                env = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context)}
                initialized = subprocess.run(command, env=env, capture_output=True, text=True)
                self.assertEqual(initialized.returncode, 0, initialized.stderr)
                runtime = ROOT / ".harness/tmp"
                runtime.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=runtime, prefix="omp-runtime-") as stream:
                    overlay = Path(stream.name)
                    armed = subprocess.run([sys.executable, str(SCRIPT), str(context), "recon"],
                                           env={**env, "VULNOPS_OMP_RUNTIME_CONFIG": str(overlay)},
                                           capture_output=True, text=True)
                    self.assertEqual(armed.returncode, 0, armed.stderr)
                    self.assertEqual(json.loads(overlay.read_text())["task"]["maxRuntimeMs"], expected)

    def test_invalid_context_does_not_replace_armed_overlay(self):
        runtime = ROOT / ".harness/tmp"
        runtime.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=runtime) as directory:
            context = Path(directory) / "context.json"
            with tempfile.NamedTemporaryFile(dir=runtime, prefix="omp-runtime-", delete=False) as stream:
                overlay = Path(stream.name)
            try:
                env = {**os.environ, "VULNOPS_OMP_RUNTIME_CONFIG": str(overlay)}
                context.write_text(json.dumps({"orchestration": {"phase_timeout_seconds": {"recon": 900}}}))
                result = subprocess.run([sys.executable, str(SCRIPT), str(context), "recon"],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(overlay.read_text()), {"task": {"maxRuntimeMs": 900000}})
                sealed = overlay.read_bytes()
                context.write_text('{"orchestration": {"phase_timeout_seconds": {"recon": false}}}')
                result = subprocess.run([sys.executable, str(SCRIPT), str(context), "recon"],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(overlay.read_bytes(), sealed)
            finally:
                overlay.unlink(missing_ok=True)

    def test_supplementary_deadline_cannot_replenish_consumed_time(self):
        from datetime import datetime, timedelta, timezone
        import gap_exploration_contract as gap
        from gap_dossier import begin_cohort, bind_original_draft, finish_cohort
        from gap_fixture import GapFixture, save

        with tempfile.TemporaryDirectory() as directory:
            fixture = GapFixture(Path(directory))
            gap.admit_plan(fixture.context, fixture.plan())
            gap.admit_worker(fixture.context, "GapA", fixture.result())
            fixture.accepted(gap.finalize_phase(fixture.context)["status"])
            context = fixture.context
            context["phases"]["synthesis"] = "running"
            context["orchestration"] = {"phase_timeout_seconds": {"synthesis": 1800}}
            fixture.persist()
            save(fixture.base / "task-ledger.json", {"run_id": context["run_id"], "tasks": [
                {"id": "Synthesis", "phase": "synthesis", "status": "running",
                 "attempt_id": context["attempt_id"], "attempts": 1}]})
            begin_cohort(context, "synthesis", "original")
            save(fixture.base / "synthesis/original-findings.json",
                 {"schema_version": "2.0", "run_id": context["run_id"],
                  "findings": [], "objective_assessments": []})
            bind_original_draft(context, "synthesis/original-findings.json")
            finish_cohort(context, "synthesis", "original")
            begin_cohort(context, "synthesis", "supplementary")
            path = fixture.base / "synthesis/dispatch.json"
            dispatch = json.loads(path.read_text())
            row = dispatch["cohorts"]["supplementary"]
            now = datetime.now(timezone.utc)
            row["started_at"] = (now - timedelta(seconds=300)).isoformat()
            row["deadline_at"] = (now + timedelta(seconds=300)).isoformat()
            save(path, dispatch)
            remaining = module.deadline_ms(context, "synthesis", cohort="supplementary")
            self.assertGreater(remaining, 0)
            self.assertLessEqual(remaining, 300000)
            context["gap_exploration_budget"]["synthesis_timeout_seconds"] = 1200
            self.assertLessEqual(module.deadline_ms(context, "synthesis", cohort="supplementary"), remaining)
            context["gap_exploration_budget"]["synthesis_timeout_seconds"] = 120
            with self.assertRaisesRegex(ValueError, "no remaining"):
                module.deadline_ms(context, "synthesis", cohort="supplementary")
            self.assertEqual(module.deadline_ms(context, "synthesis"), 1800000)
            self.assertEqual(module.deadline_ms(context, "gap-exploration"),
                             context["gap_exploration_budget"]["timeout_seconds"] * 1000)


if __name__ == "__main__":
    unittest.main()
