from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
PHASES = (
    "recon",
    "tool-collection",
    "sast",
    "campaign-planning",
    "intrusion",
    "synthesis",
    "final-verification",
    "report",
)
DIRS = {"recon": "repo-context", **{phase: phase for phase in PHASES if phase != "recon"}}
TASKS = {
    "recon": "Recon",
    "tool-collection": "ToolCollection",
    "sast": "SASTLead",
    "campaign-planning": "CampaignPlanning",
    "intrusion": "Intrusion",
    "synthesis": "Synthesis",
    "final-verification": "FinalVerification",
    "report": "Report",
}
ROLES = {"orchestrator": "p/main:low", "task": "p/main:medium", "slow": "p/main:high", "smol": "p/main:minimal"}
BUDGET = {"max_concurrency": 8, "max_hunt_tasks": 32, "max_hunt_questions": 64, "max_gapfill_rounds": 2, "max_attempts": 2, "context_packet_bytes": 65536}


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, str):
        path.write_text(value)
    else:
        path.write_text(json.dumps(value, indent=2) + "\n")


class RecoveryTests(unittest.TestCase):
    def test_failed_phase_is_cleaned_while_successful_upstream_is_sealed_and_retained(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base = Path(tmp)
            scan = base / "run"
            target = base / "target"
            target.mkdir()
            (target / "app.py").write_text("print('static')\n")
            fingerprint = subprocess.run(
                [PYTHON, str(ROOT / "scripts/target-fingerprint.py"), str(target)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            statuses = {phase: "ok" for phase in PHASES}
            statuses["tool-collection"] = "degraded"
            statuses["sast"] = "degraded"
            statuses["final-verification"] = "failed"
            statuses["report"] = "pending"
            retained_bytes = {}
            for phase in PHASES:
                directory = scan / DIRS[phase]
                directory.mkdir(parents=True)
                if phase == "report":
                    write(directory / "partial.tmp", "must disappear\n")
                    continue
                manifest_status = statuses[phase]
                write(directory / "phase-manifest.json", {"phase": phase, "status": manifest_status})
                write(directory / "evidence.json", {"phase": phase, "unchanged": True})
                if phase in PHASES[:6]:
                    retained_bytes[phase] = (directory / "evidence.json").read_bytes()
            write(scan / "final-verification/results/partial.json", {"partial": True})

            manifest = {
                "schema_version": "2.0",
                "workflow": "canonical-redteam-v2",
                "run_id": "recover-me",
                "repo_id": "fixture",
                "repository": "fixture",
                "commit": "abc",
                "depth": "balanced",
                "status": "failed",
                "scan_base": str(scan),
                "created_at": "before",
                "updated_at": "before",
                "target_fingerprint": fingerprint,
                "harness_contract_sha256": "a" * 64,
                "sast_budget": BUDGET,
                "model": "p/main:high",
                "model_roles": ROLES,
                "verifier_model": "p/main:xhigh",
                "model_diversity": False,
                "reproduction_mode": "off",
                "phases": statuses,
            }
            tasks = []
            for phase in PHASES[:7]:
                failed = phase == "final-verification"
                tasks.append(
                    {
                        "id": TASKS[phase],
                        "phase": phase,
                        "status": "failed" if failed else statuses[phase],
                        "attempts": 2 if failed else 1,
                        "artifact": None if failed else f"{DIRS[phase]}/phase-manifest.json",
                        "updated_at": "before",
                        "error": "workers had no selected model" if failed else None,
                    }
                )
            context = {
                "schema_version": "2.0",
                "workflow": "canonical-redteam-v2",
                "run_id": "recover-me",
                "repo_path": str(target),
                "scan_base": str(scan),
                "depth": "balanced",
                "target_fingerprint": fingerprint,
                "harness_contract_sha256": "a" * 64,
                "sast_budget": BUDGET,
                "reproduction_mode": "off",
                "model": "p/main:high",
                "model_roles": ROLES,
                "verifier_model": "p/main:xhigh",
            }
            context_path = base / "context.json"
            write(scan / "run-manifest.json", manifest)
            write(scan / "task-ledger.json", {"schema_version": "2.0", "run_id": "recover-me", "tasks": tasks})
            write(context_path, context)

            recovered = subprocess.run(
                [PYTHON, str(ROOT / "scripts/recover-run.py"), str(scan), str(context_path), "balanced"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertTrue(recovered.stdout.startswith("final-verification\t6\t2"))

            after = json.loads((scan / "run-manifest.json").read_text())
            ledger = json.loads((scan / "task-ledger.json").read_text())
            self.assertEqual(after["status"], "initialized")
            self.assertEqual(after["recovery_count"], 1)
            self.assertEqual(after["recovery_history"][0]["rollback_phase"], "final-verification")
            self.assertEqual(after["phases"]["final-verification"], "pending")
            self.assertEqual(after["phases"]["report"], "pending")
            self.assertEqual(len(ledger["tasks"]), 6)
            self.assertNotIn("FinalVerification", {item["id"] for item in ledger["tasks"]})
            for phase, expected in retained_bytes.items():
                self.assertEqual((scan / DIRS[phase] / "evidence.json").read_bytes(), expected)
                self.assertEqual(after["phase_seals"][phase]["validation"], "retained_prior_gate")
            self.assertEqual(list((scan / "final-verification/results").iterdir()), [])
            self.assertEqual(list((scan / "report").iterdir()), [])

            repeated = subprocess.run(
                [PYTHON, str(ROOT / "scripts/recover-run.py"), str(scan), str(context_path), "balanced"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(repeated.returncode, 0)

    def test_whole_scan_size_failure_recovers_from_owning_successful_phase(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base = Path(tmp)
            scan = base / "run"
            target = base / "target"
            target.mkdir()
            (target / "app.py").write_text("print('static')\n")
            fingerprint = subprocess.run(
                [PYTHON, str(ROOT / "scripts/target-fingerprint.py"), str(target)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            statuses = {phase: "ok" for phase in PHASES}
            for phase in PHASES:
                directory = scan / DIRS[phase]
                directory.mkdir(parents=True)
                write(directory / "phase-manifest.json", {"phase": phase, "status": "ok"})
                write(directory / "evidence.json", {"phase": phase})
            oversized = scan / "campaign-planning/evidence-index.json"
            with oversized.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)

            manifest = {
                "schema_version": "2.0",
                "workflow": "canonical-redteam-v2",
                "run_id": "whole-scan-failed",
                "repo_id": "fixture",
                "repository": "fixture",
                "commit": "abc",
                "depth": "balanced",
                "status": "failed",
                "scan_base": str(scan),
                "created_at": "before",
                "updated_at": "before",
                "target_fingerprint": fingerprint,
                "harness_contract_sha256": "a" * 64,
                "sast_budget": BUDGET,
                "model": "p/main:high",
                "model_roles": ROLES,
                "verifier_model": "p/main:xhigh",
                "model_diversity": False,
                "reproduction_mode": "off",
                "phases": statuses,
                "phase_seals": {},
                "recovery_count": 0,
                "recovery_history": [],
            }
            tasks = [
                {
                    "id": TASKS[phase],
                    "phase": phase,
                    "status": "ok",
                    "attempts": 1,
                    "artifact": f"{DIRS[phase]}/phase-manifest.json",
                    "updated_at": "before",
                    "error": None,
                }
                for phase in PHASES
            ]
            context = {
                "schema_version": "2.0",
                "workflow": "canonical-redteam-v2",
                "run_id": "whole-scan-failed",
                "repo_path": str(target),
                "scan_base": str(scan),
                "depth": "balanced",
                "target_fingerprint": fingerprint,
                "harness_contract_sha256": "a" * 64,
                "sast_budget": BUDGET,
                "reproduction_mode": "off",
                "model": "p/main:high",
                "model_roles": ROLES,
                "verifier_model": "p/main:xhigh",
            }
            context_path = base / "context.json"
            write(scan / "run-manifest.json", manifest)
            write(scan / "task-ledger.json", {"schema_version": "2.0", "run_id": "whole-scan-failed", "tasks": tasks})
            write(context_path, context)

            recovered = subprocess.run(
                [PYTHON, str(ROOT / "scripts/recover-run.py"), str(scan), str(context_path), "balanced"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertTrue(recovered.stdout.startswith("campaign-planning\t3\t5"))
            after = json.loads((scan / "run-manifest.json").read_text())
            ledger = json.loads((scan / "task-ledger.json").read_text())
            self.assertEqual(after["status"], "initialized")
            self.assertEqual(after["phases"]["campaign-planning"], "pending")
            self.assertEqual(after["recovery_history"][0]["rollback_phase"], "campaign-planning")
            self.assertEqual({item["id"] for item in ledger["tasks"]}, {"Recon", "ToolCollection", "SASTLead"})
            self.assertFalse(oversized.exists())


if __name__ == "__main__":
    unittest.main()
