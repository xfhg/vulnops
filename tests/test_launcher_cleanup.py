import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
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


def write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


class LauncherCleanupTests(unittest.TestCase):
    def test_interrupted_active_phase_records_failure_without_new_attempt(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as temporary:
            scan = Path(temporary)
            phases = {phase: "pending" for phase in PHASES}
            phases["recon"] = "ok"
            phases["tool-collection"] = "running"
            write(
                scan / "run-manifest.json",
                {
                    "run_id": "interrupted-run",
                    "status": "running",
                    "phases": phases,
                    "phase_seals": {},
                },
            )
            write(
                scan / "task-ledger.json",
                {
                    "run_id": "interrupted-run",
                    "tasks": [
                        {
                            "id": "ToolCollection",
                            "phase": "tool-collection",
                            "status": "running",
                            "attempts": 1,
                            "artifact": None,
                            "error": None,
                        }
                    ],
                },
            )
            context = scan / "context.json"
            write(
                context,
                {
                    "schema_version": "2.0",
                    "workflow": "canonical-redteam-v2",
                    "run_id": "interrupted-run",
                    "scan_base": str(scan),
                    "launcher_session_id": "owned-session",
                },
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/close-interrupted-run.py"),
                    str(context),
                    "--launcher-session-id",
                    "owned-session",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((scan / "run-manifest.json").read_text(encoding="utf-8"))
            ledger = json.loads((scan / "task-ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "incomplete")
            self.assertEqual(manifest["phases"]["tool-collection"], "failed")
            self.assertEqual(ledger["tasks"][0]["status"], "failed")
            self.assertIsNone(ledger["tasks"][0]["artifact"])
            self.assertEqual(ledger["tasks"][0]["attempts"], 1)

    def test_threat_hunter_dispatch_rejects_legacy_and_closes_interruption(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as temporary:
            scan = Path(temporary)
            phases = {phase: "pending" for phase in PHASES}
            phases.update({"recon": "ok", "tool-collection": "ok"})
            write(scan / "run-manifest.json", {
                "run_id": "hunter-run", "status": "running", "phases": phases,
            })
            write(scan / "task-ledger.json", {"run_id": "hunter-run", "tasks": []})
            context = scan / "context.json"
            write(context, {
                "schema_version": "2.0", "workflow": "canonical-redteam-v2",
                "run_id": "hunter-run", "scan_base": str(scan),
                "launcher_session_id": "hunter-session",
            })
            command = [
                sys.executable, str(ROOT / "scripts/update-run-state.py"), str(scan),
                "--phase", "sast", "--phase-status", "running", "--task-phase", "sast",
                "--task-status", "running", "--increment-attempt", "--task",
            ]
            before = {path: path.read_bytes() for path in scan.iterdir()}
            rejected = subprocess.run(command + ["SASTLead"], capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("canonical top-level workflow", rejected.stderr)
            self.assertEqual({path: path.read_bytes() for path in scan.iterdir()}, before)
            started = subprocess.run(command + ["ThreatHunter"], capture_output=True, text=True)
            self.assertEqual(started.returncode, 0, started.stderr)
            task = json.loads((scan / "task-ledger.json").read_text())["tasks"][0]
            self.assertEqual((task["id"], task["phase"], task["status"], task["attempts"]),
                             ("ThreatHunter", "sast", "running", 1))
            closed = subprocess.run([
                sys.executable, str(ROOT / "scripts/close-interrupted-run.py"), str(context),
                "--launcher-session-id", "hunter-session",
            ], capture_output=True, text=True)
            self.assertEqual(closed.returncode, 0, closed.stderr)
            manifest = json.loads((scan / "run-manifest.json").read_text())
            task = json.loads((scan / "task-ledger.json").read_text())["tasks"][0]
            self.assertEqual((manifest["status"], manifest["phases"]["sast"]), ("incomplete", "failed"))
            self.assertEqual((task["id"], task["phase"], task["status"], task["attempts"]),
                             ("ThreatHunter", "sast", "failed", 1))
            self.assertIsNone(task["artifact"])

    def test_cleanup_preserves_evidence_and_removes_only_completed_context(self) -> None:
        for case in ("unowned", "complete", "absent"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=ROOT / "scans") as temporary:
                scan = Path(temporary)
                context = scan / "context.json"
                arguments = []
                if case != "absent":
                    phases = {phase: "pending" for phase in PHASES}
                    phases["recon"] = "running"
                    write(scan / "run-manifest.json", {
                        "run_id": "fixture", "status": "complete" if case == "complete" else "running",
                        "phases": {} if case == "complete" else phases,
                    })
                    write(scan / "task-ledger.json", {"run_id": "fixture", "tasks": []})
                    write(context, {
                        "schema_version": "2.0", "workflow": "canonical-redteam-v2",
                        "run_id": "fixture", "scan_base": str(scan),
                        "launcher_session_id": "other-session",
                    })
                if case != "complete":
                    arguments = ["--launcher-session-id", "current-session"]
                before = {path.name: path.read_bytes() for path in scan.iterdir()}
                result = subprocess.run([
                    sys.executable, str(ROOT / "scripts/close-interrupted-run.py"),
                    str(context), *arguments,
                ], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                if case == "complete":
                    before.pop("context.json")
                    self.assertFalse(context.exists())
                self.assertEqual({path.name: path.read_bytes() for path in scan.iterdir()}, before)

    def test_owned_missing_manifest_is_named_error(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as temporary:
            scan = Path(temporary)
            context = scan / "context.json"
            write(context, {"schema_version": "2.0", "workflow": "canonical-redteam-v2",
                            "run_id": "missing", "scan_base": str(scan),
                            "launcher_session_id": "owned"})
            result = subprocess.run([
                sys.executable, str(ROOT / "scripts/close-interrupted-run.py"), str(context),
                "--launcher-session-id", "owned",
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("run-manifest.json", result.stderr)


if __name__ == "__main__":
    unittest.main()
