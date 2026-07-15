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
    def test_interrupted_active_phase_is_failed_atomically(self) -> None:
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
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["phases"]["tool-collection"], "failed")
            self.assertEqual(ledger["tasks"][0]["status"], "failed")
            self.assertIsNone(ledger["tasks"][0]["artifact"])
            self.assertEqual(ledger["tasks"][0]["attempts"], 1)

    def test_unowned_context_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as temporary:
            scan = Path(temporary)
            phases = {phase: "pending" for phase in PHASES}
            phases["recon"] = "running"
            manifest = {"run_id": "other-run", "status": "running", "phases": phases}
            write(scan / "run-manifest.json", manifest)
            write(scan / "task-ledger.json", {"run_id": "other-run", "tasks": []})
            context = scan / "context.json"
            write(
                context,
                {
                    "schema_version": "2.0",
                    "workflow": "canonical-redteam-v2",
                    "run_id": "other-run",
                    "scan_base": str(scan),
                    "launcher_session_id": "other-session",
                },
            )

            before = (scan / "run-manifest.json").read_text(encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/close-interrupted-run.py"),
                    str(context),
                    "--launcher-session-id",
                    "current-session",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((scan / "run-manifest.json").read_text(encoding="utf-8"), before)

    def test_completed_run_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as temporary:
            scan = Path(temporary)
            write(scan / "run-manifest.json", {"run_id": "done", "status": "complete", "phases": {}})
            write(scan / "task-ledger.json", {"run_id": "done", "tasks": []})
            context = scan / "context.json"
            write(
                context,
                {
                    "schema_version": "2.0",
                    "workflow": "canonical-redteam-v2",
                    "run_id": "done",
                    "scan_base": str(scan),
                },
            )

            before = (scan / "run-manifest.json").read_text(encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/close-interrupted-run.py"), str(context)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((scan / "run-manifest.json").read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
