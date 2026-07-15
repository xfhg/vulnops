#!/usr/bin/env python3
"""Fail-close canonical run state when its owning OMP session terminates."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


TASK_FOR_PHASE = {
    "recon": "Recon",
    "tool-collection": "ToolCollection",
    "sast": "SASTLead",
    "campaign-planning": "CampaignPlanning",
    "intrusion": "Intrusion",
    "synthesis": "Synthesis",
    "final-verification": "FinalVerification",
    "report": "Report",
}
ACTIVE_RUN_STATUSES = {"initialized", "running", "degraded"}
INTERRUPTION_ERROR = "OMP audit session ended before canonical workflow completion"


def load_object(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} must contain an object")
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("context", type=Path)
    parser.add_argument("--launcher-session-id")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    try:
        context = load_object(args.context.resolve())
    except (OSError, ValueError, json.JSONDecodeError):
        return 0
    if context.get("schema_version") != "2.0" or context.get("workflow") != "canonical-redteam-v2":
        return 0
    if args.launcher_session_id and context.get("launcher_session_id") != args.launcher_session_id:
        return 0

    scan = Path(str(context.get("scan_base", ""))).resolve()
    try:
        scan.relative_to((root / "scans").resolve())
    except ValueError:
        print("[audit] refusing to close a run outside the harness scans directory", file=sys.stderr)
        return 1

    try:
        manifest = load_object(scan / "run-manifest.json")
        ledger = load_object(scan / "task-ledger.json")
    except (OSError, ValueError, json.JSONDecodeError):
        return 0
    run_id = context.get("run_id")
    if not run_id or manifest.get("run_id") != run_id or ledger.get("run_id") != run_id:
        print("[audit] refusing to close run state with mismatched identities", file=sys.stderr)
        return 1
    if manifest.get("status") not in ACTIVE_RUN_STATUSES:
        return 0

    phases = manifest.get("phases") if isinstance(manifest.get("phases"), dict) else {}
    tasks = ledger.get("tasks") if isinstance(ledger.get("tasks"), list) else []
    running_phases = [phase for phase, status in phases.items() if status == "running"]
    running_tasks = [item for item in tasks if isinstance(item, dict) and item.get("status") == "running"]

    command = [
        sys.executable,
        str(root / "scripts" / "update-run-state.py"),
        str(scan),
    ]
    if len(running_phases) == 1 and len(running_tasks) == 1:
        phase = str(running_phases[0])
        task = running_tasks[0]
        expected_task = TASK_FOR_PHASE.get(phase)
        if task.get("id") == expected_task and task.get("phase") == phase:
            command.extend(
                [
                    "--phase", phase,
                    "--phase-status", "failed",
                    "--task", expected_task,
                    "--task-phase", phase,
                    "--task-status", "failed",
                ]
            )
    command.extend(["--run-status", "failed", "--error", INTERRUPTION_ERROR])

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        print("[audit] interrupted run could not be closed by the canonical state updater", file=sys.stderr)
        return 1
    print(f"[audit] interrupted run {run_id} marked failed for deterministic recovery", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
