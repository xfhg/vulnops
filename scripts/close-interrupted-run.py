#!/usr/bin/env python3
"""Fail-close canonical run state when its owning OMP session terminates."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from run_lifecycle import assert_owner, clear_run_context, release_run, run_status


TASK_FOR_PHASE = {
    "recon": "Recon",
    "tool-collection": "ToolCollection",
    "sast": "ThreatHunter",
    "campaign-planning": "CampaignPlanning",
    "intrusion": "Intrusion",
    "gap-exploration": "GapExploration",
    "synthesis": "Synthesis",
    "final-verification": "FinalVerification",
    "report": "Report",
}
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
    if not args.context.exists() and not args.context.is_symlink():
        return 0
    try:
        context = load_object(args.context.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[audit] cannot read cleanup context {args.context}: {exc}", file=sys.stderr)
        return 1
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
        try:
            scan.stat()
        except FileNotFoundError:
            clear_run_context(args.context, scan, context["run_id"], args.launcher_session_id)
            return 0
        assert_owner(scan, args.launcher_session_id)
        manifest = load_object(scan / "run-manifest.json")
        ledger = load_object(scan / "task-ledger.json")
        status = run_status(manifest.get("status"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[audit] cannot close owned run: {exc}", file=sys.stderr)
        return 1
    run_id = context.get("run_id")
    if not run_id or manifest.get("run_id") != run_id or ledger.get("run_id") != run_id:
        print("[audit] refusing to close run state with mismatched identities", file=sys.stderr)
        return 1
    if status == "complete":
        clear_run_context(args.context, scan, run_id, args.launcher_session_id)
        release_run(scan, args.launcher_session_id)
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
            if phase == "gap-exploration":
                command.extend(["--failure-kind", "execution_failed"])
    command.extend(["--run-status", "incomplete", "--error", INTERRUPTION_ERROR])

    environment = {**os.environ, "VULNOPS_LAUNCHER_PID": os.environ.get("VULNOPS_LAUNCHER_PID", str(os.getppid()))}
    if args.launcher_session_id:
        environment["VULNOPS_LAUNCHER_SESSION_ID"] = args.launcher_session_id
    result = subprocess.run(command, capture_output=True, text=True, check=False, env=environment)
    if result.returncode:
        print(result.stderr.strip(), file=sys.stderr)
        return 1
    release_run(scan, args.launcher_session_id)
    print(f"[audit] interrupted run {run_id} remains incomplete for checkpoint recovery", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
