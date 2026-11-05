#!/usr/bin/env python3
"""Select the current incomplete audit, or explicitly request a fresh run."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from run_lifecycle import AUDIT_TASK_PHASES, audit_phases, assert_owner, clear_run_context, optional_task_closed, release_run, run_status

TASK_PHASE = AUDIT_TASK_PHASES
SUCCESS = {"ok", "degraded", "skipped"}


def load(path: Path) -> dict:
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(f"unsafe audit record: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def selected_directory(selected: str, root: Path) -> Path | None:
    """Distinguish a deleted selection from unsafe paths and inaccessible state."""
    scan = Path(selected)
    scans = root.resolve() / "scans"
    if not scan.is_absolute() or ".." in scan.parts or not scan.is_relative_to(scans) or scan == scans:
        raise ValueError("scan_base must be beneath harness scans")
    current = scans.parent
    for part in scan.relative_to(current).parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(mode):
            raise ValueError(f"unsafe run directory: {current}")
    return scan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("context", type=Path)
    parser.add_argument("--fresh", action="store_true", help="Start a new audit without replacing old run artifacts")
    args = parser.parse_args()
    try:
        args.context.lstat()
    except FileNotFoundError:
        return 0
    except OSError as exc:
        parser.error(str(exc))
    try:
        context = load(args.context)
        if context.get("workflow") != "canonical-redteam-v2":
            raise ValueError(f"{args.context}: workflow must identify an ordinary audit")
        run_id, selected = context.get("run_id"), context.get("scan_base")
        if not isinstance(run_id, str) or not run_id or not isinstance(selected, str) or not selected:
            raise ValueError(f"{args.context}: run_id and scan_base are required")
        root = Path(context.get("harness_root") or Path(__file__).resolve().parent.parent)
        scan = selected_directory(selected, root)
        if scan is None:
            clear_run_context(args.context, Path(selected), run_id)
            print("[audit] Selected run directory no longer exists; starting a new audit.", file=sys.stderr)
            return 0
        report_path = scan / "report/security-report.json"
        if report_path.exists() and "publication" in load(report_path):
            from report_bundle import read_publication
            publication = read_publication(scan, expected_kind="audit")
            if publication["run_id"] != run_id:
                raise ValueError("completed publication differs from selected context")
            clear_run_context(args.context, scan, run_id)
            return 0
        owned = assert_owner(scan)
        session = os.environ.get("VULNOPS_LAUNCHER_SESSION_ID")
        same_session = bool(session and context.get("launcher_session_id") == session and owned)
        if args.fresh and not same_session:
            return 0
        manifest = load(scan / "run-manifest.json")
        if manifest.get("run_id") != run_id:
            raise ValueError("run-manifest.json run_id differs from selected context")
        if run_status(manifest.get("status")) == "complete":
            clear_run_context(args.context, scan, run_id)
            release_run(scan)
            return 0
        ledger = load(scan / "task-ledger.json")
        if ledger.get("run_id") != run_id:
            raise ValueError("task-ledger.json run_id differs from selected context")
        if (scan / ".recovery-invalidation.json").exists() or (scan / ".recovery-invalidation.json").is_symlink():
            raise ValueError("pending .recovery-invalidation.json: repeat its explicit recover-run.py operation first")
        phases, tasks = manifest.get("phases"), ledger.get("tasks")
        recorded_phases = audit_phases(manifest)
        if any(status not in SUCCESS | {"pending", "running", "failed"} for status in phases.values()):
            raise ValueError("run-manifest.json phases contains an invalid checkpoint status")
        if not isinstance(tasks, list):
            raise ValueError("task-ledger.json tasks must be an array")
        ids = set()
        for task in tasks:
            if not isinstance(task, dict) or task.get("id") not in TASK_PHASE or task.get("phase") != TASK_PHASE[task["id"]] or task["phase"] not in recorded_phases or task["id"] in ids:
                raise ValueError("task-ledger.json contains an invalid or duplicate task")
            ids.add(task["id"])
            if task.get("status") not in {"pending", "running", "failed", "ok", "degraded", "shallow"}:
                raise ValueError(f"task-ledger.json task {task['id']} has invalid status")
        by_phase = {task["phase"]: task for task in tasks}
        for phase, status in phases.items():
            if status in SUCCESS:
                task = by_phase.get(phase, {})
                closed = optional_task_closed(task, status)
                if task.get("status") not in {"ok", "degraded", "shallow"} and not closed:
                    raise ValueError(f"task-ledger.json missing successful task for accepted phase {phase}")
                ref = task["optional_closure"]["artifact"] if closed else task.get("artifact")
                if not isinstance(ref, str) or not ref or Path(ref).is_absolute() or not (scan / ref).resolve().is_relative_to(scan):
                    raise ValueError(f"task-ledger.json task {task['id']} has unsafe artifact")
                if not (scan / ref).is_file():
                    raise ValueError(f"missing retained task artifact: {scan / ref}")
        recover = any(status in {"running", "failed"} for status in phases.values()) or any(task.get("status") in {"running", "failed"} and not optional_task_closed(task, phases[task["phase"]]) for task in tasks)
        print(f"{run_id}\t{scan}\t{'recover' if recover else 'resume'}")
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
