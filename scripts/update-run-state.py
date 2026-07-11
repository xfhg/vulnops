#!/usr/bin/env python3
"""Atomically enforce canonical VulnOps run and top-level task transitions."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PHASE_STATUS = {"pending", "running", "ok", "degraded", "failed", "skipped"}
RUN_STATUS = {"initialized", "running", "degraded", "failed", "complete"}
TASK_STATUS = {"pending", "running", "ok", "degraded", "failed", "shallow"}
SUCCESS_PHASE = {"ok", "degraded", "skipped"}
SUCCESS_TASK = {"ok", "degraded", "shallow"}
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
TOP_LEVEL_TASKS = {
    "Recon": "recon",
    "ToolCollection": "tool-collection",
    "SASTLead": "sast",
    "CampaignPlanning": "campaign-planning",
    "Intrusion": "intrusion",
    "Synthesis": "synthesis",
    "FinalVerification": "final-verification",
    "Report": "report",
}
MAX_TOP_LEVEL_ATTEMPTS = 2


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: Path, document: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_object(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} must contain an object")
    return document


def clean_error(value: str | None) -> str | None:
    if value is None:
        return None
    return " ".join(value.split())[:1000] or None


def artifact_is_valid(scan: Path, artifact: str | None) -> bool:
    if not artifact or Path(artifact).is_absolute() or ":" in artifact or "#" in artifact:
        return False
    candidate = (scan / artifact).resolve()
    try:
        candidate.relative_to(scan.resolve())
    except ValueError:
        return False
    return candidate.is_file()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("--phase")
    parser.add_argument("--phase-status", choices=sorted(PHASE_STATUS))
    parser.add_argument("--phase-manifest", type=Path)
    parser.add_argument("--run-status", choices=sorted(RUN_STATUS))
    parser.add_argument("--task")
    parser.add_argument("--task-phase")
    parser.add_argument("--task-status", choices=sorted(TASK_STATUS))
    parser.add_argument("--artifact")
    parser.add_argument("--error")
    parser.add_argument("--increment-attempt", action="store_true")
    args = parser.parse_args()

    scan = args.scan_base.resolve()
    manifest_path = scan / "run-manifest.json"
    ledger_path = scan / "task-ledger.json"
    try:
        manifest = load_object(manifest_path)
        ledger = load_object(ledger_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"cannot load canonical run state: {exc}")
    if manifest.get("run_id") != ledger.get("run_id"):
        parser.error("run manifest and task ledger identity differ")
    if args.phase and args.phase not in PHASES:
        parser.error(f"unknown phase: {args.phase}")

    phase_status = args.phase_status
    if args.phase_manifest:
        if not args.phase:
            parser.error("--phase is required with --phase-manifest")
        source = args.phase_manifest
        if not source.is_absolute():
            source = scan / source
        try:
            source.resolve().relative_to(scan)
            phase_document = load_object(source)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"cannot load phase manifest: {exc}")
        if phase_document.get("phase") != args.phase:
            parser.error("phase manifest name does not match --phase")
        phase_status = phase_document.get("status")
        if phase_status not in PHASE_STATUS:
            parser.error(f"invalid phase manifest status: {phase_status!r}")
    if args.phase_status and args.phase_manifest:
        parser.error("use either --phase-status or --phase-manifest, not both")
    if args.phase and phase_status is None:
        parser.error("--phase-status or --phase-manifest is required with --phase")
    if args.phase and not args.task:
        parser.error("phase transitions must include their canonical top-level task")

    tasks = ledger.setdefault("tasks", [])
    if not isinstance(tasks, list):
        parser.error("task ledger tasks must be an array")
    ids = [str(item.get("id")) for item in tasks if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        parser.error("task ledger contains duplicate task IDs")
    existing_running_phases = [phase for phase, status in manifest.get("phases", {}).items() if status == "running"]
    existing_running_tasks = [str(item.get("id")) for item in tasks if isinstance(item, dict) and item.get("status") == "running"]
    if (len(existing_running_phases) > 1 or len(existing_running_tasks) > 1) and args.run_status != "failed":
        parser.error("run state is already inconsistent; close the run as failed before further work")

    current_run_status = str(manifest.get("status"))
    mutates_work = phase_status is not None or args.task_status is not None or args.increment_attempt
    if current_run_status in {"failed", "complete"} and (mutates_work or args.run_status != current_run_status):
        parser.error(f"terminal run {current_run_status!r} cannot be resumed or mutated")

    if args.phase and phase_status == "running":
        current_phase_status = manifest["phases"].get(args.phase)
        if current_phase_status in SUCCESS_PHASE:
            parser.error(f"validated phase {args.phase!r} is immutable and cannot be restarted")
        active_other = [phase for phase in existing_running_phases if phase != args.phase]
        if active_other:
            parser.error(f"cannot start {args.phase!r}; active phase is {active_other[0]!r}")
        position = PHASES.index(args.phase)
        incomplete = [phase for phase in PHASES[:position] if manifest["phases"].get(phase) not in SUCCESS_PHASE]
        if incomplete:
            parser.error(f"cannot start {args.phase!r}; prior phase {incomplete[0]!r} is not validated")

    task: dict[str, Any] | None = None
    task_status = args.task_status
    if args.task:
        if not args.task_phase:
            parser.error("--task-phase is required with --task")
        expected_phase = TOP_LEVEL_TASKS.get(args.task)
        if expected_phase is None or expected_phase != args.task_phase:
            parser.error("task ID and task phase do not match the canonical top-level workflow")
        if args.phase and args.phase != args.task_phase:
            parser.error("--phase and --task-phase must match")
        if task_status is None and phase_status is not None:
            task_status = "ok" if phase_status == "skipped" else phase_status
        if task_status not in TASK_STATUS:
            parser.error("--task-status is required unless inferred from --phase-manifest")
        task = next((item for item in tasks if isinstance(item, dict) and item.get("id") == args.task), None)
        if task is None:
            task = {
                "id": args.task,
                "phase": args.task_phase,
                "status": "pending",
                "attempts": 0,
                "artifact": None,
                "updated_at": timestamp(),
                "error": None,
            }
            tasks.append(task)
        if task.get("phase") != args.task_phase:
            parser.error("existing task phase differs from canonical phase")
        if task_status == "running":
            active_other = [task_id for task_id in existing_running_tasks if task_id != args.task]
            if active_other:
                parser.error(f"cannot start {args.task!r}; active task is {active_other[0]!r}")
            if manifest["phases"].get(args.task_phase) != "running" and not (args.phase == args.task_phase and phase_status == "running"):
                parser.error("a task may run only while its owning phase is running")
            if task.get("status") in SUCCESS_TASK:
                parser.error("a validated top-level task is immutable")
            if args.increment_attempt and task.get("status") == "running":
                parser.error("cannot increment attempts for a task that is already running")
            if task.get("status") != "running" and not args.increment_attempt:
                parser.error("a real task start must increment its attempt counter")
            next_attempts = int(task.get("attempts", 0)) + (1 if args.increment_attempt else 0)
            if next_attempts > MAX_TOP_LEVEL_ATTEMPTS:
                parser.error(f"top-level task attempt limit is {MAX_TOP_LEVEL_ATTEMPTS}")
        else:
            if args.increment_attempt:
                parser.error("attempts may be incremented only when starting a task")
            if int(task.get("attempts", 0)) < 1:
                parser.error("a task cannot become terminal before a recorded attempt")
            terminal_phase = phase_status if args.phase == args.task_phase else manifest["phases"].get(args.task_phase)
            expected_task = "ok" if terminal_phase == "skipped" else terminal_phase
            if expected_task != task_status:
                parser.error("terminal task status must be synchronized with its phase status")
            if task_status in SUCCESS_TASK:
                if not artifact_is_valid(scan, args.artifact):
                    parser.error("successful task requires an existing scan-relative canonical artifact")
                if args.error:
                    parser.error("successful task cannot retain an error")
            elif task_status == "failed":
                if args.artifact is not None:
                    parser.error("failed task artifact must be null")
                if clean_error(args.error) is None:
                    parser.error("failed task requires a bounded sanitized error")

    if args.phase:
        manifest["phases"][args.phase] = phase_status
    if args.run_status:
        manifest["status"] = args.run_status
    if task is not None and task_status is not None:
        task["status"] = task_status
        if args.increment_attempt:
            task["attempts"] = int(task.get("attempts", 0)) + 1
        task["artifact"] = args.artifact
        task["error"] = clean_error(args.error)
        task["updated_at"] = timestamp()

    if args.run_status == "failed":
        failure = clean_error(args.error) or "run stopped after a canonical phase failure"
        for phase, status in manifest.get("phases", {}).items():
            if status == "running":
                manifest["phases"][phase] = "failed"
        for item in tasks:
            if isinstance(item, dict) and item.get("status") == "running":
                item["status"] = "failed"
                item["artifact"] = None
                item["error"] = failure
                item["updated_at"] = timestamp()
    elif args.run_status == "complete":
        incomplete = [phase for phase in PHASES if manifest["phases"].get(phase) not in SUCCESS_PHASE]
        if incomplete:
            parser.error(f"cannot complete run; phase {incomplete[0]!r} is not terminal-success")
        by_id = {str(item.get("id")): item for item in tasks if isinstance(item, dict)}
        incomplete_tasks = [task_id for task_id in TOP_LEVEL_TASKS if by_id.get(task_id, {}).get("status") not in SUCCESS_TASK]
        if incomplete_tasks:
            parser.error(f"cannot complete run; task {incomplete_tasks[0]!r} is not terminal-success")

    manifest["updated_at"] = timestamp()
    tasks.sort(key=lambda item: (PHASES.index(str(item.get("phase"))) if str(item.get("phase")) in PHASES else 999, str(item.get("id"))))
    # Prepare both documents before either replace. The controller is single-writer;
    # startup reconciliation uses phase manifests if interrupted between replaces.
    atomic_write(ledger_path, ledger)
    atomic_write(manifest_path, manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
