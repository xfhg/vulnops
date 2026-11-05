#!/usr/bin/env python3
"""Atomically enforce canonical VulnOps run and top-level task transitions."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run_lifecycle import AUDIT_PHASE_DIRS, AUDIT_TASK_PHASES, audit_phases, assert_owner, clear_run_context, normalize_record, optional_task_closed, release_run, run_status, state_lock


PHASE_STATUS = {"pending", "running", "ok", "degraded", "failed", "skipped"}
RUN_STATUS = {"incomplete", "complete"}
TASK_STATUS = {"pending", "running", "ok", "degraded", "failed", "shallow"}
SUCCESS_PHASE = {"ok", "degraded", "skipped"}
SUCCESS_TASK = {"ok", "degraded", "shallow"}
PHASES = tuple(AUDIT_PHASE_DIRS)
TOP_LEVEL_TASKS = AUDIT_TASK_PHASES
MAX_TOP_LEVEL_ATTEMPTS = 2


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: Path, document: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or unsafe canonical record: {path}")
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
    parser.add_argument("--context", type=Path)
    parser.add_argument("--failure-kind", choices=("execution_failed", "deadline_exceeded"))
    parser.add_argument("--close-optional-failure", action="store_true")
    args = parser.parse_args()

    with state_lock(args.scan_base.resolve()):
        return update(args, parser)


def update(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    scan = args.scan_base.resolve()
    try:
        assert_owner(scan)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    pending_recovery = scan / ".recovery-invalidation.json"
    if pending_recovery.exists() or pending_recovery.is_symlink():
        parser.error("upstream invalidation is pending; repeat the explicit recover-run.py command first")
    manifest_path = scan / "run-manifest.json"
    ledger_path = scan / "task-ledger.json"
    try:
        manifest = normalize_record(load_object(manifest_path))
        manifest["status"] = run_status(manifest.get("status"))
        ledger = load_object(ledger_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"cannot load canonical run state: {exc}")
    if not manifest.get("run_id") or manifest.get("run_id") != ledger.get("run_id"):
        parser.error("run-manifest.json/task-ledger.json run_id is missing or differs")
    try:
        phases = audit_phases(manifest)
    except ValueError as exc:
        parser.error(str(exc))
    if args.phase and args.phase not in phases:
        parser.error(f"phase is not owned by this execution: {args.phase}")
    if args.close_optional_failure:
        return close_optional_failure(scan, manifest, ledger, args, parser)
    if args.failure_kind and not (
        args.task == "GapExploration" and args.task_phase == "gap-exploration"
        and args.phase == "gap-exploration" and args.phase_status == "failed"
        and args.task_status in {None, "failed"}
    ):
        parser.error("--failure-kind is limited to an actual failed GapExploration attempt")

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
    if any(not isinstance(item, dict) or TOP_LEVEL_TASKS.get(item.get("id")) != item.get("phase") or item.get("phase") not in phases for item in tasks):
        parser.error("task ledger contains an unowned top-level task")
    existing_running_phases = [phase for phase, status in manifest.get("phases", {}).items() if status == "running"]
    existing_running_tasks = [str(item.get("id")) for item in tasks if isinstance(item, dict) and item.get("status") == "running"]
    if (len(existing_running_phases) > 1 or len(existing_running_tasks) > 1) and not args.error:
        parser.error("run state is inconsistent; close the interrupted operation before further work")

    if manifest["status"] == "complete":
        parser.error("completed run is immutable")
    if args.phase and manifest["phases"].get(args.phase) in SUCCESS_PHASE:
        parser.error(f"accepted phase {args.phase!r} is immutable")

    if args.phase and phase_status == "running":
        current_phase_status = manifest["phases"].get(args.phase)
        if current_phase_status in SUCCESS_PHASE:
            parser.error(f"validated phase {args.phase!r} is immutable and cannot be restarted")
        active_other = [phase for phase in existing_running_phases if phase != args.phase]
        if active_other:
            parser.error(f"cannot start {args.phase!r}; active phase is {active_other[0]!r}")
        position = phases.index(args.phase)
        incomplete = [phase for phase in phases[:position] if manifest["phases"].get(phase) not in SUCCESS_PHASE]
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
        if expected_phase not in phases:
            parser.error("task phase is not owned by this execution")
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
            if args.task_phase == "gap-exploration":
                previous_attempts = int(task.get("attempts", 0))
                attempt_limit = manifest["gap_exploration_budget"]["max_attempts"]
            else:
                previous_attempts = int(task.get("invocation_attempts", task.get("attempts", 0))) if task.get("attempt_id") == manifest.get("attempt_id") else 0
                attempt_limit = MAX_TOP_LEVEL_ATTEMPTS
            next_attempts = previous_attempts + (1 if args.increment_attempt else 0)
            if next_attempts > attempt_limit:
                parser.error(f"top-level task attempt limit is {attempt_limit}")
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
                if task.get("status") != "running" or manifest["phases"].get(args.task_phase) != "running":
                    parser.error("successful checkpoint requires its recorded running task and phase")
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
        if manifest.get("attempt_id"):
            manifest.setdefault("phase_attempts", {})[args.phase] = manifest["attempt_id"]
    if args.run_status:
        manifest["status"] = args.run_status
    if task is not None and task_status is not None:
        task["status"] = task_status
        if manifest.get("attempt_id"):
            task["attempt_id"] = manifest["attempt_id"]
        if args.increment_attempt:
            task["attempts"] = int(task.get("attempts", 0)) + 1
            task["invocation_attempts"] = next_attempts
        task["artifact"] = args.artifact
        task["error"] = clean_error(args.error)
        task["updated_at"] = timestamp()
        if args.task_phase == "gap-exploration":
            task.pop("optional_closure", None)
            if task_status == "failed":
                task["failure_kind"] = args.failure_kind
                task.setdefault("failure_history", []).append({
                    "attempt": task["attempts"], "attempt_id": task.get("attempt_id"),
                    "kind": args.failure_kind, "error": task["error"],
                })

    if args.run_status == "incomplete" and args.error:
        manifest["error"] = clean_error(args.error)
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
        incomplete = [phase for phase in phases if manifest["phases"].get(phase) not in SUCCESS_PHASE]
        if incomplete:
            parser.error(f"cannot complete run; phase {incomplete[0]!r} is not terminal-success")
        by_id = {str(item.get("id")): item for item in tasks if isinstance(item, dict)}
        incomplete_tasks = [task_id for task_id, phase in TOP_LEVEL_TASKS.items() if phase in phases and by_id.get(task_id, {}).get("status") not in SUCCESS_TASK and not optional_task_closed(by_id.get(task_id, {}), manifest["phases"][phase])]
        if incomplete_tasks:
            parser.error(f"cannot complete run; task {incomplete_tasks[0]!r} is not terminal-success")
        for report in ("security-report.json", "security-report.md"):
            if not artifact_is_valid(scan, f"report/{report}"):
                parser.error(f"cannot complete run; missing or unsafe report/{report}")

    manifest["updated_at"] = timestamp()
    tasks.sort(key=lambda item: (phases.index(str(item.get("phase"))) if str(item.get("phase")) in phases else 999, str(item.get("id"))))
    # Publish the ledger first. Interrupted acceptance remains unfinished until
    # the matching manifest checkpoint is published; recovery never infers it from files.
    atomic_write(ledger_path, ledger)
    atomic_write(manifest_path, manifest)
    if args.run_status == "complete":
        from report_bundle import retire_controls
        retire_controls(scan, manifest["run_id"])
        context_path = args.context or Path(os.environ.get(
            "VULNOPS_AUDIT_CONTEXT", Path(__file__).resolve().parent.parent / ".harness/audit-context.json"))
        clear_run_context(context_path, scan, manifest["run_id"], os.environ.get("VULNOPS_LAUNCHER_SESSION_ID"))
        release_run(scan)
    return 0


def close_optional_failure(scan: Path, manifest: dict, ledger: dict,
                           args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Publish optional closure without turning a failed model attempt into success."""
    if (args.phase != "gap-exploration" or args.task != "GapExploration"
            or args.task_phase != "gap-exploration" or not args.context
            or any((args.phase_status, args.phase_manifest, args.run_status,
                    args.task_status, args.artifact, args.error, args.failure_kind))
            or args.increment_attempt):
        parser.error("optional closure requires only --phase gap-exploration --task GapExploration --task-phase gap-exploration --context")
    try:
        tasks = ledger.get("tasks")
        if not isinstance(tasks, list) or any(not isinstance(item, dict) for item in tasks):
            raise ValueError("task ledger tasks must be objects")
        identities = [item.get("id") for item in tasks]
        if len(set(identities)) != len(identities):
            raise ValueError("task ledger contains duplicate task IDs")
        if manifest["status"] == "complete" or manifest["phases"]["gap-exploration"] != "failed":
            raise ValueError("optional closure requires the actual failed phase")
        if any(state == "running" for state in manifest["phases"].values()) or any(item.get("status") == "running" for item in tasks):
            raise ValueError("stop active tasks before optional closure")
        phases = audit_phases(manifest)
        if any(TOP_LEVEL_TASKS.get(item.get("id")) != item.get("phase")
               or item.get("phase") not in phases or item.get("status") not in TASK_STATUS for item in tasks):
            raise ValueError("task ledger contains an invalid canonical task")
        if any(state not in PHASE_STATUS for state in manifest["phases"].values()):
            raise ValueError("run manifest contains an invalid phase status")
        if any(manifest["phases"][phase] not in SUCCESS_PHASE for phase in phases[:phases.index("gap-exploration")]):
            raise ValueError("optional closure requires accepted predecessors")
        task = next((item for item in tasks if item.get("id") == "GapExploration"), {})
        budget = manifest.get("gap_exploration_budget", {})
        if (task.get("phase") != "gap-exploration" or task.get("status") != "failed"
                or task.get("artifact") is not None
                or task.get("failure_kind") not in {"execution_failed", "deadline_exceeded"}
                or not clean_error(task.get("error"))
                or type(budget.get("max_attempts")) is not int
                or not 1 <= budget["max_attempts"] <= MAX_TOP_LEVEL_ATTEMPTS
                or type(task.get("attempts")) is not int
                or task["attempts"] < budget["max_attempts"]):
            raise ValueError("optional closure requires an exhausted recorded operational failure")
        history = task.get("failure_history")
        if (not isinstance(history, list) or not history
                or history[-1] != {"attempt": task["attempts"], "attempt_id": task.get("attempt_id"),
                                   "kind": task["failure_kind"], "error": task["error"]}):
            raise ValueError("optional closure requires the actual recorded failed attempt")
        context = load_object(args.context)
        if (context.get("run_id") != manifest["run_id"]
                or Path(context.get("scan_base", "")).resolve() != scan
                or context.get("attempt_id") != manifest.get("attempt_id")
                or context.get("gap_exploration_budget") != budget):
            raise ValueError("optional closure context differs from the owning attempt")
        from gap_exploration_contract import finalize_phase_locked, validate_phase
        finalize_phase_locked(context, failure_reason=task["error"])
        result = validate_phase(scan, context)
        if result.get("status") != "degraded":
            raise ValueError("optional failure finalizer must publish a degraded checkpoint")
        task["optional_closure"] = {
            "phase": "gap-exploration", "status": "degraded",
            "artifact": "gap-exploration/results.json", "failure_reason": task["error"],
        }
        task["updated_at"] = timestamp()
        manifest["phases"]["gap-exploration"] = "degraded"
        if manifest.get("attempt_id"):
            manifest.setdefault("phase_attempts", {})["gap-exploration"] = manifest["attempt_id"]
        manifest["updated_at"] = timestamp()
        atomic_write(scan / "task-ledger.json", ledger)
        atomic_write(scan / "run-manifest.json", manifest)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
