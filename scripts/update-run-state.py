#!/usr/bin/env python3
"""Atomically update a VulnOps v2 run manifest or task ledger."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


PHASE_STATUS = {"pending", "running", "ok", "degraded", "failed", "skipped"}
RUN_STATUS = {"initialized", "running", "degraded", "failed", "complete"}
TASK_STATUS = {"pending", "running", "ok", "degraded", "failed", "shallow"}


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: Path, document: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


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

    phase_status = args.phase_status
    if args.phase_manifest:
        if not args.phase:
            parser.error("--phase is required with --phase-manifest")
        manifest_source = args.phase_manifest
        if not manifest_source.is_absolute():
            manifest_source = args.scan_base / manifest_source
        try:
            manifest_source.resolve().relative_to(args.scan_base.resolve())
        except ValueError:
            parser.error("--phase-manifest must stay under scan_base")
        try:
            phase_document = json.loads(manifest_source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"cannot load phase manifest: {exc}")
        if phase_document.get("phase") != args.phase:
            parser.error("phase manifest name does not match --phase")
        phase_status = phase_document.get("status")
        if phase_status not in PHASE_STATUS:
            parser.error(f"invalid phase manifest status: {phase_status!r}")
    if args.phase_status and args.phase_manifest:
        parser.error("use either --phase-status or --phase-manifest, not both")

    if args.phase or args.run_status:
        manifest_path = args.scan_base / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if args.phase:
            if phase_status is None:
                parser.error("--phase-status or --phase-manifest is required with --phase")
            if args.phase not in manifest.get("phases", {}):
                parser.error(f"unknown phase: {args.phase}")
            manifest["phases"][args.phase] = phase_status
        if args.run_status:
            manifest["status"] = args.run_status
        manifest["updated_at"] = timestamp()
        atomic_write(manifest_path, manifest)

    if args.task:
        if not args.task_phase:
            parser.error("--task-phase is required with --task")
        task_status = args.task_status
        if task_status is None and phase_status is not None:
            task_status = "ok" if phase_status == "skipped" else phase_status
        if task_status not in TASK_STATUS:
            parser.error("--task-status is required unless inferred from --phase-manifest")
        ledger_path = args.scan_base / "task-ledger.json"
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        tasks = ledger.setdefault("tasks", [])
        task = next((item for item in tasks if item.get("id") == args.task), None)
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
        task["phase"] = args.task_phase
        task["status"] = task_status
        if args.increment_attempt:
            task["attempts"] = int(task.get("attempts", 0)) + 1
        task["artifact"] = args.artifact
        task["error"] = args.error
        task["updated_at"] = timestamp()
        tasks.sort(key=lambda item: (str(item.get("phase")), str(item.get("id"))))
        atomic_write(ledger_path, ledger)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
