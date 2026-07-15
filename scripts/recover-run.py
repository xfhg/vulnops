#!/usr/bin/env python3
"""Recover a failed or interrupted run from its first unfinished phase."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from artifact_policy import oversized_artifacts, phase_for_artifact
from harness_contract import harness_contract_sha256, resolved_sast_budget
from phase_seal import PHASE_DIRS, directory_sha256


PHASES = tuple(PHASE_DIRS)
SUCCESS = {"ok", "degraded", "skipped"}
TASK_PHASE = {
    "Recon": "recon",
    "ToolCollection": "tool-collection",
    "SASTLead": "sast",
    "CampaignPlanning": "campaign-planning",
    "Intrusion": "intrusion",
    "Synthesis": "synthesis",
    "FinalVerification": "final-verification",
    "Report": "report",
}
SUBDIRECTORIES = {
    "recon": ("research",),
    "sast": ("deepdive", "hunt-tasks", "verify", "reproduction", "fixes"),
    "intrusion": ("results", "codegraph-runs"),
    "final-verification": ("results",),
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: Path, document: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} must contain an object")
    return document


def sanitized_error(ledger: dict[str, Any], rollback: str) -> str:
    for item in ledger.get("tasks", []):
        if isinstance(item, dict) and item.get("phase") == rollback and item.get("error"):
            return " ".join(str(item["error"]).split())[:1000]
    return "interrupted or failed phase reset for deterministic recovery"


def safe_reset_directory(scan: Path, phase: str) -> None:
    directory = scan / PHASE_DIRS[phase]
    resolved_scan = scan.resolve()
    try:
        directory.resolve(strict=False).relative_to(resolved_scan)
    except ValueError as exc:
        raise ValueError(f"unsafe recovery directory: {directory}") from exc
    if directory.is_symlink():
        raise ValueError(f"refusing to recover through phase symlink: {directory}")
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    for relative in SUBDIRECTORIES.get(phase, ()):
        (directory / relative).mkdir(parents=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("context", type=Path)
    parser.add_argument("depth", choices=("quick", "balanced", "full"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    scan = args.scan_base.resolve()
    manifest_path = scan / "run-manifest.json"
    ledger_path = scan / "task-ledger.json"
    context_path = args.context.resolve()
    try:
        manifest = load(manifest_path)
        ledger = load(ledger_path)
        context = load(context_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"cannot load recoverable run state: {exc}")
    if manifest.get("run_id") != ledger.get("run_id") or manifest.get("run_id") != context.get("run_id"):
        parser.error("run manifest, task ledger, and context identities differ")
    if Path(str(context.get("scan_base", ""))).resolve() != scan:
        parser.error("audit context does not select this scan")
    if manifest.get("depth") != args.depth or context.get("depth") != args.depth:
        parser.error("recovery depth differs from the run identity")
    identity_pairs = (
        ("target_fingerprint", "target_fingerprint"),
        ("reproduction_mode", "reproduction_mode"),
        ("model", "model"),
        ("model_roles", "model_roles"),
        ("verifier_model", "verifier_model"),
    )
    if any(manifest.get(left) != context.get(right) for left, right in identity_pairs):
        parser.error("recovery context differs from the immutable audit identity")
    target = Path(str(context.get("repo_path", "")))
    fingerprint = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "target-fingerprint.py"), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if fingerprint.returncode or fingerprint.stdout.strip() != manifest.get("target_fingerprint"):
        parser.error("target changed or is unavailable; recovery refused")
    if manifest.get("status") == "complete":
        parser.error("completed runs are closed and cannot be recovered")
    phases = manifest.get("phases")
    if not isinstance(phases, dict):
        parser.error("run manifest phases are malformed")
    tasks = ledger.get("tasks", []) if isinstance(ledger.get("tasks"), list) else []
    rollback_reason: str | None = None
    rollback = next((phase for phase in PHASES if phases.get(phase) not in SUCCESS), None)
    if rollback is None:
        if manifest.get("status") != "failed":
            parser.error("run has no unfinished phase to recover")
        violations = oversized_artifacts(scan)
        violation_phases = {
            phase
            for relative, _, _ in violations
            if (phase := phase_for_artifact(relative)) in PHASES
        }
        if not violation_phases:
            parser.error("failed run has no unfinished phase or recoverable bounded-artifact violation")
        rollback = min(violation_phases, key=PHASES.index)
        rollback_reason = f"whole-scan bounded artifact violation reset at owning phase {rollback}"
    rollback_index = PHASES.index(rollback)
    retained = list(PHASES[:rollback_index])
    if any(phases.get(phase) not in SUCCESS for phase in retained):
        parser.error("run phase order is inconsistent before the recovery boundary")

    current_contract = harness_contract_sha256(Path(__file__).resolve().parent.parent)
    current_budget = resolved_sast_budget(args.depth)
    execution_failure = (
        manifest.get("status") == "failed"
        or any(status in {"failed", "running"} for status in phases.values())
        or any(isinstance(item, dict) and item.get("status") in {"failed", "running"} for item in tasks)
    )
    contract_migration = manifest.get("harness_contract_sha256") != current_contract or manifest.get("sast_budget") != current_budget
    context_drift = context.get("harness_contract_sha256") != current_contract or context.get("sast_budget") != current_budget
    if not execution_failure and not contract_migration and context_drift:
        context["harness_contract_sha256"] = current_contract
        context["sast_budget"] = current_budget
        context["recovery_count"] = int(manifest.get("recovery_count", 0))
        context["last_recovery"] = (manifest.get("recovery_history") or [None])[-1]
        if not args.dry_run:
            atomic_write(context_path, context)
        print(f"{rollback}\t{len(retained)}\t0")
        return 0
    if not execution_failure and not contract_migration:
        parser.error("run is incomplete but does not require destructive phase recovery")

    old_contract = str(manifest.get("harness_contract_sha256", ""))
    seals = manifest.get("phase_seals")
    if not isinstance(seals, dict):
        seals = {}
    for phase in retained:
        try:
            digest, file_count = directory_sha256(scan, phase)
        except ValueError as exc:
            parser.error(str(exc))
        existing = seals.get(phase)
        if isinstance(existing, dict) and existing.get("artifact_sha256") not in {None, digest}:
            parser.error(f"validated phase {phase!r} changed after it was sealed")
        seals[phase] = {
            "contract_sha256": str((existing or {}).get("contract_sha256") or old_contract),
            "artifact_sha256": digest,
            "file_count": file_count,
            "sealed_at": str((existing or {}).get("sealed_at") or now()),
            "validation": str((existing or {}).get("validation") or "retained_prior_gate"),
        }

    cleared = list(PHASES[rollback_index:])
    reason = rollback_reason or sanitized_error(ledger, rollback)
    if args.dry_run:
        print(f"{rollback}\t{len(retained)}\t{len(cleared)}")
        return 0
    for phase in cleared:
        safe_reset_directory(scan, phase)
        seals.pop(phase, None)

    retained_tasks = []
    retained_task_ids: set[str] = set()
    for item in ledger.get("tasks", []):
        if not isinstance(item, dict):
            continue
        phase = TASK_PHASE.get(str(item.get("id")))
        if phase is None or item.get("phase") != phase:
            declared = str(item.get("phase", ""))
            if declared in cleared:
                continue
            parser.error("retained task ledger contains a noncanonical entry")
        if PHASES.index(phase) < rollback_index:
            if item.get("status") not in {"ok", "degraded", "shallow"}:
                parser.error(f"retained task {item.get('id')!r} is not successful")
            if str(item.get("id")) in retained_task_ids:
                parser.error(f"retained task {item.get('id')!r} is duplicated")
            retained_task_ids.add(str(item.get("id")))
            retained_tasks.append(item)
    expected_retained_tasks = {task for task, phase in TASK_PHASE.items() if PHASES.index(phase) < rollback_index}
    if retained_task_ids != expected_retained_tasks:
        parser.error("retained phases do not have an exact successful top-level task set")

    recovered_at = now()
    history = manifest.get("recovery_history")
    if not isinstance(history, list):
        history = []
    history.append(
        {
            "generation": len(history) + 1,
            "recovered_at": recovered_at,
            "rollback_phase": rollback,
            "retained_phases": retained,
            "cleared_phases": cleared,
            "from_contract_sha256": old_contract,
            "to_contract_sha256": current_contract,
            "reason": reason,
        }
    )
    manifest["status"] = "initialized"
    manifest["harness_contract_sha256"] = current_contract
    manifest["sast_budget"] = current_budget
    manifest["phase_seals"] = seals
    manifest["recovery_history"] = history
    manifest["recovery_count"] = len(history)
    manifest["updated_at"] = recovered_at
    for phase in cleared:
        phases[phase] = "pending"
    ledger["tasks"] = retained_tasks
    context["harness_contract_sha256"] = current_contract
    context["sast_budget"] = manifest["sast_budget"]
    context["recovery_count"] = len(history)
    context["last_recovery"] = history[-1]

    # Publish context last. If interrupted between writes, the next recovery
    # pass remains fail-closed and can deterministically repeat the cleanup.
    atomic_write(ledger_path, ledger)
    atomic_write(manifest_path, manifest)
    atomic_write(context_path, context)
    print(f"{rollback}\t{len(retained)}\t{len(cleared)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
