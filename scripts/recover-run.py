#!/usr/bin/env python3
"""Reconcile interrupted publication and reset only unfinished audit work."""
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from recovery_archive import atomic_write, sync_directory
from run_lifecycle import AUDIT_PHASE_DIRS, AUDIT_TASK_PHASES, audit_phases, assert_owner, claim_run, normalize_record, optional_task_closed, state_lock

PHASE_DIRS = AUDIT_PHASE_DIRS
PHASES = tuple(PHASE_DIRS)
SUCCESS = {"ok", "degraded", "skipped"}
TASK_PHASE = AUDIT_TASK_PHASES
SUBDIRECTORIES = {"recon": ("research",), "sast": ("deepdive", "hunt-tasks", "verify", "reproduction"), "intrusion": ("results", "codegraph-runs"), "gap-exploration": ("packets", "results", "codegraph-runs"), "final-verification": ("results",)}


def load(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or unsafe recovery control: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def phase_directory(scan: Path, phase: str) -> Path:
    directory = scan / PHASE_DIRS[phase]
    if directory.is_symlink() or not directory.resolve().is_relative_to(scan):
        raise ValueError(f"unsafe recovery directory: {directory}")
    if directory.exists() and (not directory.is_dir() or any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in directory.rglob("*"))):
        raise ValueError(f"unsafe entry in recovery directory: {directory}")
    return directory


def reset_directory(scan: Path, phase: str) -> None:
    directory = phase_directory(scan, phase)
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    for relative in SUBDIRECTORIES.get(phase, ()):
        (directory / relative).mkdir(parents=True)


def retained_tasks(ledger: dict, retained: list[str]) -> list[dict]:
    tasks = ledger.get("tasks")
    if not isinstance(tasks, list):
        raise ValueError("task-ledger.json tasks must be an array")
    result, ids = [], set()
    for task in tasks:
        if not isinstance(task, dict) or TASK_PHASE.get(task.get("id")) != task.get("phase"):
            raise ValueError("task-ledger.json contains a noncanonical task")
        if task["id"] in ids:
            raise ValueError("task-ledger.json contains duplicate tasks")
        ids.add(task["id"])
        if task["phase"] in retained:
            if task.get("status") not in {"ok", "degraded", "shallow"} and not optional_task_closed(task, "degraded"):
                raise ValueError(f"task-ledger.json retained task {task['id']} is not successful")
            result.append(task)
    if {task["phase"] for task in result} != set(retained):
        raise ValueError("task-ledger.json missing successful task for retained checkpoint")
    return result


def preserve_diagnostics(scan: Path, context_path: Path, event: dict, cleared: list[str], journal: dict) -> None:
    relative = f"recovery-archives/generation-{event['generation']}"
    if event["invalidation"].get("archive_path") != relative:
        raise ValueError("noncanonical recovery archive path")
    archive = scan / relative
    if archive.parent.is_symlink() or archive.is_symlink() or not archive.resolve().is_relative_to(scan):
        raise ValueError("unsafe recovery archive path")
    if archive.exists() and any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in archive.rglob("*")):
        raise ValueError("unsafe recovery archive entry")
    if (archive / "receipt.json").is_file() or (archive / "archive-state.json").is_file():
        return
    archive.mkdir(parents=True, exist_ok=True)
    for name in ("run-manifest.json", "task-ledger.json", "audit-context.json"):
        destination = archive / name
        if not destination.exists():
            shutil.copy2(context_path if name == "audit-context.json" else scan / name, destination)
    for phase in cleared:
        source = phase_directory(scan, phase)
        if source.exists():
            for path in source.rglob("*"):
                destination = archive / path.relative_to(scan)
                if path.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif not destination.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
    atomic_write(archive / "archive-state.json", {"run_id": journal["replacement"]["run-manifest.json"]["run_id"], "generation": event["generation"], "status": "complete"})


def work_path(scan: Path, phase: str, relative: str) -> Path:
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError(f"unsafe retained {phase} work path: {relative}")
    path = scan / relative
    if not path.resolve().is_relative_to((scan / PHASE_DIRS[phase]).resolve()) or path.is_symlink():
        raise ValueError(f"unsafe retained {phase} work path: {relative}")
    return path


def unfinished_work(scan: Path, phase: str, context: dict | None = None) -> dict:
    """Retain coordinator checkpoints, not arbitrary worker-file presence."""
    phase_directory(scan, phase)
    remove, replacements = [], {}
    if phase == "sast":
        plan_path, ledger_path = scan / "sast/hunt-plan.json", scan / "sast/coverage-ledger.json"
        plan = load(plan_path) if plan_path.exists() else {"tasks": []}
        ledger = load(ledger_path) if ledger_path.exists() else {"tasks": []}
        tasks, rows = plan.get("tasks"), ledger.get("tasks")
        if not isinstance(tasks, list) or not isinstance(rows, list) or any(not isinstance(row, dict) for row in [*tasks, *rows]):
            raise ValueError("sast hunt-plan.json/coverage-ledger.json tasks must be object arrays")
        if any(not isinstance(task.get("id"), str) or not task["id"] or Path(task["id"]).name != task["id"] or ".." in task["id"] for task in tasks if isinstance(task, dict)):
            raise ValueError("sast/hunt-plan.json contains an unsafe task ID")
        owners = {task.get("id") for task in tasks}
        accepted = set()
        candidate_ids = set()
        for row in rows:
            if row.get("artifact_valid"):
                if row.get("id") not in owners:
                    raise ValueError("sast/coverage-ledger.json accepted task has no plan owner")
                accepted.add(f"sast/deepdive/{row['id']}.json")
                candidate_ids.update(row.get("candidate_ids", []))
        review_attempts = ledger.get("review_attempts", {})
        if not isinstance(review_attempts, dict):
            raise ValueError("sast/coverage-ledger.json review_attempts must be an object")
        if any(not isinstance(identity, str) or not identity or Path(identity).name != identity or ".." in identity for identity in review_attempts):
            raise ValueError("sast/coverage-ledger.json contains an unsafe review owner")
        review_ids = set(review_attempts)
        accepted.update(f"sast/verify/{identity}.json" for identity in review_ids)
        for relative in accepted:
            if not work_path(scan, phase, relative).is_file():
                raise ValueError(f"missing accepted worker artifact: {relative}")
        for directory in ("deepdive", "verify"):
            remove.extend(path.relative_to(scan).as_posix() for path in (scan / "sast" / directory).glob("*.json")
                          if path.relative_to(scan).as_posix() not in accepted)
        for name, field, identities in (
            ("raw-findings.json", "id", candidate_ids),
            ("validation-queue.json", "id", candidate_ids),
            ("validation-results.json", "candidate_id", review_ids),
            ("verified-findings.json", "id", review_ids),
        ):
            path = scan / "sast" / name
            if path.exists():
                document = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(document, list) or any(not isinstance(row, dict) for row in document):
                    raise ValueError(f"sast/{name} must contain an object array")
                retained = [row for row in document if row.get(field) in identities]
                if retained != document:
                    replacements[f"sast/{name}"] = retained
        remove.extend(("sast/phase-manifest.json", "sast/summary.md"))
    elif phase == "intrusion":
        waves = sorted((scan / "intrusion/waves").glob("*.json"))
        latest = load(waves[-1]) if waves else {"results": {}}
        records = latest.get("results")
        if not isinstance(records, dict):
            raise ValueError("intrusion latest wave results must be an object")
        accepted = set()
        for owner, record in records.items():
            if not isinstance(owner, str) or not owner or Path(owner).name != owner or ".." in owner:
                raise ValueError("intrusion wave contains an unsafe result owner")
            relative = f"intrusion/results/{owner}.json"
            if not isinstance(record, dict) or record.get("ref") != relative:
                raise ValueError("intrusion wave result has invalid owner/artifact binding")
            if not work_path(scan, phase, relative).is_file():
                raise ValueError(f"missing accepted worker artifact: {relative}")
            accepted.add(relative)
        remove.extend(path.relative_to(scan).as_posix() for path in (scan / "intrusion/results").glob("*.json")
                      if path.relative_to(scan).as_posix() not in accepted)
        remove.extend(("intrusion/phase-manifest.json", "intrusion/intrusion-results.json", "intrusion/summary.md"))
    elif phase in {"gap-exploration", "synthesis", "final-verification"}:
        if phase == "gap-exploration":
            from gap_exploration_contract import recovery_checkpoint
            checkpoint = recovery_checkpoint(context, interrupt_running=True)
        else:
            from gap_dossier import recovery_checkpoint
            checkpoint = recovery_checkpoint(scan, phase, context)
        accepted = set(checkpoint["files"])
        replacements = checkpoint["documents"]
        for relative in accepted | set(replacements):
            work_path(scan, phase, relative)
        remove.extend(path.relative_to(scan).as_posix()
                      for path in (scan / PHASE_DIRS[phase]).rglob("*")
                      if path.is_file() and path.relative_to(scan).as_posix() not in accepted
                      and path.relative_to(scan).as_posix() not in replacements)
    return {"remove": sorted(set(remove)), "replace": replacements}


def reconcile_work(scan: Path, phase: str, operation: dict) -> None:
    if not isinstance(operation, dict) or not isinstance(operation.get("remove"), list) or not isinstance(operation.get("replace"), dict):
        raise ValueError("recovery work reconciliation must record remove/replace operations")
    for relative in [*operation["remove"], *operation["replace"]]:
        path = work_path(scan, phase, relative)
        if path.exists() and not path.is_file():
            raise ValueError(f"recovery work operation is not a file: {relative}")
    for relative in operation["remove"]:
        path = work_path(scan, phase, relative)
        if path.exists() and not path.is_file():
            raise ValueError(f"recovery work removal is not a file: {relative}")
        path.unlink(missing_ok=True)
    for relative, document in operation["replace"].items():
        atomic_write(work_path(scan, phase, relative), document)


def apply_journal(scan: Path, context_path: Path, journal_path: Path, journal: dict, manifest: dict, reason: str | None, dry_run: bool) -> tuple[str, int, int]:
    event, replacements = journal.get("event"), journal.get("replacement")
    if not isinstance(event, dict) or not isinstance(replacements, dict):
        raise ValueError(f"{journal_path.name}: event and replacement are required")
    phase_order = audit_phases(manifest)
    rollback = event.get("rollback_phase")
    if rollback not in phase_order:
        raise ValueError(f"{journal_path.name}: invalid rollback_phase")
    retained, cleared = list(phase_order[:phase_order.index(rollback)]), list(phase_order[phase_order.index(rollback):])
    if event.get("retained_phases") != retained or event.get("cleared_phases") != cleared:
        raise ValueError(f"{journal_path.name}: inconsistent phase boundary")
    invalidation = event.get("invalidation")
    if invalidation is not None:
        if not isinstance(invalidation, dict) or invalidation.get("reason") != reason:
            raise ValueError("pending explicit invalidation must be retried with its original reason")
    for name in ("run-manifest.json", "task-ledger.json", "audit-context.json"):
        document = replacements.get(name)
        if not isinstance(document, dict) or document.get("run_id") != manifest.get("run_id"):
            raise ValueError(f"{journal_path.name}: replacement {name} run_id differs")
    if Path(str(replacements["audit-context.json"].get("scan_base", ""))).resolve() != scan:
        raise ValueError(f"{journal_path.name}: replacement context selects another run")
    replacement_manifest = normalize_record(replacements["run-manifest.json"])
    if audit_phases(replacement_manifest) != phase_order:
        raise ValueError("recovery transaction cannot change recorded phase ownership")
    if replacement_manifest["status"] == "complete":
        raise ValueError("recovery transaction cannot publish complete state")
    expected_cleared = {phase: "pending" for phase in cleared}
    if rollback == "gap-exploration" and not invalidation:
        failed_gap = next((row for row in replacements["task-ledger.json"].get("tasks", [])
                           if row.get("id") == "GapExploration" and row.get("status") == "failed"), None)
        if failed_gap:
            expected_cleared[rollback] = "failed"
    if any(replacement_manifest.get("phases", {}).get(phase) not in SUCCESS for phase in retained) or any(replacement_manifest.get("phases", {}).get(phase) != status for phase, status in expected_cleared.items()):
        raise ValueError(f"{journal_path.name}: replacement checkpoints differ from recorded recovery")
    retained_tasks(replacements["task-ledger.json"], retained)
    work = journal.get("work_reconciliation", {})
    if not isinstance(work, dict) or any(phase not in {"sast", "intrusion", "gap-exploration", "synthesis", "final-verification"} or phase != rollback for phase in work):
        raise ValueError("recovery work reconciliation does not match its interrupted phase")
    if invalidation is not None and work:
        raise ValueError("explicit invalidation cannot preserve invalidated work")
    for phase in cleared:
        phase_directory(scan, phase)
    if not dry_run:
        if invalidation is not None:
            preserve_diagnostics(scan, context_path, event, cleared, journal)
        for phase in cleared:
            if phase in work:
                reconcile_work(scan, phase, work[phase])
            else:
                reset_directory(scan, phase)
        replacements["run-manifest.json"] = replacement_manifest
        # Legacy identity data is inert even when reconciling a pre-cutover journal.
        replacements["audit-context.json"] = normalize_record(replacements["audit-context.json"])
        for name in ("task-ledger.json", "run-manifest.json", "audit-context.json"):
            atomic_write(context_path if name == "audit-context.json" else scan / name, replacements[name])
        journal_path.unlink()
        sync_directory(scan)
    return rollback, len(retained), len(cleared)


def recover(args: argparse.Namespace) -> tuple[str, int, int]:
    scan, context_path = args.scan_base.resolve(), args.context.resolve()
    manifest = normalize_record(load(scan / "run-manifest.json"))
    ledger, context = load(scan / "task-ledger.json"), load(context_path)
    if not manifest.get("run_id") or any(value.get("run_id") != manifest["run_id"] for value in (ledger, context)):
        raise ValueError("run-manifest.json, task-ledger.json and context run_id differ")
    if Path(str(context.get("scan_base", ""))).resolve() != scan:
        raise ValueError("audit context does not select this scan")
    if manifest["status"] == "complete":
        raise ValueError("completed runs cannot be recovered")
    phases = manifest.get("phases")
    phase_order = audit_phases(manifest)
    journal_path = scan / ".recovery-invalidation.json"
    if journal_path.is_symlink():
        raise ValueError("unsafe .recovery-invalidation.json symlink")
    if journal_path.exists():
        return apply_journal(scan, context_path, journal_path, load(journal_path), manifest, args.reason, args.dry_run)
    rollback = next((phase for phase in phase_order if phases[phase] not in SUCCESS), None)
    if rollback is None:
        raise ValueError("run has no unfinished checkpoint to recover")
    if args.invalidate_phase:
        if phase_order.index(rollback) <= phase_order.index(args.invalidate_phase):
            raise ValueError("explicit invalidation requires a successful SAST checkpoint")
        if any(status == "running" for status in phases.values()):
            raise ValueError("explicit invalidation requires an inactive operation")
        rollback = args.invalidate_phase
    index = phase_order.index(rollback)
    retained, cleared = list(phase_order[:index]), list(phase_order[index:])
    tasks = retained_tasks(ledger, retained)
    if rollback == "gap-exploration" and not args.invalidate_phase:
        for row in ledger["tasks"]:
            if row["phase"] == rollback:
                kept = dict(row)
                if kept["status"] == "running":
                    kept.update(status="failed", artifact=None, error="interrupted gap exploration coordinator", failure_kind="execution_failed")
                    kept["failure_history"] = [*kept.get("failure_history", []), {
                        "attempt": kept["attempts"], "attempt_id": kept.get("attempt_id"),
                        "kind": "execution_failed", "error": kept["error"],
                    }]
                tasks.append(kept)
    # Never clear a later accepted checkpoint merely because earlier publication interrupted.
    if any(phases[phase] in SUCCESS for phase in cleared) and not args.invalidate_phase:
        raise ValueError("run-manifest.json has accepted checkpoints after unfinished work; reconcile the interrupted state publication")
    history = manifest.get("recovery_history", [])
    if not isinstance(history, list):
        raise ValueError("run-manifest.json recovery_history must be an array")
    event = {"generation": len(history) + 1, "recovered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "rollback_phase": rollback, "retained_phases": retained, "cleared_phases": cleared, "reason": args.reason or "interrupted or failed phase reset"}
    if args.invalidate_phase:
        event["invalidation"] = {"phase": rollback, "reason": args.reason, "archive_path": f"recovery-archives/generation-{event['generation']}"}
    updated = {**manifest, "status": "incomplete", "updated_at": event["recovered_at"], "recovery_count": event["generation"], "recovery_history": [*history, event], "phases": {**phases, **dict.fromkeys(cleared, "pending")}}
    if rollback == "gap-exploration" and not args.invalidate_phase and any(row["phase"] == rollback and row["status"] == "failed" for row in tasks):
        updated["phases"][rollback] = "failed"
    updated_context = {**context, "recovery_count": event["generation"], "last_recovery": event}
    journal = {"event": event, "replacement": {"run-manifest.json": updated, "task-ledger.json": {**ledger, "tasks": tasks}, "audit-context.json": updated_context}}
    preserve_work = rollback in {"sast", "intrusion", "gap-exploration"} or (
        "gap-exploration" in phase_order and rollback in {"synthesis", "final-verification"})
    if not args.invalidate_phase and preserve_work:
        journal["work_reconciliation"] = {rollback: unfinished_work(scan, rollback, context)}
        event["retained_work"] = [rollback]
    for phase in cleared:
        phase_directory(scan, phase)
    if not args.dry_run:
        atomic_write(journal_path, journal)
    return apply_journal(scan, context_path, journal_path, journal, manifest, args.reason, args.dry_run)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("context", type=Path)
    parser.add_argument("depth", choices=("quick", "balanced", "full"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--invalidate-phase", choices=("sast",))
    parser.add_argument("--reason")
    args = parser.parse_args()
    if args.invalidate_phase and (not args.reason or args.reason != args.reason.strip() or len(args.reason) > 1000 or not args.reason.isprintable()):
        parser.error("explicit invalidation requires a printable trimmed reason of 1..1000 characters")
    if args.reason and not args.invalidate_phase:
        parser.error("--reason requires --invalidate-phase sast")
    try:
        if args.dry_run:
            assert_owner(args.scan_base.resolve())
        else:
            claim_run(args.scan_base.resolve())
        with state_lock(args.scan_base.resolve()):
            result = recover(args)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    print("\t".join(map(str, result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
