#!/usr/bin/env python3
"""Run progress, producing-attempt provenance, and live session ownership.

These helpers never inspect or hash application source. Completed artifacts are
read as history; callers publish only their own new state and output.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import subprocess
import uuid


AUDIT_PHASE_DIRS = {
    "recon": "repo-context", "tool-collection": "tool-collection", "sast": "sast",
    "campaign-planning": "campaign-planning", "intrusion": "intrusion",
    "gap-exploration": "gap-exploration", "synthesis": "synthesis",
    "final-verification": "final-verification", "report": "report",
}
AUDIT_TASK_PHASES = dict(zip(
    ("Recon", "ToolCollection", "ThreatHunter", "CampaignPlanning", "Intrusion",
     "GapExploration", "Synthesis", "FinalVerification", "Report"),
    AUDIT_PHASE_DIRS,
))


def audit_phases(manifest: dict) -> tuple[str, ...]:
    """Use recorded ownership; never retrofit the optional phase on resume."""
    phases = manifest.get("phases")
    current = set(AUDIT_PHASE_DIRS)
    if not isinstance(phases, dict) or set(phases) not in (current, current - {"gap-exploration"}):
        raise ValueError("run-manifest.json phases must contain the canonical checkpoints")
    return tuple(phase for phase in AUDIT_PHASE_DIRS if phase in phases)


def optional_task_closed(task: dict, phase_state: str) -> bool:
    """Recognize only the updater's explicit failed optional-work checkpoint."""
    closure = task.get("optional_closure")
    return bool(
        task.get("id") in {"GapExploration", "AdvantageGapExploration"}
        and task.get("phase") == "gap-exploration" and phase_state == "degraded"
        and task.get("status") == "failed" and type(task.get("attempts")) is int
        and task["attempts"] >= 1
        and task.get("failure_kind") in {"execution_failed", "deadline_exceeded"}
        and isinstance(task.get("error"), str) and task["error"]
        and isinstance(closure, dict) and closure == {
            "phase": "gap-exploration", "status": "degraded",
            "artifact": "gap-exploration/results.json", "failure_reason": task["error"],
        } and task.get("artifact") is None
    )


SUCCESS = {"ok", "degraded", "skipped"}
INCOMPLETE = {"incomplete", "initialized", "running", "failed", "degraded", "interrupted"}
OBSOLETE_FIELDS = {
    "artifact_compatibility_id", "harness_contract_sha256", "target_fingerprint",
    "repository_set_sha256", "identity_sha256", "source_manifest_sha256",
    "source_report_sha256", "source_final_findings_sha256", "phase_seals", "seals",
}


def run_status(value: object) -> str:
    if value == "complete":
        return "complete"
    if isinstance(value, str) and value in INCOMPLETE:
        return "incomplete"
    raise ValueError(f"invalid or missing run status: {value!r}")


def normalize_record(record: dict) -> dict:
    """Normalize an in-memory read without changing historical files."""
    result = {key: value for key, value in record.items() if key not in OBSOLETE_FIELDS}
    if "status" in result:
        result["status"] = run_status(result["status"])
    return result


def _attempt_details(context: dict, started_at: str) -> dict:
    return {
        "repositories": deepcopy(context.get("repositories", [])),
        "model_routing": deepcopy(context.get("model_routing", {})),
        "source_root": context.get("source_root", context.get("repo_path")),
        "started_at": started_at,
        "source_view": ("base/derived" if context.get("mode") == "diff" else
                        "derived" if context.get("mode") == "actions" and context.get("patch_binding") else "base"),
        "patch_ref": ((context.get("patch_binding") or {}).get("patch_ref")
                      or (context.get("options") or {}).get("patch")),
        **({"gap_exploration_budget": deepcopy(context["gap_exploration_budget"])}
           if "gap_exploration_budget" in context else {}),
    }


def _scope(run_id: str | None, attempt_id: str | None, details: dict,
           assessment_id: str) -> dict:
    limitations = []
    if not details.get("repositories"):
        limitations.append("Original assessed repository scope is unavailable.")
    if not details.get("started_at"):
        limitations.append("Original assessment date is unavailable.")
    if not details.get("source_view"):
        limitations.append("Original assessed source view is unavailable.")
    return {
        "assessment_id": assessment_id, "run_id": run_id, "attempt_id": attempt_id,
        "repositories": deepcopy(details.get("repositories", [])),
        "source_root": details.get("source_root"), "started_at": details.get("started_at"),
        "source_view": details.get("source_view"), "patch_ref": details.get("patch_ref"),
        "limitations": limitations,
    }


def _needs_assessment(manifest: dict, context: dict) -> bool:
    phase = "handoff" if context.get("mode") == "actions" else "final-verification"
    state = manifest.get("phases", {}).get(phase)
    if (state.get("status") if isinstance(state, dict) else state) in SUCCESS:
        return False
    if context.get("mode") == "actions":
        options = context.get("options") or {}
        return bool(options.get("verify_fix") or options.get("assess_patch_risk"))
    return True


def start_attempt(manifest: dict, context: dict) -> str:
    """Capture the prior assignment before callers refresh current settings.

    Phase status remains a string. phase_attempts identifies the producer of a
    checkpoint; attempt_contexts stores its original routing and source metadata.
    """
    if manifest.get("status") == "complete":
        raise ValueError("cannot start an attempt in a completed run")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    attempts = dict(manifest.get("attempt_contexts", {}))
    phases = dict(manifest.get("phase_attempts", {}))
    previous = manifest.get("attempt_id") or "legacy"
    completed = [phase for phase, state in manifest.get("phases", {}).items()
                 if (state.get("status") if isinstance(state, dict) else state) in SUCCESS]
    if completed:
        attempts.setdefault(previous, _attempt_details(manifest, manifest.get("created_at", stamp)))
        for phase in completed:
            phases.setdefault(phase, previous)
    attempt_id = uuid.uuid4().hex
    attempts[attempt_id] = _attempt_details(context, stamp)
    scopes = deepcopy(manifest.get("assessment_scopes", {}))
    run_id = context.get("run_id") or manifest.get("run_id")
    for producer in set(phases.values()):
        identity = f"scope-{producer}"
        if not any(scope.get("attempt_id") == producer for scope in scopes.values()):
            scopes[identity] = _scope(run_id, producer, attempts.get(producer, {}), identity)
    assessment_id = None
    if _needs_assessment(manifest, context):
        assessment_id = f"scope-{uuid.uuid4().hex}"
        scopes[assessment_id] = _scope(run_id, attempt_id, attempts[attempt_id], assessment_id)
    fields = dict(attempt_id=attempt_id, attempt_contexts=attempts, phase_attempts=phases,
                  assessment_id=assessment_id, assessment_scopes=scopes)
    manifest.update(fields)
    context.update(deepcopy(fields))
    return attempt_id


def assessment_ref(context: dict) -> dict | None:
    attempt_id = context.get("attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        return None
    reference = {"attempt_id": attempt_id}
    if context.get("assessment_id"):
        reference["assessment_id"] = context["assessment_id"]
    return reference


def current_assessment(value: dict, context: dict) -> bool:
    """Admission of new work only; never use this to filter accepted publication."""
    assessment = value.get("assessment_context")
    return bool(context.get("attempt_id") and isinstance(assessment, dict)
                and assessment.get("attempt_id") == context["attempt_id"]
                and (not assessment.get("assessment_id")
                     or assessment["assessment_id"] == context.get("assessment_id")))


def report_assessment(context: dict, records: list[dict],
                      phase: str = "final-verification") -> dict:
    """Project recorded scopes of an accepted set without re-assessing source.

    The caller selects the owning execution's accepted checkpoint, not arbitrary
    candidates or baseline records. Nothing here grants current-source admission.
    """
    registry = context.get("assessment_scopes", {})
    attempts = context.get("attempt_contexts", {})
    producer = context.get("phase_attempts", {}).get(phase)
    fresh_advantage = context.get("execution_kind") == "advantage" and not attempts
    if fresh_advantage:
        producer = context.get("attempt_id")
    scopes, record_scopes = {}, {}
    retained = False
    run_id = context.get("run_id")
    for record in records or [{}]:
        reference = record.get("assessment_context") or {}
        attempt_id = reference.get("attempt_id") or producer
        assessment_id = reference.get("assessment_id") or (context.get("assessment_id") if fresh_advantage else None)
        scope = registry.get(assessment_id) if assessment_id else None
        if assessment_id and scope is None and not fresh_advantage:
            raise ValueError(f"unknown accepted assessment scope: {assessment_id}")
        if scope is None:
            scope = next((entry for entry in registry.values()
                          if attempt_id and entry.get("attempt_id") == attempt_id), None)
        if scope is None:
            assessment_id = f"scope-{attempt_id or 'legacy'}"
            details = attempts.get(attempt_id, {})
            if fresh_advantage:
                assessment_id = context.get("assessment_id") or assessment_id
                details = {**context, "started_at": context.get("created_at")}
            # A legacy original manifest has no attempt history. A resumed
            # publisher must never fill missing old scope from today's checkout.
            if not attempts and not context.get("attempt_id"):
                details = {**context, "started_at": context.get("created_at")}
            scope = _scope(run_id, attempt_id, details, assessment_id)
        if scope.get("run_id") not in {None, run_id}:
            raise ValueError("accepted assessment scope belongs to another execution")
        if attempt_id and scope.get("attempt_id") != attempt_id:
            raise ValueError("accepted assessment scope differs from producing attempt")
        identity = scope["assessment_id"]
        scopes[identity] = deepcopy(scope)
        record_id = record.get("id") or record.get("objective_id")
        if record_id:
            if record_id in record_scopes and record_scopes[record_id] != identity:
                raise ValueError(f"conflicting accepted assessment scopes for {record_id}")
            record_scopes[record_id] = identity
        retained |= bool(context.get("attempt_id") and attempt_id != context["attempt_id"])
    return {
        "scopes": [scopes[key] for key in sorted(scopes)],
        "record_scopes": record_scopes,
        "publication_attempt_id": context.get("attempt_id"),
        "retained": retained,
        "limitations": sorted({note for scope in scopes.values() for note in scope["limitations"]}),
    }


def routing_for_artifact(scan: Path, artifact_ref: str, fallback: dict) -> dict:
    """Resolve a contributor's producing assignment, not today's global route."""
    scan = Path(scan)
    report_path = scan / "report/security-report.json"
    if report_path.is_file():
        from report_bundle import document
        publication = document(scan, "report/security-report.json").get("publication")
        if publication:
            routes = publication.get("producer_routes", {})
            relative = artifact_ref.split("#", 1)[0]
            if relative in routes:
                return routes[relative]
            raise ValueError(f"missing published producing model assignment for {relative}")
    path = scan / "advantage-manifest.json"
    if not path.exists():
        path = scan / "run-manifest.json"
    if not path.exists():
        return fallback
    if path.is_symlink():
        raise ValueError(f"unsafe run manifest: {path}")
    from artifact_policy import artifact_size_limit
    limit = artifact_size_limit(path)
    if limit is not None and path.stat().st_size > limit:
        raise ValueError(f"run manifest exceeds bounded size policy: {path}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError(f"run manifest must contain an object: {path}")
    phase = artifact_ref.split("/", 1)[0]
    if phase == "repo-context":
        phase = "recon"
    attempt_id = manifest.get("phase_attempts", {}).get(phase)
    if artifact_ref.startswith(("sast/deepdive/", "sast/verify/", "sast/reproduction/")):
        from sast_contract import producing_attempt
        attempt_id = producing_attempt(scan, artifact_ref) or attempt_id
    elif artifact_ref.startswith("gap-exploration/results/"):
        from gap_exploration_contract import producing_attempt
        attempt_id = producing_attempt(scan, artifact_ref)
        if not attempt_id:
            raise ValueError("gap result has no admitted producing attempt")
    if attempt_id:
        if attempt_id == "legacy" and not manifest.get("attempt_contexts"):
            return manifest.get("model_routing", {})
        assignment = manifest.get("attempt_contexts", {}).get(attempt_id)
        if not isinstance(assignment, dict) or not isinstance(assignment.get("model_routing"), dict):
            raise ValueError(f"missing producing model assignment for phase {phase}")
        return assignment["model_routing"]
    state = manifest.get("phases", {}).get(phase)
    status = state.get("status") if isinstance(state, dict) else state
    if status in SUCCESS:
        if manifest.get("attempt_contexts"):
            raise ValueError(f"missing producing model assignment for phase {phase}")
        return manifest.get("model_routing", {})
    return manifest.get("model_routing", fallback)


def _process_identity(pid: int) -> str | None:
    if pid <= 0:
        raise ValueError("launcher process ID must be positive")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    proc = Path(f"/proc/{pid}/stat")
    try:
        fields = proc.read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        fields = None
    except (OSError, IndexError) as exc:
        raise ValueError(f"cannot read process identity for owner {pid}") from exc
    if fields is not None:
        if fields[0] == "Z":
            return None
        return f"linux:{fields[19]}"
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart=", "-o", "stat="],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        env={**os.environ, "LC_ALL": "C"}, timeout=5,
    )
    if result.returncode == 0 and result.stdout.strip():
        started, state = result.stdout.strip().rsplit(None, 1)
        return None if state.startswith("Z") else f"ps:{started}"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    raise ValueError(f"cannot establish liveness of run owner process {pid}")


def _session(session_id: str | None) -> tuple[str, int, str]:
    raw_pid = os.environ.get("VULNOPS_LAUNCHER_PID")
    try:
        pid = int(raw_pid) if raw_pid else os.getppid()
    except ValueError as exc:
        raise ValueError("invalid VULNOPS_LAUNCHER_PID") from exc
    started = _process_identity(pid)
    if started is None:
        raise ValueError("owning launcher process has exited")
    session_id = (session_id or os.environ.get("VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID")
                  or os.environ.get("VULNOPS_LAUNCHER_SESSION_ID") or f"direct-{pid}-{started}")
    return session_id, pid, started


def _runtime_location(base: Path) -> tuple[Path, str]:
    base = Path(base).absolute()
    if base.is_symlink() or not base.is_dir():
        raise ValueError(f"missing or unsafe run directory: {base}")
    stat = base.stat()
    runtime = Path(os.environ.get("VULNOPS_RUNTIME_ROOT", Path(__file__).resolve().parents[1] / ".harness"))
    directory = runtime / "run-owners"
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink():
        raise ValueError("unsafe run ownership directory")
    stem = f"{stat.st_dev}-{stat.st_ino}"
    return directory, stem


@contextmanager
def state_lock(base: Path):
    """Serialize a state transaction, independently of session ownership."""
    directory, stem = _runtime_location(base)
    descriptor = os.open(directory / f"{stem}.state.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def _owner_record(base: Path):
    directory, stem = _runtime_location(base)
    lock = directory / f"{stem}.lock"
    path = directory / f"{stem}.json"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        owner = None
        if path.is_symlink():
            raise ValueError("unsafe run owner record")
        if path.exists():
            if path.stat().st_size > 8192:
                raise ValueError("run owner record exceeds size limit")
            owner = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(owner, dict) or not isinstance(owner.get("pid"), int)
                    or isinstance(owner.get("pid"), bool)
                    or not isinstance(owner.get("started"), str)
                    or not isinstance(owner.get("session_id"), str)):
                raise ValueError("invalid run owner record")
        yield path, owner
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _live(owner: dict | None) -> bool:
    return owner is not None and _process_identity(owner["pid"]) == owner["started"]


def claim_run(base: Path, session_id: str | None = None) -> None:
    session_id, pid, started = _session(session_id)
    with _owner_record(base) as (path, owner):
        if _live(owner) and (owner["session_id"], owner["pid"], owner["started"]) != (session_id, pid, started):
            raise ValueError(f"run already has an active owner (process {owner['pid']}); wait for that session to exit")
        value = {"session_id": session_id, "pid": pid, "started": started, "run": str(Path(base).resolve())}
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(json.dumps(value) + "\n", encoding="utf-8")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def assert_owner(base: Path, session_id: str | None = None) -> bool:
    """Reject a competing live owner; return whether this session owns the run."""
    session_id, pid, started = _session(session_id)
    with _owner_record(base) as (_, owner):
        live = _live(owner)
        if live and (owner["session_id"], owner["pid"], owner["started"]) != (session_id, pid, started):
            raise ValueError(f"run belongs to another active session (process {owner['pid']})")
        return live


def release_run(base: Path, session_id: str | None = None) -> None:
    session_id, pid, started = _session(session_id)
    with _owner_record(base) as (path, owner):
        if owner and (owner["session_id"], owner["pid"], owner["started"]) == (session_id, pid, started):
            path.unlink(missing_ok=True)


def clear_run_context(path: Path, base: Path, run_id: str, session_id: str | None = None) -> None:
    """Remove only the runtime pointer still naming this execution."""
    try:
        path.lstat()
    except FileNotFoundError:
        return
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("unsafe runtime context")
    context = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(context, dict):
        raise ValueError("runtime context must be an object")
    if (context.get("scan_base") == str(base.resolve()) and context.get("run_id") == run_id
            and (session_id is None or context.get("launcher_session_id") == session_id)):
        path.unlink()


def require_active_phase(base: Path, context: dict, phase: str) -> None:
    """Admit a publisher against existing execution, task and session authority."""
    base = Path(base).resolve()
    if Path(context["scan_base"]).resolve() != base:
        raise ValueError("publication destination differs from the active execution")
    if phase not in AUDIT_PHASE_DIRS:
        raise ValueError("unknown ordinary publication phase")
    for relative in ("run-manifest.json", "task-ledger.json", AUDIT_PHASE_DIRS[phase]):
        path = base / relative
        if path.resolve() != path:
            raise ValueError("publication authority or destination may not redirect")
    manifest = json.loads((base / "run-manifest.json").read_text(encoding="utf-8"))
    ledger = json.loads((base / "task-ledger.json").read_text(encoding="utf-8"))
    if (not context.get("run_id") or manifest.get("run_id") != context["run_id"]
            or ledger.get("run_id") != context["run_id"]
            or run_status(manifest.get("status")) != "incomplete"
            or manifest.get("phases", {}).get(phase) != "running"
            or manifest.get("attempt_id") != context.get("attempt_id")):
        raise ValueError("publication requires the active execution and owning phase")
    task_id = next(task for task, owner in AUDIT_TASK_PHASES.items() if owner == phase)
    active = [task for task in ledger.get("tasks", []) if task.get("status") == "running"]
    if (len(active) != 1 or active[0].get("id") != task_id
            or active[0].get("phase") != phase
            or active[0].get("attempt_id") != context.get("attempt_id")):
        raise ValueError("publication requires the active owning task")
    if not assert_owner(base):
        raise ValueError("publication requires a live owning session")
