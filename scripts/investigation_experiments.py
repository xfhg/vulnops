"""Contained uncertainty resolution, deliberately separate from finding reproduction."""
from __future__ import annotations

import fcntl
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
from run_lifecycle import assert_owner

ROOT = Path(__file__).resolve().parents[1]
BOUNDARY = "Only the isolated behavior was exercised; no production exposure, credential validity, end-to-end exploitability, finding confirmation, or patch validation is established."


def validate_schema(document: dict, name: str) -> None:
    spec = importlib.util.spec_from_file_location("experiment_json_validator", ROOT / "scripts/validate-json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = json.loads((ROOT / "schemas/v2" / name).read_text())
    errors = module.Validator(schema).collect(document, schema)
    if errors:
        raise ValueError("experiment contract invalid: " + "; ".join(errors[:8]))


def inside(base: Path, path: Path) -> Path:
    if not path.is_relative_to(base):
        raise ValueError("experiment path escapes its owner")
    for part in [path, *path.parents]:
        if part == base:
            break
        if part.is_symlink():
            raise ValueError("experiment path contains a symlink")
    if not path.resolve().is_relative_to(base.resolve()):
        raise ValueError("experiment path escapes its owner")
    return path


def load(path: Path, limit: int = 65536) -> dict:
    if path.stat().st_size > limit:
        raise ValueError("experiment input exceeds its metadata size limit")
    return json.loads(path.read_text())


def validate_request(context: dict, request: dict, scan: Path) -> None:
    linked = context.get("execution_kind") == "advantage"
    validate_schema(request, "advantage-experiment.schema.json" if linked else "investigation-experiment.schema.json")
    if linked:
        from advantage_owners import validate_experiment
        validate_experiment(context, request, active=False)
    if request["run_id"] != context["run_id"]:
        raise ValueError("experiment run identity mismatch")
    if request["support_exit_code"] == request["contradict_exit_code"]:
        raise ValueError("support and contradiction must be distinguishable")
    if any("\x00" in arg for arg in request["command"]):
        raise ValueError("NUL in experiment command")
    for ref in [request["owner_ref"], *([] if linked else request["input_refs"])]:
        path = Path(ref.split("#", 1)[0])
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("experiment references must be scan-relative")
        if not inside(scan, scan / path).is_file():
            raise ValueError("experiment evidence reference does not exist")
    if Path(request["owner_ref"].split("#", 1)[0]).parts[0] != request["owner_phase"]:
        raise ValueError("experiment owner belongs to another phase")


def make_result(context: dict, request: dict, ref: str, digest: str, status: str,
                sandbox: str = "none", exit_code: int | None = None) -> dict:
    outcomes = {
        "supported": ("established", "The isolated test returned its declared supporting observation code.", "Apply this observation only to the named obligation; independently assess exposure and remaining transitions.", ""),
        "contradicted": ("contradicted", "The isolated test returned its declared contradicting observation code.", "Revise the hypothesis for this behavior and continue source analysis.", ""),
        "disabled": ("locally_unresolved", "Reproduction mode is off; no target command was executed.", "Continue source analysis; an experiment requires a separately authorized safe-mode run.", "The named behavior has not been observed under containment."),
        "containment_unavailable": ("externally_blocked", "Functional containment is unavailable; no target command was executed.", "Continue source analysis; use an authorized environment with functional containment to resolve this obligation.", "A functional approved offline containment backend is unavailable."),
        "budget_deferred": ("budget_deferred", "The application-wide experiment budget is exhausted; no target command was executed.", "Preserve this obligation for a separately budgeted continuation.", "The named behavior has not been exercised within the allocated budget."),
        "execution_failed": ("execution_failed", "The contained experiment could not complete with a declared observation; this is not a security verdict.", "Review the required local dependencies and test contract before a separately budgeted attempt; continue source analysis.", "A valid supporting or contradicting observation is unavailable."),
    }
    outcome, reason, action, missing = outcomes[status]
    result = {"schema_version": "2.0", "run_id": context["run_id"], "experiment_id": request["experiment_id"],
              "owner_phase": request["owner_phase"], "request_ref": ref, "request_sha256": digest,
              "status": status, "sandbox": sandbox, "exit_code": exit_code, "limits": context["experiment_budget"],
              "resolution": {"outcome": outcome, "reason": reason, "next_action": action,
                             "evidence_refs": [ref], "missing_fact": missing}, "interpretation_boundary": BOUNDARY}
    if request.get("attempt_id"):
        result["attempt_id"] = request["attempt_id"]
    if context.get("execution_kind") == "advantage":
        result.update({key: request[key] for key in ("execution_kind", "owner_id", "question_id", "source_view", "baseline_execution_id")})
    validate_schema(result, "advantage-experiment-result.schema.json" if context.get("execution_kind") == "advantage" else "investigation-experiment-result.schema.json")
    return result


def validate_result(context: dict, request: dict, result: dict, request_path: Path) -> str:
    scan = Path(context["scan_base"])
    validate_request(context, request, scan)
    validate_schema(result, "advantage-experiment-result.schema.json" if context.get("execution_kind") == "advantage" else "investigation-experiment-result.schema.json")
    status = result["status"]
    current = bool(context.get("attempt_id")) and result.get("attempt_id") == context["attempt_id"]
    if status in {"supported", "contradicted"}:
        expected_code = request["support_exit_code" if status == "supported" else "contradict_exit_code"]
        if result["sandbox"] != "bubblewrap" or result["exit_code"] != expected_code or (current and context["reproduction_mode"] != "safe"):
            raise ValueError("experiment observation lacks authorized contained execution")
    elif status != "execution_failed" and (result["exit_code"] is not None or result["sandbox"] != "none"):
        raise ValueError("unexecuted experiment claims execution metadata")
    if current and status == "disabled" and context["reproduction_mode"] != "off":
        raise ValueError("disabled experiment differs from current execution policy")
    recorded_context = context if current else {**context, "experiment_budget": result["limits"]}
    expected = make_result(recorded_context, request, request_path.relative_to(scan).as_posix(),
                           hashlib.sha256(request_path.read_bytes()).hexdigest(), status,
                           result["sandbox"], result["exit_code"])
    actual = {key: value for key, value in result.items() if key != "source_fingerprint"}
    if actual != expected:
        raise ValueError("experiment result differs from its request, owner, or observation")
    return "current" if current else "historical"


def run(context_path: Path, request_path: Path) -> Path:
    context_path = context_path.resolve()
    context = load(context_path)
    if context.get("execution_kind") == "advantage":
        from advantage_contract import load_context
        context = load_context(context_path)
    scan = Path(context["scan_base"])
    if not scan.is_absolute() or not scan.resolve().is_relative_to(ROOT / "scans"):
        raise ValueError("experiment scan must be inside the harness scans directory")
    inside(ROOT, scan)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context["run_id"]) or ".." in context["run_id"]:
        raise ValueError("unsafe experiment run identity")
    request_path = request_path.absolute()
    inside(scan, request_path)
    request = load(request_path)
    validate_request(context, request, scan)
    linked = context.get("execution_kind") == "advantage"
    if not linked:
        assert_owner(scan, context.get("launcher_session_id"))
    attempt = context.get("attempt_id")
    if not isinstance(attempt, str) or not attempt or request.get("attempt_id") != attempt:
        raise ValueError("experiment request must belong to the current attempt")
    directory = scan / request["owner_phase"] / "experiments" / request["experiment_id"]
    if request_path != directory / "request.json":
        raise ValueError("experiment request must use its canonical owner path")
    result_path = inside(scan, directory / "result.json")
    operation = None
    if linked:
        from advantage_owners import validate_experiment
        validate_experiment(context, request)
        from advantage_contract import live_call
        operation = live_call(context, request["owner_phase"]).get("operation", {})
        if (operation.get("kind") != "experiment" or operation.get("phase") != request["owner_phase"]
                or operation.get("owner_id") != request["owner_id"] or operation.get("question_id") != request["question_id"]
                or operation.get("request_ref") != request_path.relative_to(scan).as_posix()
                or operation.get("request_sha256") != hashlib.sha256(request_path.read_bytes()).hexdigest()):
            raise ValueError("contained execution requires its exact native request allocation")
    else:
        manifest = load(scan / "run-manifest.json")
        for key in ("run_id", "attempt_id"):
            if not context.get(key) or manifest.get(key) != context[key]:
                raise ValueError("experiment context differs from current owner: " + key)
        if manifest.get("phases", {}).get(request["owner_phase"]) != "running":
            raise ValueError("experiment owner phase is not mutable and running")
        context.update({key: manifest[key] for key in ("reproduction_mode", "experiment_budget")})
    digest = hashlib.sha256(request_path.read_bytes()).hexdigest()
    ref = request_path.relative_to(scan).as_posix()
    # Validate the current finite resource envelope before any backend operation.
    make_result(context, request, ref, digest, "disabled")
    if not linked:
        lock_dir = inside(ROOT, ROOT / "work" / context["run_id"] / "experiments")
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = inside(ROOT, lock_dir / "experiment.lock")
        ledger_path = inside(ROOT, lock_dir / "experiment-attempts.json")
    reservation = attempt + ":" + ref
    with (nullcontext() if linked else lock_path.open("a")) as lock:
        if not linked:
            # Ordinary unfinished work retains its existing recovery accounting.
            fcntl.flock(lock, fcntl.LOCK_EX)
        if result_path.exists():
            prior = load(result_path)
            if prior.get("request_sha256") != digest:
                raise ValueError("completed experiment request is immutable")
            validate_result(context, request, prior, request_path)
            return result_path
        status, sandbox, exit_code = "disabled", "none", None
        if context.get("reproduction_mode") == "safe":
            attempts = {} if linked else load(ledger_path) if ledger_path.exists() else {}
            consumed = set(attempts)
            if not linked:
                legacy_refs = set()
                for prior_ledger in lock_dir.parent.glob("experiments-generation-*/experiment-attempts.json"):
                    prior = load(inside(ROOT, prior_ledger))
                    legacy_refs.update(prior)
                    consumed.update(prior_ledger.parent.name + ":" + item for item in prior)
                for prior_path in scan.glob("*/experiments/*/result.json"):
                    prior = load(inside(scan, prior_path))
                    if prior.get("sandbox") == "bubblewrap" and prior.get("request_ref") not in legacy_refs:
                        consumed.add(str(prior.get("attempt_id", "legacy")) + ":" + prior["request_ref"])
            if reservation in attempts:
                status = "execution_failed"  # Interrupted reservations are never silently replayed.
            elif len(consumed) >= context["experiment_budget"]["max_experiments"]:
                status = "budget_deferred"
            else:
                wrapper = ROOT / "scripts/run-safe-reproduction.sh"
                context_variable = "VULNOPS_ADVANTAGE_CONTEXT" if linked else "VULNOPS_AUDIT_CONTEXT"
                env = {"PATH": "/usr/bin:/bin", context_variable: str(context_path), "VULNOPS_REPRODUCTION_SANDBOX": "bubblewrap", "VULNOPS_EXPERIMENT_PHASE": request["owner_phase"]}
                env["VULNOPS_LAUNCHER_PID"] = os.environ.get("VULNOPS_LAUNCHER_PID", str(os.getppid()))
                for key in ("VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID", "VULNOPS_LAUNCHER_SESSION_ID", "VULNOPS_RUNTIME_ROOT"):
                    if key in os.environ:
                        env[key] = os.environ[key]
                for key in ("timeout_seconds", "cpu_seconds", "memory_mb", "max_processes", "max_output_kb"):
                    env["VULNOPS_REPRODUCTION_" + key.upper()] = str(context["experiment_budget"][key])
                workspace_id = "experiment-" + request["owner_phase"] + "-" + request["experiment_id"]
                def invoke(action: str, *args: str) -> int:
                    # No proof output is retained or copied into result metadata.
                    command = [str(wrapper), str(scan), workspace_id, action, *args]
                    options = {"env": env, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                               "timeout": context["experiment_budget"]["timeout_seconds"] + 30}
                    if linked and action != "detect":
                        from advantage_contract import run_native
                        return run_native(command, context, **options).returncode
                    return subprocess.run(command, **options).returncode
                try:
                    if invoke("detect") != 0:
                        status = "containment_unavailable"
                    else:
                        attempts[reservation] = digest
                        if not linked:
                            temporary = inside(ROOT, ledger_path.with_suffix(".tmp"))
                            temporary.write_text(json.dumps(attempts, sort_keys=True) + "\n")
                            temporary.replace(ledger_path)
                        sandbox = "bubblewrap"
                        prepared = invoke("prepare")
                        if prepared:
                            status = "containment_unavailable" if prepared == 4 else "execution_failed"
                            sandbox = "none"
                        else:
                            exit_code = invoke("exec", "--", *request["command"])
                            status = ("supported" if exit_code == request["support_exit_code"] else
                                      "contradicted" if exit_code == request["contradict_exit_code"] else "execution_failed")
                except (OSError, subprocess.TimeoutExpired):
                    status = "execution_failed" if reservation in attempts else "containment_unavailable"
                finally:
                    if reservation in attempts:
                        try:
                            if invoke("clean") != 0:
                                status = "execution_failed"
                        except (OSError, subprocess.TimeoutExpired):
                            status = "execution_failed"
        result = make_result(context, request, ref, digest, status, sandbox, exit_code)
        validate_result(context, request, result, request_path)
        temporary = inside(scan, directory / "result.json.tmp")
        temporary.write_text(json.dumps(result, indent=2) + "\n")
        temporary.replace(result_path)
    return result_path
