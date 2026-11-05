"""On-demand, run/view-owned navigation with native Advantage containment."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import time

from codegraph_setup import OPTIONAL_FAILURE, SHUTDOWN_GRACE_SECONDS, run_setup_command
from remediation_common import atomic_json
from run_lifecycle import state_lock

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", ".codegraph", ".harness"}


def source_digest(source: Path, deadline: float) -> str:
    """Fingerprint preparation, not run identity; never follow source symlinks."""
    source = source.resolve(strict=True)
    digest = hashlib.sha256()
    for root, directories, files in os.walk(source, followlinks=False):
        links = sorted(name for name in directories if (Path(root) / name).is_symlink())
        directories[:] = sorted(name for name in directories if name not in EXCLUDED and name not in links)
        for name in [*links, *sorted(files)]:
            if time.monotonic() >= deadline:
                raise TimeoutError("Codegraph preparation fingerprint exceeded its allowance")
            if name in EXCLUDED:
                continue
            path = Path(root) / name
            relative = path.relative_to(source).as_posix()
            digest.update(relative.encode() + b"\0")
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(source):
                    raise ValueError("Codegraph source symlink escapes its authorized source view")
                digest.update(b"link\0" + resolved.relative_to(source).as_posix().encode() + b"\0")
            else:
                if not path.is_file():
                    raise ValueError("Codegraph source contains a non-regular file")
                digest.update(b"file\0")
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Codegraph preparation fingerprint exceeded its allowance")
                        digest.update(block)
                digest.update(b"\0")
    return digest.hexdigest()


def _dispatch(context: dict) -> tuple[Path, dict]:
    if context.get("execution_kind") == "advantage":
        raise ValueError("Advantage graph operations have no dispatch state")
    base = Path(context["scan_base"])
    path = base / "gap-exploration/dispatch.json"
    if path.resolve() != base.resolve() / "gap-exploration/dispatch.json":
        raise ValueError("gap graph dispatch redirects outside its authority")
    document = json.loads(path.read_text())
    if document.get("run_id") != context["run_id"]:
        raise ValueError("gap graph dispatch belongs to another execution")
    consumption = document.setdefault("graph_consumption", {"preparations": [], "queries": []})
    if not isinstance(consumption, dict) or set(consumption) != {"preparations", "queries"}:
        raise ValueError("invalid gap graph consumption")
    for entries in consumption.values():
        if not isinstance(entries, list):
            raise ValueError("invalid gap graph accounting entries")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("run_id") != context["run_id"]:
                raise ValueError("gap graph accounting belongs to another execution")
            seconds = entry.get("seconds")
            if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
                raise ValueError("invalid gap graph consumed seconds")
    return path, document


def _reserve(context: dict, question: dict, owner: str, kind: str) -> tuple[int, float]:
    if context.get("execution_kind") == "advantage":
        from advantage_contract import live_call
        operation = live_call(context, "gap-exploration").get("operation", {})
        if (operation.get("kind") != "graph" or operation.get("owner_id") != owner
                or operation.get("question_id") != question["id"]
                or operation.get("phase") != "gap-exploration"):
            raise ValueError("gap graph requires its actual native operation allocation")
        key = "preparation_timeout_seconds" if kind == "preparations" else "timeout_seconds"
        allowance = operation.get(key)
        ceiling = context["gap_exploration_budget"]["preparation_timeout_seconds" if kind == "preparations" else "graph_timeout_seconds"]
        if type(allowance) not in (int, float) or not math.isfinite(allowance) or not 0 < allowance <= ceiling:
            raise ValueError("gap graph native operation allowance exhausted; continue source-only")
        return operation["id"], min(120, allowance) if kind == "queries" else allowance
    with state_lock(Path(context["scan_base"])):
        path, document = _dispatch(context)
        entries = document["graph_consumption"][kind]
        budget = context["gap_exploration_budget"]
        key = "preparation_timeout_seconds" if kind == "preparations" else "graph_timeout_seconds"
        remaining = budget[key] - sum(entry["seconds"] for entry in entries)
        if remaining <= 0:
            raise ValueError(f"gap graph {kind} allowance exhausted; continue source-only")
        if kind == "queries":
            if len(entries) >= budget["max_questions"] or any(
                entry["owner_id"] == owner and entry["question_id"] == question["id"] for entry in entries
            ):
                raise ValueError("gap graph logical question allowance exhausted or question already attempted")
            remaining = min(120, remaining)
        elif any(entry["status"] == "running" and entry["source_view"] == question["source_view"] for entry in entries):
            raise ValueError("gap graph preparation already reserved for this source view; continue source-only")
        entry = {"run_id": context["run_id"], "attempt_id": context["attempt_id"],
                 "owner_id": owner, "question_id": question["id"], "source_view": question["source_view"],
                 "status": "running", "seconds": remaining, "allowance_seconds": remaining, "limitation": None}
        entries.append(entry)
        atomic_json(path, document)
        return len(entries) - 1, remaining


def _finish(context: dict, kind: str, index: int, elapsed: float, **fields) -> None:
    if context.get("execution_kind") == "advantage":
        from advantage_contract import live_call
        if live_call(context, "gap-exploration").get("operation", {}).get("id") != index:
            raise ValueError("graph completion differs from current native operation")
        # The native call owns consumed execution; receipt/context retain observations.
        return
    with state_lock(Path(context["scan_base"])):
        path, document = _dispatch(context)
        entry = document["graph_consumption"][kind][index]
        if entry["attempt_id"] != context["attempt_id"] or entry["status"] != "running":
            raise ValueError("gap graph accounting completion differs from reserved attempt")
        entry.update(seconds=min(entry["allowance_seconds"], max(0, elapsed)), **fields)
        atomic_json(path, document)


def fail_running(context: dict, reason: str) -> int:
    """Close reservations after the controller has stopped their descendants."""
    if context.get("execution_kind") == "advantage":
        raise ValueError("native operation outcomes own Advantage graph interruption")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("interrupted graph closure requires an exact failure reason")
    with state_lock(Path(context["scan_base"])):
        path, document = _dispatch(context)
        changed = 0
        for entries in document["graph_consumption"].values():
            for entry in entries:
                if entry["status"] == "running":
                    entry.update(status="interrupted", limitation=reason)
                    changed += 1
        if changed:
            atomic_json(path, document)
        return changed


def source_context(context: dict, view: str) -> dict:
    from gap_exploration_contract import source_context as selected_context
    if view not in {"base", "derived"}:
        raise ValueError("gap graph source view is not qualified")
    return selected_context(context, view)


def _runtime(context: dict, view: str) -> Path:
    run_id = context["run_id"]
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id) or ".." in run_id:
        raise ValueError("unsafe gap graph execution identity")
    base = ROOT / ".harness/codegraph" / run_id
    runtime = base if view == "base" else base / "gap-derived"
    if runtime.resolve() != runtime:
        raise ValueError("gap graph runtime redirects outside its run/view authority")
    if (runtime / "project").resolve() != runtime / "project":
        raise ValueError("gap graph project redirects outside its run/view authority")
    if view == "base":
        paths = context.get("paths", {})
        for key, expected in (("codegraph_runtime", runtime), ("codegraph_project", runtime / "project")):
            if paths.get(key) is not None and Path(paths[key]) != expected:
                raise ValueError("gap graph configured navigation belongs to another run or source view")
    return runtime


def _setup(source: Path, runtime: Path, seconds: float) -> tuple[bool, str | None]:
    # The shared supervisor owns shutdown; never hard-kill it while its isolated
    # worker group is still alive. Reserve shutdown inside this caller's budget.
    work_seconds = seconds - SHUTDOWN_GRACE_SECONDS
    if work_seconds <= 0:
        return False, "Codegraph preparation has no work allowance after reserving shutdown"
    environment = {**os.environ, "CODEGRAPH_TARGET_DIR": str(source), "CODEGRAPH_RUNTIME_DIR": str(runtime),
                   "CODEGRAPH_INIT_TIMEOUT_SECONDS": str(work_seconds)}
    environment.pop("VULNOPS_ADVANTAGE_CALL", None)
    result = run_setup_command(["bash", str(ROOT / "scripts/setup-codegraph.sh")], env=environment)
    if result == OPTIONAL_FAILURE:
        return False, "Codegraph preparation failed within the remaining supplementary setup allowance"
    if result:
        raise SystemExit(result)
    return True, None


def prepare_navigation(context: dict, owner: str, question: dict) -> Path:
    """Called only after canonical registration, never for a zero-question plan."""
    if not context["gap_exploration_budget"]["enabled"] or context.get("mode") == "actions":
        raise ValueError("gap graph exploration is disabled; continue source-only")
    if context.get("codegraph_mode") == "disabled":
        raise ValueError(context.get("codegraph_limitation") or "Codegraph explicitly disabled; continue source-only")
    selected = source_context(context, question["source_view"])
    source = Path(selected.get("source_root") or selected["repo_path"]).resolve(strict=True)
    runtime = _runtime(context, question["source_view"])
    if runtime.is_relative_to(source) or source.is_relative_to(runtime):
        raise ValueError("gap graph preparation must be outside the authorized source")
    index, allowance = _reserve(context, question, owner, "preparations")
    started = time.monotonic()
    deadline = started + allowance
    details = {"runtime": str(runtime)}
    try:
        before = source_digest(source, deadline)
        details["source_sha256"] = before
        project = runtime / "project"
        database = project / ".codegraph/codegraph.db"
        if database.resolve() != database:
            raise ValueError("gap graph index redirects outside its owned project")
        navigation = {**selected, "codegraph_mode": "enabled", "codegraph_limitation": None,
                      "paths": {**selected.get("paths", {}), "codegraph_runtime": str(runtime),
                                "codegraph_project": str(project)}}
        from codegraph_contract import current_navigation
        ready = False
        # A run-specific healthy setup and byte-identical admitted view, not installed CLI presence.
        receipt_path = runtime / "index-receipt.json"
        if receipt_path.is_file():
            if receipt_path.resolve() != receipt_path:
                raise ValueError("gap graph preparation receipt redirects outside its runtime")
            receipt = json.loads(receipt_path.read_text())
            if receipt.get("status") == "ok":
                try:
                    current_navigation(navigation)
                except ValueError:
                    pass
                else:
                    ready = source_digest(project, deadline) == before
        if not ready:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Codegraph preparation exhausted its allowance before setup")
            ok, limitation = _setup(source, runtime, remaining)
            if not ok:
                raise OSError(limitation)
            if not database.is_file():
                raise OSError("Codegraph preparation did not produce a usable index")
            current_navigation(navigation)
        after = source_digest(source, deadline)
        prepared = source_digest(project, deadline)
        if before != after or prepared != after:
            raise OSError("Codegraph source changed during preparation; fresh navigation unavailable")
        details["project_sha256"] = prepared
        _finish(context, "preparations", index, time.monotonic() - started,
                status="reused" if ready else "prepared", **details)
        return project
    except (OSError, TimeoutError) as exc:
        _finish(context, "preparations", index, time.monotonic() - started,
                status="unavailable", limitation=str(exc), **details)
        raise ValueError(f"{exc}; continue source-only") from exc
    except SystemExit as exc:
        _finish(context, "preparations", index, time.monotonic() - started,
                status="interrupted" if exc.code in (130, 143) else "integrity_failed",
                limitation=f"Codegraph preparation stopped (exit {exc.code})", **details)
        raise
    except Exception:
        _finish(context, "preparations", index, time.monotonic() - started,
                status="integrity_failed", limitation="navigation integrity validation failed", **details)
        raise


def reserve_query(context: dict, owner: str, question: dict) -> dict:
    index, allowance = _reserve(context, question, owner, "queries")
    return {"timeout_seconds": allowance, "gap_query": {"context": context, "index": index}}


def finish_query(request: dict, elapsed: float) -> None:
    reservation = request["gap_query"]
    _finish(reservation["context"], "queries", reservation["index"], elapsed,
            status="completed", receipt_ref=str(request["receipt"].relative_to(Path(reservation["context"]["scan_base"]))))


def fail_query(request: dict, limitation: str) -> None:
    reservation = request["gap_query"]
    _finish(reservation["context"], "queries", reservation["index"], 0,
            status="unavailable", limitation=limitation)


def record_receipt(request: dict) -> None:
    """Retain wrapper bytes; only healthy validated navigation can be useful."""
    reservation = request["gap_query"]
    context = reservation["context"]
    base = Path(context["scan_base"])
    receipt = json.loads(request["receipt"].read_text())
    healthy = receipt.get("status") == "ok" and receipt.get("parse_status") == "ok"
    meaningful = False
    if healthy:
        from codegraph_contract import validate_query_receipt
        selected = source_context(context, request["question"]["source_view"])
        document = validate_query_receipt(
            base, Path(selected.get("source_root") or selected["repo_path"]), context,
            "gap-exploration", request["binding"]["owner_id"], request["question"],
            request["receipt"].relative_to(base).as_posix())
        meaningful = document["meaningful"]
    if context.get("execution_kind") == "advantage":
        from advantage_contract import live_call
        if live_call(context, "gap-exploration").get("operation", {}).get("id") != reservation["index"]:
            raise ValueError("graph receipt differs from current native operation")
        return
    with state_lock(base):
        path, dispatch = _dispatch(context)
        entry = dispatch["graph_consumption"]["queries"][reservation["index"]]
        if entry["attempt_id"] != context["attempt_id"] or entry["status"] != "completed":
            raise ValueError("gap graph receipt differs from its completed query reservation")
        entry.update(receipt_sha256=hashlib.sha256(request["receipt"].read_bytes()).hexdigest(),
                     context_sha256=hashlib.sha256(request["output"].read_bytes()).hexdigest(),
                     context_ref=request["output"].relative_to(base).as_posix(),
                     receipt_health="ok" if healthy else "failed", meaningful=meaningful)
        if not healthy:
            entry["limitation"] = "; ".join(receipt.get("warnings", [])) or "Codegraph query failed"
        atomic_json(path, dispatch)


def receipt_support(context: dict) -> list[dict]:
    """Return checksum-bound retention inputs, not a new evidence authority."""
    from codegraph_contract import _question_directory
    if context.get("execution_kind") == "advantage":
        return [{"ref": row[kind + "_ref"], "sha256": row[kind + "_sha256"]}
                for row in observations(context) for kind in ("receipt", "context")]
    base = Path(context["scan_base"])
    _, dispatch = _dispatch(context)
    support = []
    for entry in dispatch["graph_consumption"]["queries"]:
        directory = _question_directory(base, "gap-exploration", entry["owner_id"], entry["question_id"])
        for kind, name in (("receipt", "receipt.json"), ("context", "context.json")):
            checksum = entry.get(kind + "_sha256")
            if checksum is None:
                continue
            path = directory / name
            reference = path.relative_to(base).as_posix()
            if entry.get(kind + "_ref") != reference or path.resolve() != path:
                raise ValueError("gap graph retained support is outside its canonical query owner")
            if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError("gap graph retained support changed after wrapper publication")
            support.append({"ref": reference, "sha256": checksum})
    return support


def observations(context: dict) -> list[dict]:
    """Retain graph evidence, not operation reservations or remaining allowances."""
    from advantage_contract import inside, load, sha256_file
    base = Path(context["scan_base"])
    plan_path = inside(base, "gap-exploration/plan.json")
    if not plan_path.is_file():
        return []
    result = []
    for question in load(plan_path)["graph_questions"]:
        directory = f"gap-exploration/codegraph-runs/{question['owner']}/{question['id']}"
        receipt_path = inside(base, directory + "/receipt.json")
        context_path = inside(base, directory + "/context.json")
        if not receipt_path.is_file() or not context_path.is_file():
            continue
        receipt, document = load(receipt_path), load(context_path)
        if receipt.get("normalized_sha256") != sha256_file(context_path):
            raise ValueError("gap graph observation changed normalized context bytes")
        binding = receipt.get("binding", {})
        if (binding.get("run_id") != context["run_id"] or binding.get("owner_id") != question["owner"]
                or binding.get("question_id") != question["id"] or binding.get("source_view") != question["source_view"]
                or document.get("binding") != binding):
            raise ValueError("gap graph observation changed source/view/question ownership")
        healthy = receipt.get("status") == "ok" and receipt.get("parse_status") == "ok"
        row = {"owner_id": question["owner"], "question_id": question["id"], "source_view": question["source_view"],
               "receipt_ref": receipt_path.relative_to(base).as_posix(), "receipt_sha256": sha256_file(receipt_path),
               "context_ref": context_path.relative_to(base).as_posix(), "context_sha256": sha256_file(context_path),
               "receipt_health": "ok" if healthy else "failed", "meaningful": healthy and document.get("meaningful") is True}
        if not healthy:
            row["limitation"] = "; ".join(receipt.get("warnings", [])) or "Codegraph query failed"
        result.append(row)
    return result
