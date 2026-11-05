#!/usr/bin/env python3
"""Local ownership, safe evidence reads and phase authority for Advantage."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from artifact_policy import DEFAULT_ARTIFACT_LIMIT, artifact_size_limit, contains_raw_secret, publication_content_error
from evidence_refs import EvidenceIssue, _parts, artifact_value, source_file
from remediation_common import atomic_json, sha256_file

ROOT = Path(__file__).resolve().parents[1]
PHASES = ("baseline", "planning", "investigation", "gap-exploration", "synthesis", "final-verification", "handoff", "report")
TASKS = dict(zip(("AdvantageBaseline", "AdvantagePlanning", "AdvantageInvestigation", "AdvantageGapExploration", "AdvantageSynthesis", "AdvantageVerification", "AdvantageHandoff", "AdvantageReport"), PHASES))
OWNERS = dict(zip(PHASES, ("deterministic", "vulnops-advantage-planning", "vulnops-advantage-investigation", "vulnops-advantage-gap-exploration", "vulnops-advantage-synthesis", "vulnops-advantage-final-verification", "vulnops-advantage-investigation", "deterministic")))
ARTIFACTS = dict(zip(PHASES, ("baseline/catalog.json", "planning/plan.json", "investigation/results.json", "gap-exploration/results.json", "synthesis/findings.json", "final-verification/findings.json", "handoff/actions.json", "report/security-report.json")))
SUCCESS = {"ok", "degraded", "skipped"}
SKIPPED_PHASES = ("planning", "investigation", "gap-exploration", "synthesis", "final-verification")
_validator = None




def phase_paths(base: Path, phases: tuple[str, ...]) -> dict:
    paths = {phase: str(base / phase) for phase in phases}
    if "gap-exploration" in phases:
        paths["gap_exploration"] = str(base / "gap-exploration")
    return paths


def skip_disposition(context: dict, phase: str) -> str | None:
    if context["mode"] == "actions" and phase in SKIPPED_PHASES:
        return "actions_only_no_investigation"
    if phase == "gap-exploration" and not context.get("gap_exploration_budget", {}).get("enabled", True):
        return "gap_exploration_disabled"
    return None


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_value(path: Path | str):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or unsafe JSON artifact: " + str(path))
    limit = artifact_size_limit(path)
    if limit is not None and path.stat().st_size > limit:
        raise ValueError("artifact exceeds bounded size policy: " + str(path))
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError:
        if contains_raw_secret(path.read_bytes().decode("utf-8", errors="replace")):
            raise ValueError("artifact contains possible raw secret") from None
        raise EvidenceIssue("unreadable_content", "artifact is not readable UTF-8") from None
    if contains_raw_secret(text):
        raise ValueError("artifact contains possible raw secret")
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        raise EvidenceIssue("unreadable_content", "artifact is not readable bounded JSON") from None
    if error := publication_content_error(value, size_limit=limit):
        raise ValueError(f"{path}: {error}")
    return value


def load(path: Path | str) -> dict:
    value = load_value(path)
    if not isinstance(value, dict):
        raise ValueError("canonical artifact must contain an object: " + str(path))
    return value


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def inside(root: Path | str, path: Path | str) -> Path:
    root, path = Path(root).absolute(), Path(path)
    if not path.is_absolute():
        if ".." in path.parts:
            raise ValueError("parent traversal is forbidden")
        path = root / path
    if ".." in path.parts:
        raise ValueError("parent traversal is forbidden")
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("path escapes its authorized root")
    # Refuse even inward symlinks so each artifact has one authorized pathname.
    cursor = path
    while cursor != root and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("symlink is not a canonical artifact path")
        cursor = cursor.parent
    if root.is_symlink():
        raise ValueError("authorized root may not be a symlink")
    return resolved


def component(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("unsafe execution or record identifier")
    return value


def validate_schema(document: dict, schema_name: str) -> None:
    global _validator
    if _validator is None:
        spec = importlib.util.spec_from_file_location("advantage_schema_validator", ROOT / "scripts/validate-json.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _validator = module.Validator
    name = schema_name if schema_name.endswith(".schema.json") else schema_name + ".schema.json"
    if Path(name).name != name:
        raise ValueError("schema name must be local")
    schema = load(ROOT / "schemas/v2" / name)
    limit = None if name == "advantage-report.schema.json" else DEFAULT_ARTIFACT_LIMIT
    errors = _validator(schema, ROOT / "schemas/v2", size_limit=limit).collect(document, schema)
    if errors:
        raise ValueError("; ".join(errors[:12]))


def envelope(context: dict, **fields) -> dict:
    result = {"schema_version": "2.0", "run_id": context["run_id"], "execution_kind": "advantage"}
    result.update(fields)
    return result


def require_base(base: Path | str) -> Path:
    path = Path(base).absolute()
    if path.is_symlink() or not path.is_dir():
        raise ValueError("missing or unsafe Advantage execution directory")
    return inside(path.parent, path)


def normalize_record(record: dict) -> dict:
    """Discard obsolete admission attestations only in an in-memory operational copy."""
    from run_lifecycle import normalize_record as normalize_run
    value = normalize_run(record)
    for name in ("baseline", "action_source"):
        if isinstance(value.get(name), dict):
            binding = {key: child for key, child in value[name].items()
                       if not key.endswith("_sha256")}
            if "files" in binding:
                binding["files"] = [{"artifact_ref": row["artifact_ref"]} for row in binding["files"]]
            if "selected_findings" in binding:
                binding["selected_findings"] = [{"id": row["id"]} for row in binding["selected_findings"]]
            value[name] = binding
    if isinstance(value.get("patch_binding"), dict):
        value["patch_binding"] = {key: child for key, child in value["patch_binding"].items()
                                  if key not in {"base_fingerprint", "repository_fingerprint", "derived_fingerprint"}}
    return value


def context_for_base(base: Path | str, source_root: Path | str | None = None) -> dict:
    """Read descriptive evidence bindings, never reconstruct a runnable execution."""
    from report_bundle import read_publication
    base = require_base(base)
    publication = read_publication(base, expected_kind="advantage")
    report = publication["report"]
    source_id = component(publication["source"]["source_run_id"])
    source = inside(base.parent, source_id)
    context = {
        "schema_version": "2.0", "workflow": "canonical-redteam-v2", "execution_kind": "advantage",
        "run_id": publication["run_id"], "source_run_id": source_id,
        "repository": publication["repository"], "repositories": publication["repositories"],
        "repository_count": len(publication["repositories"]),
        "model_routing": publication["model_routing"], "producer_routes": publication["producer_routes"],
        "mode": publication["mode"], "options": publication["options"],
        "patch_binding": publication["patch_binding"], "scan_base": str(base), "source_scan": str(source),
        "source_root": str(Path(source_root).resolve()) if source_root else None,
        "repo_path": str(Path(source_root).resolve()) if source_root else None,
        "baseline": {"execution_id": source_id, "root": str(source), "catalog_ref": "baseline/catalog.json"},
        "action_source": None, "paths": phase_paths(base, PHASES),
        "assessment": report.get("assessment", {}),
    }
    action = publication.get("action_source")
    if action:
        context["action_source"] = {
            **action, "root": str(inside(base.parent, component(action["execution_id"])))}
    context["options"] = {**context["options"],
        "patch": str(base / context["options"]["patch"]) if context["options"].get("patch") else None,
        "action_source": context["action_source"]["root"] if context["action_source"] else None}
    return context


def load_context(path: Path | str | None = None) -> dict:
    """Load the explicit immutable input of this invocation, never a saved selection."""
    if path is None:
        raise ValueError("explicit current Advantage --context input is required")
    path = Path(path).absolute()
    context = load(inside(path.parent, path))
    validate_schema(context, "advantage-context")
    if Path(context["input_path"]) != path:
        raise ValueError("Advantage input path does not match its immutable binding")
    if live_call(context).get("context_sha256") != sha256_file(path):
        raise ValueError("immutable Advantage input changed after native initialization")
    check_identity(context)
    return context


_pipe_payload = None


def native_call_payload() -> dict:
    """Read one native IPC message; a one-shot process never reopens old authority."""
    global _pipe_payload
    try:
        transport = os.environ["VULNOPS_ADVANTAGE_CALL"]
        if transport.startswith("fd:"):
            if _pipe_payload is not None and _pipe_payload[0] == transport:
                return _pipe_payload[1]
            descriptor = int(transport[3:])
            if descriptor < 3:
                raise ValueError("invalid native descriptor")
            mode = os.fstat(descriptor).st_mode
            if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
                raise ValueError("native authority must arrive through anonymous IPC")
            with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as channel:
                call = json.load(channel)
        else:
            # Small explicit internal/test calls need no descriptor forwarding.
            call = json.loads(transport)
        if not isinstance(call, dict):
            raise ValueError("invalid native call")
        if transport.startswith("fd:"):
            _pipe_payload = (transport, call)
        return call
    except (KeyError, OSError, ValueError) as exc:
        raise ValueError("Advantage operation requires the live native runtime") from exc


def run_native(command, context: dict, **kwargs):
    """Forward authority to a deterministic child without an environment-size ceiling."""
    call = live_call(context)
    reader, writer = os.pipe()
    environment = dict(kwargs.pop("env", os.environ))
    environment["VULNOPS_ADVANTAGE_CALL"] = f"fd:{reader}"
    descriptors = tuple(dict.fromkeys((*kwargs.pop("pass_fds", ()), reader)))
    errors = []

    def send():
        try:
            with os.fdopen(writer, "w", encoding="utf-8") as channel:
                json.dump(call, channel, separators=(",", ":"))
        except (BrokenPipeError, OSError) as exc:
            errors.append(exc)

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    try:
        result = subprocess.run(command, env=environment, pass_fds=descriptors, **kwargs)
    finally:
        os.close(reader)
        sender.join()
    if result.returncode == 0 and errors:
        raise ValueError("deterministic child did not receive its native authority")
    return result


def live_call(context: dict, phase: str | None = None) -> dict:
    """Read private per-call native authority; never persist or infer it from artifacts."""
    call = native_call_payload()
    if (not isinstance(call, dict) or call.get("run_id") != context["run_id"]
            or not context.get("launcher_session_id")
            or call.get("launcher_session_id") != context["launcher_session_id"]
            or call.get("phase") not in PHASES):
        raise ValueError("native call belongs to another Advantage invocation")
    caller = call.get("caller")
    if (not isinstance(caller, dict) or caller.get("kind") not in {"main", "sub"}
            or not isinstance(caller.get("id"), str) or not caller["id"]):
        raise ValueError("native caller identity is missing")
    if phase is not None and call["phase"] != phase:
        raise ValueError("native caller does not own this Advantage phase")
    workers = call.get("workers")
    if not isinstance(workers, list):
        raise ValueError("native worker observations are missing")
    identities = set()
    for worker in workers:
        if (not isinstance(worker, dict) or worker.get("phase") not in PHASES
                or not isinstance(worker.get("runtime_id"), str) or not worker["runtime_id"]
                or not isinstance(worker.get("id"), str) or not worker["id"]
                or type(worker.get("attempt")) is not int or worker["attempt"] < 1
                or worker.get("status") not in {"running", "completed", "failed", "cancelled"}):
            raise ValueError("invalid actual native worker observation")
        identity = (worker["phase"], worker["id"], worker["attempt"])
        if identity in identities:
            raise ValueError("duplicate native worker observation")
        identities.add(identity)
    return call


def check_identity(context: dict, *, portable: bool = False) -> None:
    from model_routing import validate_routing
    base = require_base(context["scan_base"])
    if component(context["run_id"]) != base.name or context.get("execution_kind") != "advantage":
        raise ValueError("Advantage input belongs to another output directory")
    for phase, expected in phase_paths(base, PHASES).items():
        if phase not in context["paths"] or inside(base, context["paths"][phase]) != Path(expected):
            raise ValueError("Advantage evidence path does not match its invocation")
    if portable:
        return
    live_call(context)
    validate_routing(context["model_routing"], scope="advantage")
    if not context.get("source_root") or context["source_root"] != context.get("repo_path"):
        raise ValueError("source-root aliases differ")
    if not Path(context["source_root"]).is_dir():
        raise ValueError("current source root is unavailable")
    if Path(context["source_scan"]).resolve() != Path(context["baseline"]["root"]).resolve():
        raise ValueError("baseline source aliases differ")


def validate_phase(base: Path | str, phase: str, context: dict | None = None) -> None:
    if phase not in PHASES:
        raise ValueError("unknown Advantage phase")
    base = require_base(base)
    context = context or load_context()
    if Path(context["scan_base"]).resolve() != base:
        raise ValueError("phase context belongs to another execution")
    disposition = skip_disposition(context, phase)
    if phase == "gap-exploration":
        from gap_exploration_contract import validate_phase as validate_gap
        validate_gap(base, context)
    elif disposition:
        if any(inside(base, phase).iterdir()):
            raise ValueError("actions-only phase cannot contain investigation outputs")
    elif phase == "baseline":
        from advantage_baseline import validate_baseline
        validate_baseline(base, context)
    elif phase == "handoff":
        from advantage_actions import validate_phase as validate_actions
        validate_actions(base, phase, context)
    else:
        from advantage_pipeline import validate_phase as validate_pipeline
        validate_pipeline(base, phase, context)


def finalize_phase(base: Path | str, phase: str, status: str = "ok", warnings: list | None = None,
                   *, context: dict | None = None) -> dict:
    """Validate prepared evidence; native terminal delivery owns acceptance."""
    context = context or load_context()
    require_active(context, phase)
    if status not in SUCCESS:
        raise ValueError("invalid analytical phase disposition")
    validate_phase(base, phase, context)
    return {"run_id": context["run_id"], "phase": phase, "status": status,
            "warnings": warnings or [], "outputs": [] if skip_disposition(context, phase)
            else [ARTIFACTS[phase]]}


def resolve_pointer(value, pointer: str):
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise EvidenceIssue("unsupported_selector", "record pointer must be RFC6901")
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise EvidenceIssue("unsupported_selector", "invalid JSON pointer escape")
        key = raw.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(value, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", key):
                    raise EvidenceIssue("unsupported_selector", "noncanonical array index")
                value = value[int(key)]
            else:
                value = value[key]
        except (KeyError, IndexError, TypeError):
            raise EvidenceIssue("missing_record", "baseline record pointer does not resolve") from None
    return value


def resolve_reference(context: dict, ref: str | dict, kind: str = "mixed"):
    """Resolve typed inherited evidence separately from local/source namespaces."""
    if kind not in {"mixed", "artifact", "source"}:
        raise ValueError("unknown evidence reference kind")
    if isinstance(ref, dict):
        if kind == "source":
            raise ValueError("cross-execution references carry artifacts, not source authority")
        validate_schema(ref, "advantage-reference")
        admitted = [context["baseline"]]
        if context.get("action_source"):
            admitted.append(context["action_source"])
        owners = [owner for owner in admitted if owner["execution_id"] == ref["execution_id"]]
        if len(owners) != 1 or ref["execution_id"] == context["run_id"]:
            raise ValueError("unadmitted or ambiguous cross-execution owner")
        owner = owners[0]
        relative, selector = _parts(ref["artifact_ref"])
        from run_lifecycle import AUDIT_PHASE_DIRS
        canonical = {*AUDIT_PHASE_DIRS.values(), *PHASES,
                     "run-manifest.json", "advantage-manifest.json", "task-ledger.json"}
        if PurePosixPath(relative).parts[0] not in canonical:
            raise ValueError("historical reference is outside canonical evidence")
        if PurePosixPath(relative).parts[0] == "gap-exploration":
            from gap_exploration_contract import accepted_support_refs
            if relative not in accepted_support_refs(Path(owner["root"])):
                raise ValueError("historical gap support is not admitted canonical evidence")
        path = inside(Path(owner["root"]), relative)
        if not path.is_file():
            raise EvidenceIssue("missing_file", "historical support unavailable")
        limit = artifact_size_limit(Path(relative))
        if limit is not None and path.stat().st_size > limit:
            raise ValueError("historical support exceeds size bound: " + relative)
        if path.suffix == ".json":
            document = load_value(path)
            if isinstance(document, dict) and "run_id" in document and document["run_id"] != owner["execution_id"]:
                raise ValueError("historical artifact declares another execution")
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeError:
                if contains_raw_secret(path.read_bytes().decode("utf-8", errors="replace")):
                    raise ValueError("historical support contains possible raw secret") from None
                raise EvidenceIssue("unreadable_content", "historical support is not readable UTF-8") from None
            if contains_raw_secret(text):
                raise ValueError("historical support contains possible raw secret")
        if selector.startswith("/") and "#" in ref["artifact_ref"]:
            if path.suffix != ".json":
                raise EvidenceIssue("unsupported_selector", "record pointers require JSON")
            record = resolve_pointer(document, selector)
            if not isinstance(record, dict):
                raise EvidenceIssue("missing_record", "typed evidence pointer must resolve a canonical record object")
            return record
        if path.suffix != ".json":
            if selector or ":" in ref["artifact_ref"] or "#" in ref["artifact_ref"]:
                raise EvidenceIssue("unsupported_selector", "text navigation cannot carry a record selector")
            return path
        return artifact_value(Path(owner["root"]), ref["artifact_ref"])
    relative, selector = _parts(ref)
    base = Path(context["scan_base"])
    local = PurePosixPath(relative).parts[0] in {*PHASES, "advantage-manifest.json", "task-ledger.json"}
    if kind == "artifact" or kind == "mixed" and local:
        path = inside(base, relative)
        if not local:
            raise ValueError("artifact is outside the local Advantage namespace")
        if PurePosixPath(relative).parts[0] == "gap-exploration":
            from gap_exploration_contract import accepted_support_refs
            if relative not in accepted_support_refs(base, context=context):
                raise ValueError("gap support is not admitted canonical evidence")
        if not path.is_file():
            raise EvidenceIssue("missing_file", "unresolved local Advantage artifact")
        if context.get("source_root") and (Path(context["source_root"]) / relative).is_file() and kind == "mixed":
            inside(Path(context["source_root"]), relative)
            raise EvidenceIssue("ambiguous_namespace", "ambiguous local artifact/source namespace")
        if path.suffix == ".json":
            document = load_value(path)
            if isinstance(document, dict) and "run_id" in document and document["run_id"] != context["run_id"]:
                raise ValueError("local artifact declares another execution")
            if selector.startswith("/") and "#" in ref:
                return resolve_pointer(document, selector)
            return artifact_value(base, ref)
        if selector or ":" in ref or "#" in ref:
            raise EvidenceIssue("unsupported_selector", "text navigation cannot carry a record selector")
        limit = artifact_size_limit(Path(relative))
        if limit is not None and path.stat().st_size > limit:
            raise ValueError("local support exceeds size bound")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            if contains_raw_secret(path.read_bytes().decode("utf-8", errors="replace")):
                raise ValueError("local support contains possible raw secret") from None
            raise EvidenceIssue("unreadable_content", "local support is not readable UTF-8") from None
        if contains_raw_secret(text):
            raise ValueError("local support contains possible raw secret")
        return path
    if not context.get("source_root") or not Path(context["source_root"]).is_dir():
        raise ValueError("source evidence requires an authorized source tree")
    inside(Path(context["source_root"]), relative)
    return source_file(Path(context["source_root"]), context["repositories"], ref)


def require_active(context: dict, phase: str) -> None:
    check_identity(context)
    live_call(context, phase)
