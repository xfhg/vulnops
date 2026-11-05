"""Typed optional graph navigation with local request and result provenance."""
from __future__ import annotations

from contextlib import closing
import fcntl
import hashlib
import importlib.util
import json
import re
import sqlite3
from pathlib import Path

SYMBOL_OPERATIONS = {"callers", "callees", "impact"}
MAX_SYMBOLS = 128


def source_file(project: Path, relative: str) -> str:
    _relative(relative)
    path = (project / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(project.resolve()) or not path.is_file():
        raise ValueError("graph subject must reference an existing project-relative file")
    return Path(relative).as_posix()


def resolve_subject(operation: str, subject: str, project: Path, file: str | None = None) -> list[dict]:
    if not isinstance(subject, str) or not subject.strip() or "\x00" in subject:
        raise ValueError("graph subject must be a nonempty string")
    if operation not in SYMBOL_OPERATIONS | {"query", "affected"}:
        raise ValueError("unsupported graph operation")
    if file is not None and operation not in SYMBOL_OPERATIONS:
        raise ValueError("file qualification requires a symbol operation")
    if operation == "affected":
        source_file(project, subject)
        return []
    if operation == "query":
        return []
    scope = source_file(project, file) if file is not None else None
    is_file = (project / subject).is_file()
    if is_file:
        if scope is not None:
            raise ValueError("file-scoped subjects cannot also specify a symbol file")
        scope = source_file(project, subject)
        kinds = ["function", "method", "class", "component"]
        # Codegraph 1.6.2 indexes JavaScript/TypeScript arrow functions as constants.
        if Path(scope).suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
            kinds.extend(["constant", "variable"])
        where = "file_path = ? AND kind IN (" + ",".join("?" for _ in kinds) + ")"
        parameters: list[object] = [scope, *kinds]
    else:
        where = "(name = ? OR qualified_name = ?)"
        parameters = [subject, subject]
        if scope is not None:
            where += " AND file_path = ?"
            parameters.append(scope)
    database = project / ".codegraph/codegraph.db"
    try:
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT id, name, qualified_name, file_path, start_line, kind FROM nodes WHERE "
                + where + " ORDER BY file_path, start_line, id LIMIT ?",
                [*parameters, MAX_SYMBOLS + 1],
            ).fetchall()
    except sqlite3.Error:
        raise ValueError("Codegraph symbol index is unavailable or incompatible") from None
    if not rows:
        raise ValueError("unresolved graph subject: no indexed definitions" if is_file else "unresolved graph subject: symbol not found")
    if len(rows) > MAX_SYMBOLS:
        raise ValueError("graph subject exceeds the 128-definition bound; use a narrower symbol question")
    if not is_file and len({row["file_path"] for row in rows}) > 1:
        raise ValueError("ambiguous graph symbol: supply its project-relative file")
    return [dict(row) for row in rows]


ROOT = Path(__file__).resolve().parent.parent


def _load(path: Path) -> dict:
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("graph artifact exceeds its metadata size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read graph authority {path}: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError(f"graph authority must be an object: {path}")
    return value


def _schema(value: object, name: str, definition: str | None = None) -> None:
    spec = importlib.util.spec_from_file_location("graph_validate_json", ROOT / "scripts/validate-json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = _load(ROOT / "schemas/v2" / name)
    errors = module.Validator(schema).collect(value, schema["$defs"][definition] if definition else schema)
    if errors:
        raise ValueError("invalid graph artifact: " + "; ".join(errors))


def _relative(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("graph path must be canonical and relative")
    path = Path(value)
    if path.is_absolute() or any(part in {".", ".."} for part in value.split("/")) or path.as_posix() != value:
        raise ValueError("graph path must be canonical and relative")
    return path


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value):
        raise ValueError("invalid graph owner or question ID")
    return value


def current_navigation(context: dict) -> Path:
    """Resolve disposable current navigation, never historical receipt authority."""
    if context.get("codegraph_mode") != "enabled" or context.get("codegraph_limitation"):
        raise ValueError("optional Codegraph is unavailable; continue source-only")
    paths = context.get("paths", {})
    try:
        runtime = Path(paths["codegraph_runtime"])
        project = Path(paths["codegraph_project"])
    except (KeyError, TypeError):
        raise ValueError("optional Codegraph paths are unavailable; continue source-only") from None
    if not runtime.is_absolute() or not project.is_absolute():
        raise ValueError("Codegraph navigation paths must be absolute")
    if project != runtime / "project" or project.resolve() != runtime.resolve() / "project":
        raise ValueError("Codegraph project may not redirect outside its runtime")
    source = Path(context.get("source_root") or context.get("repo_path") or "").resolve()
    if runtime.resolve().is_relative_to(source) or source.is_relative_to(project.resolve()):
        raise ValueError("Codegraph navigation must be separate from target source")
    database = project / ".codegraph/codegraph.db"
    if not database.is_file() or not database.resolve().is_relative_to(project.resolve()):
        raise ValueError("optional Codegraph index is unavailable; continue source-only")
    return project


def _run_identity(context: dict) -> dict:
    identity = {"run_id": context.get("run_id")}
    if context.get("execution_kind") == "advantage":
        identity.update(execution_kind="advantage", baseline_execution_id=context["source_run_id"])
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise ValueError("missing graph run identity")
    return identity


def _question_directory(scan: Path, phase: str, owner_id: str, question_id: str) -> Path:
    _identifier(owner_id)
    _identifier(question_id)
    if phase == "intrusion":
        relative = Path("intrusion/codegraph-runs") / owner_id / question_id
    elif phase == "campaign-planning" and owner_id == "discovery":
        relative = Path("campaign-planning/codegraph-runs") / question_id
    elif phase == "investigation":
        relative = Path("investigation/codegraph-runs") / owner_id / question_id
    elif phase == "gap-exploration":
        relative = Path("gap-exploration/codegraph-runs") / owner_id / question_id
    else:
        raise ValueError("invalid audit graph phase or owner")
    directory = scan / relative
    if directory.resolve() != scan.resolve() / relative:
        raise ValueError("graph artifact owner directory redirects through a symlink")
    return directory


def _planned_question(scan: Path, context: dict, phase: str, owner_id: str, question_id: str) -> dict:
    _question_directory(scan, phase, owner_id, question_id)
    if phase == "gap-exploration":
        from gap_exploration_contract import graph_question
        return graph_question(context, owner_id, question_id, active=False)
    if context.get("execution_kind") == "advantage":
        from advantage_owners import owner
        packet = owner(context, phase, owner_id, question_id, active=False)
        if packet["source_view"] != "base":
            raise ValueError("base graph snapshot cannot establish derived-source navigation; use source-only review")
        matches = [item for item in packet.get("graph_questions", []) if item["id"] == question_id]
        if len(matches) != 1:
            raise ValueError("linked graph question must match exactly one immutable packet question")
        return matches[0]
    if phase == "investigation":
        raise ValueError("linked graph phase requires explicit Advantage execution identity")
    if phase == "intrusion":
        path = scan / "campaign-planning/campaign-plan.json"
        configured = context.get("paths", {}).get("campaign_plan")
        if configured is not None and Path(configured) != path:
            raise ValueError("campaign plan path differs from canonical authority")
        plan = _load(path)
        owners = [item for item in plan.get("campaigns", []) if item.get("id") == owner_id]
        if not owners:
            from intrusion_contract import load as load_wave, read_snapshot, reference
            for wave_path in sorted((scan / "intrusion/waves").glob("[0-9][0-9][0-9].json")):
                wave = load_wave(wave_path)
                read_snapshot(scan, context, reference(scan, wave))
                if owner_id in wave["assignments"]:
                    owners.append(wave["assignments"][owner_id])
        if len(owners) != 1:
            raise ValueError("graph owner must match exactly one immutable assignment")
        questions = [*owners[0].get("graph_questions", []), *followup_questions(scan, context, owner_id)]
    else:
        path = scan / "campaign-planning/discovery.json"
        questions = _load(path).get("questions", [])
    if path.resolve() != scan.resolve() / path.relative_to(scan):
        raise ValueError("graph plan may not redirect through symlinks")
    matches = [item for item in questions if isinstance(item, dict) and item.get("id") == question_id]
    if len(matches) != 1:
        raise ValueError("graph question must match exactly one planned question")
    return matches[0]


def followup_questions(scan: Path, context: dict, owner_id: str) -> list[dict]:
    """Only registered, source-bound phase-owned follow-ups may enter the wrapper."""
    from intrusion_contract import read_snapshot
    _identifier(owner_id)
    questions = []
    for path in sorted((Path(scan) / "intrusion/graph-followups" / owner_id).glob("*.json")):
        if path.resolve() != path.absolute():
            raise ValueError("follow-up registry may not redirect")
        request = _load(path)
        wave = read_snapshot(scan, context, request["input_snapshot"])
        question = request["question"]
        if request["owner_id"] != owner_id or owner_id not in wave["assignments"] or path.stem != question["id"]:
            raise ValueError("graph follow-up owner mismatch")
        questions.append(question)
    return questions


def register_followup(scan: Path, context: dict, owner_id: str, question: dict,
                      triggering_evidence: list[str], input_snapshot: dict) -> dict:
    """Coordinator registration reserves one bounded question before execution."""
    from intrusion_contract import publish, read_snapshot, refs_exist, require_active
    require_active(scan, context)
    _identifier(owner_id)
    _identifier(question["id"])
    wave = read_snapshot(scan, context, input_snapshot)
    if owner_id not in wave["assignments"]:
        raise ValueError("follow-up requires an assigned campaign or continuation owner")
    latest = sorted((Path(scan) / "intrusion/waves").glob("[0-9][0-9][0-9].json"))[-1]
    if _load(latest)["wave"] != wave["wave"]:
        raise ValueError("follow-up cannot mutate a completed wave")
    refs_exist(scan, triggering_evidence)
    _binding(context, "intrusion", owner_id, question)
    if any(q["id"] == question["id"] for q in wave["assignments"][owner_id].get("graph_questions", [])):
        raise ValueError("follow-up cannot replace a sealed planned request")
    directory = Path(scan) / "intrusion/graph-followups"
    directory.mkdir(parents=True, exist_ok=True)
    # One phase coordinator owns registration; flock also makes concurrent retries safe.
    with (directory / ".registration.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = directory / owner_id / (question["id"] + ".json")
        count = len(list(directory.glob("*/*.json")))
        if not path.exists() and count >= context["intrusion_budget"]["graph_followups"]:
            raise ValueError("graph follow-up reserve exhausted")
        request = {"owner_id": owner_id, "question": question, "triggering_evidence": triggering_evidence,
                   "input_snapshot": input_snapshot, "attempt_id": context["attempt_id"],
                   "remaining_budget": context["intrusion_budget"]["graph_followups"] - count - int(not path.exists())}
        if path.exists():
            prior = _load(path)
            request["remaining_budget"] = prior["remaining_budget"]
        publish(path, request)
    return request


def _binding(context: dict, phase: str, owner_id: str, question: dict) -> dict:
    operation = question.get("operation") if phase == "gap-exploration" else question.get("type")
    subject, file = question.get("subject"), question.get("file")
    if operation not in SYMBOL_OPERATIONS | {"query", "affected"}:
        raise ValueError("unsupported planned graph operation")
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512 or "\x00" in subject:
        raise ValueError("invalid planned graph subject")
    if file is not None:
        _relative(file)
        if len(file) > 512 or operation not in SYMBOL_OPERATIONS:
            raise ValueError("invalid planned graph file qualification")
    attempt = context.get("attempt_id")
    if not isinstance(attempt, str) or not attempt:
        raise ValueError("new graph queries require current attempt ownership")
    binding = {**_run_identity(context), "attempt_id": attempt,
               "phase": phase, "owner_id": owner_id, "question_id": question["id"],
               "operation": operation, "subject": subject, "file": file}
    if phase == "gap-exploration":
        binding["source_view"] = question["source_view"]
    return binding


def audit_request(context_path: Path, phase: str, owner_id: str, question_id: str) -> dict:
    context = _load(Path(context_path))
    if context.get("execution_kind") == "advantage":
        from advantage_contract import load_context
        context = load_context(context_path)
    scan = Path(context["scan_base"])
    if not scan.is_absolute():
        raise ValueError("audit scan authority must be absolute")
    from run_lifecycle import assert_owner
    if context.get("execution_kind") != "advantage":
        assert_owner(scan, context.get("launcher_session_id"))
    if context.get("execution_kind") == "advantage":
        from advantage_owners import owner
        owner(context, phase, owner_id, question_id)
    else:
        manifest = _load(scan / "run-manifest.json")
        if any(not context.get(key) or manifest.get(key) != context[key] for key in ("run_id", "attempt_id")):
            raise ValueError("graph query does not belong to the current run attempt")
        if manifest.get("phases", {}).get(phase) != "running":
            raise ValueError("graph query owner phase is not active")
    if phase == "gap-exploration":
        from gap_exploration_contract import graph_question
        from gap_graph import prepare_navigation, reserve_query, fail_query
        question = graph_question(context, owner_id, question_id)
        directory = _question_directory(scan, phase, owner_id, question_id)
        binding = _binding(context, phase, owner_id, question)
        request = {"output": directory / "context.json", "receipt": directory / "receipt.json",
                   "binding": binding, "question": question, **reserve_query(context, owner_id, question)}
        try:
            request["project"] = prepare_navigation(context, owner_id, question)
            resolve_subject(binding["operation"], binding["subject"], request["project"], binding["file"])
        except (ValueError, OSError) as exc:
            fail_query(request, str(exc))
            raise
        return request
    else:
        project = current_navigation(context)
        question = _planned_question(scan, context, phase, owner_id, question_id)
    directory = _question_directory(scan, phase, owner_id, question_id)
    binding = _binding(context, phase, owner_id, question)
    resolve_subject(binding["operation"], binding["subject"], project, binding["file"])
    request = {"project": project, "output": directory / "context.json", "receipt": directory / "receipt.json",
               "binding": binding, "question": question}
    if context.get("execution_kind") == "advantage":
        from advantage_contract import live_call
        operation = live_call(context, phase).get("operation", {})
        if (operation.get("kind") != "graph" or operation.get("phase") != phase
                or operation.get("owner_id") != owner_id or operation.get("question_id") != question_id
                or type(operation.get("timeout_seconds")) not in (int, float)
                or not 0 < operation["timeout_seconds"] <= 120):
            raise ValueError("graph query requires its bounded current native operation")
        request["timeout_seconds"] = operation["timeout_seconds"]
    if phase == "campaign-planning":
        from campaign_contract import DISCOVERY_BUDGETS
        discovery = _load(scan / "campaign-planning/discovery.json")
        if discovery.get("status") != "prepared":
            raise ValueError("discovery queries are forbidden after sealing")
        budget = DISCOVERY_BUDGETS[context["depth"]]
        if len(discovery.get("questions", [])) > budget["questions"]:
            raise ValueError("discovery question ceiling exceeded")
        ledger = scan / "campaign-planning/codegraph-runs/discovery-budget.json"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        with ledger.open("a+", encoding="utf-8") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.seek(0)
            try:
                entries = json.loads(stream.read() or "{}")
            except json.JSONDecodeError:
                raise ValueError("discovery time ledger is unavailable") from None
            if not isinstance(entries, dict) or any(type(v) not in (int, float) or not 0 <= v <= 120 for v in entries.values()):
                raise ValueError("invalid discovery time accounting")
            remaining = budget["query_seconds"] - sum(entries.values())
            if question_id in entries or len(entries) >= budget["questions"] or remaining <= 0:
                raise ValueError("discovery budget exhausted or question already attempted")
            allowance = min(120, remaining)
            # Reserve before dispatch; an interrupted process cannot overspend on retry.
            entries[question_id] = allowance
            stream.seek(0); stream.truncate(); json.dump(entries, stream); stream.flush()
        request.update(timeout_seconds=allowance, budget_ledger=ledger)
    return request


def finish_discovery_query(request: dict, elapsed: float) -> None:
    if "gap_query" in request:
        from gap_graph import finish_query
        finish_query(request, elapsed)
        return
    ledger = request.get("budget_ledger")
    if ledger is None:
        return
    with Path(ledger).open("r+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        entries = json.load(stream)
        entries[request["question"]["id"]] = min(request["timeout_seconds"], max(0, elapsed))
        stream.seek(0); stream.truncate(); json.dump(entries, stream); stream.flush()


def _source_location(target: Path, file: str, start: int | None = None, end: int | None = None) -> None:
    _relative(file)
    source_file(target, file)
    if start is not None:
        if type(start) is not int or type(end) is not int or not 1 <= start <= end:
            raise ValueError("invalid graph source line range")
        with (target / file).open(encoding="utf-8", errors="replace") as stream:
            lines = sum(1 for _ in stream)
        if end > lines:
            raise ValueError("graph source line range exceeds file")


def validate_query_receipt(scan: Path, target: Path, context: dict, phase: str, owner_id: str,
                           question: dict, receipt_ref: str) -> dict:
    scan, target = Path(scan).resolve(), Path(target).resolve()
    if scan.resolve() != Path(context["scan_base"]).resolve():
        raise ValueError("graph receipt scan differs from active audit")
    source_context = context
    if phase == "gap-exploration":
        from gap_graph import source_context as selected_context
        source_context = selected_context(context, question["source_view"])
    portable = context.get("execution_kind") == "advantage" and not source_context.get("source_root")
    if not portable and target.resolve() != Path(source_context.get("source_root") or source_context["repo_path"]).resolve():
        raise ValueError("graph receipt source differs from its assigned source view")
    planned = _planned_question(scan, context, phase, owner_id, question["id"])
    if question != planned:
        raise ValueError("graph question differs from canonical plan")
    binding = {**_run_identity(context), "phase": phase, "owner_id": owner_id,
               "question_id": question["id"], "operation": question.get("operation") if phase == "gap-exploration" else question["type"],
               "subject": question["subject"], "file": question.get("file")}
    if phase == "gap-exploration":
        binding["source_view"] = question["source_view"]
    directory = _question_directory(scan, phase, owner_id, question["id"])
    expected = (directory / "receipt.json").relative_to(scan).as_posix()
    if _relative(receipt_ref).as_posix() != expected:
        raise ValueError("graph receipt is outside its canonical question directory")
    receipt_path, output = directory / "receipt.json", directory / "context.json"
    if receipt_path.resolve() != receipt_path or output.resolve() != output:
        raise ValueError("graph receipt/context may not redirect through symlinks")
    receipt, document = _load(receipt_path), _load(output)
    linked = context.get("execution_kind") == "advantage"
    _schema(receipt, "advantage-graph-receipt.schema.json" if linked else "tool-receipt.schema.json")
    _schema(document, "advantage-graph-context.schema.json" if linked else "codegraph-context.schema.json")
    obsolete = {"target_fingerprint", "repository_set_sha256", "snapshot_sha256"}
    receipt_binding = {key: value for key, value in receipt.get("binding", {}).items() if key not in obsolete}
    document_binding = {key: value for key, value in document.get("binding", {}).items() if key not in obsolete}
    if receipt_binding != document_binding:
        raise ValueError("graph receipt and context bind different requests")
    for artifact in (receipt, document):
        if any(artifact.get("binding", {}).get(key) != value for key, value in binding.items()) or artifact.get("tool") != "codegraph" or artifact.get("operation") != binding["operation"]:
            raise ValueError("graph artifact query binding differs from planned authority")
    current = bool(context.get("attempt_id")) and receipt["binding"].get("attempt_id") == context["attempt_id"]
    if document.get("subject") != binding["subject"]:
        raise ValueError("graph context subject differs from binding")
    if receipt.get("status") != "ok" or receipt.get("parse_status") != "ok":
        raise ValueError("graph query receipt is unhealthy")
    if receipt.get("normalized_sha256") != hashlib.sha256(output.read_bytes()).hexdigest():
        raise ValueError("graph receipt context hash mismatch")
    nodes, edges = document["nodes"], document["edges"]
    ids = [node["id"] for node in nodes]
    if len(ids) != len(set(ids)) or any(edge["source"] not in ids or edge["target"] not in ids for edge in edges):
        raise ValueError("graph context has duplicate nodes or dangling endpoints")
    for node in nodes:
        if node.get("file") is not None:
            _relative(node["file"])
            if current and not portable:
                _source_location(target, node["file"], node.get("line"), node.get("line"))
        elif node.get("line") is not None:
            raise ValueError("graph node line requires source file")
    meaningful = bool(edges) or any(node["role"] == "result" for node in nodes)
    if document.get("meaningful") is not meaningful or receipt.get("meaningful") is not meaningful:
        raise ValueError("graph artifact has forged meaningful flag")
    if receipt.get("result_count") != sum(node["role"] == "result" for node in nodes):
        raise ValueError("graph result count differs from normalized context")
    completeness = document["completeness"]
    if receipt.get("completeness") != completeness:
        raise ValueError("graph receipt completeness differs from context")
    if completeness["local_truncated"] != bool(completeness["dropped_nodes"] or completeness["dropped_edges"]):
        raise ValueError("graph local truncation disagrees with omission counts")
    if completeness["upstream_truncated"] and completeness["upstream_complete"] is not False:
        raise ValueError("truncated graph cannot claim upstream completeness")
    return {**document, "assessment_scope": "current" if current else "historical"}


def validate_graph_answers(target: Path, questions: list[dict], answers: list[dict], receipt_refs: list[str]) -> None:
    if not isinstance(answers, list) or len(answers) > 128 or not isinstance(receipt_refs, list):
        raise ValueError("graph answers and receipts must be bounded arrays")
    if any(not isinstance(ref, str) for ref in receipt_refs):
        raise ValueError("graph receipt references must be strings")
    for ref in receipt_refs:
        _relative(ref)
    ids = [question["id"] for question in questions]
    if len(ids) != len(set(ids)) or len(receipt_refs) != len(set(receipt_refs)) or len(receipt_refs) != len(ids):
        raise ValueError("graph questions and receipts must correspond exactly once")
    answered, cited = [], []
    for answer in answers:
        _schema(answer, "intrusion-results.schema.json", "graphAnswer")
        answered.append(answer["question_id"])
        cited.append(answer["receipt_ref"])
        if answer["receipt_ref"] not in receipt_refs or Path(answer["receipt_ref"]).parent.name != answer["question_id"]:
            raise ValueError("graph answer receipt does not belong to its question")
        if answer["disposition"] in {"supported", "contradicted"} and not answer["source_locations"]:
            raise ValueError("supported or contradicted graph answers require source inspection")
        if answer["disposition"] == "inconclusive" and not answer["limitations"]:
            raise ValueError("inconclusive graph answers require explicit limitations")
        if not answer["observation"].strip() or not answer["conclusion_effect"].strip() or any(not item.strip() for item in answer["limitations"]):
            raise ValueError("graph answer text must be substantive")
        for location in answer["source_locations"]:
            _source_location(Path(target), location["file"], location["start_line"], location["end_line"])
    if sorted(answered) != sorted(ids) or sorted(cited) != sorted(receipt_refs):
        raise ValueError("graph answers must cover each relied-on question and receipt exactly once")


def validate_campaign_graph(scan: Path, target: Path, context: dict, campaign: dict, result: dict) -> None:
    questions = [*campaign.get("graph_questions", []), *followup_questions(Path(scan), context, campaign["id"])]
    refs, evidence = result.get("graph_query_receipts"), result.get("graph_evidence_refs")
    if not isinstance(refs, list) or not isinstance(evidence, list) or any(not isinstance(ref, str) for ref in [*refs, *evidence]):
        raise ValueError("campaign graph receipts/evidence must be string arrays")
    if len(refs) != len(set(refs)) or len(evidence) != len(set(evidence)):
        raise ValueError("campaign graph receipts/evidence must be unique arrays")
    limitations = result.get("graph_limitations")
    if not isinstance(limitations, list) or len(limitations) > 16 or any(
            not isinstance(item, str) or not item.strip() or len(item) > 1000 for item in limitations):
        raise ValueError("campaign graph limitations must be a bounded array of substantive reasons")
    owner = _identifier(campaign["id"])
    expected = {f"intrusion/codegraph-runs/{owner}/{_identifier(q['id'])}/receipt.json": q for q in questions}
    if len(expected) != len(questions) or not set(refs).issubset(expected):
        raise ValueError("campaign graph receipts must belong to distinct planned questions")
    for ref in refs:
        question = expected[ref]
        _question_directory(Path(scan), "intrusion", owner, question["id"])
        if question != _planned_question(Path(scan), context, "intrusion", owner, question["id"]):
            raise ValueError("graph question differs from canonical plan")
    if not set(evidence).issubset(refs):
        raise ValueError("graph evidence must be a subset of attempted receipts")
    if set(expected) - set(evidence) and not limitations:
        raise ValueError("skipped or unused graph questions require explicit graph limitations")
    for ref in evidence:
        document = validate_query_receipt(scan, target, context, "intrusion", owner, expected[ref], ref)
        if document["assessment_scope"] != "current":
            raise ValueError("historical graph navigation cannot establish current evidence; inspect current source")
        if not document["meaningful"]:
            raise ValueError("campaign cites non-meaningful graph evidence")
    validate_graph_answers(target, [expected[ref] for ref in evidence], result.get("graph_answers"), evidence)


def validate_linked_receipt(context: dict, reference: str) -> dict:
    """Admit only a healthy, source-backed receipt of an allocated linked question."""
    if context.get("execution_kind") != "advantage":
        raise ValueError("linked graph receipt requires Advantage context")
    relative = _relative(reference)
    if len(relative.parts) != 5 or relative.parts[0] not in {"investigation", "gap-exploration"} or relative.parts[1] != "codegraph-runs" or relative.name != "receipt.json":
        raise ValueError("linked graph receipt has no canonical owner")
    owner_id, question_id = relative.parts[2:4]
    scan = Path(context["scan_base"])
    phase = relative.parts[0]
    question = _planned_question(scan, context, phase, owner_id, question_id)
    selected = context
    if phase == "gap-exploration":
        from gap_graph import source_context
        selected = source_context(context, question["source_view"])
    document = validate_query_receipt(scan, Path(selected.get("source_root") or "."), context, phase, owner_id, question, reference)
    if document["assessment_scope"] != "current":
        raise ValueError("historical graph navigation cannot establish current evidence; inspect current source")
    if not document["meaningful"]:
        raise ValueError("linked graph receipt has no meaningful navigation evidence")
    return document
