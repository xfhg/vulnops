"""Bounded, source-first supplementary investigation for both execution kinds.

Only this module publishes packets and admitted results.  Updaters, not this
module, accept the top-level phase.  Historical validation uses immutable
admission receipts, never today's source tree or disposable graph index.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from contextlib import nullcontext
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import advantage_contract as core
from artifact_policy import artifact_size_limit, publication_content_error
from evidence_refs import _parts, artifact_value, source_file
from intrusion_contract import publish
from objective_contract import stable_id, validate_registry
from run_lifecycle import assessment_ref, state_lock

PHASE = "gap-exploration"
SUCCESS = {"ok", "degraded", "skipped"}
OUTCOMES = {"established", "contradicted", "locally_unresolved", "externally_blocked", "budget_deferred", "execution_failed", "redundant"}
PROOF = {"actor_control", "reachability", "security_boundary", "impact", "intervening_controls", "conditions_compatible"}
INPUTS = {
    "ordinary": {"recon": ["repo-context/repo-context.json", "repo-context/security-surfaces.json"],
                 "tool-collection": ["tool-collection/collection.json", "tool-collection/sca-advisories.json", "tool-collection/secrets-redacted.json", "tool-collection/dependency-limitations.json"],
                 "sast": ["sast/threat-model.json", "sast/verified-findings.json", "sast/validation-results.json", "sast/dropped-findings.json", "sast/coverage-ledger.json"],
                 "campaign-planning": ["campaign-planning/evidence-index.json", "campaign-planning/campaign-plan.json"],
                 "intrusion": ["intrusion/intrusion-results.json"]},
    "advantage": {"baseline": ["baseline/catalog.json"], "planning": ["planning/plan.json"],
                  "investigation": ["investigation/results.json"]},
}


def linked(context):
    return context.get("execution_kind") == "advantage"


def invocation_lock(context):
    return nullcontext() if linked(context) else state_lock(base_of(context))


def base_of(context):
    return Path(context["scan_base"])


def actor(context, worker=False):
    return "vulnops-" + ("advantage-" if linked(context) else "") + ("gap-investigator" if worker else "gap-exploration")


def coordinator(context):
    return "AdvantageGapExploration" if linked(context) else "GapExploration"


def assigned_route(context, *, worker=False):
    selector = context.get("model_routing", {}).get("agents", {}).get(actor(context, worker))
    if not isinstance(selector, str) or not selector.lower().endswith(":high"):
        raise ValueError("gap actor requires exact current High route; no generic fallback")
    return selector


def envelope(context, **fields):
    value = {"schema_version": "2.0", "run_id": context["run_id"], "attempt_id": context["attempt_id"]}
    if linked(context):
        value["execution_kind"] = "advantage"
    if assessment_ref(context):
        value["assessment_context"] = assessment_ref(context)
    return {**value, **fields}


def path(context, relative):
    target = core.inside(base_of(context), relative)
    if target.exists() and not target.is_file() and not target.is_dir():
        raise ValueError("unsupported gap control or evidence file type")
    limit = artifact_size_limit(target)
    if target.is_file() and limit is not None and target.stat().st_size > limit:
        raise ValueError("gap artifact exceeds bounded size policy")
    return target


def read(context, relative):
    return core.load(path(context, relative))


def manifest(context):
    if linked(context):
        raise ValueError("Advantage has no execution manifest")
    value = read(context, "run-manifest.json")
    if value.get("run_id") != context.get("run_id") or PHASE not in value.get("phases", {}):
        raise ValueError("gap exploration is not owned by this execution")
    configured = context.get("paths", {}).get("gap_exploration")
    if configured is not None and Path(configured).absolute() != path(context, PHASE):
        raise ValueError("redirected gap exploration path")
    return value


def state(value):
    return value.get("status") if isinstance(value, dict) else value


def owned(context, *, failure=False):
    if linked(context):
        call = core.live_call(context, PHASE)
        if context.get("mode") != "actions" and "investigation" not in call["accepted_phases"]:
            raise ValueError("gap exploration requires accepted predecessor")
        return call
    value = manifest(context)
    allowed = {"running", "failed", "interrupted"} if failure else {"running"}
    if state(value["phases"][PHASE]) not in allowed or value.get("status") == "complete":
        raise ValueError("gap publication requires its active owning phase")
    if value.get("attempt_id") and value["attempt_id"] != context.get("attempt_id"):
        raise ValueError("gap publication changed current attempt")
    if any(name != PHASE and state(status) == "running" for name, status in value["phases"].items()):
        raise ValueError("competing active phase owner")
    predecessor = "intrusion"
    if context.get("mode") != "actions" and state(value["phases"].get(predecessor)) not in SUCCESS:
        raise ValueError("gap exploration requires accepted predecessor")
    return value


def budget(context):
    value = context.get("gap_exploration_budget")
    keys = {"max_questions", "graph_timeout_seconds", "preparation_timeout_seconds", "max_tasks", "max_concurrency", "max_attempts", "max_candidates", "timeout_seconds", "synthesis_timeout_seconds", "verification_timeout_seconds"}
    if not isinstance(value, dict) or type(value.get("enabled")) is not bool or any(type(value.get(k)) is not int or value[k] < (1 if k in {"max_concurrency", "max_attempts", "timeout_seconds"} else 0) for k in keys):
        raise ValueError("missing or invalid independent gap exploration budget")
    return value


def schema(value, kind):
    core.validate_schema(value, f"gap-{kind}.schema.json")
    if error := publication_content_error(value):
        raise ValueError(error)


def unique(rows, key="id"):
    result = {}
    for row in rows:
        identity = core.component(row[key])
        if identity in result:
            raise ValueError("duplicate gap ownership: " + identity)
        result[identity] = row
    return result


def source_context(context, view):
    if view not in {"base", "derived"}:
        raise ValueError("unqualified gap source view")
    if view == "derived":
        if not linked(context):
            raise ValueError("ordinary gap work has no derived source authority")
        from advantage_pipeline import source_context as resolve
        return resolve(context, view)
    return context


def source_refs(context, view, refs):
    if not isinstance(refs, list) or not refs:
        raise ValueError("source-established proof requires inspected source references")
    selected = source_context(context, view)
    root = Path(selected.get("source_root") or selected["repo_path"])
    for ref in refs:
        if not isinstance(ref, str) or not _parts(ref)[1]:
            raise ValueError("source proof requires exact source line ranges")
        source_file(root, selected["repositories"], ref)
    return refs


def accepted_inputs(context):
    run = core.live_call(context) if linked(context) else manifest(context)
    rows = []
    for phase, relatives in INPUTS["advantage" if linked(context) else "ordinary"].items():
        if (phase not in run["accepted_phases"] if linked(context) else state(run["phases"].get(phase)) not in SUCCESS):
            continue
        for relative in relatives:
            target = path(context, relative)
            if target.is_file():
                document = core.load_value(target)
                if isinstance(document, dict) and document.get("run_id", context["run_id"]) != context["run_id"]:
                    raise ValueError("accepted input belongs to another execution")
                rows.append({"ref": relative, "sha256": core.sha256_file(target)})
    required = "investigation/results.json" if linked(context) else "intrusion/intrusion-results.json"
    if context.get("mode") != "actions" and required not in {r["ref"] for r in rows}:
        raise ValueError("accepted gap predecessor artifact is missing")
    return rows


def dispatch_state(context):
    if linked(context):
        return native_evidence(context)
    target = path(context, PHASE + "/dispatch.json")
    if not target.exists() and path(context, PHASE + "/plan.json").exists():
        raise ValueError("admitted gap plan lost authoritative dispatch state")
    value = core.load(target) if target.exists() else envelope(context, phase=PHASE, started_at=core.now(), workers=[], graph_consumption={"preparations": [], "queries": []})
    schema(value, "dispatch")
    if value["run_id"] != context["run_id"] or value["phase"] != PHASE:
        raise ValueError("gap dispatch changed execution ownership")
    groups = {}
    for row in value["workers"]:
        groups.setdefault(row["id"], []).append(row)
    for rows in groups.values():
        if [r["attempt"] for r in rows] != list(range(1, len(rows) + 1)) or any(r["status"] != "failed" for r in rows[:-1]):
            raise ValueError("gap dispatch has duplicate or conflicting worker ownership")
    if value["workers"]:
        selected = read(context, PHASE + "/plan.json")
        assignments = unique(selected["assignments"], "task_id")
        for row in value["workers"]:
            assignment = assignments.get(row["id"])
            if assignment is None or row["source_view"] != assignment["source_view"] or row["actor"] != actor(context, True):
                raise ValueError("gap dispatch has unknown assignment or forged source ownership")
            if row["source_receipts"] and any(item["source_view"] != row["source_view"] for item in row["source_receipts"]):
                raise ValueError("gap admission receipt substituted source view")
    if value.get("inputs_sha256") and core.sha256_file(path(context, PHASE + "/inputs.json")) != value["inputs_sha256"]:
        raise ValueError("prepared gap input authority changed")
    return value


def prepare_inputs(context):
    with invocation_lock(context):
        owned(context)
        limits = budget(context)
        if limits["enabled"] and context.get("mode") != "actions":
            assigned_route(context)
        target = path(context, PHASE + "/inputs.json")
        if target.exists():
            if linked(context):
                value = read(context, PHASE + "/inputs.json")
                schema(value, "inputs")
                if value["run_id"] != context["run_id"] or value["inputs"] != accepted_inputs(context):
                    raise ValueError("immutable gap input binding changed")
                return value
            ledger = dispatch_state(context)
            value = read(context, PHASE + "/inputs.json")
            schema(value, "inputs")
            if value["run_id"] != context["run_id"]:
                raise ValueError("prepared gap input changed execution ownership")
            if not ledger.get("inputs_sha256"):
                if value["inputs"] != accepted_inputs(context):
                    raise ValueError("interrupted preparation changed accepted input scope")
                ledger["inputs_sha256"] = core.sha256_file(target)
                core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
            return value
        value = envelope(context, inputs=accepted_inputs(context), budget=deepcopy(limits))
        if linked(context):
            value["baseline"] = deepcopy(context["baseline"])
        schema(value, "inputs")
        publish(target, value)
        if linked(context):
            return value
        ledger = dispatch_state(context)
        ledger["inputs_sha256"] = core.sha256_file(target)
        core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
        return value


def input_reference(context, reference, inputs):
    if isinstance(reference, dict):
        if not linked(context):
            raise ValueError("ordinary gap input cannot claim linked baseline authority")
        return core.resolve_reference(context, reference, kind="artifact")
    relative, selector = _parts(reference)
    if relative not in {row["ref"] for row in inputs}:
        raise ValueError("gap seed consumes unaccepted or unpublished input")
    expected = next(row["sha256"] for row in inputs if row["ref"] == relative)
    if core.sha256_file(path(context, relative)) != expected:
        raise ValueError("accepted gap input changed after preparation")
    if selector:
        return core.resolve_reference(context, reference, kind="artifact") if linked(context) else artifact_value(base_of(context), reference)
    return core.load_value(path(context, relative))


def admit_plan(context, authored):
    with invocation_lock(context):
        owned(context)
        inputs = read(context, PHASE + "/inputs.json")
        limits = budget(context)
        schema(authored, "plan")
        if authored["run_id"] != context["run_id"] or authored["attempt_id"] != context["attempt_id"]:
            raise ValueError("gap plan changed execution or producing attempt")
        if authored["budget"] != inputs["budget"] or authored["inputs"] != inputs["inputs"]:
            raise ValueError("gap plan changes prepared input or independent allocation")
        seeds, assignments = unique(authored["seeds"]), unique(authored["assignments"], "task_id")
        inherited = []
        for field in ("objectives", "questions"):
            definitions = unique(authored[field])
            accepted = {}
            for row in definitions.values():
                if row["owner"] == PHASE + "/plan.json":
                    continue
                documents = [input_reference(context, item["ref"], inputs["inputs"]) for item in inputs["inputs"]]
                names = ("objectives", "attack_objectives") if field == "objectives" else ("questions", "investigation_questions")
                if not any(isinstance(document, dict) and any(row in document.get(name, []) for name in names) for document in documents):
                    raise ValueError("gap objective is not owned or inherited accepted evidence")
                accepted[row["id"]] = row
            inherited.append(accepted)
        objectives, questions = validate_registry(
            [row for row in authored["objectives"] if row["id"] not in inherited[0]],
            [row for row in authored["questions"] if row["id"] not in inherited[1]],
            inherited_objectives=inherited[0], inherited_questions=inherited[1])
        selected = set()
        for seed in seeds.values():
            if seed["objective_id"] not in objectives or seed["question_id"] not in questions or questions[seed["question_id"]]["objective_id"] != seed["objective_id"]:
                raise ValueError("gap seed objective/question binding differs")
            if seed["source_refs"]:
                source_refs(context, seed["source_view"], seed["source_refs"])
            elif seed["disposition"] != "locally_unresolved":
                raise ValueError("unanchored scanner lead must retain its unresolved source prerequisite")
            prior = [input_reference(context, ref, inputs["inputs"]) for ref in seed["input_refs"]]
            defeated = seed["prior_outcome"] in {"contradicted", "redundant"} or any(isinstance(item, dict) and (item.get("resolution", {}).get("outcome") in {"contradicted", "redundant"} or item.get("disposition") == "rejected") for item in prior)
            if defeated and seed["disposition"] != "redundant":
                if not (seed["changed_hypothesis"].strip() and seed["counterevidence_response"].strip() and seed.get("changed_evidence_refs")):
                    raise ValueError("resolved route requires changed hypothesis and source evidence addressing counterevidence")
                source_refs(context, seed["source_view"], seed["changed_evidence_refs"])
            for definition in (objectives[seed["objective_id"]], questions[seed["question_id"]]):
                if definition["owner"] == PHASE + "/plan.json":
                    anchors = [ref for ref in definition["evidence_refs"] if isinstance(ref, str) and _parts(ref)[0] not in {item["ref"] for item in inputs["inputs"]}]
                    source_refs(context, seed["source_view"], anchors)
            if seed["external_blocker"] and not seed["local_answer"] and seed["disposition"] != "externally_blocked":
                raise ValueError("external blocker has no authorized local answer")
            if seed["disposition"] == "selected":
                selected.add(seed["id"])
        if len(selected) > limits["max_questions"] or len(authored["graph_questions"]) > limits["max_questions"] or len(assignments) > limits["max_tasks"]:
            raise ValueError("gap plan exceeds independent question/task allocation")
        if len({a["seed_id"] for a in assignments.values()}) != len(assignments) or {a["seed_id"] for a in assignments.values()} != selected:
            raise ValueError("selected useful seeds require exactly one supplementary investigator; no advisory-only selection")
        for assignment in assignments.values():
            seed = seeds[assignment["seed_id"]]
            if any(assignment[k] != seed[k] for k in ("objective_id", "question_id", "source_view")):
                raise ValueError("assignment changes seed objective/question/source view")
        graph_ids = set()
        for question in authored["graph_questions"]:
            pair = question["owner"], question["id"]
            if pair in graph_ids:
                raise ValueError("duplicate graph question ownership")
            graph_ids.add(pair)
            if question["owner"] == coordinator(context):
                seed = seeds.get(question["seed_id"])
            else:
                assignment = assignments.get(question["owner"])
                seed = seeds.get(assignment["seed_id"]) if assignment else None
            if seed is None or seed["disposition"] != "selected" or seed["source_view"] != question["source_view"]:
                raise ValueError("graph question lacks selected source-bound owner")
            source_refs(context, question["source_view"], question["source_refs"])
            from codegraph_contract import _binding, _identifier
            _identifier(question["owner"])
            _identifier(question["id"])
            _binding(context, PHASE, question["owner"], question)
            if question.get("file") and question["file"] not in {_parts(ref)[0] for ref in question["source_refs"]}:
                raise ValueError("qualified graph symbol lacks its exact inspected source anchor")
        if (not limits["enabled"] or context.get("mode") == "actions") and (selected or authored["graph_questions"]):
            raise ValueError("disabled gap exploration cannot dispatch discovery")
        publish(path(context, PHASE + "/plan.json"), authored)
        for assignment in assignments.values():
            packet = envelope(context, assignment=assignment, seed=seeds[assignment["seed_id"]],
                objective=objectives[assignment["objective_id"]], question=questions[assignment["question_id"]],
                graph_questions=[q for q in authored["graph_questions"] if q["owner"] == assignment["task_id"]],
                inputs=inputs["inputs"], plan_sha256=core.sha256_file(path(context, PHASE + "/plan.json")), max_candidates=2)
            if linked(context):
                packet["baseline"] = deepcopy(context["baseline"])
            schema(packet, "packet")
            publish(path(context, f"{PHASE}/packets/{assignment['task_id']}.json"), packet)
        if linked(context):
            return authored
        ledger = dispatch_state(context)
        ledger["plan_sha256"] = core.sha256_file(path(context, PHASE + "/plan.json"))
        core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
        return authored


def plan(context):
    value = read(context, PHASE + "/plan.json")
    schema(value, "plan")
    if value["run_id"] != context["run_id"]:
        raise ValueError("gap plan changed execution")
    if not linked(context) and not context.get("gap_exploration") and dispatch_state(context).get("plan_sha256") != core.sha256_file(path(context, PHASE + "/plan.json")):
        raise ValueError("gap plan changed its immutable admission receipt")
    return value


def packet(context, task_id):
    core.component(task_id)
    selected = plan(context)
    assignments = unique(selected["assignments"], "task_id")
    if task_id not in assignments:
        raise ValueError("worker has no selected immutable gap assignment")
    value = read(context, f"{PHASE}/packets/{task_id}.json")
    schema(value, "packet")
    if value["assignment"] != assignments[task_id] or value["plan_sha256"] != core.sha256_file(path(context, PHASE + "/plan.json")):
        raise ValueError("gap packet changed immutable ownership")
    assignment = assignments[task_id]
    expected = {"seed": unique(selected["seeds"])[assignment["seed_id"]],
                "objective": unique(selected["objectives"])[assignment["objective_id"]],
                "question": unique(selected["questions"])[assignment["question_id"]],
                "inputs": selected["inputs"],
                "graph_questions": [q for q in selected["graph_questions"] if q["owner"] == task_id]}
    if value["run_id"] != context["run_id"] or any(value[key] != item for key, item in expected.items()):
        raise ValueError("gap packet changed immutable source proof obligations")
    return value


def elapsed(ledger):
    return (datetime.now(timezone.utc) - datetime.fromisoformat(ledger["started_at"].replace("Z", "+00:00"))).total_seconds()


def dispatch_worker(context, task_id):
    if linked(context):
        raise ValueError("launch Advantage workers with native task; dispatch registration is unsupported")
    with state_lock(base_of(context)):
        owned(context)
        limits, value, ledger = budget(context), packet(context, task_id), dispatch_state(context)
        if ledger.get("finalization"):
            raise ValueError("finalized gap exploration cannot launch another wave")
        prior = [r for r in ledger["workers"] if r["id"] == task_id]
        started = {r["id"] for r in ledger["workers"]}
        if not limits["enabled"] or context.get("mode") == "actions" or elapsed(ledger) >= limits["timeout_seconds"]:
            raise ValueError("gap phase is disabled or its separate deadline is exhausted")
        if any(r["status"] != "failed" for r in prior) or len(prior) >= limits["max_attempts"]:
            raise ValueError("gap worker already active/admitted or attempts exhausted")
        if task_id not in started and len(started) >= min(limits["max_tasks"], limits["max_questions"]):
            raise ValueError("current supplementary task/question allocation exhausted")
        if sum(r["status"] == "running" for r in ledger["workers"]) >= limits["max_concurrency"]:
            raise ValueError("supplementary concurrency exhausted")
        route = assigned_route(context, worker=True)
        if prior:
            cleanup_worker(context, task_id, ledger)
        row = {"id": task_id, "attempt": len(prior) + 1, "attempt_id": context["attempt_id"], "status": "running",
               "actor": actor(context, True), "selector": route,
               "input_sha256": core.sha256_file(path(context, f"{PHASE}/packets/{task_id}.json")),
               "source_view": value["assignment"]["source_view"], "result_ref": None, "result_sha256": None,
               "error": "", "source_receipts": [], "support": []}
        ledger["workers"].append(row)
        core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
        return {**row, "packet": value}


def proof_refs(result):
    refs = list(result["resolution"]["source_refs"])
    for candidate in result["candidates"]:
        refs.extend(f"{p['file']}:{p['line']}" for p in candidate["source_locations"])
        for proof in candidate["proof"].values():
            refs.extend(proof["source_refs"])
        for item in [*candidate["causal_trace"], *candidate["inspected_controls"]]:
            refs.extend(item["source_refs"])
    return sorted(set(refs))


def validate_worker(context, task_id, value, receipt, *, historical=False):
    schema(value, "result")
    assigned = packet(context, task_id)["assignment"]
    relative = f"{PHASE}/results/{task_id}.json"
    expected = {"actor": receipt["actor"], "selector": receipt["selector"], "artifact_ref": relative}
    if linked(context):
        expected["execution_id"] = context["run_id"]
    if value["provenance"] != expected or receipt["actor"] != actor(context, True):
        raise ValueError("forged gap worker provenance or canonical owner")
    if any(value[k] != assigned[k] for k in ("task_id", "objective_id", "question_id", "source_view")) or value["run_id"] != context["run_id"] or value["attempt"] != receipt["attempt"] or value["attempt_id"] != receipt["attempt_id"]:
        raise ValueError("gap result differs from exact dispatched ownership/source view")
    if receipt["input_sha256"] != core.sha256_file(path(context, f"{PHASE}/packets/{task_id}.json")):
        raise ValueError("gap result packet changed after dispatch")
    if not historical and (receipt["attempt_id"] != context["attempt_id"] or receipt["selector"] != context["model_routing"]["agents"].get(actor(context, True))):
        raise ValueError("gap result changes current attempt route")
    resolution = value["resolution"]
    if not resolution["reason"].strip():
        raise ValueError("gap resolution requires substantive source reasoning")
    if resolution["outcome"] in {"established", "contradicted"} and not resolution["source_refs"]:
        raise ValueError("established or defeated gap outcome requires inspected source")
    if resolution["outcome"] not in {"established", "contradicted"} and (not resolution["missing_fact"].strip() or not resolution["next_action"].strip()):
        raise ValueError("gap unresolved disposition requires missing fact and next action")
    if value["candidates"] and resolution["outcome"] != "established":
        raise ValueError("gap candidates require established investigation resolution")
    unique(value["candidates"])
    for candidate in value["candidates"]:
        if not candidate["id"].startswith("GC-" + task_id + "-"):
            raise ValueError("gap candidate identity is not task-owned")
        if candidate["objective_ids"] != [assigned["objective_id"]] or candidate["question_id"] != assigned["question_id"] or candidate["source_view"] != assigned["source_view"]:
            raise ValueError("gap candidate changes assigned objective/source scope")
        if set(candidate["proof"]) != PROOF or any(p["outcome"] != "established" or not p["reason"].strip() for p in candidate["proof"].values()):
            raise ValueError("gap candidate lacks complete source-established proof obligations")
        if candidate.get("provenance", expected) != expected or candidate.get("contributors", [expected]) != [expected]:
            raise ValueError("gap candidate forges contributor provenance")
        if any(not candidate[key].strip() for key in ("root_cause_key", "terminal_impact", "reason")) or any(not item.strip() for item in candidate["conditions"]):
            raise ValueError("gap candidate lacks explicit causal scope and conditions")
        if any(not item["step"].strip() for item in candidate["causal_trace"]) or any(not item["control"].strip() or not item["effect"].strip() for item in candidate["inspected_controls"]):
            raise ValueError("gap candidate requires inspected causal trace and controls")
        if historical and (candidate.get("provenance") != expected or candidate.get("contributors") != [expected] or candidate.get("artifact_ref") != relative + ":" + candidate["id"]):
            raise ValueError("admitted gap candidate lost durable attribution")
        if not historical:
            if candidate["classification"] in {"baseline_correction", "baseline_revalidation"} and not candidate["baseline_ids"]:
                raise ValueError("baseline classification requires an actual admitted baseline finding")
            if candidate["baseline_ids"]:
                if not linked(context):
                    raise ValueError("ordinary supplementary work has no linked baseline authority")
                from advantage_pipeline import baseline_findings
                if not set(candidate["baseline_ids"]).issubset(baseline_findings(context)):
                    raise ValueError("gap candidate names an unaccepted baseline finding")
            inputs = packet(context, task_id)["inputs"]
            for ref in candidate["evidence_refs"]:
                if isinstance(ref, str) and ref in proof_refs(value):
                    continue
                if isinstance(ref, str) and ref.startswith(PHASE + "/"):
                    raise ValueError("raw graph or unpublished peer output is not candidate proof")
                try:
                    input_reference(context, ref, inputs)
                except ValueError:
                    if isinstance(ref, str) and _parts(ref)[0].split("/", 1)[0] not in {PHASE, *INPUTS["ordinary"], *INPUTS["advantage"]}:
                        source_refs(context, value["source_view"], [ref])
                    else:
                        raise
    refs = proof_refs(value)
    if not historical and refs:
        source_refs(context, value["source_view"], refs)
    if historical and refs != sorted(r["ref"] for r in receipt["source_receipts"]):
        raise ValueError("gap result source-proof admission receipt changed")
    return expected


def receipt_support(context, owner, references):
    support = []
    for ref in references:
        relative, _ = _parts(ref)
        parts = Path(relative).parts
        if len(parts) != 5 or parts[:2] != (PHASE, "codegraph-runs") or parts[2] != owner or parts[4] != "receipt.json":
            raise ValueError("graph receipt substituted another gap owner")
        question = graph_question(context, owner, parts[3], active=False)
        selected = source_context(context, question["source_view"])
        from codegraph_contract import validate_query_receipt
        validate_query_receipt(base_of(context), Path(selected.get("source_root") or selected["repo_path"]), context, PHASE, owner, question, ref)
        for name in ("receipt.json", "context.json"):
            relative = "/".join((*parts[:4], name))
            support.append({"ref": relative, "sha256": core.sha256_file(path(context, relative))})
    return support


def _analytical_result(result):
    """Exclude only publisher-owned receipts, not analytical or attribution fields."""
    return {key: value for key, value in result.items() if key != "admission"}


def _normalize_worker_result(context, result, provenance):
    """Apply the same publication transform to an admitted or reconciled draft."""
    result = deepcopy(_analytical_result(result))
    assessment = assessment_ref(context)
    relative = f"{PHASE}/results/{result['task_id']}.json"
    for candidate in result["candidates"]:
        candidate.update(provenance=provenance, contributors=[provenance],
                         artifact_ref=relative + ":" + candidate["id"])
        if assessment:
            candidate["assessment_context"] = assessment
    if assessment:
        result["assessment_context"] = assessment
    return result


def admit_worker(context, task_id, result):
    with invocation_lock(context):
        owned(context)
        ledger = dispatch_state(context)
        attempts = [r for r in ledger["workers"] if r["id"] == task_id]
        if linked(context):
            running = [attempts[-1]] if attempts and attempts[-1]["status"] in {"delivered", "failed", "cancelled"} else []
        else:
            running = [r for r in attempts if r["status"] == "running"]
        if len(running) != 1:
            raise ValueError("gap result has no single active dispatched attempt")
        row = running[0]
        if linked(context):
            native = next(r for r in core.live_call(context, PHASE)["workers"]
                          if r["runtime_id"] == row["runtime_id"])
            if native["status"] not in {"completed", "failed", "cancelled"}:
                raise ValueError("gap admission requires a stopped native worker")
            matches = []
            for artifact in native.get("artifacts", []):
                candidate_path = path(context, artifact)
                expected_hash = native.get("artifact_sha256", {}).get(artifact)
                if candidate_path.is_file() and expected_hash == core.sha256_file(candidate_path) and core.load_value(candidate_path) == result:
                    matches.append(candidate_path)
            if not matches:
                raise ValueError("gap admission requires exact actual native terminal artifact")
        provenance = validate_worker(context, task_id, result, row)
        admitted_count = sum(len(read(context, r["result_ref"])["candidates"]) for r in ledger["workers"] if r["status"] == "completed")
        if admitted_count + len(result["candidates"]) > budget(context)["max_candidates"]:
            raise ValueError("supplementary candidate allocation exhausted; retain explicit allocation deferral")
        graph = packet(context, task_id)["graph_questions"]
        if graph and not result["graph_receipt_refs"] and not result["limitations"]:
            raise ValueError("unused graph questions require exact source-only limitation")
        row["support"] = receipt_support(context, task_id, result["graph_receipt_refs"])
        selected = source_context(context, result["source_view"])
        root = Path(selected.get("source_root") or selected["repo_path"])
        row["source_receipts"] = [{"ref": ref, "source_view": result["source_view"], "sha256": core.sha256_file(source_file(root, selected["repositories"], ref))} for ref in proof_refs(result)]
        result = _normalize_worker_result(context, result, provenance)
        result["admission"] = {key: row[key] for key in ("input_sha256", "source_receipts", "support")}
        if linked(context):
            result["admission"]["runtime_id"] = row["runtime_id"]
        schema(result, "result")
        relative = f"{PHASE}/results/{task_id}.json"
        publish(path(context, relative), result)
        row.update(status="completed", result_ref=relative, result_sha256=core.sha256_file(path(context, relative)))
        if not linked(context):
            core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
        return row


def cleanup_worker(context, task_id, ledger):
    if linked(context):
        raise ValueError("Advantage cleanup uses confined native invocation teardown")
    attempts = [r for r in ledger["workers"] if r["id"] == task_id]
    if not attempts or any(r["status"] != "failed" for r in attempts):
        raise ValueError("cleanup requires stopped failed worker attempts")
    protected = {item["ref"] for row in ledger["workers"] if row["status"] == "completed" for item in row["support"]}
    protected.update(r["result_ref"] for r in ledger["workers"] if r["status"] == "completed")
    files, directories = [], []
    for relative in (f"{PHASE}/results/{task_id}.json", f"{PHASE}/drafts/{task_id}", f"{PHASE}/scratch/{task_id}"):
        target = path(context, relative)
        if target.is_dir():
            directories.append(target)
            for child in target.rglob("*"):
                child = core.inside(base_of(context), child)
                if child.is_dir():
                    directories.append(child)
                elif child.is_file():
                    files.append(child)
                else:
                    raise ValueError("unsafe rejected gap output type")
        elif target.is_file():
            files.append(target)
    for target in files:
        if target.relative_to(base_of(context)).as_posix() not in protected:
            target.unlink()
    for target in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        if not any(target.iterdir()):
            target.rmdir()


def fail_worker(context, task_id, reason):
    if linked(context):
        raise ValueError("native task outcomes own Advantage failures")
    core.component(task_id)
    if not isinstance(reason, str) or not reason.strip() or publication_content_error(reason):
        raise ValueError("gap worker failure requires sanitized actual error")
    with state_lock(base_of(context)):
        owned(context, failure=True)
        ledger = dispatch_state(context)
        rows = [r for r in ledger["workers"] if r["id"] == task_id and r["status"] == "running"]
        if len(rows) != 1:
            raise ValueError("failed gap worker has no single active attempt")
        rows[0].update(status="failed", error=reason)
        core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
        cleanup_worker(context, task_id, ledger)
        return rows[0]


def graph_question(context, owner, question_id, *, active=True):
    if active:
        owned(context)
        if dispatch_state(context).get("finalization"):
            raise ValueError("finalized gap exploration cannot launch graph work")
    value = plan(context)
    matches = [q for q in value["graph_questions"] if q["owner"] == owner and q["id"] == question_id]
    if len(matches) != 1:
        raise ValueError("graph question is not registered to exact gap owner")
    if owner != coordinator(context):
        packet(context, owner)
        if active and len([r for r in dispatch_state(context)["workers"] if r["id"] == owner and r["status"] == "running" and r["attempt_id"] == context["attempt_id"]]) != 1:
            raise ValueError("graph owner lacks current dispatched gap attempt")
    question = {k: v for k, v in matches[0].items() if k not in {"owner", "seed_id", "source_refs"}}
    question["owner_ref"] = PHASE + "/plan.json" if owner == coordinator(context) else f"{PHASE}/packets/{owner}.json"
    return question


def admitted(context, ledger):
    records, candidates = [], []
    for row in ledger["workers"]:
        if row["status"] != "completed":
            continue
        relative = f"{PHASE}/results/{row['id']}.json"
        if row["result_ref"] != relative or core.sha256_file(path(context, relative)) != row["result_sha256"]:
            raise ValueError("accepted gap worker result changed immutable admission")
        result = read(context, relative)
        validate_worker(context, row["id"], result, row, historical=True)
        for item in row["support"]:
            if core.sha256_file(path(context, item["ref"])) != item["sha256"]:
                raise ValueError("accepted gap support changed immutable admission")
        record = {"task_id": row["id"], "ref": relative, "sha256": row["result_sha256"], "source_view": result["source_view"], "provenance": result["provenance"]}
        if result.get("assessment_context"):
            record["assessment_context"] = result["assessment_context"]
        records.append(record)
        candidates.extend(result["candidates"])
    unique(candidates)
    return records, candidates


def aggregate(context, *, failure_reason=None):
    ledger = dispatch_state(context)
    if any(r["status"] == "running" for r in ledger["workers"]) or any(r.get("status") == "running" for rows in ledger["graph_consumption"].values() for r in rows):
        raise ValueError("stop and close gap descendants before deterministic finalization")
    selected = plan(context) if ledger.get("plan_sha256") else None
    missing_plan = selected is None and budget(context)["enabled"] and context.get("mode") != "actions"
    if missing_plan and not linked(context) and not failure_reason:
        raise ValueError("enabled gap phase needs an admitted empty or selected plan")
    records, candidates = admitted(context, ledger)
    non_promoted, limitations = [], []
    if linked(context) and missing_plan:
        limitations.append("Gap exploration has no admitted plan; supplementary source coverage remains unreviewed.")
    if failure_reason:
        limitations.append(failure_reason)
    completed = {r["task_id"] for r in records}
    unlaunched = ({a["task_id"] for a in selected["assignments"]} - {r["id"] for r in ledger["workers"]}
                  if linked(context) and selected else set())
    for assignment in selected["assignments"] if selected else []:
        if assignment["task_id"] in completed:
            continue
        attempts = [r for r in ledger["workers"] if r["id"] == assignment["task_id"]]
        if linked(context):
            outcome = "locally_unresolved"
            reason = "Selected gap assignment was never launched; its proof obligation remains unreviewed."
            if attempts:
                latest = attempts[-1]
                if latest["status"] in {"failed", "cancelled"}:
                    outcome = "execution_failed"
                reason = latest.get("error") or "Native worker delivered no admitted analytical result."
        else:
            limits = budget(context)
            exhausted = (failure_reason or not limits["enabled"] or elapsed(ledger) >= limits["timeout_seconds"] or len(attempts) >= limits["max_attempts"] or not attempts and len({r["id"] for r in ledger["workers"]}) >= min(limits["max_tasks"], limits["max_questions"]))
            if not exhausted:
                raise ValueError("selected useful gap assignment still has supplementary investigation capacity")
            reason = attempts[-1]["error"] if attempts else failure_reason or "Current supplementary allocation exhausted before dispatch."
            outcome = "execution_failed" if attempts else "budget_deferred"
        non_promoted.append({"id": assignment["task_id"], "objective_id": assignment["objective_id"], "question_id": assignment["question_id"], "outcome": outcome, "reason": reason, "missing_fact": assignment["proof_obligation"], "next_action": assignment["expected_outcome"]})
    if selected:
        non_promoted.extend({"id": seed["id"], "objective_id": seed["objective_id"], "question_id": seed["question_id"], "outcome": seed["disposition"], "reason": seed["stop_condition"], "missing_fact": seed["missing_fact"], "next_action": seed["next_action"]} for seed in selected["seeds"] if seed["disposition"] != "selected")
    for record in records:
        result = read(context, record["ref"])
        limitations.extend(result["limitations"])
        if result["resolution"]["outcome"] != "established":
            non_promoted.append({"id": record["task_id"], "objective_id": result["objective_id"], "question_id": result["question_id"], **{k: result["resolution"][k] for k in ("outcome", "reason", "missing_fact", "next_action")}})
    graph = ledger["graph_consumption"]
    for row in [*graph["queries"], *graph["preparations"]]:
        if row.get("limitation"):
            limitations.append(row["limitation"])
    disabled = not budget(context)["enabled"] or context.get("mode") == "actions"
    status = "degraded" if failure_reason else "skipped" if disabled and not records and not ledger["workers"] else "degraded" if limitations or any(r["outcome"] in {"execution_failed", "budget_deferred", "externally_blocked", "locally_unresolved"} for r in non_promoted) else "ok"
    value = envelope(context, status=status, objectives=selected["objectives"] if selected else [], questions=selected["questions"] if selected else [], results=records,
        candidates=candidates, non_promoted=non_promoted, limitations=list(dict.fromkeys(limitations)), graph_consumption=deepcopy(graph),
        summary={"examined_questions": len(selected["seeds"]) if selected else 0,
                 "graph_queries": len(graph["queries"]), "useful_navigation": sum(r.get("receipt_health") == "ok" and r.get("meaningful") is True for r in graph["queries"]),
                 "investigated_leads": len(completed), "worker_attempts": len(ledger["workers"]),
                 "candidates": len(candidates), "independently_accepted": 0,
                 "uninvestigated_leads": sum(r["outcome"] == "budget_deferred" or r["id"] in unlaunched
                                             for r in non_promoted)})
    if linked(context):
        value.pop("graph_consumption")
        value["graph_observations"] = graph["queries"]
    schema(value, "results")
    return value


def validate_failure_record(context, reason):
    if linked(context):
        call = core.live_call(context, PHASE)
        rows = [row for row in call["workers"] if row["id"] == coordinator(context)
                and row["phase"] == PHASE]
        if (not rows or rows[-1]["status"] not in {"failed", "cancelled"}
                or rows[-1].get("error") != reason
                or any(row["status"] == "running" for row in call["workers"] if row["phase"] == PHASE)):
            raise ValueError("optional gap closure requires actual stopped native coordinator failure")
        return
    run = manifest(context)
    ledger = read(context, "task-ledger.json")
    tasks = ledger.get("tasks")
    if ledger.get("run_id") != context["run_id"] or not isinstance(tasks, list):
        raise ValueError("optional closure requires authoritative coordinator failure history")
    rows = [row for row in tasks if isinstance(row, dict) and row.get("id") == coordinator(context)]
    if len(rows) != 1 or state(run["phases"][PHASE]) != "failed" or any(row.get("status") == "running" for row in tasks if isinstance(row, dict)):
        raise ValueError("optional closure requires the actual failed coordinator and stopped descendants")
    row = rows[0]
    if (row.get("phase") != PHASE or row.get("status") != "failed" or row.get("error") != reason
            or row.get("attempt_id") != context["attempt_id"]
            or row.get("failure_kind") not in {"execution_failed", "deadline_exceeded"}
            or type(row.get("attempts")) is not int or row["attempts"] < budget(context)["max_attempts"]):
        raise ValueError("optional closure requires an exhausted recorded operational failure")
    expected = {"attempt": row["attempts"], "attempt_id": row["attempt_id"], "kind": row["failure_kind"], "error": reason}
    if not row.get("failure_history") or row["failure_history"][-1] != expected:
        raise ValueError("optional closure changed actual coordinator failure history")


def finalize_phase_locked(context, *, failure_reason=None):
    """Publish while the lifecycle caller already holds its state lock."""
    if linked(context) and failure_reason is None:
        call = core.live_call(context, PHASE)
        coordinators = [row for row in call["workers"] if row["phase"] == PHASE and row["id"] == coordinator(context)]
        if coordinators and coordinators[-1]["status"] in {"failed", "cancelled"}:
            failure_reason = coordinators[-1].get("error") or None
    if failure_reason is not None and (not failure_reason.strip() or publication_content_error(failure_reason)):
        raise ValueError("optional closure requires sanitized actual coordinator failure")
    owned(context, failure=failure_reason is not None)
    if failure_reason is not None:
        validate_failure_record(context, failure_reason)
    if linked(context):
        value = aggregate(context, failure_reason=failure_reason)
        publish(path(context, PHASE + "/results.json"), value)
        return value
    ledger = dispatch_state(context)
    if ledger.get("finalization"):
        validate_phase(base_of(context), context)
        if failure_reason is None or failure_reason == ledger["finalization"]["failure_reason"]:
            return read(context, PHASE + "/results.json")
    core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
    value = aggregate(context, failure_reason=failure_reason)
    if ledger.get("finalization"):
        # The top-level checkpoint is still unaccepted. Preserve all immutable
        # worker publications while adding the actual failed coordinator closure.
        core.atomic_json(path(context, PHASE + "/results.json"), value)
    else:
        publish(path(context, PHASE + "/results.json"), value)
    now = core.now()
    phase = {"phase": PHASE, "status": value["status"], "started_at": ledger["started_at"], "completed_at": now,
             "inputs": [r["ref"] for r in read(context, PHASE + "/inputs.json")["inputs"]] if path(context, PHASE + "/inputs.json").exists() else [],
             "outputs": [PHASE + "/results.json"], "coverage": value["summary"], "tool_versions": {},
             "warnings": value["limitations"], "errors": []}
    core.atomic_json(path(context, PHASE + "/phase-manifest.json"), phase)
    ledger["finalization"] = {"results_sha256": core.sha256_file(path(context, PHASE + "/results.json")), "failure_reason": failure_reason}
    core.atomic_json(path(context, PHASE + "/dispatch.json"), ledger)
    return value


def finalize_phase(context, *, failure_reason=None):
    with invocation_lock(context):
        return finalize_phase_locked(context, failure_reason=failure_reason)


def validation_context(base, context=None):
    if context is not None:
        if Path(context["scan_base"]).resolve() != Path(base).resolve():
            raise ValueError("gap validation base differs from context")
        return context
    if core.inside(base, "report/security-report.json").is_file():
        from report_bundle import read_publication
        return read_publication(Path(base))
    name = "advantage-manifest.json" if (Path(base) / "advantage-manifest.json").is_file() else "run-manifest.json"
    value = core.load(core.inside(base, name))
    return {**value, "scan_base": str(Path(base).absolute())}


def validate_phase(base, context):
    context = validation_context(base, context)
    if linked(context) or context.get("gap_exploration"):
        return validate_analytical_phase(context)
    manifest(context)
    value = read(context, PHASE + "/results.json")
    schema(value, "results")
    if value["run_id"] != context["run_id"]:
        raise ValueError("gap aggregate changed execution ownership")
    ledger = dispatch_state(context)
    if ledger.get("finalization", {}).get("results_sha256") != core.sha256_file(path(context, PHASE + "/results.json")):
        raise ValueError("gap aggregate lacks its exact deterministic finalization receipt")
    if value["graph_consumption"] != ledger["graph_consumption"]:
        raise ValueError("gap aggregate changed graph consumption")
    if any(r["status"] == "running" for r in ledger["workers"]):
        raise ValueError("completed gap aggregate retains running worker")
    records, candidates = admitted(context, ledger)
    if value["results"] != records or value["candidates"] != candidates:
        raise ValueError("gap aggregate is not exact admitted worker union")
    if ledger.get("plan_sha256"):
        selected = plan(context)
        if value["objectives"] != selected["objectives"] or value["questions"] != selected["questions"]:
            raise ValueError("gap aggregate changed admitted objectives/questions")
        accounted = {r["task_id"] for r in records} | {r["id"] for r in value["non_promoted"]}
        if not {r["task_id"] for r in selected["assignments"]}.issubset(accounted):
            raise ValueError("gap aggregate omitted selected work")
    phase = read(context, PHASE + "/phase-manifest.json")
    if phase.get("phase") != PHASE or phase.get("status") != value["status"] or PHASE + "/results.json" not in phase.get("outputs", []):
        raise ValueError("gap phase manifest differs from canonical aggregate")
    return phase


def load_accepted(base, *, context=None):
    if context and not linked(context) and core.inside(base, "run-manifest.json").is_file():
        active = validation_context(base, context)
        run = core.load(core.inside(base, "run-manifest.json"))
        if run.get("status") != "complete" and any(state(value) == "running" for value in run.get("phases", {}).values()):
            if (not active.get("run_id") or run.get("run_id") != active["run_id"]
                    or run.get("attempt_id") != active.get("attempt_id")):
                raise ValueError("active supplementary reader changed execution or attempt ownership")
            if PHASE not in run.get("phases", {}):
                return None
            if not active.get("attempt_id"):
                raise ValueError("declared supplementary phase lacks current attempt ownership")
            if state(run["phases"][PHASE]) not in SUCCESS:
                raise ValueError("declared gap exploration has no accepted checkpoint")
            validate_phase(base, active)
            return read(active, PHASE + "/results.json")
    if core.inside(base, "report/security-report.json").is_file():
        from report_bundle import read_publication
        bundle = read_publication(Path(base))
        binding = bundle.get("gap_exploration")
        if binding:
            if binding["ref"] != PHASE + "/results.json" or core.sha256_file(core.inside(base, binding["ref"])) != binding["sha256"]:
                raise ValueError("completed supplementary evidence changed publication binding")
            value = core.load(core.inside(base, binding["ref"]))
            if all("admission" in core.load(core.inside(base, row["ref"])) for row in value["results"]):
                validate_analytical_phase(bundle)
                return value
        elif core.inside(base, PHASE + "/results.json").exists() and not any(
                core.inside(base, name).exists() for name in ("run-manifest.json", "advantage-manifest.json")):
            raise ValueError("completed report omitted its supplementary evidence binding")
        if core.inside(base, PHASE + "/dispatch.json").is_file():
            legacy_name = "advantage-manifest.json" if core.inside(base, "advantage-manifest.json").is_file() else "run-manifest.json"
            legacy = {**core.load(core.inside(base, legacy_name)), "scan_base": str(Path(base).absolute())}
            legacy_value = read(legacy, PHASE + "/results.json")
            ledger = core.load(core.inside(base, PHASE + "/dispatch.json"))
            if ledger.get("finalization", {}).get("results_sha256") != core.sha256_file(core.inside(base, PHASE + "/results.json")):
                raise ValueError("legacy supplementary evidence changed final publication")
            records, candidates = admitted(legacy, ledger)
            if legacy_value["results"] != records or legacy_value["candidates"] != candidates:
                raise ValueError("legacy supplementary evidence lost canonical candidates")
            return legacy_value
        if binding is None:
            return None
    if context and context.get("_retained_publication"):
        validate_analytical_phase(context, native=False)
        return read(context, PHASE + "/results.json")
    if context and linked(context):
        call = core.live_call(context)
        if PHASE not in call["accepted_phases"]:
            raise ValueError("supplementary phase has no native acceptance")
        validate_analytical_phase(context)
        return read(context, PHASE + "/results.json")
    if not any(core.inside(base, name).exists() for name in ("run-manifest.json", "advantage-manifest.json")):
        if context and PHASE in context.get("phases", {}):
            raise ValueError("declared gap execution lost authoritative manifest")
        return None
    context = validation_context(base, context)
    name = "advantage-manifest.json" if linked(context) else "run-manifest.json"
    run = core.load(core.inside(base, name))
    if PHASE not in run.get("phases", {}):
        return None
    if state(run["phases"][PHASE]) not in SUCCESS:
        raise ValueError("declared gap exploration has no accepted checkpoint")
    validate_phase(base, context)
    return read(context, PHASE + "/results.json")


def load_accepted_candidates(base):
    value = load_accepted(base)
    return value["candidates"] if value else []


def producing_attempt(base, artifact_ref):
    context = validation_context(base)
    relative, _ = _parts(artifact_ref)
    if not relative.startswith(PHASE + "/results/"):
        return None
    if linked(context) or context.get("gap_exploration"):
        value = load_accepted(base, context=context)
        records = [row for row in value["results"] if row["ref"] == relative] if value else []
        if len(records) != 1 or core.sha256_file(path(context, relative)) != records[0]["sha256"]:
            raise ValueError("gap contributor lacks exact admitted producing evidence")
        return read(context, relative)["attempt_id"]
    ledger = dispatch_state(context)
    rows = [r for r in ledger["workers"] if r["status"] == "completed" and r["result_ref"] == relative]
    if len(rows) != 1 or core.sha256_file(path(context, relative)) != rows[0]["result_sha256"]:
        raise ValueError("gap contributor lacks exact admitted producing attempt")
    return rows[0]["attempt_id"]


def recovery_checkpoint(context, *, interrupt_running=True):
    if linked(context):
        raise ValueError("Advantage supplementary work cannot recover")
    run = manifest(context)
    controls = [PHASE + "/" + name for name in ("inputs.json", "plan.json", "dispatch.json")]
    if not any(path(context, relative).exists() for relative in controls):
        return {"files": [], "documents": {}}
    predecessor = "intrusion"
    if context.get("mode") != "actions" and state(run["phases"].get(predecessor)) not in SUCCESS:
        raise ValueError("gap recovery controls lack accepted predecessor")
    ledger = dispatch_state(context)
    running_graph = [row for rows in ledger["graph_consumption"].values() for row in rows if row.get("status") == "running"]
    if not interrupt_running and (any(row["status"] == "running" for row in ledger["workers"]) or running_graph):
        raise ValueError("stop gap descendants before cleanup; running worker output is protected")
    files = set()
    if ledger.get("inputs_sha256"):
        files.add(PHASE + "/inputs.json")
    if ledger.get("plan_sha256"):
        files.add(PHASE + "/plan.json")
        for assignment in plan(context)["assignments"]:
            packet(context, assignment["task_id"])
            files.add(f"{PHASE}/packets/{assignment['task_id']}.json")
    records, _ = admitted(context, ledger)
    files.update(r["ref"] for r in records)
    for row in ledger["workers"]:
        if row["status"] == "completed":
            files.update(item["ref"] for item in row["support"])
        elif row["status"] == "running" and interrupt_running:
            row.update(status="failed", error="Interrupted supplementary worker; stopped before recovery.")
    for row in running_graph:
        row.update(status="interrupted", limitation="Interrupted graph operation; reservation remains consumed.")
    # All graph consumption survives, including failed reservations. Retained
    # receipts are support, not a grant of renewed query/preparation capacity.
    from gap_graph import receipt_support as graph_support
    files.update(item["ref"] for item in graph_support(context))
    if ledger.get("finalization"):
        validate_phase(base_of(context), context)
        files.update({PHASE + "/results.json", PHASE + "/phase-manifest.json"})
    return {"files": sorted(files), "documents": {PHASE + "/dispatch.json": ledger}}


def accepted_support_refs(base, context=None):
    context = validation_context(base, context)
    if load_accepted(base, context=context) is None:
        return set()
    if linked(context) or context.get("gap_exploration"):
        value = read(context, PHASE + "/results.json")
        files = {PHASE + "/results.json"}
        for relative in (PHASE + "/inputs.json", PHASE + "/plan.json"):
            if path(context, relative).is_file():
                files.add(relative)
        if path(context, PHASE + "/plan.json").is_file():
            files.update(f"{PHASE}/packets/{row['task_id']}.json" for row in read(context, PHASE + "/plan.json")["assignments"])
        files.update(row[key + "_ref"] for row in value.get("graph_observations", []) for key in ("receipt", "context"))
        for record in value["results"]:
            files.add(record["ref"])
            files.add(f"{PHASE}/packets/{record['task_id']}.json")
            result = read(context, record["ref"])
            if result.get("admission"):
                files.update(row["ref"] for row in result["admission"]["support"])
            else:
                ledger = read(context, PHASE + "/dispatch.json")
                files.update(item["ref"] for row in ledger["workers"] if row["status"] == "completed" and row["id"] == record["task_id"] for item in row["support"])
        return files
    checkpoint = recovery_checkpoint(context, interrupt_running=False)
    return set(checkpoint["files"]) | {PHASE + "/results.json"}


def accounting(base, context=None):
    value = load_accepted(base, context=context)
    return {**value["summary"], "status": value["status"], "limitations": value["limitations"], "non_promoted": value["non_promoted"]} if value else None


def evidence_row(context, task_id, result):
    """Validation inputs from analytical provenance, never scheduling state."""
    return {"id": task_id, "attempt": result["attempt"], "attempt_id": result["attempt_id"],
            "actor": result["provenance"]["actor"], "selector": result["provenance"]["selector"],
            "source_view": result["source_view"], "status": "completed",
            "result_ref": f"{PHASE}/results/{task_id}.json",
            "result_sha256": core.sha256_file(path(context, f"{PHASE}/results/{task_id}.json")),
            **result["admission"]}


def native_evidence(context):
    call = core.live_call(context)
    workers = []
    assignments = unique(read(context, PHASE + "/plan.json")["assignments"], "task_id") if path(context, PHASE + "/plan.json").is_file() else {}
    for native in call["workers"]:
        if native["phase"] != PHASE or native["actor"] != actor(context, True):
            continue
        task_id = native["id"]
        if task_id not in assignments or native["selector"] != assigned_route(context, worker=True):
            raise ValueError("native gap worker changed assignment or exact route")
        input_hash = core.sha256_file(path(context, f"{PHASE}/packets/{task_id}.json"))
        if native.get("input_sha256") != input_hash:
            raise ValueError("native gap worker changed immutable packet binding")
        relative = f"{PHASE}/results/{task_id}.json"
        if path(context, relative).is_file():
            result = read(context, relative)
            if result.get("admission", {}).get("runtime_id") == native["runtime_id"]:
                if native["status"] not in {"completed", "failed", "cancelled"}:
                    raise ValueError("canonical gap result lacks stopped native worker evidence")
                drafts = []
                for ref in native.get("artifacts", []):
                    target = path(context, ref)
                    if native.get("artifact_sha256", {}).get(ref) != core.sha256_file(target):
                        raise ValueError("native gap terminal artifact changed")
                    draft = core.load(target)
                    if draft.get("task_id") == task_id:
                        drafts.append(draft)
                if len(drafts) != 1:
                    raise ValueError("gap worker lacks one exact terminal analytical result")
                expected = _normalize_worker_result(context, drafts[0], result["provenance"])
                if _analytical_result(result) != expected:
                    raise ValueError("canonical gap evidence differs from actual native delivery")
                workers.append(evidence_row(context, task_id, result))
                continue
        status = native["status"]
        if status == "completed":
            status = "delivered"
        workers.append({**native, "attempt_id": context["attempt_id"], "status": status,
            "input_sha256": core.sha256_file(path(context, f"{PHASE}/packets/{task_id}.json")),
            "source_view": assignments[task_id]["source_view"], "result_ref": None,
            "result_sha256": None, "source_receipts": [], "support": [],
            "error": native.get("error") or "Native worker delivered no admissible analytical result."})
    limits = budget(context)
    for identity in assignments:
        attempts = [row for row in workers if row["id"] == identity]
        if ([row["attempt"] for row in attempts] != list(range(1, len(attempts) + 1))
                or any(row["status"] not in {"failed", "cancelled", "delivered"} for row in attempts[:-1])):
            raise ValueError("native gap execution sequence has conflicting ownership")
    if (len({row["id"] for row in workers}) > limits["max_tasks"] or
            sum(row["status"] == "running" for row in workers) > limits["max_concurrency"]):
        raise ValueError("native supplementary work exceeds current invocation allocation")
    from gap_graph import observations
    return {"workers": workers,
            "plan_sha256": core.sha256_file(path(context, PHASE + "/plan.json")) if path(context, PHASE + "/plan.json").is_file() else None,
            "graph_consumption": {"preparations": [], "queries": observations(context)}}


def validate_analytical_phase(context, *, native=True):
    value = read(context, PHASE + "/results.json")
    schema(value, "results")
    if value["run_id"] != context["run_id"]:
        raise ValueError("gap evidence belongs to another execution")
    rows = []
    for record in value["results"]:
        result = read(context, record["ref"])
        row = evidence_row(context, record["task_id"], result)
        if record["sha256"] != row["result_sha256"]:
            raise ValueError("canonical gap result changed analytical binding")
        rows.append(row)
    records, candidates = admitted(context, {"workers": rows})
    if records != value["results"] or candidates != value["candidates"]:
        raise ValueError("gap aggregate omitted or changed canonical candidate evidence")
    if path(context, PHASE + "/plan.json").is_file():
        selected = plan(context)
        if any(value[key] != selected[key] for key in ("objectives", "questions")):
            raise ValueError("gap aggregate changed analytical objective/question scope")
        accounted = {r["task_id"] for r in records} | {r["id"] for r in value["non_promoted"]}
        if not {r["task_id"] for r in selected["assignments"]}.issubset(accounted):
            raise ValueError("gap aggregate omitted selected obligations")
    for observation in value.get("graph_observations", []):
        for key in ("receipt", "context"):
            if core.sha256_file(path(context, observation[key + "_ref"])) != observation[key + "_sha256"]:
                raise ValueError("gap graph observation changed analytical binding")
    if native and linked(context) and not path(context, "report/security-report.json").is_file():
        call = core.live_call(context)
        coordinators = [row for row in call["workers"] if row["phase"] == PHASE and row["id"] == coordinator(context)]
        failure = coordinators[-1].get("error") if coordinators and coordinators[-1]["status"] in {"failed", "cancelled"} else None
        if aggregate(context, failure_reason=failure) != value:
            raise ValueError("gap analytical closure differs from actual native outcomes")
    return {"phase": PHASE, "status": value["status"], "outputs": [PHASE + "/results.json"],
            "coverage": value["summary"], "warnings": value["limitations"], "errors": []}


def cli(command):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=Path)
    if command == "prepare":
        parser.add_argument("--plan", type=Path)
    elif command == "worker":
        parser.add_argument("action", choices=("dispatch", "admit", "fail", "fail-graph"))
        parser.add_argument("--task-id")
        parser.add_argument("--result", type=Path)
        parser.add_argument("--reason")
    else:
        parser.add_argument("--failure-reason")
    args = parser.parse_args()
    try:
        if not args.context.is_absolute():
            raise ValueError("--context must be absolute")
        context = core.load(args.context)
        if linked(context):
            context = core.load_context(args.context)
        if command == "prepare":
            result = admit_plan(context, core.load(args.plan)) if args.plan else prepare_inputs(context)
        elif command == "worker":
            if args.action != "fail-graph" and not args.task_id:
                raise ValueError("worker operation requires --task-id")
            if args.action == "fail-graph":
                owned(context, failure=True)
                if not args.reason or not args.reason.strip() or publication_content_error(args.reason):
                    raise ValueError("graph interruption requires a sanitized actual reason")
                from gap_graph import fail_running
                result = {"closed_graph_operations": fail_running(context, args.reason)}
            elif args.action == "dispatch":
                result = dispatch_worker(context, args.task_id)
            elif args.action == "admit":
                if args.result is None:
                    raise ValueError("admit requires --result")
                if linked(context):
                    owned(context)
                    dispatch_state(context)
                    packet(context, args.task_id)
                    result_path = core.inside(base_of(context), args.result)
                    try:
                        result = admit_worker(context, args.task_id, core.load(result_path))
                    except (ValueError, FileNotFoundError, KeyError, TypeError):
                        result = {"status": "not_admitted",
                                  "reason": "No usable source-bound publication; continue other work."}
                else:
                    result = admit_worker(context, args.task_id, core.load(args.result))
            else:
                result = fail_worker(context, args.task_id, args.reason)
        else:
            result = finalize_phase(context, failure_reason=args.failure_reason)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    return 0


def phase_status(context):
    """Analytical closure, not an execution checkpoint."""
    return validate_analytical_phase(context)["status"]
