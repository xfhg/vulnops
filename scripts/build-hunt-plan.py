#!/usr/bin/env python3
"""Build or gapfill the bounded, contextual VulnOps V5 SAST hunt plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from harness_contract import resolved_sast_budget
from objective_contract import validate_registry, validate_binding

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load(path: Path, fallback: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def unique(values: list[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"


def phase_status(scan: Path, name: str) -> str:
    doc = load(scan / name / "phase-manifest.json", {})
    return str(doc.get("status", "missing")) if isinstance(doc, dict) else "missing"


def budget(depth: str, context: dict) -> dict[str, int]:
    snapshotted = context.get("sast_budget")
    if isinstance(snapshotted, dict):
        return {key: int(value) for key, value in snapshotted.items()}
    return resolved_sast_budget(depth)


def methodology_refs(attack_class: dict) -> list[str]:
    refs = [str(attack_class.get("methodology_ref", "skill://vulnops-audit-core"))]
    if "skill://vulnops-audit-core" not in refs:
        refs.append("skill://vulnops-audit-core")
    return unique(refs)


def specialist_lenses(attack_class: dict) -> list[str]:
    return unique([str(item) for item in attack_class.get("lenses", []) if str(item)])


def publish_task_packets(scan: Path, plan: dict, plan_bytes: bytes) -> None:
    directory = scan / "sast/hunt-tasks"
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(plan_bytes).hexdigest()
    cell_map = {str(cell.get("id")): cell for cell in plan.get("cells", []) if isinstance(cell, dict)}
    limit = int((plan.get("budget") or {}).get("context_packet_bytes", 65536))
    expected: set[str] = set()
    for task in plan.get("tasks", []):
        task_id = str(task.get("id", ""))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", task_id):
            raise ValueError(f"unsafe hunt task ID: {task_id!r}")
        expected.add(f"{task_id}.json")
        path = directory / f"{task_id}.json"
        if path.exists():
            retained = load(path, {})
            if retained.get("run_id") != plan.get("run_id") or retained.get("task") != task:
                raise ValueError(f"retained hunt task packet ownership mismatch: {task_id}")
            continue
        packet = {
            "schema_version": "2.0",
            "run_id": str(plan.get("run_id", "")),
            "hunt_plan_ref": "sast/hunt-plan.json",
            "hunt_plan_sha256": digest,
            "task": task,
            "attack_objectives": [row for row in plan["attack_objectives"] if row["id"] in task["objective_ids"]],
            "investigation_questions": [row for row in plan["investigation_questions"] if row["id"] in task["question_ids"]],
            "cells": [cell_map[str(cell_id)] for cell_id in task.get("cell_ids", [])],
            "resource_allowance": plan["budget"],
            "source_policy": "Initial files are anchors, not a whitelist. Follow attributed dependencies only inside the authorized application repository set; preserve repository prefixes.",
            "model_amendments": plan.get("model_amendments", []),
        }
        rendered = (json.dumps(packet, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(rendered) > limit:
            raise ValueError(f"hunt task packet {task_id} exceeds {limit} bytes")
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_bytes(rendered)
        temporary.replace(path)
    for path in directory.glob("*.json"):
        if path.name not in expected:
            path.unlink()


def class_map(root: Path, threat: dict) -> dict[str, dict]:
    taxonomy = load(root / "config/attack-taxonomy-v2.json", {})
    known = {
        str(item["id"]): item
        for item in taxonomy.get("classes", [])
        if isinstance(item, dict) and item.get("id")
    }
    return {
        str(item["id"]): {**known.get(str(item["id"]), {}), **item}
        for item in threat.get("attack_classes", [])
        if isinstance(item, dict) and item.get("id")
    }


def cell_from_mapping(mapping: dict, attack_class: dict, scan: Path) -> dict:
    owner = str(attack_class.get("owner", "sast"))
    status = "planned"
    reason = "scheduled from a source-backed contextual hunt mapping"
    evidence = unique([*mapping.get("evidence_refs", []), *attack_class.get("evidence_refs", [])])
    if owner in {"sca", "secrets"}:
        if phase_status(scan, "tool-collection") == "ok":
            status = "tool_satisfied"
            reason = f"owned by validated {owner.upper()} collection; SAST will not repeat enumeration"
            evidence.append("tool-collection/phase-manifest.json")
        else:
            status = "deferred"
            reason = f"owning {owner.upper()} collection did not provide validated evidence"
    return {
        "id": f"CELL-{slug(str(mapping['id']))}",
        "mapping_id": str(mapping["id"]),
        "objective_id": mapping["objective_id"],
        "question_id": mapping["question_id"],
        "surface_ids": unique([str(item) for item in mapping.get("surface_ids", [])]),
        "subsystem": str(mapping["subsystem_id"]),
        "attack_class_id": str(mapping["attack_class_id"]),
        "domain": str(attack_class.get("domain", "general")),
        "methodology_refs": methodology_refs(attack_class),
        "lenses": specialist_lenses(attack_class),
        "status": status,
        "priority": str(mapping.get("priority", "medium")),
        "threat_ids": unique([str(item) for item in mapping.get("threat_ids", [])]),
        "asset_ids": unique([str(item) for item in mapping.get("asset_ids", [])]),
        "attacker": str(mapping.get("attacker", "")),
        "entrypoint_ids": unique([str(item) for item in mapping.get("entrypoint_ids", [])]),
        "boundary_ids": unique([str(item) for item in mapping.get("boundary_ids", [])]),
        "files": unique([str(item) for item in mapping.get("source_files", [])]),
        "security_question": str(mapping.get("security_question", "")),
        "stop_conditions": [str(item) for item in mapping.get("stop_conditions", [])],
        "applicability_reason": str(mapping.get("applicability_reason", "")),
        "evidence_refs": unique(evidence),
        "owner": owner,
        "lead_key": None,
        "disposition_reason": reason,
    }


def cells_compatible(batch: list[dict], candidate: dict) -> bool:
    if not batch:
        return True
    if (candidate["subsystem"] != batch[0]["subsystem"] or candidate["domain"] != batch[0]["domain"]
            or candidate.get("attacker") != batch[0].get("attacker")):
        return False
    if candidate["attack_class_id"] in {cell["attack_class_id"] for cell in batch}:
        return False
    files = {item for cell in batch for item in cell.get("files", [])}
    flow = {
        item
        for cell in batch
        for key in ("surface_ids", "entrypoint_ids", "boundary_ids")
        for item in cell.get(key, [])
    }
    candidate_flow = {
        item
        for key in ("surface_ids", "entrypoint_ids", "boundary_ids")
        for item in candidate.get(key, [])
    }
    return bool(files.intersection(candidate.get("files", []))) and bool(flow.intersection(candidate_flow))


def contextual_batches(cells: list[dict]) -> list[list[dict]]:
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for cell in cells:
        groups[(cell["subsystem"], str(cell.get("attacker", "")), cell["domain"])].append(cell)
    queues: dict[tuple[str, str], list[list[dict]]] = defaultdict(list)
    for (subsystem, actor, _domain), group in sorted(groups.items()):
        remaining = sorted(group, key=lambda cell: (RISK_ORDER.get(cell["priority"], 9), cell["id"]))
        batches: list[list[dict]] = []
        while remaining:
            batch = [remaining.pop(0)]
            for candidate in list(remaining):
                if len(batch) >= 4:
                    break
                if cells_compatible(batch, candidate):
                    batch.append(candidate)
                    remaining.remove(candidate)
            batches.append(batch)
        queues[(subsystem, actor)].extend(batches)
    for subsystem in queues:
        queues[subsystem].sort(key=lambda batch: (min(RISK_ORDER.get(cell["priority"], 9) for cell in batch), batch[0]["id"]))
    ordered: list[list[dict]] = []
    while any(queues.values()):
        active = sorted(
            (subsystem for subsystem, queue in queues.items() if queue),
            key=lambda subsystem: (
                min(RISK_ORDER.get(cell["priority"], 9) for cell in queues[subsystem][0]),
                subsystem,
            ),
        )
        for subsystem in active:
            ordered.append(queues[subsystem].pop(0))
    return ordered


def make_task(task_id: str, batch: list[dict], attempt: int, round_number: int) -> dict:
    return {
        "id": task_id,
        "objective_ids": unique([cell["objective_id"] for cell in batch]),
        "question_ids": unique([cell["question_id"] for cell in batch]),
        "cell_ids": [cell["id"] for cell in batch],
        "subsystem": batch[0]["subsystem"],
        "attack_class_ids": unique([cell["attack_class_id"] for cell in batch]),
        "domain": batch[0]["domain"],
        "methodology_refs": unique([ref for cell in batch for ref in cell["methodology_refs"]]),
        "lenses": unique([lens for cell in batch for lens in cell["lenses"]]),
        "files": unique([path for cell in batch for path in cell["files"]]),
        "entrypoints": unique([entrypoint for cell in batch for entrypoint in cell["entrypoint_ids"]]),
        "evidence_refs": unique([ref for cell in batch for ref in cell["evidence_refs"]]),
        "attempt": attempt,
        "round": round_number,
    }


def initial_plan(root: Path, scan: Path, context: dict, threat: dict) -> dict:
    objectives, questions = validate_registry(threat["attack_objectives"], threat["investigation_questions"],
        scan=scan, target=context.get("source_root") or context.get("repo_path"), repositories=context.get("repositories"))
    if any(row["owner"] != "sast/threat-model.json" for row in [*objectives.values(), *questions.values()]):
        raise ValueError("initial objectives/questions require ThreatModel ownership")
    limits = budget(str(context.get("depth", "quick")), context)
    classes = class_map(root, threat)
    cells: list[dict] = []
    custom: list[dict] = []
    seen_cell_ids: set[str] = set()
    for item in threat.get("attack_classes", []):
        if isinstance(item, dict) and item.get("custom"):
            custom.append({
                "id": str(item["id"]),
                "title": str(item["title"]),
                "methodology": str(item.get("reason", "Repository-specific attack methodology")),
                "evidence_refs": list(item.get("evidence_refs", [])),
            })
    mappings = sorted(
        (item for item in threat.get("hunt_mappings", []) if isinstance(item, dict)),
        key=lambda item: (
            RISK_ORDER.get(str(item.get("priority")), 9),
            str(item.get("subsystem_id")),
            str(item.get("attack_class_id")),
            str(item.get("id")),
        ),
    )
    for mapping in mappings:
        validate_binding(mapping, objectives, questions)
        if questions[mapping["question_id"]].get("equivalent_to"):
            raise ValueError("equivalent questions cannot acquire duplicate hunt ownership")
        if mapping["security_question"] != questions[mapping["question_id"]]["security_question"]:
            raise ValueError("mapping question differs from its registered proof obligation")
        if any(cell["question_id"] == mapping["question_id"] for cell in cells):
            raise ValueError("duplicate hunt question ownership")
        attack_class = classes.get(str(mapping.get("attack_class_id")))
        if attack_class is None:
            raise ValueError(f"hunt mapping {mapping.get('id')} references unknown attack class")
        cell = cell_from_mapping(mapping, attack_class, scan)
        if cell["id"] in seen_cell_ids:
            raise ValueError(f"hunt mapping IDs collide after normalization: {mapping.get('id')}")
        seen_cell_ids.add(cell["id"])
        cells.append(cell)

    schedulable = [cell for cell in cells if cell["owner"] == "sast" and cell["status"] == "planned"]
    reserve = max(1, limits["max_hunt_tasks"] // 4) if limits["max_gapfill_rounds"] else 0
    initial_cap = max(1, limits["max_hunt_tasks"] - reserve)
    batches = contextual_batches(schedulable)
    tasks: list[dict] = []
    scheduled_questions = 0
    for batch in batches:
        remaining_questions = limits["max_hunt_questions"] - scheduled_questions
        if len(tasks) >= initial_cap or remaining_questions <= 0:
            for cell in batch:
                cell["status"] = "deferred"
                cell["disposition_reason"] = "initial contextual hunt budget exhausted; eligible only after evidence-driven gapfill"
            continue
        selected_batch = batch[:remaining_questions]
        for cell in batch[remaining_questions:]:
            cell["status"] = "deferred"
            cell["disposition_reason"] = "initial contextual hunt-question budget exhausted; eligible only after evidence-driven gapfill"
        task_id = f"H{len(tasks) + 1:03d}-{slug(batch[0]['subsystem'])}"
        tasks.append(make_task(task_id, selected_batch, 1, 0))
        scheduled_questions += len(selected_batch)

    return {
        "schema_version": "2.0",
        "run_id": context["run_id"],
        "attack_objectives": list(objectives.values()),
        "investigation_questions": list(questions.values()),
        "rationale": "Source-backed hunt mappings are fairly scheduled and batched only when their code flow and specialist context overlap.",
        "budget": limits,
        "custom_attack_classes": custom,
        "cells": cells,
        "tasks": tasks,
        "warnings": [],
        "errors": [],
    }


def rabbit_cell(rabbit: dict, attack_class: dict, lead_key: str) -> dict:
    return {
        "id": f"CELL-RABBIT-{lead_key}",
        "mapping_id": f"RABBIT-{lead_key}",
        "objective_id": rabbit["objective_id"],
        "question_id": rabbit["question_id"],
        "surface_ids": unique([str(item) for item in rabbit.get("surface_ids", [])]),
        "subsystem": str(rabbit["subsystem"]),
        "attack_class_id": str(rabbit["attack_class_id"]),
        "domain": str(attack_class.get("domain", "general")),
        "methodology_refs": methodology_refs(attack_class),
        "lenses": specialist_lenses(attack_class),
        "status": "deferred",
        "priority": str(rabbit.get("priority", "medium")),
        "threat_ids": unique([str(item) for item in rabbit.get("threat_ids", [])]),
        "asset_ids": unique([str(item) for item in rabbit.get("asset_ids", [])]),
        "attacker": str(rabbit.get("attacker", "")),
        "entrypoint_ids": unique([str(item) for item in rabbit.get("entrypoint_ids", [])]),
        "boundary_ids": unique([str(item) for item in rabbit.get("boundary_ids", [])]),
        "files": unique([str(item) for item in rabbit.get("files", [])]),
        "security_question": str(rabbit.get("security_question", "")),
        "stop_conditions": [str(item) for item in rabbit.get("stop_conditions", [])],
        "applicability_reason": str(rabbit.get("reason", "")),
        "evidence_refs": unique([str(item) for item in rabbit.get("evidence_refs", [])]),
        "owner": "sast",
        "lead_key": lead_key,
        "disposition_reason": f"evidence-backed rabbit hole awaiting gapfill: {rabbit.get('expected_added_value', '')}",
    }


def gapfill(root: Path, plan: dict, scan: Path, threat: dict) -> dict:
    ledger = load(scan / "sast/coverage-ledger.json", {})
    if not isinstance(ledger, dict):
        return plan
    limits = plan["budget"]
    current_round = max((int(task.get("round", 0)) for task in plan.get("tasks", [])), default=0)
    next_round = current_round + 1
    classes = class_map(root, threat)
    cells_by_id = {str(cell["id"]): cell for cell in plan.get("cells", []) if isinstance(cell, dict)}
    existing_leads = {str(cell.get("lead_key")) for cell in cells_by_id.values() if cell.get("lead_key")}
    valid_tasks = {str(row["id"]) for row in ledger.get("tasks", []) if row.get("artifact_valid") or row.get("status") in {"ok", "shallow"}}
    checkpoints: dict[str, dict] = {}
    amendments = {item["id"]: item for item in plan.get("model_amendments", [])}
    objectives, questions = validate_registry(plan["attack_objectives"], plan["investigation_questions"])
    for task in plan["tasks"]:
        if task["id"] not in valid_tasks:
            continue
        result_ref = f"sast/deepdive/{task['id']}.json"
        result = load(scan / result_ref, {})
        for amendment in result.get("model_amendments", []):
            if amendment["id"] in amendments and amendments[amendment["id"]] != amendment:
                raise ValueError("conflicting phase-local model amendment")
            amendments[amendment["id"]] = amendment
        additions = result.get("model_amendments", [])
        objectives, questions = validate_registry(
            [item["entity"] for item in additions if item["kind"] == "objective"],
            [item["entity"] for item in additions if item["kind"] == "question"],
            inherited_objectives=objectives, inherited_questions=questions)
        for row in result.get("cell_results", []):
            checkpoints[row["cell_id"]] = {
                "cell_id": row["cell_id"], "resolution": row["resolution"], "checkpoint": row["checkpoint"],
                "objective_id": row["objective_id"], "question_id": row["question_id"],
                "source_expansions": row["source_expansions"], "evidence_refs": unique([*row["evidence_refs"], result_ref]),
            }
        for rabbit in result.get("rabbit_holes", []):
            if rabbit.get("attack_class_id") not in classes:
                continue
            validate_binding(rabbit, objectives, questions)
            if any(cell["question_id"] == rabbit["question_id"] for cell in cells_by_id.values()):
                continue
            material = "\0".join((rabbit["objective_id"], rabbit["question_id"]))
            lead_key = hashlib.sha256(material.encode()).hexdigest()[:16]
            if lead_key in existing_leads:
                continue
            copied = dict(rabbit)
            copied["evidence_refs"] = unique([*rabbit["evidence_refs"], result_ref])
            cell = rabbit_cell(copied, classes[rabbit["attack_class_id"]], lead_key)
            plan["cells"].append(cell)
            cells_by_id[cell["id"]] = cell
            existing_leads.add(lead_key)
    plan["model_amendments"] = list(amendments.values())
    plan["attack_objectives"] = list(objectives.values())
    plan["investigation_questions"] = list(questions.values())
    ledger_rows = {row["id"]: row for row in ledger.get("cells", [])}
    # Aggregate resolutions include local evidence gaps absent from the sealed worker's conclusion.
    for cell_id, row in ledger_rows.items():
        if cell_id in checkpoints and row.get("resolution"):
            checkpoints[cell_id]["resolution"] = row["resolution"]
            checkpoints[cell_id]["checkpoint"] = row["checkpoint"]
    attempts = {cell_id: sum(cell_id in task["cell_ids"] for task in plan["tasks"]) for cell_id in cells_by_id}

    def priority(cell: dict) -> tuple:
        checkpoint = checkpoints.get(cell["id"], {}).get("checkpoint", {})
        concrete = bool(checkpoint.get("next_step") and checkpoint.get("established_facts"))
        return (RISK_ORDER.get(cell.get("priority"), 9), not concrete,
                attempts[cell["id"]] > 1, cell["subsystem"], cell["attacker"], cell["id"])

    eligible = []
    for cell_id, cell in cells_by_id.items():
        if cell.get("owner") != "sast":
            continue
        outcome = checkpoints.get(cell_id, {}).get("resolution", {}).get("outcome")
        if outcome in {"established", "contradicted", "externally_blocked"}:
            continue
        if attempts[cell_id] >= limits["max_attempts"]:
            cell["disposition_reason"] = "budget deferred: per-question attempt ceiling exhausted"
            continue
        if outcome in {"locally_unresolved", "budget_deferred", "execution_failed"} or (
                ledger_rows.get(cell_id, {}).get("status") == "failed") or (
                cell.get("status") == "deferred"):
            eligible.append(cell)
    # Rank all demand together, then batch compatible questions rather than fragmenting continuations.
    batches = contextual_batches(sorted(eligible, key=priority))
    batches.sort(key=lambda batch: min(priority(cell)[:3] for cell in batch))
    question_count = sum(len(task["cell_ids"]) for task in plan["tasks"])
    for batch in batches:
        available = limits["max_hunt_questions"] - question_count
        if current_round >= limits["max_gapfill_rounds"] or len(plan["tasks"]) >= limits["max_hunt_tasks"] or available <= 0:
            for cell in batch:
                ceiling = ("gapfill-round" if current_round >= limits["max_gapfill_rounds"] else
                           "hunt-task" if len(plan["tasks"]) >= limits["max_hunt_tasks"] else "hunt-question")
                cell["disposition_reason"] = (
                    f"budget deferred: {ceiling} ceiling exhausted; priority={cell['priority']}; "
                    "higher-ranked risk/fairness obligations consumed the finite allocation")
            continue
        selected = batch[:available]
        task_id = f"H{len(plan['tasks']) + 1:03d}-{slug(selected[0]['subsystem'])}-g{next_round}"
        task = make_task(task_id, selected, max(attempts[cell["id"]] for cell in selected) + 1, next_round)
        task["continuations"] = [checkpoints[cell["id"]] for cell in selected if cell["id"] in checkpoints]
        plan["tasks"].append(task)
        question_count += len(selected)
        for cell in selected:
            cell["status"] = "planned"
            cell["disposition_reason"] = "selected by impact, established evidence, concrete next step, and diminishing retry value"
        for cell in batch[available:]:
            cell["disposition_reason"] = "budget deferred: hunt-question ceiling exhausted"
    return plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_path", type=Path)
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("--gapfill", action="store_true")
    parser.add_argument("--context", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    context = load(args.context or root / ".harness/audit-context.json", {})
    threat = load(args.scan_base / "sast/threat-model.json", {})
    if not isinstance(context, dict) or not isinstance(threat, dict):
        raise SystemExit("missing audit context or threat model")
    output = args.scan_base / "sast/hunt-plan.json"
    existing = output.is_file()
    prior_ids = set()
    prior_tasks = load(args.scan_base / "sast/coverage-ledger.json", {}).get("tasks", [])
    accepted = {row["id"] for row in prior_tasks if row.get("artifact_valid")}
    historical_reservations = set()
    if existing:
        plan = load(output, {})
        if not isinstance(plan, dict) or "tasks" not in plan:
            raise SystemExit("missing hunt plan")
        prior_ids = {task["id"] for task in plan["tasks"]}
        plan["budget"] = budget(context["depth"], context)
        plan["depth"] = context["depth"]
        historical_reservations = {task["id"] for task in plan["tasks"]
                                   if context.get("attempt_id") and task.get("attempt_id") != context["attempt_id"]}
        interrupted_cells = {cell_id for task in plan["tasks"]
                             if task["id"] in historical_reservations - accepted for cell_id in task["cell_ids"]}
        for cell in plan["cells"]:
            if cell["id"] in interrupted_cells:
                cell["status"] = "deferred"
                cell["disposition_reason"] = "Interrupted reserved attempt; further work requires remaining allocation."
        if args.gapfill:
            plan = gapfill(root, plan, args.scan_base, threat)
    elif args.gapfill:
        raise SystemExit("missing hunt plan")
    else:
        plan = initial_plan(root, args.scan_base, context, threat)
    if context.get("attempt_id"):
        for task in plan["tasks"]:
            if task["id"] not in prior_ids:
                task["attempt_id"] = context["attempt_id"]
    consumed_ids = historical_reservations | {row["id"] for row in prior_tasks if row.get("status") != "deferred"}
    consumed = [task for task in plan["tasks"] if task["id"] in consumed_ids]
    tasks_left = max(0, plan["budget"]["max_hunt_tasks"] - len(consumed))
    questions_left = max(0, plan["budget"]["max_hunt_questions"] - sum(len(task["cell_ids"]) for task in consumed))
    plan["deferred_task_ids"] = []
    for task in plan["tasks"]:
        if task["id"] in accepted:
            continue
        if task["id"] in historical_reservations or tasks_left <= 0 or len(task["cell_ids"]) > questions_left:
            plan["deferred_task_ids"].append(task["id"])
        else:
            tasks_left -= 1
            questions_left -= len(task["cell_ids"])
    active_cells = {cell_id for task in plan["tasks"] if task["id"] not in plan["deferred_task_ids"]
                    for cell_id in task["cell_ids"]}
    deferred_cells = {cell_id for task in plan["tasks"] if task["id"] in plan["deferred_task_ids"]
                      for cell_id in task["cell_ids"]}
    for cell in plan["cells"]:
        if cell["id"] in deferred_cells - active_cells:
            cell["status"] = "deferred"
            cell["disposition_reason"] = "budget deferred: retained reserved attempts consume the current allocation"
    rendered = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_bytes(rendered)
    temporary.replace(output)
    publish_task_packets(args.scan_base, plan, rendered)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
