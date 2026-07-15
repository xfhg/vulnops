#!/usr/bin/env python3
"""Build or gapfill the bounded, contextual VulnOps v2 SAST hunt plan."""

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
        packet = {
            "schema_version": "2.0",
            "run_id": str(plan.get("run_id", "")),
            "hunt_plan_ref": "sast/hunt-plan.json",
            "hunt_plan_sha256": digest,
            "task": task,
            "cells": [cell_map[str(cell_id)] for cell_id in task.get("cell_ids", [])],
        }
        rendered = (json.dumps(packet, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(rendered) > limit:
            raise ValueError(f"hunt task packet {task_id} exceeds {limit} bytes")
        path = directory / f"{task_id}.json"
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
    if candidate["subsystem"] != batch[0]["subsystem"] or candidate["domain"] != batch[0]["domain"]:
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
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for cell in cells:
        groups[(cell["subsystem"], cell["domain"])].append(cell)
    queues: dict[str, list[list[dict]]] = defaultdict(list)
    for (subsystem, _domain), group in sorted(groups.items()):
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
        queues[subsystem].extend(batches)
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
    scheduling_allowed = current_round < limits["max_gapfill_rounds"]
    next_round = current_round + 1
    classes = class_map(root, threat)
    cells_by_id = {str(cell["id"]): cell for cell in plan.get("cells", []) if isinstance(cell, dict)}
    existing_leads = {str(cell.get("lead_key")) for cell in cells_by_id.values() if cell.get("lead_key")}
    ledger_task_status = {
        str(row.get("id")): str(row.get("status"))
        for row in ledger.get("tasks", [])
        if isinstance(row, dict) and row.get("id")
    }
    task_count = len(plan["tasks"])
    question_count = sum(len(task.get("cell_ids", [])) for task in plan["tasks"])
    scheduled: set[str] = set()

    def schedule(cell: dict, attempt: int, marker: str) -> bool:
        nonlocal task_count, question_count
        if not scheduling_allowed or task_count >= limits["max_hunt_tasks"] or question_count >= limits["max_hunt_questions"]:
            return False
        task_count += 1
        question_count += 1
        cell["status"] = "planned"
        cell["disposition_reason"] = marker
        task_id = f"H{task_count:03d}-{slug(cell['subsystem'])}-{slug(cell['attack_class_id'])}-g{next_round}"
        plan["tasks"].append(make_task(task_id, [cell], attempt, next_round))
        scheduled.add(cell["id"])
        return True

    rabbit_candidates: list[tuple[dict, str]] = []
    for result_path in sorted((scan / "sast/deepdive").glob("*.json")):
        if ledger_task_status.get(result_path.stem) not in {"ok", "shallow"}:
            continue
        result = load(result_path, {})
        if not isinstance(result, dict):
            continue
        for rabbit in result.get("rabbit_holes", []):
            if not isinstance(rabbit, dict):
                continue
            subsystem = str(rabbit.get("subsystem", ""))
            attack_id = str(rabbit.get("attack_class_id", ""))
            if attack_id not in classes:
                continue
            material = "\0".join([
                subsystem,
                attack_id,
                *sorted(str(item) for item in rabbit.get("surface_ids", [])),
                *sorted(str(item) for item in rabbit.get("files", [])),
                str(rabbit.get("security_question", "")).strip().casefold(),
            ])
            lead_key = hashlib.sha256(material.encode()).hexdigest()[:16]
            if lead_key in existing_leads:
                continue
            copied = dict(rabbit)
            copied["evidence_refs"] = unique([*rabbit.get("evidence_refs", []), str(result_path.relative_to(scan))])
            rabbit_candidates.append((copied, lead_key))
            existing_leads.add(lead_key)
    rabbit_candidates.sort(key=lambda item: (RISK_ORDER.get(str(item[0].get("priority")), 9), item[1]))
    for rabbit, lead_key in rabbit_candidates:
        cell = rabbit_cell(rabbit, classes[str(rabbit["attack_class_id"])], lead_key)
        plan["cells"].append(cell)
        cells_by_id[cell["id"]] = cell
        if not schedule(cell, 1, "scheduled from an evidence-backed rabbit hole"):
            cell["disposition_reason"] = "evidence-backed rabbit hole deferred because the total hunt-task budget is exhausted"

    ledger_rows = {
        str(row.get("id")): row
        for row in ledger.get("cells", [])
        if isinstance(row, dict) and row.get("id")
    }
    retry_cells = sorted(
        (
            cell for cell_id, cell in cells_by_id.items()
            if cell.get("owner") == "sast"
            and cell_id not in scheduled
            and (ledger_rows.get(cell_id) or {}).get("status") in {"shallow", "failed"}
        ),
        key=lambda cell: (RISK_ORDER.get(cell.get("priority"), 9), cell["id"]),
    )
    for cell in retry_cells:
        attempts = sum(1 for task in plan["tasks"] if cell["id"] in task.get("cell_ids", []))
        if attempts >= limits["max_attempts"]:
            continue
        if not schedule(cell, attempts + 1, "requeued after a cell-specific shallow or failed disposition"):
            break

    deferred_cells = sorted(
        (
            cell for cell in cells_by_id.values()
            if cell.get("owner") == "sast"
            and cell["id"] not in scheduled
            and cell.get("status") == "deferred"
            and str(cell.get("disposition_reason", "")).startswith("initial contextual hunt budget exhausted")
        ),
        key=lambda cell: (RISK_ORDER.get(cell.get("priority"), 9), cell["subsystem"], cell["id"]),
    )
    for cell in deferred_cells:
        if not schedule(cell, 1, "scheduled after evidence-driven gapfill demand was satisfied"):
            break
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
    if args.gapfill:
        plan = load(output, {})
        if not isinstance(plan, dict):
            raise SystemExit("missing hunt plan")
        plan = gapfill(root, plan, args.scan_base, threat)
    else:
        plan = initial_plan(root, args.scan_base, context, threat)
    rendered = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_bytes(rendered)
    temporary.replace(output)
    publish_task_packets(args.scan_base, plan, rendered)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
