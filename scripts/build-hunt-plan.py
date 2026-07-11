#!/usr/bin/env python3
"""Build or gapfill the bounded VulnOps v2 area x attack-class hunt plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path


DEFAULTS = {
    "quick": {"max_concurrency": 4, "max_hunt_tasks": 12, "max_gapfill_rounds": 1, "max_attempts": 2},
    "balanced": {"max_concurrency": 8, "max_hunt_tasks": 32, "max_gapfill_rounds": 2, "max_attempts": 2},
    "full": {"max_concurrency": 16, "max_hunt_tasks": 64, "max_gapfill_rounds": 3, "max_attempts": 2},
}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
def load(path: Path, fallback: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"


def phase_status(scan: Path, name: str) -> str:
    doc = load(scan / name / "phase-manifest.json", {})
    return str(doc.get("status", "missing")) if isinstance(doc, dict) else "missing"


def budget(depth: str) -> dict[str, int]:
    defaults = DEFAULTS[depth]
    prefix = f"VULNOPS_SAST_{depth.upper()}"
    return {
        "max_concurrency": defaults["max_concurrency"],
        "max_hunt_tasks": int(os.environ.get(f"{prefix}_MAX_HUNT_TASKS", defaults["max_hunt_tasks"])),
        "max_gapfill_rounds": int(os.environ.get(f"{prefix}_MAX_GAPFILL_ROUNDS", defaults["max_gapfill_rounds"])),
        "max_attempts": int(os.environ.get(f"{prefix}_MAX_ATTEMPTS", defaults["max_attempts"])),
        "context_packet_bytes": int(os.environ.get("VULNOPS_SAST_CONTEXT_PACKET_BYTES", "65536")),
    }


def context_packet(threat: dict, subsystem: dict, attack_class: dict, scan: Path, limit: int) -> str:
    packet = {
        "repository_profile": threat.get("repository_profile", {}),
        "subsystem": subsystem,
        "attack_class": attack_class,
        "trust_boundaries": threat.get("trust_boundaries", []),
        "entrypoints": threat.get("entrypoints", []),
        "sca_evidence_ref": "tool-collection/sca-advisories.json" if (scan / "tool-collection/sca-advisories.json").is_file() else None,
        "secrets_evidence_ref": "tool-collection/secrets-redacted.json" if (scan / "tool-collection/secrets-redacted.json").is_file() else None,
        "instructions": "Use the assigned VulnOps attack class and evidence gate. Return rabbit holes; do not repeat SCA or secret enumeration.",
    }
    rendered = json.dumps(packet, sort_keys=True, separators=(",", ":"))
    if len(rendered.encode("utf-8")) > limit:
        packet["trust_boundaries"] = []
        packet["entrypoints"] = []
        packet["context_truncated"] = True
        rendered = json.dumps(packet, sort_keys=True, separators=(",", ":"))
    if len(rendered.encode("utf-8")) > limit:
        raise ValueError(f"context packet for {subsystem.get('id')} exceeds {limit} bytes")
    return rendered


def methodology_refs(attack_class: dict) -> list[str]:
    refs = [str(attack_class.get("methodology_ref", "skill://vulnops-audit-core"))]
    if "skill://vulnops-audit-core" not in refs:
        refs.append("skill://vulnops-audit-core")
    return list(dict.fromkeys(refs))


def specialist_lenses(attack_class: dict) -> list[str]:
    return [str(item) for item in attack_class.get("lenses", []) if str(item)]


def initial_plan(root: Path, scan: Path, context: dict, threat: dict) -> dict:
    depth = str(context.get("depth", "quick"))
    limits = budget(depth)
    taxonomy = load(root / "config/attack-taxonomy-v2.json", {})
    known = {item["id"]: item for item in taxonomy.get("classes", []) if isinstance(item, dict) and item.get("id")}
    subsystems = {item["id"]: item for item in threat.get("subsystems", []) if isinstance(item, dict) and item.get("id")}
    cells: list[dict] = []
    custom: list[dict] = []
    selected: list[tuple[dict, dict]] = []

    for item in threat.get("attack_classes", []):
        if not isinstance(item, dict):
            continue
        base = known.get(item.get("id"), {})
        attack_class = {**base, **item}
        if item.get("custom"):
            custom.append({
                "id": str(item["id"]),
                "title": str(item["title"]),
                "methodology": str(item.get("reason", "Repository-specific attack methodology")),
                "evidence_refs": list(item.get("evidence_refs", [])),
            })
        for subsystem_id in item.get("applicable_subsystems", []):
            subsystem = subsystems.get(subsystem_id)
            if subsystem is not None:
                selected.append((subsystem, attack_class))

    selected.sort(key=lambda pair: (RISK_ORDER.get(pair[0].get("risk"), 9), str(pair[0].get("id")), str(pair[1].get("id"))))
    for subsystem, attack_class in selected:
        owner = str(attack_class.get("owner", "sast"))
        surface_ids = subsystem.get("security_surface_ids") or [subsystem["id"]]
        for surface_id in surface_ids:
            status = "planned"
            reason = "scheduled for focused SAST hunting"
            evidence = list(dict.fromkeys([*subsystem.get("evidence_refs", []), *attack_class.get("evidence_refs", [])]))
            if owner in {"sca", "secrets"}:
                tool_status = phase_status(scan, "tool-collection")
                if tool_status in {"ok", "degraded"}:
                    status = "tool_satisfied"
                    reason = f"owned by validated {owner.upper()} phase; SAST will not repeat enumeration"
                    evidence.append("tool-collection/phase-manifest.json")
                else:
                    status = "deferred"
                    reason = f"owning {owner.upper()} phase did not provide usable evidence"
            cells.append({
                "id": f"CELL-{slug(str(surface_id))}-{slug(str(attack_class['id']))}",
                "surface_id": str(surface_id),
                "subsystem": str(subsystem["id"]),
                "attack_class_id": str(attack_class["id"]),
                "domain": str(attack_class.get("domain", "general")),
                "status": status,
                "priority": str(subsystem.get("risk", "medium")),
                "evidence_refs": evidence,
                "owner": owner,
                "lead_key": None,
                "disposition_reason": reason,
            })

    tasks: list[dict] = []
    schedulable = [cell for cell in cells if cell["owner"] == "sast" and cell["status"] == "planned"]
    reserve = max(1, limits["max_hunt_tasks"] // 4) if limits["max_gapfill_rounds"] else 0
    initial_cap = max(1, limits["max_hunt_tasks"] - reserve)
    grouped: dict[str, list[dict]] = {}
    for cell in schedulable:
        grouped.setdefault(cell["subsystem"], []).append(cell)
    batches: list[tuple[str, list[dict]]] = []
    for subsystem_id, group in grouped.items():
        ordered = sorted(group, key=lambda item: (RISK_ORDER.get(item["priority"], 9), item["attack_class_id"], item["id"]))
        batches.extend((subsystem_id, ordered[index:index + 4]) for index in range(0, len(ordered), 4))
    for index, (subsystem_id, batch) in enumerate(batches, start=1):
        if len(tasks) >= initial_cap:
            for cell in batch:
                cell["status"] = "deferred"
                cell["disposition_reason"] = "reserved single-run budget for high-risk gapfill"
            continue
        subsystem = subsystems[subsystem_id]
        attack_classes = [next(item for sub, item in selected if sub["id"] == subsystem_id and item["id"] == cell["attack_class_id"]) for cell in batch]
        primary_class = attack_classes[0]
        tasks.append({
            "id": f"H{index:03d}-{slug(subsystem_id)}",
            "cell_ids": [cell["id"] for cell in batch],
            "subsystem": subsystem_id,
            "attack_class_ids": [cell["attack_class_id"] for cell in batch],
            "domain": primary_class.get("domain", "general"),
            "methodology_refs": list(dict.fromkeys(ref for item in attack_classes for ref in methodology_refs(item))),
            "lenses": list(dict.fromkeys(lens for item in attack_classes for lens in specialist_lenses(item))),
            "files": subsystem["files"],
            "entrypoints": subsystem.get("entrypoints", []),
            "context_packet": context_packet(threat, subsystem, {"id": "+".join(cell["attack_class_id"] for cell in batch), "title": "Batched compatible attack classes", "evidence_refs": []}, scan, limits["context_packet_bytes"]),
            "evidence_refs": list(dict.fromkeys([*subsystem.get("evidence_refs", []), *(ref for item in attack_classes for ref in item.get("evidence_refs", []))])),
            "attempt": 1,
            "round": 0,
        })

    return {
        "schema_version": "2.0",
        "run_id": context["run_id"],
        "rationale": "Risk-prioritized subsystem plan batching up to four compatible attack classes; tool-owned enumeration is not repeated by SAST.",
        "budget": limits,
        "custom_attack_classes": custom,
        "cells": cells,
        "tasks": tasks,
        "warnings": [],
        "errors": [],
    }


def gapfill(root: Path, plan: dict, scan: Path, threat: dict) -> dict:
    ledger = load(scan / "sast/coverage-ledger.json", {})
    if not isinstance(ledger, dict):
        return plan
    current_round = max((int(task.get("round", 0)) for task in plan.get("tasks", [])), default=0)
    limits = plan["budget"]
    if current_round >= limits["max_gapfill_rounds"] or len(plan["tasks"]) >= limits["max_hunt_tasks"]:
        return plan
    cells_by_id = {cell["id"]: cell for cell in plan.get("cells", [])}
    subsystem_map = {item["id"]: item for item in threat.get("subsystems", [])}
    taxonomy = load(root / "config/attack-taxonomy-v2.json", {})
    known_classes = {item["id"]: item for item in taxonomy.get("classes", []) if isinstance(item, dict) and item.get("id")}
    class_map = {
        item["id"]: {**known_classes.get(item["id"], {}), **item}
        for item in threat.get("attack_classes", [])
        if isinstance(item, dict) and item.get("id")
    }
    task_count = len(plan["tasks"])

    # Spend the deliberately reserved budget on the highest-risk cells that
    # did not fit in the initial wave. This is part of gapfill, not dead work.
    deferred_cells = sorted(
        (
            cell for cell in plan.get("cells", [])
            if cell.get("owner") == "sast"
            and cell.get("status") == "deferred"
            and cell.get("disposition_reason") == "reserved single-run budget for high-risk gapfill"
        ),
        key=lambda cell: (RISK_ORDER.get(cell.get("priority"), 9), str(cell.get("id"))),
    )
    for cell in deferred_cells:
        if task_count >= limits["max_hunt_tasks"]:
            break
        subsystem = subsystem_map[cell["subsystem"]]
        attack_class = class_map[cell["attack_class_id"]]
        task_count += 1
        plan["tasks"].append({
            "id": f"H{task_count:03d}-{slug(cell['subsystem'])}-{slug(cell['attack_class_id'])}-g{current_round + 1}",
            "cell_ids": [cell["id"]],
            "subsystem": cell["subsystem"],
            "attack_class_ids": [cell["attack_class_id"]],
            "domain": cell["domain"],
            "methodology_refs": methodology_refs(attack_class),
            "lenses": specialist_lenses(attack_class),
            "files": subsystem["files"],
            "entrypoints": subsystem.get("entrypoints", []),
            "context_packet": context_packet(threat, subsystem, attack_class, scan, limits["context_packet_bytes"]),
            "evidence_refs": list(dict.fromkeys([*cell.get("evidence_refs", []), "sast/coverage-ledger.json"])),
            "attempt": 1,
            "round": current_round + 1,
        })
        cell["status"] = "planned"
        cell["disposition_reason"] = "scheduled from reserved high-risk gapfill budget"
    for row in ledger.get("cells", []):
        cell = cells_by_id.get(row.get("id")) if isinstance(row, dict) else None
        if not cell or cell.get("owner") != "sast" or row.get("status") not in {"shallow", "failed"}:
            continue
        if cell.get("priority") not in {"critical", "high", "medium"}:
            continue
        if task_count >= limits["max_hunt_tasks"]:
            break
        attempts = sum(1 for task in plan["tasks"] if cell["id"] in task.get("cell_ids", []))
        if attempts >= limits["max_attempts"]:
            continue
        subsystem = subsystem_map[cell["subsystem"]]
        attack_class = class_map[cell["attack_class_id"]]
        task_count += 1
        plan["tasks"].append({
            "id": f"H{task_count:03d}-{slug(cell['subsystem'])}-{slug(cell['attack_class_id'])}-g{current_round + 1}",
            "cell_ids": [cell["id"]],
            "subsystem": cell["subsystem"],
            "attack_class_ids": [cell["attack_class_id"]],
            "domain": cell["domain"],
            "methodology_refs": methodology_refs(attack_class),
            "lenses": specialist_lenses(attack_class),
            "files": subsystem["files"],
            "entrypoints": subsystem.get("entrypoints", []),
            "context_packet": context_packet(threat, subsystem, attack_class, scan, limits["context_packet_bytes"]),
            "evidence_refs": list(dict.fromkeys([*cell.get("evidence_refs", []), "sast/coverage-ledger.json"])),
            "attempt": attempts + 1,
            "round": current_round + 1,
        })
        cell["status"] = "planned"
        cell["disposition_reason"] = "requeued by bounded high-risk gapfill"

    # Micro-forks are persisted as lead-owned rabbit-hole tasks so workers do
    # not create unbounded children. They consume the same single-run budget.
    existing_leads = {str(cell.get("lead_key")) for cell in plan.get("cells", []) if cell.get("lead_key")}
    for result_path in sorted((scan / "sast/deepdive").glob("*.json")):
        result = load(result_path, {})
        if not isinstance(result, dict):
            continue
        for rabbit in result.get("rabbit_holes", []):
            if task_count >= limits["max_hunt_tasks"]:
                break
            if not isinstance(rabbit, dict):
                continue
            subsystem_id = str(rabbit.get("subsystem", ""))
            attack_id = str(rabbit.get("attack_class_id", ""))
            files = [str(item) for item in (rabbit.get("files") or [])]
            lead_material = "\0".join([subsystem_id, attack_id, *sorted(files), str(rabbit.get("reason", "")).strip().lower()])
            lead_key = hashlib.sha256(lead_material.encode()).hexdigest()[:16]
            if lead_key in existing_leads or subsystem_id not in subsystem_map or attack_id not in class_map:
                continue
            subsystem = subsystem_map[subsystem_id]
            attack_class = class_map[attack_id]
            cell_id = f"CELL-RABBIT-{slug(subsystem_id)}-{slug(attack_id)}-{lead_key}"
            refs = list(dict.fromkeys([*rabbit.get("evidence_refs", []), str(result_path.relative_to(scan))]))
            cell = {
                "id": cell_id,
                "surface_id": str((subsystem.get("security_surface_ids") or [subsystem_id])[0]),
                "subsystem": subsystem_id,
                "attack_class_ids": [attack_id],
                "domain": attack_class.get("domain", "general"),
                "status": "planned",
                "priority": subsystem.get("risk", "medium"),
                "evidence_refs": refs,
                "owner": "sast",
                "lead_key": lead_key,
                "disposition_reason": f"bounded rabbit hole: {rabbit.get('reason', '')}",
            }
            plan["cells"].append(cell)
            task_count += 1
            plan["tasks"].append({
                "id": f"H{task_count:03d}-{slug(subsystem_id)}-{slug(attack_id)}-r{current_round + 1}",
                "cell_ids": [cell_id],
                "subsystem": subsystem_id,
                "attack_class_id": attack_id,
                "domain": attack_class.get("domain", "general"),
                "methodology_refs": methodology_refs(attack_class),
                "lenses": specialist_lenses(attack_class),
                "files": files or subsystem["files"],
                "entrypoints": subsystem.get("entrypoints", []),
                "context_packet": context_packet(threat, subsystem, attack_class, scan, limits["context_packet_bytes"]),
                "evidence_refs": refs,
                "attempt": 1,
                "round": current_round + 1,
            })
            existing_leads.add(lead_key)
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
    output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
