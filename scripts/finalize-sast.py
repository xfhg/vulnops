#!/usr/bin/env python3
"""Deterministically aggregate, deduplicate, and finalize VulnOps v2 SAST."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE = {"low": 0, "medium": 1, "high": 2}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def validator_module(root: Path):
    spec = importlib.util.spec_from_file_location("vulnops_validate_json", root / "scripts/validate-json.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load validate-json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_errors(root: Path, repo: Path, candidate: object) -> list[str]:
    module = validator_module(root)
    schema = load(root / "schemas/v2/candidate-finding.schema.json", {})
    errors = module.Validator(schema).collect(candidate, schema)
    errors.extend(module.semantic_errors(candidate, "candidate", repo))
    return errors


def root_key(candidate: dict) -> str:
    location = candidate.get("root_cause_location", {})
    material = "\0".join(
        [
            str(candidate.get("category", "")).lower().strip(),
            str(location.get("file", "")).lower().strip(),
            str(location.get("line", "")),
            str(location.get("scope", "")).lower().strip(),
            re.sub(r"\W+", " ", str(location.get("mechanism", "")).lower()).strip(),
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()[:24]


def canonical_candidate_id(task_id: str, offset: int) -> str:
    safe_task = re.sub(r"[^A-Za-z0-9_.-]", "-", task_id).strip(".-") or "task"
    digest = hashlib.sha256(f"{task_id}\0{offset}".encode()).hexdigest()[:10]
    return f"C-{safe_task[:96]}-{offset:03d}-{digest}"


def is_shallow(result: dict) -> bool:
    if result.get("status") in {"shallow", "failed"}:
        return True
    if result.get("candidates"):
        return False
    return any(not result.get(key) for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"))


def aggregate(root: Path, repo: Path, scan: Path) -> tuple[list[dict], list[dict], dict]:
    plan = load(scan / "sast/hunt-plan.json", {})
    raw: list[dict] = []
    dropped: list[dict] = []
    hardening: list[dict] = []
    positives: list[dict] = []
    wishlist_items: list[dict] = []
    task_rows: list[dict] = []
    cell_outcomes: dict[str, list[tuple[str, str, list[str], int, int]]] = {}
    raw_count = 0
    seen_candidate_ids: set[str] = set()

    for task in plan.get("tasks", []):
        task_id = str(task.get("id", ""))
        result_path = scan / f"sast/deepdive/{task_id}.json"
        result = load(result_path, {})
        if not isinstance(result, dict):
            result = {}
        shallow = is_shallow(result)
        status = "shallow" if shallow else "ok"
        if result.get("status") == "failed":
            status = "failed"
        candidate_ids: list[str] = []
        submitted_candidates = result.get("candidates", [])
        if not isinstance(submitted_candidates, list):
            submitted_candidates = []
        for offset, candidate in enumerate(submitted_candidates, start=1):
            raw_count += 1
            if not isinstance(candidate, dict):
                dropped.append({
                    "id": f"MECH-{task_id}-{offset}",
                    "raw_id": f"{task_id}:{offset}",
                    "status": "rejected",
                    "reason": "candidate is not a JSON object",
                    "evidence_refs": [str(result_path.relative_to(scan))],
                    "raw_refs": [f"sast/deepdive/{task_id}.json#{offset}"],
                })
                continue
            source_candidate_id = str(candidate.get("id", f"{task_id}:{offset}"))
            candidate["id"] = canonical_candidate_id(task_id, offset)
            candidate["task_id"] = task_id
            errors = candidate_errors(root, repo, candidate)
            candidate_id = str(candidate.get("id", ""))
            if candidate_id in seen_candidate_ids:
                errors.append(f"duplicate candidate ID {candidate_id!r}")
            if errors:
                dropped.append({
                    "id": f"MECH-{task_id}-{offset}",
                    "raw_id": source_candidate_id,
                    "status": "rejected",
                    "reason": "mechanical validation failed: " + "; ".join(errors[:8]),
                    "evidence_refs": list(candidate.get("evidence_refs", [])) or [str(result_path.relative_to(scan))],
                    "raw_refs": [f"sast/deepdive/{task_id}.json#{offset}"],
                })
                continue
            seen_candidate_ids.add(candidate_id)
            raw.append(candidate)
            candidate_ids.append(str(candidate["id"]))
        hardening.extend(item for item in result.get("hardening_notes", []) if isinstance(item, dict))
        positives.extend(item for item in result.get("positive_patterns", []) if isinstance(item, dict))
        for item in result.get("wishlist_items", []):
            if not isinstance(item, dict):
                continue
            wishlist_items.append({
                "id": str(item.get("id") or f"W-{len(wishlist_items) + 1:03d}"),
                "finding_id": item.get("finding_id"),
                "kind": str(item.get("kind", "tool")),
                "request": str(item.get("request", "Additional audit dependency")),
                "reason": str(item.get("reason", "Required evidence is unavailable")),
                "status": str(item.get("status", "open")),
                "evidence_refs": list(item.get("evidence_refs", [])),
            })
        if submitted_candidates and not candidate_ids and status != "failed":
            status = "shallow"
        row = {
            "id": task_id,
            "status": status,
            "attempts": int(task.get("attempt", 1)),
            "files_reviewed": list(result.get("files_reviewed", [])),
            "entrypoints_traced": list(result.get("entrypoints_traced", [])),
            "sinks_reviewed": list(result.get("sinks_reviewed", [])),
            "mitigations_checked": list(result.get("mitigations_checked", [])),
            "candidate_ids": candidate_ids,
            "rabbit_holes": [str(item.get("reason", "")) for item in result.get("rabbit_holes", []) if isinstance(item, dict)],
        }
        task_rows.append(row)
        for cell_id in task.get("cell_ids", []):
            outcome = "finding" if candidate_ids else status
            evidence = [str(result_path.relative_to(scan))]
            cell_outcomes.setdefault(str(cell_id), []).append((task_id, outcome, evidence, int(task.get("round", 0)), int(task.get("attempt", 1))))

    clusters: dict[str, list[dict]] = {}
    for candidate in raw:
        clusters.setdefault(root_key(candidate), []).append(candidate)
    queue: list[dict] = []
    cluster_doc: list[dict] = []
    for key, members in sorted(clusters.items()):
        ranked = sorted(
            members,
            key=lambda item: (SEVERITY.get(item.get("severity"), -1), CONFIDENCE.get(item.get("confidence"), -1), len(item.get("evidence_refs", []))),
            reverse=True,
        )
        canonical = dict(ranked[0])
        canonical["cell_ids"] = list(dict.fromkeys(cell_id for item in ranked for cell_id in item.get("cell_ids", [])))
        canonical["evidence_refs"] = list(dict.fromkeys(ref for item in ranked for ref in item.get("evidence_refs", [])))
        canonical["methodology_refs"] = list(dict.fromkeys(ref for item in ranked for ref in item.get("methodology_refs", [])))
        canonical["lenses"] = list(dict.fromkeys(ref for item in ranked for ref in item.get("lenses", [])))
        queue.append(canonical)
        duplicate_ids = [str(item["id"]) for item in ranked[1:]]
        cluster_doc.append({"root_key": key, "canonical_id": canonical["id"], "member_ids": [item["id"] for item in ranked], "duplicate_ids": duplicate_ids})

    cell_rows: list[dict] = []
    for cell in plan.get("cells", []):
        cell_id = str(cell.get("id", ""))
        outcomes = cell_outcomes.get(cell_id, [])
        if cell.get("status") == "tool_satisfied":
            status = "tool_satisfied"
            reason = str(cell.get("disposition_reason"))
            task_ids: list[str] = []
            evidence = list(cell.get("evidence_refs", []))
        elif outcomes:
            latest = max(outcomes, key=lambda item: (item[3], item[4]))
            status = latest[1]
            reason = "candidate produced" if status == "finding" else "focused review completed" if status == "clean" else "task needs bounded gapfill"
            task_ids = [item[0] for item in outcomes]
            evidence = [ref for item in outcomes for ref in item[2]]
        else:
            status = "deferred" if cell.get("status") == "deferred" else "failed"
            reason = str(cell.get("disposition_reason") or "no completed task")
            task_ids = []
            evidence = list(cell.get("evidence_refs", []))
        cell_rows.append({"id": cell_id, "status": status, "task_ids": task_ids, "evidence_refs": list(dict.fromkeys(evidence)), "reason": reason})

    ledger = {
        "schema_version": "2.0",
        "run_id": plan.get("run_id", "unknown"),
        "rounds_completed": max((int(task.get("round", 0)) for task in plan.get("tasks", [])), default=0),
        "cells": cell_rows,
        "tasks": task_rows,
        "funnel": {
            "raw_candidates": raw_count,
            "deduplicated_candidates": len(queue),
            "mechanically_rejected": sum(1 for item in dropped if str(item.get("id", "")).startswith("MECH-")),
            "adversarially_rejected": 0,
            "source_verified": 0,
            "dynamic_verified": 0,
            "environment_required": 0,
            "final_rejected": 0,
            "reported": 0,
        },
        "warnings": [],
        "errors": [],
    }
    write(scan / "sast/raw-findings.json", raw)
    write(scan / "sast/validation-queue.json", queue)
    write(scan / "sast/dedup-clusters.json", {"schema_version": "2.0", "clusters": cluster_doc})
    write(scan / "sast/mechanical-dropped.json", dropped)
    write(scan / "sast/hardening-notes.json", hardening)
    write(scan / "sast/positive-patterns.json", positives)
    write(scan / "sast/wishlist.json", {"schema_version": "2.0", "run_id": plan.get("run_id", "unknown"), "items": wishlist_items})
    write(scan / "sast/coverage-ledger.json", ledger)
    return queue, dropped, ledger


def advance_alternates(scan: Path) -> int:
    raw = load(scan / "sast/raw-findings.json", [])
    raw_by_id = {str(item.get("id")): item for item in raw if isinstance(item, dict)}
    cluster_document = load(scan / "sast/dedup-clusters.json", {})
    validations = load(scan / "sast/validation-results.json", [])
    queue = load(scan / "sast/validation-queue.json", [])
    if not isinstance(queue, list):
        queue = []
    by_candidate = {str(item.get("candidate_id")): item for item in validations if isinstance(item, dict)}
    queued_ids = {str(item.get("id")) for item in queue if isinstance(item, dict)}
    added: list[str] = []
    for cluster in cluster_document.get("clusters", []) if isinstance(cluster_document, dict) else []:
        if not isinstance(cluster, dict):
            continue
        members = [str(item) for item in cluster.get("member_ids", [])]
        statuses = [by_candidate[item].get("status") for item in members if item in by_candidate]
        if any(status in {"source_verified", "environment_required"} for status in statuses):
            continue
        if not statuses:
            continue
        next_id = next((item for item in members if item not in by_candidate and item not in queued_ids), None)
        candidate = raw_by_id.get(str(next_id)) if next_id else None
        if isinstance(candidate, dict):
            queue.append(candidate)
            queued_ids.add(str(next_id))
            added.append(str(next_id))
    write(scan / "sast/validation-queue.json", queue)
    write(scan / "sast/alternate-queue-state.json", {"schema_version": "2.0", "added": added, "added_count": len(added)})
    return len(added)


def finalize(root: Path, repo: Path, scan: Path) -> None:
    prior_queue = load(scan / "sast/validation-queue.json", [])
    queue, dropped, ledger = aggregate(root, repo, scan)
    queued_ids = {str(item.get("id")) for item in queue if isinstance(item, dict)}
    if isinstance(prior_queue, list):
        for item in prior_queue:
            if isinstance(item, dict) and str(item.get("id")) not in queued_ids and not candidate_errors(root, repo, item):
                queue.append(item)
                queued_ids.add(str(item.get("id")))
    write(scan / "sast/validation-queue.json", queue)
    validations = load(scan / "sast/validation-results.json", [])
    if not isinstance(validations, list) or not validations:
        validations = []
        for path in sorted((scan / "sast/verify").glob("*.json")):
            item = load(path, None)
            if isinstance(item, dict):
                validations.append(item)
        write(scan / "sast/validation-results.json", validations)
    by_candidate = {str(item.get("candidate_id")): item for item in validations if isinstance(item, dict)}
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    context = load(context_path, {})
    reproduction_mode = context.get("reproduction_mode", "off") if isinstance(context, dict) else "off"
    verified: list[dict] = []
    validation_dropped = list(dropped)
    for candidate in queue:
        result = by_candidate.get(str(candidate["id"]))
        if not result:
            validation_dropped.append({
                "id": f"NOVAL-{candidate['id']}", "raw_id": candidate["id"], "status": "deferred",
                "reason": "no adversarial validator result", "evidence_refs": candidate["evidence_refs"],
                "raw_refs": [f"sast/validation-queue.json:{candidate['id']}"],
            })
            continue
        status = result.get("status")
        if status in {"source_verified", "environment_required"}:
            corrections = result.get("corrections", [])
            corrected = result.get("corrected_candidate")
            if corrections:
                if not isinstance(corrected, dict) or corrected.get("id") != candidate.get("id"):
                    validation_dropped.append({
                        "id": f"CORRECTION-{candidate['id']}", "raw_id": candidate["id"], "status": "rejected",
                        "reason": "promoted validator corrections were not applied to a complete candidate",
                        "evidence_refs": list(result.get("evidence_refs", candidate["evidence_refs"])),
                        "raw_refs": [f"sast/validation-results.json:{result.get('id')}"],
                    })
                    continue
                correction_errors = candidate_errors(root, repo, corrected)
                if correction_errors:
                    validation_dropped.append({
                        "id": f"CORRECTION-{candidate['id']}", "raw_id": candidate["id"], "status": "rejected",
                        "reason": "corrected candidate failed mechanical validation: " + "; ".join(correction_errors[:8]),
                        "evidence_refs": list(result.get("evidence_refs", candidate["evidence_refs"])),
                        "raw_refs": [f"sast/validation-results.json:{result.get('id')}"],
                    })
                    continue
                candidate = corrected
            elif corrected is not None:
                validation_dropped.append({
                    "id": f"CORRECTION-{candidate['id']}", "raw_id": candidate["id"], "status": "rejected",
                    "reason": "validator supplied a corrected candidate without recording corrections",
                    "evidence_refs": list(result.get("evidence_refs", candidate["evidence_refs"])),
                    "raw_refs": [f"sast/validation-results.json:{result.get('id')}"],
                })
                continue
            reproduction_path = scan / f"sast/reproduction/{candidate['id']}/result.json"
            reproduction = load(reproduction_path, None)
            if isinstance(reproduction, dict) and reproduction.get("status") == "contradicted":
                validation_dropped.append({
                    "id": f"REPRO-{candidate['id']}", "raw_id": candidate["id"], "status": "rejected",
                    "reason": "safe reproduction contradicted the claimed behavior",
                    "evidence_refs": [str(reproduction_path.relative_to(scan))],
                    "raw_refs": [f"sast/validation-results.json:{result['id']}"],
                })
                continue
            reproduction_status = reproduction.get("status") if isinstance(reproduction, dict) else None
            if reproduction_status == "dynamic_verified":
                verification_level = "dynamic_verified"
            elif reproduction_status in {"environment_required", "failed"} or (reproduction_mode == "safe" and reproduction_status is None):
                verification_level = "environment_required"
            else:
                verification_level = status
            verified.append({
                **candidate,
                "validation": result,
                "verification_level": verification_level,
                "reproduction_ref": str(reproduction_path.relative_to(scan)) if isinstance(reproduction, dict) else None,
                "reproduction": reproduction,
            })
        else:
            validation_dropped.append({
                "id": f"VAL-{candidate['id']}", "raw_id": candidate["id"],
                "status": "rejected" if status == "rejected" else "deferred",
                "reason": str(result.get("closure_reason", "validator rejected or deferred candidate")),
                "evidence_refs": list(result.get("evidence_refs", candidate["evidence_refs"])),
                "raw_refs": [f"sast/validation-results.json:{result.get('id')}"],
            })

    verified_ids = {str(item.get("id")) for item in verified}
    cluster_document = load(scan / "sast/dedup-clusters.json", {})
    for cluster in cluster_document.get("clusters", []) if isinstance(cluster_document, dict) else []:
        if not isinstance(cluster, dict):
            continue
        members = [str(item) for item in cluster.get("member_ids", [])]
        survivor = next((item for item in members if item in verified_ids), None)
        if not survivor:
            continue
        for duplicate_id in members:
            if duplicate_id == survivor or any(item.get("raw_id") == duplicate_id for item in validation_dropped):
                continue
            validation_dropped.append({
                "id": f"DEDUP-{duplicate_id}",
                "raw_id": duplicate_id,
                "status": "suppressed",
                "reason": f"same structured root cause as verified candidate {survivor}",
                "evidence_refs": [f"sast/raw-findings.json:{duplicate_id}"],
                "raw_refs": [f"sast/dedup-clusters.json:{cluster.get('root_key')}"],
            })
    ledger["funnel"]["adversarially_rejected"] = sum(1 for item in validation_dropped if str(item.get("id", "")).startswith("VAL-") and item.get("status") == "rejected")
    ledger["funnel"]["source_verified"] = sum(1 for item in verified if item.get("verification_level") == "source_verified")
    ledger["funnel"]["dynamic_verified"] = sum(1 for item in verified if item.get("verification_level") == "dynamic_verified")
    ledger["funnel"]["environment_required"] = sum(1 for item in verified if item.get("verification_level") == "environment_required")
    write(scan / "sast/verified-findings.json", verified)
    write(scan / "sast/dropped-findings.json", validation_dropped)
    write(scan / "sast/coverage-ledger.json", ledger)
    write_text(
        scan / "sast/summary.md",
        "# SAST v2 Summary\n\n"
        f"- Raw candidates: {ledger['funnel']['raw_candidates']}\n"
        f"- Deduplicated candidates: {ledger['funnel']['deduplicated_candidates']}\n"
        f"- Source verified: {ledger['funnel']['source_verified']}\n"
        f"- Dynamically verified: {ledger['funnel']['dynamic_verified']}\n"
        f"- Environment required: {ledger['funnel']['environment_required']}\n"
        f"- Rejected/deferred: {len(validation_dropped)}\n",
    )
    manifest = {
        "phase": "sast", "status": "degraded" if ledger["funnel"]["environment_required"] or any(cell["status"] in {"deferred", "shallow", "failed"} for cell in ledger["cells"]) else "ok",
        "started_at": now(), "completed_at": now(),
        "inputs": ["repo-context/security-surfaces.json", "sca/raw-advisories.json", "secrets/redacted-candidates.json", "sast/threat-model.json", "sast/hunt-plan.json"],
        "outputs": ["sast/raw-findings.json", "sast/validation-results.json", "sast/verified-findings.json", "sast/dropped-findings.json", "sast/coverage-ledger.json", "sast/wishlist.json"],
        "coverage": {"cells": len(ledger["cells"]), "tasks": len(ledger["tasks"]), **ledger["funnel"]},
        "tool_versions": {"vulnops_audit_doctrine": "2.0"},
        "warnings": ledger["warnings"], "errors": ledger["errors"],
    }
    write(scan / "sast/phase-manifest.json", manifest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_path", type=Path)
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument("--advance-alternates", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.finalize:
        finalize(root, args.repo_path, args.scan_base)
    elif args.advance_alternates:
        print(advance_alternates(args.scan_base))
    else:
        aggregate(root, args.repo_path, args.scan_base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
