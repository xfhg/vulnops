#!/usr/bin/env python3
"""Deterministically aggregate, deduplicate, and finalize VulnOps V5 SAST."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sast_contract import (validate_hunt_result, effective_threat_model, validate_sast_provenance,
                           correction_contributors, hunt_evidence_diagnostics, review_projection,
                           candidate_errors, validate_review_result, sast_review_support, validate_retained_hunt)
from model_identity import validate_provenance, contributor_union
from evidence_refs import EvidenceIssue
from exploration_evidence import model_evidence_quality
from evidence_accounting import classify_refs, summarize, validate_non_promoted
from run_lifecycle import assessment_ref, current_assessment, require_active_phase, routing_for_artifact


SEVERITY = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE = {"low": 0, "medium": 1, "high": 2}
EXPECTED_DEPTH_LIMITS = {"deferred", "shallow"}


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


def allocation_limits(plan: dict, cell_id: str) -> list[str]:
    limits = plan.get("budget", {})
    tasks = plan.get("tasks", [])
    used = {
        "max_attempts": ("per-question attempts", sum(cell_id in task["cell_ids"] for task in tasks)),
        "max_hunt_tasks": ("hunt tasks", len(tasks)),
        "max_hunt_questions": ("hunt questions", sum(len(task["cell_ids"]) for task in tasks)),
        "max_gapfill_rounds": ("gapfill rounds", max((task.get("round", 0) for task in tasks), default=0)),
    }
    return [f"{label} {count}/{limits[key]}" for key, (label, count) in used.items()
            if key in limits and count >= limits[key]]


def close_depth_limited_cells(ledger: dict, plan: dict | None = None) -> int:
    """Close unfinished work by its recorded reason, not its lifecycle label."""
    closed = 0
    for cell in ledger.get("cells", []):
        if not isinstance(cell, dict) or cell.get("status") not in EXPECTED_DEPTH_LIMITS:
            continue
        outcome = cell.get("resolution", {}).get("outcome")
        limits = allocation_limits(plan or {}, cell.get("id", ""))
        if outcome == "externally_blocked":
            cell["status"] = "externally_blocked"
        elif outcome == "execution_failed":
            cell["status"] = "failed"
        elif limits:
            cell["status"] = "depth_limited"
            cell["reason"] += "; SAST allocation exhausted: " + "; ".join(limits)
        else:
            cell["status"] = "locally_unresolved"
        closed += 1
    return closed


def sast_phase_status(ledger: dict) -> str:
    funnel = ledger.get("funnel", {}) if isinstance(ledger.get("funnel"), dict) else {}
    cells = ledger.get("cells", []) if isinstance(ledger.get("cells"), list) else []
    material_loss = bool(funnel.get("environment_required")) or any(
        isinstance(cell, dict) and cell.get("status") in {"failed", "externally_blocked"} for cell in cells
    )
    return "degraded" if material_loss else "ok"




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


def aggregate(root: Path, repo: Path, scan: Path, *, publish: bool = True) -> tuple[list[dict], list[dict], dict]:
    if publish:
        context = load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json")), {})
        require_active_phase(scan, context, "sast")
    plan = load(scan / "sast/hunt-plan.json", {})
    raw: list[dict] = []
    dropped: list[dict] = []
    hardening: list[dict] = []
    positives: list[dict] = []
    wishlist_items: list[dict] = []
    task_rows: list[dict] = []
    cell_outcomes: dict[str, list[tuple[str, str, str, list[str], int, int]]] = {}
    raw_count = 0
    seen_candidate_ids: set[str] = set()
    plan_cells = {str(cell.get("id")): cell for cell in plan.get("cells", []) if isinstance(cell, dict)}
    threat = load(scan / "sast/threat-model.json", {})
    context = load(scan / "run-manifest.json", {})
    prior_tasks = {row["id"]: row for row in load(scan / "sast/coverage-ledger.json", {}).get("tasks", [])}
    investigation_details: dict[str, dict] = {}
    diagnostics = []
    model_evidence_quality(scan, repo, context.get("repositories", []), threat,
                           owner="sast/threat-model.json", kind="threat-model", diagnostics=diagnostics, historical=True)

    for task in plan.get("tasks", []):
        task_id = str(task.get("id", ""))
        if task_id in plan.get("deferred_task_ids", []):
            task_rows.append({"id": task_id, "status": "deferred", "artifact_valid": False,
                              "attempts": int(task.get("attempt", 1)),
                              **{key: [] for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed",
                                                    "mitigations_checked", "candidate_ids", "rabbit_holes")}})
            continue
        result_path = scan / f"sast/deepdive/{task_id}.json"
        result = load(result_path, {})
        if not isinstance(result, dict):
            result = {}
        assigned_cells = [plan_cells[str(cell_id)] for cell_id in task.get("cell_ids", []) if str(cell_id) in plan_cells]
        prior_task = prior_tasks.get(task_id, {})
        retained = bool(context.get("attempt_id") and prior_task.get("artifact_valid")
                        and prior_task.get("attempt_id") != context["attempt_id"])
        result_errors = (validate_retained_hunt(task, assigned_cells, result) if retained else
                         validate_hunt_result(root, repo, task, assigned_cells, result, threat if isinstance(threat, dict) else None,
                                              context.get("repositories", []), context.get("model_routing"), scan=scan, raise_integrity=True))
        valid_result = not result_errors
        if valid_result:
            cell_results = [row for row in result.get("cell_results", []) if isinstance(row, dict)]
            threat = effective_threat_model(threat, result.get("model_amendments", []))
        else:
            bounded = f"hunt result failed {len(result_errors) or 1} schema or per-cell semantic check(s)"
            cell_results = [{
                "cell_id": str(cell_id),
                "status": "failed",
                "reason": bounded,
                "files_reviewed": [],
                "entrypoints_traced": [],
                "sinks_reviewed": [],
                "mitigations_checked": [],
                "candidate_ids": [],
                "evidence_refs": [str(result_path.relative_to(scan))],
            } for cell_id in task.get("cell_ids", [])]
        candidate_ids: list[str] = []
        source_to_canonical: dict[str, str] = {}
        submitted_candidates = result.get("candidates", []) if valid_result else []
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
            candidate["contributors"] = [result["provenance"]]
            if not retained and assessment_ref(context):
                candidate["assessment_context"] = assessment_ref(context)
            errors = [] if retained else candidate_errors(root, repo, candidate, scan=scan, repositories=context.get("repositories", []))
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
            source_to_canonical[source_candidate_id] = str(candidate["id"])
        if valid_result:
            if not retained:
                diagnostics.extend(hunt_evidence_diagnostics(scan, repo, context.get("repositories", []), result))
            hardening.extend({key: item[key] for key in ("title", "description", "evidence_refs")}
                             for item in result.get("hardening_notes", []) if isinstance(item, dict))
            positives.extend({key: item[key] for key in ("title", "description", "evidence_refs")}
                             for item in result.get("positive_patterns", []) if isinstance(item, dict))
        for item in result.get("wishlist_items", []) if valid_result else []:
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
        cell_statuses: list[str] = []
        for cell_result in cell_results:
            cell_id = str(cell_result.get("cell_id", ""))
            source_ids = [str(item) for item in cell_result.get("candidate_ids", [])]
            surviving = [source_to_canonical[item] for item in source_ids if item in source_to_canonical]
            outcome = str(cell_result.get("status", "failed"))
            reason = str(cell_result.get("reason", "cell result missing rationale"))
            if outcome == "finding" and not surviving:
                outcome = "shallow"
                reason = "all candidates for this cell failed mechanical validation"
            evidence = list(dict.fromkeys([*cell_result.get("evidence_refs", []), str(result_path.relative_to(scan))]))
            resolution = cell_result.get("resolution")
            consequential = [
                issue for issue in diagnostics if issue["owner"] == str(result_path.relative_to(scan))
                and issue["disposition"] == "evidence_limited" and (
                    cell_id in issue["affected_item_ids"] or
                    set(surviving).intersection(issue["affected_item_ids"]))]
            if consequential and outcome != "failed" and (resolution or {}).get("outcome") != "externally_blocked":
                outcome = "shallow"
                reason = "Targeted source review required: " + "; ".join(
                    dict.fromkeys(f"{issue['field']} ({issue['code']})" for issue in consequential))
                resolution = {
                    "outcome": "locally_unresolved", "reason": reason,
                    "next_action": (cell_result.get("checkpoint") or {}).get("next_step") or
                                   "inspect the diagnosed source obligation and record replacement support",
                    "evidence_refs": evidence,
                    "missing_fact": (cell_result.get("checkpoint") or {}).get("remaining_question") or
                                    plan_cells[cell_id]["security_question"],
                }
            cell_statuses.append(outcome)
            if not resolution or (resolution.get("outcome") == "established" and outcome != "finding"):
                resolution = {"outcome": "execution_failed" if outcome == "failed" else "locally_unresolved",
                              "reason": reason, "next_action": "retry the exact proof obligation within the remaining allowance",
                              "evidence_refs": evidence, "missing_fact": ""}
            investigation_details[cell_id] = {
                "resolution": resolution,
                "checkpoint": cell_result.get("checkpoint") or investigation_details.get(cell_id, {}).get("checkpoint") or {
                    "established_facts": [], "contradicted_paths": [], "remaining_question": plan_cells[cell_id]["security_question"],
                    "objective_id": plan_cells[cell_id]["objective_id"], "question_id": plan_cells[cell_id]["question_id"],
                    "files_reviewed": [], "next_step": resolution["next_action"], "expected_results": [],
                },
            }
            if consequential:
                checkpoint = dict(investigation_details[cell_id]["checkpoint"])
                checkpoint["remaining_question"] = checkpoint["remaining_question"] or resolution["missing_fact"]
                checkpoint["next_step"] = checkpoint["next_step"] or resolution["next_action"]
                investigation_details[cell_id]["checkpoint"] = checkpoint
            cell_outcomes.setdefault(cell_id, []).append((
                task_id,
                outcome,
                reason,
                evidence,
                int(task.get("round", 0)),
                int(task.get("attempt", 1)),
            ))
        status = "failed" if "failed" in cell_statuses else "shallow" if "shallow" in cell_statuses else "ok"
        row = {
            "id": task_id,
            "status": status,
            "artifact_valid": valid_result,
            "attempts": int(task.get("attempt", 1)),
            "files_reviewed": list(result.get("files_reviewed", [])) if valid_result else [],
            "entrypoints_traced": list(result.get("entrypoints_traced", [])) if valid_result else [],
            "sinks_reviewed": list(result.get("sinks_reviewed", [])) if valid_result else [],
            "mitigations_checked": list(result.get("mitigations_checked", [])) if valid_result else [],
            "candidate_ids": candidate_ids,
            "rabbit_holes": [str(item.get("reason", "")) for item in result.get("rabbit_holes", []) if isinstance(item, dict)] if valid_result else [],
        }
        if retained and prior_task.get("attempt_id"):
            row["attempt_id"] = prior_task["attempt_id"]
        elif not retained and context.get("attempt_id"):
            row["attempt_id"] = context["attempt_id"]
        task_rows.append(row)

    clusters: dict[str, list[dict]] = {}
    for candidate in raw:
        clusters.setdefault(root_key(candidate), []).append(candidate)
    queue: list[dict] = []
    cluster_doc: list[dict] = []
    for key, members in sorted(clusters.items()):
        ranked = sorted(
            members,
            key=lambda item: (SEVERITY.get(item.get("severity"), -1), CONFIDENCE.get(item.get("confidence"), -1)),
            reverse=True,
        )
        canonical = dict(ranked[0])
        canonical["cell_ids"] = list(dict.fromkeys(cell_id for item in ranked for cell_id in item.get("cell_ids", [])))
        canonical["evidence_refs"] = list(dict.fromkeys(ref for item in ranked for ref in item.get("evidence_refs", [])))
        canonical["methodology_refs"] = list(dict.fromkeys(ref for item in ranked for ref in item.get("methodology_refs", [])))
        canonical["lenses"] = list(dict.fromkeys(ref for item in ranked for ref in item.get("lenses", [])))
        canonical["contributors"] = contributor_union(*(item["contributors"] for item in ranked))
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
            latest = max(outcomes, key=lambda item: (item[4], item[5]))
            status = latest[1]
            reason = latest[2]
            task_ids = [item[0] for item in outcomes]
            evidence = [ref for item in outcomes for ref in item[3]]
        else:
            status = "deferred" if cell.get("status") == "deferred" else "failed"
            reason = str(cell.get("disposition_reason") or "no completed task")
            task_ids = []
            evidence = list(cell.get("evidence_refs", []))
        details = investigation_details.get(cell_id) or {
            "resolution": {"outcome": "execution_failed" if status == "failed" else "budget_deferred",
                           "reason": reason, "next_action": "triage collected evidence" if status == "tool_satisfied" else "resume the source question with an explicit allowance",
                           "evidence_refs": evidence, "missing_fact": ""},
            "objective_id": cell["objective_id"], "question_id": cell["question_id"],
            "checkpoint": {"objective_id": cell["objective_id"], "question_id": cell["question_id"],
                           "established_facts": [], "contradicted_paths": [], "remaining_question": cell["security_question"],
                           "files_reviewed": [], "next_step": "inspect the initial anchors and resolve the security question", "expected_results": []},
        }
        cell_rows.append({"id": cell_id, "objective_id": cell["objective_id"], "question_id": cell["question_id"],
                          "status": status, "task_ids": task_ids, "evidence_refs": list(dict.fromkeys(evidence)), "reason": reason, **details})

    ledger = {
        "schema_version": "2.0",
        "run_id": plan.get("run_id", "unknown"),
        "rounds_completed": max((int(task.get("round", 0)) for task in plan.get("tasks", [])), default=0),
        "cells": cell_rows,
        "tasks": task_rows,
        "evidence_quality": summarize(diagnostics),
        "non_promoted": [],
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
    prior_review_attempts = load(scan / "sast/coverage-ledger.json", {}).get("review_attempts")
    if prior_review_attempts is not None:
        ledger["review_attempts"] = dict(prior_review_attempts)
    if publish:
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
    root = Path(__file__).resolve().parent.parent
    context = load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json")), {})
    require_active_phase(scan, context, "sast")
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


def finalize(root: Path, repo: Path, scan: Path, *, validate_only: bool = False) -> None:
    if not validate_only:
        context = load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json")), {})
        require_active_phase(scan, context, "sast")
    run = load(scan / "run-manifest.json", {})
    routing = run.get("model_routing") or {}
    repositories = run.get("repositories", [])
    hunt_plan = load(scan / "sast/hunt-plan.json", {})
    plan_cells = {str(cell.get("id")): cell for cell in hunt_plan.get("cells", []) if isinstance(cell, dict)}
    prior_queue = load(scan / "sast/validation-queue.json", [])
    prior_ledger = load(scan / "sast/coverage-ledger.json", {})
    prior_validations = load(scan / "sast/validation-results.json", [])
    legacy_reviews = "review_attempts" not in prior_ledger and any(
        row.get("artifact_valid") and row.get("attempt_id") != run.get("attempt_id")
        for row in prior_ledger.get("tasks", []))
    historical_reviews = {item["candidate_id"] for item in prior_validations
                          if run.get("attempt_id") and (legacy_reviews or
                          item["candidate_id"] in prior_ledger.get("review_attempts", {}) and
                          prior_ledger["review_attempts"][item["candidate_id"]] != run["attempt_id"])}
    retained_verified = {item["id"]: item for item in load(scan / "sast/verified-findings.json", [])
                         if item["id"] in historical_reviews}
    for candidate in prior_queue if isinstance(prior_queue, list) else []:
        if isinstance(candidate, dict):
            classify_refs(scan, repo, repositories, candidate.get("evidence_refs", []),
                          owner=candidate.get("id"), field="evidence_refs", affected_item_ids=[candidate.get("id")],
                          historical=not current_assessment(candidate, run))
    queue, dropped, ledger = aggregate(root, repo, scan, publish=not validate_only)
    queued_ids = {str(item.get("id")) for item in queue if isinstance(item, dict)}
    if isinstance(prior_queue, list):
        for item in prior_queue:
            if isinstance(item, dict) and str(item.get("id")) not in queued_ids:
                queue.append(item)
                queued_ids.add(str(item.get("id")))
    if not validate_only:
        write(scan / "sast/validation-queue.json", queue)
    validations = load(scan / "sast/validation-results.json", [])
    if not isinstance(validations, list) or not validations:
        validations = []
        for path in sorted((scan / "sast/verify").glob("*.json")):
            item = load(path, None)
            if isinstance(item, dict):
                validations.append(item)
        if not validate_only:
            write(scan / "sast/validation-results.json", validations)
    by_candidate = {str(item.get("candidate_id")): item for item in validations if isinstance(item, dict)}
    correction_sources = {}
    for result in validations:
        candidate = next((item for item in queue if item["id"] == result.get("candidate_id")), None)
        if candidate is None:
            raise ValueError("candidate review has no queued owner")
        if result["candidate_id"] in historical_reviews:
            if result != load(scan / f"sast/verify/{candidate['id']}.json", None):
                raise ValueError("retained review differs from its owned publication")
            correction_sources[result["candidate_id"]] = []
            continue
        errors = validate_review_result(root, repo, candidate, result, scan=scan,
                                        repositories=repositories, routing=routing)
        if errors:
            raise ValueError("review repair or owned evidence-limited closure required: " + "; ".join(errors))
        if result != load(scan / f"sast/verify/{candidate['id']}.json", None):
            raise ValueError("candidate review differs from its source-owned publication")
        correction_sources[result["candidate_id"]] = correction_contributors(
            scan, routing, result, source_root=repo, repositories=repositories)
    ledger["review_attempts"] = dict(prior_ledger.get("review_attempts", {}))
    if run.get("attempt_id"):
        ledger["review_attempts"].update({result["candidate_id"]: run["attempt_id"]
                                         for result in validations if result["candidate_id"] not in historical_reviews})
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    context = load(context_path, {})
    reproduction_mode = context.get("reproduction_mode", "off") if isinstance(context, dict) else "off"
    verified: list[dict] = []
    validation_dropped = list(dropped)
    diagnostics = []
    model_evidence_quality(scan, repo, repositories, load(scan / "sast/threat-model.json", {}),
                           owner="sast/threat-model.json", kind="threat-model", diagnostics=diagnostics, historical=True)
    for task in hunt_plan.get("tasks", []):
        if any(row["id"] == task["id"] and row.get("artifact_valid") for row in ledger["tasks"]):
            source = load(scan / f"sast/deepdive/{task['id']}.json", {})
            for offset, candidate in enumerate(source.get("candidates", []), 1):
                candidate["id"] = canonical_candidate_id(task["id"], offset)
            accepted = next(row for row in ledger["tasks"] if row["id"] == task["id"])
            if not run.get("attempt_id") or accepted.get("attempt_id") == run["attempt_id"]:
                diagnostics.extend(hunt_evidence_diagnostics(scan, repo, repositories, source))
    for candidate in queue:
        result = by_candidate.get(str(candidate["id"]))
        if candidate["id"] in historical_reviews:
            if candidate["id"] in retained_verified:
                verified.append(retained_verified[candidate["id"]])
            else:
                validation_dropped.append({
                    "id": f"VAL-{candidate['id']}", "raw_id": candidate["id"], "status": "deferred",
                    "reason": "Retained review is historical; no current effective finding was established.",
                    "evidence_refs": [f"sast/verify/{candidate['id']}.json"],
                    "raw_refs": [f"sast/validation-queue.json:{candidate['id']}"]})
            continue
        if not result:
            _, issues = classify_refs(scan, repo, repositories, candidate.get("evidence_refs", []),
                                      owner=candidate["id"], field="evidence_refs", affected_item_ids=[candidate["id"]])
            if issues:
                raise ValueError("evidence-limited candidate requires attributed review or a precise owned deferral before closure")
            validation_dropped.append({
                "id": f"NOVAL-{candidate['id']}", "raw_id": candidate["id"], "status": "deferred",
                "reason": "no adversarial validator result", "evidence_refs": candidate["evidence_refs"],
                "raw_refs": [f"sast/validation-queue.json:{candidate['id']}"],
            })
            continue
        status = result.get("status")
        owner = f"sast/verify/{candidate['id']}.json"
        if status == "evidence_limited":
            closure = result["non_promoted"]
            ledger["non_promoted"].append(closure)
            validation_dropped.append({
                "id": f"EVIDENCE-{candidate['id']}", "raw_id": candidate["id"], "status": "evidence_limited",
                "reason": closure["reason"], "evidence_refs": list(result.get("evidence_refs", [])),
                "raw_refs": [f"sast/validation-queue.json:{candidate['id']}", owner],
            })
            continue
        _, review_issues = classify_refs(scan, repo, repositories, result.get("evidence_refs", []),
                                        owner=owner, field="evidence_refs", affected_item_ids=[candidate["id"]])
        _, candidate_issues = classify_refs(scan, repo, repositories,
            (result.get("corrected_candidate") or candidate).get("evidence_refs", []),
            owner=owner, field="candidate.evidence_refs", affected_item_ids=[candidate["id"]])
        if review_issues or candidate_issues or result.get("optional_support"):
            try:
                support = sast_review_support(scan, repo, repositories, candidate, result, diagnostics)
            except EvidenceIssue:
                closure = result.get("non_promoted")
                if (not isinstance(closure, dict) or closure.get("id") != candidate["id"] or
                        closure.get("disposition") != "evidence_limited" or
                        closure.get("input_refs") != [f"sast/validation-queue.json:{candidate['id']}"]):
                    raise ValueError("unresolved SAST proof requires an owned evidence-limited source-review/deferral record")
                validate_non_promoted(closure, routing, scan, repo, repositories, actor="vulnops-verify-one")
                diagnostics.extend(review_issues + candidate_issues)
                ledger["non_promoted"].append(closure)
                validation_dropped.append({
                    "id": f"EVIDENCE-{candidate['id']}", "raw_id": candidate["id"], "status": "evidence_limited",
                    "reason": closure["reason"], "evidence_refs": list(result.get("evidence_refs", [])),
                    "raw_refs": [f"sast/validation-queue.json:{candidate['id']}"],
                })
                continue
        contributors = contributor_union(candidate["contributors"], [result["provenance"]], correction_sources[result["candidate_id"]])
        if status in {"source_verified", "environment_required"}:
            if result.get("corrections"):
                candidate = result["corrected_candidate"]
            if result.get("optional_support"):
                candidate = {**candidate, "evidence_refs": support["evidence_refs"]}
            reproduction_path = scan / f"sast/reproduction/{candidate['id']}/result.json"
            reproduction = load(reproduction_path, None)
            if isinstance(reproduction, dict):
                provenance = validate_provenance(reproduction.get("provenance"), routing or {}, "vulnops-reproduce-one",
                                                 str(reproduction_path.relative_to(scan)))
                contributors = contributor_union(contributors, [provenance])
                if reproduction.get("contributors") != contributors:
                    raise ValueError("reproduction must retain its investigator and reviewer contributors")
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
                **({"assessment_context": assessment_ref(run)} if assessment_ref(run) else {}),
                "contributors": contributors,
                "validation": review_projection(result),
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
    # A later attributed review can discharge a candidate gap without rewriting its investigator.
    for issue in diagnostics:
        if issue["affected_item_ids"] and set(issue["affected_item_ids"]).issubset(verified_ids):
            issue["disposition"] = "optional"
    for cell in ledger["cells"]:
        affected = any(issue["disposition"] == "evidence_limited" and cell["id"] in issue["affected_item_ids"]
                       for issue in diagnostics)
        cell_candidates = [candidate["id"] for candidate in queue if cell["id"] in candidate.get("cell_ids", [])]
        limited = [row for row in ledger["non_promoted"] if row["id"] in cell_candidates]
        if limited:
            cell["status"] = "locally_unresolved"
            cell["reason"] = "; ".join(row["reason"] for row in limited)
            cell["resolution"] = {
                "outcome": "locally_unresolved", "reason": cell["reason"],
                "missing_fact": "; ".join(row["missing_fact"] for row in limited),
                "next_action": "; ".join(row["next_action"] for row in limited),
                "evidence_refs": [f"sast/verify/{row['id']}.json" for row in limited],
            }
        if not affected and cell_candidates and set(cell_candidates).issubset(verified_ids):
            cell["status"] = "finding"
            cell["resolution"] = {"outcome": "established", "reason": "Attributed adversarial review established the candidate obligations",
                                  "next_action": "independent verification", "missing_fact": "",
                                  "evidence_refs": [f"sast/verified-findings.json:{key}" for key in cell_candidates]}
        if not affected:
            continue
        original = plan_cells[cell["id"]]
        closure = {
            "id": f"EVIDENCE-{cell['id']}", "input_refs": [f"sast/hunt-plan.json:{cell['id']}"],
            "disposition": "evidence_limited", "reason": cell["reason"],
            "risk_context": f"{original['attacker']}: {original['security_question']}",
            "missing_fact": cell["resolution"].get("missing_fact") or original["security_question"],
            "next_action": cell["resolution"]["next_action"], "review": None, "deferral": None,
        }
        tasks = [task for task in hunt_plan["tasks"] if cell["id"] in task["cell_ids"]]
        exhausted = allocation_limits(hunt_plan, cell["id"])
        if cell["resolution"]["outcome"] == "externally_blocked":
            closure["deferral"] = {"kind": "external", "reason": "Missing external prerequisite: " + closure["missing_fact"]}
        elif exhausted:
            closure["deferral"] = {"kind": "budget", "reason": "SAST allocation exhausted: " + "; ".join(exhausted)}
        elif tasks:
            task = tasks[-1]
            publication = load(scan / f"sast/deepdive/{task['id']}.json", {})
            row = next(row for row in publication["cell_results"] if row["cell_id"] == cell["id"])
            reviewed, _ = classify_refs(scan, repo, repositories, row["checkpoint"]["files_reviewed"],
                owner=publication["provenance"]["artifact_ref"], field="checkpoint.files_reviewed",
                affected_item_ids=[cell["id"]], kind="source")
            if reviewed and row["checkpoint"]["remaining_question"] and row["checkpoint"]["next_step"]:
                closure["review"] = {key: publication["provenance"][key] for key in ("actor", "selector")}
                closure["review"].update(action=original["security_question"], result=row["reason"], evidence_refs=reviewed)
        validate_non_promoted(closure, routing, scan, repo, repositories, actor="vulnops-deepdive-chunk")
        ledger["non_promoted"].append(closure)
    ledger["evidence_quality"] = summarize(diagnostics)
    close_depth_limited_cells(ledger, hunt_plan)
    terminal_counts = {status: sum(cell.get("status") == status for cell in ledger["cells"])
                       for status in ("depth_limited", "externally_blocked", "locally_unresolved", "failed")}
    mapping_count = sum(1 for cell in plan_cells.values() if cell.get("lead_key") is None)
    rabbit_count = sum(1 for cell in plan_cells.values() if cell.get("lead_key") is not None)
    question_count = sum(len(task.get("cell_ids", [])) for task in hunt_plan.get("tasks", []))
    not_applicable_count = sum(1 for cell in ledger["cells"] if cell.get("status") == "not_applicable")
    if validate_only:
        published = load(scan / "sast/coverage-ledger.json", {})
        for key in ("evidence_quality", "non_promoted"):
            empty = summarize([]) if key == "evidence_quality" else []
            if published.get(key, empty) != ledger[key]:
                raise ValueError(f"SAST {key} differs from source-owned evidence accounting")
        if published.get("cells") != ledger["cells"]:
            raise ValueError("SAST coverage labels differ from source-owned resolutions and allocation")
        expected = {item["id"]: {key: item[key] for key in ("evidence_refs", "validation", "contributors")}
                    for item in verified}
        actual = {item["id"]: {key: item.get(key) for key in ("evidence_refs", "validation", "contributors")}
                  for item in load(scan / "sast/verified-findings.json", [])}
        if actual != expected:
            raise ValueError("SAST verified proof differs from deterministic reviewer-derived support")
        return
    write(scan / "sast/verified-findings.json", verified)
    write(scan / "sast/dropped-findings.json", validation_dropped)
    write(scan / "sast/coverage-ledger.json", ledger)
    validate_sast_provenance(scan, routing, source_root=repo, repositories=repositories)
    write_text(
        scan / "sast/summary.md",
        "# VulnOps V5 SAST Summary\n\n"
        f"- Raw candidates: {ledger['funnel']['raw_candidates']}\n"
        f"- Deduplicated candidates: {ledger['funnel']['deduplicated_candidates']}\n"
        f"- Source verified: {ledger['funnel']['source_verified']}\n"
        f"- Dynamically verified: {ledger['funnel']['dynamic_verified']}\n"
        f"- Environment required: {ledger['funnel']['environment_required']}\n"
        f"- Contextual mappings: {mapping_count}\n"
        f"- Hunt questions executed: {question_count}\n"
        f"- Rabbit-hole cells: {rabbit_count}\n"
        f"- Not applicable: {not_applicable_count}\n"
        f"- Depth-limited cells: {terminal_counts['depth_limited']}\n"
        f"- Externally blocked cells: {terminal_counts['externally_blocked']}\n"
        f"- Locally unresolved cells: {terminal_counts['locally_unresolved']}\n"
        f"- Failed cells: {terminal_counts['failed']}\n"
        f"- Evidence-quality diagnostics: {ledger['evidence_quality']['total']}\n"
        f"- Evidence-limited candidates: {len(ledger['non_promoted'])}\n"
        f"- Rejected/deferred: {len(validation_dropped)}\n",
    )
    manifest = {
        "phase": "sast", "status": sast_phase_status(ledger),
        "started_at": now(), "completed_at": now(),
        "inputs": ["repo-context/security-surfaces.json", "tool-collection/sca-advisories.json", "tool-collection/secrets-redacted.json", "sast/threat-model.json", "sast/hunt-plan.json"],
        "outputs": [
            "sast/threat-model.json", "sast/hunt-plan.json",
            "sast/raw-findings.json", "sast/validation-results.json",
            "sast/verified-findings.json", "sast/dropped-findings.json",
            "sast/dedup-clusters.json", "sast/coverage-ledger.json",
            "sast/wishlist.json", "sast/summary.md",
        ],
        "coverage": {
            "cells": len(ledger["cells"]), "contextual_mappings": mapping_count,
            "rabbit_hole_cells": rabbit_count, "tasks": len(ledger["tasks"]),
            "hunt_questions": question_count, "not_applicable": not_applicable_count,
            **terminal_counts,
            "evidence_limited": len(ledger["non_promoted"]),
            **ledger["funnel"],
        },
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
