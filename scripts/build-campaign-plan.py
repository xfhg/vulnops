#!/usr/bin/env python3
"""Prepare optional discovery, then seal deterministic source-first campaigns."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from campaign_contract import (BUDGETS, graph_question, prepare_discovery,
                               selected_candidates, validate_discovery, validate_selection, priority,
                               question_dispositions)
from codegraph_contract import _load, _schema
from evidence_accounting import summarize
from run_lifecycle import assessment_ref, require_active_phase


def write(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def close_discovery(scan: Path, discovery: dict) -> None:
    ledger = scan / "campaign-planning/codegraph-runs/discovery-budget.json"
    entries = {}
    if ledger.exists():
        try:
            entries = _load(ledger)
            if any(type(value) not in (int, float) or not 0 <= value <= 120 for value in entries.values()):
                raise ValueError("invalid discovery time accounting")
        except (ValueError, OSError):
            discovery["graph_limitations"].append("Optional discovery accounting unavailable; no further graph dispatch is permitted.")
            entries = {q["id"]: 0 for q in discovery["questions"]}
    counters = discovery["counters"]
    counters["questions_used"] = len(entries)
    counters["query_seconds_used"] = min(sum(entries.values()), discovery["budget"]["query_seconds"])
    counters["time_exhausted"] = int(counters["query_seconds_used"] >= discovery["budget"]["query_seconds"])
    answers = {answer["question_id"]: answer for answer in discovery["graph_answers"]}
    for question in discovery["questions"]:
        if question["disposition"] == "pending":
            answer = answers.get(question["id"])
            if answer:
                question["disposition"] = {"supported": "source-supported", "contradicted": "contradicted", "inconclusive": "inconclusive"}[answer["disposition"]]
                question["reason_closed"] = answer["conclusion_effect"][:1000]
            else:
                question["disposition"] = "depth-limited" if counters["time_exhausted"] else "unavailable" if question["id"] in entries else "skipped"
                question["reason_closed"] = "Optional navigation was not relied upon; continue source-only."
    discovery["status"] = "sealed"


def build_plan(scan: Path, context: dict, index: dict, discovery: dict) -> dict:
    records = {r["id"]: r for r in index["records"]}
    primitives = {p["id"]: p for p in index["primitives"]}
    investigations = {q["id"]: q for q in discovery["investigation_questions"]}
    objectives = {o["id"]: o for o in discovery["attack_objectives"]}
    campaigns = []
    for offset, selection in enumerate(selected_candidates(index, discovery, limit=BUDGETS[context["depth"]]["max_campaigns"]), 1):
        selected = [primitives[pid] for pid in selection["primitive_ids"]]
        evidence = selection["starting_evidence"]
        files = sorted({file for rid in evidence for file in records[rid]["files"]})
        questions = []
        if context.get("codegraph_mode") == "enabled":
            project = Path(context.get("paths", {}).get("codegraph_project", "/nonexistent"))
            for rid in evidence:
                question = graph_question(records[rid], project)
                if question:
                    questions = [{"id": f"Q-{offset:03d}-1", **question}]
                    break
        investigation = investigations[selection["question_id"]]
        objective = objectives[selection["objective_id"]]
        hypothesis = investigation["security_question"]
        campaigns.append({"id": f"CAM-{offset:03d}", **selection,
                          "attacker_capability": "; ".join(
                              p["capability_gained"] if p["trust"] == "confirmed"
                              else "Unconfirmed source question: " + p["capability_gained"] for p in selected)
                              or "Not established; investigate attacker access from the cited source.",
                          "target_boundary": objective["resource_scope"],
                          "hypothesis": hypothesis, "source_files": files, "graph_questions": questions,
                          "graph_limitations": [] if questions else ["Optional graph navigation is disabled, unavailable or lacks a resolved source anchor; inspect source directly."],
                          "validation_method": "Read the complete source path, verify preconditions, alternate paths and mitigations; use safe reproduction only when configured containment is available.",
                          "stop_conditions": ["Close when source disproves reachability or a required precondition.", "Use needs_environment when deployment-only evidence is required."],
                          "expected_added_value": "A source-backed root cause, impact expansion, boundary transition or reasoned closure; graph navigation alone is not proof.",
                          "disposition": "unresolved"})
    triage = {item["evidence_id"]: item for item in discovery.get("scanner_triage", [])}
    accounting = []
    for rec in records.values():
        if rec["source_kind"] not in {"sca", "secret"}:
            continue
        owners = [c["id"] for c in campaigns if rec["id"] in c["starting_evidence"]]
        item = triage.get(rec["id"], {})
        accounting.append({"evidence_id": rec["id"], "campaign_ids": owners,
                           "status": "selected" if owners else "contradicted" if item.get("status") == "contradicted" else "deferred",
                           "reason": "Selected for source triage; no credential or dependency capability assumed." if owners else item.get("reason") if item.get("status") in {"contradicted", "deferred"} else "Finite phase capacity prioritized distinct source questions; this observation remains uninvestigated."})
    dispositions = []
    relationship_gaps = {rid for rel in discovery["relationships"] if rel.get("evidence_quality") == "evidence_limited" for rid in rel["evidence_ids"]}
    relationship_gaps.update(rid for question in discovery["questions"] if question.get("evidence_quality") == "evidence_limited" for rid in question["evidence_ids"])
    selected_priorities = sorted({priority(records[rid]) for campaign in campaigns for rid in campaign["starting_evidence"]})
    for rec in records.values():
        if rec["id"] not in relationship_gaps and (rec["source_kind"] in {"sca", "secret", "tool_warning"} or
                (rec["disposition"] not in {"unresolved", "evidence_limited", "needs_environment"} and rec.get("objective_id") and rec.get("question_id"))):
            continue
        owners = [campaign["id"] for campaign in campaigns if rec["id"] in campaign["starting_evidence"]]
        anchored = bool(rec["files"])
        bound = bool(rec.get("objective_id") and rec.get("question_id"))
        dispositions.append({
            "evidence_id": rec["id"], "campaign_ids": owners,
            "status": "selected" if owners else "evidence_limited",
            "missing_fact": f"Establish source support, attacker reachability and authority for: {rec['summary']} Owning evidence: {rec['artifact_ref']}." if bound else f"No supported objective/question binding. Inspect {rec['artifact_ref']} for actor control, desired effect and a concrete proof obligation.",
            "attempted_resolution": "Deterministic source-anchor and reference resolution only; no investigator source review is claimed.",
            "next_action": "Inspect the owning record and its exact evidence diagnostics in the assigned campaign." if owners else "Establish the missing source anchor and attacker path before claiming eligibility." if not anchored else "Review the missing proof in a future authorized allocation; do not reopen sealed work.",
            "deferral_reason": "" if owners else "No established source anchor; risk-weighted deferral prevents inventing an attacker capability from an unsupported assertion." if not anchored else "No source-backed objective/question definition; accountable lead is not scheduling authority." if not bound else f"Finite {context['depth']} campaign allocation {BUDGETS[context['depth']]} selected other distinct source questions under risk and actor/subsystem fairness.",
            "priority_reason": f"Source-authored risk rank {priority(rec)}; selected ranks {selected_priorities}. Evidence formatting is not a ranking input."})
    return {"schema_version": "2.0", "run_id": context["run_id"], "depth": context["depth"],
            **({"assessment_context": assessment_ref(context)} if assessment_ref(context) else {}),
            "budget": dict(BUDGETS[context["depth"]]), "campaigns": campaigns,
            "attack_objectives": discovery["attack_objectives"],
            "investigation_questions": discovery["investigation_questions"],
            "question_dispositions": question_dispositions(index, discovery, campaigns),
            "selection_revisions": [], "scanner_accounting": accounting,
            "evidence_dispositions": dispositions,
            "evidence_quality": discovery.get("evidence_quality", summarize([])),
            "discovery_ref": "campaign-planning/discovery.json",
            "coverage": {"evidence_records": len(records), "primitives": len(primitives), "campaigns": len(campaigns)},
            "warnings": discovery["graph_limitations"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--prepare-discovery", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    context = _load(args.context or root / ".harness/audit-context.json")
    require_active_phase(args.scan_base, context, "campaign-planning")
    scan = args.scan_base.resolve()
    target = Path(context.get("source_root") or context["repo_path"])
    index = _load(scan / "campaign-planning/evidence-index.json")
    _schema(index, "evidence-index.schema.json")
    discovery_path = scan / "campaign-planning/discovery.json"
    plan_path = scan / "campaign-planning/campaign-plan.json"
    if plan_path.exists():
        validate_selection(scan, target, context, _load(plan_path))
        if args.prepare_discovery:
            raise ValueError("cannot prepare discovery after final selection")
        print(plan_path)
        return 0
    if not discovery_path.exists():
        write(discovery_path, prepare_discovery(scan, context, index))
    discovery = validate_discovery(scan, target, context, require_sealed=False)
    if args.prepare_discovery:
        if discovery["status"] != "prepared":
            raise ValueError("cannot reopen sealed discovery")
        print(discovery_path)
        return 0
    if discovery["status"] != "sealed":
        close_discovery(scan, discovery)
        write(discovery_path, discovery)
        validate_discovery(scan, target, context)
    doc = build_plan(scan, context, index, discovery)
    _schema(doc, "campaign-plan.schema.json")
    validate_selection(scan, target, context, doc)
    write(plan_path, doc)
    counts = {lane: sum(c["lane"] == lane for c in doc["campaigns"])
              for lane in ("primitive_led", "gap_driven", "direct_validation")}
    unresolved = sum(row["status"] == "evidence_limited" for row in doc["evidence_dispositions"])
    (scan / "campaign-planning/summary.md").write_text("# Red-Team Campaign Planning\n\n"
        + f"- Total campaigns: {len(doc['campaigns'])}/{doc['budget']['max_campaigns']}\n"
        + "\n".join(f"- {lane}: {count}" for lane, count in counts.items())
        + f"\n- Admitted questions not allocated: {sum(row['status'] != 'selected' for row in doc['question_dispositions'])}"
        + f"\n- Unresolved source records not allocated: {unresolved}\n"
        + "- Lanes describe work; they do not reserve or cap capacity.\n"
        + "- Zero campaigns means no eligible allocated work, not a clean application.\n")
    manifest = {"phase": "campaign-planning", "status": "ok", "started_at": now(), "completed_at": now(),
                "inputs": ["repo-context/security-surfaces.json", "tool-collection/collection.json", "tool-collection/wraith-receipt.json", "tool-collection/poltergeist-receipt.json", "sast/verified-findings.json", "sast/dropped-findings.json", "sast/validation-results.json", "sast/coverage-ledger.json", "sast/hunt-plan.json", "sast/threat-model.json", "sast/wishlist.json"],
                "outputs": ["campaign-planning/evidence-index.json", "campaign-planning/discovery.json", "campaign-planning/campaign-plan.json", "campaign-planning/summary.md"],
                "coverage": {**doc["coverage"], **counts}, "tool_versions": {"planner": "deterministic-v2", "primary_model": str(context.get("model", "unknown"))},
                "warnings": doc["warnings"], "errors": []}
    write(scan / "campaign-planning/phase-manifest.json", manifest)
    print(plan_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
