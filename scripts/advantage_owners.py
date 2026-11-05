"""Explicit linked owner admission for existing containment and graph backends."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

import advantage_contract as contract
from advantage_actions import derived_root, validate_patch


def owner(context: dict, phase: str, owner_id: str, question_id: str, *, active: bool = True) -> dict:
    if context.get("execution_kind") != "advantage":
        raise ValueError("linked adapter requires an Advantage execution")
    for identifier in (owner_id, question_id):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", identifier) or ".." in identifier:
            raise ValueError("unsafe linked owner or question identifier")
    base = Path(context["scan_base"])
    if active:
        contract.live_call(context, phase)
    if phase == "gap-exploration":
        if context["mode"] == "actions":
            raise ValueError("actions-only execution cannot own gap graph work")
        from gap_exploration_contract import graph_question
        question = graph_question(context, owner_id, question_id, active=active)
        return {"source_view": question["source_view"], "owner_ref": question["owner_ref"],
                "graph_questions": [question]}
    if phase == "handoff":
        if context["mode"] != "actions" or owner_id != "AdvantageHandoff":
            raise ValueError("only actions-only assessments may execute under handoff")
        if question_id not in context["options"].get("verify_fix", []) and not (question_id == "patch-risk" and context["options"].get("assess_patch_risk")):
            raise ValueError("handoff question is not an explicitly selected assessment")
        return {"owner_ref": "handoff/action-draft.json", "question_id": question_id}
    if phase != "investigation" or context["mode"] == "actions":
        raise ValueError("linked experiments/graphs require ordinary investigation or selected action handoff")
    packet_path = contract.inside(base, base / "investigation/packets" / (owner_id + ".json"))
    packet = contract.load(packet_path)
    contract.validate_schema(packet, "advantage-packet")
    if active:
        from advantage_pipeline import packets
        if packets(context).get(owner_id) != packet:
            raise ValueError("linked owner packet differs from canonical plan/wave closure")
    if packet["run_id"] != context["run_id"] or packet["assignment"]["task_id"] != owner_id:
        raise ValueError("linked owner packet belongs to another execution or task")
    assignment = packet["assignment"]
    ids = list(assignment["question_ids"])
    ids.extend(item["id"] for item in assignment.get("graph_questions", []))
    if question_id not in ids:
        raise ValueError("question is not allocated to this linked owner")
    return {**assignment, "owner_ref": packet_path.relative_to(base).as_posix()}


def validate_experiment(context: dict, request: dict, *, active: bool = True) -> tuple[Path, None]:
    contract.validate_schema(request, "advantage-experiment")
    assignment = owner(context, request["owner_phase"], request["owner_id"], request["question_id"], active=active)
    if active and (not request.get("attempt_id") or request["attempt_id"] != context.get("attempt_id")):
        raise ValueError("experiment does not belong to the active attempt")
    if request["owner_ref"] != assignment["owner_ref"] or request["baseline_execution_id"] != context["source_run_id"]:
        raise ValueError("experiment owner or baseline reference mismatch")
    if request["owner_phase"] == "investigation" and request["source_view"] != assignment["source_view"]:
        raise ValueError("experiment view differs from immutable owner assignment")
    if request["source_view"] == "derived":
        if active:
            validate_patch(context)
        if not context.get("patch_binding"):
            raise ValueError("derived experiment requires a bound patch")
        source = derived_root(context)
    else:
        source = Path(context["source_root"]) if context.get("source_root") else Path(".")
    from advantage_pipeline import refs, source_context
    if active:
        refs(source_context(context, request["source_view"]), request["input_refs"])
    return source, None


def backend_context(context_path: Path, scan: Path, phase: str, workspace_id: str) -> dict:
    context = contract.load_context(context_path)
    if Path(context["scan_base"]).resolve() != scan.resolve():
        raise ValueError("linked reproduction scan mismatch")
    prefix = "experiment-" + phase + "-"
    if not workspace_id.startswith(prefix):
        raise ValueError("Advantage reproduction requires a reserved experiment request")
    experiment_id = workspace_id[len(prefix):]
    request_path = contract.inside(scan, scan / phase / "experiments" / experiment_id / "request.json")
    request = contract.load(request_path)
    source, _ = validate_experiment(context, request)
    operation = contract.live_call(context, phase).get("operation", {})
    if (operation.get("kind") != "experiment" or operation.get("phase") != phase
            or operation.get("owner_id") != request["owner_id"] or operation.get("question_id") != request["question_id"]
            or operation.get("request_ref") != request_path.relative_to(scan).as_posix()
            or operation.get("request_sha256") != contract.sha256_file(request_path)):
        raise ValueError("linked containment requires its immutable native experiment allocation")
    return {"repo_path": str(source), "run_id": context["run_id"],
            "reproduction_mode": context["reproduction_mode"], **context["experiment_budget"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("context", type=Path)
    parser.add_argument("scan", type=Path)
    parser.add_argument("phase")
    parser.add_argument("workspace_id")
    args = parser.parse_args()
    try:
        value = backend_context(args.context, args.scan, args.phase, args.workspace_id)
        print("\t".join(str(value[key]) for key in ("repo_path", "run_id", "reproduction_mode",
                                                    "timeout_seconds", "cpu_seconds", "memory_mb", "max_processes", "max_output_kb")))
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
