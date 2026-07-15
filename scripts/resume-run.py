#!/usr/bin/env python3
"""Return the matching incomplete v2 run and whether it needs recovery."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness_contract import harness_contract_sha256, resolved_sast_budget


TASK_PHASE = {
    "Recon": "recon", "ToolCollection": "tool-collection", "SASTLead": "sast",
    "CampaignPlanning": "campaign-planning", "Intrusion": "intrusion",
    "Synthesis": "synthesis", "FinalVerification": "final-verification", "Report": "report",
}


def load(path: Path) -> dict | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("context", type=Path)
    parser.add_argument("repo_path")
    parser.add_argument("commit")
    parser.add_argument("depth")
    parser.add_argument("target_fingerprint")
    parser.add_argument("reproduction_mode")
    parser.add_argument("model")
    parser.add_argument("orchestrator_model")
    parser.add_argument("task_model")
    parser.add_argument("slow_model")
    parser.add_argument("smol_model")
    parser.add_argument("verifier_model")
    args = parser.parse_args()

    context = load(args.context)
    if context is None or context.get("schema_version") != "2.0" or context.get("workflow") != "canonical-redteam-v2":
        return 0
    root = Path(__file__).resolve().parent.parent
    current_contract = harness_contract_sha256(root)
    current_budget = resolved_sast_budget(args.depth)
    identity = (
        ("repo_path", args.repo_path),
        ("short_sha", args.commit),
        ("depth", args.depth),
        ("target_fingerprint", args.target_fingerprint),
        ("reproduction_mode", args.reproduction_mode),
        ("model", args.model.strip()),
    )
    if any(str(context.get(key)) != expected for key, expected in identity):
        return 0
    if str(context.get("verifier_model", "")) != args.verifier_model.strip():
        return 0
    expected_roles = {
        "orchestrator": args.orchestrator_model.strip(),
        "task": args.task_model.strip(),
        "slow": args.slow_model.strip(),
        "smol": args.smol_model.strip(),
    }
    if context.get("model_roles") != expected_roles:
        return 0

    scan_base = Path(str(context.get("scan_base", "")))
    try:
        scan_base.resolve().relative_to((root / "scans").resolve())
    except ValueError:
        return 0
    manifest = load(scan_base / "run-manifest.json")
    ledger = load(scan_base / "task-ledger.json")
    if manifest is None or ledger is None:
        return 0
    if manifest.get("run_id") != context.get("run_id") or ledger.get("run_id") != context.get("run_id"):
        return 0
    if manifest.get("workflow") != "canonical-redteam-v2":
        return 0
    manifest_identity = (
        ("commit", args.commit),
        ("depth", args.depth),
        ("target_fingerprint", args.target_fingerprint),
        ("reproduction_mode", args.reproduction_mode),
    )
    if any(str(manifest.get(key)) != expected for key, expected in manifest_identity):
        return 0
    if str(manifest.get("model", "")) != args.model.strip():
        return 0
    if str(manifest.get("verifier_model", "")) != args.verifier_model.strip():
        return 0
    if manifest.get("model_roles") != expected_roles:
        return 0
    if manifest.get("status") == "complete":
        return 0

    phases = manifest.get("phases", {})
    phases_valid = isinstance(phases, dict)
    if not phases_valid:
        phases = {}
    running_phases = [phase for phase, status in phases.items() if status == "running"]
    tasks = ledger.get("tasks", []) if isinstance(ledger.get("tasks"), list) else []
    task_ids = [str(item.get("id")) for item in tasks if isinstance(item, dict)]
    running_tasks = [item for item in tasks if isinstance(item, dict) and item.get("status") == "running"]
    inconsistent = (
        not phases_valid
        or set(phases) != set(TASK_PHASE.values())
        or len(task_ids) != len(set(task_ids))
        or len(running_phases) > 1
        or len(running_tasks) > 1
        or any(task_id not in TASK_PHASE for task_id in task_ids)
    )
    interrupted = bool(running_phases or running_tasks)
    for item in tasks:
        if not isinstance(item, dict) or item.get("status") not in {"ok", "degraded", "shallow"}:
            continue
        ref = item.get("artifact")
        if not isinstance(ref, str) or not ref or Path(ref).is_absolute():
            inconsistent = True
            continue
        artifact = (scan_base / ref).resolve()
        try:
            artifact.relative_to(scan_base.resolve())
        except ValueError:
            inconsistent = True
        if not artifact.is_file():
            inconsistent = True

    run_id = str(context.get("run_id", ""))
    if run_id and str(scan_base):
        needs_recovery = (
            manifest.get("status") == "failed"
            or any(status == "failed" for status in phases.values())
            or interrupted
            or inconsistent
            or context.get("harness_contract_sha256") != current_contract
            or manifest.get("harness_contract_sha256") != current_contract
            or context.get("sast_budget") != current_budget
            or manifest.get("sast_budget") != current_budget
        )
        print(f"{run_id}\t{scan_base}\t{'recover' if needs_recovery else 'resume'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
