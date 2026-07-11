#!/usr/bin/env python3
"""Return the resumable v2 run matching the complete audit identity, if any."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


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
    parser.add_argument("verifier_model")
    args = parser.parse_args()

    context = load(args.context)
    if context is None or context.get("schema_version") != "2.0" or context.get("workflow") != "canonical-redteam-v2":
        return 0
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

    scan_base = Path(str(context.get("scan_base", "")))
    manifest = load(scan_base / "run-manifest.json")
    ledger = load(scan_base / "task-ledger.json")
    if manifest is None or ledger is None:
        return 0
    if manifest.get("workflow") != "canonical-redteam-v2":
        return 0
    if str(manifest.get("model", "")) != args.model.strip():
        return 0
    if str(manifest.get("verifier_model", "")) != args.verifier_model.strip():
        return 0
    if manifest.get("status") in {"complete", "failed"}:
        return 0

    phases = manifest.get("phases", {})
    running_phases = [phase for phase, status in phases.items() if status == "running"] if isinstance(phases, dict) else []
    tasks = ledger.get("tasks", []) if isinstance(ledger.get("tasks"), list) else []
    task_ids = [str(item.get("id")) for item in tasks if isinstance(item, dict)]
    running_tasks = [item for item in tasks if isinstance(item, dict) and item.get("status") == "running"]
    if len(task_ids) != len(set(task_ids)) or len(running_phases) > 1 or len(running_tasks) > 1:
        return 0
    if any(task_id not in TASK_PHASE for task_id in task_ids):
        return 0
    if any(int(item.get("attempts", 0)) > 2 for item in tasks if isinstance(item, dict)):
        return 0
    if running_tasks:
        running = running_tasks[0]
        if len(running_phases) != 1 or TASK_PHASE.get(str(running.get("id"))) != running_phases[0] or running.get("phase") != running_phases[0]:
            return 0
    elif running_phases:
        return 0
    for item in tasks:
        if not isinstance(item, dict) or item.get("status") not in {"ok", "degraded", "shallow"}:
            continue
        ref = item.get("artifact")
        if not isinstance(ref, str) or not ref or Path(ref).is_absolute():
            return 0
        artifact = (scan_base / ref).resolve()
        try:
            artifact.relative_to(scan_base.resolve())
        except ValueError:
            return 0
        if not artifact.is_file():
            return 0

    run_id = str(context.get("run_id", ""))
    if run_id and str(scan_base):
        print(f"{run_id}\t{scan_base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
