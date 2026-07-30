#!/usr/bin/env python3
"""Initialize or resume one isolated VulnOps v2 run atomically."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from harness_contract import harness_contract_sha256, resolved_sast_budget
from model_identity import model_diversity
from offline_package import network_identity, package_identity


PHASES = (
    "recon",
    "tool-collection",
    "sast",
    "campaign-planning",
    "intrusion",
    "synthesis",
    "final-verification",
    "report",
)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness-root", type=Path, required=True)
    parser.add_argument("--repo-path", type=Path, required=True)
    parser.add_argument("--scan-base", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repo-name", required=True)
    parser.add_argument("--remote-url", required=True)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--depth", choices=("quick", "balanced", "full"), required=True)
    parser.add_argument("--target-fingerprint", required=True)
    parser.add_argument("--reproduction-mode", choices=("off", "safe"), required=True)
    parser.add_argument(
        "--network-mode",
        choices=("enforced", "policy_only"),
        default=os.environ.get("VULNOPS_LINUX_AGENT_EGRESS", "enforced"),
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--orchestrator-model", required=True)
    parser.add_argument("--task-model", required=True)
    parser.add_argument("--slow-model", required=True)
    parser.add_argument("--smol-model", required=True)
    parser.add_argument("--verifier-model", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    model = args.model.strip()
    verifier_model = args.verifier_model.strip()
    model_roles = {
        "orchestrator": args.orchestrator_model.strip(),
        "task": args.task_model.strip(),
        "slow": args.slow_model.strip(),
        "smol": args.smol_model.strip(),
    }
    if not model or not verifier_model or any(not value for value in model_roles.values()):
        parser.error("model selectors and model roles must be non-empty")
    diversity = model_diversity(model, verifier_model)

    root = args.harness_root.resolve()
    contract_sha256 = harness_contract_sha256(root)
    sast_budget = resolved_sast_budget(args.depth)
    offline_package = package_identity(root)
    network = network_identity(args.network_mode)
    repo = args.repo_path.resolve()
    scan = args.scan_base.resolve()
    try:
        scan.relative_to((root / "scans").resolve())
    except ValueError:
        parser.error("scan base must be under the harness scans directory")

    manifest_path = scan / "run-manifest.json"
    ledger_path = scan / "task-ledger.json"
    if args.resume:
        if not manifest_path.is_file() or not ledger_path.is_file():
            parser.error("resume requested without an existing run manifest and task ledger")
        try:
            existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"cannot read resume manifest: {exc}")
        if existing_manifest.get("harness_contract_sha256") != contract_sha256:
            parser.error("resume manifest was created by a different harness contract")
        if existing_manifest.get("sast_budget") != sast_budget:
            parser.error("resume manifest was created with a different SAST budget")
        if existing_manifest.get("offline_package") != offline_package:
            parser.error("resume manifest was created from a different offline package")
        if existing_manifest.get("network") != network:
            parser.error("resume manifest was created with a different agent egress policy")
    else:
        created = now()
        atomic_write(
            manifest_path,
            {
                "schema_version": "2.0",
                "workflow": "canonical-redteam-v2",
                "run_id": args.run_id,
                "repo_id": args.repo_id,
                "repository": args.repo_name,
                "commit": args.commit,
                "depth": args.depth,
                "status": "initialized",
                "scan_base": str(scan),
                "created_at": created,
                "updated_at": created,
                "target_fingerprint": args.target_fingerprint,
                "harness_contract_sha256": contract_sha256,
                "sast_budget": sast_budget,
                "model": model,
                "model_roles": model_roles,
                "verifier_model": verifier_model,
                "model_diversity": diversity,
                "reproduction_mode": args.reproduction_mode,
                "network": network,
                "offline_package": offline_package,
                "phases": {phase: "pending" for phase in PHASES},
                "phase_seals": {},
                "recovery_count": 0,
                "recovery_history": [],
            },
        )
        atomic_write(
            ledger_path,
            {"schema_version": "2.0", "run_id": args.run_id, "tasks": []},
        )

    paths = {
        "repo_context": scan / "repo-context",
        "repo_md": scan / "repo-context/repo.md",
        "repo_context_json": scan / "repo-context/repo-context.json",
        "security_surfaces_json": scan / "repo-context/security-surfaces.json",
        "tool_collection": scan / "tool-collection",
        "sca_advisories": scan / "tool-collection/sca-advisories.json",
        "sca_receipt": scan / "tool-collection/wraith-receipt.json",
        "secrets_redacted_candidates": scan / "tool-collection/secrets-redacted.json",
        "secrets_receipt": scan / "tool-collection/poltergeist-receipt.json",
        "dependency_limitations": scan / "tool-collection/dependency-limitations.json",
        "sast": scan / "sast",
        "sast_threat_model": scan / "sast/threat-model.json",
        "sast_threat_model_md": scan / "sast/threat-model.md",
        "sast_hunt_plan": scan / "sast/hunt-plan.json",
        "sast_hunt_tasks": scan / "sast/hunt-tasks",
        "sast_deepdive": scan / "sast/deepdive",
        "sast_verify": scan / "sast/verify",
        "sast_raw_findings": scan / "sast/raw-findings.json",
        "sast_verified_findings": scan / "sast/verified-findings.json",
        "sast_dropped_findings": scan / "sast/dropped-findings.json",
        "sast_coverage_ledger": scan / "sast/coverage-ledger.json",
        "sast_dedup_clusters": scan / "sast/dedup-clusters.json",
        "sast_validation_results": scan / "sast/validation-results.json",
        "sast_wishlist": scan / "sast/wishlist.json",
        "sast_reproduction": scan / "sast/reproduction",
        "campaign_planning": scan / "campaign-planning",
        "evidence_index": scan / "campaign-planning/evidence-index.json",
        "campaign_plan": scan / "campaign-planning/campaign-plan.json",
        "report": scan / "report",
        "intrusion": scan / "intrusion",
        "intrusion_results_dir": scan / "intrusion/results",
        "intrusion_results": scan / "intrusion/intrusion-results.json",
        "intrusion_codegraph_runs": scan / "intrusion/codegraph-runs",
        "synthesis": scan / "synthesis",
        "synthesis_findings": scan / "synthesis/findings.json",
        "final_verification": scan / "final-verification",
        "final_verification_results": scan / "final-verification/results",
        "final_verified_findings": scan / "final-verification/findings.json",
        "final_report_md": scan / "report/security-report.md",
        "final_report_json": scan / "report/security-report.json",
        "run_manifest": manifest_path,
        "task_ledger": ledger_path,
        "codegraph_runtime": root / ".harness/codegraph" / args.run_id,
        "codegraph_project": root / ".harness/codegraph" / args.run_id / "project",
    }
    tools = {
        "wraith": root / "bins/wraith",
        "poltergeist": root / "bins/poltergeist",
        "omp": root / "bins/omp",
        "osv_scanner": root / "bins/osv-scanner",
        "codegraph": root / "bins/codegraph",
        "run_wraith": root / "scripts/run-wraith.sh",
        "run_poltergeist": root / "scripts/run-poltergeist.sh",
        "collect_tools": root / "scripts/collect-tools.py",
        "finalize_tool_collection": root / "scripts/finalize-tool-collection.py",
        "run_codegraph": root / "scripts/run-codegraph.sh",
        "normalize_wraith": root / "scripts/normalize-wraith.py",
        "normalize_poltergeist": root / "scripts/normalize-poltergeist.py",
        "codegraph_adapter": root / "scripts/codegraph-adapter.py",
        "build_evidence_index": root / "scripts/build-evidence-index.py",
        "build_campaign_plan": root / "scripts/build-campaign-plan.py",
        "finalize_intrusion": root / "scripts/finalize-intrusion.py",
        "finalize_synthesis": root / "scripts/finalize-synthesis.py",
        "empty_synthesis": root / "scripts/empty-synthesis.py",
        "validate_json": root / "scripts/validate-json.py",
        "target_fingerprint": root / "scripts/target-fingerprint.py",
        "build_hunt_plan": root / "scripts/build-hunt-plan.py",
        "sast_contract": root / "scripts/sast_contract.py",
        "harness_contract": root / "scripts/harness_contract.py",
        "finalize_recon": root / "scripts/finalize-recon.py",
        "finalize_sast": root / "scripts/finalize-sast.py",
        "safe_reproduction": root / "scripts/run-safe-reproduction.sh",
        "finalize_verification": root / "scripts/finalize-verification.py",
        "render_report": root / "scripts/render-report.py",
        "update_run_state": root / "scripts/update-run-state.py",
        "osv_snapshot": root / "scripts/osv_snapshot.py",
        "offline_package": root / "scripts/offline_package.py",
    }
    context = {
        "schema_version": "2.0",
        "workflow": "canonical-redteam-v2",
        "run_id": args.run_id,
        "repo_name": args.repo_name,
        "remote_url": args.remote_url,
        "repo_id": args.repo_id,
        "short_sha": args.commit,
        "depth": args.depth,
        "target_fingerprint": args.target_fingerprint,
        "harness_contract_sha256": contract_sha256,
        "sast_budget": sast_budget,
        "model": model,
        "model_roles": model_roles,
        "verifier_model": verifier_model,
        "model_diversity": diversity,
        "reproduction_mode": args.reproduction_mode,
        "network": network,
        "offline_package": offline_package,
        "recovery_count": int(existing_manifest.get("recovery_count", 0)) if args.resume else 0,
        "last_recovery": (existing_manifest.get("recovery_history") or [None])[-1] if args.resume else None,
        "launcher_session_id": os.environ.get("VULNOPS_LAUNCHER_SESSION_ID"),
        "harness_root": str(root),
        "repo_path": str(repo),
        "repo_scan_root": str(scan.parent.parent),
        "scan_base": str(scan),
        "paths": {key: str(value) for key, value in paths.items()},
        "tools": {key: str(value) for key, value in tools.items()},
        "orchestration": {
            "completion_signal": "job",
            "phase_timeout_seconds": {
                "recon": 900,
                "tool-collection": 900,
                "sast": {"quick": 3600, "balanced": 7200, "full": 14400},
                "campaign-planning": 1200,
                "intrusion": {"quick": 1800, "balanced": 3600, "full": 7200},
                "synthesis": 1200,
                "final-verification": {"quick": 2700, "balanced": 5400, "full": 10800},
                "report": 600,
            },
        },
        "created_at": now(),
    }
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    atomic_write(context_path, context)
    print(json.dumps(context, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
