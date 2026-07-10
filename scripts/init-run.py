#!/usr/bin/env python3
"""Initialize or resume one isolated VulnOps v2 run atomically."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


PHASES = (
    "recon",
    "sca",
    "secrets",
    "sast",
    "intelligence",
    "triage",
    "intrusion",
    "final-reconciliation",
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
    parser.add_argument("--model", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    root = args.harness_root.resolve()
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
    else:
        created = now()
        atomic_write(
            manifest_path,
            {
                "schema_version": "2.0",
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
                "model": args.model,
                "model_diversity": False,
                "reproduction_mode": args.reproduction_mode,
                "phases": {phase: "pending" for phase in PHASES},
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
        "sca": scan / "sca",
        "sca_raw_advisories": scan / "sca/raw-advisories.json",
        "sast": scan / "sast",
        "sast_threat_model": scan / "sast/threat-model.json",
        "sast_threat_model_md": scan / "sast/threat-model.md",
        "sast_task_manifest": scan / "sast/task-manifest.json",
        "sast_hunt_plan": scan / "sast/hunt-plan.json",
        "sast_decompose_md": scan / "sast/decompose.md",
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
        "sast_fixes": scan / "sast/fixes",
        "secrets": scan / "secrets",
        "secrets_redacted_candidates": scan / "secrets/redacted-candidates.json",
        "intelligence": scan / "intelligence",
        "intelligence_evidence_corpus": scan / "intelligence/evidence-corpus.json",
        "intelligence_attack_surface_map": scan / "intelligence/attack-surface-map.json",
        "intelligence_intel_plan": scan / "intelligence/intel-plan.json",
        "intelligence_cards": scan / "intelligence/investigation-cards.json",
        "intelligence_coverage_gaps": scan / "intelligence/coverage-gaps.json",
        "intelligence_rule_gaps": scan / "intelligence/rule-gaps.json",
        "intelligence_codegraph_runs": scan / "intelligence/codegraph-runs",
        "triage": scan / "triage",
        "intrusion_seeds": scan / "triage/intrusion-seeds.json",
        "report": scan / "report",
        "intrusion": scan / "intrusion",
        "intrusion_findings": scan / "intrusion/findings",
        "intrusion_enrichment": scan / "intrusion/enrichment.json",
        "intrusion_plan": scan / "intrusion/intrusion-plan.json",
        "intrusion_codegraph_runs": scan / "intrusion/codegraph-runs",
        "final_reconciliation": scan / "final-reconciliation",
        "final_reconciliation_candidates": scan / "final-reconciliation/candidates.json",
        "final_verification": scan / "final-verification",
        "final_verification_results": scan / "final-verification/results",
        "final_verified_findings": scan / "final-verification/findings.json",
        "final_report_md": scan / "report/security-report.md",
        "final_report_json": scan / "report/security-report.json",
        "run_manifest": manifest_path,
        "task_ledger": ledger_path,
        "codegraph_index_dir": scan / ".codegraph",
    }
    tools = {
        "wraith": root / "bins/wraith",
        "poltergeist": root / "bins/poltergeist",
        "omp": root / "bins/omp",
        "osv_scanner": root / "bins/osv-scanner",
        "codegraph": root / "bins/codegraph",
        "run_wraith": root / "scripts/run-wraith.sh",
        "run_poltergeist": root / "scripts/run-poltergeist.sh",
        "run_codegraph": root / "scripts/run-codegraph.sh",
        "codegraph_context": root / "scripts/codegraph-context.sh",
        "build_intelligence": root / "scripts/build-intelligence.py",
        "build_intrusion_plan": root / "scripts/build-intrusion-plan.py",
        "finalize_intrusion": root / "scripts/finalize-intrusion.py",
        "validate_json": root / "scripts/validate-json.py",
        "target_fingerprint": root / "scripts/target-fingerprint.py",
        "build_hunt_plan": root / "scripts/build-hunt-plan.py",
        "finalize_sast": root / "scripts/finalize-sast.py",
        "safe_reproduction": root / "scripts/run-safe-reproduction.sh",
        "finalize_verification": root / "scripts/finalize-verification.py",
        "render_report": root / "scripts/render-report.py",
        "update_run_state": root / "scripts/update-run-state.py",
    }
    context = {
        "schema_version": "2.0",
        "run_id": args.run_id,
        "repo_name": args.repo_name,
        "remote_url": args.remote_url,
        "repo_id": args.repo_id,
        "short_sha": args.commit,
        "depth": args.depth,
        "target_fingerprint": args.target_fingerprint,
        "model": args.model,
        "model_diversity": False,
        "reproduction_mode": args.reproduction_mode,
        "harness_root": str(root),
        "repo_path": str(repo),
        "repo_scan_root": str(scan.parent.parent),
        "scan_base": str(scan),
        "paths": {key: str(value) for key, value in paths.items()},
        "tools": {key: str(value) for key, value in tools.items()},
        "created_at": now(),
    }
    atomic_write(root / ".harness/audit-context.json", context)
    print(json.dumps(context, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
