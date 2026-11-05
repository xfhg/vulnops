#!/usr/bin/env python3
"""Initialize or resume one isolated VulnOps V5 run atomically."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from codegraph_setup import OPTIONAL_FAILURE, run_setup_command
from harness_contract import resolved_sast_budget, resolved_intrusion_budget, resolved_experiment_budget, resolved_recon_timeout, resolved_gap_exploration_budget
from run_lifecycle import AUDIT_PHASE_DIRS, audit_phases, claim_run, normalize_record, run_status, start_attempt, state_lock
from model_routing import audit_routing, load_routing
from offline_package import network_identity, package_identity


PHASES = tuple(AUDIT_PHASE_DIRS)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)

def repository_identity(args: argparse.Namespace, source_root: Path) -> list[dict[str, str]]:
    if args.repositories_file is None:
        repositories = [
            {
                "name": args.repo_name,
                "path": ".",
                "remote_url": args.remote_url,
                "commit": args.commit,
            }
        ]
    else:
        try:
            inventory = json.loads(args.repositories_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read target repository inventory: {exc}") from exc
        if not isinstance(inventory, dict):
            raise ValueError("target repository inventory must contain an object")
        expected = {
            "source_root": str(source_root),
            "application_name": args.repo_name,
            "application_id": args.repo_id,
            "revision": args.commit,
            "remote_url": args.remote_url,
        }
        if any(str(inventory.get(key)) != value for key, value in expected.items()):
            raise ValueError("target repository inventory differs from the requested application identity")
        repositories = inventory.get("repositories")
        if not isinstance(repositories, list) or not repositories:
            raise ValueError("target repository inventory must contain at least one repository")

    normalized: list[dict[str, str]] = []
    paths: set[str] = set()
    for item in repositories:
        if not isinstance(item, dict):
            raise ValueError("target repository inventory contains a non-object entry")
        row = {key: str(item.get(key, "")).strip() for key in ("name", "path", "remote_url", "commit")}
        if any(not row[key] for key in row):
            raise ValueError("target repository identity fields must be non-empty")
        relative = PurePosixPath(row["path"])
        if row["path"] != "." and (relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts)):
            raise ValueError(f"unsafe target repository path: {row['path']}")
        repository_root = (source_root / row["path"]).resolve()
        try:
            repository_root.relative_to(source_root)
        except ValueError as exc:
            raise ValueError(f"target repository path escapes the application source root: {row['path']}") from exc
        if not repository_root.is_dir():
            raise ValueError(f"target repository path is unavailable: {row['path']}")
        if row["path"] in paths:
            raise ValueError(f"duplicate target repository path: {row['path']}")
        paths.add(row["path"])
        normalized.append(row)
    normalized.sort(key=lambda item: item["path"])
    return normalized




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
    parser.add_argument("--repositories-file", type=Path)
    parser.add_argument("--reproduction-mode", choices=("off", "safe"), required=True)
    parser.add_argument("--codegraph-mode", choices=("enabled", "disabled"), default="enabled")
    parser.add_argument("--codegraph-limitation", default="")
    parser.add_argument("--prepare-codegraph", action="store_true")
    parser.add_argument(
        "--network-mode",
        choices=("enforced", "policy_only"),
        default=os.environ.get("VULNOPS_LINUX_AGENT_EGRESS", "enforced"),
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    scan = args.scan_base.resolve()
    if not scan.is_relative_to((args.harness_root.resolve() / "scans").resolve()):
        parser.error("scan base must be under the harness scans directory")
    scan.mkdir(parents=True, exist_ok=True)
    try:
        claim_run(scan)
        with state_lock(scan):
            return initialize(args, parser)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


def initialize(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    root = args.harness_root.resolve()
    try:
        model_routing = audit_routing(load_routing(root))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    model = model_routing["controllers"]["audit"]
    verifier_model = model_routing["groups"]["final_verification"]
    sast_budget = resolved_sast_budget(args.depth)
    intrusion_budget = resolved_intrusion_budget(args.depth)
    experiment_budget = resolved_experiment_budget(args.depth)
    gap_exploration_budget = resolved_gap_exploration_budget(root, args.depth)
    offline_package = package_identity(root)
    network = network_identity(args.network_mode)
    repo = args.repo_path.resolve()
    scan = args.scan_base.resolve()
    try:
        repositories = repository_identity(args, repo)
        recon_timeout = resolved_recon_timeout(root, args.depth, len(repositories))
    except ValueError as exc:
        parser.error(str(exc))
    repository_inventory_verified = args.repositories_file is not None
    try:
        scan.relative_to((root / "scans").resolve())
    except ValueError:
        parser.error("scan base must be under the harness scans directory")

    manifest_path = scan / "run-manifest.json"
    ledger_path = scan / "task-ledger.json"
    pending_recovery = scan / ".recovery-invalidation.json"
    if pending_recovery.exists() or pending_recovery.is_symlink():
        parser.error("upstream invalidation is pending; repeat the explicit recover-run.py command first")
    if args.resume:
        try:
            existing_manifest = normalize_record(json.loads(manifest_path.read_text(encoding="utf-8")))
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            if existing_manifest.get("run_id") != args.run_id or ledger.get("run_id") != args.run_id:
                raise ValueError("run-manifest.json/task-ledger.json run_id differs from selected run")
            if run_status(existing_manifest.get("status")) == "complete":
                raise ValueError("completed run cannot be resumed")
            audit_phases(existing_manifest)
            if not isinstance(ledger.get("tasks"), list):
                raise ValueError("task-ledger.json tasks must be an array")
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            parser.error(f"cannot read selected run: {exc}")
    else:
        created = now()
        if manifest_path.exists() or ledger_path.exists():
            parser.error("selected run already exists; use --resume")
        existing_manifest = {
                "schema_version": "2.0",
                "workflow": "canonical-redteam-v2",
                "run_id": args.run_id,
                "repo_id": args.repo_id,
                "repository": args.repo_name,
                "commit": args.commit,
                "depth": args.depth,
                "status": "incomplete",
                "scan_base": str(scan),
                "created_at": created,
                "updated_at": created,
                "repositories": repositories,
                "repository_inventory_verified": repository_inventory_verified,
                "sast_budget": sast_budget,
                "intrusion_budget": intrusion_budget,
                "experiment_budget": experiment_budget,
                "model": model,
                "model_routing": model_routing,
                "verifier_model": verifier_model,
                "model_diversity": False,
                "reproduction_mode": args.reproduction_mode,
                "codegraph_mode": args.codegraph_mode,
                "network": network,
                "offline_package": offline_package,
                "phases": {phase: "pending" for phase in PHASES},
                "recovery_count": 0,
                "recovery_history": [],
            }
        ledger = {"schema_version": "2.0", "run_id": args.run_id, "tasks": []}

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
        "sast_experiments": scan / "sast/experiments",
        "campaign_planning": scan / "campaign-planning",
        "evidence_index": scan / "campaign-planning/evidence-index.json",
        "campaign_discovery": scan / "campaign-planning/discovery.json",
        "campaign_planning_codegraph_runs": scan / "campaign-planning/codegraph-runs",
        "campaign_plan": scan / "campaign-planning/campaign-plan.json",
        "report": scan / "report",
        "intrusion": scan / "intrusion",
        "intrusion_results_dir": scan / "intrusion/results",
        "intrusion_results": scan / "intrusion/intrusion-results.json",
        "intrusion_codegraph_runs": scan / "intrusion/codegraph-runs",
        "intrusion_waves": scan / "intrusion/waves",
        "intrusion_experiments": scan / "intrusion/experiments",
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
    if "gap-exploration" in existing_manifest["phases"]:
        paths["gap_exploration"] = scan / "gap-exploration"
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
        "build_intrusion_wave": root / "scripts/build-intrusion-wave.py",
        "prepare_gap_exploration": root / "scripts/prepare-gap-exploration.py",
        "gap_exploration_worker": root / "scripts/gap-exploration-worker.py",
        "finalize_gap_exploration": root / "scripts/finalize-gap-exploration.py",
        "finalize_synthesis": root / "scripts/finalize-synthesis.py",
        "empty_synthesis": root / "scripts/empty-synthesis.py",
        "validate_json": root / "scripts/validate-json.py",
        "build_hunt_plan": root / "scripts/build-hunt-plan.py",
        "sast_contract": root / "scripts/sast_contract.py",
        "finalize_recon": root / "scripts/finalize-recon.py",
        "finalize_sast": root / "scripts/finalize-sast.py",
        "safe_reproduction": root / "scripts/run-safe-reproduction.sh",
        "run_investigation_experiment": root / "scripts/run-investigation-experiment.py",
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
        "repositories": repositories,
        "repository_count": len(repositories),
        "repository_inventory_verified": repository_inventory_verified,
        "sast_budget": sast_budget,
        "intrusion_budget": intrusion_budget,
        "experiment_budget": experiment_budget,
        "model": model,
        "model_routing": model_routing,
        "verifier_model": verifier_model,
        "model_diversity": False,
        "reproduction_mode": args.reproduction_mode,
        "codegraph_mode": args.codegraph_mode,
        "codegraph_limitation": args.codegraph_limitation[:1000],
        "network": network,
        "offline_package": offline_package,
        "recovery_count": int(existing_manifest.get("recovery_count", 0)) if args.resume else 0,
        "last_recovery": (existing_manifest.get("recovery_history") or [None])[-1] if args.resume else None,
        "launcher_session_id": os.environ.get("VULNOPS_LAUNCHER_SESSION_ID"),
        "harness_root": str(root),
        "repo_path": str(repo),
        "source_root": str(repo),
        "repo_scan_root": str(scan.parent.parent),
        "scan_base": str(scan),
        "paths": {key: str(value) for key, value in paths.items()},
        "tools": {key: str(value) for key, value in tools.items()},
        "orchestration": {
            "completion_signal": "terminal_delivery",
            "phase_timeout_seconds": {
                # One deadline covers parallel research, consolidation and validation.
                "recon": recon_timeout,
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
    context["phases"] = dict(existing_manifest["phases"])
    if "gap-exploration" in existing_manifest["phases"]:
        context["gap_exploration_budget"] = gap_exploration_budget
        existing_manifest["gap_exploration_budget"] = gap_exploration_budget
        context["orchestration"]["phase_timeout_seconds"]["gap-exploration"] = gap_exploration_budget["timeout_seconds"]
    final_state = existing_manifest.get("phases", {}).get("final-verification")
    final_status = final_state.get("status") if isinstance(final_state, dict) else final_state
    if (final_status not in {"ok", "degraded", "skipped"} and args.prepare_codegraph
            and context["codegraph_mode"] == "enabled" and not context["codegraph_limitation"]):
        result = run_setup_command(
            ["bash", str(root / "scripts/setup-codegraph.sh")],
            env={**os.environ, "CODEGRAPH_TARGET_DIR": str(repo),
                 "CODEGRAPH_RUNTIME_DIR": str(paths["codegraph_runtime"])},
        )
        if result == OPTIONAL_FAILURE:
            context["codegraph_mode"] = "disabled"
            reason = "Codegraph preparation failed"
            receipt = paths["codegraph_runtime"] / "index-receipt.json"
            try:
                if receipt.resolve() == receipt and receipt.stat().st_size <= 16384:
                    failed = json.loads(receipt.read_text(encoding="utf-8"))
                    warnings = failed.get("warnings")
                    if (failed.get("status") == "failed" and isinstance(warnings, list)
                            and warnings and isinstance(warnings[0], str)):
                        reason += ": " + " ".join(warnings[0][:750].split())
            except (OSError, ValueError, AttributeError):
                pass  # A diagnostic receipt is not required for ordinary fallback.
            context["codegraph_limitation"] = reason + "; graph-assisted coverage was not performed."
        elif result:
            return result
    start_attempt(existing_manifest, context)
    existing_manifest.pop("prior_reports", None)
    for key in ("repo_id", "depth", "repositories", "repository_inventory_verified",
                "sast_budget", "intrusion_budget", "experiment_budget",
                "model", "model_routing", "verifier_model", "reproduction_mode",
                "codegraph_mode", "network", "offline_package", "source_root"):
        existing_manifest[key] = context[key]
    existing_manifest.update(repository=args.repo_name, commit=args.commit,
                             status="incomplete", updated_at=now())
    for task in ledger["tasks"]:
        if isinstance(task, dict) and task.get("status") in {"ok", "degraded", "shallow"}:
            task.setdefault("attempt_id", existing_manifest["phase_attempts"].get(task.get("phase")))
    atomic_write(manifest_path, existing_manifest)
    atomic_write(ledger_path, ledger)
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    atomic_write(context_path, context)
    print(json.dumps(context, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
