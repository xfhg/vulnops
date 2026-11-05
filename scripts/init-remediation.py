#!/usr/bin/env python3
"""Initialize or recover one linked post-audit remediation execution."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from remediation_common import (
    atomic_json,
    load_object,
    now,
    relative_to_root,
    sha256_file,
    target_fingerprint,
    source_publication,
    validate_advantage_source,
    require_exact_source_authority,
)
from remediation_contract import remediation_contract_sha256
from model_routing import load_routing, remediation_routing, validate_routing


SUCCESS = {"ok", "degraded"}
GENERATED_DIRECTORIES = ("packets", "results", "patches", "receipts")
GENERATED_FILES = ("remediation-plan.json", "remediation.json", "summary.md")


def find_target(root: Path, run: dict) -> tuple[Path, dict]:
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/target-inventory.py"),
            str(root / "target"),
            "--application-name",
            str(run.get("repository", "application")),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        inventory = json.loads(result.stdout) if result.returncode == 0 else {}
    except json.JSONDecodeError:
        inventory = {}
    if not inventory.get("repositories") or not inventory.get("source_root"):
        raise ValueError("cannot discover the current target repository for remediation")
    if inventory["repositories"] != run.get("repositories"):
        raise ValueError(
            "manual-required: current repository ownership or revision differs from the exact-source "
            "remediation input; establish the findings on the intended patch base before manual remediation"
        )
    if len(inventory.get("repositories", [])) != 1:
        raise ValueError(
            "linked automated remediation supports single-repository audits only; "
            "multi-repository audit findings require per-repository patch ownership"
        )
    return Path(str(inventory["source_root"])).resolve(), inventory


def safe_component(value: object, label: str) -> str:
    text = str(value or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", text):
        raise ValueError(f"unsafe {label}: {text!r}")
    return text


def safe_directory_component(value: object, label: str) -> str:
    text = str(value or "")
    if not text or text in {".", ".."} or "/" in text or "\0" in text or len(text.encode("utf-8")) > 255:
        raise ValueError(f"unsafe {label}: {text!r}")
    return text




def clear_generated(root: Path, base: Path, repo_id: str, source_run_id: str, remediation_id: str) -> None:
    for name in GENERATED_DIRECTORIES:
        path = base / name
        if path.is_symlink():
            raise ValueError(f"unsafe remediation directory symlink: {path}")
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)
    for name in GENERATED_FILES:
        (base / name).unlink(missing_ok=True)
    work = root / "work/remediation" / repo_id / source_run_id / remediation_id
    if work.is_symlink():
        raise ValueError(f"unsafe remediation work symlink: {work}")
    if work.exists():
        shutil.rmtree(work)


def compatible(
    manifest: dict,
    *,
    source_run_id: str,
    target_digest: str,
    report_digest: str,
    findings_digest: str,
    contract_digest: str,
    model_routing: dict,
    source_manifest_digest: str | None,
) -> bool:
    expected = {
        "artifact_kind": "linked-remediation",
        "source_run_id": source_run_id,
        "target_fingerprint": target_digest,
        "report_sha256": report_digest,
        "final_findings_sha256": findings_digest,
        "remediation_contract_sha256": contract_digest,
        "model_routing": model_routing,
        "model": model_routing["controllers"]["remediation"],
        **({"source_manifest_sha256": source_manifest_digest} if "source_manifest_sha256" in manifest else {}),
    }
    return all(manifest.get(key) == value for key, value in expected.items())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    scan = args.scan_base.resolve()
    try:
        scan.relative_to((root / "scans").resolve())
        run = source_publication(scan)
        linked_advantage = run["execution_kind"] == "advantage"
        if "publication" not in run["report"] and (
                run.get("schema_version") != "2.0" or run.get("workflow") != "canonical-redteam-v2"):
            raise ValueError("source scan is not a supported VulnOps V5 audit input")
        if not linked_advantage:
            validate_routing(run.get("model_routing"), scope="audit")
        source_run_id = safe_component(run.get("run_id"), "source run ID")
        repo_id = safe_directory_component(run.get("repo_id", run["repository"]), "repository ID")
        depth = run.get("depth", os.environ.get("VULNOPS_DEFAULT_DEPTH", "quick"))
        if depth not in {"quick", "balanced", "full"}:
            raise ValueError("invalid selected remediation depth")
        report = scan / "report/security-report.json"
        findings = scan / "final-verification/findings.json"
        for path in (report, findings):
            if not path.is_file():
                raise ValueError(f"completed remediation source is missing {path.relative_to(scan)}")
        final = load_object(findings)
        expected_digest = require_exact_source_authority(run, final, load_object(report))
        repo, inventory = find_target(root, run)
        target_digest = target_fingerprint(root, repo)
        if target_digest != expected_digest:
            raise ValueError(
                "manual-required: current target is not the exact source that authorized the findings; "
                "independently establish the claims on the intended patch base before manual remediation"
            )
        if linked_advantage:
            validate_advantage_source(scan, repo)
        report_digest = sha256_file(report)
        findings_digest = sha256_file(findings)
        contract_digest = remediation_contract_sha256(root)
        model_routing = remediation_routing(load_routing(root))
        model = model_routing["controllers"]["remediation"]
        from remediation_common import legacy_source_manifest
        source_manifest_digest = (sha256_file(legacy_source_manifest(scan))
                                  if "publication" not in run["report"] else None)

        remediation_root = root / "remediations"
        if remediation_root.is_symlink():
            raise ValueError("remediations root must not be a symlink")
        remediation_root.mkdir(parents=True, exist_ok=True)
        repo_root = remediation_root / repo_id
        if repo_root.is_symlink():
            raise ValueError("repository remediation root must not be a symlink")
        repo_root.mkdir(exist_ok=True)
        linked_root = repo_root / source_run_id
        if linked_root.is_symlink():
            raise ValueError("audit remediation root must not be a symlink")
        linked_root.mkdir(exist_ok=True)
        selected_base: Path | None = None
        selected_manifest: dict | None = None
        for candidate in sorted(linked_root.iterdir(), reverse=True):
            if not candidate.is_dir() or candidate.is_symlink():
                continue
            try:
                document = load_object(candidate / "remediation-manifest.json")
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if document.get("status") in SUCCESS:
                continue
            if compatible(
                document,
                source_run_id=source_run_id,
                target_digest=target_digest,
                report_digest=report_digest,
                findings_digest=findings_digest,
                contract_digest=contract_digest,
                model_routing=model_routing,
                source_manifest_digest=source_manifest_digest,
            ):
                selected_base, selected_manifest = candidate, document
                break

        timestamp = now()
        if selected_base is None:
            remediation_id = safe_component(
                f"{timestamp.replace('-', '').replace(':', '')}-{str(run.get('commit', 'unknown'))[:12]}-{os.getpid()}",
                "remediation ID",
            )
            selected_base = linked_root / remediation_id
            selected_base.mkdir(parents=True)
            selected_manifest = {
                "schema_version": "2.0",
                "artifact_kind": "linked-remediation",
                "remediation_id": remediation_id,
                "source_run_id": source_run_id,
                "repo_id": repo_id,
                "source_scan_ref": relative_to_root(root, scan),
                "source_report_ref": "report/security-report.json",
                "depth": depth,
                "target_fingerprint": target_digest,
                "report_sha256": report_digest,
                "final_findings_sha256": findings_digest,
                "remediation_contract_sha256": contract_digest,
                "model": model,
                "model_routing": model_routing,
                "status": "initialized",
                "attempts": 0,
                "recovery_count": 0,
                "recovery_history": [],
                "created_at": timestamp,
                "updated_at": timestamp,
                "completed_at": None,
                "artifact": None,
                "artifact_sha256": None,
                "error": None,
            }
        else:
            remediation_id = safe_component(selected_manifest.get("remediation_id"), "remediation ID")
            old_status = str(selected_manifest.get("status", "initialized"))
            has_generated = any((selected_base / name).exists() for name in GENERATED_FILES)
            if old_status != "initialized" or has_generated:
                history = selected_manifest.get("recovery_history")
                if not isinstance(history, list):
                    history = []
                history.append(
                    {
                        "generation": len(history) + 1,
                        "recovered_at": timestamp,
                        "reason": f"reset incomplete linked remediation from {old_status}",
                    }
                )
                selected_manifest["recovery_history"] = history
                selected_manifest["recovery_count"] = len(history)
            selected_manifest.update(
                {
                    "status": "initialized",
                    "attempts": 0,
                    "updated_at": timestamp,
                    "completed_at": None,
                    "artifact": None,
                    "artifact_sha256": None,
                    "error": None,
                }
            )

        clear_generated(root, selected_base, repo_id, source_run_id, remediation_id)
        atomic_json(selected_base / "remediation-manifest.json", selected_manifest)
        max_concurrency = {"quick": 4, "balanced": 8, "full": 12}[depth]
        context = {
            "schema_version": "2.0",
            "artifact_kind": "linked-remediation",
            "remediation_id": remediation_id,
            "source_run_id": source_run_id,
            "repo_id": repo_id,
            "depth": depth,
            "target_fingerprint": target_digest,
            "report_sha256": report_digest,
            "final_findings_sha256": findings_digest,
            "remediation_contract_sha256": contract_digest,
            "model": model,
            "model_routing": model_routing,
            "harness_root": str(root),
            "repo_path": str(repo),
            "source_scan": str(scan),
            "remediation_base": str(selected_base),
            "work_base": str(root / "work/remediation" / repo_id / source_run_id / remediation_id),
            "launcher_session_id": os.environ.get("VULNOPS_REMEDIATION_LAUNCHER_SESSION_ID"),
            "orchestration": {"max_concurrency": max_concurrency, "timeout_seconds": {"quick": 1800, "balanced": 3600, "full": 7200}[depth]},
            "paths": {
                "manifest": str(selected_base / "remediation-manifest.json"),
                "plan": str(selected_base / "remediation-plan.json"),
                "packets": str(selected_base / "packets"),
                "results": str(selected_base / "results"),
                "patches": str(selected_base / "patches"),
                "receipts": str(selected_base / "receipts"),
                "bundle": str(selected_base / "remediation.json"),
                "summary": str(selected_base / "summary.md"),
                "source_report": str(report),
                "source_final_findings": str(findings),
            },
            "tools": {
                "build_plan": str(root / "scripts/build-remediation-plan.py"),
                "prepare_work": str(root / "scripts/prepare-remediation-work.py"),
                "publish_patch": str(root / "scripts/publish-remediation-patch.py"),
                "finalize": str(root / "scripts/finalize-remediation.py"),
                "validate": str(root / "scripts/validate-remediation.py"),
                "update_state": str(root / "scripts/update-remediation-state.py"),
            },
            "created_at": timestamp,
        }
        if selected_manifest.get("source_manifest_sha256"):
            context["source_manifest_sha256"] = selected_manifest["source_manifest_sha256"]
        context_path = Path(
            os.environ.get(
                "VULNOPS_REMEDIATION_CONTEXT",
                root / ".harness/remediation-context.json",
            )
        )
        atomic_json(context_path, context)
        print(json.dumps(context, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
