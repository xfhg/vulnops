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
)
from remediation_contract import remediation_contract_sha256


SUCCESS = {"ok", "degraded"}
GENERATED_DIRECTORIES = ("packets", "results", "patches", "receipts")
GENERATED_FILES = ("remediation-plan.json", "remediation.json", "summary.md")


def find_target(root: Path) -> Path:
    target_root = root / "target"
    candidates: list[Path] = []
    if (target_root / ".git").is_dir():
        candidates.append(target_root)
    if target_root.is_dir():
        candidates.extend(
            sorted(path.parent for path in target_root.glob("*/.git") if path.is_dir())
        )
    unique = list(dict.fromkeys(path.resolve() for path in candidates))
    if len(unique) != 1:
        raise ValueError("linked remediation requires exactly one target Git repository")
    return unique[0]


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


def validate_source_audit(root: Path, scan: Path, run: dict, repo: Path) -> None:
    validation_context = {
        "schema_version": "2.0",
        "workflow": "canonical-redteam-v2",
        "run_id": run["run_id"],
        "scan_base": str(scan),
        "repo_path": str(repo),
        "harness_contract_sha256": run["harness_contract_sha256"],
        "sast_budget": run["sast_budget"],
        "model": run["model"],
        "model_roles": run["model_roles"],
        "verifier_model": run["verifier_model"],
        "model_diversity": run["model_diversity"],
        "target_fingerprint": run["target_fingerprint"],
    }
    path = root / ".harness/tmp/remediation-source-audit-context.json"
    atomic_json(path, validation_context)
    environment = dict(os.environ)
    environment["VULNOPS_AUDIT_CONTEXT"] = str(path)
    result = subprocess.run(
        ["bash", str(root / "scripts/validate-scan.sh"), str(scan)],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    path.unlink(missing_ok=True)
    if result.returncode:
        raise ValueError("source audit is not complete and valid under the current harness contract")


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
    model: str,
) -> bool:
    expected = {
        "artifact_kind": "linked-remediation",
        "source_run_id": source_run_id,
        "target_fingerprint": target_digest,
        "report_sha256": report_digest,
        "final_findings_sha256": findings_digest,
        "remediation_contract_sha256": contract_digest,
        "model": model,
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
        run = load_object(scan / "run-manifest.json")
        if run.get("schema_version") != "2.0" or run.get("workflow") != "canonical-redteam-v2":
            raise ValueError("source scan is not canonical VulnOps V2")
        if run.get("status") != "complete":
            raise ValueError("source audit must be complete before remediation")
        source_run_id = safe_component(run.get("run_id"), "source run ID")
        repo_id = safe_directory_component(run.get("repo_id"), "repository ID")
        repo = find_target(root)
        target_digest = target_fingerprint(root, repo)
        if target_digest != run.get("target_fingerprint"):
            raise ValueError("current target fingerprint differs from the completed audit")
        report = scan / "report/security-report.json"
        findings = scan / "final-verification/findings.json"
        if not report.is_file() or not findings.is_file():
            raise ValueError("completed audit is missing report or final findings")
        validate_source_audit(root, scan, run, repo)
        report_digest = sha256_file(report)
        findings_digest = sha256_file(findings)
        contract_digest = remediation_contract_sha256(root)
        model = str(os.environ.get("OMP_SLOW_MODEL_SELECTOR") or os.environ.get("OMP_MODEL_SELECTOR") or "").strip()
        if not model:
            raise ValueError("remediation model selector is unavailable")

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
                model=model,
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
                "depth": run["depth"],
                "target_fingerprint": target_digest,
                "report_sha256": report_digest,
                "final_findings_sha256": findings_digest,
                "remediation_contract_sha256": contract_digest,
                "model": model,
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
        max_concurrency = {"quick": 4, "balanced": 8, "full": 12}[str(run["depth"])]
        context = {
            "schema_version": "2.0",
            "artifact_kind": "linked-remediation",
            "remediation_id": remediation_id,
            "source_run_id": source_run_id,
            "repo_id": repo_id,
            "depth": run["depth"],
            "target_fingerprint": target_digest,
            "report_sha256": report_digest,
            "final_findings_sha256": findings_digest,
            "remediation_contract_sha256": contract_digest,
            "model": model,
            "harness_root": str(root),
            "repo_path": str(repo),
            "source_scan": str(scan),
            "remediation_base": str(selected_base),
            "work_base": str(root / "work/remediation" / repo_id / source_run_id / remediation_id),
            "launcher_session_id": os.environ.get("VULNOPS_REMEDIATION_LAUNCHER_SESSION_ID"),
            "orchestration": {"max_concurrency": max_concurrency, "timeout_seconds": {"quick": 1800, "balanced": 3600, "full": 7200}[str(run["depth"])]},
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
