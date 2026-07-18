#!/usr/bin/env python3
"""Validate one linked remediation bundle and its immutable audit linkage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from remediation_common import (
    atomic_json,
    load_context,
    load_object,
    resolve_beneath,
    sha256_file,
    sha256_json,
    target_fingerprint,
    validate_schema,
)
from remediation_contract import remediation_contract_sha256


SENSITIVE = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\"']?(?!<redacted>|<removed>|(?:os\.)?environ\b|env\b|process\.env\b|getenv\b|settings\b|config\b)[^\s,;\"']{8,}"),
)


def source_validation_context(run: dict[str, Any], scan: Path, repo: Path) -> dict[str, Any]:
    return {
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("remediation_base", type=Path)
    parser.add_argument("--precommit", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    base = args.remediation_base.resolve()
    errors: list[str] = []
    try:
        base.relative_to((root / "remediations").resolve())
    except ValueError:
        errors.append("remediation base is outside the dedicated remediations root")
    try:
        context = load_context(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        context = {}
        errors.append(str(exc))
    if Path(str(context.get("remediation_base", ""))).resolve() != base:
        errors.append("remediation context does not select this bundle")
    try:
        manifest = load_object(base / "remediation-manifest.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        manifest = {}
        errors.append(f"cannot load remediation manifest: {exc}")
    errors.extend(validate_schema(root, "remediation-manifest.schema.json", base / "remediation-manifest.json"))
    if manifest.get("remediation_contract_sha256") != remediation_contract_sha256(root):
        errors.append("remediation contract fingerprint mismatch")
    if manifest.get("remediation_id") != context.get("remediation_id") or manifest.get("source_run_id") != context.get("source_run_id"):
        errors.append("remediation context and manifest identities differ")
    if manifest.get("model") != context.get("model"):
        errors.append("remediation model identity mismatch")
    history = manifest.get("recovery_history", []) if isinstance(manifest.get("recovery_history"), list) else []
    if manifest.get("recovery_count") != len(history):
        errors.append("remediation recovery count mismatch")
    if [item.get("generation") for item in history if isinstance(item, dict)] != list(range(1, len(history) + 1)):
        errors.append("remediation recovery generations are not contiguous")

    scan = Path(str(context.get("source_scan", ""))).resolve()
    repo = Path(str(context.get("repo_path", ""))).resolve()
    try:
        scan.relative_to((root / "scans").resolve())
        run = load_object(scan / "run-manifest.json")
        if run.get("status") != "complete" or run.get("run_id") != manifest.get("source_run_id"):
            errors.append("source audit is not the linked completed run")
        if manifest.get("source_scan_ref") != scan.relative_to(root).as_posix():
            errors.append("source scan reference mismatch")
        report = scan / "report/security-report.json"
        final_path = scan / "final-verification/findings.json"
        if sha256_file(report) != manifest.get("report_sha256") or sha256_file(final_path) != manifest.get("final_findings_sha256"):
            errors.append("source report or final findings changed after remediation initialization")
        if target_fingerprint(root, repo) != manifest.get("target_fingerprint"):
            errors.append("target fingerprint differs from the audited remediation base")
        validation_context = root / ".harness/tmp/remediation-validation-audit-context.json"
        validation_context.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(validation_context, source_validation_context(run, scan, repo))
        environment = dict(os.environ)
        environment["VULNOPS_AUDIT_CONTEXT"] = str(validation_context)
        source_check = subprocess.run(
            ["bash", str(root / "scripts/validate-scan.sh"), str(scan)],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        validation_context.unlink(missing_ok=True)
        if source_check.returncode:
            errors.append("linked source audit no longer passes whole-scan validation")
        final = load_object(final_path)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        run, final = {}, {}
        errors.append(f"cannot validate linked source audit: {exc}")

    plan_path = base / "remediation-plan.json"
    bundle_path = base / "remediation.json"
    try:
        plan = load_object(plan_path)
        bundle = load_object(bundle_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        plan, bundle = {}, {}
        errors.append(f"cannot load remediation aggregate: {exc}")
    errors.extend(validate_schema(root, "remediation-plan.schema.json", plan_path))
    errors.extend(validate_schema(root, "remediation.schema.json", bundle_path))
    if plan.get("remediation_id") != manifest.get("remediation_id") or bundle.get("remediation_id") != manifest.get("remediation_id"):
        errors.append("plan or bundle remediation identity mismatch")
    if plan.get("report_sha256") != manifest.get("report_sha256") or plan.get("final_findings_sha256") != manifest.get("final_findings_sha256"):
        errors.append("remediation plan source hashes mismatch")
    source = bundle.get("source") if isinstance(bundle.get("source"), dict) else {}
    if source != {
        "run_id": manifest.get("source_run_id"),
        "scan_ref": manifest.get("source_scan_ref"),
        "report_ref": manifest.get("source_report_ref"),
        "report_sha256": manifest.get("report_sha256"),
        "final_findings_sha256": manifest.get("final_findings_sha256"),
        "target_fingerprint": manifest.get("target_fingerprint"),
    }:
        errors.append("remediation bundle source linkage mismatch")
    if bundle.get("model") != manifest.get("model"):
        errors.append("remediation bundle model mismatch")

    final_by_id = {
        str(item.get("id")): item
        for item in final.get("findings", [])
        if isinstance(item, dict)
    }
    plan_items = plan.get("items", []) if isinstance(plan.get("items"), list) else []
    plan_by_id = {str(item.get("finding_id")): item for item in plan_items if isinstance(item, dict)}
    bundle_items = bundle.get("items", []) if isinstance(bundle.get("items"), list) else []
    bundle_by_id = {str(item.get("finding_id")): item for item in bundle_items if isinstance(item, dict)}
    if len(plan_by_id) != len(plan_items) or len(bundle_by_id) != len(bundle_items):
        errors.append("duplicate remediation finding IDs")
    if set(final_by_id) != set(plan_by_id) or set(final_by_id) != set(bundle_by_id):
        errors.append("remediation artifacts do not exactly dispose final accepted findings")
    eligible_count = sum(item.get("classification") == "eligible" for item in plan_items)
    if plan.get("counts") != {"total": len(plan_items), "eligible": eligible_count, "manual_only": len(plan_items) - eligible_count}:
        errors.append("remediation plan counts mismatch")
    expected_packets: set[str] = set()
    expected_results: set[str] = set()
    expected_patches: set[str] = set()
    expected_receipts: set[str] = set()
    for finding_id, finding in final_by_id.items():
        plan_item = plan_by_id.get(finding_id, {})
        bundle_item = bundle_by_id.get(finding_id, {})
        packet_ref = str(plan_item.get("packet_ref", ""))
        try:
            packet_path = resolve_beneath(base, packet_ref, require_file=True)
            expected_packets.add(packet_path.name)
            errors.extend(validate_schema(root, "remediation-packet.schema.json", packet_path))
            packet = load_object(packet_path)
            if sha256_file(packet_path) != plan_item.get("packet_sha256"):
                errors.append(f"packet hash mismatch: {finding_id}")
            if packet.get("finding") != finding or packet.get("finding_sha256") != sha256_json(finding):
                errors.append(f"packet does not preserve final finding: {finding_id}")
            if packet.get("classification") != plan_item.get("classification"):
                errors.append(f"packet classification mismatch: {finding_id}")
            if packet.get("remediation_id") != manifest.get("remediation_id") or packet.get("source_run_id") != manifest.get("source_run_id"):
                errors.append(f"packet identity mismatch: {finding_id}")
            if packet.get("report_sha256") != manifest.get("report_sha256") or packet.get("final_findings_sha256") != manifest.get("final_findings_sha256"):
                errors.append(f"packet source hash mismatch: {finding_id}")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"invalid remediation packet {finding_id}: {exc}")
        if bundle_item.get("finding_kind") != finding.get("finding_kind"):
            errors.append(f"finding kind mismatch: {finding_id}")
        if bundle_item.get("disposition") == "patch_ready":
            if plan_item.get("classification") != "eligible":
                errors.append(f"manual-only finding has a patch: {finding_id}")
            patch_ref = str(bundle_item.get("patch_ref", ""))
            receipt_ref = str(bundle_item.get("receipt_ref", ""))
            result_ref = str(bundle_item.get("result_ref", ""))
            try:
                patch_path = resolve_beneath(base, patch_ref, require_file=True)
                receipt_path = resolve_beneath(base, receipt_ref, require_file=True)
                result_path = resolve_beneath(base, result_ref, require_file=True)
                expected_patches.add(patch_path.name)
                expected_receipts.add(receipt_path.name)
                expected_results.add(result_path.name)
                errors.extend(validate_schema(root, "remediation-patch-receipt.schema.json", receipt_path))
                errors.extend(validate_schema(root, "remediation-worker-result.schema.json", result_path))
                receipt = load_object(receipt_path)
                result = load_object(result_path)
                patch_sha = sha256_file(patch_path)
                if receipt.get("remediation_id") != manifest.get("remediation_id") or receipt.get("finding_id") != finding_id or receipt.get("patch_ref") != patch_ref:
                    errors.append(f"patch receipt identity mismatch: {finding_id}")
                if patch_sha != bundle_item.get("patch_sha256") or patch_sha != receipt.get("patch_sha256"):
                    errors.append(f"published patch hash mismatch: {finding_id}")
                if receipt.get("target_fingerprint") != manifest.get("target_fingerprint"):
                    errors.append(f"patch receipt target mismatch: {finding_id}")
                if receipt.get("changed_files") != bundle_item.get("changed_files") or result.get("changed_files") != bundle_item.get("changed_files"):
                    errors.append(f"changed-file records mismatch: {finding_id}")
                if result.get("remediation_id") != manifest.get("remediation_id") or result.get("finding_id") != finding_id or result.get("model") != manifest.get("model") or result.get("status") != "candidate":
                    errors.append(f"patch-ready worker result is invalid: {finding_id}")
                apply_check = subprocess.run(
                    ["git", "-C", str(repo), "apply", "--check", "--whitespace=error-all", str(patch_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if apply_check.returncode:
                    errors.append(f"published patch no longer applies cleanly: {finding_id}")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"invalid ready patch {finding_id}: {exc}")
        elif bundle_item.get("disposition") == "manual_required":
            if any(bundle_item.get(key) is not None for key in ("patch_ref", "patch_sha256", "receipt_ref")):
                errors.append(f"manual remediation carries a patch artifact: {finding_id}")
            result_ref = bundle_item.get("result_ref")
            if result_ref:
                try:
                    result_path = resolve_beneath(base, str(result_ref), require_file=True)
                    expected_results.add(result_path.name)
                    errors.extend(validate_schema(root, "remediation-worker-result.schema.json", result_path))
                    result = load_object(result_path)
                    if result.get("remediation_id") != manifest.get("remediation_id") or result.get("finding_id") != finding_id or result.get("status") != "manual_required" or result.get("model") != manifest.get("model") or result.get("changed_files"):
                        errors.append(f"manual worker result is invalid: {finding_id}")
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    errors.append(f"invalid manual result {finding_id}: {exc}")
        else:
            errors.append(f"unknown remediation disposition: {finding_id}")
    actual_packets = {path.name for path in (base / "packets").glob("*.json")}
    actual_results = {path.name for path in (base / "results").glob("*.json")}
    actual_patches = {path.name for path in (base / "patches").glob("*.patch")}
    actual_receipts = {path.name for path in (base / "receipts").glob("*.json")}
    if actual_packets != expected_packets or actual_results != expected_results or actual_patches != expected_patches or actual_receipts != expected_receipts:
        errors.append("remediation supporting artifact set contains missing or orphan files")
    counts = bundle.get("counts") if isinstance(bundle.get("counts"), dict) else {}
    patch_count = sum(item.get("disposition") == "patch_ready" for item in bundle_items)
    manual_count = sum(item.get("disposition") == "manual_required" for item in bundle_items)
    if counts != {"total": len(bundle_items), "patch_ready": patch_count, "manual_required": manual_count}:
        errors.append("remediation aggregate counts mismatch")
    expected_status = "degraded" if manual_count else "ok"
    if bundle.get("status") != expected_status:
        errors.append("remediation aggregate status does not reflect manual dispositions")
    if args.precommit:
        if manifest.get("status") != "running" or manifest.get("artifact") is not None:
            errors.append("precommit remediation validation requires running unpublished state")
    else:
        if manifest.get("status") != expected_status or manifest.get("artifact") != "remediation.json":
            errors.append("terminal remediation state is not synchronized with its bundle")
        if manifest.get("artifact_sha256") != (sha256_file(bundle_path) if bundle_path.is_file() else None):
            errors.append("terminal remediation artifact seal mismatch")
    for path in sorted(base.rglob("*")):
        if path.is_symlink():
            errors.append(f"remediation bundle contains a symlink: {path.relative_to(base)}")
            continue
        if not path.is_file():
            continue
        limit = 2 * 1024 * 1024
        if path.parent.name in {"receipts", "results", "packets"} or path.name == "remediation-manifest.json":
            limit = 64 * 1024
        if path.stat().st_size > limit:
            errors.append(f"remediation artifact exceeds its size bound: {path.relative_to(base)}")
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(pattern.search(text) for pattern in SENSITIVE):
            errors.append(f"possible raw secret in remediation artifact: {path.relative_to(base)}")
    try:
        if target_fingerprint(root, repo) != manifest.get("target_fingerprint"):
            errors.append("target changed during remediation validation")
    except (OSError, ValueError):
        errors.append("target fingerprint could not be revalidated")
    if errors:
        for error in errors:
            print(f"[validate-remediation] ERROR: {error}", file=sys.stderr)
        print(f"[validate-remediation] failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"[validate-remediation] {expected_status}: {patch_count} patch ready, {manual_count} manual required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
