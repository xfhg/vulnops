#!/usr/bin/env python3
"""Validate cross-phase integrity for a complete VulnOps v2 scan."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


PHASES = (
    "recon", "sca", "secrets", "sast", "intelligence", "triage",
    "intrusion", "final-reconciliation", "final-verification", "report",
)

PHASE_DIRECTORIES = {
    "recon": "repo-context",
    "sca": "sca",
    "secrets": "secrets",
    "sast": "sast",
    "intelligence": "intelligence",
    "triage": "triage",
    "intrusion": "intrusion",
    "final-reconciliation": "final-reconciliation",
    "final-verification": "final-verification",
    "report": "report",
}

TASKS = {
    "recon": "Recon",
    "sca": "SCA",
    "secrets": "Secrets",
    "sast": "SASTLead",
    "intelligence": "Intelligence",
    "triage": "Triage",
    "intrusion": "Intrusion",
    "final-reconciliation": "Reconcile",
    "final-verification": "FinalVerification",
    "report": "RenderReport",
}


def load(path: Path, errors: list[str]) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load {path}: {exc}")
        return None


def artifact_for_ref(scan: Path, ref: object) -> Path | None:
    text = str(ref or "").split("#", 1)[0]
    candidates = [text]
    while ":" in candidates[-1]:
        candidates.append(candidates[-1].rsplit(":", 1)[0])
    for candidate in candidates:
        path = (scan / candidate).resolve()
        try:
            path.relative_to(scan.resolve())
        except ValueError:
            continue
        if path.is_file():
            return path
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: validate-scan-v2.py <harness-root> <scan-base>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    scan = Path(sys.argv[2]).resolve()
    errors: list[str] = []

    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    context = load(context_path, errors)
    manifest = load(scan / "run-manifest.json", errors)
    ledger = load(scan / "task-ledger.json", errors)
    if not isinstance(context, dict) or not isinstance(manifest, dict):
        return 1
    target = Path(str(context.get("repo_path", "")))
    if Path(str(context.get("scan_base", ""))).resolve() != scan:
        errors.append("audit context scan_base mismatch")
    if context.get("run_id") != manifest.get("run_id"):
        errors.append("audit context run_id mismatch")
    if context.get("model") != manifest.get("model"):
        errors.append("audit context model mismatch")
    if manifest.get("status") not in {"running", "degraded", "complete"}:
        errors.append("run manifest is not in a final-validation state")
    if manifest.get("scan_base") != str(scan):
        errors.append("run manifest scan_base mismatch")

    schema_checks = [
        ("run-manifest.schema.json", scan / "run-manifest.json", []),
        ("task-ledger.schema.json", scan / "task-ledger.json", []),
        ("final-findings.schema.json", scan / "final-verification/findings.json", ["--semantic", "final-findings", "--target", str(target)]),
        ("report.schema.json", scan / "report/security-report.json", []),
    ]
    for schema, document, extra in schema_checks:
        result = subprocess.run(
            [sys.executable, str(root / "scripts/validate-json.py"), str(root / f"schemas/v2/{schema}"), str(document), *extra],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            errors.append(result.stderr.strip() or f"schema validation failed: {document}")

    for phase in PHASES:
        result = subprocess.run(
            [sys.executable, str(root / "scripts/validate-phase-v2.py"), str(root), str(scan), phase],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            errors.append(result.stderr.strip() or f"phase validation failed: {phase}")

        phase_document = load(scan / PHASE_DIRECTORIES[phase] / "phase-manifest.json", errors)
        recorded = (manifest.get("phases") or {}).get(phase)
        actual = phase_document.get("status") if isinstance(phase_document, dict) else None
        if recorded != actual:
            errors.append(f"run manifest phase {phase}={recorded!r} does not match artifact status {actual!r}")
        if actual not in {"ok", "degraded", "skipped"}:
            errors.append(f"phase {phase} is not terminal")

    if target.is_dir():
        result = subprocess.run(
            [sys.executable, str(root / "scripts/target-fingerprint.py"), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode or result.stdout.strip() != manifest.get("target_fingerprint"):
            errors.append("target working tree changed during the audit")
    else:
        errors.append("target repository is unavailable")

    final_doc = load(scan / "final-verification/findings.json", errors)
    report = load(scan / "report/security-report.json", errors)
    final_items = final_doc.get("findings", []) if isinstance(final_doc, dict) else []
    report_items = report.get("findings", []) if isinstance(report, dict) else []
    confirmed = [item for item in final_items if isinstance(item, dict) and item.get("verdict") in {"confirmed", "needs_environment"}]
    rejected = [item for item in final_items if isinstance(item, dict) and item.get("verdict") == "rejected"]
    final_by_id = {str(item.get("id")): item for item in confirmed}
    report_ids = {str(item.get("id")) for item in report_items if isinstance(item, dict)}
    if report_ids != set(final_by_id):
        errors.append("report finding IDs do not equal confirmed/environment-required final IDs")

    configured_model = str(manifest.get("model", ""))
    for finding in confirmed:
        finding_id = str(finding.get("id", "<unknown>"))
        verification = finding.get("verification") or {}
        if verification.get("model") != configured_model or verification.get("model_diversity") is not False:
            errors.append(f"{finding_id} verification model does not match the single configured model")
        provenance = finding.get("provenance") or {}
        for key in ("raw_refs", "intelligence_refs", "graph_refs", "validation_refs"):
            for ref in provenance.get(key, []):
                if artifact_for_ref(scan, ref) is None:
                    errors.append(f"{finding_id} {key} reference does not resolve: {ref}")
        for ref in (
            provenance.get("independent_verification_ref"),
            verification.get("source_validation_ref"),
            verification.get("reproduction_ref"),
            (finding.get("remediation") or {}).get("test_ref"),
            (finding.get("remediation") or {}).get("patch_ref"),
        ):
            if ref and artifact_for_ref(scan, ref) is None:
                errors.append(f"{finding_id} artifact reference does not resolve: {ref}")

    validation_documents = load(scan / "sast/validation-results.json", errors)
    for item in validation_documents if isinstance(validation_documents, list) else []:
        if isinstance(item, dict) and item.get("model") != configured_model:
            errors.append(f"SAST validator {item.get('id')} used a different model")
    verification_dir = scan / "final-verification/results"
    for path in sorted(verification_dir.glob("*.json")) if verification_dir.is_dir() else []:
        item = load(path, errors)
        if isinstance(item, dict) and (item.get("model") != configured_model or item.get("model_diversity") is not False):
            errors.append(f"independent verifier {path.stem} model metadata mismatch")

    if isinstance(report, dict):
        summary = report.get("summary", {})
        if not isinstance(summary, dict):
            errors.append("report summary is not an object")
            summary = {}
        severity_counts = {name: 0 for name in ("critical", "high", "medium", "low", "informational")}
        verification_counts = {name: 0 for name in ("source_verified", "dynamic_verified", "needs_environment")}
        for item in confirmed:
            severity = (item.get("severity") or {}).get("overall")
            if severity in severity_counts:
                severity_counts[severity] += 1
            level = (item.get("verification") or {}).get("level")
            if level == "environment_required":
                verification_counts["needs_environment"] += 1
            elif level in verification_counts:
                verification_counts[level] += 1
            if severity in {"critical", "high"} and not (item.get("provenance") or {}).get("graph_refs"):
                errors.append(f"{item.get('id')} critical/high finding has no graph evidence")
        if summary.get("total") != len(confirmed):
            errors.append("report summary.total mismatch")
        if summary.get("rejected") != len(rejected):
            errors.append("report summary.rejected mismatch")
        for name, count in {**severity_counts, **verification_counts}.items():
            if summary.get(name) != count:
                errors.append(f"report summary.{name} mismatch")

    reproduction_dir = scan / "sast/reproduction"
    for result_path in sorted(reproduction_dir.glob("*/result.json")) if reproduction_dir.is_dir() else []:
        schema_result = subprocess.run(
            [
                sys.executable,
                str(root / "scripts/validate-json.py"),
                str(root / "schemas/v2/reproduction-result.schema.json"),
                str(result_path),
                "--semantic",
                "reproduction-result",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if schema_result.returncode:
            errors.append(schema_result.stderr.strip() or f"invalid reproduction result: {result_path}")
        result_doc = load(result_path, errors)
        if not isinstance(result_doc, dict):
            continue
        for ref_key, hash_key in (("test_ref", "test_sha256"), ("patch_ref", "patch_sha256")):
            ref = result_doc.get(ref_key)
            expected = (result_doc.get("hashes") or {}).get(hash_key)
            if not ref:
                continue
            artifact = (scan / str(ref)).resolve()
            try:
                artifact.relative_to(scan.resolve())
            except ValueError:
                errors.append(f"reproduction artifact escapes scan: {ref}")
                continue
            if not artifact.is_file():
                errors.append(f"missing reproduction artifact: {ref}")
                continue
            actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if actual != expected:
                errors.append(f"reproduction artifact hash mismatch: {ref}")

    secret_patterns = (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"ghp_[A-Za-z0-9]{30,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"sk-[A-Za-z0-9]{32,}"),
    )
    for path in scan.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(pattern.search(text) for pattern in secret_patterns):
            errors.append(f"possible unredacted secret in {path.relative_to(scan)}")

    if not isinstance(ledger, dict):
        errors.append("task ledger is not an object")
    else:
        if ledger.get("run_id") != manifest.get("run_id"):
            errors.append("task ledger run_id mismatch")
        task_by_id = {
            str(item.get("id")): item
            for item in ledger.get("tasks", [])
            if isinstance(item, dict)
        }
        for phase, task_id in TASKS.items():
            task = task_by_id.get(task_id)
            if task is None:
                errors.append(f"task ledger missing terminal task {task_id}")
                continue
            if task.get("phase") != phase:
                errors.append(f"task {task_id} phase mismatch")
            if task.get("status") not in {"ok", "degraded"}:
                errors.append(f"task {task_id} is not terminal")
            if artifact_for_ref(scan, task.get("artifact")) is None:
                errors.append(f"task {task_id} artifact does not resolve")
    if errors:
        for error in errors:
            print(f"[validate-scan-v2] ERROR: {error}", file=sys.stderr)
        print(f"[validate-scan-v2] failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print("[validate-scan-v2] scan artifacts valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
