#!/usr/bin/env python3
"""Apply independent verifier outcomes and emit canonical VulnOps v2 findings."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SAFE_ID = re.compile(r"^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def candidate_items(document: object) -> list[dict]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if isinstance(document, dict) and isinstance(document.get("findings"), list):
        return [item for item in document["findings"] if isinstance(item, dict)]
    return []


def full_finding_errors(root: Path, repo: Path, finding: object) -> list[str]:
    spec = importlib.util.spec_from_file_location("vulnops_validate_json", root / "scripts/validate-json.py")
    if spec is None or spec.loader is None:
        return ["cannot load strict finding validator"]
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = load(root / "schemas/v2/final-findings.schema.json", {})
    errors = module.Validator(schema).collect(finding, schema["$defs"]["fullFinding"])
    wrapper = {"findings": [finding]}
    errors.extend(module.semantic_errors(wrapper, "final-findings", repo))
    return errors


def result_ref(scan: Path, finding_id: str) -> str:
    return f"final-verification/results/{finding_id}.json"


def set_independent_ref(finding: dict, ref: str) -> None:
    provenance = finding.setdefault("provenance", {})
    provenance["independent_verification_ref"] = ref


def rejected(candidate: dict, result: dict, ref: str) -> dict:
    provenance = dict(candidate.get("provenance", {}))
    provenance["independent_verification_ref"] = ref
    return {
        "id": candidate["id"],
        "verdict": "rejected",
        "finding_kind": candidate["finding_kind"],
        "title": candidate["title"],
        "closure_reason": str(result.get("closure_reason", "independent verification rejected the finding")),
        "provenance": provenance,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_path", type=Path)
    parser.add_argument("scan_base", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    context = load(context_path, {})
    candidates_doc = load(args.scan_base / "final-reconciliation/candidates.json", [])
    candidates = candidate_items(candidates_doc)
    findings: list[dict] = []
    warnings: list[str] = []
    errors: list[str] = []

    for candidate in candidates:
        finding_id = str(candidate.get("id", ""))
        if not SAFE_ID.fullmatch(finding_id):
            errors.append(f"reconciled candidate has unsafe id: {finding_id!r}")
            continue
        path = args.scan_base / result_ref(args.scan_base, finding_id)
        result = load(path, None)
        if not isinstance(result, dict):
            errors.append(f"missing independent verifier result for {finding_id}")
            continue
        status = result.get("status")
        ref = result_ref(args.scan_base, finding_id)
        if status == "verified":
            finding = dict(candidate)
            set_independent_ref(finding, ref)
            findings.append(finding)
        elif status == "corrected":
            corrected = result.get("corrected_finding")
            if not isinstance(corrected, dict) or corrected.get("id") != finding_id:
                errors.append(f"invalid corrected finding for {finding_id}")
                continue
            correction_errors = full_finding_errors(root, args.repo_path, corrected)
            if correction_errors:
                errors.append(f"corrected finding {finding_id} is invalid: {'; '.join(correction_errors[:8])}")
                continue
            set_independent_ref(corrected, ref)
            findings.append(corrected)
        elif status == "needs_environment":
            finding = dict(candidate)
            finding["verdict"] = "needs_environment"
            verification = dict(finding.get("verification", {}))
            verification["level"] = "environment_required"
            verification["reproduction_status"] = "environment_required"
            finding["verification"] = verification
            finding["closure_reason"] = str(result.get("closure_reason"))
            set_independent_ref(finding, ref)
            findings.append(finding)
        elif status == "rejected":
            findings.append(rejected(candidate, result, ref))
        else:
            errors.append(f"unknown independent verifier status for {finding_id}")

    output = {
        "schema_version": "2.0",
        "run_id": str(context.get("run_id", "unknown")),
        "model_diversity": False,
        "findings": findings,
    }
    write_json(args.scan_base / "final-verification/findings.json", output)

    confirmed = sum(1 for item in findings if item.get("verdict") == "confirmed")
    needs_environment = sum(1 for item in findings if item.get("verdict") == "needs_environment")
    rejected_count = sum(1 for item in findings if item.get("verdict") == "rejected")
    write_text(
        args.scan_base / "final-verification/summary.md",
        "# Independent Final Verification\n\n"
        f"- Confirmed: {confirmed}\n"
        f"- Needs environment: {needs_environment}\n"
        f"- Rejected: {rejected_count}\n"
        f"- Model diversity: false\n",
    )
    manifest = {
        "phase": "final-verification",
        "status": "failed" if errors else "degraded" if needs_environment else "ok",
        "started_at": now(),
        "completed_at": now(),
        "inputs": ["final-reconciliation/candidates.json"],
        "outputs": ["final-verification/findings.json", "final-verification/summary.md"],
        "coverage": {"candidates": len(candidates), "confirmed": confirmed, "needs_environment": needs_environment, "rejected": rejected_count},
        "tool_versions": {"model": str(context.get("model", os.environ.get("OMP_MODEL_SELECTOR", "unknown"))), "model_diversity": False},
        "warnings": warnings,
        "errors": errors,
    }
    write_json(args.scan_base / "final-verification/phase-manifest.json", manifest)

    ledger_path = args.scan_base / "sast/coverage-ledger.json"
    ledger = load(ledger_path, {})
    if isinstance(ledger, dict) and isinstance(ledger.get("funnel"), dict):
        ledger["funnel"]["final_rejected"] = rejected_count
        ledger["funnel"]["reported"] = confirmed + needs_environment
        write_json(ledger_path, ledger)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
