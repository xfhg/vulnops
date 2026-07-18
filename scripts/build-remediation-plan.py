#!/usr/bin/env python3
"""Build exact hash-bound remediation packets from final accepted findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from remediation_common import (
    atomic_json,
    load_context,
    load_object,
    require_remediation_base,
    resolve_beneath,
    sha256_file,
    sha256_json,
    validate_schema,
)


def artifact_refs(finding: dict[str, Any]) -> list[str]:
    refs: set[str] = set()
    independent = finding.get("independent_verification_ref")
    if independent:
        refs.add(str(independent))
    verification = finding.get("verification") if isinstance(finding.get("verification"), dict) else {}
    refs.update(str(ref) for ref in verification.get("source_validation_refs", []) if ref)
    if verification.get("reproduction_ref"):
        refs.add(str(verification["reproduction_ref"]))
    refs.update(str(ref) for ref in finding.get("graph_receipt_refs", []) if ref)
    for source in finding.get("source_refs", []):
        if isinstance(source, dict) and source.get("artifact_ref"):
            refs.add(str(source["artifact_ref"]))
    for step in finding.get("primitive_steps", []):
        if isinstance(step, dict):
            refs.update(str(ref) for ref in step.get("evidence_refs", []) if ref)
    return sorted(refs)


def source_files(finding: dict[str, Any]) -> list[str]:
    files = {
        str(location.get("file"))
        for location in [*finding.get("root_causes", []), *finding.get("trace", [])]
        if isinstance(location, dict) and location.get("file")
    }
    secret = finding.get("secret")
    if isinstance(secret, dict) and secret.get("file"):
        files.add(str(secret["file"]))
    return sorted(files)


def classification(finding: dict[str, Any]) -> tuple[str, str]:
    if finding.get("verdict") != "confirmed" or finding.get("status") != "verified":
        return "manual_only", "finding requires environment confirmation before a source patch is appropriate"
    if finding.get("finding_kind") == "secret":
        return "manual_only", "secret remediation requires removal and external rotation without persisting a deletion hunk"
    return "eligible", "confirmed source-backed finding is eligible for production patch authoring"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("remediation_base", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        base = require_remediation_base(root, args.remediation_base)
    except ValueError as exc:
        parser.error(str(exc))
    errors: list[str] = []
    try:
        context = load_context(root)
        if Path(str(context.get("remediation_base", ""))).resolve() != base:
            raise ValueError("remediation context does not select this output directory")
        manifest = load_object(base / "remediation-manifest.json")
        scan = Path(str(context["source_scan"])).resolve()
        repo = Path(str(context["repo_path"])).resolve()
        findings_path = Path(str(context["paths"]["source_final_findings"])).resolve()
        report_path = Path(str(context["paths"]["source_report"])).resolve()
        if sha256_file(findings_path) != manifest.get("final_findings_sha256"):
            raise ValueError("final findings hash differs from remediation identity")
        if sha256_file(report_path) != manifest.get("report_sha256"):
            raise ValueError("security report hash differs from remediation identity")
        final = load_object(findings_path)
        report = load_object(report_path)
        findings = final.get("findings")
        rendered = report.get("findings")
        if not isinstance(findings, list) or not isinstance(rendered, list):
            raise ValueError("source audit finding arrays are malformed")
        final_ids = [str(item.get("id")) for item in findings if isinstance(item, dict)]
        report_ids = [str(item.get("id")) for item in rendered if isinstance(item, dict)]
        if len(final_ids) != len(findings) or len(final_ids) != len(set(final_ids)):
            raise ValueError("final accepted finding IDs must be unique")
        if set(final_ids) != set(report_ids):
            raise ValueError("report and final accepted finding IDs differ")

        packet_dir = base / "packets"
        packet_dir.mkdir(parents=True, exist_ok=True)
        items = []
        for finding in findings:
            finding_id = str(finding["id"])
            disposition, reason = classification(finding)
            refs = artifact_refs(finding)
            for ref in refs:
                relative = ref.split(":", 1)[0].split("#", 1)[0]
                resolve_beneath(scan, relative, require_file=True)
            files = source_files(finding)
            for relative in files:
                resolve_beneath(repo, relative, require_file=True)
            packet = {
                "schema_version": "2.0",
                "remediation_id": context["remediation_id"],
                "source_run_id": context["source_run_id"],
                "finding_id": finding_id,
                "classification": disposition,
                "classification_reason": reason,
                "report_sha256": manifest["report_sha256"],
                "final_findings_sha256": manifest["final_findings_sha256"],
                "finding_sha256": sha256_json(finding),
                "finding": finding,
                "artifact_refs": refs,
                "source_files": files,
            }
            packet_path = packet_dir / f"{finding_id}.json"
            atomic_json(packet_path, packet)
            errors.extend(validate_schema(root, "remediation-packet.schema.json", packet_path))
            items.append(
                {
                    "finding_id": finding_id,
                    "finding_kind": finding["finding_kind"],
                    "classification": disposition,
                    "reason": reason,
                    "packet_ref": f"packets/{finding_id}.json",
                    "packet_sha256": sha256_file(packet_path),
                }
            )
        eligible = sum(item["classification"] == "eligible" for item in items)
        plan = {
            "schema_version": "2.0",
            "remediation_id": context["remediation_id"],
            "source_run_id": context["source_run_id"],
            "report_sha256": manifest["report_sha256"],
            "final_findings_sha256": manifest["final_findings_sha256"],
            "items": items,
            "counts": {"total": len(items), "eligible": eligible, "manual_only": len(items) - eligible},
        }
        plan_path = base / "remediation-plan.json"
        atomic_json(plan_path, plan)
        errors.extend(validate_schema(root, "remediation-plan.schema.json", plan_path))
        if errors:
            raise ValueError("; ".join(errors))
        print(json.dumps(plan["counts"], sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
