#!/usr/bin/env python3
"""Aggregate exact per-finding remediation dispositions without editing audit data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from remediation_common import (
    atomic_json,
    atomic_text,
    load_context,
    load_object,
    require_remediation_base,
    sha256_file,
    validate_schema,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("remediation_base", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        base = require_remediation_base(root, args.remediation_base)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        context = load_context(root)
        if Path(str(context.get("remediation_base", ""))).resolve() != base:
            raise ValueError("remediation context does not select this output directory")
        manifest = load_object(base / "remediation-manifest.json")
        plan = load_object(base / "remediation-plan.json")
        final = load_object(Path(str(context["paths"]["source_final_findings"])))
        final_by_id = {
            str(finding.get("id")): finding
            for finding in final.get("findings", [])
            if isinstance(finding, dict)
        }
        plan_items = plan.get("items", []) if isinstance(plan.get("items"), list) else []
        plan_ids = [str(item.get("finding_id")) for item in plan_items if isinstance(item, dict)]
        if set(plan_ids) != set(final_by_id) or len(plan_ids) != len(set(plan_ids)):
            raise ValueError("remediation plan does not exactly cover final accepted findings")
        eligible_ids = {str(item["finding_id"]) for item in plan_items if item.get("classification") == "eligible"}
        actual_results = {path.stem for path in (base / "results").glob("*.json")}
        if actual_results - eligible_ids:
            raise ValueError("orphan or manual-only worker result exists")

        items = []
        expected_patches: set[str] = set()
        expected_receipts: set[str] = set()
        for item in plan_items:
            finding_id = str(item["finding_id"])
            finding = final_by_id[finding_id]
            if item.get("classification") == "manual_only":
                prescribed = " ".join(str(finding.get("remediation", "Manual remediation is required.")).split())
                items.append(
                    {
                        "finding_id": finding_id,
                        "finding_kind": finding["finding_kind"],
                        "disposition": "manual_required",
                        "summary": f"{prescribed} Reason no patch is published: {item['reason']}",
                        "patch_ref": None,
                        "patch_sha256": None,
                        "receipt_ref": None,
                        "result_ref": None,
                        "changed_files": [],
                        "addressed_locations": [],
                        "limitations": ["No Git patch is published for this non-eligible final finding."],
                    }
                )
                continue
            result_ref = f"results/{finding_id}.json"
            result_path = base / result_ref
            result = load_object(result_path)
            schema_errors = validate_schema(root, "remediation-worker-result.schema.json", result_path)
            if schema_errors:
                raise ValueError("; ".join(schema_errors))
            if result.get("remediation_id") != context.get("remediation_id") or result.get("finding_id") != finding_id:
                raise ValueError(f"worker result identity mismatch: {finding_id}")
            if result.get("model") != context.get("model"):
                raise ValueError(f"worker result model mismatch: {finding_id}")
            if result.get("status") == "failed" or result.get("errors"):
                raise ValueError(f"worker did not reach a successful terminal disposition: {finding_id}")
            if result.get("status") == "manual_required":
                if result.get("changed_files"):
                    raise ValueError(f"manual remediation may not retain changed files: {finding_id}")
                items.append(
                    {
                        "finding_id": finding_id,
                        "finding_kind": finding["finding_kind"],
                        "disposition": "manual_required",
                        "summary": str(result["summary"]),
                        "patch_ref": None,
                        "patch_sha256": None,
                        "receipt_ref": None,
                        "result_ref": result_ref,
                        "changed_files": [],
                        "addressed_locations": result.get("addressed_locations", []),
                        "limitations": result.get("limitations", []),
                    }
                )
                continue
            if result.get("status") != "candidate":
                raise ValueError(f"unknown worker disposition: {finding_id}")
            patch_ref = f"patches/{finding_id}.patch"
            receipt_ref = f"receipts/{finding_id}.json"
            patch_path, receipt_path = base / patch_ref, base / receipt_ref
            receipt = load_object(receipt_path)
            schema_errors = validate_schema(root, "remediation-patch-receipt.schema.json", receipt_path)
            if schema_errors:
                raise ValueError("; ".join(schema_errors))
            patch_sha = sha256_file(patch_path)
            if receipt.get("finding_id") != finding_id or receipt.get("patch_ref") != patch_ref or receipt.get("patch_sha256") != patch_sha:
                raise ValueError(f"patch receipt mismatch: {finding_id}")
            if receipt.get("changed_files") != result.get("changed_files"):
                raise ValueError(f"patch receipt changed files differ from worker result: {finding_id}")
            expected_patches.add(f"{finding_id}.patch")
            expected_receipts.add(f"{finding_id}.json")
            items.append(
                {
                    "finding_id": finding_id,
                    "finding_kind": finding["finding_kind"],
                    "disposition": "patch_ready",
                    "summary": str(result["summary"]),
                    "patch_ref": patch_ref,
                    "patch_sha256": patch_sha,
                    "receipt_ref": receipt_ref,
                    "result_ref": result_ref,
                    "changed_files": result.get("changed_files", []),
                    "addressed_locations": result.get("addressed_locations", []),
                    "limitations": result.get("limitations", []),
                }
            )
        actual_patches = {path.name for path in (base / "patches").glob("*.patch")}
        actual_receipts = {path.name for path in (base / "receipts").glob("*.json")}
        if actual_patches != expected_patches or actual_receipts != expected_receipts:
            raise ValueError("published patch or receipt set differs from ready dispositions")
        patch_ready = sum(item["disposition"] == "patch_ready" for item in items)
        manual_required = len(items) - patch_ready
        status = "degraded" if manual_required else "ok"
        limitations = [
            "Patches were checked with git apply --check but were not executed, tested, or independently reviewed."
        ] if patch_ready else []
        if manual_required:
            limitations.append(f"{manual_required} final finding(s) require manual remediation and have no published patch.")
        bundle = {
            "schema_version": "2.0",
            "artifact_kind": "linked-remediation",
            "remediation_id": context["remediation_id"],
            "source": {
                "run_id": context["source_run_id"],
                "scan_ref": manifest["source_scan_ref"],
                "report_ref": manifest["source_report_ref"],
                "report_sha256": manifest["report_sha256"],
                "final_findings_sha256": manifest["final_findings_sha256"],
                "target_fingerprint": manifest["target_fingerprint"],
            },
            "model": context["model"],
            "status": status,
            "counts": {"total": len(items), "patch_ready": patch_ready, "manual_required": manual_required},
            "items": items,
            "limitations": limitations,
        }
        bundle_path = base / "remediation.json"
        atomic_json(bundle_path, bundle)
        schema_errors = validate_schema(root, "remediation.schema.json", bundle_path)
        if schema_errors:
            bundle_path.unlink(missing_ok=True)
            raise ValueError("; ".join(schema_errors))
        lines = [
            "# Linked Security Remediation",
            "",
            f"- Source audit: `{manifest['source_scan_ref']}`",
            f"- Source report: `{manifest['source_report_ref']}`",
            f"- Patch ready: {patch_ready}",
            f"- Manual required: {manual_required}",
            f"- Status: {status}",
            "",
            "## Dispositions",
            "",
        ]
        for record in items:
            suffix = f" — `{record['patch_ref']}`" if record["patch_ref"] else ""
            lines.append(f"- {record['finding_id']}: {record['disposition']}{suffix}")
        if limitations:
            lines.extend(["", "## Limitations", "", *[f"- {value}" for value in limitations]])
        atomic_text(base / "summary.md", "\n".join(lines) + "\n")
        print(json.dumps(bundle["counts"], sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
