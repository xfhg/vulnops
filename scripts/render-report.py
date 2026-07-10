#!/usr/bin/env python3
"""Render sanitized v2 reports deterministically from canonical findings."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITIES = ("critical", "high", "medium", "low", "informational")
REPORT_REDACTIONS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "<redacted-private-key>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "ghp_<redacted>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA<redacted>"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "sk-<redacted>"),
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s]+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*)[^\s,;]+"), r"\1<redacted>"),
    (re.compile(r"```.*?```", re.S), "<technical-example-omitted>"),
    (re.compile(r"`[^`\n]+`"), "<technical-token-omitted>"),
)


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


def evidence_refs(finding: dict) -> list[str]:
    if finding.get("finding_kind") == "code":
        refs = [f"{step['file']}:{step['line']}" for step in finding.get("trace", []) if isinstance(step, dict)]
        if refs:
            return refs
    return list((finding.get("provenance") or {}).get("raw_refs", []))


def sanitize_text(value: object, limit: int = 8000) -> str:
    text = str(value).replace("\x00", "")[:limit]
    for pattern, replacement in REPORT_REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_value(value: object) -> object:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_value(item) for key, item in value.items()}
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    context = load(context_path, {})
    final_doc = load(args.scan_base / "final-verification/findings.json", {})
    all_findings = final_doc.get("findings", []) if isinstance(final_doc, dict) else []
    reportable = [item for item in all_findings if isinstance(item, dict) and item.get("verdict") in {"confirmed", "needs_environment"}]
    rejected = [item for item in all_findings if isinstance(item, dict) and item.get("verdict") == "rejected"]
    hardening = load(args.scan_base / "sast/hardening-notes.json", [])
    positives = load(args.scan_base / "sast/positive-patterns.json", [])
    coverage = load(args.scan_base / "sast/coverage-ledger.json", {})
    threat = load(args.scan_base / "sast/threat-model.json", {})
    wishlist = load(args.scan_base / "sast/wishlist.json", {})

    summary = {
        "total": len(reportable),
        **{severity: 0 for severity in SEVERITIES},
        "source_verified": 0,
        "dynamic_verified": 0,
        "needs_environment": 0,
        "rejected": len(rejected),
    }
    rendered_findings: list[dict] = []
    for finding in reportable:
        severity = (finding.get("severity") or {}).get("overall", "informational")
        level = (finding.get("verification") or {}).get("level", "source_verified")
        summary[severity] += 1
        if level == "environment_required":
            summary["needs_environment"] += 1
        else:
            summary[level] += 1
        rendered_findings.append({
            "id": finding["id"],
            "title": sanitize_text(finding["title"]),
            "finding_kind": finding["finding_kind"],
            "severity": severity,
            "confidence": (finding.get("confidence") or {}).get("score", "low"),
            "verdict": finding["verdict"],
            "verification_level": level,
            "description": sanitize_text(finding["description"]),
            "impact": sanitize_text(((finding.get("severity") or {}).get("impact") or {}).get("reason", "Impact is described in the finding evidence.")),
            "remediation": sanitize_text((finding.get("remediation") or {}).get("strategy", "Review and correct the vulnerable boundary.")),
            "evidence_refs": evidence_refs(finding),
            "test_ref": (finding.get("remediation") or {}).get("test_ref"),
            "patch_ref": (finding.get("remediation") or {}).get("patch_ref"),
        })

    limitations = ["Discovery and independent verification used fresh contexts with one configured model; model diversity is false."]
    if context.get("reproduction_mode") == "off":
        limitations.append("Safe reproduction was disabled; confirmed findings are source-verified unless another deterministic runtime artifact is cited.")
    open_wishlist = [item for item in wishlist.get("items", []) if isinstance(item, dict) and item.get("status") == "open"] if isinstance(wishlist, dict) else []
    if open_wishlist:
        limitations.append(f"{len(open_wishlist)} environment or tooling request(s) remain open in sast/wishlist.json.")
    for phase, directory in (
        ("recon", "repo-context"), ("sca", "sca"), ("secrets", "secrets"),
        ("sast", "sast"), ("triage", "triage"),
        ("final-reconciliation", "final-reconciliation"),
        ("final-verification", "final-verification"),
    ):
        manifest = load(args.scan_base / directory / "phase-manifest.json", {})
        if isinstance(manifest, dict) and manifest.get("status") == "degraded":
            limitations.append(f"{phase} completed in degraded mode; see its phase manifest.")

    scans: dict[str, object] = {}
    for phase in ("recon", "sca", "secrets", "sast", "intelligence", "triage", "intrusion", "final-reconciliation", "final-verification"):
        directory = "repo-context" if phase == "recon" else phase
        manifest = load(args.scan_base / directory / "phase-manifest.json", {})
        if isinstance(manifest, dict):
            scans[phase] = {"status": manifest.get("status"), "coverage": manifest.get("coverage", {})}

    report = {
        "schema_version": "2.0",
        "run_id": str(context.get("run_id", "unknown")),
        "repository": str(context.get("repo_name", "unknown")),
        "commit": str(context.get("short_sha", "unknown")),
        "date": now(),
        "summary": summary,
        "findings": rendered_findings,
        "hardening_notes": sanitize_value(hardening) if isinstance(hardening, list) else [],
        "positive_patterns": sanitize_value(positives) if isinstance(positives, list) else [],
        "coverage": coverage if isinstance(coverage, dict) else {},
        "limitations": limitations,
        "scans": scans,
    }
    write_json(args.scan_base / "report/security-report.json", report)

    comparable = ((threat.get("repository_profile") or {}).get("comparable") or {}) if isinstance(threat, dict) else {}
    lines = [
        "# Security Audit Report", "",
        f"**Repository:** {report['repository']}",
        f"**Commit:** {report['commit']}",
        f"**Run:** {report['run_id']}",
        "**Audit type:** Read-only evidence-driven source audit", "",
        "## Executive Summary", "",
        f"The audit reports {summary['total']} confirmed or environment-required finding(s): "
        f"{summary['critical']} critical, {summary['high']} high, {summary['medium']} medium, "
        f"{summary['low']} low, and {summary['informational']} informational. "
        f"Independent verification rejected {summary['rejected']} reconciled candidate(s).", "",
        f"Verification evidence: {summary['dynamic_verified']} dynamic, {summary['source_verified']} source-only, "
        f"and {summary['needs_environment']} requiring additional environment evidence.", "",
        "## Comparable Baseline", "",
        f"- Comparable: {comparable.get('name') or 'None identified'}",
        f"- Basis: {comparable.get('basis', 'No reliable offline baseline was available.')}",
        f"- Confidence: {comparable.get('confidence', 'not_applicable')}", "",
        "## Findings", "",
    ]
    for finding in rendered_findings:
        lines.extend([
            f"### [{finding['id']}] {finding['title']}", "",
            f"- Severity: {finding['severity']}",
            f"- Confidence: {finding['confidence']}",
            f"- Verification: {finding['verification_level']}",
            f"- Verdict: {finding['verdict']}", "",
            finding["description"], "",
            f"**Impact:** {finding['impact']}", "",
            f"**Remediation:** {finding['remediation']}", "",
            "**Evidence:** " + ", ".join(finding["evidence_refs"]), "",
        ])
        if finding.get("test_ref") or finding.get("patch_ref"):
            lines.append("**Local remediation artifacts:** " + ", ".join(ref for ref in (finding.get("test_ref"), finding.get("patch_ref")) if ref))
            lines.append("")
    lines.extend(["## Hardening Notes", ""])
    lines.extend(f"- {item.get('title')}: {item.get('description')}" for item in report["hardening_notes"] if isinstance(item, dict))
    if not report["hardening_notes"]:
        lines.append("- None recorded.")
    lines.extend(["", "## Positive Security Patterns", ""])
    lines.extend(f"- {item.get('title')}: {item.get('description')}" for item in report["positive_patterns"] if isinstance(item, dict))
    if not report["positive_patterns"]:
        lines.append("- None recorded.")
    lines.extend(["", "## Coverage and Limitations", ""])
    lines.extend(f"- {item}" for item in limitations)
    lines.append("")
    write_text(args.scan_base / "report/security-report.md", "\n".join(lines))

    manifest = {
        "phase": "report", "status": "degraded" if summary["needs_environment"] else "ok",
        "started_at": now(), "completed_at": now(),
        "inputs": ["final-verification/findings.json", "sast/coverage-ledger.json", "sast/hardening-notes.json", "sast/positive-patterns.json"],
        "outputs": ["report/security-report.md", "report/security-report.json"],
        "coverage": summary, "tool_versions": {"renderer": "v2"},
        "warnings": limitations, "errors": [],
    }
    write_json(args.scan_base / "report/phase-manifest.json", manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
