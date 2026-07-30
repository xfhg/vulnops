#!/usr/bin/env python3
"""Close healthy deterministic scanner results into an ok Tool Collection phase."""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    context = load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json")))
    sca = load(args.scan_base / "tool-collection/sca-advisories.json")
    secrets = load(args.scan_base / "tool-collection/secrets-redacted.json")
    dependency_limitations = load(args.scan_base / "tool-collection/dependency-limitations.json")
    receipts = ["tool-collection/wraith-receipt.json", "tool-collection/poltergeist-receipt.json"]
    versions: dict[str, str] = {}

    for ref in receipts:
        receipt = load(args.scan_base / ref)
        if receipt.get("status") != "ok" or receipt.get("parse_status") != "ok":
            raise SystemExit(f"tool receipt is not healthy: {ref}")
        if receipt.get("warnings"):
            raise SystemExit(f"healthy deterministic tool receipt must not contain warnings: {ref}")
        versions[str(receipt.get("tool", Path(ref).stem))] = str(receipt.get("version", "unknown"))

    collection = {
        "schema_version": "2.0",
        "run_id": str(context.get("run_id", "")),
        "sca_ref": "tool-collection/sca-advisories.json",
        "secrets_ref": "tool-collection/secrets-redacted.json",
        "receipts": receipts,
        "limitations": dependency_limitations.get("limitations", []),
        "warnings": [],
    }
    write(args.scan_base / "tool-collection/collection.json", collection)

    match_count = int(secrets["match_count"])
    candidate_count = int(secrets.get("candidate_count", 0))
    (args.scan_base / "tool-collection/summary.md").write_text(
        "# Tool Collection\n\n"
        f"- Dependency advisories: {sca.get('advisory_count', 0)}\n"
        f"- Secret match occurrences: {match_count}\n"
        f"- Unique redacted secret candidates: {candidate_count}\n"
        f"- Healthy tool receipts: {len(receipts)}\n"
        f"- Structured dependency limitations: {len(dependency_limitations.get('limitations', []))}\n"
    )

    manifest = {
        "phase": "tool-collection",
        "status": "ok",
        "started_at": now(),
        "completed_at": now(),
        "inputs": ["repo-context/repo-context.json"],
        "outputs": [
            "tool-collection/collection.json",
            "tool-collection/sca-advisories.json",
            "tool-collection/secrets-redacted.json",
            "tool-collection/dependency-limitations.json",
            *receipts,
            "tool-collection/summary.md",
        ],
        "coverage": {
            "dependency_advisories": sca.get("advisory_count", 0),
            "secret_matches": match_count,
            "secret_candidates": candidate_count,
        },
        "tool_versions": versions,
        "warnings": [],
        "errors": [],
    }
    write(args.scan_base / "tool-collection/phase-manifest.json", manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
