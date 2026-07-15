#!/usr/bin/env python3
"""Single authority for bounded canonical artifact sizes and phase ownership."""

from __future__ import annotations

from pathlib import Path


DEFAULT_ARTIFACT_LIMIT = 16 * 1024 * 1024
CONTEXT_AND_REPORT_LIMIT = 2 * 1024 * 1024
RECEIPT_LIMIT = 64 * 1024
PHASE_BY_DIRECTORY = {
    "repo-context": "recon",
    "tool-collection": "tool-collection",
    "sast": "sast",
    "campaign-planning": "campaign-planning",
    "intrusion": "intrusion",
    "synthesis": "synthesis",
    "final-verification": "final-verification",
    "report": "report",
}


def artifact_size_limit(relative: Path) -> int:
    if relative.name.endswith("receipt.json"):
        return RECEIPT_LIMIT
    if relative.name == "context.json" or "report" in relative.parts:
        return CONTEXT_AND_REPORT_LIMIT
    return DEFAULT_ARTIFACT_LIMIT


def phase_for_artifact(relative: Path) -> str | None:
    return PHASE_BY_DIRECTORY.get(relative.parts[0]) if relative.parts else None


def oversized_artifacts(scan: Path) -> list[tuple[Path, int, int]]:
    violations: list[tuple[Path, int, int]] = []
    for path in sorted(scan.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(scan)
        size = path.stat().st_size
        limit = artifact_size_limit(relative)
        if size > limit:
            violations.append((relative, size, limit))
    return violations
