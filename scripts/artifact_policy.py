#!/usr/bin/env python3
"""Single authority for canonical artifact sizes, hygiene and phase ownership."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path


DEFAULT_ARTIFACT_LIMIT = 16 * 1024 * 1024
CONTEXT_LIMIT = 2 * 1024 * 1024
RECEIPT_LIMIT = 64 * 1024
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"\bauthorization\s*:\s*(?:bearer|basic)\s+(?!<redacted>(?:$|[\s\"'\\,]))[^\s\"'\\,]+", re.I),
)
PHASE_BY_DIRECTORY = {
    "repo-context": "recon",
    "tool-collection": "tool-collection",
    "sast": "sast",
    "campaign-planning": "campaign-planning",
    "intrusion": "intrusion",
    "gap-exploration": "gap-exploration",
    "synthesis": "synthesis",
    "final-verification": "final-verification",
    "report": "report",
}


def artifact_size_limit(relative: Path) -> int | None:
    if relative.parent.name == "report" and relative.name in {"security-report.json", "security-report.md"}:
        return None
    if relative == Path("campaign-planning/discovery.json"):
        return CONTEXT_LIMIT
    if relative.name.endswith("receipt.json"):
        return RECEIPT_LIMIT
    if relative.name == "context.json" or "report" in relative.parts:
        return CONTEXT_LIMIT
    return DEFAULT_ARTIFACT_LIMIT


def phase_for_artifact(relative: Path) -> str | None:
    return PHASE_BY_DIRECTORY.get(relative.parts[0]) if relative.parts else None


def contains_raw_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def publication_content_error(value: object, *, size_limit: int | None = DEFAULT_ARTIFACT_LIMIT) -> str | None:
    """Apply publication hygiene before schema errors can echo unsafe context."""
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            return "JSON content exceeds the 64-level nesting bound"
        if isinstance(item, str):
            if contains_raw_secret(item):
                return "possible raw secret in JSON content"
        elif isinstance(item, dict):
            if {"raw_output", "raw_scanner_output", "proof_token", "stdout", "stderr"}.intersection(item):
                return "raw execution, scanner or proof material is not publishable"
            pending.extend((child, depth + 1) for child in item.values())
            pending.extend((key, depth + 1) for key in item)
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            return "JSON content contains a non-finite number"
    if size_limit is not None and len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > size_limit:
        return "JSON content exceeds the bounded artifact size policy"
    return None


def oversized_artifacts(scan: Path) -> list[tuple[Path, int, int]]:
    violations: list[tuple[Path, int, int]] = []
    for path in sorted(scan.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(scan)
        size = path.stat().st_size
        limit = artifact_size_limit(relative)
        if limit is not None and size > limit:
            violations.append((relative, size, limit))
    return violations
