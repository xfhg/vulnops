#!/usr/bin/env python3
"""Inventory bounded operator-supplied context without copying its contents."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


MAX_FILES = 1024
MAX_BYTES = 16 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_context(root: Path) -> dict[str, Any]:
    root = root.resolve()
    records: list[dict[str, Any]] = []
    accepted_files = accepted_bytes = 0
    if root.exists() and not root.is_dir():
        raise ValueError(f"operator context path is not a directory: {root}")

    paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()) if root.is_dir() else []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        reason: str | None = None
        line_count: int | None = None
        if stat.S_ISLNK(mode):
            payload = os.readlink(path).encode("utf-8", "surrogateescape")
            kind, size, checksum, reason = "symlink", len(payload), hashlib.sha256(payload).hexdigest(), "symlink_not_followed"
        elif not stat.S_ISREG(mode):
            kind, size, checksum, reason = "other", 0, hashlib.sha256(b"").hexdigest(), "unsupported_file_type"
        else:
            kind, size, checksum = "file", path.stat().st_size, _sha256(path)
            if accepted_files >= MAX_FILES:
                reason = "file_limit"
            elif accepted_bytes + size > MAX_BYTES:
                reason = "byte_limit"
            else:
                try:
                    content = path.read_bytes().decode("utf-8")
                    if "\x00" in content:
                        raise UnicodeError("NUL byte")
                except (OSError, UnicodeError):
                    reason = "binary_or_non_utf8"
                else:
                    accepted_files += 1
                    accepted_bytes += size
                    line_count = content.count("\n") + (0 if not content or content.endswith("\n") else 1)
        records.append(
            {
                "path": relative,
                "type": kind,
                "size": size,
                "sha256": checksum,
                "status": "skipped" if reason else "accepted",
                "reason": reason,
                "lines": line_count,
            }
        )

    digest = hashlib.sha256(b"vulnops-operator-context-v1\0")
    for record in records:
        digest.update(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\0")
    skipped = len(records) - accepted_files
    reasons: dict[str, int] = {}
    for record in records:
        if record["reason"]:
            reasons[record["reason"]] = reasons.get(record["reason"], 0) + 1
    warnings = [f"Skipped {count} operator-context item(s): {reason}." for reason, count in sorted(reasons.items())]
    return {
        "schema_version": "2.0",
        "fingerprint": digest.hexdigest(),
        "limits": {"max_files": MAX_FILES, "max_bytes": MAX_BYTES},
        "discovered_files": len(records),
        "accepted_files": accepted_files,
        "accepted_bytes": accepted_bytes,
        "skipped_files": skipped,
        "files": records,
        "observations": [],
        "warnings": warnings,
    }


def identity(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: document[key]
        for key in ("fingerprint", "limits", "discovered_files", "accepted_files", "accepted_bytes", "skipped_files")
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("context_dir", type=Path)
    parser.add_argument("--identity", action="store_true")
    args = parser.parse_args()
    document = inspect_context(args.context_dir)
    print(json.dumps(identity(document) if args.identity else document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
