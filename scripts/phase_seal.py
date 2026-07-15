#!/usr/bin/env python3
"""Deterministically seal and verify one finalized phase directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PHASE_DIRS = {
    "recon": "repo-context",
    "tool-collection": "tool-collection",
    "sast": "sast",
    "campaign-planning": "campaign-planning",
    "intrusion": "intrusion",
    "synthesis": "synthesis",
    "final-verification": "final-verification",
    "report": "report",
}


def directory_sha256(scan: Path, phase: str) -> tuple[str, int]:
    directory = scan / PHASE_DIRS[phase]
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"phase directory is missing or unsafe: {directory}")
    digest = hashlib.sha256()
    count = 0
    for path in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError(f"phase directory contains a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
        digest.update(b"\0")
        count += 1
    if count == 0:
        raise ValueError(f"phase directory contains no files: {directory}")
    return digest.hexdigest(), count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("phase", choices=tuple(PHASE_DIRS))
    parser.add_argument("--expect")
    args = parser.parse_args()
    try:
        digest, count = directory_sha256(args.scan_base.resolve(), args.phase)
    except ValueError as exc:
        parser.error(str(exc))
    if args.expect and digest != args.expect:
        parser.error(f"phase seal mismatch for {args.phase}")
    print(json.dumps({"phase": args.phase, "sha256": digest, "file_count": count}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
