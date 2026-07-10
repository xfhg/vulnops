#!/usr/bin/env python3
"""Compute a deterministic fingerprint of the exact audited working tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


def fingerprint(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = 0
    bytes_read = 0
    root = root.resolve()

    def visit(directory: Path) -> None:
        nonlocal files, bytes_read
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            if directory == root and entry.name == ".git":
                continue
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if entry.is_symlink():
                target = os.readlink(path)
                digest.update(f"L\0{relative}\0{mode:o}\0{target}\0".encode())
                files += 1
            elif entry.is_dir(follow_symlinks=False):
                digest.update(f"D\0{relative}\0{mode:o}\0".encode())
                visit(path)
            elif entry.is_file(follow_symlinks=False):
                digest.update(f"F\0{relative}\0{mode:o}\0{info.st_size}\0".encode())
                with path.open("rb") as handle:
                    while block := handle.read(1024 * 1024):
                        digest.update(block)
                        bytes_read += len(block)
                digest.update(b"\0")
                files += 1
            else:
                digest.update(f"S\0{relative}\0{mode:o}\0".encode())
                files += 1

    visit(root)
    return digest.hexdigest(), files, bytes_read


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    value, files, bytes_read = fingerprint(args.target)
    if args.json:
        print(json.dumps({"sha256": value, "files": files, "bytes": bytes_read}, sort_keys=True))
    else:
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
