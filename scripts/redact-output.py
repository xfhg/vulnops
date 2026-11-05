#!/usr/bin/env python3
"""Emit a size-bounded, conservatively redacted text file."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "<redacted-private-key>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "ghp_<redacted>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA<redacted>"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "sk-<redacted>"),
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s]+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*)[^\s,;]+"), r"\1<redacted>"),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("max_bytes", type=int)
    args = parser.parse_args()
    raw = args.path.read_bytes()
    truncated = len(raw) > args.max_bytes
    text = raw[: args.max_bytes].decode("utf-8", errors="replace")
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    print(text, end="" if text.endswith("\n") else "\n")
    if truncated:
        print(f"[vulnops] output truncated at {args.max_bytes} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
