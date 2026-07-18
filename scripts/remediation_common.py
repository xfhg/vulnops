#!/usr/bin/env python3
"""Shared fail-closed helpers for linked remediation artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_object(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} must contain an object")
    return document


def atomic_json(path: Path, document: object) -> bytes:
    data = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)
    return data


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def atomic_text(path: Path, text: str) -> None:
    atomic_bytes(path, text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_json(document: object) -> str:
    data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def resolve_beneath(base: Path, relative: str, *, require_file: bool = False) -> Path:
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError(f"unsafe relative artifact path: {relative!r}")
    candidate = (base / relative).resolve()
    candidate.relative_to(base.resolve())
    if require_file and not candidate.is_file():
        raise ValueError(f"artifact does not resolve: {relative}")
    return candidate


def relative_to_root(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def require_remediation_base(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    resolved.relative_to((root / "remediations").resolve())
    if resolved.is_symlink():
        raise ValueError("remediation base must not be a symlink")
    return resolved


def require_work_base(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    resolved.relative_to((root / "work/remediation").resolve())
    if resolved.is_symlink():
        raise ValueError("remediation work base must not be a symlink")
    return resolved


def context_path(root: Path) -> Path:
    return Path(
        os.environ.get(
            "VULNOPS_REMEDIATION_CONTEXT",
            root / ".harness/remediation-context.json",
        )
    )


def load_context(root: Path) -> dict[str, Any]:
    context = load_object(context_path(root))
    if context.get("schema_version") != "2.0" or context.get("artifact_kind") != "linked-remediation":
        raise ValueError("invalid linked-remediation context")
    return context


def target_fingerprint(root: Path, target: Path) -> str:
    result = subprocess.run(
        [sys.executable, str(root / "scripts/target-fingerprint.py"), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("target fingerprint command failed")
    value = result.stdout.strip()
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("target fingerprint command returned an invalid digest")
    return value


def validate_schema(root: Path, schema_name: str, document: Path) -> list[str]:
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/validate-json.py"),
            str(root / f"schemas/v2/{schema_name}"),
            str(document),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return [result.stderr.strip() or f"schema validation failed: {document}"]
    return []


def sanitized_error(value: object) -> str:
    return " ".join(str(value).split())[:1000] or "linked remediation failed"
