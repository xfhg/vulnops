#!/usr/bin/env python3
"""Publish one bounded, secret-free Git patch after read-only apply checking."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from remediation_common import (
    atomic_bytes,
    atomic_json,
    load_context,
    load_object,
    now,
    require_remediation_base,
    require_work_base,
    resolve_beneath,
    sha256_file,
    target_fingerprint,
    validate_schema,
)


MAX_PATCH_BYTES = 2 * 1024 * 1024
FORBIDDEN_PARTS = {"test", "tests", "testing", "spec", "specs", "fixture", "fixtures", "example", "examples", "doc", "docs"}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\"']?(?!<redacted>|<removed>|(?:os\.)?environ\b|env\b|process\.env\b|getenv\b|settings\b|config\b)[^\s,;\"']{8,}"),
)


def file_map(root: Path) -> dict[str, tuple[str, int, str]]:
    result: dict[str, tuple[str, int, str]] = {}

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if entry.is_symlink():
                result[relative] = ("symlink", mode, os.readlink(path))
            elif entry.is_dir(follow_symlinks=False):
                visit(path)
            elif entry.is_file(follow_symlinks=False):
                result[relative] = ("file", mode, hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                result[relative] = ("special", mode, "")

    visit(root)
    return result


def non_production(relative: str) -> bool:
    path = Path(relative)
    lowered = [part.lower() for part in path.parts]
    name = path.name.lower()
    if any(part in FORBIDDEN_PARTS for part in lowered):
        return True
    if name.startswith(("test_", "spec_", "readme", "changelog")):
        return True
    if re.search(r"(?:^|[._-])(?:test|tests|spec)(?:[._-]|$)", name):
        return True
    return False


def normalized_diff(original: Path, working: Path) -> bytes:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--full-index",
            "--no-prefix",
            "--",
            "original",
            "working",
        ],
        cwd=original.parent,
        capture_output=True,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise ValueError("git could not construct the remediation diff")
    if result.returncode == 0 or not result.stdout:
        raise ValueError("remediation candidate contains no changes")
    normalized: list[bytes] = []
    for line in result.stdout.splitlines(keepends=True):
        if line.startswith(b"diff --git "):
            line = line.replace(b"original/", b"a/", 1).replace(b"working/", b"b/", 1)
        elif line.startswith(b"--- "):
            line = line.replace(b"original/", b"a/", 1)
        elif line.startswith(b"+++ "):
            line = line.replace(b"working/", b"b/", 1)
        normalized.append(line)
    data = b"".join(normalized)
    header_lines = [line for line in data.splitlines() if line.startswith((b"diff --git ", b"--- ", b"+++ "))]
    if any(b"original/" in line or b"working/" in line for line in header_lines):
        raise ValueError("git diff paths could not be normalized safely")
    return data


def known_secret_files(scan: Path) -> set[str]:
    document = load_object(scan / "tool-collection/secrets-redacted.json")
    if not isinstance(document.get("candidates"), list):
        raise ValueError("validated redacted secret candidate list is unavailable")
    return {
        str(item.get("file"))
        for item in document.get("candidates", [])
        if isinstance(item, dict) and item.get("file")
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("finding_id")
    args = parser.parse_args()
    if not re.fullmatch(r"F-[0-9]{3}", args.finding_id):
        parser.error("invalid final finding ID")
    root = Path(__file__).resolve().parent.parent
    temporary = root / f".harness/tmp/remediation-{os.getpid()}-{args.finding_id}.patch"
    try:
        context = load_context(root)
        base = require_remediation_base(root, Path(str(context["remediation_base"])))
        repo = Path(str(context["repo_path"])).resolve()
        scan = Path(str(context["source_scan"])).resolve()
        expected = str(context["target_fingerprint"])
        result_path = base / f"results/{args.finding_id}.json"
        result_doc = load_object(result_path)
        schema_errors = validate_schema(root, "remediation-worker-result.schema.json", result_path)
        if schema_errors:
            raise ValueError("; ".join(schema_errors))
        if result_doc.get("remediation_id") != context.get("remediation_id") or result_doc.get("finding_id") != args.finding_id:
            raise ValueError("worker result identity mismatch")
        if result_doc.get("status") != "candidate" or result_doc.get("errors"):
            raise ValueError("only an error-free candidate result may publish a patch")
        if result_doc.get("model") != context.get("model"):
            raise ValueError("worker result model differs from remediation context")
        plan = load_object(base / "remediation-plan.json")
        item = next((item for item in plan.get("items", []) if item.get("finding_id") == args.finding_id), None)
        if not isinstance(item, dict) or item.get("classification") != "eligible":
            raise ValueError("finding is not eligible for patch publication")
        packet_path = resolve_beneath(base, str(item["packet_ref"]), require_file=True)
        if sha256_file(packet_path) != item.get("packet_sha256"):
            raise ValueError("remediation packet hash mismatch")
        packet = load_object(packet_path)
        if packet.get("remediation_id") != context.get("remediation_id") or packet.get("finding_id") != args.finding_id:
            raise ValueError("remediation packet identity mismatch")
        roots = {
            (str(location.get("file")), int(location.get("line", 0)))
            for location in packet.get("finding", {}).get("root_causes", [])
            if isinstance(location, dict)
        }
        addressed = {
            (str(location.get("file")), int(location.get("line", 0)))
            for location in result_doc.get("addressed_locations", [])
            if isinstance(location, dict)
        }
        if not roots or not roots.issubset(addressed):
            raise ValueError("candidate does not account for every final root-cause location")
        work = require_work_base(root, Path(str(context["work_base"]))) / args.finding_id
        original, working = work / "original", work / "working"
        if not original.is_dir() or not working.is_dir() or original.is_symlink() or working.is_symlink():
            raise ValueError("prepared remediation workspace is unavailable or unsafe")
        if target_fingerprint(root, repo) != expected or target_fingerprint(root, original) != expected:
            raise ValueError("target or immutable remediation original differs from the audited fingerprint")
        before_map, after_map = file_map(original), file_map(working)
        changed = sorted(path for path in set(before_map) | set(after_map) if before_map.get(path) != after_map.get(path))
        if not changed:
            raise ValueError("remediation candidate contains no changed files")
        if changed != sorted(result_doc.get("changed_files", [])):
            raise ValueError("worker changed-file declaration does not match the workspace")
        for relative in changed:
            before = before_map.get(relative)
            after = after_map.get(relative)
            if (before and before[0] != "file") or (after and after[0] != "file"):
                raise ValueError(f"patch changes a symlink or special file: {relative}")
            if non_production(relative):
                raise ValueError(f"production-only patch changes a test, fixture, example, or documentation path: {relative}")
            if after and b"\0" in (working / relative).read_bytes():
                raise ValueError(f"binary patch content is forbidden: {relative}")
        secret_files = known_secret_files(scan)
        if secret_files.intersection(changed):
            raise ValueError("patch touches a file containing a redacted secret candidate")
        patch = normalized_diff(original, working)
        if len(patch) > MAX_PATCH_BYTES:
            raise ValueError("remediation patch exceeds the 2 MiB bound")
        if b"GIT binary patch" in patch or b"Binary files " in patch:
            raise ValueError("binary Git patches are forbidden")
        text = patch.decode("utf-8", errors="strict")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            raise ValueError("candidate patch contains possible raw secret material")
        atomic_bytes(temporary, patch)
        apply_result = subprocess.run(
            ["git", "-C", str(repo), "apply", "--check", "--whitespace=error-all", str(temporary)],
            capture_output=True,
            text=True,
            check=False,
        )
        if apply_result.returncode:
            raise ValueError("git apply --check rejected the candidate patch")
        if target_fingerprint(root, repo) != expected:
            raise ValueError("target changed during read-only patch validation")
        patch_ref = f"patches/{args.finding_id}.patch"
        patch_path = base / patch_ref
        atomic_bytes(patch_path, patch)
        receipt = {
            "schema_version": "2.0",
            "remediation_id": context["remediation_id"],
            "finding_id": args.finding_id,
            "status": "ok",
            "patch_ref": patch_ref,
            "patch_sha256": sha256_file(patch_path),
            "target_fingerprint": expected,
            "changed_files": changed,
            "apply_check": "ok",
            "secret_scan": "ok",
            "production_only": True,
            "created_at": now(),
        }
        receipt_path = base / f"receipts/{args.finding_id}.json"
        atomic_json(receipt_path, receipt)
        schema_errors = validate_schema(root, "remediation-patch-receipt.schema.json", receipt_path)
        if schema_errors:
            patch_path.unlink(missing_ok=True)
            receipt_path.unlink(missing_ok=True)
            raise ValueError("; ".join(schema_errors))
        print(json.dumps({"patch": patch_ref, "receipt": f"receipts/{args.finding_id}.json"}, sort_keys=True))
        return 0
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
