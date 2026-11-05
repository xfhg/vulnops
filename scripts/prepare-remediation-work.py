#!/usr/bin/env python3
"""Prepare immutable-original and writable production-patch work copies."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

from remediation_common import load_context, load_object, require_remediation_base, require_work_base, sha256_file, target_fingerprint


def ignore_git(directory: str, names: list[str]) -> set[str]:
    return {".git"} if ".git" in names else set()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("finding_id")
    args = parser.parse_args()
    if not re.fullmatch(r"F-[0-9]{3}", args.finding_id):
        parser.error("invalid final finding ID")
    root = Path(__file__).resolve().parent.parent
    try:
        context = load_context(root)
        base = require_remediation_base(root, Path(str(context["remediation_base"])))
        plan = load_object(base / "remediation-plan.json")
        item = next((item for item in plan.get("items", []) if item.get("finding_id") == args.finding_id), None)
        if not isinstance(item, dict) or item.get("classification") != "eligible":
            raise ValueError("finding is not eligible for patch authoring")
        packet = base / str(item["packet_ref"])
        if sha256_file(packet) != item.get("packet_sha256"):
            raise ValueError("remediation packet hash mismatch")
        repo = Path(str(context["repo_path"])).resolve()
        expected = str(context["target_fingerprint"])
        if target_fingerprint(root, repo) != expected:
            raise ValueError("target changed before remediation workspace preparation")
        for relative in (
            f"results/{args.finding_id}.json",
            f"patches/{args.finding_id}.patch",
            f"receipts/{args.finding_id}.json",
        ):
            artifact = base / relative
            if artifact.is_symlink():
                raise ValueError(f"refusing to reset remediation artifact symlink: {relative}")
            artifact.unlink(missing_ok=True)
        work_root = require_work_base(root, Path(str(context["work_base"])))
        finding_work = work_root / args.finding_id
        if finding_work.is_symlink():
            raise ValueError("refusing remediation work through a symlink")
        if finding_work.exists():
            shutil.rmtree(finding_work)
        original = finding_work / "original"
        working = finding_work / "working"
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(repo, original, symlinks=True, ignore=ignore_git)
        shutil.copytree(repo, working, symlinks=True, ignore=ignore_git)
        if target_fingerprint(root, original) != expected or target_fingerprint(root, working) != expected:
            raise ValueError("disposable remediation copies differ from the audited target")
        if target_fingerprint(root, repo) != expected:
            raise ValueError("target changed while preparing remediation workspace")
        print(json.dumps({"original": str(original), "working": str(working)}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
