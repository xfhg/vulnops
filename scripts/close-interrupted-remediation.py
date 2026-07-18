#!/usr/bin/env python3
"""Fail-close linked remediation owned by a terminating launcher session."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from remediation_common import load_object


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("context", type=Path)
    parser.add_argument("--launcher-session-id")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        context = load_object(args.context.resolve())
    except (OSError, ValueError, json.JSONDecodeError):
        return 0
    if context.get("artifact_kind") != "linked-remediation":
        return 0
    if args.launcher_session_id and context.get("launcher_session_id") != args.launcher_session_id:
        return 0
    base = Path(str(context.get("remediation_base", ""))).resolve()
    try:
        base.relative_to((root / "remediations").resolve())
        manifest = load_object(base / "remediation-manifest.json")
    except (OSError, ValueError, json.JSONDecodeError):
        return 0
    if manifest.get("remediation_id") != context.get("remediation_id"):
        print("[remediation] refusing to close mismatched remediation state", file=sys.stderr)
        return 1
    if manifest.get("status") in {"ok", "degraded", "failed"}:
        return 0
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/update-remediation-state.py"),
            str(base),
            "--status",
            "failed",
            "--error",
            "OMP remediation session ended before linked remediation completion",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        print("[remediation] interrupted state could not be closed", file=sys.stderr)
        return 1
    print(f"[remediation] interrupted execution {context.get('remediation_id')} marked failed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
