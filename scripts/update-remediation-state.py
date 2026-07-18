#!/usr/bin/env python3
"""Single writer for linked-remediation lifecycle state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from remediation_common import atomic_json, load_object, now, require_remediation_base, resolve_beneath, sanitized_error, sha256_file


TERMINAL_SUCCESS = {"ok", "degraded"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("remediation_base", type=Path)
    parser.add_argument("--status", choices=("running", "ok", "degraded", "failed"), required=True)
    parser.add_argument("--increment-attempt", action="store_true")
    parser.add_argument("--artifact")
    parser.add_argument("--error")
    args = parser.parse_args()
    try:
        base = require_remediation_base(Path(__file__).resolve().parent.parent, args.remediation_base)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        manifest = load_object(base / "remediation-manifest.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"cannot load remediation manifest: {exc}")
    current = str(manifest.get("status"))
    if current in TERMINAL_SUCCESS:
        parser.error("completed remediation bundles are immutable")
    attempts = int(manifest.get("attempts", 0))
    if args.status == "running":
        if not args.increment_attempt:
            parser.error("a real remediation attempt must increment its attempt counter")
        if current == "running":
            parser.error("remediation is already running")
        if attempts >= 2:
            parser.error("linked remediation attempt limit is 2")
        if args.artifact or args.error:
            parser.error("running remediation cannot publish an artifact or error")
        attempts += 1
    elif args.increment_attempt:
        parser.error("attempts may be incremented only when starting work")
    elif args.status in TERMINAL_SUCCESS and current != "running":
        parser.error("successful remediation may close only from running state")
    elif args.status == "failed" and current not in {"initialized", "running"}:
        parser.error("failed remediation may close only initialized or running work")

    artifact_ref: str | None = None
    artifact_sha: str | None = None
    error: str | None = None
    completed: str | None = None
    if args.status in TERMINAL_SUCCESS:
        if attempts < 1:
            parser.error("successful remediation requires a recorded attempt")
        if not args.artifact:
            parser.error("successful remediation requires its canonical artifact")
        try:
            artifact_path = resolve_beneath(base, args.artifact, require_file=True)
        except ValueError as exc:
            parser.error(str(exc))
        if args.error:
            parser.error("successful remediation cannot retain an error")
        try:
            artifact_document = load_object(artifact_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"cannot load successful remediation artifact: {exc}")
        if artifact_document.get("status") != args.status:
            parser.error("terminal remediation status must match its canonical artifact")
        artifact_ref = args.artifact
        artifact_sha = sha256_file(artifact_path)
        completed = now()
    elif args.status == "failed":
        if args.artifact:
            parser.error("failed remediation cannot publish a canonical artifact")
        error = sanitized_error(args.error)

    manifest.update(
        {
            "status": args.status,
            "attempts": attempts,
            "updated_at": now(),
            "completed_at": completed,
            "artifact": artifact_ref,
            "artifact_sha256": artifact_sha,
            "error": error,
        }
    )
    atomic_json(base / "remediation-manifest.json", manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
