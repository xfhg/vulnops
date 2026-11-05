#!/usr/bin/env python3
"""Read recorded audit checkpoints and required local publication inputs."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from artifact_policy import artifact_size_limit, publication_content_error
from run_lifecycle import run_status, audit_phases, optional_task_closed

TERMINAL={"ok","degraded","skipped"}


def read_document(scan:Path, relative:str)->dict:
    path=(scan/relative).resolve()
    if not path.is_relative_to(scan.resolve()):
        raise ValueError(f"unsafe artifact path: {relative}")
    try:
        limit=artifact_size_limit(Path(relative))
        if limit is not None and path.stat().st_size>limit:
            raise ValueError(f"artifact exceeds bounded size policy: {relative}")
        text=path.read_text(encoding="utf-8")
        error=publication_content_error(text,size_limit=limit)
        if error:raise ValueError(f"{relative}: {error}")
        value=json.loads(text)
    except (OSError,UnicodeError,json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {relative}: {exc}") from exc
    if not isinstance(value,dict):raise ValueError(f"{relative}: expected object")
    return value


def read_state(scan:Path)->dict:
    run=read_document(scan,"run-manifest.json")
    for key in ("run_id","status"):
        if not isinstance(run.get(key),str) or not run[key]:
            raise ValueError(f"run-manifest.json: missing or invalid {key}")
    try:status=run_status(run["status"])
    except ValueError as exc:raise ValueError(f"run-manifest.json: invalid status: {run['status']}") from exc
    if run.get("workflow")!="canonical-redteam-v2":
        raise ValueError("run-manifest.json: invalid workflow (ordinary audit required)")
    phases=run.get("phases")
    if not isinstance(phases,dict):raise ValueError("run-manifest.json: missing or invalid phases")
    for phase in audit_phases(run):
        if not isinstance(phases.get(phase),str) or phases[phase] not in TERMINAL|{"pending","running","failed"}:
            raise ValueError(f"run-manifest.json: missing or invalid phases.{phase}")
    return {**run,"status":status}

def read_publication(scan:Path)->dict:
    from report_bundle import read_publication as read_bundle
    return read_bundle(scan, expected_kind="audit")["report"]


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("harness_root",type=Path)
    parser.add_argument("scan_base",type=Path)
    args=parser.parse_args()
    scan=args.scan_base.resolve()
    try:
        read_publication(scan)
    except (ValueError, OSError) as exc:
        print(f"[validate-scan-v2] ERROR: {exc}",file=sys.stderr)
        return 1
    print("[validate-scan-v2] completed report and canonical final evidence readable")
    return 0

if __name__=="__main__":raise SystemExit(main())
