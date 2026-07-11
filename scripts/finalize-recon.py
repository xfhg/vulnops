#!/usr/bin/env python3
"""Deterministically seal Recon and own its dependency-input handoff."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from dependency_contract import dependency_language, discover_dependency_files


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def is_within(relative: str, base: str) -> bool:
    path_parts = PurePosixPath(relative).parts
    base_parts = PurePosixPath(base or ".").parts
    if base_parts == (".",):
        base_parts = ()
    return path_parts[: len(base_parts)] == base_parts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_path", type=Path)
    parser.add_argument("scan_base", type=Path)
    args = parser.parse_args()
    repo = args.repo_path.resolve(strict=True)
    scan = args.scan_base.resolve()
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", Path(__file__).resolve().parent.parent / ".harness/audit-context.json"))
    context = load(context_path)
    if Path(str(context.get("repo_path", ""))).resolve() != repo or Path(str(context.get("scan_base", ""))).resolve() != scan:
        raise SystemExit("Recon finalizer context identity mismatch")

    repo_context_path = scan / "repo-context/repo-context.json"
    document = load(repo_context_path)
    projects = document.get("projects", [])
    if not isinstance(projects, list) or not projects:
        raise SystemExit("Recon finalizer requires at least one modeled project")
    for project in projects:
        if not isinstance(project, dict):
            raise SystemExit("Recon project must be an object")
        project["dependency_files"] = []

    discovered = discover_dependency_files(repo)
    unassigned: list[str] = []
    for relative in discovered:
        required_languages = dependency_language(relative)
        candidates: list[tuple[tuple[int, int, int, int], dict[str, Any]]] = []
        for index, project in enumerate(projects):
            base = str(project.get("base_path", ""))
            if not is_within(relative, base):
                continue
            languages = {str(item).strip().lower() for item in project.get("languages", [])}
            language_match = int(bool(required_languages & languages))
            base_depth = len(PurePosixPath(base).parts) if base else 0
            non_infra = int(project.get("type") != "infra")
            candidates.append(((base_depth, language_match, non_infra, -index), project))
        if not candidates:
            unassigned.append(relative)
            continue
        owner = max(candidates, key=lambda item: item[0])[1]
        owner["dependency_files"].append(relative)
    if unassigned:
        raise SystemExit("Recon projects do not cover supported dependency inputs: " + ", ".join(unassigned))

    for project in projects:
        project["dependency_files"] = sorted(set(project["dependency_files"]))
    write(repo_context_path, document)

    outputs = [
        "repo-context/repo.md",
        "repo-context/repo-context.json",
        "repo-context/security-surfaces.json",
        "repo-context/research/overview.json",
        "repo-context/research/trust-boundaries.json",
        "repo-context/research/input-surfaces.json",
    ]
    missing = [relative for relative in outputs if not (scan / relative).is_file()]
    if missing:
        raise SystemExit("Recon finalizer missing required artifacts: " + ", ".join(missing))
    manifest = {
        "phase": "recon",
        "status": "ok",
        "started_at": now(),
        "completed_at": now(),
        "inputs": [".harness/audit-context.json"],
        "outputs": outputs,
        "coverage": {
            "projects": len(projects),
            "entry_points": sum(len(project.get("entry_points", [])) for project in projects),
            "dependency_inputs": len(discovered),
        },
        "tool_versions": {"recon_finalizer": "deterministic-v2"},
        "warnings": list(document.get("warnings", [])),
        "errors": [],
    }
    write(scan / "repo-context/phase-manifest.json", manifest)
    print(repo_context_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
