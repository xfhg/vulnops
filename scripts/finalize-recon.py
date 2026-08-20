#!/usr/bin/env python3
"""Deterministically seal Recon and own its dependency-input handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from dependency_contract import dependency_language, discover_dependency_files
from operator_context import identity as operator_context_identity
from operator_context import inspect_context


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def render_repo_markdown(document: dict[str, Any], operator_context: dict[str, Any]) -> str:
    lines = [
        "# Repository Context",
        "",
        f"- Repository: {document.get('repository', 'unknown')}",
        f"- Projects: {len(document.get('projects', []))}",
        f"- Domain tags: {', '.join(str(item) for item in document.get('domain_tags', [])) or 'none'}",
        "",
        "## Projects",
        "",
    ]
    for project in document.get("projects", []):
        if not isinstance(project, dict):
            continue
        lines.extend(
            [
                f"### {project.get('id', 'project')}",
                "",
                f"- Type: {project.get('type', 'unknown')}",
                f"- Base path: {project.get('base_path', '.')}",
                f"- Languages: {', '.join(str(item) for item in project.get('languages', [])) or 'unknown'}",
                f"- Frameworks: {', '.join(str(item) for item in project.get('frameworks', [])) or 'none'}",
                f"- Entry points: {len(project.get('entry_points', []))}",
                "",
            ]
        )
    lines.extend(
        [
            "## Operator Context",
            "",
            f"- Accepted files: {operator_context['accepted_files']}",
            f"- Skipped files: {operator_context['skipped_files']}",
            f"- Derived observations: {len(operator_context['observations'])}",
            "",
        ]
    )
    warnings = [str(item) for item in document.get("warnings", [])]
    if warnings:
        lines.extend(["## Limitations", ""])
        lines.extend(f"- {warning}" for warning in warnings)
        lines.append("")
    return "\n".join(lines)


def is_within(relative: str, base: str) -> bool:
    path_parts = PurePosixPath(relative).parts
    base_parts = PurePosixPath(base or ".").parts
    if base_parts == (".",):
        base_parts = ()
    return path_parts[: len(base_parts)] == base_parts


def target_ref_exists(repo: Path, ref: str) -> bool:
    try:
        relative, line_text = ref.rsplit(":", 1)
        line = int(line_text)
    except (ValueError, TypeError):
        return False
    path = (repo / relative).resolve()
    try:
        path.relative_to(repo)
    except ValueError:
        return False
    if not path.is_file() or line < 1:
        return False
    content = path.read_bytes()
    lines = content.count(b"\n") + (0 if not content or content.endswith(b"\n") else 1)
    return line <= lines


def context_ref_valid(ref: str, files: dict[str, dict[str, Any]]) -> bool:
    if not ref.startswith("context/"):
        return False
    raw = ref.removeprefix("context/")
    try:
        relative, line_text = raw.rsplit(":", 1)
        line = int(line_text)
    except (ValueError, TypeError):
        return False
    item = files.get(relative)
    return bool(item and item["status"] == "accepted" and 1 <= line <= int(item["lines"] or 0))


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
    operator_context = inspect_context(Path(str(context["paths"]["operator_context"])))
    if operator_context_identity(operator_context) != context.get("operator_context"):
        raise SystemExit("Operator context changed during Recon")

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
    research = [
        load(scan / "repo-context/research/overview.json"),
        load(scan / "repo-context/research/trust-boundaries.json"),
        load(scan / "repo-context/research/input-surfaces.json"),
    ]
    accepted = {item["path"]: item for item in operator_context["files"]}
    observations: list[dict[str, Any]] = []
    for worker_document in research:
        worker = str(worker_document.get("worker", ""))
        for item in worker_document.get("observations", []):
            if not isinstance(item, dict):
                continue
            if bool(item.get("context_refs")) != bool(item.get("context_assessment")):
                raise SystemExit(f"Operator-context references and assessment must be paired in {worker}:{item.get('id')}")
            if not item.get("context_refs"):
                continue
            context_refs = list(dict.fromkeys(str(ref) for ref in item["context_refs"]))
            if any(not context_ref_valid(ref, accepted) for ref in context_refs):
                raise SystemExit(f"Invalid operator-context reference in {worker}:{item.get('id')}")
            target_refs = list(dict.fromkeys(str(ref) for ref in item.get("evidence_refs", [])))
            if any(not target_ref_exists(repo, ref) for ref in target_refs):
                raise SystemExit(f"Invalid target evidence in operator-context observation {worker}:{item.get('id')}")
            assessment = str(item.get("context_assessment", "context_only"))
            if assessment in {"corroborated", "contradicted"} and not target_refs:
                raise SystemExit(f"{assessment} operator-context observation lacks target evidence")
            source_id = str(item.get("id", ""))
            stable_id = "CTX-" + hashlib.sha256(f"{worker}\0{source_id}".encode()).hexdigest()[:12].upper()
            if any(existing["id"] == stable_id for existing in observations):
                raise SystemExit(f"Duplicate operator-context observation ID in {worker}: {source_id}")
            observations.append(
                {
                    "id": stable_id,
                    "worker": worker,
                    "category": str(item.get("category", "operator_context")),
                    "summary": " ".join(f"{item.get('title', '')}: {item.get('description', '')}".split())[:2000],
                    "assessment": assessment,
                    "context_refs": context_refs,
                    "target_evidence_refs": target_refs,
                }
            )
    operator_context["observations"] = observations
    document["warnings"] = list(dict.fromkeys([*document.get("warnings", []), *operator_context["warnings"]]))
    write(repo_context_path, document)
    write(scan / "repo-context/operator-context.json", operator_context)
    (scan / "repo-context/repo.md").write_text(render_repo_markdown(document, operator_context), encoding="utf-8")

    outputs = [
        "repo-context/repo.md",
        "repo-context/repo-context.json",
        "repo-context/security-surfaces.json",
        "repo-context/operator-context.json",
        "repo-context/research/overview.json",
        "repo-context/research/trust-boundaries.json",
        "repo-context/research/input-surfaces.json",
    ]
    missing = [relative for relative in outputs if not (scan / relative).is_file()]
    if missing:
        raise SystemExit("Recon finalizer missing required artifacts: " + ", ".join(missing))
    manifest = {
        "phase": "recon",
        "status": "degraded" if operator_context["skipped_files"] else "ok",
        "started_at": min((str(item.get("started_at", "")) for item in research if item.get("started_at")), default=now()),
        "completed_at": now(),
        "inputs": [".harness/audit-context.json", "context/"],
        "outputs": outputs,
        "coverage": {
            "projects": len(projects),
            "entry_points": sum(len(project.get("entry_points", [])) for project in projects),
            "dependency_inputs": len(discovered),
            "workers": len(research),
            "operator_context_discovered": operator_context["discovered_files"],
            "operator_context_accepted": operator_context["accepted_files"],
            "operator_context_skipped": operator_context["skipped_files"],
            "operator_context_observations": len(observations),
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
