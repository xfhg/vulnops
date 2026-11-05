#!/usr/bin/env python3
"""Run deterministic tool collection from a validated Recon handoff."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dependency_contract import (
    discover_dependency_files,
    discover_dependency_limitations,
    is_metadata_only_npm_lockfile,
    is_supported_dependency_file,
    load_requirements_input_reviews,
    requirements_input_disposition,
)
from run_lifecycle import require_active_phase


SAFE_RUN_ID = re.compile(r"^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
WRAITH_FAILURE_CATEGORIES = {
    64: "input_validation",
    70: "prerequisite",
    71: "database_verification",
    72: "scanner_execution",
    73: "unexpected_diagnostics",
    74: "normalization",
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def atomic_json(path: Path, document: object) -> None:
    atomic_bytes(path, json.dumps(document, indent=2, sort_keys=True).encode() + b"\n")


def failed_manifest(scan: Path, message: str) -> None:
    clean = " ".join(message.split())[:1000] or "deterministic tool collection failed"
    atomic_json(
        scan / "tool-collection/phase-manifest.json",
        {
            "phase": "tool-collection",
            "status": "failed",
            "started_at": now(),
            "completed_at": now(),
            "inputs": ["repo-context/repo-context.json"],
            "outputs": [],
            "coverage": {"dependency_advisories": 0, "secret_candidates": 0},
            "tool_versions": {"collector": "deterministic-v2"},
            "warnings": [],
            "errors": [clean],
        },
    )


def invoke(spec: tuple[str, list[str]]) -> tuple[str, subprocess.CompletedProcess[str]]:
    label, command = spec
    return label, subprocess.run(command, capture_output=True, text=True, check=False)


def validate_document(root: Path, schema: str, document: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(root / "scripts/validate-json.py"), str(root / "schemas/v2" / schema), str(document)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"staged {document.name} failed its canonical schema")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("--context", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    context_path = args.context or Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    scan = args.scan_base.resolve()

    try:
        context = load(context_path)
        require_active_phase(args.scan_base, context, "tool-collection")
    except (OSError, ValueError, KeyError) as exc:
        print(f"[collect-tools] ERROR: {' '.join(str(exc).split())[:1000]}", file=sys.stderr)
        return 1

    try:
        run_id = str(context.get("run_id", ""))
        if not SAFE_RUN_ID.fullmatch(run_id):
            raise RuntimeError("audit context contains an unsafe run ID")
        repo = Path(str(context.get("source_root") or context.get("repo_path", ""))).resolve()
        if not repo.is_dir():
            raise RuntimeError("audit target is unavailable")

        # Accepted Recon is historical navigation, not a current source snapshot.
        manifest = load(scan / "run-manifest.json")
        if manifest.get("run_id") != run_id or manifest.get("phases", {}).get("recon") not in {"ok", "degraded"}:
            raise RuntimeError("accepted Recon checkpoint is unavailable")

        lockfiles: list[tuple[str, Path]] = []
        metadata_only_npm_files: list[str] = []
        empty_requirements_files: list[str] = []
        reviewed_requirements_files: dict[str, dict[str, str]] = {}
        requirements_reviews = load_requirements_input_reviews(
            Path(os.environ.get("VULNOPS_CONFIG_PATH", root / "config.toml"))
        )
        seen_lockfiles: set[Path] = set()
        projects = [{"dependency_files": discover_dependency_files(repo)}]
        for project in projects:
            for raw_relative in project["dependency_files"]:
                relative = str(raw_relative)
                if not is_supported_dependency_file(relative):
                    raise RuntimeError(f"Recon dependency_files contains an unsupported Wraith input: {relative}")
                path = (repo / relative).resolve()
                try:
                    path.relative_to(repo)
                except ValueError as exc:
                    raise RuntimeError(f"dependency input escapes target: {relative}") from exc
                if not path.is_file():
                    raise RuntimeError(f"dependency input is missing: {relative}")
                disposition = requirements_input_disposition(path, requirements_reviews.get(relative))
                if disposition == "requirements_no_dependency_inventory":
                    empty_requirements_files.append(relative)
                elif disposition == "requirements_reviewed_non_dependency":
                    reviewed_requirements_files[relative] = requirements_reviews[relative]
                elif is_metadata_only_npm_lockfile(path):
                    metadata_only_npm_files.append(relative)
                elif path not in seen_lockfiles:
                    seen_lockfiles.add(path)
                    lockfiles.append((relative, path))

        work = root / ".harness/tool-work" / run_id
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)

        commands: list[tuple[str, list[str]]] = []
        normalized: list[Path] = []
        for index, (relative, lockfile) in enumerate(lockfiles, 1):
            output = work / f"wraith-{index}.json"
            receipt = work / f"wraith-{index}-receipt.json"
            normalized.append(output)
            commands.append(
                (relative, ["bash", str(root / "scripts/run-wraith.sh"), str(repo), str(lockfile), str(output), str(receipt)])
            )
        commands.append(
            (
                "poltergeist",
                [
                    "bash",
                    str(root / "scripts/run-poltergeist.sh"),
                    str(repo),
                    str(work / "secrets-redacted.json"),
                    str(work / "poltergeist-receipt.json"),
                ],
            )
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(commands))) as pool:
            results = list(pool.map(invoke, commands))
        failed = [(label, result.returncode) for label, result in results if result.returncode]
        if failed:
            summary = ", ".join(
                f"{label} exited {status} "
                f"({WRAITH_FAILURE_CATEGORIES.get(status, 'invocation') if label != 'poltergeist' else 'invocation'})"
                for label, status in failed
            )
            raise RuntimeError(f"deterministic scanner invocation failed: {summary}")

        for index, output in enumerate(normalized, 1):
            receipt = load(work / f"wraith-{index}-receipt.json")
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            if receipt.get("status") != "ok" or receipt.get("parse_status") != "ok" or receipt.get("normalized_sha256") != digest:
                raise RuntimeError(f"unhealthy Wraith invocation receipt {index}")

        merged = subprocess.run(
            [
                sys.executable,
                str(root / "scripts/merge-wraith.py"),
                "--output",
                str(work / "sca-advisories.json"),
                "--receipt",
                str(work / "wraith-receipt.json"),
                *[
                    item
                    for index in range(1, len(normalized) + 1)
                    for item in ("--input-receipt", str(work / f"wraith-{index}-receipt.json"))
                ],
                *[str(path) for path in normalized],
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if merged.returncode:
            raise RuntimeError("Wraith normalized merge failed")

        for schema, name in (
            ("sca-advisories.schema.json", "sca-advisories.json"),
            ("secrets-redacted.schema.json", "secrets-redacted.json"),
            ("tool-receipt.schema.json", "wraith-receipt.json"),
            ("tool-receipt.schema.json", "poltergeist-receipt.json"),
        ):
            validate_document(root, schema, work / name)
        for artifact_name, receipt_name in (
            ("sca-advisories.json", "wraith-receipt.json"),
            ("secrets-redacted.json", "poltergeist-receipt.json"),
        ):
            artifact = work / artifact_name
            receipt = load(work / receipt_name)
            if receipt.get("status") != "ok" or receipt.get("parse_status") != "ok":
                raise RuntimeError(f"unhealthy staged receipt: {receipt_name}")
            if receipt.get("normalized_sha256") != hashlib.sha256(artifact.read_bytes()).hexdigest():
                raise RuntimeError(f"staged receipt hash mismatch: {receipt_name}")

        atomic_json(
            work / "dependency-limitations.json",
            {
                "schema_version": "2.0",
                "limitations": discover_dependency_limitations(
                    repo, metadata_only_npm_files=metadata_only_npm_files,
                    empty_requirements_files=empty_requirements_files,
                    reviewed_requirements_files=reviewed_requirements_files,
                ),
            },
        )
        validate_document(root, "dependency-limitations.schema.json", work / "dependency-limitations.json")

        # Publish the complete normalized set only after every invocation, schema,
        # count, and hash is healthy. No raw scanner file crosses this boundary.
        destination = scan / "tool-collection"
        destination.mkdir(parents=True, exist_ok=True)
        for name in (
            "sca-advisories.json",
            "wraith-receipt.json",
            "secrets-redacted.json",
            "poltergeist-receipt.json",
            "dependency-limitations.json",
        ):
            atomic_bytes(destination / name, (work / name).read_bytes())

        finalized = subprocess.run(
            [sys.executable, str(root / "scripts/finalize-tool-collection.py"), str(scan)],
            env={**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path)},
            capture_output=True,
            text=True,
            check=False,
        )
        if finalized.returncode:
            raise RuntimeError("Tool Collection finalization failed")
        shutil.rmtree(work)
        print(destination / "collection.json")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        failed_manifest(scan, str(exc))
        print(f"[collect-tools] ERROR: {' '.join(str(exc).split())[:1000]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
