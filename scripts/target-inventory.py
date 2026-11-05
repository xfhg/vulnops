#!/usr/bin/env python3
"""Discover one application source namespace containing one or more Git repositories."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$")


def atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def git(root: Path, *arguments: str, required: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    value = result.stdout.strip()
    if required and (result.returncode or not value):
        detail = " ".join(result.stderr.split())[:300]
        raise ValueError(f"cannot read Git identity for {root.name}: {detail or 'git command failed'}")
    return value if result.returncode == 0 else ""


def sanitized_remote(value: str) -> str:
    remote = "".join(character for character in value.strip() if character >= " " and character not in "\x7f\r\n\t")
    if not remote:
        return "local"
    if "://" not in remote:
        return remote if not Path(remote).is_absolute() else "local"
    parsed = urlsplit(remote)
    hostname = parsed.hostname or ""
    if not hostname:
        return "local"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme.lower(), f"{hostname}{port}", parsed.path, "", ""))


def repository_roots(target: Path) -> list[Path]:
    target = target.resolve(strict=True)
    if not target.is_dir():
        raise ValueError("target must be a directory")
    if (target / ".git").is_dir() or (target / ".git").is_file():
        return [target]

    roots: list[Path] = []
    for current, directories, _ in os.walk(target, topdown=True, followlinks=False):
        directory = Path(current)
        directories[:] = sorted(
            name
            for name in directories
            if name != ".git" and not (directory / name).is_symlink()
        )
        if directory == target:
            continue
        marker = directory / ".git"
        if not marker.is_dir() and not marker.is_file():
            continue
        resolved = directory.resolve(strict=True)
        try:
            resolved.relative_to(target)
        except ValueError as exc:
            raise ValueError(f"repository escapes target: {directory}") from exc
        roots.append(resolved)
        directories.clear()
    if not roots:
        raise ValueError("no Git repository found beneath target")
    return sorted(set(roots), key=lambda path: path.relative_to(target).as_posix())


def application_name(value: str | None, repository_names: list[str], multi_repository: bool) -> str:
    if value:
        candidate = value.strip()
    elif not multi_repository:
        candidate = repository_names[0]
    else:
        common = os.path.commonprefix(repository_names).rstrip(" ._-")
        candidate = common if len(common) >= 2 and SAFE_NAME.fullmatch(common) else "application"
    if not SAFE_NAME.fullmatch(candidate):
        raise ValueError("application name must be 1-128 safe display characters")
    return candidate


def safe_component(value: str) -> str:
    component = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return (component or "application")[:80]


def discover(target: Path, requested_name: str | None = None) -> dict[str, object]:
    target = target.resolve(strict=True)
    roots = repository_roots(target)
    source_root = roots[0] if len(roots) == 1 else target
    repositories: list[dict[str, str]] = []
    for root in roots:
        top_level = Path(git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
        if top_level != root:
            raise ValueError(f"Git worktree root mismatch for {root}")
        relative = "." if root == source_root else root.relative_to(source_root).as_posix()
        repositories.append(
            {
                "name": root.name,
                "path": relative,
                "remote_url": sanitized_remote(git(root, "remote", "get-url", "origin", required=False)),
                "commit": git(root, "rev-parse", "--verify", "HEAD^{commit}"),
            }
        )
    repositories.sort(key=lambda item: item["path"])
    name = application_name(requested_name, [item["name"] for item in repositories], len(repositories) > 1)
    revision = repositories[0]["commit"][:12] if len(repositories) == 1 else "multi-repository"
    return {
        "schema_version": "2.0",
        "application_name": name,
        "application_id": safe_component(name),
        "source_root": str(source_root),
        "repository_count": len(repositories),
        "revision": revision,
        "remote_url": repositories[0]["remote_url"] if len(repositories) == 1 else "multiple-repositories",
        "repositories": repositories,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("--application-name")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--print0-fields", action="store_true")
    args = parser.parse_args()
    try:
        document = discover(args.target, args.application_name)
        if args.output:
            atomic_json(args.output, document)
        if args.print0_fields:
            fields = (
                document["source_root"],
                document["application_name"],
                document["remote_url"],
                document["application_id"],
                document["revision"],
                str(document["repository_count"]),
            )
            sys.stdout.buffer.write(b"\0".join(str(value).encode() for value in fields) + b"\0")
        elif not args.output:
            print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
