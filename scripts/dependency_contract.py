#!/usr/bin/env python3
"""Canonical target-relative dependency inputs accepted by offline Wraith.

Keep discovery, semantic validation, and collection on this one contract. These
names match the lockfiles/manifests supported by the bundled OSV-Scanner source
lockfile plugin; arbitrary build/config files are never valid SCA inputs.
"""

from __future__ import annotations

import argparse
import json
import os
import fnmatch
from pathlib import Path
from pathlib import PurePosixPath


SUPPORTED_BASENAMES = frozenset(
    {
        "Cargo.lock",
        "Gemfile.lock",
        "Pipfile.lock",
        "buildscript-gradle.lockfile",
        "bun.lock",
        "cabal.project.freeze",
        "composer.lock",
        "conan.lock",
        "deps.json",
        "gems.locked",
        "go.mod",
        "gradle.lockfile",
        "mix.lock",
        "package-lock.json",
        "packages.config",
        "packages.lock.json",
        "pdm.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pubspec.lock",
        "pylock.toml",
        "renv.lock",
        "requirements.txt",
        "stack.yaml.lock",
        "uv.lock",
        "yarn.lock",
    }
)
DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {".git", ".harness", ".codegraph", "node_modules", "vendor", ".venv", "venv", "dist", "build", ".next", "coverage"}
)


def normalized_target_relative(value: object) -> PurePosixPath | None:
    text = str(value)
    if not text or "\\" in text:
        return None
    raw_parts = text.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        return None
    path = PurePosixPath(text)
    if path.is_absolute():
        return None
    return path


def is_supported_dependency_file(value: object) -> bool:
    path = normalized_target_relative(value)
    if path is None:
        return False
    if path.name == "verification-metadata.xml":
        return len(path.parts) >= 2 and path.parts[-2] == "gradle"
    return path.name in SUPPORTED_BASENAMES


def supported_display_names() -> list[str]:
    return [*sorted(SUPPORTED_BASENAMES), "gradle/verification-metadata.xml"]


def discover_dependency_files(repo: Path, ignored_patterns: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Return every supported, regular, target-contained dependency input."""
    root = repo.resolve(strict=True)
    found: list[str] = []
    seen_targets: set[Path] = set()

    def ignored(relative: str) -> bool:
        return any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(relative + "/", pattern) for pattern in ignored_patterns)

    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(root)
        kept: list[str] = []
        for name in sorted(directories):
            candidate = current_path / name
            relative = (relative_dir / name).as_posix()
            if name in DEFAULT_EXCLUDED_DIRECTORIES or candidate.is_symlink() or ignored(relative):
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(files):
            candidate = current_path / name
            relative = (relative_dir / name).as_posix()
            if candidate.is_symlink() or ignored(relative) or not is_supported_dependency_file(relative):
                continue
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            if resolved not in seen_targets:
                seen_targets.add(resolved)
                found.append(relative)
    return sorted(found)


def dependency_language(path: str) -> frozenset[str]:
    name = PurePosixPath(path).name
    mapping = {
        "go.mod": {"go"}, "Cargo.lock": {"rust"}, "package-lock.json": {"javascript", "typescript", "node", "nodejs"},
        "pnpm-lock.yaml": {"javascript", "typescript", "node", "nodejs"}, "yarn.lock": {"javascript", "typescript", "node", "nodejs"},
        "bun.lock": {"javascript", "typescript", "node", "nodejs"}, "requirements.txt": {"python"}, "poetry.lock": {"python"},
        "Pipfile.lock": {"python"}, "pdm.lock": {"python"}, "pylock.toml": {"python"}, "uv.lock": {"python"},
        "Gemfile.lock": {"ruby"}, "gems.locked": {"ruby"}, "composer.lock": {"php"}, "pom.xml": {"java"},
        "gradle.lockfile": {"java", "kotlin"}, "buildscript-gradle.lockfile": {"java", "kotlin"},
        "verification-metadata.xml": {"java", "kotlin"}, "pubspec.lock": {"dart"}, "mix.lock": {"elixir"},
        "conan.lock": {"c", "c++", "cpp"}, "deps.json": {"c#", "csharp", ".net", "dotnet"},
        "packages.config": {"c#", "csharp", ".net", "dotnet"}, "packages.lock.json": {"c#", "csharp", ".net", "dotnet"},
        "cabal.project.freeze": {"haskell"}, "stack.yaml.lock": {"haskell"}, "renv.lock": {"r"},
    }
    return frozenset(mapping.get(name, set()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        print(json.dumps(supported_display_names(), indent=2))
        return 0
    invalid = [path for path in args.paths if not is_supported_dependency_file(path)]
    if invalid:
        for path in invalid:
            print(f"unsupported Wraith dependency input: {path}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
