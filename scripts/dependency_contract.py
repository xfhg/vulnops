#!/usr/bin/env python3
"""Canonical target-relative dependency inputs accepted by offline Wraith.

Keep discovery, semantic validation, and collection on this one contract. These
names match the lockfiles/manifests supported by the bundled OSV-Scanner source
lockfile plugin; arbitrary build/config files are never valid SCA inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import fnmatch
import re
import tomllib
import xml.etree.ElementTree as ET
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
DEPENDENCY_ECOSYSTEMS = {
    "Cargo.lock": "crates.io",
    "Gemfile.lock": "RubyGems",
    "Pipfile.lock": "PyPI",
    "buildscript-gradle.lockfile": "Maven",
    "bun.lock": "npm",
    "cabal.project.freeze": "Hackage",
    "composer.lock": "Packagist",
    "deps.json": "NuGet",
    "gems.locked": "RubyGems",
    "go.mod": "Go",
    "gradle.lockfile": "Maven",
    "mix.lock": "Hex",
    "package-lock.json": "npm",
    "packages.config": "NuGet",
    "packages.lock.json": "NuGet",
    "pdm.lock": "PyPI",
    "pnpm-lock.yaml": "npm",
    "poetry.lock": "PyPI",
    "pom.xml": "Maven",
    "pubspec.lock": "Pub",
    "pylock.toml": "PyPI",
    "renv.lock": "CRAN",
    "requirements.txt": "PyPI",
    "stack.yaml.lock": "Hackage",
    "uv.lock": "PyPI",
    "yarn.lock": "npm",
}
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


def ecosystem_for_dependency_file(value: object) -> str | None:
    path = normalized_target_relative(value)
    if path is None or not is_supported_dependency_file(value):
        return None
    if path.name == "verification-metadata.xml":
        return "Maven"
    return DEPENDENCY_ECOSYSTEMS.get(path.name)


def _is_metadata_only_maven_manifest(path: Path) -> bool:
    """Return whether a concrete POM provably has no extractable project packages."""
    try:
        if not path.is_file():
            return False
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return False

    def local_name(tag: object) -> str:
        return str(tag).rsplit("}", 1)[-1]

    if local_name(root.tag) != "project":
        return False
    direct_children = list(root)
    packaging = next((child for child in direct_children if local_name(child.tag) == "packaging"), None)
    if packaging is None or (packaging.text or "").strip() != "pom":
        return False
    if any(local_name(child.tag) == "parent" for child in direct_children):
        return False
    return not any(local_name(element.tag) == "dependency" for element in root.iter())


def is_scannable_dependency_path(path: Path) -> bool:
    """Return whether the bundled Wraith/OSV versions can scan this input."""
    return path.name not in {"pom.xml", "cabal.project.freeze"}


def is_metadata_only_npm_lockfile(path: Path) -> bool:
    """Prove a v1 npm lockfile contains metadata but no package inventory."""
    if path.name != "package-lock.json":
        return False

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, ValueError, RecursionError):
        return False
    if not isinstance(document, dict):
        return False
    # ponytail: only v1's known metadata shape; extend when another version has an inventory proof.
    return (
        type(document.get("lockfileVersion")) is int
        and document["lockfileVersion"] == 1
        and document.keys() <= {"lockfileVersion", "name", "version", "requires", "dependencies"}
        and all(isinstance(document[key], str) for key in ("name", "version") if key in document)
        and ("requires" not in document or isinstance(document["requires"], bool))
        and document.get("dependencies", {}) == {}
    )


def load_requirements_input_reviews(config_path: Path) -> dict[str, dict[str, str]]:
    """Read exact-content operator reviews, never filename-wide exclusions."""
    with config_path.open("rb") as stream:
        config = tomllib.load(stream)
    settings = config
    for key in ("harness", "scans"):
        settings = settings.get(key, {})
        if not isinstance(settings, dict):
            raise ValueError("requirements input reviews require harness.scans to be a table")
    entries = settings.get("reviewed_non_dependency_requirements", [])
    if not isinstance(entries, list):
        raise ValueError("reviewed_non_dependency_requirements must be an array of tables")
    reviews: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "reason"}:
            raise ValueError("requirements input review requires exactly path, sha256 and reason")
        if not all(isinstance(value, str) for value in entry.values()):
            raise ValueError("requirements input review fields must be strings")
        relative = normalized_target_relative(entry["path"])
        if relative is None or relative.name != "requirements.txt":
            raise ValueError("requirements input review must name a target-relative requirements.txt")
        if entry["path"] in reviews:
            raise ValueError("requirements input reviews contain a duplicate path")
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("requirements input review requires a lowercase SHA-256")
        reason = entry["reason"]
        if not 1 <= len(reason) <= 500 or reason != reason.strip() or not reason.isprintable():
            raise ValueError("requirements input review requires a printable reason of 1 to 500 characters")
        reviews[entry["path"]] = entry
    return reviews


def requirements_input_disposition(path: Path, review: dict[str, str] | None = None) -> str | None:
    """Exclude only proven empty input or the exact bytes explicitly reviewed."""
    if path.name != "requirements.txt":
        return None
    data = path.read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    if all(not line.strip() or line.lstrip().startswith("#") for line in text.splitlines()):
        return "requirements_no_dependency_inventory"
    if review is not None and hashlib.sha256(data).hexdigest() == review["sha256"]:
        return "requirements_reviewed_non_dependency"
    # Includes, options, URLs, malformed and unrecognized content still reach
    # the scanner. A changed review never becomes an implicit exclusion.
    return None


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
            if resolved not in seen_targets and is_scannable_dependency_path(resolved):
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
        "deps.json": {"c#", "csharp", ".net", "dotnet"},
        "packages.config": {"c#", "csharp", ".net", "dotnet"}, "packages.lock.json": {"c#", "csharp", ".net", "dotnet"},
        "cabal.project.freeze": {"haskell"}, "stack.yaml.lock": {"haskell"}, "renv.lock": {"r"},
    }
    return frozenset(mapping.get(name, set()))


def discover_dependency_limitations(
    repo: Path, scanner_incompatible_files: list[str] | None = None,
    *, metadata_only_npm_files: list[str] | tuple[str, ...] = (),
    empty_requirements_files: list[str] | tuple[str, ...] = (),
    reviewed_requirements_files: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, object]]:
    """Return deterministic structured gaps that cannot be scanned offline."""
    root = repo.resolve(strict=True)
    conan: list[str] = []
    discovered_scanner_incompatible: list[str] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(root)
        directories[:] = [
            name
            for name in sorted(directories)
            if name not in DEFAULT_EXCLUDED_DIRECTORIES and not (current_path / name).is_symlink()
        ]
        for name in sorted(files):
            candidate = current_path / name
            if candidate.is_symlink():
                continue
            relative = (relative_dir / name).as_posix()
            if name in {"conan.lock", "conanfile.py", "conanfile.txt"}:
                conan.append(relative)
            elif name in {"pom.xml", "cabal.project.freeze"}:
                discovered_scanner_incompatible.append(relative)
    if scanner_incompatible_files is None:
        omitted_scanner_inputs = sorted(set(discovered_scanner_incompatible))
    else:
        omitted_scanner_inputs = sorted(
            {
                normalized.as_posix()
                for value in scanner_incompatible_files
                if (normalized := normalized_target_relative(value)) is not None
                and normalized.name in {"pom.xml", "cabal.project.freeze"}
            }
        )
    limitations: list[dict[str, object]] = []
    if conan:
        limitations.append(
            {
                "code": "conan_offline_sca_unsupported",
                "message": "Conan dependency inputs are excluded because OSV has no offline Conan ecosystem database.",
                "files": conan,
            }
        )
    if omitted_scanner_inputs:
        limitations.append(
            {
                "code": "bundled_scanner_input_unsupported",
                "message": "The bundled Wraith/OSV versions cannot extract packages from Maven POM or Cabal freeze inputs; these files are reported instead of failing Tool Collection.",
                "files": omitted_scanner_inputs,
            }
        )
    if metadata_only_npm_files:
        limitations.append(
            {
                "code": "npm_lockfile_no_dependency_inventory",
                "message": "Metadata-only npm v1 lockfiles contain no dependency inventory and were not scanned; this does not establish absence of application dependencies.",
                "files": sorted(set(metadata_only_npm_files)),
            }
        )
    if empty_requirements_files:
        limitations.append(
            {
                "code": "requirements_no_dependency_inventory",
                "message": "Empty or comment-only Python requirements files contain no dependency inventory and were not scanned; this does not establish absence of application dependencies.",
                "files": sorted(set(empty_requirements_files)),
            }
        )
    if reviewed_requirements_files:
        limitations.append(
            {
                "code": "requirements_reviewed_non_dependency",
                "message": "Requirements-named files explicitly reviewed as non-dependency documents were not scanned because their current bytes match the recorded reviews; Python dependency coverage is not established for these files.",
                "files": sorted(reviewed_requirements_files),
                "reviews": [
                    {"file": relative, "sha256": review["sha256"], "reason": review["reason"]}
                    for relative, review in sorted(reviewed_requirements_files.items())
                ],
            }
        )
    return limitations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--ecosystem", action="store_true")
    parser.add_argument("--limitations", type=Path)
    args = parser.parse_args()
    if args.list:
        print(json.dumps(supported_display_names(), indent=2))
        return 0
    if args.limitations is not None:
        print(json.dumps(discover_dependency_limitations(args.limitations), indent=2, sort_keys=True))
        return 0
    if args.ecosystem:
        if len(args.paths) != 1:
            parser.error("--ecosystem requires exactly one target-relative dependency path")
        ecosystem = ecosystem_for_dependency_file(args.paths[0])
        if ecosystem is None:
            print(f"unsupported Wraith dependency input: {args.paths[0]}", file=__import__("sys").stderr)
            return 1
        print(ecosystem)
        return 0
    invalid = [path for path in args.paths if not is_supported_dependency_file(path)]
    if invalid:
        for path in invalid:
            print(f"unsupported Wraith dependency input: {path}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
