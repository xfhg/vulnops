#!/usr/bin/env python3
"""Deterministic offline-package locks, manifests, archives, and chunks."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlparse

sys.dont_write_bytecode = True

try:
    from osv_snapshot import ECOSYSTEMS as OSV_ECOSYSTEMS
    from osv_snapshot import load_lock as load_osv_lock
except ModuleNotFoundError:  # Imported as scripts.offline_package in tests.
    from scripts.osv_snapshot import ECOSYSTEMS as OSV_ECOSYSTEMS
    from scripts.osv_snapshot import load_lock as load_osv_lock


TOOL_LOCK_SCHEMA = "vulnops.offline-tool-lock.v2"
MANIFEST_SCHEMA = "vulnops.offline-pack-manifest.v5"
CHUNK_SCHEMA = "vulnops.offline-pack-chunks.v2"
TOOLS = ("wraith", "poltergeist", "omp", "osv-scanner", "codegraph")
RUNTIME_ASSETS = ("omp-natives",)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
PLATFORMS = {"linux_amd64", "darwin_arm64"}
MUTABLE_PATHS = {
    "config.toml",
    ".omp/config.yml",
}
MUTABLE_PREFIXES = (
    "target/",
    "scans/",
    "remediations/",
    "work/",
    ".harness/",
)
IMMUTABLE_HARNESS_PREFIXES = (
    ".harness/osv-db/",
)
class ContractError(ValueError):
    """Raised for a bounded package contract failure."""


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a JSON object")
    return value


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def only_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    extra = set(value) - expected
    missing = expected - set(value)
    if extra:
        raise ContractError(f"{label} contains unknown field(s): {', '.join(sorted(extra))}")
    if missing:
        raise ContractError(f"{label} is missing field(s): {', '.join(sorted(missing))}")


def validate_tool_lock(path: Path, expected_platform: str | None = None) -> dict[str, Any]:
    lock = load_object(path)
    only_keys(lock, {"schema", "platform", "minimum_python", "tools", "runtime_assets"}, "tool lock")
    if lock["schema"] != TOOL_LOCK_SCHEMA:
        raise ContractError(f"unsupported tool lock schema: {lock['schema']!r}")
    platform = str(lock["platform"])
    if platform not in PLATFORMS:
        raise ContractError(f"unsupported tool lock platform: {platform!r}")
    if expected_platform is not None and platform != expected_platform:
        raise ContractError(f"tool lock platform {platform!r} does not match {expected_platform!r}")
    minimum_python = str(lock["minimum_python"])
    if not re.fullmatch(r"3\.(?:1[1-9]|[2-9][0-9])", minimum_python):
        raise ContractError("minimum_python must be Python 3.11 or newer")
    tools = lock["tools"]
    if not isinstance(tools, dict) or set(tools) != set(TOOLS):
        raise ContractError(f"tool lock must define exactly: {', '.join(TOOLS)}")
    for name in TOOLS:
        item = tools[name]
        if not isinstance(item, dict):
            raise ContractError(f"tool {name} must be an object")
        only_keys(item, {"version", "url", "sha256", "size", "format"}, f"tool {name}")
        if not str(item["version"]).strip():
            raise ContractError(f"tool {name} has an empty version")
        parsed = urlparse(str(item["url"]))
        if parsed.scheme != "https" or not parsed.netloc:
            raise ContractError(f"tool {name} URL must use HTTPS")
        if not SHA256_RE.fullmatch(str(item["sha256"])):
            raise ContractError(f"tool {name} has an invalid SHA-256")
        if not isinstance(item["size"], int) or item["size"] < 1:
            raise ContractError(f"tool {name} has an invalid asset size")
        if item["format"] not in {"binary", "tar.gz"}:
            raise ContractError(f"tool {name} has unsupported format {item['format']!r}")
        if name == "codegraph" and item["format"] != "tar.gz":
            raise ContractError("codegraph must be locked as a tar.gz bundle")
    runtime_assets = lock["runtime_assets"]
    if not isinstance(runtime_assets, dict) or set(runtime_assets) != set(RUNTIME_ASSETS):
        raise ContractError(f"tool lock must define exactly these runtime assets: {', '.join(RUNTIME_ASSETS)}")
    for name in RUNTIME_ASSETS:
        item = runtime_assets[name]
        if not isinstance(item, dict):
            raise ContractError(f"runtime asset {name} must be an object")
        only_keys(item, {"version", "url", "sha256", "size", "format", "members"}, f"runtime asset {name}")
        parsed = urlparse(str(item["url"]))
        if not str(item["version"]).strip() or parsed.scheme != "https" or not parsed.netloc:
            raise ContractError(f"runtime asset {name} identity is invalid")
        if not SHA256_RE.fullmatch(str(item["sha256"])):
            raise ContractError(f"runtime asset {name} has an invalid SHA-256")
        if not isinstance(item["size"], int) or item["size"] < 1 or item["format"] != "tar.gz":
            raise ContractError(f"runtime asset {name} archive contract is invalid")
        members = item["members"]
        if not isinstance(members, list) or not members:
            raise ContractError(f"runtime asset {name} must contain locked members")
        targets: list[str] = []
        for index, member in enumerate(members):
            if not isinstance(member, dict):
                raise ContractError(f"runtime asset {name} member {index} must be an object")
            only_keys(member, {"source", "target", "size", "sha256"}, f"runtime asset {name} member {index}")
            source, target = str(member["source"]), str(member["target"])
            if Path(source).name != source or Path(target).name != target or not source.endswith(".node") or not target.endswith(".node"):
                raise ContractError(f"runtime asset {name} member names are invalid")
            if not isinstance(member["size"], int) or member["size"] < 1 or not SHA256_RE.fullmatch(str(member["sha256"])):
                raise ContractError(f"runtime asset {name} member integrity is invalid")
            targets.append(target)
        if targets != sorted(targets) or len(targets) != len(set(targets)):
            raise ContractError(f"runtime asset {name} members must be uniquely sorted")
    return lock


def tool_field(path: Path, tool: str, field: str) -> str:
    lock = validate_tool_lock(path)
    if tool not in TOOLS:
        raise ContractError(f"unknown tool: {tool}")
    if field not in {"version", "url", "sha256", "size", "format"}:
        raise ContractError(f"unknown tool field: {field}")
    return str(lock["tools"][tool][field])


def runtime_field(path: Path, asset: str, field: str) -> str:
    lock = validate_tool_lock(path)
    if asset not in RUNTIME_ASSETS:
        raise ContractError(f"unknown runtime asset: {asset}")
    if field not in {"version", "url", "sha256", "size", "format"}:
        raise ContractError(f"unknown runtime asset field: {field}")
    return str(lock["runtime_assets"][asset][field])


def is_mutable(relative: str) -> bool:
    if relative in MUTABLE_PATHS:
        return True
    if any(relative.startswith(prefix) for prefix in IMMUTABLE_HARNESS_PREFIXES):
        return False
    return any(relative.startswith(prefix) for prefix in MUTABLE_PREFIXES)


def is_runtime_cache(relative: str) -> bool:
    pure = PurePosixPath(relative)
    return "__pycache__" in pure.parts or pure.suffix in {".pyc", ".pyo"}


def safe_relative(path: Path, root: Path) -> str:
    relative = path.relative_to(root).as_posix()
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ContractError(f"unsafe package path: {relative!r}")
    return relative


def iter_entries(root: Path, manifest_name: str) -> Iterable[tuple[str, Path]]:
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = safe_relative(path, root)
        if relative == manifest_name or is_mutable(relative) or is_runtime_cache(relative):
            continue
        if path.name.startswith("._"):
            raise ContractError(f"AppleDouble metadata is forbidden: {relative}")
        if path.is_dir():
            continue
        if not path.is_file() and not path.is_symlink():
            raise ContractError(f"unsupported package entry type: {relative}")
        yield relative, path


def entry_record(relative: str, path: Path, root: Path) -> dict[str, Any]:
    mode = stat.S_IMODE(path.lstat().st_mode)
    if path.is_symlink():
        target = os.readlink(path)
        resolved = (path.parent / target).resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError as exc:
            raise ContractError(f"symlink escapes package root: {relative} -> {target}") from exc
        return {"path": relative, "type": "symlink", "mode": mode, "target": target}
    return {
        "path": relative,
        "type": "file",
        "mode": mode,
        "size": path.stat().st_size,
        "sha256": sha256_path(path),
    }


def create_manifest(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    if not root.is_dir():
        raise ContractError(f"package root is not a directory: {root}")
    validate_package_config(root / "config.toml")
    tool_lock = validate_tool_lock(args.tool_lock, args.platform)
    osv_lock = load_osv_lock(args.osv_lock)
    manifest_name = args.output.name
    files = [entry_record(relative, path, root) for relative, path in iter_entries(root, manifest_name)]
    document = {
        "schema": MANIFEST_SCHEMA,
        "platform": args.platform,
        "source": {
            "commit": args.source_commit,
            "state": args.source_state,
            "source_date_epoch": args.source_date_epoch,
        },
        "created_at": args.created_at,
        "minimum_python": tool_lock["minimum_python"],
        "tool_lock": {
            "path": args.tool_lock_relative,
            "sha256": sha256_path(args.tool_lock),
        },
        "osv_snapshot": {
            "id": str(osv_lock.get("snapshot", "")),
            "lock_path": args.osv_lock_relative,
            "lock_sha256": sha256_path(args.osv_lock),
            "ecosystems": [str(item.get("name")) for item in osv_lock.get("ecosystems", [])],
        },
        "security": {
            "live_config_included": args.live_config,
            "authenticity": "sha256",
            "installation": "dependency-complete-offline",
            "runtime_policy": "configured",
        },
        "mutable_paths": sorted(MUTABLE_PATHS),
        "mutable_prefixes": sorted(MUTABLE_PREFIXES),
        "files": files,
    }
    write_json(args.output, document)


def validate_manifest_document(path: Path) -> dict[str, Any]:
    document = load_object(path)
    required = {
        "schema",
        "platform",
        "source",
        "created_at",
        "minimum_python",
        "tool_lock",
        "osv_snapshot",
        "security",
        "mutable_paths",
        "mutable_prefixes",
        "files",
    }
    only_keys(document, required, "offline package manifest")
    if document["schema"] != MANIFEST_SCHEMA:
        raise ContractError(f"unsupported package manifest schema: {document['schema']!r}")
    if document["platform"] not in PLATFORMS:
        raise ContractError("manifest platform is unsupported")
    source = document["source"]
    if not isinstance(source, dict):
        raise ContractError("manifest source must be an object")
    only_keys(source, {"commit", "state", "source_date_epoch"}, "manifest source")
    if not re.fullmatch(r"[a-f0-9]{40,64}", str(source["commit"])):
        raise ContractError("manifest source commit is invalid")
    if source["state"] not in {"release", "development"} or not isinstance(source["source_date_epoch"], int):
        raise ContractError("manifest source state or epoch is invalid")
    if not isinstance(document["created_at"], str) or not document["created_at"]:
        raise ContractError("manifest created_at is invalid")
    if not re.fullmatch(r"3\.(?:1[1-9]|[2-9][0-9])", str(document["minimum_python"])):
        raise ContractError("manifest minimum_python is invalid")
    tool_lock = document["tool_lock"]
    if not isinstance(tool_lock, dict):
        raise ContractError("manifest tool_lock must be an object")
    only_keys(tool_lock, {"path", "sha256"}, "manifest tool_lock")
    osv_snapshot = document["osv_snapshot"]
    if not isinstance(osv_snapshot, dict):
        raise ContractError("manifest osv_snapshot must be an object")
    only_keys(osv_snapshot, {"id", "lock_path", "lock_sha256", "ecosystems"}, "manifest osv_snapshot")
    for label, relative in (("tool lock", tool_lock["path"]), ("OSV lock", osv_snapshot["lock_path"])):
        pure = PurePosixPath(str(relative))
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise ContractError(f"manifest {label} path is unsafe")
    if not SHA256_RE.fullmatch(str(tool_lock["sha256"])) or not SHA256_RE.fullmatch(str(osv_snapshot["lock_sha256"])):
        raise ContractError("manifest lock SHA-256 is invalid")
    if not str(osv_snapshot["id"]).strip() or osv_snapshot["ecosystems"] != list(OSV_ECOSYSTEMS):
        raise ContractError("manifest OSV snapshot identity is incomplete")
    security = document["security"]
    if not isinstance(security, dict):
        raise ContractError("manifest security must be an object")
    only_keys(
        security,
        {
            "live_config_included",
            "authenticity",
            "installation",
            "runtime_policy",
        },
        "manifest security",
    )
    if not isinstance(security["live_config_included"], bool) or security["authenticity"] != "sha256":
        raise ContractError("manifest security metadata is invalid")
    if (
        security["installation"] != "dependency-complete-offline"
        or security["runtime_policy"] != "configured"
    ):
        raise ContractError("manifest installation metadata is invalid")
    if document["mutable_paths"] != sorted(MUTABLE_PATHS) or document["mutable_prefixes"] != sorted(MUTABLE_PREFIXES):
        raise ContractError("manifest mutable path policy does not match the package contract")
    files = document["files"]
    if not isinstance(files, list):
        raise ContractError("manifest files must be an array")
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ContractError(f"manifest files[{index}] must be an object")
        kind = item.get("type")
        expected = {"path", "type", "mode", "size", "sha256"} if kind == "file" else {"path", "type", "mode", "target"}
        only_keys(item, expected, f"manifest files[{index}]")
        relative = str(item["path"])
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise ContractError(f"manifest contains unsafe path: {relative!r}")
        if is_runtime_cache(relative):
            raise ContractError(f"manifest contains a forbidden runtime cache: {relative}")
        if relative in seen:
            raise ContractError(f"manifest contains duplicate path: {relative}")
        seen.add(relative)
        if not isinstance(item["mode"], int):
            raise ContractError(f"manifest mode is invalid for {relative}")
        if kind == "file":
            if not isinstance(item["size"], int) or item["size"] < 0:
                raise ContractError(f"manifest size is invalid for {relative}")
            if not SHA256_RE.fullmatch(str(item["sha256"])):
                raise ContractError(f"manifest SHA-256 is invalid for {relative}")
        elif kind != "symlink":
            raise ContractError(f"manifest type is invalid for {relative}")
    if [str(item["path"]) for item in files] != sorted(seen):
        raise ContractError("manifest file inventory must be sorted")
    return document


def verify_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    root = root.resolve()
    document = validate_manifest_document(manifest_path)
    validate_package_config(root / "config.toml")
    expected = {str(item["path"]): item for item in document["files"]}
    actual = {
        relative: entry_record(relative, path, root)
        for relative, path in iter_entries(root, manifest_path.name)
    }
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = sorted(relative for relative in set(expected) & set(actual) if expected[relative] != actual[relative])
    problems: list[str] = []
    if missing:
        problems.append("missing: " + ", ".join(missing[:20]))
    if extra:
        problems.append("extra: " + ", ".join(extra[:20]))
    if changed:
        problems.append("changed: " + ", ".join(changed[:20]))
    if problems:
        raise ContractError("package manifest verification failed (" + "; ".join(problems) + ")")
    tool_lock_path = root / str(document["tool_lock"]["path"])
    osv_lock_path = root / str(document["osv_snapshot"]["lock_path"])
    if sha256_path(tool_lock_path) != document["tool_lock"]["sha256"]:
        raise ContractError("package tool lock differs from manifest identity")
    if sha256_path(osv_lock_path) != document["osv_snapshot"]["lock_sha256"]:
        raise ContractError("package OSV lock differs from manifest identity")
    tool_lock = validate_tool_lock(tool_lock_path, str(document["platform"]))
    osv_lock = load_osv_lock(osv_lock_path)
    if tool_lock["minimum_python"] != document["minimum_python"]:
        raise ContractError("package Python contract differs from the tool lock")
    if osv_lock["snapshot"] != document["osv_snapshot"]["id"]:
        raise ContractError("package OSV snapshot differs from the OSV lock")
    return document


def normalized_tarinfo(path: Path, root: Path, epoch: int) -> tarfile.TarInfo:
    relative = path.relative_to(root).as_posix()
    info = tarfile.TarInfo(relative + ("/" if path.is_dir() else ""))
    source = path.lstat()
    info.mtime = epoch
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mode = stat.S_IMODE(source.st_mode)
    info.pax_headers = {}
    if path.is_symlink():
        info.type = tarfile.SYMTYPE
        info.linkname = os.readlink(path)
        info.size = 0
    elif path.is_dir():
        info.type = tarfile.DIRTYPE
        info.size = 0
    elif path.is_file():
        info.type = tarfile.REGTYPE
        info.size = source.st_size
    else:
        raise ContractError(f"unsupported archive entry: {relative}")
    return info


def create_archive(root: Path, output: Path, epoch: int) -> None:
    root = root.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    entries = sorted(
        (
            path
            for path in root.rglob("*")
            if not is_runtime_cache(safe_relative(path, root))
        ),
        key=lambda item: item.relative_to(root).as_posix(),
    )
    for path in entries:
        if path.name.startswith("._"):
            raise ContractError(f"AppleDouble metadata is forbidden: {path.relative_to(root)}")
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for path in entries:
                        info = normalized_tarinfo(path, root, epoch)
                        if path.is_file() and not path.is_symlink():
                            with path.open("rb") as handle:
                                archive.addfile(info, handle)
                        else:
                            archive.addfile(info)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def safe_extract_tar(archive_path: Path, destination: Path, strip_top_level: bool = False) -> None:
    if destination.is_symlink():
        raise ContractError(f"archive destination must not be a symlink: {destination}")
    if destination.exists() and any(destination.iterdir()):
        raise ContractError(f"archive destination must be empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:*") as archive:
        members = archive.getmembers()
        names: list[PurePosixPath] = []
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or any(part in {"", ".", ".."} for part in name.parts):
                raise ContractError(f"unsafe archive member: {member.name!r}")
            if member.isdev() or member.isfifo():
                raise ContractError(f"special archive member is forbidden: {member.name!r}")
            names.append(name)
        prefix: str | None = None
        if strip_top_level:
            roots = {name.parts[0] for name in names if name.parts}
            if len(roots) != 1:
                raise ContractError("tool bundle must contain exactly one top-level directory")
            prefix = next(iter(roots))
        for member, name in zip(members, names):
            parts = name.parts[1:] if prefix else name.parts
            if not parts:
                continue
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or ".." in link.parts:
                    raise ContractError(f"unsafe symlink in archive: {member.name!r}")
                target.symlink_to(member.linkname)
                continue
            if not member.isfile():
                raise ContractError(f"unsupported archive member: {member.name!r}")
            source = archive.extractfile(member)
            if source is None:
                raise ContractError(f"cannot extract archive member: {member.name!r}")
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(stat.S_IMODE(member.mode))


def verify_asset(path: Path, expected_size: int, expected_sha256: str) -> None:
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        raise ContractError(f"asset size mismatch: {actual_size} != {expected_size}")
    actual_sha256 = sha256_path(path)
    if actual_sha256 != expected_sha256:
        raise ContractError(f"asset SHA-256 mismatch: {actual_sha256} != {expected_sha256}")


def verify_runtime_install(lock_path: Path, asset_name: str, destination: Path) -> None:
    lock = validate_tool_lock(lock_path)
    if asset_name not in RUNTIME_ASSETS:
        raise ContractError(f"unknown runtime asset: {asset_name}")
    for member in lock["runtime_assets"][asset_name]["members"]:
        path = destination / str(member["target"])
        if not path.is_file() or path.is_symlink():
            raise ContractError(f"runtime member is missing: {path}")
        verify_asset(path, int(member["size"]), str(member["sha256"]))


def install_runtime_asset(archive: Path, lock_path: Path, asset_name: str, destination: Path) -> None:
    lock = validate_tool_lock(lock_path)
    if asset_name not in RUNTIME_ASSETS:
        raise ContractError(f"unknown runtime asset: {asset_name}")
    asset = lock["runtime_assets"][asset_name]
    verify_asset(archive, int(asset["size"]), str(asset["sha256"]))
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{asset_name}.") as temporary_name:
        temporary = Path(temporary_name)
        safe_extract_tar(archive, temporary, strip_top_level=True)
        for member in asset["members"]:
            source = temporary / str(member["source"])
            verify_asset(source, int(member["size"]), str(member["sha256"]))
            target = destination / str(member["target"])
            staging = target.with_name(f".{target.name}.{os.getpid()}.tmp")
            try:
                shutil.copyfile(source, staging)
                staging.chmod(0o755)
                staging.replace(target)
            finally:
                staging.unlink(missing_ok=True)
    verify_runtime_install(lock_path, asset_name, destination)


def alpha_suffix(index: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    if index >= len(alphabet) ** 2:
        raise ContractError("too many chunks for two-letter suffixes")
    return alphabet[index // len(alphabet)] + alphabet[index % len(alphabet)]


def write_chunks(archive: Path, output_dir: Path, platform: str, chunk_size: int) -> dict[str, Any]:
    if platform not in PLATFORMS:
        raise ContractError(f"unsupported platform: {platform}")
    if chunk_size < 1:
        raise ContractError("chunk size must be positive")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output_dir.name}.publish.", dir=output_dir.parent) as staging_name:
        staging = Path(staging_name)
        chunks: list[dict[str, Any]] = []
        with archive.open("rb") as source:
            index = 0
            while data := source.read(chunk_size):
                name = f"{archive.name}.part-{alpha_suffix(index)}"
                path = staging / name
                path.write_bytes(data)
                chunks.append({"index": index, "file": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                index += 1
        document = {
            "schema": CHUNK_SCHEMA,
            "platform": platform,
            "archive": {
                "file": archive.name,
                "size": archive.stat().st_size,
                "sha256": sha256_path(archive),
                "format": "tar.gz",
            },
            "chunk_size": chunk_size,
            "chunks": chunks,
        }
        staging_manifest = staging / "offline-pack-chunks.json"
        write_json(staging_manifest, document)
        validate_chunk_manifest(staging_manifest, platform)

        output_dir.mkdir(parents=True, exist_ok=True)
        expected_names = {str(item["file"]) for item in chunks}
        for name in sorted(expected_names):
            (staging / name).replace(output_dir / name)
        staging_manifest.replace(output_dir / "offline-pack-chunks.json")
        for path in output_dir.glob("*.part-*"):
            if path.is_file() and path.name not in expected_names:
                path.unlink()
        return document


def validate_chunk_manifest(path: Path, expected_platform: str | None = None) -> dict[str, Any]:
    document = load_object(path)
    only_keys(document, {"schema", "platform", "archive", "chunk_size", "chunks"}, "chunk manifest")
    if document["schema"] != CHUNK_SCHEMA:
        raise ContractError(f"unsupported chunk manifest schema: {document['schema']!r}")
    if document["platform"] not in PLATFORMS:
        raise ContractError("chunk manifest platform is unsupported")
    if expected_platform is not None and document["platform"] != expected_platform:
        raise ContractError("chunk manifest platform does not match requested platform")
    archive = document["archive"]
    if not isinstance(archive, dict):
        raise ContractError("chunk archive metadata must be an object")
    only_keys(archive, {"file", "size", "sha256", "format"}, "chunk archive metadata")
    name = str(archive["file"])
    if "/" in name or name.startswith(".") or not name.endswith(".tar.gz"):
        raise ContractError("chunk archive file name is unsafe")
    if archive["format"] != "tar.gz" or not isinstance(archive["size"], int) or archive["size"] < 1:
        raise ContractError("chunk archive metadata is invalid")
    if not SHA256_RE.fullmatch(str(archive["sha256"])):
        raise ContractError("chunk archive SHA-256 is invalid")
    if not isinstance(document["chunk_size"], int) or document["chunk_size"] < 1:
        raise ContractError("chunk size is invalid")
    chunks = document["chunks"]
    if not isinstance(chunks, list) or not chunks:
        raise ContractError("chunk manifest must contain at least one chunk")
    seen: set[str] = set()
    for index, item in enumerate(chunks):
        if not isinstance(item, dict):
            raise ContractError(f"chunk {index} must be an object")
        only_keys(item, {"index", "file", "size", "sha256"}, f"chunk {index}")
        if item["index"] != index:
            raise ContractError("chunks must use contiguous ordered indexes")
        chunk_name = str(item["file"])
        if "/" in chunk_name or chunk_name.startswith(".") or chunk_name in seen:
            raise ContractError(f"unsafe or duplicate chunk name: {chunk_name!r}")
        if chunk_name != f"{name}.part-{alpha_suffix(index)}":
            raise ContractError(f"chunk {index} has a non-canonical name")
        if not isinstance(item["size"], int) or item["size"] < 1 or not SHA256_RE.fullmatch(str(item["sha256"])):
            raise ContractError(f"chunk {index} metadata is invalid")
        if index < len(chunks) - 1 and item["size"] != document["chunk_size"]:
            raise ContractError(f"chunk {index} does not match the declared chunk size")
        if index == len(chunks) - 1 and item["size"] > document["chunk_size"]:
            raise ContractError("final chunk exceeds the declared chunk size")
        seen.add(chunk_name)
    if sum(int(item["size"]) for item in chunks) != int(archive["size"]):
        raise ContractError("chunk sizes do not equal archive size")
    return document


def rebuild_chunks(manifest_path: Path, output: Path | None, force: bool) -> Path:
    document = validate_chunk_manifest(manifest_path)
    directory = manifest_path.parent
    expected_names = {str(item["file"]) for item in document["chunks"]}
    actual_names = {item.name for item in directory.glob("*.part-*") if item.is_file()}
    extra = sorted(actual_names - expected_names)
    if extra:
        raise ContractError("unexpected chunk file(s): " + ", ".join(extra[:20]))
    archive_name = str(document["archive"]["file"])
    destination = output or manifest_path.parent.parent.parent / archive_name
    destination = destination.resolve()
    protected = {manifest_path.resolve()} | {(directory / name).resolve() for name in expected_names}
    if destination in protected:
        raise ContractError("output must not overwrite the chunk manifest or an input chunk")
    if destination.exists() and not force:
        raise ContractError(f"output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as combined:
            for item in document["chunks"]:
                path = directory / str(item["file"])
                if not path.is_file():
                    raise ContractError(f"missing chunk: {path}")
                verify_asset(path, int(item["size"]), str(item["sha256"]))
                with path.open("rb") as source:
                    shutil.copyfileobj(source, combined)
        verify_asset(temporary, int(document["archive"]["size"]), str(document["archive"]["sha256"]))
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def scan_path_leaks(root: Path, forbidden: str) -> None:
    needle = forbidden.encode()
    hits: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            continue
        data = path.read_bytes()
        if b"\0" not in data and needle in data:
            hits.append(path.relative_to(root).as_posix())
    if hits:
        raise ContractError("absolute staging path leaked into packaged text: " + ", ".join(hits))


def validate_package_config(config_path: Path) -> None:
    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ContractError(f"cannot read offline package configuration: {exc}") from exc
    if not isinstance(config, dict):
        raise ContractError("offline package configuration must be a TOML table")


def package_identity(root: Path) -> dict[str, Any]:
    manifest_path = root / "offline-pack-manifest.json"
    if not manifest_path.is_file():
        return {
            "manifest_sha256": None,
            "platform": host_platform(),
            "release": False,
            "osv_snapshot": "development",
            "osv_lock_sha256": None,
        }
    document = validate_manifest_document(manifest_path)
    return {
        "manifest_sha256": sha256_path(manifest_path),
        "platform": str(document["platform"]),
        "release": document.get("source", {}).get("state") == "release",
        "osv_snapshot": str(document.get("osv_snapshot", {}).get("id", "")),
        "osv_lock_sha256": str(document.get("osv_snapshot", {}).get("lock_sha256", "")) or None,
    }


def network_identity(mode: str) -> dict[str, Any]:
    if mode not in {"enforced", "policy_only"}:
        raise ContractError(f"unsupported agent egress mode: {mode!r}")
    platform = host_platform()
    enforced = mode == "enforced" and platform.startswith("linux_")
    return {
        "agent_egress": mode,
        "backend": "bubblewrap-unshare-net" if enforced else "none",
        "enforced": enforced,
        "limitation": None
        if enforced
        else "agent shell egress is not technically enforced by the harness",
    }


def host_platform() -> str:
    os_name = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)
    machine = os.uname().machine.lower()
    arch = "amd64" if machine in {"x86_64", "amd64"} else "arm64" if machine in {"aarch64", "arm64"} else None
    return f"{os_name}_{arch}" if os_name and arch else "unsupported"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    validate_lock = sub.add_parser("validate-tool-lock")
    validate_lock.add_argument("lock", type=Path)
    validate_lock.add_argument("--platform")

    field = sub.add_parser("tool-field")
    field.add_argument("lock", type=Path)
    field.add_argument("tool")
    field.add_argument("field")

    runtime_field_parser = sub.add_parser("runtime-field")
    runtime_field_parser.add_argument("lock", type=Path)
    runtime_field_parser.add_argument("asset")
    runtime_field_parser.add_argument("field")

    asset = sub.add_parser("verify-asset")
    asset.add_argument("path", type=Path)
    asset.add_argument("size", type=int)
    asset.add_argument("sha256")

    extract = sub.add_parser("extract-tool")
    extract.add_argument("archive", type=Path)
    extract.add_argument("destination", type=Path)
    extract.add_argument("--strip-top-level", action="store_true")

    install_runtime = sub.add_parser("install-runtime-asset")
    install_runtime.add_argument("archive", type=Path)
    install_runtime.add_argument("lock", type=Path)
    install_runtime.add_argument("asset")
    install_runtime.add_argument("destination", type=Path)

    verify_runtime = sub.add_parser("verify-runtime-install")
    verify_runtime.add_argument("lock", type=Path)
    verify_runtime.add_argument("asset")
    verify_runtime.add_argument("destination", type=Path)

    manifest = sub.add_parser("create-manifest")
    manifest.add_argument("root", type=Path)
    manifest.add_argument("output", type=Path)
    manifest.add_argument("--platform", required=True)
    manifest.add_argument("--tool-lock", type=Path, required=True)
    manifest.add_argument("--tool-lock-relative", required=True)
    manifest.add_argument("--osv-lock", type=Path, required=True)
    manifest.add_argument("--osv-lock-relative", required=True)
    manifest.add_argument("--source-commit", required=True)
    manifest.add_argument("--source-state", choices=("release", "development"), required=True)
    manifest.add_argument("--source-date-epoch", type=int, required=True)
    manifest.add_argument("--created-at", required=True)
    manifest.add_argument("--live-config", action="store_true")

    package_config = sub.add_parser("validate-package-config")
    package_config.add_argument("config", type=Path)

    verify = sub.add_parser("verify-manifest")
    verify.add_argument("root", type=Path)
    verify.add_argument("manifest", type=Path)

    archive = sub.add_parser("create-archive")
    archive.add_argument("root", type=Path)
    archive.add_argument("output", type=Path)
    archive.add_argument("--source-date-epoch", type=int, required=True)

    chunks = sub.add_parser("write-chunks")
    chunks.add_argument("archive", type=Path)
    chunks.add_argument("output_dir", type=Path)
    chunks.add_argument("--platform", required=True)
    chunks.add_argument("--chunk-size", type=int, default=45 * 1024 * 1024)

    validate_chunks = sub.add_parser("validate-chunks")
    validate_chunks.add_argument("manifest", type=Path)
    validate_chunks.add_argument("--platform")

    rebuild = sub.add_parser("rebuild-chunks")
    rebuild.add_argument("manifest", type=Path)
    rebuild.add_argument("--output", type=Path)
    rebuild.add_argument("--force", action="store_true")

    leaks = sub.add_parser("scan-path-leaks")
    leaks.add_argument("root", type=Path)
    leaks.add_argument("forbidden")

    identity = sub.add_parser("identity")
    identity.add_argument("root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "validate-tool-lock":
            validate_tool_lock(args.lock, args.platform)
        elif args.command == "tool-field":
            print(tool_field(args.lock, args.tool, args.field))
        elif args.command == "runtime-field":
            print(runtime_field(args.lock, args.asset, args.field))
        elif args.command == "verify-asset":
            verify_asset(args.path, args.size, args.sha256)
        elif args.command == "extract-tool":
            safe_extract_tar(args.archive, args.destination, args.strip_top_level)
        elif args.command == "install-runtime-asset":
            install_runtime_asset(args.archive, args.lock, args.asset, args.destination)
        elif args.command == "verify-runtime-install":
            verify_runtime_install(args.lock, args.asset, args.destination)
        elif args.command == "create-manifest":
            create_manifest(args)
        elif args.command == "validate-package-config":
            validate_package_config(args.config)
        elif args.command == "verify-manifest":
            document = verify_manifest(args.root, args.manifest)
            print(json.dumps({"status": "ok", "manifest_sha256": sha256_path(args.manifest), "files": len(document["files"])}))
        elif args.command == "create-archive":
            create_archive(args.root, args.output, args.source_date_epoch)
            print(sha256_path(args.output))
        elif args.command == "write-chunks":
            document = write_chunks(args.archive, args.output_dir, args.platform, args.chunk_size)
            print(json.dumps({"chunks": len(document["chunks"]), "manifest": str(args.output_dir / "offline-pack-chunks.json")}))
        elif args.command == "validate-chunks":
            validate_chunk_manifest(args.manifest, args.platform)
        elif args.command == "rebuild-chunks":
            print(rebuild_chunks(args.manifest, args.output, args.force))
        elif args.command == "scan-path-leaks":
            scan_path_leaks(args.root, args.forbidden)
        elif args.command == "identity":
            print(json.dumps(package_identity(args.root), sort_keys=True))
        return 0
    except (ValueError, OSError, tarfile.TarError) as exc:
        print(f"[offline-package] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
