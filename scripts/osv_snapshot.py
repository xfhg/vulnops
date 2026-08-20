#!/usr/bin/env python3
"""Download and verify the complete lockfile-focused OSV offline snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "vulnops.osv-snapshot-lock.v1"
ECOSYSTEMS = (
    "CRAN",
    "Go",
    "Hackage",
    "Hex",
    "Maven",
    "NuGet",
    "Packagist",
    "Pub",
    "PyPI",
    "RubyGems",
    "crates.io",
    "npm",
)


class SnapshotError(ValueError):
    pass


MAX_ECOSYSTEM_BYTES = 1024 * 1024 * 1024
DATABASE_DIRECTORY = "osv-scalibr"
LEGACY_DATABASE_DIRECTORY = "osv-scanner"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read OSV snapshot lock: {exc}") from exc
    if not isinstance(value, dict):
        raise SnapshotError("OSV snapshot lock must contain an object")
    if set(value) != {"schema", "snapshot", "generated_at", "ecosystems"}:
        raise SnapshotError("OSV snapshot lock fields are invalid")
    if value["schema"] != SCHEMA or not str(value["snapshot"]).strip() or not str(value["generated_at"]).strip():
        raise SnapshotError("OSV snapshot lock identity is invalid")
    items = value["ecosystems"]
    if not isinstance(items, list) or [item.get("name") for item in items if isinstance(item, dict)] != list(ECOSYSTEMS):
        raise SnapshotError("OSV snapshot ecosystems must be complete and canonically ordered")
    for item in items:
        if not isinstance(item, dict) or set(item) != {"name", "url", "size", "sha256"}:
            raise SnapshotError("OSV snapshot ecosystem fields are invalid")
        if item["url"] != f"https://osv-vulnerabilities.storage.googleapis.com/{item['name']}/all.zip":
            raise SnapshotError(f"OSV snapshot URL is not canonical for {item['name']}")
        if not isinstance(item["size"], int) or item["size"] < 1:
            raise SnapshotError(f"OSV snapshot size is invalid for {item['name']}")
        digest = str(item["sha256"])
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise SnapshotError(f"OSV snapshot SHA-256 is invalid for {item['name']}")
    return value


def validate_zip(path: Path, ecosystem: str) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            bad = archive.testzip()
            if bad is not None:
                raise SnapshotError(f"{ecosystem} database has a corrupt member")
            members = [item for item in archive.infolist() if not item.is_dir()]
            if not members:
                raise SnapshotError(f"{ecosystem} database is empty")
            if not any(item.filename.endswith(".json") for item in members):
                raise SnapshotError(f"{ecosystem} database contains no advisory JSON")
    except zipfile.BadZipFile as exc:
        raise SnapshotError(f"{ecosystem} database is not a valid ZIP") from exc


def target_path(cache_root: Path, ecosystem: str) -> Path:
    return cache_root / DATABASE_DIRECTORY / ecosystem / "all.zip"


def migrate_legacy_database_root(cache_root: Path) -> None:
    current = cache_root / DATABASE_DIRECTORY
    legacy = cache_root / LEGACY_DATABASE_DIRECTORY
    if current.exists() and legacy.exists():
        if current.is_dir() and not current.is_symlink() and not any(current.iterdir()):
            current.rmdir()
        elif legacy.is_dir() and not legacy.is_symlink() and not any(legacy.iterdir()):
            legacy.rmdir()
            return
        else:
            raise SnapshotError("both current and legacy OSV database directories exist")
    if current.exists() or not legacy.exists():
        return
    if legacy.is_symlink() or not legacy.is_dir():
        raise SnapshotError("legacy OSV database path is not a regular directory")
    legacy.replace(current)
    nested = current / DATABASE_DIRECTORY
    if nested.is_dir() and not nested.is_symlink() and not any(nested.iterdir()):
        nested.rmdir()


def canonicalize_ecosystem_directory(cache_root: Path, ecosystem: str) -> None:
    database_root = cache_root / DATABASE_DIRECTORY
    if not database_root.is_dir():
        return
    matches = [
        path
        for path in database_root.iterdir()
        if path.name.casefold() == ecosystem.casefold()
    ]
    exact = [path for path in matches if path.name == ecosystem]
    if exact:
        if len(matches) > 1:
            raise SnapshotError(f"duplicate OSV ecosystem database directories for {ecosystem}")
        return
    if not matches:
        return
    if len(matches) > 1 or matches[0].is_symlink() or not matches[0].is_dir():
        raise SnapshotError(f"ambiguous OSV ecosystem database directory for {ecosystem}")
    temporary = database_root / f".{ecosystem}.casefix.{os.getpid()}"
    if temporary.exists():
        raise SnapshotError(f"temporary OSV case-normalization path already exists for {ecosystem}")
    matches[0].replace(temporary)
    temporary.replace(database_root / ecosystem)


def download(url: str, destination: Path, maximum_bytes: int) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "vulnops-offline-pack/2"})
    total = 0
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise SnapshotError(f"OSV database download exceeds {maximum_bytes} bytes")
            output.write(chunk)


def verify_item(cache_root: Path, item: dict[str, Any]) -> None:
    ecosystem = str(item["name"])
    path = target_path(cache_root, ecosystem)
    if not path.is_file():
        raise SnapshotError(f"missing OSV database for {ecosystem}: {path}")
    if path.stat().st_size != int(item["size"]):
        raise SnapshotError(f"OSV database size mismatch for {ecosystem}")
    if sha256(path) != item["sha256"]:
        raise SnapshotError(f"OSV database SHA-256 mismatch for {ecosystem}")
    validate_zip(path, ecosystem)


def verify(lock: dict[str, Any], cache_root: Path, ecosystem: str | None = None) -> None:
    selected = [item for item in lock["ecosystems"] if ecosystem is None or item["name"] == ecosystem]
    if ecosystem is not None and not selected:
        raise SnapshotError(f"ecosystem is not in the OSV snapshot: {ecosystem}")
    for item in selected:
        verify_item(cache_root, item)
    if ecosystem is None:
        expected = {str(item["name"]) for item in lock["ecosystems"]}
        database_root = cache_root / DATABASE_DIRECTORY
        actual = {path.parent.name for path in database_root.glob("*/all.zip")} if database_root.is_dir() else set()
        extra = sorted(actual - expected)
        if extra:
            raise SnapshotError("unexpected OSV ecosystem database(s): " + ", ".join(extra))


def sync(lock: dict[str, Any], lock_path: Path, cache_root: Path) -> None:
    migrate_legacy_database_root(cache_root)
    for item in lock["ecosystems"]:
        ecosystem = str(item["name"])
        canonicalize_ecosystem_directory(cache_root, ecosystem)
        destination = target_path(cache_root, ecosystem)
        if destination.is_file():
            try:
                verify_item(cache_root, item)
                print(f"[osv-snapshot] {ecosystem}: already verified")
                continue
            except SnapshotError:
                pass
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".all.", suffix=".zip", dir=destination.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            print(f"[osv-snapshot] {ecosystem}: downloading locked database")
            download(str(item["url"]), temporary, int(item["size"]))
            if temporary.stat().st_size != int(item["size"]) or sha256(temporary) != item["sha256"]:
                raise SnapshotError(f"downloaded OSV database does not match lock for {ecosystem}")
            validate_zip(temporary, ecosystem)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    verify(lock, cache_root)
    snapshot_receipt = {
        "schema": SCHEMA,
        "snapshot": lock["snapshot"],
        "lock_sha256": sha256(lock_path),
        "ecosystems": list(ECOSYSTEMS),
    }
    receipt = cache_root / DATABASE_DIRECTORY / "snapshot.json"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".snapshot.", suffix=".json", dir=receipt.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_text(json.dumps(snapshot_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(receipt)
    finally:
        temporary.unlink(missing_ok=True)


def refresh_lock(lock_path: Path, cache_root: Path, snapshot: str) -> None:
    if not snapshot.strip() or any(character not in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-" for character in snapshot):
        raise SnapshotError("snapshot identity must use only letters, numbers, dot, underscore, and hyphen")
    cache_root.parent.mkdir(parents=True, exist_ok=True)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=".osv-refresh.", dir=cache_root.parent))
    descriptor, candidate_name = tempfile.mkstemp(prefix=".osv-lock.", suffix=".json", dir=lock_path.parent)
    os.close(descriptor)
    candidate_path = Path(candidate_name)
    try:
        migrate_legacy_database_root(cache_root)
        staged_cache = staging_root / "cache"
        ecosystems: list[dict[str, Any]] = []
        for ecosystem in ECOSYSTEMS:
            url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
            destination = target_path(staged_cache, ecosystem)
            destination.parent.mkdir(parents=True, exist_ok=True)
            print(f"[osv-snapshot] {ecosystem}: downloading candidate database")
            download(url, destination, MAX_ECOSYSTEM_BYTES)
            validate_zip(destination, ecosystem)
            ecosystems.append({
                "name": ecosystem,
                "url": url,
                "size": destination.stat().st_size,
                "sha256": sha256(destination),
            })
        candidate = {
            "schema": SCHEMA,
            "snapshot": snapshot,
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "ecosystems": ecosystems,
        }
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
        validated = load_lock(candidate_path)
        verify(validated, staged_cache)

        # Publish each validated database first and the lock last. An interrupted
        # publication is detectable because the old lock cannot validate a mixed
        # cache; a successful publication always has one exact lock identity.
        for item in validated["ecosystems"]:
            ecosystem = str(item["name"])
            source = target_path(staged_cache, ecosystem)
            canonicalize_ecosystem_directory(cache_root, ecosystem)
            destination = target_path(cache_root, ecosystem)
            destination.parent.mkdir(parents=True, exist_ok=True)
            source.replace(destination)
        candidate_path.replace(lock_path)
        verify(validated, cache_root)
        sync(validated, lock_path, cache_root)
    finally:
        candidate_path.unlink(missing_ok=True)
        shutil.rmtree(staging_root, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("sync", "verify", "identity", "refresh-lock"))
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--ecosystem")
    parser.add_argument("--snapshot")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "refresh-lock":
            if args.ecosystem is not None:
                raise SnapshotError("--ecosystem cannot be used with refresh-lock")
            if args.snapshot is None:
                raise SnapshotError("--snapshot is required with refresh-lock")
            refresh_lock(args.lock, args.cache_root, args.snapshot)
            return 0
        lock = load_lock(args.lock)
        if args.command == "sync":
            sync(lock, args.lock, args.cache_root)
        elif args.command == "verify":
            verify(lock, args.cache_root, args.ecosystem)
        else:
            print(json.dumps({
                "snapshot": lock["snapshot"],
                "lock_sha256": sha256(args.lock),
                "ecosystems": list(ECOSYSTEMS),
            }, sort_keys=True))
        return 0
    except (OSError, SnapshotError, urllib.error.URLError) as exc:
        print(f"[osv-snapshot] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
