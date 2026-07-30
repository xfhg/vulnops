from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

from scripts.dependency_contract import (
    DEPENDENCY_ECOSYSTEMS,
    SUPPORTED_BASENAMES,
    discover_dependency_limitations,
    ecosystem_for_dependency_file,
    is_supported_dependency_file,
)
from scripts.offline_package import (
    ContractError,
    TOOLS,
    create_archive,
    create_manifest,
    install_runtime_asset,
    rebuild_chunks,
    safe_extract_tar,
    sha256_path,
    validate_chunk_manifest,
    validate_package_config,
    validate_tool_lock,
    verify_manifest,
    verify_runtime_install,
    write_chunks,
)
from scripts.osv_snapshot import ECOSYSTEMS, SnapshotError, load_lock, refresh_lock, verify


ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


class OfflinePackageTests(unittest.TestCase):
    def test_platform_locks_are_strict_and_include_omp_runtime(self) -> None:
        for platform in ("linux_amd64", "darwin_arm64"):
            lock = validate_tool_lock(ROOT / f"config/offline-pack.{platform}.lock.json", platform)
            self.assertEqual(set(lock["tools"]), set(TOOLS))
            self.assertEqual(set(lock["runtime_assets"]), {"omp-natives"})
            self.assertTrue(lock["runtime_assets"]["omp-natives"]["members"])
            self.assertTrue(all(item["url"].startswith("https://") for item in lock["tools"].values()))

    def test_manifest_is_relocatable_exact_and_archive_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            base = Path(temporary_name)
            package = base / "package"
            package.mkdir()
            shutil.copytree(ROOT / "config", package / "config")
            (package / "scripts").mkdir()
            script = package / "scripts/run.sh"
            script.write_text("#!/usr/bin/env bash\necho offline\n")
            script.chmod(0o755)
            cache = package / "scripts/__pycache__/osv_snapshot.cpython-314.pyc"
            cache.parent.mkdir()
            cache.write_bytes(b"host-specific bytecode")
            (package / "config.toml").write_text(
                '[harness.network]\nlinux_agent_egress = "policy_only"\n'
                '[harness.reproduction]\nmode = "off"\n'
            )
            (package / "target").mkdir()
            (package / "target/input.txt").write_text("mutable target\n")
            tool_lock = package / "config/offline-pack.linux_amd64.lock.json"
            osv_lock = package / "config/osv-snapshot.lock.json"
            manifest = package / "offline-pack-manifest.json"
            create_manifest(
                argparse.Namespace(
                    root=package,
                    output=manifest,
                    platform="linux_amd64",
                    tool_lock=tool_lock,
                    tool_lock_relative="config/offline-pack.linux_amd64.lock.json",
                    osv_lock=osv_lock,
                    osv_lock_relative="config/osv-snapshot.lock.json",
                    source_commit="a" * 40,
                    source_state="release",
                    source_date_epoch=1_700_000_000,
                    created_at="2023-11-14T22:13:20Z",
                    live_config=False,
                )
            )
            document = verify_manifest(package, manifest)
            self.assertEqual(document["schema"], "vulnops.offline-pack-manifest.v5")
            self.assertEqual(
                document["security"],
                {
                    "authenticity": "sha256",
                    "installation": "dependency-complete-offline",
                    "live_config_included": False,
                    "runtime_policy": "configured",
                },
            )
            inventory = {item["path"] for item in document["files"]}
            self.assertIn("scripts/run.sh", inventory)
            self.assertNotIn("scripts/__pycache__/osv_snapshot.cpython-314.pyc", inventory)
            self.assertNotIn("config.toml", inventory)
            self.assertNotIn("target/input.txt", inventory)

            relocated = base / "relocated"
            shutil.copytree(package, relocated, symlinks=True)
            verify_manifest(relocated, relocated / manifest.name)

            first = base / "first.tar.gz"
            second = base / "second.tar.gz"
            create_archive(package, first, 1_700_000_000)
            create_archive(package, second, 1_700_000_000)
            self.assertEqual(sha256_path(first), sha256_path(second))
            with tarfile.open(first, "r:gz") as archive:
                members = archive.getmembers()
            self.assertTrue(members)
            self.assertTrue(all(member.uid == 0 and member.gid == 0 and member.mtime == 1_700_000_000 for member in members))
            self.assertFalse(any(Path(member.name).name.startswith("._") for member in members))
            self.assertFalse(any("__pycache__" in Path(member.name).parts for member in members))

            (relocated / "scripts/run.sh").write_text("tampered\n")
            with self.assertRaises(ContractError):
                verify_manifest(relocated, relocated / manifest.name)

    def test_package_config_does_not_override_runtime_capabilities(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            package = Path(temporary_name)
            config = package / "config.toml"
            config.write_text(
                '[harness.network]\nlinux_agent_egress = "policy_only"\n'
                '[harness.reproduction]\nmode = "off"\n'
            )
            validate_package_config(config)

            optional_backend = package / "scripts/safe-reproduction-backend.sh"
            optional_backend.parent.mkdir(parents=True)
            optional_backend.write_text("# optional backend\n")
            validate_package_config(config)

            config.write_text(
                '[harness.network]\nlinux_agent_egress = "enforced"\n'
                '[harness.reproduction]\nmode = "safe"\n'
            )
            validate_package_config(config)

            config.write_text(
                '[harness.network\nlinux_agent_egress = "policy_only"\n'
            )
            with self.assertRaises(ContractError):
                validate_package_config(config)

    def test_runtime_wrappers_handle_policy_only_and_missing_optional_backend(self) -> None:
        policy_shell = subprocess.run(
            [str(ROOT / "scripts/agent-shell.sh"), "-c", "printf policy-only"],
            cwd=ROOT,
            env={
                **os.environ,
                "VULNOPS_LINUX_AGENT_EGRESS": "policy_only",
                "VULNOPS_AGENT_REAL_SHELL": "/bin/sh",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(policy_shell.returncode, 0, policy_shell.stderr)
        self.assertEqual(policy_shell.stdout, "policy-only")

        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            package = Path(temporary_name)
            scripts = package / "scripts"
            scripts.mkdir()
            wrapper = scripts / "run-safe-reproduction.sh"
            shutil.copyfile(ROOT / "scripts/run-safe-reproduction.sh", wrapper)
            wrapper.chmod(0o755)
            unavailable = subprocess.run(
                [str(wrapper), "scan", "F-001", "detect"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(unavailable.returncode, 1)
            self.assertEqual(unavailable.stdout.strip(), "unavailable")

    def test_chunks_reject_tampering_and_stale_parts(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            base = Path(temporary_name)
            archive = base / "package.tar.gz"
            archive.write_bytes(bytes(range(256)) * 20)
            chunks = base / "offline/linux_amd64"
            write_chunks(archive, chunks, "linux_amd64", 1024)
            manifest = chunks / "offline-pack-chunks.json"
            validate_chunk_manifest(manifest, "linux_amd64")
            rebuilt = rebuild_chunks(manifest, base / "rebuilt.tar.gz", False)
            self.assertEqual(rebuilt.read_bytes(), archive.read_bytes())
            first = next(chunks.glob("*.part-*"))
            with self.assertRaises(ContractError):
                rebuild_chunks(manifest, first, True)

            original_manifest = json.loads(manifest.read_text())
            changed_manifest = json.loads(manifest.read_text())
            changed_manifest["chunk_size"] += 1
            write_json(manifest, changed_manifest)
            with self.assertRaises(ContractError):
                validate_chunk_manifest(manifest, "linux_amd64")
            write_json(manifest, original_manifest)

            stale = chunks / "stale.tar.gz.part-zz"
            stale.write_bytes(b"stale")
            with self.assertRaises(ContractError):
                rebuild_chunks(manifest, base / "stale-output.tar.gz", False)
            stale.unlink()

            first.write_bytes(b"x" + first.read_bytes()[1:])
            with self.assertRaises(ContractError):
                rebuild_chunks(manifest, base / "tampered.tar.gz", False)

    def test_safe_extraction_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            base = Path(temporary_name)
            archive = base / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                info = tarfile.TarInfo("../escape")
                data = b"escape"
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))
            with self.assertRaises(ContractError):
                safe_extract_tar(archive, base / "extract")
            self.assertFalse((base / "escape").exists())
            actual_destination = base / "actual"
            actual_destination.mkdir()
            linked_destination = base / "linked"
            linked_destination.symlink_to(actual_destination, target_is_directory=True)
            with self.assertRaises(ContractError):
                safe_extract_tar(archive, linked_destination)

    def test_native_runtime_archive_members_are_individually_verified(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            base = Path(temporary_name)
            native = b"native-addon-fixture"
            archive = base / "runtime.tgz"
            with tarfile.open(archive, "w:gz") as output:
                info = tarfile.TarInfo("package/pi_natives.linux-x64-modern.node")
                info.mode = 0o755
                info.size = len(native)
                output.addfile(info, io.BytesIO(native))
            tools = {
                name: {
                    "version": "v1",
                    "url": f"https://example.invalid/{name}",
                    "sha256": "a" * 64,
                    "size": 1,
                    "format": "tar.gz" if name in {"wraith", "poltergeist", "codegraph"} else "binary",
                }
                for name in TOOLS
            }
            lock = {
                "schema": "vulnops.offline-tool-lock.v2",
                "platform": "linux_amd64",
                "minimum_python": "3.11",
                "tools": tools,
                "runtime_assets": {
                    "omp-natives": {
                        "version": "v1",
                        "url": "https://example.invalid/runtime.tgz",
                        "sha256": sha256_path(archive),
                        "size": archive.stat().st_size,
                        "format": "tar.gz",
                        "members": [
                            {
                                "source": "pi_natives.linux-x64-modern.node",
                                "target": "pi_natives.linux-x64-modern.node",
                                "size": len(native),
                                "sha256": hashlib.sha256(native).hexdigest(),
                            }
                        ],
                    }
                },
            }
            lock_path = base / "lock.json"
            write_json(lock_path, lock)
            destination = base / "bins"
            install_runtime_asset(archive, lock_path, "omp-natives", destination)
            verify_runtime_install(lock_path, "omp-natives", destination)
            (destination / "pi_natives.linux-x64-modern.node").write_bytes(b"tampered")
            with self.assertRaises(ContractError):
                verify_runtime_install(lock_path, "omp-natives", destination)

    def test_osv_snapshot_requires_every_locked_ecosystem(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            base = Path(temporary_name)
            cache = base / "cache"
            items = []
            for ecosystem in ECOSYSTEMS:
                database = cache / "osv-scanner" / ecosystem / "all.zip"
                database.parent.mkdir(parents=True)
                with zipfile.ZipFile(database, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("OSV-FIXTURE.json", "{}")
                items.append(
                    {
                        "name": ecosystem,
                        "url": f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip",
                        "size": database.stat().st_size,
                        "sha256": sha256_path(database),
                    }
                )
            lock_path = base / "osv-lock.json"
            write_json(
                lock_path,
                {
                    "schema": "vulnops.osv-snapshot-lock.v1",
                    "snapshot": "fixture",
                    "generated_at": "2026-01-01T00:00:00Z",
                    "ecosystems": items,
                },
            )
            lock = load_lock(lock_path)
            verify(lock, cache)
            (cache / "osv-scanner/Packagist/all.zip").unlink()
            with self.assertRaises(SnapshotError):
                verify(lock, cache)

    def test_osv_lock_refresh_stages_all_databases_before_publication(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            base = Path(temporary_name)
            cache = base / "cache"
            archive_buffer = io.BytesIO()
            with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("OSV-FIXTURE.json", "{}")
            payload = archive_buffer.getvalue()
            items = []
            for ecosystem in ECOSYSTEMS:
                database = cache / "osv-scanner" / ecosystem / "all.zip"
                database.parent.mkdir(parents=True)
                database.write_bytes(payload)
                items.append({
                    "name": ecosystem,
                    "url": f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                })
            lock_path = base / "osv-lock.json"
            write_json(lock_path, {
                "schema": "vulnops.osv-snapshot-lock.v1",
                "snapshot": "old",
                "generated_at": "2026-01-01T00:00:00Z",
                "ecosystems": items,
            })
            old_lock = lock_path.read_bytes()

            with mock.patch(
                "scripts.osv_snapshot.urllib.request.urlopen",
                side_effect=[io.BytesIO(payload), urllib.error.URLError("fixture failure")],
            ):
                with self.assertRaises(urllib.error.URLError):
                    refresh_lock(lock_path, cache, "failed-candidate")
            self.assertEqual(lock_path.read_bytes(), old_lock)
            verify(load_lock(lock_path), cache)

            with mock.patch(
                "scripts.osv_snapshot.urllib.request.urlopen",
                side_effect=[io.BytesIO(payload) for _ in ECOSYSTEMS],
            ) as urlopen:
                refresh_lock(lock_path, cache, "new-snapshot")
            self.assertEqual(urlopen.call_count, len(ECOSYSTEMS))
            refreshed = load_lock(lock_path)
            self.assertEqual(refreshed["snapshot"], "new-snapshot")
            verify(refreshed, cache)
            receipt = json.loads((cache / "osv-scanner/snapshot.json").read_text())
            self.assertEqual(receipt["snapshot"], "new-snapshot")

    def test_dependency_ecosystem_mapping_and_structured_gaps_are_complete(self) -> None:
        expected = set(SUPPORTED_BASENAMES)
        self.assertEqual(set(DEPENDENCY_ECOSYSTEMS), expected)
        for basename in expected:
            self.assertIsNotNone(ecosystem_for_dependency_file(basename), basename)
        self.assertEqual(ecosystem_for_dependency_file("gradle/verification-metadata.xml"), "Maven")
        self.assertFalse(is_supported_dependency_file("conan.lock"))

        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as temporary_name:
            repo = Path(temporary_name)
            (repo / "conan.lock").write_text("{}")
            (repo / "conanfile.txt").write_text("[requires]\n")
            (repo / "pom.xml").write_text("<project/>\n")
            limitations = discover_dependency_limitations(repo)
            self.assertEqual(
                [item["code"] for item in limitations],
                ["conan_offline_sca_unsupported", "maven_transitive_resolution_offline"],
            )
            self.assertEqual(limitations[0]["files"], ["conan.lock", "conanfile.txt"])

    def test_offline_install_does_not_impose_network_runtime_policy(self) -> None:
        bootstrap = (ROOT / "scripts/bootstrap-omp.sh").read_text()
        launcher = (ROOT / "run.sh").read_text()
        packer = (ROOT / "scripts/offline-pack.sh").read_text()
        setup = (ROOT / "setup.sh").read_text().lower()
        guard = (ROOT / ".omp/guards/target-readonly.ts").read_text()
        project_config = (ROOT / ".omp/config.yml").read_text()
        self.assertNotIn('"fetch:"', bootstrap)
        self.assertNotIn('"web_search:"', bootstrap)
        self.assertNotIn('"  autoUpdate: off"', bootstrap)
        self.assertNotIn("--no-extensions", launcher)
        self.assertNotIn("--no-lsp", launcher)
        self.assertNotIn("offline-guard.ts", launcher)
        self.assertIn("target-readonly.ts", launcher)
        self.assertIn("lsp", launcher)
        self.assertIn('cd "$HARNESS_ROOT"', launcher)
        self.assertIn('cd "$harness_root"', setup)
        self.assertNotIn("NETWORK_COMMAND_RE", guard)
        self.assertNotIn("offline policy", guard.lower())
        self.assertIn("VULNOPSV3_TARGET", guard)
        self.assertNotIn("--agent-egress", packer)
        self.assertIn("validate-package-config", packer)
        self.assertNotIn("static-policy-only", packer)
        self.assertIn(":(exclude)offline/*/*.part-*", packer)
        self.assertNotIn("requires policy_only", setup)
        self.assertNotIn("requires reproduction mode off", setup)
        self.assertIn("runtime policy is config-driven", setup)
        self.assertIn('auth-broker login "$login_provider"', setup)
        self.assertIn("no harness dependencies will be downloaded", setup)
        self.assertNotIn("shellPath:", project_config)
        self.assertNotIn("web_search:", project_config)
        self.assertNotIn("fetch:", project_config)
        self.assertNotIn("/home/", project_config)


if __name__ == "__main__":
    unittest.main()
