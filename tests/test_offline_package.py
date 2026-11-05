from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
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
    host_platform,
    install_runtime_asset,
    rebuild_chunks,
    safe_extract_tar,
    sha256_path,
    validate_chunk_manifest,
    validate_package_config,
    validate_tool_lock,
    verify_manifest,
    verify_native_skill_references,
    verify_runtime_install,
    verify_grammars,
    write_chunks,
)
from scripts.osv_snapshot import ECOSYSTEMS, SnapshotError, load_lock, refresh_lock, verify
from scripts.model_routing import GROUP_AGENTS, resolve_routing


ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def exercise_relocated_gap_package(platform: str | None = None) -> dict:
    """Synthetic package/readiness smoke; no binaries, downloads, models or scans.

    Source selection uses the packer's Git inventory (including development
    additions), and manifest/archive inclusion uses its existing recursive APIs.
    Only deployable harness directories are read; live configuration is not used.
    """
    case = unittest.TestCase()
    platform = platform or host_platform()
    validate_tool_lock(ROOT / f"config/offline-pack.{platform}.lock.json", platform)
    selected = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others",
         "--exclude-standard", "--", "scripts", "schemas", "config",
         ".omp/agents", ".omp/main", ".omp/skills", "advantage.sh"],
        check=True, capture_output=True,
    )
    sources = sorted(set(os.fsdecode(selected.stdout).split("\0")) - {""})
    gap_sources = {
        path.relative_to(ROOT).as_posix()
        for pattern in ("scripts/*gap*.py", "schemas/v2/gap-*.schema.json",
                        ".omp/agents/vulnops-*gap*.md")
        for path in ROOT.glob(pattern)
    }
    case.assertTrue(gap_sources, "supplementary sources must exist")
    case.assertLessEqual(gap_sources, set(sources), "gap source missing from package Git inventory")
    groups = {group: f"fixture/{group}:high" for group in GROUP_AGENTS}
    routing = resolve_routing({"routing": groups})
    gap_actors = {
        "vulnops-gap-exploration": "intrusion",
        "vulnops-gap-investigator": "intrusion",
        "vulnops-advantage-gap-exploration": "advantage",
        "vulnops-advantage-gap-investigator": "advantage",
    }
    with tempfile.TemporaryDirectory(prefix="gap-package-") as temporary:
        base = Path(temporary)
        package = base / "staging"
        for relative in sources:
            source = ROOT / relative
            if not source.is_file():
                continue  # Same missing tracked-file behavior as copy_candidate.
            destination = package / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=False)
        for relative in (
            "scripts/recover-advantage.py", "scripts/update-advantage-state.py",
            "scripts/close-interrupted-advantage.py",
            *[f"schemas/v2/advantage-{name}.schema.json"
              for name in ("manifest", "phase-manifest", "task-ledger", "dispatch")],
        ):
            case.assertFalse((package / relative).exists(), relative)
        for relative in ("scripts/advantage-cleanup.py", "scripts/recover-run.py",
                         "scripts/update-run-state.py", "scripts/update-remediation-state.py"):
            case.assertTrue((package / relative).is_file(), relative)
        (package / "config.toml").write_text(
            "[llm.routing]\n"
            + "".join(f'{group} = "{selector}"\n' for group, selector in groups.items())
            + '\n[harness.network]\nlinux_agent_egress = "policy_only"\n'
        )
        manifest_name = "offline-pack-manifest.json"
        create_manifest(argparse.Namespace(
            root=package, output=package / manifest_name, platform=platform,
            tool_lock=package / f"config/offline-pack.{platform}.lock.json",
            tool_lock_relative=f"config/offline-pack.{platform}.lock.json",
            osv_lock=package / "config/osv-snapshot.lock.json",
            osv_lock_relative="config/osv-snapshot.lock.json",
            source_commit="a" * 40, source_state="development",
            source_date_epoch=1_700_000_000, created_at="2023-11-14T22:13:20Z",
            live_config=False,
        ))
        archive = base / "synthetic.tar.gz"
        create_archive(package, archive, 1_700_000_000)
        relocated = base / "relocated harness"
        safe_extract_tar(archive, relocated)
        document = verify_manifest(relocated, relocated / manifest_name)
        case.assertLessEqual(gap_sources, {item["path"] for item in document["files"]})
        case.assertFalse((relocated / "reviewers").exists())
        case.assertEqual(
            {path.name for path in relocated.glob(".*")}, {".omp"},
            "generated editor adapters must not enter the native-only fixture",
        )
        native_skills = verify_native_skill_references(relocated)
        case.assertEqual(len(native_skills), 30)
        case.assertEqual(
            native_skills,
            {path.parent.name for path in (relocated / ".omp/skills").glob("*/SKILL.md")},
        )
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("VULNOPS_", "VULNOPSV3_", "PI_", "OMP_", "PYTHON"))
        }
        environment.update(PYTHONDONTWRITEBYTECODE="1", HOME=str(base))

        def command(*arguments, success=True):
            result = subprocess.run(
                list(map(str, arguments)), cwd=relocated, env=environment,
                capture_output=True, text=True, timeout=60, check=False,
            )
            case.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
            return result

        validator = relocated / "scripts/validate-omp-agents.py"
        command(sys.executable, validator, relocated)
        package_validator = relocated / "scripts/offline_package.py"
        command(sys.executable, package_validator, "verify-advantage-sources", relocated)

        # Both actual commands must reject the same broken transitive closure,
        # without a reviewer snapshot or an editor adapter supplying a fallback.
        reference = relocated / ".omp/skills/vulnops-self-verification/references/static-assessment.md"
        original_reference = reference.read_bytes()
        reference.unlink()
        for arguments in (
            (sys.executable, validator, relocated),
            (sys.executable, package_validator, "verify-advantage-sources", relocated),
        ):
            rejected = command(*arguments, success=False)
            case.assertIn("static-assessment.md", rejected.stderr)
            case.assertIn(" -> ", rejected.stderr)
            case.assertIn("missing native document", rejected.stderr)
        reference.write_bytes(original_reference)
        command(sys.executable, validator, relocated)
        command(sys.executable, package_validator, "verify-advantage-sources", relocated)
        command("bash", relocated / "scripts/bootstrap-omp.sh")
        overrides = dict(re.findall(
            r"^    (vulnops-[\w-]+): '([^']+)'$",
            (relocated / ".omp/config.yml").read_text(), re.MULTILINE,
        ))
        case.assertEqual(overrides, routing["agents"])
        for actor, group in gap_actors.items():
            case.assertEqual(overrides[actor], groups[group])
        case.assertNotIn(str(package), (relocated / ".omp/config.yml").read_text())
        agent_home = relocated / ".harness/home/.omp/agent/config.yml"
        case.assertIn(str(relocated / "scripts/agent-shell.sh"), agent_home.read_text())
        case.assertNotIn(str(package), agent_home.read_text())

        # The offline probe sees synthetic OMP metadata only. Any inference,
        # installer, dispatch or other unapproved invocation fails immediately.
        metadata = base / "metadata.json"
        catalog = {"models": [
            {"provider": "fixture", "id": group, "thinking": ["high"]}
            for group in GROUP_AGENTS
        ]}
        write_json(metadata, {"overrides": overrides, "catalog": catalog})
        omp = base / "fixture-omp"
        omp.write_text(
            f"#!{sys.executable}\nimport json, sys\nfrom pathlib import Path\n"
            f"data = json.loads(Path({str(metadata)!r}).read_text())\n"
            "args = sys.argv[1:]\n"
            "if args == ['config', 'get', 'task.agentModelOverrides', '--json']:\n"
            "    print(json.dumps({'value': data['overrides']}))\n"
            "elif args == ['models', 'fixture', '--json', '--no-extensions']:\n"
            "    print(json.dumps(data['catalog']))\n"
            "else:\n    raise SystemExit('non-metadata command forbidden')\n"
        )
        omp.chmod(0o755)
        probe = relocated / "scripts/probe-verifier-model.py"
        ready = command(sys.executable, probe, omp, "--root", relocated, "--offline")
        case.assertIn("catalog resolved; live access not checked", ready.stdout)
        for actor in gap_actors:
            with case.subTest(missing_override=actor):
                write_json(metadata, {"overrides": {
                    key: value for key, value in overrides.items() if key != actor
                }, "catalog": catalog})
                rejected = command(sys.executable, probe, omp, "--root", relocated,
                                   "--offline", success=False)
                case.assertIn("effective agent overrides differ", rejected.stderr)
        for group in ("intrusion", "advantage"):
            with case.subTest(missing_high=group):
                bad_catalog = {"models": [
                    {**item, "thinking": ["low"]} if item["id"] == group else item
                    for item in catalog["models"]
                ]}
                write_json(metadata, {"overrides": overrides, "catalog": bad_catalog})
                rejected = command(sys.executable, probe, omp, "--root", relocated,
                                   "--offline", success=False)
                case.assertIn("unsupported reasoning effort", rejected.stderr)

        commands = sorted(path for path in gap_sources
                          if path.startswith("scripts/") and "-" in Path(path).stem)
        case.assertTrue(commands, "supplementary CLI inventory must not be empty")
        for relative in commands:
            command(sys.executable, relocated / relative, "--help")
        for actor in gap_actors:
            path = relocated / ".omp/agents" / f"{actor}.md"
            original = path.read_text()
            expected_tools = {"read", "write", "grep", "glob", "bash", "yield"}
            if actor.endswith("-exploration"):
                expected_tools.update(("task", "wait"))
            tools = re.search(r"^tools: \[([^]]+)\]$", original, re.MULTILINE)
            case.assertIsNotNone(tools, actor)
            case.assertEqual({item.strip() for item in tools.group(1).split(",")}, expected_tools)
            for old, new, diagnostic in (
                ("bash", "network", "tools are missing or unsupported"),
                ("model: [pi/task]", "model: [pi/slow]", "canonical contract"),
                ("thinkingLevel: high", "thinkingLevel: low", "reasoning must be high"),
            ):
                with case.subTest(actor=actor, invalid=new):
                    path.write_text(original.replace(old, new, 1))
                    rejected = command(sys.executable, validator, relocated, success=False)
                    case.assertIn(diagnostic, rejected.stderr)
                    path.write_text(original)
        # Readiness may create mutable local state, never rewrite locked inputs.
        verify_manifest(relocated, relocated / manifest_name)
        return {"platform": platform, "gap_sources": sorted(gap_sources),
                "agents": sorted(gap_actors), "commands": commands,
                "readiness": "synthetic offline catalog; no live inference"}


class NativeSkillReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="native-skill-references-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.entry = self.write_skill("vulnops-one", "Read [guidance](references/guide.md).")
        self.guide = self.write_file(".omp/skills/vulnops-one/references/guide.md", "Native guidance.\n")

    def write_file(self, relative: str, text: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_skill(self, name: str, body: str) -> Path:
        return self.write_file(
            f".omp/skills/{name}/SKILL.md",
            f"---\nname: {name}\ndescription: Native fixture skill\n---\n{body}\n",
        )

    def assert_reference_error(self, consumer: Path, target: str, reason: str) -> None:
        with self.assertRaises(ContractError) as raised:
            verify_native_skill_references(self.root)
        diagnostic = str(raised.exception)
        self.assertIn(consumer.relative_to(self.root).as_posix(), diagnostic)
        self.assertIn(target, diagnostic)
        self.assertIn(reason, diagnostic)

    def test_missing_and_empty_methodology_identify_consumer_and_target(self) -> None:
        self.guide.unlink()
        self.assert_reference_error(self.entry, "references/guide.md", "missing")
        for content in ("", " \n\t"):
            with self.subTest(content=content):
                self.guide.write_text(content)
                self.assert_reference_error(self.entry, "references/guide.md", "empty")
        self.guide.unlink()
        self.guide.mkdir()
        self.assert_reference_error(self.entry, "references/guide.md", "missing")

    def test_transitive_missing_methodology_is_not_hidden_by_existing_entry(self) -> None:
        self.guide.write_text("For the next step read [detail](nested/detail.md).\n")
        detail = self.write_file(
            ".omp/skills/vulnops-one/references/nested/detail.md",
            "Then read [control](../control.md).\n",
        )
        self.assert_reference_error(detail, "../control.md", "missing")

    def test_unresolved_skills_in_every_native_consumer_and_reference(self) -> None:
        for relative, content in (
            (".omp/agents/vulnops-worker.md", "Read `skill://vulnops-absent`.\n"),
            (".omp/main/vulnops-main.md", "Read skill://vulnops-absent\n"),
            ("config/attack-taxonomy-v2.json",
             '{"classes": [{"methodology_ref": "skill://vulnops-absent#proof"}]}\n'),
            (".omp/skills/vulnops-one/references/guide.md", "Read `skill://vulnops-absent`.\n"),
        ):
            with self.subTest(consumer=relative):
                consumer = self.write_file(relative, content)
                self.assert_reference_error(consumer, "skill://vulnops-absent", "unresolved")
                if consumer == self.guide:
                    consumer.write_text("Native guidance.\n")
                else:
                    consumer.unlink()

    def test_escaped_and_redirected_methodology_are_rejected(self) -> None:
        outside = self.write_file("outside.md", "Not native guidance.\n")
        for reference in ("../../../outside.md", str(outside)):
            with self.subTest(reference=reference):
                self.entry = self.write_skill("vulnops-one", f"Read [guidance]({reference}).")
                self.assert_reference_error(self.entry, reference, "escapes")
        self.entry = self.write_skill("vulnops-one", "Read [guidance](references/guide.md).")
        self.guide.unlink()
        for destination in (
            outside,
            self.write_file(".omp/skills/vulnops-one/references/other.md", "Other guidance.\n"),
        ):
            with self.subTest(destination=destination):
                self.guide.symlink_to(destination)
                self.assert_reference_error(self.entry, "references/guide.md", "redirected")
                self.guide.unlink()
        redirected = self.write_file("outside/guide.md", "Outside directory.\n").parent
        shutil.rmtree(self.guide.parent)
        self.guide.parent.symlink_to(redirected, target_is_directory=True)
        self.assert_reference_error(self.entry, "references/guide.md", "redirected")
        self.guide.parent.unlink()
        self.guide.parent.mkdir()
        self.guide.write_text("Native guidance.\n")
        (self.guide.parent / "redirect").symlink_to(redirected, target_is_directory=True)
        reference = "references/redirect/../guide.md"
        self.entry = self.write_skill("vulnops-one", f"Read [guidance]({reference}).")
        self.assert_reference_error(self.entry, reference, "redirected")

    def test_skill_uri_suffix_cannot_escape_to_an_existing_consumer(self) -> None:
        consumer = self.write_file(".omp/agents/vulnops-worker.md", "Native worker.\n")
        self.guide.write_text("Read `skill://vulnops-one/../../agents/vulnops-worker.md`.\n")
        self.assert_reference_error(self.guide, "skill://vulnops-one/", "escapes")
        self.assertTrue(consumer.is_file())

    def test_sibling_owner_cycle_and_skill_uri_document_resolve(self) -> None:
        self.write_skill("vulnops-two", "Read `skill://vulnops-one#method`.\n")
        self.guide.write_text("Read [shared](../../vulnops-two/references/shared.md#controls).\n")
        self.write_file(
            ".omp/skills/vulnops-two/references/shared.md",
            "Read [cycle](../../vulnops-one/references/guide.md).\n"
            "Read `skill://vulnops-two/references/extra.md`.\n",
        )
        self.write_file(".omp/skills/vulnops-two/references/extra.md", "Extra guidance.\n")
        self.assertEqual(verify_native_skill_references(self.root), {"vulnops-one", "vulnops-two"})

    def test_nonmethodology_mentions_are_not_dependencies(self) -> None:
        self.guide.write_text(
            "Source example: `references/not-present.md` and "
            "`[example](references/not-present.md)`.\n"
            '`read("skill://vulnops-example")` is source, not a read directive.\n'
            "```markdown\nRead `skill://vulnops-fenced`.\n"
            "[example](missing.md)\n```\n"
            "~~~~markdown\n[example](also-missing.md)\n~~~\n"
            "skill://vulnops-still-fenced\n~~~~\n"
            "[upstream](https://example.invalid/reference.md)\n"
            "[section](#controls)\n"
            "[schema](../../../../schemas/v2/example.schema.json)\n"
            "[schema guidance](../../../../schemas/README.md)\n"
            "[controller](../../../main/vulnops-main.md)\n"
            "[source](../../../../target/example.md)\n"
            "[artifact](../../../../scans/assigned/result.md)\n"
            "Assigned `target/file.py`, `scans/<run>/result.json` and prose missing.md.\n"
        )
        self.assertEqual(verify_native_skill_references(self.root), {"vulnops-one"})

    def test_product_frontmatter_must_identify_nonempty_real_skill(self) -> None:
        original = self.entry.read_text()
        for content, reason in (
            ("# No frontmatter\n", "frontmatter"),
            (original.replace("name: vulnops-one", "name: vulnops-wrong"), "match directory"),
            (original.replace("description: Native fixture skill", "description: ''"), "description"),
            ("---\nname: vulnops-one\ndescription: Native fixture\n---\n \n", "body"),
        ):
            with self.subTest(reason=reason):
                self.entry.write_text(content)
                self.assert_reference_error(self.entry, "SKILL.md", reason)
        self.entry.write_text(original)
        self.entry.unlink()
        self.assert_reference_error(self.entry, "SKILL.md", "missing")


class OfflinePackageTests(unittest.TestCase):
    def test_relocated_gap_package_inventory_and_offline_readiness(self) -> None:
        result = exercise_relocated_gap_package()
        self.assertEqual(len(result["agents"]), 4)
        self.assertIn("scripts/gap_exploration_contract.py", result["gap_sources"])
        self.assertIn("scripts/gap_graph.py", result["gap_sources"])
        self.assertIn("scripts/gap_dossier.py", result["gap_sources"])
        self.assertIn("scripts/gap-dossier.py", result["commands"])
        self.assertIn("scripts/gap-exploration-worker.py", result["commands"])
        self.assertIn("scripts/prepare-gap-exploration.py", result["commands"])
        self.assertIn("scripts/finalize-gap-exploration.py", result["commands"])
        for name in ("inputs", "plan", "packet", "dispatch", "result", "results",
                     "common", "exploration-budget"):
            self.assertIn(f"schemas/v2/gap-{name}.schema.json", result["gap_sources"])

    def test_platform_locks_are_strict_and_include_omp_runtime(self) -> None:
        for platform in ("linux_amd64", "darwin_arm64"):
            lock = validate_tool_lock(ROOT / f"config/offline-pack.{platform}.lock.json", platform)
            self.assertEqual(set(lock["tools"]), set(TOOLS))
            self.assertEqual(set(lock["runtime_assets"]), {"omp-natives"})
            self.assertTrue(lock["runtime_assets"]["omp-natives"]["members"])
            self.assertTrue(all(item["url"].startswith("https://") for item in lock["tools"].values()))

    def test_grammar_lock_accepts_new_releases_but_rejects_unsafe_or_duplicate_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            original = json.loads((ROOT / "config/offline-pack.darwin_arm64.lock.json").read_text())
            original["tools"]["omp"]["version"] = "v99.1.0"
            original["grammar_assets"]["version"] = "99.1.0"
            original["grammar_assets"]["members"][0]["language"] = "future-language"
            write_json(path, original)
            self.assertEqual(validate_tool_lock(path)["grammar_assets"]["members"][0]["language"],
                             "future-language")
            for target in ("../outside.wasm", "/tmp/outside.wasm", "nested/file.wasm"):
                with self.subTest(target=target):
                    changed = json.loads(json.dumps(original))
                    changed["grammar_assets"]["members"][0]["target"] = target
                    write_json(path, changed)
                    with self.assertRaisesRegex(ContractError, "safe WASM filename"):
                        validate_tool_lock(path)
            original["grammar_assets"]["members"].append(dict(original["grammar_assets"]["members"][0]))
            write_json(path, original)
            with self.assertRaisesRegex(ContractError, "unique"):
                validate_tool_lock(path)

    def test_offline_grammar_verification_detects_missing_corrupt_and_symlinked_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "grammars" / "sample.wasm"
            path.parent.mkdir()
            content = b"grammar fixture"
            lock = {"grammar_assets": {"members": [{"target": path.name,
                    "installed_size": len(content), "installed_sha256": hashlib.sha256(content).hexdigest()}]}}
            with self.assertRaisesRegex(ContractError, "grammar is missing"):
                verify_grammars(lock, directory)
            path.write_bytes(content)
            verify_grammars(lock, directory)
            path.write_bytes(b"damaged fixture")
            with self.assertRaisesRegex(ContractError, "SHA-256 mismatch"):
                verify_grammars(lock, directory)
            path.unlink()
            outside = directory / "outside"
            outside.write_bytes(content)
            path.symlink_to(outside)
            with self.assertRaisesRegex(ContractError, "grammar is missing"):
                verify_grammars(lock, directory)

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
                database = cache / "osv-scalibr" / ecosystem / "all.zip"
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
            (cache / "osv-scalibr/Packagist/all.zip").unlink()
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
                database = cache / "osv-scalibr" / ecosystem / "all.zip"
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
            receipt = json.loads((cache / "osv-scalibr/snapshot.json").read_text())
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
            metadata = repo / "metadata"
            metadata.mkdir()
            (metadata / "pom.xml").write_text("<project><packaging>pom</packaging></project>\n")
            limitations = discover_dependency_limitations(repo)
            self.assertEqual(
                [item["code"] for item in limitations],
                ["conan_offline_sca_unsupported", "bundled_scanner_input_unsupported"],
            )
            self.assertEqual(limitations[0]["files"], ["conan.lock", "conanfile.txt"])
            self.assertEqual(limitations[1]["files"], ["metadata/pom.xml", "pom.xml"])



if __name__ == "__main__":
    unittest.main()
