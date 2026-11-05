from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from test_run_lifecycle import activate_publisher


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run(*arguments: object, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(argument) for argument in arguments],
        cwd=ROOT,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )


def initialize_repository(path: Path, filename: str, content: str) -> str:
    path.mkdir(parents=True)
    commands = (
        ("git", "init", "-q", str(path)),
        ("git", "-C", str(path), "config", "user.email", "fixture@example.invalid"),
        ("git", "-C", str(path), "config", "user.name", "Fixture"),
    )
    for command in commands:
        result = run(*command)
        if result.returncode:
            raise AssertionError(result.stderr)
    (path / filename).write_text(content, encoding="utf-8")
    for command in (
        ("git", "-C", str(path), "add", filename),
        ("git", "-C", str(path), "commit", "-q", "-m", "fixture"),
    ):
        result = run(*command)
        if result.returncode:
            raise AssertionError(result.stderr)
    result = run("git", "-C", str(path), "rev-parse", "HEAD")
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def fingerprint(path: Path) -> str:
    result = run(PYTHON, "scripts/target-fingerprint.py", path)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


class MultiRepositoryTargetTests(unittest.TestCase):
    def test_inventory_uses_common_source_root_and_ignores_nested_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            first_commit = initialize_repository(target / "service-a", "app.py", "print('a')\n")
            second_commit = initialize_repository(target / "service-b", "main.go", "package main\n")

            result = run(PYTHON, "scripts/target-inventory.py", target, "--application-name", "fixture-app")
            self.assertEqual(result.returncode, 0, result.stderr)
            inventory = json.loads(result.stdout)
            self.assertEqual(inventory["source_root"], str(target.resolve()))
            self.assertEqual(inventory["repository_count"], 2)
            self.assertEqual(inventory["application_name"], "fixture-app")
            self.assertEqual(
                [(item["path"], item["commit"]) for item in inventory["repositories"]],
                [("service-a", first_commit), ("service-b", second_commit)],
            )

            before = fingerprint(target)
            with (target / "service-a/.git/config").open("a", encoding="utf-8") as handle:
                handle.write("\n# metadata-only change\n")
            self.assertEqual(fingerprint(target), before)
            (target / "service-a/app.py").write_text("print('changed')\n", encoding="utf-8")
            self.assertNotEqual(fingerprint(target), before)

    def test_single_repository_keeps_its_worktree_as_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            commit = initialize_repository(target / "component", "app.py", "pass\n")
            result = run(PYTHON, "scripts/target-inventory.py", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            inventory = json.loads(result.stdout)
            self.assertEqual(inventory["source_root"], str((target / "component").resolve()))
            self.assertEqual(inventory["application_name"], "component")
            self.assertEqual(inventory["revision"], commit[:12])
            self.assertEqual(inventory["repositories"][0]["path"], ".")

    def test_initializer_and_recon_preserve_repository_prefixes(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as temporary:
            base = Path(temporary)
            target = base / "target"
            target.mkdir()
            initialize_repository(target / "service-a", "requirements.txt", "example==1.0\n")
            initialize_repository(target / "service-b", "main.go", "package main\n")
            inventory_path = base / "inventory.json"
            inventory_result = run(
                PYTHON,
                "scripts/target-inventory.py",
                target,
                "--application-name",
                "fixture-app",
                "--output",
                inventory_path,
            )
            self.assertEqual(inventory_result.returncode, 0, inventory_result.stderr)
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            scan = base / "scan"
            context_path = base / "context.json"
            init = run(
                PYTHON,
                "scripts/init-run.py",
                "--harness-root", ROOT,
                "--repo-path", target,
                "--scan-base", scan,
                "--run-id", "multi-run",
                "--repo-name", inventory["application_name"],
                "--remote-url", inventory["remote_url"],
                "--repo-id", inventory["application_id"],
                "--commit", inventory["revision"],
                "--depth", "quick",
                "--repositories-file", inventory_path,
                "--reproduction-mode", "off",
                "--codegraph-mode", "disabled",
                "--network-mode", "policy_only",
                env={"VULNOPS_AUDIT_CONTEXT": str(context_path)},
            )
            self.assertEqual(init.returncode, 0, init.stderr)
            context = json.loads(context_path.read_text(encoding="utf-8"))
            self.assertEqual(context["repo_path"], str(target.resolve()))
            self.assertEqual(context["source_root"], str(target.resolve()))
            self.assertEqual(context["repository_count"], 2)
            self.assertTrue(context["repository_inventory_verified"])
            manifest_check = run(
                PYTHON,
                "scripts/validate-json.py",
                "schemas/v2/run-manifest.schema.json",
                scan / "run-manifest.json",
            )
            self.assertEqual(manifest_check.returncode, 0, manifest_check.stderr)

            research = scan / "repo-context/research"
            research.mkdir(parents=True)
            projects = [
                {
                    "id": "PRJ-A",
                    "type": "backend",
                    "base_path": "service-a",
                    "languages": ["python"],
                    "frameworks": [],
                    "dependency_files": [],
                    "entry_points": [],
                    "trust_boundary_ids": [],
                    "ignore_patterns": [],
                    "evidence_refs": ["service-a/requirements.txt:1"],
                }
            ]
            repo_context = {
                "repository": "fixture-app",
                "projects": projects,
                "domain_tags": [],
                "warnings": [],
            }
            (scan / "repo-context/repo-context.json").write_text(json.dumps(repo_context), encoding="utf-8")
            (scan / "repo-context/security-surfaces.json").write_text("{}\n", encoding="utf-8")
            worker = {"started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z"}
            for name, actor in (
                ("overview.json", "vulnops-recon-overview"),
                ("trust-boundaries.json", "vulnops-recon-trust"),
                ("input-surfaces.json", "vulnops-recon-inputs"),
            ):
                provenance = {
                    "actor": actor,
                    "selector": context["model_routing"]["agents"][actor],
                    "artifact_ref": f"repo-context/research/{name}",
                }
                (research / name).write_text(json.dumps({**worker, "provenance": provenance}), encoding="utf-8")
            environment = activate_publisher(scan, context, "recon", {"VULNOPS_AUDIT_CONTEXT": str(context_path)})

            incomplete = run(
                PYTHON,
                "scripts/finalize-recon.py",
                target,
                scan,
                env=environment,
            )
            self.assertNotEqual(incomplete.returncode, 0)
            self.assertIn("service-b", incomplete.stderr)

            projects.append(
                {
                    "id": "PRJ-B",
                    "type": "backend",
                    "base_path": "service-b",
                    "languages": ["go"],
                    "frameworks": [],
                    "dependency_files": [],
                    "entry_points": [],
                    "trust_boundary_ids": [],
                    "ignore_patterns": [],
                    "evidence_refs": ["service-b/main.go:1"],
                }
            )
            (scan / "repo-context/repo-context.json").write_text(json.dumps(repo_context), encoding="utf-8")
            finalized = run(
                PYTHON,
                "scripts/finalize-recon.py",
                target,
                scan,
                env=environment,
            )
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            final_context = json.loads((scan / "repo-context/repo-context.json").read_text(encoding="utf-8"))
            self.assertEqual(final_context["projects"][0]["dependency_files"], ["service-a/requirements.txt"])
            manifest = json.loads((scan / "repo-context/phase-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["coverage"]["repositories"], 2)


if __name__ == "__main__":
    unittest.main()
