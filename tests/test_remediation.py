from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=ROOT,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )


class LinkedRemediationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.token = f"test-{uuid.uuid4().hex}"
        self.remediation_base = ROOT / "remediations" / self.token / "audit" / "remediation"
        self.work_base = ROOT / "work/remediation" / self.token
        self.temp = tempfile.TemporaryDirectory()
        self.temp_root = Path(self.temp.name)
        self.repo = self.temp_root / "repo"
        self.scan = self.temp_root / "scan"
        self.context_path = ROOT / ".harness/tmp" / f"{self.token}-context.json"
        self.repo.mkdir(parents=True)
        write(self.repo / "app.py", "def allowed(user):\n    return True\n")
        write(self.repo / "secrets.env", "TOKEN=<removed>\n")
        write(self.repo / "tests/test_app.py", "def test_allowed():\n    assert True\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        fingerprint = run(PYTHON, "scripts/target-fingerprint.py", str(self.repo)).stdout.strip()
        self.fingerprint = fingerprint
        self.remediation_base.mkdir(parents=True)
        for name in ("packets", "results", "patches", "receipts"):
            (self.remediation_base / name).mkdir()
        self.scan.mkdir()
        for finding_id in ("F-001", "F-002", "F-003"):
            write(self.scan / f"final-verification/results/{finding_id}.json", {"finding_id": finding_id})
        findings = [
            self.finding("F-001", "code", "verified", "confirmed", "app.py"),
            self.finding("F-002", "secret", "verified", "confirmed", "secrets.env"),
            self.finding("F-003", "code", "needs_environment", "needs_environment", "app.py"),
        ]
        write(
            self.scan / "final-verification/findings.json",
            {"schema_version": "2.0", "run_id": "audit", "model_diversity": True, "findings": findings, "rejections": []},
        )
        write(self.scan / "report/security-report.json", {"findings": [{"id": item["id"]} for item in findings]})
        write(
            self.scan / "tool-collection/secrets-redacted.json",
            {
                "schema_version": "2.0",
                "tool": "poltergeist",
                "match_count": 1,
                "candidate_count": 1,
                "candidates": [{"id": "SEC-1", "file": "secrets.env", "line": 1}],
            },
        )
        self.scan_snapshot = {
            path.relative_to(self.scan).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.scan.rglob("*")
            if path.is_file()
        }
        report_sha = hashlib.sha256((self.scan / "report/security-report.json").read_bytes()).hexdigest()
        findings_sha = hashlib.sha256((self.scan / "final-verification/findings.json").read_bytes()).hexdigest()
        contract = run(PYTHON, "scripts/remediation_contract.py").stdout.strip()
        manifest = {
            "schema_version": "2.0",
            "artifact_kind": "linked-remediation",
            "remediation_id": self.token,
            "source_run_id": "audit",
            "repo_id": self.token,
            "source_scan_ref": "scans/fixture/runs/audit",
            "source_report_ref": "report/security-report.json",
            "depth": "quick",
            "target_fingerprint": fingerprint,
            "report_sha256": report_sha,
            "final_findings_sha256": findings_sha,
            "remediation_contract_sha256": contract,
            "model": "fixture/slow",
            "status": "running",
            "attempts": 1,
            "recovery_count": 0,
            "recovery_history": [],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "completed_at": None,
            "artifact": None,
            "artifact_sha256": None,
            "error": None,
        }
        write(self.remediation_base / "remediation-manifest.json", manifest)
        context = {
            "schema_version": "2.0",
            "artifact_kind": "linked-remediation",
            "remediation_id": self.token,
            "source_run_id": "audit",
            "repo_id": self.token,
            "depth": "quick",
            "target_fingerprint": fingerprint,
            "report_sha256": report_sha,
            "final_findings_sha256": findings_sha,
            "remediation_contract_sha256": contract,
            "model": "fixture/slow",
            "harness_root": str(ROOT),
            "repo_path": str(self.repo),
            "source_scan": str(self.scan),
            "remediation_base": str(self.remediation_base),
            "work_base": str(self.work_base),
            "paths": {
                "source_final_findings": str(self.scan / "final-verification/findings.json"),
                "source_report": str(self.scan / "report/security-report.json"),
            },
        }
        write(self.context_path, context)
        self.env = {"VULNOPS_REMEDIATION_CONTEXT": str(self.context_path)}

    def tearDown(self) -> None:
        shutil.rmtree(self.remediation_base.parents[1], ignore_errors=True)
        shutil.rmtree(self.work_base, ignore_errors=True)
        self.context_path.unlink(missing_ok=True)
        self.temp.cleanup()

    @staticmethod
    def finding(finding_id: str, kind: str, status: str, verdict: str, path: str) -> dict:
        secret = None
        if kind == "secret":
            secret = {"file": path, "line": 1, "redaction": "<redacted>"}
        return {
            "id": finding_id,
            "finding_kind": kind,
            "status": status,
            "verdict": verdict,
            "root_causes": [{"file": path, "line": 1, "scope": "allowed", "mechanism": "missing authorization"}],
            "trace": [
                {"kind": "entrypoint", "file": path, "line": 1},
                {"kind": "sink", "file": path, "line": 2 if path == "app.py" else 1},
            ],
            "verification": {"source_validation_refs": []},
            "primitive_steps": [],
            "source_refs": [],
            "graph_receipt_refs": [],
            "independent_verification_ref": f"final-verification/results/{finding_id}.json",
            "secret": secret,
        }

    def prepare_candidate(self, changed_files: list[str] | None = None) -> Path:
        planned = run(PYTHON, "scripts/build-remediation-plan.py", str(self.remediation_base), env=self.env)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        plan = json.loads((self.remediation_base / "remediation-plan.json").read_text())
        self.assertEqual(plan["counts"], {"total": 3, "eligible": 1, "manual_only": 2})
        prepared = run(PYTHON, "scripts/prepare-remediation-work.py", "F-001", env=self.env)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        working = Path(json.loads(prepared.stdout)["working"])
        write(working / "app.py", "def allowed(user):\n    return bool(user and user.is_admin)\n")
        for relative in (changed_files or ["app.py"]):
            if relative == "tests/test_app.py":
                write(working / relative, "def test_allowed():\n    assert False\n")
        result = {
            "schema_version": "2.0",
            "remediation_id": self.token,
            "finding_id": "F-001",
            "status": "candidate",
            "summary": "Require an administrative principal before allowing the operation.",
            "addressed_locations": [{"file": "app.py", "line": 1, "reason": "Enforce authorization at the root cause."}],
            "changed_files": changed_files or ["app.py"],
            "limitations": [],
            "errors": [],
            "model": "fixture/slow",
        }
        write(self.remediation_base / "results/F-001.json", result)
        return working

    def test_production_patch_is_published_and_manual_findings_remain_explicit(self) -> None:
        before = self.fingerprint
        self.prepare_candidate()
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertEqual(published.returncode, 0, published.stderr)
        patch = (self.remediation_base / "patches/F-001.patch").read_text()
        self.assertIn("diff --git a/app.py b/app.py", patch)
        self.assertNotIn("tests/test_app.py", patch)
        finalized = run(PYTHON, "scripts/finalize-remediation.py", str(self.remediation_base), env=self.env)
        self.assertEqual(finalized.returncode, 0, finalized.stderr)
        bundle = json.loads((self.remediation_base / "remediation.json").read_text())
        self.assertEqual(bundle["status"], "degraded")
        self.assertEqual(bundle["counts"], {"total": 3, "patch_ready": 1, "manual_required": 2})
        self.assertEqual([item["disposition"] for item in bundle["items"]], ["patch_ready", "manual_required", "manual_required"])
        after = run(PYTHON, "scripts/target-fingerprint.py", str(self.repo)).stdout.strip()
        self.assertEqual(before, after)
        scan_after = {
            path.relative_to(self.scan).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.scan.rglob("*")
            if path.is_file()
        }
        self.assertEqual(self.scan_snapshot, scan_after)

    def test_test_file_change_is_rejected(self) -> None:
        self.prepare_candidate(["app.py", "tests/test_app.py"])
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertNotEqual(published.returncode, 0)
        self.assertIn("production-only patch", published.stderr)
        self.assertFalse((self.remediation_base / "patches/F-001.patch").exists())

    def test_possible_secret_in_patch_is_rejected(self) -> None:
        working = self.prepare_candidate()
        write(working / "app.py", 'API_KEY="sk-abcdefghijklmnopqrstuvwxyz123456"\n')
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertNotEqual(published.returncode, 0)
        self.assertIn("secret", published.stderr.lower())
        self.assertFalse((self.remediation_base / "patches/F-001.patch").exists())

    def test_environment_reference_and_content_path_are_preserved(self) -> None:
        working = self.prepare_candidate()
        write(
            working / "app.py",
            'import os\nTOKEN = os.environ["TOKEN"]\nLABEL = " working/path"\ndef allowed(user):\n    return bool(user and user.is_admin)\n',
        )
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertEqual(published.returncode, 0, published.stderr)
        patch = (self.remediation_base / "patches/F-001.patch").read_text()
        self.assertIn('TOKEN = os.environ["TOKEN"]', patch)
        self.assertIn('LABEL = " working/path"', patch)

    def test_state_writer_seals_success_and_refuses_mutation(self) -> None:
        self.prepare_candidate()
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertEqual(published.returncode, 0, published.stderr)
        finalized = run(PYTHON, "scripts/finalize-remediation.py", str(self.remediation_base), env=self.env)
        self.assertEqual(finalized.returncode, 0, finalized.stderr)
        updated = run(PYTHON, "scripts/update-remediation-state.py", str(self.remediation_base), "--status", "degraded", "--artifact", "remediation.json")
        self.assertEqual(updated.returncode, 0, updated.stderr)
        manifest = json.loads((self.remediation_base / "remediation-manifest.json").read_text())
        self.assertEqual(manifest["status"], "degraded")
        self.assertEqual(manifest["artifact_sha256"], hashlib.sha256((self.remediation_base / "remediation.json").read_bytes()).hexdigest())
        immutable = run(PYTHON, "scripts/update-remediation-state.py", str(self.remediation_base), "--status", "failed", "--error", "late change")
        self.assertNotEqual(immutable.returncode, 0)

    def test_retry_preparation_clears_stale_finding_artifacts(self) -> None:
        self.prepare_candidate()
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertEqual(published.returncode, 0, published.stderr)
        prepared = run(PYTHON, "scripts/prepare-remediation-work.py", "F-001", env=self.env)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertFalse((self.remediation_base / "results/F-001.json").exists())
        self.assertFalse((self.remediation_base / "patches/F-001.patch").exists())
        self.assertFalse((self.remediation_base / "receipts/F-001.json").exists())

    def test_state_writer_allows_one_stable_retry(self) -> None:
        first_failed = run(
            PYTHON,
            "scripts/update-remediation-state.py",
            str(self.remediation_base),
            "--status",
            "failed",
            "--error",
            "first attempt failed",
        )
        self.assertEqual(first_failed.returncode, 0, first_failed.stderr)
        retry = run(
            PYTHON,
            "scripts/update-remediation-state.py",
            str(self.remediation_base),
            "--status",
            "running",
            "--increment-attempt",
        )
        self.assertEqual(retry.returncode, 0, retry.stderr)
        second_failed = run(
            PYTHON,
            "scripts/update-remediation-state.py",
            str(self.remediation_base),
            "--status",
            "failed",
            "--error",
            "second attempt failed",
        )
        self.assertEqual(second_failed.returncode, 0, second_failed.stderr)
        exhausted = run(
            PYTHON,
            "scripts/update-remediation-state.py",
            str(self.remediation_base),
            "--status",
            "running",
            "--increment-attempt",
        )
        self.assertNotEqual(exhausted.returncode, 0)
        self.assertIn("attempt limit", exhausted.stderr)


if __name__ == "__main__":
    unittest.main()
