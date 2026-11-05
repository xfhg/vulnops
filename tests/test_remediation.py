from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
sys.path.insert(0, str(ROOT / "scripts"))
from model_routing import audit_routing, load_routing, remediation_routing
from test_dossiers import add_dossier, sample_finding
import remediation_common
from remediation_contract import CONTRACT_FILES


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
        self.scan = ROOT / "scans" / self.token / "audit"
        self.context_path = ROOT / ".harness/tmp" / f"{self.token}-context.json"
        self.repo.mkdir(parents=True)
        write(self.repo / "app.py", "def allowed(user):\n    return True\n")
        write(self.repo / "policy.py", "def is_admin(user):\n    return bool(user and user.is_admin)\n")
        write(self.repo / "secrets.env", "TOKEN=<removed>\n")
        write(self.repo / "tests/test_app.py", "def test_allowed():\n    assert True\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        fingerprint = run(PYTHON, "scripts/target-fingerprint.py", str(self.repo)).stdout.strip()
        self.fingerprint = fingerprint
        self.remediation_base.mkdir(parents=True)
        for name in ("packets", "results", "patches", "receipts"):
            (self.remediation_base / name).mkdir()
        self.scan.mkdir(parents=True)
        for finding_id in ("F-001", "F-002", "F-003"):
            write(self.scan / f"final-verification/results/{finding_id}.json", {"finding_id": finding_id})
        findings = [
            self.finding("F-001", "code", "verified", "confirmed", "app.py"),
            self.finding("F-002", "secret", "verified", "confirmed", "secrets.env"),
            self.finding("F-003", "code", "needs_environment", "needs_environment", "app.py"),
        ]
        write(self.scan / "sast/deepdive/policy.json", {"evidence_refs": ["policy.py:1-2"]})
        write(self.scan / "sast/verified-findings.json", [
            {"id": "C-" + finding["id"], "evidence_refs": [finding["root_causes"][0]["file"] + ":1"]}
            for finding in findings])
        write(
            self.scan / "final-verification/findings.json",
            {"schema_version": "2.0", "run_id": "audit", "model_diversity": True, "findings": findings, "rejections": []},
        )
        write(self.scan / "report/security-report.json", {"findings": findings})
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
        write(self.scan / "run-manifest.json", {"run_id": "audit", "status": "complete",
                                               "target_fingerprint": fingerprint})
        source_manifest_sha = hashlib.sha256((self.scan / "run-manifest.json").read_bytes()).hexdigest()
        routing = remediation_routing(load_routing(ROOT))
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
            "source_scan_ref": self.scan.relative_to(ROOT).as_posix(),
            "source_report_ref": "report/security-report.json",
            "depth": "quick",
            "target_fingerprint": fingerprint,
            "report_sha256": report_sha,
            "final_findings_sha256": findings_sha,
            "remediation_contract_sha256": contract,
            "model": routing["controllers"]["remediation"],
            "model_routing": routing,
            "source_manifest_sha256": source_manifest_sha,
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
            "model": routing["controllers"]["remediation"],
            "model_routing": routing,
            "source_manifest_sha256": source_manifest_sha,
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
        shutil.rmtree(self.scan.parent, ignore_errors=True)
        self.temp.cleanup()

    def test_missing_or_mismatched_routing_fails_before_work(self):
        original = json.loads(self.context_path.read_text())
        before = {path: path.read_bytes() for path in self.remediation_base.rglob("*") if path.is_file()}
        for routing, diagnostic in ((None, "model routing requires groups, agents and controllers"),
                                    ({"groups": {}, "agents": {}, "controllers": {}}, "incomplete remediation routing groups")):
            with self.subTest(routing=routing):
                context = dict(original)
                if routing is None:
                    context.pop("model_routing")
                else:
                    context["model_routing"] = routing
                write(self.context_path, context)
                result = run(PYTHON, "scripts/build-remediation-plan.py", str(self.remediation_base), env=self.env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
                self.assertEqual(before, {path: path.read_bytes() for path in self.remediation_base.rglob("*") if path.is_file()})
                self.assertFalse(self.work_base.exists())
        write(self.context_path, original)
        accepted = run(PYTHON, "scripts/build-remediation-plan.py", str(self.remediation_base), env=self.env)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertTrue((self.remediation_base / "packets/F-001.json").is_file())

    @staticmethod
    def finding(finding_id: str, kind: str, status: str, verdict: str, path: str) -> dict:
        finding = sample_finding()
        finding.update(id=finding_id, finding_kind=kind, status=status, verdict=verdict,
                       model_diversity=True, independent_verification_ref=f"final-verification/results/{finding_id}.json",
                       source_refs=[{"kind": "sast", "source_id": "C-" + finding_id,
                                     "artifact_ref": "sast/verified-findings.json:C-" + finding_id}])
        for location in [*finding["root_causes"], *finding["trace"]]:
            location["file"] = path
            if path != "app.py":location["line"] = 1
        finding["verification"]["source_validation_refs"] = [f"{path}:1"]
        finding["verification"]["level"] = "source_verified" if status == "verified" else "environment_required"
        if kind == "secret":
            finding["secret"] = {"type": "token", "file": path, "line": 1, "redaction": "<redacted>",
                                 "exposure_path": "Source distribution", "validity": "confirmed_format"}
        add_dossier(finding)
        finding["remediation"]["actions"][0]["change"] = "Enforce administrative authority in the shared allowed guard."
        if finding_id == "F-001":
            finding["affected_components"].append({"id": "policy", "name": "Shared authority predicate", "repository": ".",
                "locations": [{"file": "policy.py", "line": 1, "scope": "is_admin", "mechanism": "Reusable administrative authority predicate."}],
                "entrypoints": ["is_admin"], "service": {**finding["affected_components"][0]["service"]}, "evidence_refs": ["policy.py:1-2"]})
            finding["remediation"]["actions"][0]["evidence_refs"].append("sast/deepdive/policy.json")
        return finding

    def test_dossier_only_locations_are_bound_into_patch_inputs(self):
        planned = run(PYTHON, "scripts/build-remediation-plan.py", str(self.remediation_base), env=self.env)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        packet_path = self.remediation_base / "packets/F-001.json"
        packet = json.loads(packet_path.read_text())
        self.assertEqual(set(packet["source_files"]), {"app.py", "policy.py"})
        self.assertIn("sast/deepdive/policy.json", packet["artifact_refs"])
        self.assertEqual(packet["final_findings_sha256"], hashlib.sha256((self.scan / "final-verification/findings.json").read_bytes()).hexdigest())
        write(self.repo / "policy.py", "def is_admin(user):\n    return True\n")
        prepared = run(PYTHON, "scripts/prepare-remediation-work.py", "F-001", env=self.env)
        self.assertNotEqual(prepared.returncode, 0)
        self.assertFalse((self.work_base / "F-001").exists())

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
            "addressed_locations": [{"file": "app.py", "line": 2, "reason": "Enforce authorization at the unconditional approval."}],
            "changed_files": changed_files or ["app.py"],
            "limitations": [],
            "errors": [],
            "model": json.loads(self.context_path.read_text())["model_routing"]["agents"]["vulnops-remediate-one"],
        }
        write(self.remediation_base / "results/F-001.json", result)
        return working

    def bind_advantage_publisher_source(self, *, legacy: bool = False) -> Path:
        """Stage exact-source accepted inputs for the existing publisher fixture."""
        baseline = self.scan.parent / "baseline"
        secrets = self.scan / "tool-collection/secrets-redacted.json"
        write(baseline / "tool-collection/secrets-redacted.json", json.loads(secrets.read_text()))
        secrets.unlink()
        (self.scan / "run-manifest.json").unlink()
        final_path = self.scan / "final-verification/findings.json"
        final = json.loads(final_path.read_text())
        final["links"] = [{"finding_id": finding["id"], "source_view": "base"} for finding in final["findings"]]
        write(final_path, final)
        metadata = {
            "execution_kind": "advantage", "repository": self.token,
            "repositories": [{"path": "."}], "model_routing": {}, "producer_routes": {},
            "mode": "standard", "options": {}, "patch_binding": None,
            "source": {"source_run_id": "baseline"}, "target_fingerprint": self.fingerprint,
        }
        markdown = "# Accepted exact-source findings\n"
        report = {"run_id": "audit", "findings": final["findings"],
                  "summary": {"total": len(final["findings"])}}
        if legacy:
            write(self.scan / "advantage-manifest.json",
                  {**metadata, "run_id": "audit", "source_run_id": "baseline", "status": "complete"})
        else:
            report["publication"] = {
                **metadata, "markdown_sha256": hashlib.sha256(markdown.encode()).hexdigest()}
        write(self.scan / "report/security-report.md", markdown)
        write(self.scan / "report/security-report.json", report)
        final_hash = hashlib.sha256(final_path.read_bytes()).hexdigest()
        report_hash = hashlib.sha256((self.scan / "report/security-report.json").read_bytes()).hexdigest()
        for path in (self.context_path, self.remediation_base / "remediation-manifest.json"):
            value = json.loads(path.read_text())
            value.pop("source_manifest_sha256", None)
            value.update(report_sha256=report_hash, final_findings_sha256=final_hash)
            write(path, value)
        packet_path = self.remediation_base / "packets/F-001.json"
        packet = json.loads(packet_path.read_text())
        packet["final_findings_sha256"] = final_hash
        write(packet_path, packet)
        plan_path = self.remediation_base / "remediation-plan.json"
        plan = json.loads(plan_path.read_text())
        for item in plan["items"]:
            if item["finding_id"] == "F-001":
                item["packet_sha256"] = hashlib.sha256(packet_path.read_bytes()).hexdigest()
        write(plan_path, plan)
        return baseline

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

    def test_control_free_advantage_uses_baseline_secret_evidence(self) -> None:
        self.prepare_candidate()
        self.bind_advantage_publisher_source()
        self.assertFalse((self.scan / "advantage-manifest.json").exists())
        self.assertFalse((self.scan / "tool-collection/secrets-redacted.json").exists())
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertEqual(published.returncode, 0, published.stderr)
        self.assertTrue((self.remediation_base / "patches/F-001.patch").is_file())

    def test_legacy_advantage_uses_baseline_secret_evidence(self) -> None:
        self.prepare_candidate()
        self.bind_advantage_publisher_source(legacy=True)
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertEqual(published.returncode, 0, published.stderr)
        self.assertTrue((self.remediation_base / "patches/F-001.patch").is_file())

    def test_control_free_advantage_rejects_known_secret_file_patch(self) -> None:
        working = self.prepare_candidate(["app.py", "secrets.env"])
        write(working / "secrets.env", "TOKEN=<removed>\n# Rotate credentials before deployment.\n")
        self.bind_advantage_publisher_source()
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertNotEqual(published.returncode, 0)
        self.assertIn("file containing a redacted secret candidate", published.stderr)
        self.assertFalse((self.remediation_base / "patches/F-001.patch").exists())

    def test_control_free_advantage_requires_baseline_secret_evidence(self) -> None:
        self.prepare_candidate()
        baseline = self.bind_advantage_publisher_source()
        (baseline / "tool-collection/secrets-redacted.json").unlink()
        published = run(PYTHON, "scripts/publish-remediation-patch.py", "F-001", env=self.env)
        self.assertNotEqual(published.returncode, 0)
        self.assertIn("secrets-redacted.json", published.stderr)
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
        self.assertFalse((self.remediation_base / "remediation-manifest.json").exists())
        bundle = remediation_common.read_remediation(self.remediation_base)
        self.assertEqual(bundle["status"], "degraded")
        self.assertEqual(bundle["model_routing"], remediation_routing(load_routing(ROOT)))
        before = {path: path.read_bytes() for path in self.remediation_base.rglob("*") if path.is_file()}
        immutable = run(PYTHON, "scripts/update-remediation-state.py", str(self.remediation_base), "--status", "failed", "--error", "late change")
        self.assertNotEqual(immutable.returncode, 0)
        self.assertEqual(before, {path: path.read_bytes() for path in self.remediation_base.rglob("*") if path.is_file()})

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


class RemediationSourceCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in (*CONTRACT_FILES, "config.toml"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self.repo = self.root / "target"
        self.repo.mkdir()
        write(self.repo / "app.py", "allowed = True\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "app.py"], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture",
        ], check=True)
        inventory = json.loads(subprocess.check_output([
            PYTHON, str(ROOT / "scripts/target-inventory.py"), str(self.repo),
            "--application-name", "fixture",
        ], text=True))
        self.digest = remediation_common.target_fingerprint(ROOT, self.repo)
        self.scan = self.root / "scans/fixture/runs/audit"
        self.manifest = {
            "schema_version": "2.0", "workflow": "canonical-redteam-v2",
            "run_id": "audit", "repo_id": "fixture", "repository": "fixture",
            "commit": inventory["repositories"][0]["commit"], "status": "complete",
            "depth": "quick", "repositories": inventory["repositories"],
            "model_routing": audit_routing(load_routing(ROOT)), "target_fingerprint": self.digest,
        }
        self.final = {"findings": [], "rejections": []}
        write(self.scan / "run-manifest.json", self.manifest)
        write(self.scan / "final-verification/findings.json", self.final)
        write(self.scan / "report/security-report.json", {"findings": []})
        self.environment = {
            **os.environ, "PYTHONPATH": str(ROOT / "scripts"),
            "VULNOPS_REMEDIATION_CONTEXT": str(self.root / ".harness/remediation-context.json"),
        }

    def initialize(self):
        return subprocess.run([
            PYTHON, str(self.root / "scripts/init-remediation.py"), str(self.scan),
        ], cwd=self.root, env=self.environment, capture_output=True, text=True, check=False)

    def command(self, script, *arguments):
        return subprocess.run([PYTHON, str(self.root / "scripts" / script),
                               *map(str, arguments)], cwd=self.root, env=self.environment,
                              capture_output=True, text=True, check=False)

    def mixed_findings(self):
        write(self.repo / "app.py", "def allowed(user):\n    return True\n")
        write(self.repo / "policy.py", "def is_admin(user):\n    return bool(user and user.is_admin)\n")
        eligible = LinkedRemediationTests.finding("F-001", "code", "verified", "confirmed", "app.py")
        manual = LinkedRemediationTests.finding("F-002", "code", "needs_environment", "needs_environment", "app.py")
        manual["verification"]["source_validation_refs"] = ["unavailable.py:1"]
        manual["remediation"]["actions"][0]["evidence_refs"].append("sast/deepdive/unavailable.json:proof")
        self.final = {"schema_version": "2.0", "run_id": "audit", "model_diversity": True,
                      "findings": [eligible, manual], "rejections": []}
        write(self.scan / "sast/verified-findings.json", [
            {"id": "C-F-001", "evidence_refs": ["app.py:1"]},
            {"id": "C-F-002", "evidence_refs": ["app.py:1"]}])
        write(self.scan / "sast/deepdive/policy.json", {"evidence_refs": ["policy.py:1-2"]})
        write(self.scan / "tool-collection/secrets-redacted.json", {
            "schema_version": "2.0", "tool": "poltergeist",
            "match_count": 0, "candidate_count": 0, "candidates": []})
        write(self.scan / "final-verification/results/F-001.json", {"finding_id": "F-001"})
        write(self.scan / "final-verification/findings.json", self.final)
        write(self.scan / "report/security-report.json", {"findings": self.final["findings"]})
        self.digest = remediation_common.target_fingerprint(self.root, self.repo)
        self.manifest["target_fingerprint"] = self.digest
        write(self.scan / "run-manifest.json", self.manifest)
        return eligible, manual

    def test_manual_unavailable_evidence_does_not_block_apply_checked_eligible_patch(self):
        eligible, manual = self.mixed_findings()
        before = {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()}
        initialized = self.initialize()
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        context = json.loads(initialized.stdout)
        base = Path(context["remediation_base"])
        started = self.command("update-remediation-state.py", base, "--status", "running", "--increment-attempt")
        self.assertEqual(started.returncode, 0, started.stderr)
        planned = self.command("build-remediation-plan.py", base)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        plan = json.loads((base / "remediation-plan.json").read_text())
        self.assertEqual(plan["counts"], {"total": 2, "eligible": 1, "manual_only": 1})
        self.assertIn("Safe supporting evidence is unavailable", plan["items"][1]["reason"])
        packet = json.loads((base / "packets/F-002.json").read_text())
        self.assertEqual(packet["finding"], manual)
        self.assertIn("unavailable.py", packet["source_files"])
        self.assertIn("sast/deepdive/unavailable.json:proof", packet["artifact_refs"])
        refused = self.command("prepare-remediation-work.py", "F-002")
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((Path(context["work_base"]) / "F-002").exists())
        prepared = self.command("prepare-remediation-work.py", "F-001")
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        working = Path(json.loads(prepared.stdout)["working"])
        write(working / "app.py", "def allowed(user):\n    return bool(user and user.is_admin)\n")
        write(base / "results/F-001.json", {
            "schema_version": "2.0", "remediation_id": context["remediation_id"], "finding_id": "F-001",
            "status": "candidate", "summary": "Require administrative authority.",
            "addressed_locations": [{"file": "app.py", "line": 2, "reason": "Enforce authorization."}],
            "changed_files": ["app.py"], "limitations": [], "errors": [],
            "model": context["model_routing"]["agents"]["vulnops-remediate-one"]})
        for script, argument in (("publish-remediation-patch.py", "F-001"),
                                 ("finalize-remediation.py", base)):
            result = self.command(script, argument)
            self.assertEqual(result.returncode, 0, result.stderr)
        validated = self.command("validate-remediation.py", base, "--precommit")
        self.assertEqual(validated.returncode, 0, validated.stderr)
        bundle = json.loads((base / "remediation.json").read_text())
        self.assertEqual(bundle["counts"], {"total": 2, "patch_ready": 1, "manual_required": 1})
        self.assertEqual(bundle["items"][1]["result_ref"], None)
        self.assertTrue(any("Safe supporting evidence is unavailable" in value
                            for value in bundle["items"][1]["limitations"]))
        applied = subprocess.run(["git", "-C", str(self.repo), "apply", "--check",
                                  str(base / "patches/F-001.patch")],
                                 capture_output=True, text=True, check=False)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(remediation_common.target_fingerprint(self.root, self.repo), self.digest)
        self.assertEqual(before, {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()})

    def test_manual_availability_never_hides_unsafe_or_foreign_evidence(self):
        _, manual = self.mixed_findings()
        for reference in ("../outside.json", "/outside.json", "sast/deepdive/absent.json:",
                          "sast/deepdive/escape.json", "sast/deepdive/foreign.json",
                          "sast/deepdive/secret.json", "sast/deepdive/forbidden.json"):
            write(self.root / "outside.json", {"safe": True})
            path = self.scan / "sast/deepdive/escape.json"
            if not path.exists():
                path.symlink_to(self.root / "outside.json")
            write(self.scan / "sast/deepdive/foreign.json", {"run_id": "foreign"})
            write(self.scan / "sast/deepdive/secret.json", {"value": "ghp_" + "x" * 24})
            write(self.scan / "sast/deepdive/forbidden.json", {"raw_output": "not publishable"})
            manual["remediation"]["actions"][0]["evidence_refs"] = [
                "sast/deepdive/unavailable.json", reference]
            with self.subTest(reference=reference), self.assertRaises(ValueError) as caught:
                remediation_common.finding_evidence(self.scan, self.repo, manual)
            self.assertNotIsInstance(caught.exception, remediation_common.EvidenceIssue)
        manual["remediation"]["actions"][0]["evidence_refs"] = ["app.py:1"]
        manual["contributors"][0]["execution_id"] = "foreign"
        with self.assertRaisesRegex(ValueError, "contributor declares another execution"):
            remediation_common.finding_evidence(self.scan, self.repo, manual)

    def test_historical_intake_requires_exact_source_authority_for_every_cohort(self):
        for mixed in (False, True):
            if mixed:
                self.mixed_findings()
            report = {"findings": self.final["findings"]}
            variants = (
                ("missing authority", {"target_fingerprint": None}, {}),
                ("mixed attempt", {"attempt_id": "later-attempt"}, {}),
                ("historical cohort", {}, {"historical_findings": [{"id": "F-history"}]}),
                ("assessed publication", {}, {"assessment": {
                    "scopes": [], "record_scopes": {}, "publication_attempt_id": "publisher",
                    "retained": True, "limitations": ["Original source was not revalidated."]}}),
            )
            for label, manifest_changes, report_changes in variants:
                with self.subTest(cohort="eligible and unavailable manual" if mixed else "empty", case=label):
                    write(self.scan / "run-manifest.json", {**self.manifest, **manifest_changes})
                    write(self.scan / "report/security-report.json", {**report, **report_changes})
                    before = {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()}
                    refused = self.initialize()
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertIn("manual-required", refused.stderr)
                    self.assertIn("exact-source authority", refused.stderr)
                    self.assertFalse((self.root / "remediations").exists())
                    self.assertEqual(before, {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()})

    def test_eligible_neighbor_still_requires_complete_patch_evidence(self):
        eligible, manual = self.mixed_findings()
        broken = copy.deepcopy(eligible)
        broken["verification"]["source_validation_refs"] = ["unavailable.py:1"]
        with self.assertRaises(remediation_common.EvidenceIssue):
            remediation_common.finding_evidence(self.scan, self.repo, broken)
        limitations = []
        refs, files = remediation_common.finding_evidence(self.scan, self.repo, manual,
                                                         limitations=limitations)
        self.assertIn("unavailable.py", files)
        self.assertIn("final-verification/results/F-002.json", refs)
        self.assertTrue(limitations)

    def test_legacy_exact_source_initializes_without_audit_snapshot_metadata(self):
        write(self.scan / "report/security-report.json",
              {"findings": [], "assessment": {"status": "completed"}})
        before = {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()}
        # Whole-scan replay is neither needed nor allowed for linked patch intake.
        write(self.root / "scripts/validate-scan.sh", "exit 97\n")
        result = self.initialize()
        self.assertEqual(result.returncode, 0, result.stderr)
        context = json.loads(result.stdout)
        self.assertEqual(context["target_fingerprint"], self.digest)
        self.assertEqual(context["source_run_id"], "audit")
        self.assertEqual(before, {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()})
    def test_remediation_route_changes_require_distinct_execution(self):
        initialized = self.initialize()
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        previous = json.loads(initialized.stdout)
        unchanged = self.initialize()
        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
        self.assertEqual(json.loads(unchanged.stdout)["remediation_id"], previous["remediation_id"])
        config = self.root / "config.toml"
        for selector in ("fixture/other:high", "fixture/other:xhigh"):
            with self.subTest(selector=selector):
                old_base = Path(previous["remediation_base"])
                before = {path: path.read_bytes() for path in old_base.rglob("*") if path.is_file()}
                text = config.read_text()
                changed = re.sub(r'(?m)^remediation\s*=.*$', f'remediation = "{selector}"', text)
                self.assertNotEqual(changed, text)
                config.write_text(changed)
                result = self.initialize()
                self.assertEqual(result.returncode, 0, result.stderr)
                current = json.loads(result.stdout)
                self.assertNotEqual(current["remediation_id"], previous["remediation_id"])
                self.assertEqual(current["model_routing"]["controllers"]["remediation"], selector)
                self.assertEqual(before, {path: path.read_bytes() for path in old_base.rglob("*") if path.is_file()})
                previous = current


    def test_simplified_historical_input_names_manual_prerequisite_before_target_lookup(self):
        self.manifest.pop("target_fingerprint")
        write(self.scan / "run-manifest.json", self.manifest)
        shutil.rmtree(self.repo)
        result = self.initialize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manual-required", result.stderr)
        self.assertIn("exact-source authority", result.stderr)
        self.assertIn("intended patch base", result.stderr)
        self.assertNotIn("fingerprint differs", result.stderr)
        self.assertFalse((self.root / "remediations").exists())

    def test_changed_exact_source_is_not_authorized(self):
        write(self.repo / "app.py", "allowed = False\n")
        result = self.initialize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manual-required: current target is not the exact source", result.stderr)
        self.assertFalse((self.root / "remediations").exists())

    def test_advantage_intake_requires_exact_source_before_context_reconstruction(self):
        (self.scan / "run-manifest.json").unlink()
        write(self.scan / "final-verification/findings.json", {**self.final, "links": []})
        for change in ({"target_fingerprint": None}, {"attempt_id": "later-attempt"}):
            with self.subTest(change=change):
                write(self.scan / "advantage-manifest.json", {**self.manifest, "mode": "standard", **change})
                before = {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()}
                with patch("advantage_contract.context_for_base", side_effect=AssertionError("source reconstruction before authorization")):
                    with self.assertRaisesRegex(ValueError, "manual-required.*exact-source authority"):
                        remediation_common.validate_advantage_source(self.scan, self.repo)
                self.assertEqual(before, {path: path.read_bytes() for path in self.scan.rglob("*") if path.is_file()})



if __name__ == "__main__":
    unittest.main()
