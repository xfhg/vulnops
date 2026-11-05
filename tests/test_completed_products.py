"""Disposable completed-bundle readers; no model or target execution is exercised."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from report_bundle import document, publication_identity, publication_metadata, read_publication
from remediation_common import read_remediation, require_exact_source_authority, source_publication
from run_lifecycle import report_assessment


def put(base, ref, value):
    path = base / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def completed_audit(base):
    report = {"run_id": "audit-001", "summary": {"total": 0}, "findings": [],
              "publication": {"execution_kind": "audit", "repository": "fixture",
                              "repositories": [{"path": "."}], "model_routing": {}, "producer_routes": {}}}
    put(base, "report/security-report.json", report)
    (base / "report/security-report.md").write_text("# Completed assessment\n", encoding="utf-8")
    put(base, "final-verification/findings.json", {"run_id": report["run_id"], "findings": []})
    return report


class CompletedProducts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="completed-products-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def test_new_publication_ignores_corrupt_retired_controls(self):
        report = completed_audit(self.base)
        for ref in ("run-manifest.json", "advantage-manifest.json", "task-ledger.json"):
            (self.base / ref).write_text("{ abandoned control bytes")
        before = {path: path.read_bytes() for path in self.base.rglob("*") if path.is_file()}
        bundle = read_publication(self.base, expected_kind="audit")
        self.assertEqual(bundle["report"], report)
        self.assertEqual(bundle["run_id"], "audit-001")
        self.assertNotIn("phases", bundle)
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        result = subprocess.run([sys.executable, str(ROOT / "scripts/validate-scan-v2.py"),
                                 str(ROOT), str(self.base)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_publication_uses_local_metadata_without_rewriting(self):
        report = completed_audit(self.base)
        report.pop("publication")
        put(self.base, "report/security-report.json", report)
        put(self.base, "run-manifest.json", {"run_id": "audit-001", "status": "complete", "repository": "fixture"})
        before = {path: path.read_bytes() for path in self.base.rglob("*") if path.is_file()}
        self.assertEqual(read_publication(self.base)["report"], report)
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_missing_companion_or_final_identity_is_not_zero_findings(self):
        completed_audit(self.base)
        (self.base / "report/security-report.md").unlink()
        self.assertEqual(publication_identity(self.base)["run_id"], "audit-001")
        with self.assertRaises((OSError, ValueError)):
            read_publication(self.base)
        (self.base / "report/security-report.md").write_text("# Completed assessment\n")
        put(self.base, "final-verification/findings.json", {"run_id": "foreign", "findings": []})
        with self.assertRaisesRegex(ValueError, "canonical final authority"):
            read_publication(self.base)
        (self.base / "report/security-report.json").unlink()
        with self.assertRaises((OSError, ValueError)):
            read_publication(self.base)

    def test_committed_report_is_not_selected_for_recovery_after_crash(self):
        scan = (self.base / "scans/fixture/audit-001").resolve()
        completed_audit(scan)
        put(scan, "run-manifest.json", {"run_id": "audit-001", "status": "incomplete"})
        put(scan, "task-ledger.json", {"run_id": "audit-001", "tasks": [{"status": "running"}]})
        context = {"workflow": "canonical-redteam-v2", "run_id": "audit-001",
                   "scan_base": str(scan), "harness_root": str(self.base)}
        pointer = self.base / "runtime-context.json"
        for retain_controls in (True, False):
            with self.subTest(retain_controls=retain_controls):
                if not retain_controls:
                    (scan / "run-manifest.json").unlink()
                    (scan / "task-ledger.json").unlink()
                put(self.base, pointer.name, context)
                result = subprocess.run([sys.executable, str(ROOT / "scripts/resume-run.py"), str(pointer)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse(pointer.exists())
                self.assertEqual(read_publication(scan)["run_id"], "audit-001")

    def test_wrong_source_kind_and_nonregular_artifacts_fail_closed(self):
        completed_audit(self.base)
        with self.assertRaisesRegex(ValueError, "advantage publication"):
            read_publication(self.base, expected_kind="advantage")
        path = self.base / "pipe.json"
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "regular file"):
            document(self.base, "pipe.json")
        path.unlink()
        (self.base / "alias.json").symlink_to(self.base / "report/security-report.json")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            document(self.base, "alias.json")

    def test_publication_metadata_excludes_runnable_context_and_keeps_patch_views(self):
        context = {"run_id": "adv-001", "execution_kind": "advantage", "repository": "fixture",
                   "scan_base": str(self.base), "repositories": [{"path": "."}], "model_routing": {},
                   "mode": "diff", "source_run_id": "audit-001", "source_root": "/gone/source",
                   "baseline": {"execution_id": "audit-001", "catalog_ref": "baseline/catalog.json", "root": "/gone/audit"},
                   "action_source": None, "attempt_contexts": {"must-not-copy": {}}, "budget": {"must-not-copy": 100},
                   "patch_binding": {"patch_ref": "baseline/assessment.patch", "sha256": "a" * 64,
                                     "repository": ".", "changed_files": []},
                   "options": {"patch": "/gone/input.patch", "verify_fix": ["F-001"], "track_findings": [],
                               "hardening": False, "assess_patch_risk": True, "repository": "."}}
        value = publication_metadata(context, execution_kind="advantage")
        self.assertEqual(value["options"]["patch"], "baseline/assessment.patch")
        self.assertEqual(value["options"]["verify_fix"], ["F-001"])
        self.assertEqual(value["patch_binding"], context["patch_binding"])
        self.assertNotIn("root", value["baseline"])
        for key in ("source_root", "attempt_contexts", "budget", "phases", "tasks"):
            self.assertNotIn(key, value)
        self.assertNotIn("/gone", json.dumps(value))

    def test_publication_routes_keep_typed_inherited_support_out_of_local_namespace(self):
        context = {"run_id": "adv-001", "execution_kind": "advantage", "scan_base": str(self.base),
                   "source_run_id": "audit-001", "model_routing": {"agents": {"local": "fixture/current:high"}},
                   "baseline": {"execution_id": "audit-001", "root": "/unavailable/baseline"},
                   "action_source": {"execution_id": "adv-old", "root": "/unavailable/action-source"}}
        finding = {"contributors": [
            {"artifact_ref": "synthesis/findings.json", "execution_id": "adv-001"},
            {"artifact_ref": "synthesis/findings.json", "execution_id": "audit-001"}],
            "source_refs": [
                {"artifact_ref": "investigation/results.json#local"},
                {"artifact_ref": {"execution_id": "audit-001",
                                  "artifact_ref": "sast/verified-findings.json#baseline"}},
                {"artifact_ref": {"execution_id": "adv-old",
                                  "artifact_ref": "final-verification/findings.json#prior"}}]}
        put(self.base, "final-verification/findings.json", {"findings": [finding]})
        for ref in ("synthesis/findings.json", "investigation/results.json"):
            put(self.base, ref, {})
        before = copy.deepcopy(finding)
        metadata = publication_metadata(context, execution_kind="advantage")
        self.assertEqual(metadata["producer_routes"], {
            ref: context["model_routing"] for ref in ("synthesis/findings.json", "investigation/results.json")})
        self.assertEqual(document(self.base, "final-verification/findings.json")["findings"], [before])
        self.assertFalse((self.base / "sast").exists())

    def test_publication_routes_reject_unsafe_or_ambiguous_reference_ownership(self):
        context = {"run_id": "adv-001", "execution_kind": "advantage", "scan_base": str(self.base),
                   "source_run_id": "audit-001", "model_routing": {},
                   "baseline": {"execution_id": "audit-001", "root": "/unavailable/baseline"}}
        cases = (
            {"artifact_ref": {"execution_id": "foreign", "artifact_ref": "synthesis/findings.json"}},
            {"execution_id": "adv-001", "artifact_ref": {
                "execution_id": "audit-001", "artifact_ref": "synthesis/findings.json"}},
            {"artifact_ref": {"execution_id": "adv-001", "artifact_ref": "synthesis/findings.json"}},
            {"artifact_ref": {"execution_id": "audit-001", "artifact_ref": "../outside.json"}},
            {"artifact_ref": {"execution_id": "audit-001", "artifact_ref": None}},
        )
        for index, source in enumerate(cases):
            with self.subTest(case=index):
                put(self.base, "final-verification/findings.json", {"findings": [{"source_refs": [source]}]})
                with self.assertRaises(ValueError):
                    publication_metadata(context, execution_kind="advantage")

    def test_empty_fresh_assessment_keeps_current_source_scope(self):
        scope = {"assessment_id": "assessment-one", "attempt_id": "producer-one", "run_id": "adv-one",
                 "repositories": [{"path": "."}], "limitations": [], "source_view": "base"}
        context = {"run_id": "adv-one", "execution_kind": "advantage", "attempt_id": "producer-one",
                   "assessment_id": "assessment-one", "assessment_scopes": {"assessment-one": scope}}
        before = copy.deepcopy(context)
        assessment = report_assessment(context, [])
        self.assertEqual(assessment["scopes"], [scope])
        self.assertFalse(assessment["retained"])
        self.assertEqual(context, before)

    def test_completed_remediation_reads_without_context_source_or_replay(self):
        bundle = {"schema_version": "2.0", "artifact_kind": "linked-remediation", "remediation_id": "patch-001",
                  "source": {"run_id": "audit-001", "scan_ref": "scans/gone/audit-001",
                             "report_ref": "report/security-report.json", "report_sha256": "a" * 64,
                             "final_findings_sha256": "b" * 64, "target_fingerprint": "c" * 64},
                  "model": "fixture/patcher", "status": "ok", "counts": {"total": 0, "patch_ready": 0, "manual_required": 0},
                  "items": [], "limitations": ["Recorded outcome only; current applicability is not inferred."]}
        put(self.base, "remediation.json", bundle)
        (self.base / "summary.md").write_text("# Completed remediation\n")
        with patch("remediation_common.load_context", side_effect=AssertionError("must not load context")), \
             patch("remediation_common.target_fingerprint", side_effect=AssertionError("must not inspect target")):
            self.assertEqual(read_remediation(self.base), bundle)
        result = subprocess.run([sys.executable, str(ROOT / "scripts/validate-remediation.py"), str(self.base)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_readable_publication_does_not_authorize_new_production_patch(self):
        completed_audit(self.base)
        source = source_publication(self.base)
        with self.assertRaisesRegex(ValueError, "manual-required.*exact-source authority"):
            require_exact_source_authority(source, source["final"], source["report"])


if __name__ == "__main__":
    unittest.main()
