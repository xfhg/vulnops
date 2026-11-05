from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from dossier_contract import dossier_hash
spec = importlib.util.spec_from_file_location("investigation_synthesis", ROOT / "scripts/finalize-synthesis.py")
synthesis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(synthesis)
spec = importlib.util.spec_from_file_location("investigation_validator", ROOT / "scripts/validate-json.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def completed_prior(base, run_id, *, findings=(), historical=(), legacy=False, kind="audit"):
    """Write only synthetic portable publication evidence, never target source."""
    def save(relative, value):
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
    claims = [dict(row, independent_verification_ref=f"final-verification/results/{row['id']}.json")
              for row in findings]
    report = {"run_id": run_id, "summary": {}, "findings": claims,
              "historical_findings": list(historical)}
    metadata = {"execution_kind": kind, "repository": "synthetic",
                "repositories": [], "model_routing": {}, "producer_routes": {}}
    if legacy:
        save("run-manifest.json" if kind == "audit" else "advantage-manifest.json",
             {"run_id": run_id, "status": "complete", **metadata})
    else:
        report["publication"] = metadata
    save("report/security-report.json", report)
    (base / "report/security-report.md").write_text("# Synthetic historical report\n")
    save("final-verification/findings.json", {"run_id": run_id, "findings": claims})
    for finding in claims:
        save(finding["independent_verification_ref"],
             {"finding_id": finding["id"], "dossier_review": {"dossier_sha256": dossier_hash(finding)}})
    return base / "report/security-report.json"


class InvestigationIdentityTests(unittest.TestCase):
    def test_prior_reports_read_completed_history_after_source_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory).resolve() / "runs"
            completed_prior(runs / "a", "a", legacy=True)
            completed_prior(runs / "b", "b", legacy=True)
            manifest = runs / "b/run-manifest.json"
            document = json.loads(manifest.read_text())
            document["status"] = "incomplete"
            manifest.write_text(json.dumps(document))
            completed_prior(runs / "c", "c")
            completed_prior(runs / "advantage", "advantage", kind="advantage")
            completed_prior(runs / "current", "current")
            inputs = list(synthesis.prior_reports(runs / "current"))
            self.assertEqual({item["run_id"] for item in inputs}, {"a", "c"})
            self.assertTrue(all(Path(item["path"]).is_file() for item in inputs))
            external = Path(directory) / "external.json"
            external.write_text("{}")
            report = runs / "a/report/security-report.json"
            report.unlink()
            report.symlink_to(external)
            self.assertEqual([item["run_id"] for item in synthesis.prior_reports(runs / "current")], ["c"])

    def test_prior_reports_are_bounded_safe_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory).resolve() / "runs"
            for number in range(10):
                completed_prior(runs / f"prior-{number}", f"prior-{number}")
            broken = completed_prior(runs / "z-broken", "broken")
            broken.write_text("{")
            fifo = completed_prior(runs / "z-fifo", "fifo")
            fifo.unlink()
            os.mkfifo(fifo)
            outside = Path(directory).resolve() / "outside"
            completed_prior(outside, "outside")
            (runs / "z-symlink").symlink_to(outside, target_is_directory=True)
            before = {path: path.read_bytes() for path in runs.rglob("*")
                      if path.is_file() and not path.is_symlink()}
            inputs = list(synthesis.prior_reports(runs / "current"))
            self.assertEqual([item["run_id"] for item in inputs],
                             [f"prior-{number}" for number in range(9, 1, -1)])
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            (runs / "prior-9/report/security-report.json").unlink()
            self.assertEqual(len(list(synthesis.prior_reports(runs / "current"))), 8)

    def test_prior_report_listing_cli_needs_no_active_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory).resolve() / "runs"
            report = completed_prior(runs / "prior", "prior")
            before = report.read_bytes()
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/finalize-synthesis.py"),
                 str(runs / "current"), "--list-prior-reports"],
                env={**os.environ, "VULNOPS_AUDIT_CONTEXT": str(runs / "missing-context.json")},
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([item["run_id"] for item in json.loads(result.stdout)], ["prior"])
            self.assertEqual(report.read_bytes(), before)
            self.assertFalse((runs / "current").exists())

    def test_external_schema_references_keep_document_scope_and_reject_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "child.json").write_text(json.dumps({"$ref": "#/$defs/name", "$defs": {"item": {"$ref": "#/$defs/name"}, "name": {"type": "string", "minLength": 3}}}))
            schema = {"$defs": {"name": {"type": "integer"}}, "$ref": "child.json#/$defs/item"}
            check = validator.Validator(schema, base)
            self.assertEqual(check.collect("valid", schema), [])
            self.assertTrue(check.collect(7, schema))
            with self.assertRaises(ValueError):
                check.collect("valid", {"$ref": "../child.json#/$defs/item"})
            root_reference = {"$defs": {"name": {"type": "integer"}}, "$ref": "child.json"}
            self.assertEqual(check.collect("valid", root_reference), [])
            self.assertTrue(check.collect(7, root_reference))
            self.assertTrue(check.collect("no", root_reference))
            for reference in ("../child.json", "https://example.invalid/child.json", "child.json#named-anchor"):
                with self.subTest(reference=reference), self.assertRaises(ValueError):
                    check.collect("valid", {"$ref": reference})


if __name__ == "__main__":
    unittest.main()
