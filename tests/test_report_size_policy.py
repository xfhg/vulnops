"""Final report size exemptions must not weaken publication hygiene or other limits."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from artifact_policy import DEFAULT_ARTIFACT_LIMIT, artifact_size_limit, oversized_artifacts, publication_content_error


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


schema_validator = load_script("validate-json")
scan_reader = load_script("validate-scan-v2")


class ReportSizePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Individually bounded values, aggregated beyond the old hidden 16 MiB cap.
        cls.entries = [f"Entry {index}: " + "x" * 7900 for index in range(2200)]
        cls.document = {"entries": cls.entries}
        cls.schema = {"type": "object", "required": ["entries"], "properties": {
            "entries": {"type": "array", "items": {"type": "string", "maxLength": 8000}}}}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.scan = Path(temporary.name)

    def save(self, relative, value):
        path = self.scan / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_unlimited_schema_validation_preserves_schema_rules(self):
        self.assertGreater(len(json.dumps(self.document).encode()), DEFAULT_ARTIFACT_LIMIT)
        self.assertIn("size policy", publication_content_error(self.document))
        self.assertIsNone(publication_content_error(self.document, size_limit=None))
        bounded = schema_validator.Validator(self.schema)
        self.assertTrue(any("size policy" in error for error in bounded.collect(self.document, self.schema)))
        unlimited = schema_validator.Validator(self.schema, size_limit=None)
        self.assertEqual(unlimited.collect(self.document, self.schema), [])
        invalid = {"entries": [*self.entries, 7]}
        self.assertTrue(unlimited.collect(invalid, self.schema))

    def test_oversized_reports_preserve_content_and_structure_safety(self):
        secret = "ghp_" + "SyntheticCredentialForRegressionOnly12345"
        cases = [("secret", {"note": secret}, "raw secret")]
        cases.extend((key, {key: "synthetic execution material"}, "not publishable")
                     for key in ("raw_output", "raw_scanner_output", "proof_token", "stdout", "stderr"))
        nested = "leaf"
        for _ in range(66):
            nested = [nested]
        cases.extend((name, value, reason) for name, value, reason in (
            ("deep_nesting", nested, "nesting"),
            ("infinity", float("inf"), "non-finite"),
            ("nan", float("nan"), "non-finite")))
        for name, unsafe, reason in cases:
            with self.subTest(content=name):
                value = {**self.document, "unsafe": unsafe}
                self.assertIn(reason, publication_content_error(value, size_limit=None))
                errors = schema_validator.Validator(self.schema, size_limit=None).collect(value, self.schema)
                self.assertTrue(any(reason in error for error in errors))
                self.assertNotIn(secret, "\n".join(errors))


    def test_oversized_json_and_markdown_readers_still_reject_secret_patterns(self):
        safe_report = {**self.document, "summary": {}, "findings": []}
        report_path = self.save("report/security-report.json", safe_report)
        self.save("final-verification/findings.json", {"findings": []})
        self.save("run-manifest.json", {"run_id": "large-legacy-report", "status": "complete", "repository": "fixture"})
        markdown_path = self.scan / "report/security-report.md"
        markdown_path.write_text("\n".join(self.entries), encoding="utf-8")
        self.assertGreater(report_path.stat().st_size, DEFAULT_ARTIFACT_LIMIT)
        self.assertGreater(markdown_path.stat().st_size, DEFAULT_ARTIFACT_LIMIT)
        self.assertEqual(scan_reader.read_publication(self.scan), safe_report)
        secret = "Authorization: Bearer synthetic-credential-for-regression-only"
        self.save("report/security-report.json", {**safe_report, "unsafe": secret})
        with self.assertRaisesRegex(ValueError, "raw secret") as caught:
            scan_reader.read_publication(self.scan)
        self.assertNotIn(secret, str(caught.exception))
        self.save("report/security-report.json", safe_report)
        with markdown_path.open("a", encoding="utf-8") as handle:
            handle.write("\n" + secret)
        with self.assertRaisesRegex(ValueError, "raw secret") as caught:
            scan_reader.read_publication(self.scan)
        self.assertNotIn(secret, str(caught.exception))

    def test_non_report_artifacts_and_report_sidecars_remain_bounded(self):
        for relative, limit in (("context.json", 2 * 1024 * 1024),
                                ("sast/coverage-ledger.json", DEFAULT_ARTIFACT_LIMIT),
                                ("sast/graph-receipt.json", 64 * 1024),
                                ("report/phase-manifest.json", 2 * 1024 * 1024),
                                ("other/security-report.json", DEFAULT_ARTIFACT_LIMIT)):
            with self.subTest(path=relative):
                path = self.save(relative, {"description": "x" * limit})
                self.assertEqual(artifact_size_limit(Path(relative)), limit)
                self.assertIn((Path(relative), path.stat().st_size, limit), oversized_artifacts(self.scan))
                with self.assertRaisesRegex(ValueError, "bounded size policy"):
                    scan_reader.read_document(self.scan, relative)


if __name__ == "__main__":
    unittest.main()
