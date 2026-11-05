import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from evidence_refs import EvidenceIssue, artifact_value, source_file, validate_evidence_refs


class EvidenceReferenceFormsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        self.source = root / "source"
        self.scan = root / "scan"
        (self.source / "api").mkdir(parents=True)
        (self.scan / "sast").mkdir(parents=True)
        (self.source / "api/code.py").write_text("one\ntwo\nthree\nfour\n")
        (self.source / "api/config.json").write_text('{"id":"source-not-artifact"}\n')
        (self.scan / "sast/records.json").write_text(json.dumps([{"id": "C1", "value": 1}]))
        self.repositories = [{"path": "api"}]

    def test_equivalent_forms_resolve_all_components(self):
        cache = {}
        path = self.source / "api/code.py"
        for selector in ("1", "1-4", "1,3-4", "1, 2-4", "1-3,2-4,1"):
            self.assertEqual(source_file(self.source, self.repositories, "api/code.py:" + selector, cache), path)
        self.assertEqual(cache, {path: 4})
        self.assertEqual(artifact_value(self.scan, "sast/records.json:C1"),
                         artifact_value(self.scan, "sast/records.json#C1"))
        self.assertEqual(validate_evidence_refs(self.scan, self.source, self.repositories,
                         ["api/config.json:1", "sast/records.json#C1"], owner="fixture"),
                         ["sast/records.json#C1"])

    def test_bad_component_is_not_silently_dropped(self):
        for selector in ("", "0", "2-1", "1,5", "1-5", "line", "1,", "1,,2", "1,line", "1#C1"):
            with self.subTest(selector=selector), self.assertRaises(EvidenceIssue):
                source_file(self.source, self.repositories, "api/code.py:" + selector)
        for ref in ("sast/records.json#missing", "sast/missing.json", "sast/records.json#", "sast/records.json:C1#C1"):
            with self.subTest(ref=ref), self.assertRaises(EvidenceIssue):
                artifact_value(self.scan, ref)
        for ref in ("api/extra/code.py:1", "api/code.py#L1"):
            with self.subTest(ref=ref), self.assertRaises(EvidenceIssue):
                validate_evidence_refs(self.scan, self.source, self.repositories, [ref], owner="fixture")
        (self.scan / "sast/records.json").write_text('[{"id":"C1"},{"id":"C1"}]')
        with self.assertRaises(EvidenceIssue) as caught:
            artifact_value(self.scan, "sast/records.json#C1")
        self.assertEqual(caught.exception.code, "ambiguous_record")

    def test_descriptive_extensions_cannot_invent_record_identity(self):
        path = self.scan / "sast/threat-model.json"
        path.write_text(json.dumps({"id": "forged-root", "assets": [
            {"id": "A1", "notes": {"id": "forged-child", "contributors": []}}]}))
        self.assertEqual(artifact_value(self.scan, "sast/threat-model.json#A1")["id"], "A1")
        for identifier in ("forged-root", "forged-child"):
            with self.assertRaises(EvidenceIssue):
                artifact_value(self.scan, "sast/threat-model.json#" + identifier)

    def test_advantage_candidates_require_unique_declared_identity(self):
        relative = "investigation/passes/PASS-001/results/TASK-001.json"
        path = self.scan / relative
        path.parent.mkdir(parents=True)
        document = {"candidates": [{"id": "C-001", "terminal_impact": "Cross-tenant enqueue"}],
                    "notes": {"id": "C-NOTE"}}
        path.write_text(json.dumps(document))
        for identifier in ("C-MISSING", "C-NOTE"):
            with self.subTest(identifier=identifier), self.assertRaises(EvidenceIssue) as caught:
                artifact_value(self.scan, relative + ":" + identifier)
            self.assertEqual(caught.exception.code, "missing_record")
        document["candidates"].append(dict(document["candidates"][0]))
        path.write_text(json.dumps(document))
        with self.assertRaises(EvidenceIssue) as caught:
            artifact_value(self.scan, relative + "#C-001")
        self.assertEqual(caught.exception.code, "ambiguous_record")

    def test_safety_failures_are_not_local_quality_issues(self):
        (self.source / "api/escape.py").symlink_to(self.scan / "sast/records.json")
        for ref in ("../scan/sast/records.json:bad", "api/escape.py:bad", "unregistered/missing.py:1",
                    str(self.source / "api/code.py"), "api/../outside.py", "outside.py"):
            with self.subTest(ref=ref), self.assertRaises(ValueError) as caught:
                validate_evidence_refs(self.scan, self.source, self.repositories, [ref], owner="fixture")
            self.assertNotIsInstance(caught.exception, EvidenceIssue)
        (self.scan / "sast/escape.json").symlink_to(self.source / "api/config.json")
        with self.assertRaises(ValueError) as caught:
            artifact_value(self.scan, "sast/escape.json#bad")
        self.assertNotIsInstance(caught.exception, EvidenceIssue)

    def test_synthesis_consumer_checks_selected_record_not_only_file(self):
        from synthesis_contract import _artifact
        expected = self.scan / "sast/records.json"
        for delimiter in (":", "#"):
            with self.subTest(delimiter=delimiter):
                self.assertEqual(_artifact(self.scan, f"sast/records.json{delimiter}C1"), expected)
                self.assertIsNone(_artifact(self.scan, f"sast/records.json{delimiter}missing"))
        with self.assertRaises(ValueError):
            _artifact(self.scan, "../source/api/config.json:source-not-artifact")


if __name__ == "__main__":
    unittest.main()
