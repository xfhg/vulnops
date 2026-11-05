"""In-memory synthesis admission and protected publication regression fixtures."""
from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gap_dossier as gap
import synthesis_contract as contract
from dossier_contract import validate_publication_schema
from evidence_accounting import account_inputs, synthesis_inputs
from test_dossiers import sample_finding
import test_gap_dossier as gap_fixtures
from test_gap_dossier import module


STEP = {"primitive_id": "P-001", "input_capability": "Tenant session",
        "output_capability": "Another tenant's record", "boundary_crossed": "Tenant ownership",
        "evidence_refs": ["source.py:1-2"]}


def document():
    return {"schema_version": "2.0", "run_id": "fixture", "findings": [sample_finding()],
            "objective_assessments": []}


def violations():
    cases = []
    value = document(); value["findings"][0]["primitive_steps"] = [copy.deepcopy(STEP)]
    cases.append(("non-chain finding must not contain primitive steps", value))
    value = document(); value["findings"][0]["finding_kind"] = "chain"
    cases.append(("chain requires composite origin", value))
    value = document(); value["findings"][0]["trace"][0]["kind"] = "sink"
    cases.append(("trace must run from entrypoint to sink", value))
    value = document(); value["findings"][0]["trace"].insert(1, copy.deepcopy(value["findings"][0]["trace"][0]))
    cases.append(("intermediate trace steps must be propagation", value))
    value = document(); value["findings"][0]["finding_kind"] = "dependency"
    cases.append(("dependency finding requires proven reachable", value))
    value = document(); value["findings"][0]["dependency"] = {
        "advisory_id": "ADV-1", "package": "fixture", "installed_version": "1", "affected_use": "lookup", "reachability": "reachable"}
    cases.append(("non-dependency finding must use dependency: null", value))
    value = document(); value["findings"][0]["finding_kind"] = "secret"
    cases.append(("secret finding requires exact redaction", value))
    value = document(); value["findings"][0]["secret"] = {
        "type": "fixture", "file": "source.py", "line": 1, "redaction": "<redacted>", "exposure_path": "fixture", "validity": "likely"}
    cases.append(("non-secret finding must use secret: null", value))
    value = document(); value["findings"][0]["status"] = "needs_environment"
    cases.append(("needs_environment status requires environment_required", value))
    value = document(); value["findings"].append(copy.deepcopy(value["findings"][0]))
    cases.append(("synthesis finding IDs must be unique", value))
    return cases


class SynthesisStructureTests(unittest.TestCase):
    def test_schema_and_intrinsic_violations_are_repairable_structure(self):
        for message, value in violations():
            with self.subTest(message=message):
                validate_publication_schema(value, "synthesis-findings.schema.json")
                with self.assertRaisesRegex(contract.InvalidSynthesisStructure, message):
                    contract.validate_synthesis_structure(value)

        with self.subTest(message="missing required trace"):
            value = document(); del value["findings"][0]["trace"]
            with self.assertRaises(contract.InvalidSynthesisStructure):
                contract.validate_synthesis_structure(value)




class SynthesisAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = gap_fixtures.ProtectedGapDossiers()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.finalizer = module("finalize-synthesis")
        self.fixture.save("campaign-planning/campaign-plan.json", {"campaigns": []})
        self.fixture.save("campaign-planning/evidence-index.json", {
            "primitives": [], "records": [{"source_kind": "sast", "source_id": "C-001"}]})
        self.context_path = self.fixture.save("fixture-context.json", self.fixture.context)

    def invoke(self, stage):
        stderr = io.StringIO()
        with patch.dict(os.environ, {"VULNOPS_AUDIT_CONTEXT": str(self.context_path)}), \
                patch.object(sys, "argv", ["finalize-synthesis", str(self.fixture.base), "--stage", stage]), \
                redirect_stderr(stderr):
            result = self.finalizer.main()
        return result, stderr.getvalue()

    def candidate(self):
        value = document()
        value["run_id"] = self.fixture.context["run_id"]
        return value

    def test_artifact_selectors_resolve_exact_records_with_equal_forms(self):
        base = self.fixture.base
        relative = "sast/verified-findings.json"
        expected = (base / relative).resolve()
        for selector in (":C-001", "#C-001"):
            with self.subTest(selector=selector):
                self.assertEqual(contract._artifact(base, relative + selector), expected)
        self.fixture.save("sast/other-findings.json", [{"id": "C-002"}])
        self.assertEqual(contract._artifact(base, "sast/other-findings.json:C-002"),
                         (base / "sast/other-findings.json").resolve())
        self.assertIsNone(contract._artifact(base, relative + ":C-002"))
        self.assertIsNone(contract._artifact(base, relative + "#missing"))
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            contract._artifact(base, "../outside.json:C-001")

    def test_empty_publisher_rejects_completed_owner_before_output_mutation(self):
        f = self.fixture
        empty = module("empty-synthesis")
        f.save("sast/verified-findings.json", [])
        f.save("campaign-planning/evidence-index.json", {"primitives": [], "records": []})
        f.save("intrusion/intrusion-results.json", {"results": [], "composition": {"status": "resolved"}})
        with patch.dict(os.environ, {"VULNOPS_AUDIT_CONTEXT": str(self.context_path)}), \
                patch.object(sys, "argv", ["empty-synthesis", str(f.base)]), \
                redirect_stderr(io.StringIO()):
            # Real active-owner control reaches the writer and actual finalizer.
            self.assertEqual(empty.main(), 0)
            output = f.base / "synthesis/findings.json"
            self.assertEqual(json.loads(output.read_text())["findings"], [])
            self.assertTrue((f.base / "synthesis/phase-manifest.json").is_file())
            f.manifest.update(status="complete")
            f.manifest["phases"]["synthesis"] = "ok"
            f.save("run-manifest.json", f.manifest)
            before = {path: path.read_bytes() for path in f.base.rglob("*") if path.is_file()}
            self.assertEqual(empty.main(), 1)
        self.assertEqual({path: path.read_bytes() for path in f.base.rglob("*") if path.is_file()}, before)

    def test_retained_original_preserves_draft_on_schema_resource_failure(self):
        f = self.fixture
        relative = "synthesis/original-findings.json"
        with f.accepted():
            gap.begin_cohort(f.context, "synthesis", "original")
            draft = f.save(relative, self.candidate())
            gap.bind_original_draft(f.context, relative)
            gap.finish_cohort(f.context, "synthesis", "original")
        dispatch_path = f.base / "synthesis/dispatch.json"
        dispatch = json.loads(dispatch_path.read_text())
        before_dispatch = copy.deepcopy(dispatch)
        before_files = {draft: draft.read_bytes(), dispatch_path: dispatch_path.read_bytes()}
        # Retention consumes accepted structure rather than replaying present source.
        (f.target / "source.py").unlink()
        self.assertEqual(gap.retained_original(f.base, f.context, dispatch), relative)
        schema_path = ROOT / "schemas/v2/synthesis-findings.schema.json"
        replacement = f.base.parent / "recovery-schema.json"
        read_text = Path.read_text

        def read_schema(path, *args, **kwargs):
            return read_text(replacement if path == schema_path else path, *args, **kwargs)

        for damage, exception in (("missing", FileNotFoundError), ("corrupt", json.JSONDecodeError)):
            with self.subTest(schema=damage):
                if damage == "corrupt":
                    replacement.write_text("{broken")
                with patch.object(Path, "read_text", new=read_schema):
                    with self.assertRaises(exception):
                        gap.retained_original(f.base, f.context, dispatch)
                self.assertEqual(dispatch, before_dispatch)
                self.assertEqual({path: path.read_bytes() for path in before_files}, before_files)

    def test_unsafe_retained_original_is_not_discarded_as_authoring_failure(self):
        f = self.fixture
        relative = "synthesis/original-findings.json"
        value = self.candidate()
        value["findings"][0]["stdout"] = "synthetic execution output"
        # Historical binding is authored here to isolate the cleanup consumer.
        with f.accepted():
            gap.begin_cohort(f.context, "synthesis", "original")
            draft = f.save(relative, value)
            gap.bind_original_draft(f.context, relative)
            gap.finish_cohort(f.context, "synthesis", "original")
        dispatch_path = f.base / "synthesis/dispatch.json"
        dispatch = json.loads(dispatch_path.read_text())
        before_dispatch = copy.deepcopy(dispatch)
        before_files = {draft: draft.read_bytes(), dispatch_path: dispatch_path.read_bytes()}
        with self.assertRaisesRegex(ValueError, "not publishable") as raised:
            gap.retained_original(f.base, f.context, dispatch)
        self.assertNotIsInstance(raised.exception, contract.InvalidSynthesisStructure)
        self.assertEqual(dispatch, before_dispatch)
        self.assertEqual({path: path.read_bytes() for path in before_files}, before_files)

    def test_invalid_original_never_publishes_or_binds(self):
        with self.fixture.accepted():
            gap.begin_cohort(self.fixture.context, "synthesis", "original")
            for message, value in violations():
                with self.subTest(message=message):
                    value["run_id"] = self.fixture.context["run_id"]
                    self.fixture.save("synthesis/original-draft.json", value)
                    with patch.object(self.finalizer, "bind_original_draft") as bind:
                        result, _ = self.invoke("original")
                    self.assertEqual(result, 1)
                    bind.assert_not_called()
                    self.assertFalse((self.fixture.base / "synthesis/original-findings.json").exists())
                    self.assertFalse((self.fixture.base / "synthesis/findings.json").exists())

    def test_invalid_complete_never_rewrites_candidate_or_publishes_manifest(self):
        with patch.object(gap, "accepted", return_value=None):
            for message, value in violations():
                with self.subTest(message=message):
                    value["run_id"] = self.fixture.context["run_id"]
                    path = self.fixture.save("synthesis/findings.json", value)
                    before = path.read_bytes()
                    result, _ = self.invoke("complete")
                    self.assertEqual(result, 1)
                    self.assertEqual(path.read_bytes(), before)
                    self.assertFalse((self.fixture.base / "synthesis/phase-manifest.json").exists())

    def test_source_semantics_reject_before_original_binding(self):
        with self.fixture.accepted():
            gap.begin_cohort(self.fixture.context, "synthesis", "original")
            self.fixture.save("campaign-planning/evidence-index.json", {"primitives": [], "records": []})
            self.fixture.save("synthesis/original-draft.json", self.candidate())
            result, stderr = self.invoke("original")
            self.assertEqual(result, 1)
            self.assertIn("source ID does not resolve in evidence index", stderr)
            self.assertFalse((self.fixture.base / "synthesis/original-findings.json").exists())

    def test_source_example_authoring_failure_preserves_inputs_and_prepared_output(self):
        f = self.fixture
        with f.accepted(), patch("model_identity.routing_for_artifact", return_value=f.routing):
            gap.begin_cohort(f.context, "synthesis", "original")
            value = self.candidate()
            f.save("synthesis/original-draft.json", value)
            result, stderr = self.invoke("original")
            self.assertEqual(result, 0, stderr)
            output = f.base / "synthesis/original-findings.json"
            before = output.read_bytes()
            dispatch = (f.base / "synthesis/dispatch.json").read_bytes()
            inputs = (f.base / "sast/verified-findings.json").read_bytes()
            example = {"id": "example-1", "kind": "source", "content": "invented lookup",
                       "evidence_refs": ["source.py:1-2"], "substitutions": [],
                       "execution_status": "not_executed", "observation_refs": []}
            value["findings"][0]["technical_examples"] = [example]
            draft = f.save("synthesis/original-draft.json", value)
            authored = draft.read_bytes()
            result, stderr = self.invoke("original")
            self.assertEqual(result, 1)
            self.assertIn("cited range", stderr)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(draft.read_bytes(), authored)
            self.assertEqual((f.base / "synthesis/dispatch.json").read_bytes(), dispatch)
            self.assertEqual((f.base / "sast/verified-findings.json").read_bytes(), inputs)
            example["content"] = (f.target / "source.py").read_text().rstrip("\n")
            f.save("synthesis/original-draft.json", value)
            result, stderr = self.invoke("original")
            self.assertEqual(result, 0, stderr)
            self.assertEqual(json.loads(output.read_text())["findings"][0]["technical_examples"][0]["kind"], "source")
            self.assertEqual(json.loads((f.base / "synthesis/dispatch.json").read_text())["cohorts"]["original"]["status"], "running")
            gap.finish_cohort(f.context, "synthesis", "original")

    def test_missing_positive_proof_cannot_publish(self):
        f = self.fixture
        with f.accepted(), patch("model_identity.routing_for_artifact", return_value=f.routing):
            gap.begin_cohort(f.context, "synthesis", "original")
            value = self.candidate()
            value["findings"][0]["exploitation"]["steps"][0]["evidence_refs"] = ["missing.py:1"]
            f.save("synthesis/original-draft.json", value)
            result, _ = self.invoke("original")
            self.assertEqual(result, 1)
            self.assertFalse((f.base / "synthesis/original-findings.json").exists())
            self.assertNotIn("output_ref", json.loads((f.base / "synthesis/dispatch.json").read_text())["cohorts"]["original"])

    def test_valid_original_then_supplementary_and_invalid_supplement_retry(self):
        f = self.fixture
        f.save(f.provenance["artifact_ref"], {"provenance": f.provenance, "candidates": [f.candidate]})
        with f.accepted(), patch("model_identity.routing_for_artifact", return_value=f.routing):
            gap.begin_cohort(f.context, "synthesis", "original")
            f.save("synthesis/original-draft.json", self.candidate())
            result, stderr = self.invoke("original")
            self.assertEqual(result, 0, stderr)
            original_path = f.base / "synthesis/original-findings.json"
            original_bytes = original_path.read_bytes()
            original = json.loads(original_bytes)
            self.assertEqual(len(original["input_claims"]), 1)
            self.assertFalse((f.base / "synthesis/findings.json").exists())
            gap.finish_cohort(f.context, "synthesis", "original")
            gap.begin_cohort(f.context, "synthesis", "supplementary")
            combined = copy.deepcopy(original)
            combined["findings"].append(f.supplemental_finding())
            combined["input_claims"] = account_inputs(
                synthesis_inputs(f.base), combined["findings"], combined["non_promoted"])
            invalid = copy.deepcopy(combined)
            invalid["findings"][-1]["primitive_steps"] = [copy.deepcopy(STEP)]
            f.save("synthesis/supplementary-draft.json", invalid)
            result, _ = self.invoke("supplementary")
            self.assertEqual(result, 1)
            self.assertFalse((f.base / "synthesis/findings.json").exists())
            self.assertEqual(original_path.read_bytes(), original_bytes)
            f.save("synthesis/supplementary-draft.json", combined)
            result, stderr = self.invoke("supplementary")
            self.assertEqual(result, 0, stderr)
            published = json.loads((f.base / "synthesis/findings.json").read_text())
            self.assertEqual(len(published["findings"]), 2)
            self.assertEqual(len(published["input_claims"]), 2)
            self.assertEqual(published["findings"][0], original["findings"][0])
            self.assertEqual(original_path.read_bytes(), original_bytes)


if __name__ == "__main__":
    unittest.main()
