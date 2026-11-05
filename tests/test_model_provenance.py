from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from evidence_refs import EvidenceIssue, validate_evidence_refs
from model_identity import (
    contributor_union,
    diversity_summary,
    finding_contributors,
    finding_diversity,
    validate_provenance,
)


RED = "openai-codex/gpt-daybreak-red-latest:high"
ASTRA = "openai-codex/gpt-6-astra:high"
BLUE = "openai-codex/gpt-daybreak-blue-latest:high"
ROUTING = {"agents": {
    "vulnops-deepdive-chunk": RED,
    "vulnops-verify-one": RED,
    "vulnops-recon-inputs": ASTRA,
    "vulnops-synthesis": ASTRA,
    "vulnops-independent-verify-one": RED,
}}


class ModelProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.scan = Path(temporary.name) / "scan"
        self.target = Path(temporary.name) / "source"
        (self.target / "api").mkdir(parents=True)
        (self.target / "shared").mkdir()
        (self.target / "api/entry.py").write_text("input = 1\nresult = input\n")
        (self.target / "shared/config.json").write_text('{"trusted": false}\n')
        self.source_context = {"source_root": self.target, "repositories": [{"path": "api"}, {"path": "shared"}]}
        self.red = self.source("sast/deepdive/T.json", "vulnops-deepdive-chunk", RED)
        self.review = self.source("sast/verify/C.json", "vulnops-verify-one", RED)
        self.astra = self.source("repo-context/research/input-surfaces.json", "vulnops-recon-inputs", ASTRA)

    def source(self, ref, actor, selector):
        provenance = {"actor": actor, "selector": selector, "artifact_ref": ref}
        path = self.scan / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"provenance": provenance}))
        return provenance

    def finding(self, *contributors):
        return {
            "source_refs": [{"kind": "sast", "source_id": "T", "artifact_ref": item["artifact_ref"]}
                            for item in contributors],
            "verification": {"actor": "vulnops-synthesis", "model": ASTRA,
                             "source_validation_refs": []},
            "primitive_steps": [],
        }

    def test_provenance_requires_exact_assigned_actor_selector_and_reference(self):
        self.assertEqual(validate_provenance(self.red, ROUTING, "vulnops-deepdive-chunk",
                                            "sast/deepdive/T.json"), self.red)
        invalid = [
            {**self.red, "selector": ASTRA},
            {**self.red, "selector": RED.replace(":high", ":xhigh")},
            {**self.red, "actor": "vulnops-verify-one"},
            {**self.red, "actor": "unknown-agent"},
            {**self.red, "artifact_ref": "sast/deepdive/other.json"},
            {**self.red, "artifact_ref": "../sast/deepdive/T.json"},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_provenance(value, ROUTING, "vulnops-deepdive-chunk", "sast/deepdive/T.json")
        with self.assertRaisesRegex(ValueError, "canonical actor-owned"):
            validate_provenance({**self.red, "artifact_ref": "fabricated.json"}, ROUTING)
        with self.assertRaisesRegex(ValueError, "canonical actor-owned"):
            validate_provenance({**self.red, "actor": "vulnops-synthesis", "selector": ASTRA}, ROUTING)
        for value in (None, {}, {"actor": "vulnops-deepdive-chunk", "selector": RED}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_provenance(value, ROUTING)

    def test_mixed_primitive_origins_are_sorted_deduplicated_and_recomputed(self):
        finding = self.finding(self.astra)
        finding["primitive_steps"] = [{"primitive_id": "P-001", "evidence_refs": ["api/entry.py:1-2"]}]
        primitives = {"P-001": {"contributors": [self.review, self.red, self.review],
                                "capability": {"evidence_status": "source_established"},
                                "evidence_refs": [self.red["artifact_ref"], "shared/config.json:1"]}}
        contributors = finding_contributors(self.scan, finding, ROUTING, primitives, **self.source_context)
        expected = sorted([self.red, self.review, self.astra],
                          key=lambda item: (item["actor"], item["selector"], item["artifact_ref"]))
        self.assertEqual(contributors, expected)
        self.assertEqual(contributor_union([self.review, self.red], [self.astra, self.red]), expected)
        for origins, selector, expected_diversity in (
                ([self.red], RED.replace(":high", ":xhigh"), False),
                ([self.red], ASTRA, True)):
            with self.subTest(origins=origins, selector=selector):
                self.assertEqual(finding_diversity(origins, selector), expected_diversity)
        red_origins = finding_contributors(self.scan, self.finding(self.red, self.review),
                                          ROUTING, **self.source_context)
        self.assertEqual(red_origins, contributor_union([self.red], [self.review]))
        self.assertNotIn("vulnops-synthesis", [item["actor"] for item in red_origins])
        self.assertFalse(finding_diversity(red_origins, RED))
        self.assertFalse(finding_diversity(contributors, RED))
        self.assertFalse(finding_diversity(contributors, ASTRA))
        self.assertTrue(finding_diversity(contributors, BLUE))
        finding["contributors"] = contributors
        finding["primitive_steps"] = []
        corrected = finding_contributors(self.scan, finding, ROUTING, primitives, **self.source_context)
        self.assertEqual(corrected, [self.astra])
        self.assertTrue(finding_diversity(corrected, RED))
        self.assertEqual(diversity_summary([]), {
            "model_diversity": False, "diversity_counts": {"diverse": 0, "same_model": 0, "total": 0}})
        self.assertEqual(diversity_summary([{"model_diversity": True}, {"model_diversity": False}]), {
            "model_diversity": False, "diversity_counts": {"diverse": 1, "same_model": 1, "total": 2}})
        self.assertEqual(diversity_summary([{"model_diversity": True}]), {
            "model_diversity": True, "diversity_counts": {"diverse": 1, "same_model": 0, "total": 1}})
        with self.assertRaises(ValueError):
            finding_diversity([], RED)
        with self.assertRaises(ValueError):
            finding_diversity([{"actor": "vulnops-deepdive-chunk"}], RED)
        with self.assertRaises(ValueError):
            diversity_summary([{}])

    def test_resume_uses_each_artifacts_original_route(self):
        current = {"agents": {**ROUTING["agents"], "vulnops-deepdive-chunk": BLUE,
                              "vulnops-verify-one": BLUE}}
        (self.scan / "run-manifest.json").write_text(json.dumps({
            "attempt_id": "new", "model_routing": current,
            "phase_attempts": {"sast": "old", "recon": "new"},
            "attempt_contexts": {"old": {"model_routing": ROUTING},
                                 "new": {"model_routing": current}}}))
        finding = self.finding(self.red, self.review, self.astra)
        contributors = finding_contributors(self.scan, finding, current, **self.source_context)
        self.assertEqual(contributors, contributor_union([self.red, self.review, self.astra]))
        self.assertTrue(finding_diversity(contributors, BLUE))
        self.assertFalse(finding_diversity(contributors, ASTRA))
        with self.assertRaisesRegex(ValueError, "assigned route"):
            validate_provenance(self.red, current)

    def test_historical_support_does_not_replay_removed_source(self):
        (self.scan / "run-manifest.json").write_text(json.dumps({
            "attempt_id": "new", "model_routing": ROUTING,
            "phase_attempts": {"sast": "old"},
            "attempt_contexts": {"old": {"model_routing": ROUTING}}}))
        path = self.scan / self.red["artifact_ref"]
        path.write_text(json.dumps({"provenance": self.red, "candidates": [{
            "id": "C-old", "evidence_refs": ["api/removed.py:400-410"]}]}))
        finding = {"source_refs": [{"kind": "sast", "source_id": "C-old",
                                   "artifact_ref": self.red["artifact_ref"] + ":C-old"}]}
        before = path.read_bytes()
        self.assertEqual(finding_contributors(self.scan, finding, ROUTING, **self.source_context), [self.red])
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaises(EvidenceIssue):
            validate_evidence_refs(self.scan, self.target, [{"path": "."}],
                                   ["api/removed.py:400-410"], owner="current")
        # The same claimed support produced in this attempt must still resolve;
        # historical attribution is not a general waiver for current proof.
        (self.scan / "run-manifest.json").write_text(json.dumps({
            "attempt_id": "new", "model_routing": ROUTING,
            "phase_attempts": {"sast": "new"},
            "attempt_contexts": {"new": {"model_routing": ROUTING}}}))
        with self.assertRaises(EvidenceIssue):
            finding_contributors(self.scan, finding, ROUTING, **self.source_context)

        (self.scan / "run-manifest.json").write_text(json.dumps({
            "model_routing": ROUTING, "phase_attempts": {"sast": "lost"},
            "attempt_contexts": {}}))
        with self.assertRaises(EvidenceIssue) as caught:
            finding_contributors(self.scan, self.finding(self.red), ROUTING, **self.source_context)
        self.assertEqual(caught.exception.code, "unreadable_content")

        references = ["removed/component.py:400-410", "api/entry.py:100"]
        self.assertEqual(validate_evidence_refs(self.scan, self.target, [{"path": "api"}],
                         references, owner="historical", historical=True), [])
        with self.assertRaises(ValueError):
            validate_evidence_refs(self.scan, self.target, [{"path": "api"}],
                                   ["../outside.py:1"], owner="historical", historical=True)


    def test_contributors_must_resolve_source_owned_provenance(self):
        path = self.scan / "sast/aggregate.json"
        path.write_text(json.dumps({"contributors": [{**self.red, "selector": ASTRA}]}))
        finding = self.finding({"artifact_ref": "sast/aggregate.json"})
        with self.assertRaises(ValueError):
            finding_contributors(self.scan, finding, ROUTING, **self.source_context)
        (self.scan / self.red["artifact_ref"]).write_text("{}")
        path.write_text(json.dumps({"contributors": [self.red]}))
        with self.assertRaises(ValueError):
            finding_contributors(self.scan, finding, ROUTING, **self.source_context)
        (self.scan / self.red["artifact_ref"]).write_text("{}")
        with self.assertRaises(ValueError):
            finding_contributors(self.scan, self.finding(self.red), ROUTING, **self.source_context)

    def test_mixed_reference_namespace_requires_explicit_kind(self):
        def validate(refs, kind="mixed"):
            return validate_evidence_refs(self.scan, self.target, self.source_context["repositories"],
                                          refs, owner="P-1.evidence_refs", kind=kind)
        artifact = self.red["artifact_ref"]
        self.assertEqual(validate(["api/entry.py:1-2", "shared/config.json", artifact]), [artifact])
        with self.assertRaisesRegex(ValueError, "scan artifact"):
            validate(["api/entry.py:1"], kind="artifact")
        (self.target / "sast").mkdir()
        (self.target / "sast/missing.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            validate(["sast/missing.json"])

    def test_source_citations_cannot_replace_primitive_contributors(self):
        finding = self.finding(self.astra)
        finding["primitive_steps"] = [{"primitive_id": "P-1", "evidence_refs": ["api/entry.py:1"]}]
        primitive = {"capability": {"evidence_status": "source_established"},
                     "evidence_refs": ["api/entry.py:1"]}
        with self.assertRaisesRegex(ValueError, "lacks investigation contributors"):
            finding_contributors(self.scan, finding, ROUTING, {"P-1": primitive}, **self.source_context)



if __name__ == "__main__":
    unittest.main()
