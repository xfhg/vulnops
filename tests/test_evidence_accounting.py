"""Deterministic local-proof regressions; no audit or target code is executed."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evidence_accounting import (account_inputs, classify_refs, diagnostic, effective_support,
                                 summarize, synthesis_inputs, validate_non_promoted)
from evidence_refs import EvidenceIssue
from model_identity import finding_contributors
from test_dossiers import sample_finding, seed_objective
from test_run_lifecycle import activate_publisher

DEPENDENCY_LIMITATIONS = [
    {"code": "conan_offline_sca_unsupported",
     "message": "Conan dependency inputs are excluded because OSV has no offline Conan ecosystem database.",
     "files": ["native/conan.lock"]},
    {"code": "bundled_scanner_input_unsupported",
     "message": "The bundled Wraith/OSV versions cannot extract packages from Maven POM or Cabal freeze inputs; these files are reported instead of failing Tool Collection.",
     "files": ["haskell/cabal.project.freeze", "java/pom.xml"]},
    {"code": "npm_lockfile_no_dependency_inventory",
     "message": "Metadata-only npm v1 lockfiles contain no dependency inventory and were not scanned; this does not establish absence of application dependencies.",
     "files": ["package-lock.json", "web/package-lock.json"]},
    {"code": "requirements_no_dependency_inventory",
     "message": "Empty requirements files do not establish application dependency coverage.",
     "files": ["empty/requirements.txt"]},
    {"code": "requirements_reviewed_non_dependency",
     "message": "An exact-content review identified a non-dependency document.",
     "files": ["docs/requirements.txt"],
     "reviews": [{"file": "docs/requirements.txt", "sha256": "a" * 64,
                  "reason": "Reviewed business requirements."}]},
]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LocalEvidenceAccounting(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.scan = self.base / "scan"
        self.target = self.base / "source"
        self.scan.mkdir(); self.target.mkdir()
        (self.target / "source.py").write_text("entrypoint\nimpact\n")
        (self.target / "source.txt").write_text("entrypoint and effect\n")
        seed_objective(self.scan)
        self.repositories = [{"path": "."}]
        self.actor = "vulnops-deepdive-chunk"
        self.routing = {"agents": {self.actor: "p/investigator:high", "vulnops-synthesis": "p/synthesis:high", "vulnops-independent-verify-one": "p/verifier:high"}}
        self.provenance = {"actor": self.actor, "selector": self.routing["agents"][self.actor], "artifact_ref": "sast/deepdive/T.json"}
        self.save(self.provenance["artifact_ref"], {"provenance": self.provenance})
        self.context = {"model_routing": self.routing, "source_root": str(self.target), "repositories": self.repositories}

    def save(self, ref, value):
        path = self.scan / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def finding(self, fid="F-001", source_id="C-1"):
        finding = sample_finding()
        finding.update(id=fid, contributors=[self.provenance],
                       source_refs=[{"kind": "sast", "source_id": source_id, "artifact_ref": "sast/verified-findings.json:" + source_id}])
        finding["verification"].update(model="p/synthesis:high",
            source_validation_refs=["source.py:1-2", self.provenance["artifact_ref"]])
        return finding

    def closure(self, fid="F-001", ref="sast/verified-findings.json:C-1"):
        return {"id": fid, "input_refs": [ref], "disposition": "evidence_limited", "reason": "Impact proof remains missing after entrypoint inspection.",
                "risk_context": "Established tenant-controlled entrypoint; privileged effect is not established.", "missing_fact": "Authority at the privileged write", "next_action": "Inspect the effect-side authority check",
                "review": None, "deferral": {"kind": "budget", "reason": "The assigned synthesis allocation was exhausted inspecting the higher-priority cross-tenant write; no source-review slot remains."}}

    def test_dependency_limitations_are_unresolved_coverage_not_primitives(self):
        for limitation in DEPENDENCY_LIMITATIONS:
            for relative in limitation["files"]:
                path = self.target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"lockfileVersion": 1}\n' if path.name == "package-lock.json" else "fixture\n")
        documents = {
            "dependency-limitations": {"schema_version": "2.0", "limitations": DEPENDENCY_LIMITATIONS},
            "tool-collection": {"schema_version": "2.0", "run_id": "coverage-fixture",
                "sca_ref": "tool-collection/sca-advisories.json",
                "secrets_ref": "tool-collection/secrets-redacted.json",
                "receipts": ["tool-collection/wraith-receipt.json", "tool-collection/poltergeist-receipt.json"],
                "limitations": DEPENDENCY_LIMITATIONS, "warnings": []},
        }
        for name, document in documents.items():
            schema = json.loads((ROOT / f"schemas/v2/{name}.schema.json").read_text())
            self.assertEqual(module("validate-json").Validator(schema).collect(document, schema), [])
            filename = "collection" if name == "tool-collection" else name
            self.save(f"tool-collection/{filename}.json", document)
        authority = {**self.context, "run_id": "coverage-fixture", "scan_base": str(self.scan)}
        context = self.save("context.json", authority)
        environment = activate_publisher(self.scan, authority, "campaign-planning", os.environ)
        before = {path: path.read_bytes() for root in (self.scan, self.target)
                  for path in root.rglob("*") if path.is_file()}
        with patch.dict(os.environ, environment), patch.object(sys, "argv", ["build-evidence-index", str(self.scan), "--context", str(context)]):
            self.assertEqual(module("build-evidence-index").main(), 0)
        index = json.loads((self.scan / "campaign-planning/evidence-index.json").read_text())
        self.assertEqual(len(index["records"]), len(DEPENDENCY_LIMITATIONS))
        records = {row["source_id"]: row for row in index["records"]}
        for limitation in DEPENDENCY_LIMITATIONS:
            record = records[limitation["code"]]
            self.assertEqual(record["source_kind"], "coverage")
            self.assertEqual(record["disposition"], "unresolved")
            self.assertEqual(record["files"], limitation["files"])
            self.assertEqual(record["summary"], limitation["message"])
            self.assertEqual(record["artifact_ref"], f"tool-collection/dependency-limitations.json:{limitation['code']}")
        self.assertEqual(set(index["coverage_gaps"]), {row["id"] for row in records.values()})
        self.assertEqual(index["primitives"], [])
        self.assertEqual(index["evidence_quality"]["total"], 0)
        self.assertEqual({path: path.read_bytes() for path in before}, before)

        schema = json.loads((ROOT / "schemas/v2/dependency-limitations.schema.json").read_text())
        validator = module("validate-json").Validator(schema)
        reviewed = copy.deepcopy(DEPENDENCY_LIMITATIONS[-1])
        variants = []
        missing = copy.deepcopy(reviewed); del missing["reviews"]; variants.append(missing)
        for field in ("file", "sha256", "reason"):
            incomplete = copy.deepcopy(reviewed); del incomplete["reviews"][0][field]; variants.append(incomplete)
        invalid_digest = copy.deepcopy(reviewed); invalid_digest["reviews"][0]["sha256"] = "invalid"; variants.append(invalid_digest)
        missing_files = copy.deepcopy(reviewed); del missing_files["files"]; variants.append(missing_files)
        empty_review = copy.deepcopy(reviewed); empty_review["reviews"] = []; variants.append(empty_review)
        for item in variants:
            document = {"schema_version": "2.0", "limitations": [item]}
            self.assertTrue(validator.collect(document, schema))

    def test_local_quality_does_not_swallow_safety(self):
        valid, issues = classify_refs(self.scan, self.target, self.repositories, ["source.py:1, 2", "source.py:99"], owner="candidate", field="evidence_refs", affected_item_ids=["C-1"])
        self.assertEqual(valid, ["source.py:1, 2"])
        self.assertEqual(issues[0]["code"], "invalid_range")
        with self.assertRaises(ValueError) as error:
            classify_refs(self.scan, self.target, self.repositories, ["source.py:99", "../escape.py"], owner="candidate", field="evidence_refs", affected_item_ids=["C-1"])
        self.assertNotIsInstance(error.exception, EvidenceIssue)

    def test_targeted_review_or_precise_deferral_is_required(self):
        row = self.closure()
        validate_non_promoted(row, self.routing, self.scan, self.target, self.repositories)
        row["deferral"] = None
        with self.assertRaisesRegex(ValueError, "targeted source review"):
            validate_non_promoted(row, self.routing, self.scan, self.target, self.repositories)
        row["review"] = {"actor": "vulnops-synthesis", "selector": "p/synthesis:high", "action": "Inspected entrypoint and followed the effect call.", "result": "Entrypoint is reachable; effect implementation is absent.", "evidence_refs": ["source.py:1,2"]}
        validate_non_promoted(row, self.routing, self.scan, self.target, self.repositories, actor="vulnops-synthesis")
        row["review"]["evidence_refs"] = [self.provenance["artifact_ref"]]
        with self.assertRaisesRegex(ValueError, "inspected source"):
            validate_non_promoted(row, self.routing, self.scan, self.target, self.repositories)

    def test_sibling_notes_and_extension_attribution_are_inert(self):
        path = self.save(self.provenance["artifact_ref"], {"provenance": self.provenance, "evidence_refs": ["missing.py:1"], "contributors": [{"actor": "forged"}], "positive_patterns": [{"evidence_refs": ["missing.py:1"]}]})
        finding = {"verification": {"source_validation_refs": [self.provenance["artifact_ref"]]}}
        before = path.read_bytes()
        self.assertEqual(finding_contributors(self.scan, finding, self.routing, source_root=self.target, repositories=self.repositories), [self.provenance])
        self.assertEqual(path.read_bytes(), before)
        finding["transitions"] = [{"resolution": {"evidence_refs": ["missing.py:1"]}}]
        with self.assertRaises(EvidenceIssue):
            finding_contributors(self.scan, finding, self.routing, source_root=self.target, repositories=self.repositories)

    def test_shared_bad_support_limits_only_dependent_claims(self):
        candidates = [{"id": cid, "contributors": [self.provenance], "evidence_refs": ["missing.py:1" if cid != "C-3" else "source.py:1-2"]} for cid in ("C-1", "C-2", "C-3")]
        source = self.save("sast/verified-findings.json", candidates)
        self.save("intrusion/intrusion-results.json", {"results": []})
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        doc = {"findings": [self.finding("F-00" + str(i), "C-" + str(i)) for i in range(1, 4)], "non_promoted": [self.closure("F-00" + str(i), "sast/verified-findings.json:C-" + str(i)) for i in (1, 2)]}
        result = module("finalize-synthesis").finalize_document(self.scan, self.context, doc)
        self.assertEqual([row["id"] for row in result["findings"]], ["F-003"])
        self.assertEqual([row["disposition"] for row in result["input_claims"]], ["evidence_limited", "evidence_limited", "eligible"])
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertEqual(module("finalize-synthesis").finalize_document(self.scan, self.context, copy.deepcopy(result)), result)
        for artifact_ref, source_ref in (("sast/verified-findings.json:C-3", "source.py:1-2"),
                                         ("sast/verified-findings.json#C-3", "source.py:1, 2")):
            with self.subTest(artifact_ref=artifact_ref, source_ref=source_ref):
                variant = copy.deepcopy(doc)
                variant["findings"][0]["source_refs"][0]["artifact_ref"] = artifact_ref
                variant["findings"][0]["verification"]["source_validation_refs"][0] = source_ref
                published = module("finalize-synthesis").finalize_document(self.scan, self.context, variant)
                self.assertEqual([row["id"] for row in published["findings"]], ["F-003"])
                self.assertEqual(published["findings"][0]["contributors"], [self.provenance])
        self.assertEqual(len(result["non_promoted"]), 2)
        with self.assertRaisesRegex(ValueError, "every input claim"):
            account_inputs(synthesis_inputs(self.scan), [], [])

    def test_intrusion_owner_and_aggregate_are_one_claim(self):
        candidate = {"id": "IC-AAAAAAAAAAAA", "evidence_refs": ["missing.py:1"]}
        closure = self.closure(candidate["id"], "intrusion/results/CAM-001.json#IC-AAAAAAAAAAAA")
        self.save("sast/verified-findings.json", [])
        self.save("intrusion/intrusion-results.json", {"results": [{
            "campaign_id": "CAM-001", "candidates": [candidate], "non_promoted": [closure]}]})
        inputs = synthesis_inputs(self.scan)
        self.assertEqual(set(inputs), {"intrusion/intrusion-results.json:IC-AAAAAAAAAAAA"})
        accounting = account_inputs(inputs, [], [closure])
        self.assertEqual([(row["input_ref"], row["disposition"]) for row in accounting],
                         [("intrusion/intrusion-results.json:IC-AAAAAAAAAAAA", "evidence_limited")])


    def test_optional_support_requires_real_independent_support(self):
        finding = {"id": "F-001", "verification": {"source_validation_refs": ["missing.py:1"]}, "optional_support": [{"reference": "missing.py:1", "obligation": "effect-side authority", "independent_support": ["source.py:2"], "rationale": "The inspected effect implementation independently establishes the authority mismatch; the missing duplicate adds nothing."}]}
        before = copy.deepcopy(finding)
        diagnostics = []
        projected = effective_support(self.scan, self.target, self.repositories, finding, diagnostics)
        self.assertEqual(projected["verification"]["source_validation_refs"], ["source.py:2"])
        self.assertEqual(finding, before)
        self.assertEqual(diagnostics[0]["disposition"], "optional")
        finding["optional_support"][0]["independent_support"] = ["also-missing.py:1"]
        with self.assertRaises(EvidenceIssue):
            effective_support(self.scan, self.target, self.repositories, finding)

    def test_selected_record_optional_support_requires_carried_rationale(self):
        self.save("sast/verified-findings.json", [{"id": "C-1", "contributors": [self.provenance], "evidence_refs": ["missing.py:1"]}])
        finding = self.finding()
        with self.assertRaises(EvidenceIssue):
            finding_contributors(self.scan, finding, self.routing, source_root=self.target, repositories=self.repositories)
        finding["optional_support"] = [{"reference": "missing.py:1", "obligation": "effect-side authority",
            "independent_support": ["source.py:2"], "rationale": "Fresh synthesis inspected the complete effect-side implementation; this older duplicate adds no necessary proof."}]
        diagnostics = []
        self.assertEqual(finding_contributors(self.scan, finding, self.routing, source_root=self.target, repositories=self.repositories, diagnostics=diagnostics), [self.provenance])
        self.assertEqual(diagnostics[0]["disposition"], "optional")

    def test_independent_verifier_challenges_optional_impact_proof(self):
        spec = importlib.util.spec_from_file_location("closure_fixtures", ROOT / "tests/test_investigation_closure.py")
        fixtures = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixtures)
        candidate = fixtures.finding()
        self.save(fixtures.ORIGIN["artifact_ref"], {"provenance": fixtures.ORIGIN})
        self.save("evidence.json", {"contributors": [fixtures.ORIGIN]})
        candidate["verification"]["source_validation_refs"].append("missing.py:1")
        candidate["optional_support"] = [{"reference": "missing.py:1", "obligation": "privileged impact",
            "independent_support": ["source.py:1"], "rationale": "Producer claims the entrypoint independently proves impact."}]
        result = fixtures.result(candidate)
        verify = module("finalize-verification")
        with self.assertRaisesRegex(ValueError, "challenge every"):
            verify.validate_assessment(ROOT, self.scan, self.target, candidate, result, fixtures.PRIMARY, {}, fixtures.ROUTING, repositories=self.repositories)
        result["optional_support_reviews"] = [{"reference": "missing.py:1", "obligation": "privileged impact",
            "sufficient": False, "evidence_refs": ["source.py:1"], "reason": "The inspected entrypoint does not establish privileged impact."}]
        with self.assertRaisesRegex(ValueError, "sufficient proof"):
            verify.validate_assessment(ROOT, self.scan, self.target, candidate, result, fixtures.PRIMARY, {}, fixtures.ROUTING, repositories=self.repositories)
        result["status"] = "evidence_limited"
        result["objective_results"][0]["satisfied"] = False
        result["non_promoted"] = self.closure(ref="synthesis/findings.json:F-001")
        result["joint_conditions"] = fixtures.resolution("locally_unresolved")
        verify.validate_assessment(ROOT, self.scan, self.target, candidate, result, fixtures.PRIMARY, {}, fixtures.ROUTING, repositories=self.repositories)
        result = fixtures.result(candidate)
        result["optional_support_reviews"] = [{"reference": "missing.py:1", "obligation": "privileged impact",
            "sufficient": True, "evidence_refs": ["source.py:2"], "reason": "Independent effect-side source inspection establishes the privileged write without the missing duplicate."}]
        self.assertEqual(verify.validate_assessment(ROOT, self.scan, self.target, candidate, result, fixtures.PRIMARY, {}, fixtures.ROUTING, repositories=self.repositories)["id"], "F-001")

    def test_bounded_rows_preserve_exact_totals_and_consequential_scope(self):
        diagnostics = [diagnostic("missing_file", "owner", "field" + str(i), ["C-" + str(i)]) for i in range(205)]
        quality = summarize(diagnostics + [diagnostics[0]])
        self.assertEqual((len(quality["diagnostics"]), quality["total"], quality["truncated"], quality["affected_item_count"]), (200, 206, 5, 205))
        self.save("synthesis/findings.json", {"evidence_quality": quality})
        final = {"non_promoted": [self.closure("F-" + str(i)) for i in range(205)]}
        rendered_quality, limited = module("render-report").evidence_accounting(self.scan, final)
        self.assertIsNone(rendered_quality["total"])
        self.assertIsNone(rendered_quality["truncated"])
        self.assertEqual(rendered_quality["phase_totals"]["synthesis/findings.json"],
                         {"total":206,"truncated":5,"affected_item_count":205})
        self.assertEqual(len(limited), 205)
        self.assertEqual(rendered_quality["canonical_refs"], ["synthesis/findings.json"])


if __name__ == "__main__":
    unittest.main()
