"""Consumer-visible dossier checks; fixtures are shared with pipeline tests."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from dossier_contract import (ASPECTS, dossier_hash, dossier_references, objective_assessments,
                              validate_dossier, validate_dossier_review, validate_publication_schema,
                              DossierAuthoringError)
from evidence_accounting import claim_diagnostics, effective_support
from evidence_refs import EvidenceIssue
from objective_contract import stable_id

OWNER = "sast/threat-model.json"
OBJECTIVE_ID = stable_id("OBJ-", OWNER, "tenant-read")
SUCCESS = "Read another tenant's record using only an ordinary account."


def seed_objective(scan, source="source.py:1-2"):
    """Seed real canonical definitions; never mock load_objectives in consumers."""
    objective = {"id": OBJECTIVE_ID, "owner": OWNER, "local_key": "tenant-read",
                 "starting_actor": "ordinary authenticated tenant user", "controlled_material": "record identifier",
                 "resource_scope": "another tenant's record", "desired_effect": "unauthorized read",
                 "success_condition": SUCCESS, "evidence_refs": [source]}
    question = {"id": stable_id("Q-", OWNER, "record-guard"), "owner": OWNER, "local_key": "record-guard",
                "objective_id": OBJECTIVE_ID, "security_question": "Does the shared lookup enforce tenant ownership?",
                "route": "authenticated record lookup", "proof_obligation": "tenant ownership guard",
                "novelty_reason": "Tests the shared resource authorization decision.", "evidence_refs": [source]}
    path = scan / OWNER
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"attack_objectives": [objective], "investigation_questions": [question]}))
    return objective, question


def add_dossier(finding, *, objective_id=OBJECTIVE_ID, source=None, repository="."):
    """Extend a synthetic canonical finding; call before creating its review."""
    root = finding["root_causes"][0]
    source = source or f"{root['file']}:{root['line']}"
    finding.update({"objective_ids": [objective_id], "attack_summary": "An ordinary account reads another tenant's record.",
                    "affected_components": [{"id": "component-1", "name": "Record lookup", "repository": repository,
                        "locations": copy.deepcopy(finding["root_causes"]), "entrypoints": [root["scope"]],
                        "service": {"name": None, "binding": "unknown", "evidence_refs": [],
                                    "limitation": "Deployment service identity was not established from inspected source."},
                        "evidence_refs": [source]}],
                    "exploitation": {"rationale": "The shared lookup uses the supplied ID without the tenant predicate.",
                        "setup": ["An ordinary account and another tenant's record identifier are required."],
                        "steps": [{"id": "step-1", "action": "Request the other tenant's record.",
                            "controlled_input": "A synthetic record identifier belonging to another tenant.",
                            "component_ids": ["component-1"], "why_it_works": "The lookup omits the ownership predicate.",
                            "expected_result": "The lookup returns the unauthorized record.", "evidence_status": "source_established",
                            "evidence_refs": [source], "observed_result": None, "observation_refs": [], "example_ids": [],
                            "primitive_ids": [row["primitive_id"] for row in finding["primitive_steps"]]}]},
                    "technical_examples": [], "impact_limits": ["No live deployment or target execution was exercised; no safe request example was prepared."],
                    "remediation": {"actions": [{"id": "fix-1", "component_ids": ["component-1"],
                        "locations": [copy.deepcopy(root)], "change": "Enforce the authenticated tenant in the shared lookup predicate.",
                        "rationale": "Resource ownership becomes part of the authority decision.", "breaks_steps": ["step-1"],
                        "evidence_refs": [source], "example_ids": []}], "containment": [], "detection": [],
                        "limitations": ["Deployment controls and a reliable existing detection signal were not established."],
                        "verification_checks": [{"id": "check-1", "description": "Exercise cross-tenant and own-tenant lookups.",
                            "attack_expected": "Reject another tenant's ID without disclosing its contents.",
                            "legitimate_expected": "Return the authenticated tenant's own record.", "status": "proposed", "evidence_refs": [source]}]}})
    return finding


def review_dossier(finding, result, *, success_condition=SUCCESS, satisfied=None):
    """Bind a synthetic fresh review to the complete effective finding."""
    effective = copy.deepcopy(finding)
    if result["status"] == "needs_environment":
        effective["status"] = "needs_environment"
        effective["verification"]["level"] = "environment_required"
        effective["closure_rationale"] = result["closure_reason"]
    refs = [f"{row['file']}:{row['line']}" for row in finding["root_causes"]]
    result["dossier_review"] = {"dossier_sha256": dossier_hash(effective), **{
        aspect: {"disposition": "supported", "reason": "Inspected source supports this bounded dossier claim.", "evidence_refs": refs}
        for aspect in ASPECTS}}
    accepted = result["status"] in {"verified", "corrected"} and finding["status"] == "verified"
    result["objective_results"] = [{"objective_id": oid, "success_condition": success_condition,
        "satisfied": accepted if satisfied is None else satisfied,
        "reason": "The inspected lookup returns another tenant's record without a tenant predicate." if accepted else
                  "The effective finding does not establish the complete scoped success condition.", "evidence_refs": refs}
        for oid in finding["objective_ids"]]
    return result


def sample_finding():
    location = {"file": "source.py", "line": 2, "scope": "lookup", "mechanism": "Missing tenant predicate."}
    return add_dossier({"id": "F-001", "finding_kind": "code", "origin": "standalone_known",
        "title": "Tenant record disclosure", "category": "authorization", "severity": "high", "risk_score": 80,
        "confidence": "high", "status": "verified", "attacker": {"perspective": "ordinary tenant",
            "starting_access": "authenticated ordinary account", "boundary_crossed": "tenant record ownership"},
        "intended_behavior": "Only return records owned by the authenticated tenant.", "root_causes": [location],
        "trace": [{"kind": kind, "file": "source.py", "line": line, "scope": "lookup", "description": description}
                  for kind, line, description in [("entrypoint", 1, "Accept a record ID."), ("sink", 2, "Return the record without ownership filtering.")]],
        "conditions": ["An ordinary account can supply record identifiers."], "impact": "Cross-tenant record disclosure.",
        "verification": {"level": "source_verified", "actor": "vulnops-synthesis", "model": "fixture/synthesis:high",
            "source_validation_refs": ["source.py:1-2"], "reproduction_ref": None},
        "contributors": [{"actor": "vulnops-deepdive-chunk", "selector": "fixture/investigator:high", "artifact_ref": "sast/deepdive/task.json"}],
        "primitive_steps": [], "transitions": [], "source_refs": [{"kind": "sast", "source_id": "C-001", "artifact_ref": "sast/verified-findings.json:C-001"}],
        "graph_receipt_refs": [], "closure_rationale": "Source establishes the missing shared authorization predicate.",
        "dependency": None, "secret": None})


class DossierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.scan = Path(self.temp.name) / "scan"
        self.target = Path(self.temp.name) / "target"
        self.scan.mkdir(); self.target.mkdir()
        (self.target / "source.py").write_text("def lookup(record_id):\n    return records[record_id]\n")
        self.repositories = [{"path": "."}]
        self.objective, self.question = seed_objective(self.scan)
        self.finding = sample_finding()

    def validate(self, finding=None):
        validate_dossier(self.scan, self.target, self.repositories, finding or self.finding)

    def test_dangling_dossier_bindings_fail(self):
        for field in ("component_ids", "example_ids", "primitive_ids"):
            with self.subTest(field=field):
                finding = copy.deepcopy(self.finding)
                finding["exploitation"]["steps"][0][field] = ["unknown"]
                with self.assertRaisesRegex(ValueError, "binding"):
                    self.validate(finding)
        self.finding["remediation"]["actions"][0]["breaks_steps"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "break point"):
            self.validate()

    def test_excerpt_aliases_substitution_and_fabrication(self):
        example = {"id": "example-1", "kind": "source", "content": "def lookup(record_id):\n    return records[record_id]",
                   "evidence_refs": ["source.py:1,2"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []}
        self.finding["technical_examples"] = [example]
        self.validate()
        example["evidence_refs"] = ["source.py#1-2"]
        with self.assertRaisesRegex(EvidenceIssue, "source selectors require a colon") as raised:
            self.validate()
        self.assertNotIsInstance(raised.exception, DossierAuthoringError)
        example["evidence_refs"] = ["source.py:1-2"]
        example["content"] = example["content"].replace("record_id", "synthetic_id")
        example["substitutions"] = [{"original": "record_id", "replacement": "synthetic_id", "reason": "Explicit synthetic identifier name."}]
        self.validate()
        example["content"] += "\n    authorize()"
        with self.assertRaisesRegex(DossierAuthoringError, "cited range") as raised:
            self.validate()
        self.assertNotIsInstance(raised.exception, EvidenceIssue)

        (self.scan / "sast/verified-findings.json").write_text(json.dumps([{"id": "C-001"}]))
        example = {"id": "example-1", "kind": "source", "content": "illustration",
                   "evidence_refs": ["sast/verified-findings.json:C-001"], "substitutions": [],
                   "execution_status": "not_executed", "observation_refs": []}
        self.finding["technical_examples"] = [example]
        with self.assertRaisesRegex(DossierAuthoringError, "source attribution"):
            self.validate()
        self.assertEqual(example["kind"], "source")
        example["evidence_refs"] = ["missing.py:1"]
        with self.assertRaises(EvidenceIssue) as raised:
            self.validate()
        self.assertNotIsInstance(raised.exception, DossierAuthoringError)

    def test_missing_proof_is_local_but_unsafe_paths_are_fatal(self):
        self.finding["exploitation"]["steps"][0]["evidence_refs"] = ["missing.py:1"]
        with self.assertRaises(EvidenceIssue):
            self.validate()
        diagnostics = claim_diagnostics(self.scan, self.target, self.repositories, self.finding, owner="synthesis/findings.json", item_id="F-001")
        self.assertTrue(any(row["field"] == "exploitation.steps[0].evidence_refs" for row in diagnostics))
        self.finding["exploitation"]["steps"][0]["evidence_refs"] = ["../outside.py:1"]
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            self.validate()

    def test_no_observation_from_expected_behavior_or_file_existence(self):
        step = self.finding["exploitation"]["steps"][0]
        step["observed_result"] = "The record was returned."
        with self.assertRaisesRegex(ValueError, "unexecuted"):
            self.validate()
        step["evidence_status"] = "observed_contained"
        step["observation_refs"] = ["sast/observation.json"]
        (self.scan / "sast/observation.json").write_text('{"status":"supported"}')
        (self.scan / "run-manifest.json").write_text('{"reproduction_mode":"safe"}')
        with self.assertRaisesRegex(ValueError, "approved contained"):
            self.validate()

    def test_source_only_dossier_requires_fresh_hash_and_exact_goal_review(self):
        self.validate()
        final = {**self.finding, "verdict": "confirmed", "model_diversity": True,
                 "independent_verification_ref": "final-verification/results/F-001.json"}
        validate_publication_schema(final, "final-findings.schema.json", "finding")
        self.assertEqual(dossier_hash(final), dossier_hash(self.finding))
        self.assertIn("source.py:2", dossier_references(final))
        result = review_dossier(self.finding, {"status": "verified"})
        validate_dossier_review(self.scan, self.target, self.repositories, self.finding, result)
        for field in ("attack_summary", "impact", "closure_rationale"):
            finding = copy.deepcopy(self.finding); finding[field] += " Changed scope."
            with self.assertRaisesRegex(ValueError, "stale"):
                validate_dossier_review(self.scan, self.target, self.repositories, finding, result)
        result["objective_results"][0]["success_condition"] = "A different goal"
        with self.assertRaisesRegex(ValueError, "success condition"):
            validate_dossier_review(self.scan, self.target, self.repositories, self.finding, result)

    def test_empty_rejected_and_standalone_objective_accounting(self):
        empty = objective_assessments(self.scan, [])
        self.assertEqual(empty[0]["status"], "unresolved")
        self.assertEqual(empty[0]["finding_ids"], [])
        self.assertTrue(empty[0]["remaining_obligations"])
        final = {**self.finding, "verdict": "confirmed"}
        result = review_dossier(self.finding, {"status": "verified"})
        self.assertEqual(objective_assessments(self.scan, [final])[0]["status"], "unresolved")
        self.assertEqual(objective_assessments(self.scan, [final], results={"F-001": result})[0]["status"], "achieved")
        result["status"] = "rejected"
        self.assertEqual(objective_assessments(self.scan, [final], results={"F-001": result})[0]["status"], "unresolved")
        with self.assertRaisesRegex(ValueError, "cannot achieve"):
            validate_dossier_review(self.scan, self.target, self.repositories, self.finding, result)

    def test_isolated_observation_receipt_cannot_expand_to_unrelated_step_or_fix(self):
        environment = copy.deepcopy(self.finding)
        environment["status"] = "needs_environment"
        environment["verification"]["level"] = "environment_required"
        environment["exploitation"]["steps"][0]["evidence_status"] = "environment_required"
        self.validate(environment)
        check = environment["remediation"]["verification_checks"][0]
        check.update(status="executed", evidence_refs=[])
        with self.assertRaisesRegex(ValueError, "approved reproduction"):
            self.validate(environment)

        # Authored receipt metadata exercises validation, not contained execution.
        from investigation_experiments import make_result
        directory = self.scan / "sast/experiments/parser"
        directory.mkdir(parents=True)
        (self.scan / "sast/task.json").write_text("{}")
        context = {"run_id": "fixture", "attempt_id": "current", "scan_base": str(self.scan), "reproduction_mode": "safe",
                   "experiment_budget": {"max_experiments": 1, "max_concurrency": 1, "timeout_seconds": 10,
                       "cpu_seconds": 10, "memory_mb": 128, "max_processes": 10, "max_output_kb": 4}}
        request = {"schema_version": "2.0", "run_id": "fixture", "attempt_id": "current", "experiment_id": "parser", "owner_phase": "sast",
                   "owner_ref": "sast/task.json", "obligation": "Record lookup behavior", "static_limitation": "Isolated return not executed.",
                   "behavior": "Exercise only the isolated lookup.", "supports": "The isolated lookup returned the selected fixture record.",
                   "contradicts": "The isolated lookup rejected the fixture record.", "input_refs": ["sast/task.json"],
                   "dependencies": [], "execution_policy": "safe_offline_disposable",
                   "interpretation_boundary": "Only the isolated lookup is exercised.", "command": ["fixture-test"],
                   "support_exit_code": 0, "contradict_exit_code": 1}
        request_path = directory / "request.json"
        request_path.write_text(json.dumps(request))
        result = make_result(context, request, "sast/experiments/parser/request.json",
                             hashlib.sha256(request_path.read_bytes()).hexdigest(), "supported", "bubblewrap", 0)
        (directory / "result.json").write_text(json.dumps(result))
        (self.scan / "run-manifest.json").write_text(json.dumps(context))
        step = self.finding["exploitation"]["steps"][0]
        step.update(evidence_status="observed_contained", action=request["behavior"], observed_result=request["supports"],
                    observation_refs=["sast/experiments/parser/result.json"])
        self.validate()
        step["action"] = "Read a live production tenant record."
        with self.assertRaisesRegex(ValueError, "does not bind"):
            self.validate()
        step["action"] = request["behavior"]
        check = self.finding["remediation"]["verification_checks"][0]
        check.update(status="executed", evidence_refs=step["observation_refs"])
        with self.assertRaisesRegex(ValueError, "never verify a fix"):
            self.validate()

    def test_mixed_route_outcomes_remain_explicit(self):
        second = {**self.question, "local_key": "second-route", "route": "background export",
                  "proof_obligation": "background consumer authority", "id": stable_id("Q-", OWNER, "second-route")}
        (self.scan / OWNER).write_text(json.dumps({"attack_objectives": [self.objective],
                                                  "investigation_questions": [self.question, second]}))
        (self.scan / "sast/coverage-ledger.json").write_text(json.dumps({"cells": [{
            "id": "cell-1", "objective_id": OBJECTIVE_ID, "question_id": self.question["id"],
            "resolution": {"outcome": "contradicted", "reason": "This route enforces ownership.",
                           "evidence_refs": ["source.py:2"], "missing_fact": "", "next_action": "Inspect alternate route."}}]}))
        assessment = objective_assessments(self.scan, [])[0]
        self.assertEqual(assessment["status"], "unresolved")
        self.assertEqual({row["outcome"] for row in assessment["question_outcomes"]}, {"contradicted", "not_investigated"})
        self.assertIn(second["proof_obligation"], assessment["remaining_obligations"])

    def test_optional_dossier_support_is_read_only_and_requires_independent_source(self):
        step = self.finding["exploitation"]["steps"][0]
        step["evidence_refs"] = ["missing.py:1"]
        self.finding["optional_support"] = [{"reference": "missing.py:1", "obligation": "lookup authority",
            "independent_support": ["source.py:2"], "rationale": "Inspected effect-side lookup independently establishes the missing ownership predicate."}]
        before = copy.deepcopy(self.finding)
        effective = effective_support(self.scan, self.target, self.repositories, self.finding)
        self.validate(effective)
        self.assertEqual(self.finding, before)
        self.assertEqual(effective["exploitation"]["steps"][0]["evidence_refs"], ["source.py:2"])
        (self.scan / "sast/verified-findings.json").write_text(json.dumps([{"id": "C-001"}]))
        for support, reason in ((["sast/verified-findings.json:C-001"], "independently inspected source"),
                                (["missing.py:1"], "cannot establish itself")):
            with self.subTest(support=support):
                invalid = copy.deepcopy(self.finding)
                invalid["optional_support"][0]["independent_support"] = support
                snapshot = copy.deepcopy(invalid)
                with self.assertRaisesRegex(ValueError, reason):
                    effective_support(self.scan, self.target, self.repositories, invalid)
                self.assertEqual(invalid, snapshot)

    def test_new_dossier_proof_fields_contribute_source_owned_provenance(self):
        from model_identity import finding_contributors
        origin = self.finding["contributors"][0]
        reviewer = {"actor": "vulnops-recon-overview", "selector": "fixture/recon:high",
                    "artifact_ref": "repo-context/research/overview.json"}
        routing = {"agents": {origin["actor"]: origin["selector"], reviewer["actor"]: reviewer["selector"]}}
        for provenance in (origin, reviewer):
            path = self.scan / provenance["artifact_ref"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"provenance": provenance}))
        (self.scan / "sast/verified-findings.json").write_text(json.dumps([
            {"id": "C-001", "contributors": [origin], "evidence_refs": ["source.py:1-2"]}]))
        self.finding["remediation"]["actions"][0]["evidence_refs"].append(reviewer["artifact_ref"])
        contributors = finding_contributors(self.scan, self.finding, routing,
                                             source_root=self.target, repositories=self.repositories)
        self.assertEqual({row["actor"] for row in contributors}, {origin["actor"], reviewer["actor"]})
        (self.scan / reviewer["artifact_ref"]).write_text(json.dumps({"provenance": {**reviewer, "selector": "forged/model:high"}}))
        with self.assertRaisesRegex(ValueError, "assigned route"):
            finding_contributors(self.scan, self.finding, routing, source_root=self.target, repositories=self.repositories)



if __name__ == "__main__":
    unittest.main()
