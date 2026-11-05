#!/usr/bin/env python3
"""Stage 4 behavioral checks; no audited application code is executed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from intrusion_contract import OBLIGATIONS
from model_identity import contributor_union, diversity_summary, finding_diversity
from model_routing import GROUP_AGENTS, audit_routing, resolve_routing
from test_dossiers import add_dossier, review_dossier, seed_objective
from test_report_outcome_categories import report_context
from test_run_lifecycle import activate_publisher
from test_investigation_identity import completed_prior

PRIMARY = "openai-codex/gpt-6-astra:high"
VERIFIER = "openai-codex/gpt-daybreak-red-latest:high"
ROUTING = audit_routing(resolve_routing({"routing": {
    group: PRIMARY if group in {"audit_lead", "recon", "synthesis"} else VERIFIER
    for group in GROUP_AGENTS
}}))
ORIGIN = {"actor": "vulnops-deepdive-chunk", "selector": VERIFIER, "artifact_ref": "sast/deepdive/T-001.json"}


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


verification = module("finalize-verification")
synthesis = module("finalize-synthesis")
reporting = module("render-report")


def resolution(outcome="established"):
    return {"outcome": outcome, "reason": "Inspected scoped source and handoff mapping.", "next_action": "Inspect deployment binding." if outcome != "established" else "", "evidence_refs": ["evidence.json"], "missing_fact": "Deployment binding" if outcome == "externally_blocked" else ""}


def edge(left, right):
    proof = {"outcome": "established", "reason": "Source maps the scoped authority across this handoff.", "evidence_refs": ["evidence.json"], "source_locations": [{"file": "source.txt", "start_line": 1, "end_line": 1}]}
    return {"producer_id": left, "consumer_id": right, "resolution": resolution(), "obligations": {key: copy.deepcopy(proof) for key in OBLIGATIONS}}


def finding(ids=(), fid="F-001"):
    return add_dossier({"id": fid, "finding_kind": "chain" if ids else "code", "origin": "composite_chain" if ids else "independent_discovery", "title": "Scoped authority crossing", "category": "authorization", "severity": "high", "risk_score": 80, "confidence": "high", "status": "verified", "attacker": {"perspective": "tenant user", "starting_access": "account", "boundary_crossed": "resource authority"}, "intended_behavior": "Preserve tenant scope", "root_causes": [{"file": "source.txt", "line": 1, "scope": "handler", "mechanism": "Missing scoped authorization"}], "trace": [{"kind": "entrypoint", "file": "source.txt", "line": 1, "scope": "handler", "description": "Actor-controlled entry"}, {"kind": "sink", "file": "source.txt", "line": 1, "scope": "effect", "description": "Sensitive effect"}], "conditions": ["same tenant and active session"], "impact": "Unauthorized scoped write", "remediation": "Enforce the resource authority", "verification": {"level": "source_verified", "actor": "vulnops-synthesis", "model": PRIMARY, "source_validation_refs": ["evidence.json"], "reproduction_ref": None}, "contributors": [dict(ORIGIN)], "primitive_steps": [{"primitive_id": pid, "input_capability": "tenant-scoped request", "output_capability": "mapped queue credential", "boundary_crossed": "queue handoff", "evidence_refs": ["evidence.json"]} for pid in ids], "transitions": [edge(a, b) for a, b in zip(ids, ids[1:])], "source_refs": [{"kind": "sast", "source_id": "SAST-001", "artifact_ref": "evidence.json"}], "graph_receipt_refs": [], "closure_rationale": "Current scoped evidence supports the claim", "dependency": None, "secret": None})


def result(candidate, status="verified"):
    return review_dossier(candidate, {"schema_version": "2.0", "finding_id": candidate["id"], "status": status, "closure_reason": "Current source independently inspected", "evidence_refs": ["evidence.json", "source.txt:1"], "primitive_results": [{"primitive_id": p["primitive_id"], "status": "verified", "evidence_refs": ["evidence.json"], "reason": "Scoped capability established"} for p in candidate["primitive_steps"]], "transition_results": copy.deepcopy(candidate["transitions"]), "joint_conditions": resolution(), "corrections": [], "corrected_finding": copy.deepcopy(candidate) if status == "corrected" else None, "actor": "vulnops-independent-verify-one", "model": VERIFIER, "model_diversity": finding_diversity(candidate["contributors"], VERIFIER)})

def exercise_dossier_finalizers(base):
    """Fixed model outputs exercise publication gates, not semantic model judgment."""
    base = base.resolve()
    def save(ref, value):
        path = base / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
    target = base / "source"; target.mkdir()
    (target / "source.txt").write_text("synthetic scoped queue mapping\n")
    seed_objective(base, "source.txt:1")
    save(ORIGIN["artifact_ref"], {"provenance": ORIGIN})
    save("evidence.json", {"contributors": [ORIGIN]})
    context = {"run_id": "dossier-smoke", "scan_base": str(base), "model_routing": ROUTING,
               "repo_path": str(target), "source_root": str(target),
               "repositories": [{"path": "."}]}
    save("context.json", context)
    claims = [finding(["P-A", "P-B"]), finding(fid="F-002"), finding(fid="F-003")]
    for claim in claims:
        cid = "C-" + claim["id"]
        claim["source_refs"] = [{"kind": "sast", "source_id": cid, "artifact_ref": "sast/verified-findings.json:" + cid}]
    save("sast/verified-findings.json", [{"id": "C-" + claim["id"], "contributors": [ORIGIN],
                                       "evidence_refs": ["source.txt:1"]} for claim in claims])
    save("intrusion/intrusion-results.json", {"results": []})
    save("campaign-planning/campaign-plan.json", {"campaigns": []})
    save("campaign-planning/evidence-index.json", {
        "records": [{"source_kind": "sast", "source_id": "C-" + claim["id"]} for claim in claims],
        "primitives": [{"id": pid, "contributors": [ORIGIN], "capability": {"evidence_status": "source_established"}}
                       for pid in ("P-A", "P-B")]})
    claims[2]["exploitation"]["steps"][0]["evidence_refs"] = ["missing-effect.txt:1"]
    def limited(fid, input_ref):
        return {"id": fid, "input_refs": [input_ref], "disposition": "evidence_limited",
            "reason": "The effect-side authority remains unproven.", "risk_context": "A tenant-controlled reference crosses a privileged consumer boundary.",
            "missing_fact": "Authority applied by the consumer", "next_action": "Inspect the effect-side ownership check",
            "review": None, "deferral": {"kind": "budget",
                "reason": "The assigned review allocation was exhausted on the independently established higher-impact chain; no consumer-review slot remains."}}
    save("synthesis/findings.json", {"schema_version": "2.0", "run_id": "dossier-smoke", "findings": claims,
        "objective_assessments": synthesis.objective_assessments(base, claims),
        "non_promoted": [limited("F-003", "sast/verified-findings.json:C-F-003")]})
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "VULNOPS_AUDIT_CONTEXT": str(base / "context.json")}
    env = activate_publisher(base, context, "synthesis", env)
    def invoke(script, *arguments):
        completed = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, arguments)],
                                   env=env, capture_output=True, text=True)
        if completed.returncode:raise AssertionError(completed.stderr)
    invoke("finalize-synthesis.py", base)
    synthesized = json.loads((base / "synthesis/findings.json").read_text())
    chain, component = synthesized["findings"]
    corrected = copy.deepcopy(chain)
    corrected["impact"] = "Unauthorized write within the independently established tenant and queue scope."
    assessment = result(corrected, "corrected")
    assessment["corrections"] = [{"field": "impact", "before": chain["impact"], "after": corrected["impact"],
                                 "reason": "The independently inspected handoff establishes only this resource scope."}]
    save("final-verification/results/F-001.json", assessment)
    assessment = result(component, "evidence_limited")
    assessment["non_promoted"] = limited("F-002", "synthesis/findings.json:F-002")
    assessment["joint_conditions"] = {**resolution("locally_unresolved"),
                                     "missing_fact": "Authority applied by the consumer", "next_action": "Inspect effect-side ownership."}
    assessment["dossier_review"]["exploitation"].update(disposition="unresolved", reason="Consumer authority remains unproven.")
    save("final-verification/results/F-002.json", assessment)
    env = activate_publisher(base, context, "final-verification", env)
    invoke("finalize-verification.py", target, base)
    final = json.loads((base / "final-verification/findings.json").read_text())
    return synthesized, final, corrected


class InvestigationClosure(unittest.TestCase):
    def test_real_finalizers_preserve_corrected_chain_and_local_evidence_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            synthesized, final, corrected = exercise_dossier_finalizers(Path(directory))
            self.assertEqual([row["id"] for row in synthesized["findings"]], ["F-001", "F-002"])
            self.assertEqual([row["id"] for row in final["findings"]], ["F-001"])
            self.assertEqual(final["findings"][0]["impact"], corrected["impact"])
            self.assertEqual({row["id"] for row in final["non_promoted"]}, {"F-002", "F-003"})
            self.assertEqual(final["findings"][0]["primitive_steps"], corrected["primitive_steps"])

    def test_corrected_sequence_requires_matching_assessments(self):
        original = finding(["P-A", "P-B"])
        corrected = finding(["P-A", "P-C", "P-B"])
        assessment = result(corrected, "corrected")
        self.assertEqual(verification.effective_assessment(ROOT, original, assessment, PRIMARY)["primitive_steps"], corrected["primitive_steps"])
        assessment["primitive_results"] = result(original)["primitive_results"]
        with self.assertRaisesRegex(ValueError, "effective primitives"):
            verification.effective_assessment(ROOT, original, assessment, PRIMARY)
        assessment = result(corrected, "corrected")
        assessment["transition_results"] = original["transitions"]
        with self.assertRaisesRegex(ValueError, "transitions"):
            verification.effective_assessment(ROOT, original, assessment, PRIMARY)

    def test_corrected_mixed_origin_chain_recomputes_contributors(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "source"
            target.mkdir()
            (target / "source.txt").write_text("scoped queue mapping\n")
            seed_objective(base, "source.txt:1")
            (base / "evidence.json").write_text(json.dumps({"contributors": [ORIGIN]}))
            astra = {"actor": "vulnops-recon-inputs", "selector": PRIMARY, "artifact_ref": "repo-context/research/input-surfaces.json"}
            for provenance in (ORIGIN, astra):
                owner = base / provenance["artifact_ref"]
                owner.parent.mkdir(parents=True, exist_ok=True)
                owner.write_text(json.dumps({"provenance": provenance}))
            original = finding(["P-A", "P-B"])
            corrected = finding(["P-A", "P-C", "P-B"])
            primitives = {pid: {"contributors": [astra if pid == "P-C" else ORIGIN],
                                "capability": {"evidence_status": "source_established"}}
                          for pid in ("P-A", "P-B", "P-C")}
            assessment = result(corrected, "corrected")
            with self.assertRaisesRegex(ValueError, "contributors"):
                verification.validate_assessment(ROOT, base, target, original, assessment, PRIMARY, primitives, ROUTING, repositories=[{"path": "."}])
            corrected["contributors"] = contributor_union([ORIGIN], [astra])
            assessment = result(corrected, "corrected")
            effective = verification.validate_assessment(ROOT, base, target, original, assessment, PRIMARY, primitives, ROUTING, repositories=[{"path": "."}])
            self.assertEqual(effective["contributors"], corrected["contributors"])
            self.assertFalse(assessment["model_diversity"])
            assessment["model_diversity"] = True
            with self.assertRaisesRegex(ValueError, "diversity"):
                verification.validate_assessment(ROOT, base, target, original, assessment, PRIMARY, primitives, ROUTING, repositories=[{"path": "."}])

    def test_finalizer_retains_component_after_chain_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            def save(ref, value):
                path = base / ref
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            target = base / "source"
            target.mkdir()
            (target / "source.txt").write_text("scoped queue mapping\n")
            seed_objective(base, "source.txt:1")
            save(ORIGIN["artifact_ref"], {"provenance": ORIGIN})
            save("evidence.json", {"contributors": [ORIGIN]})
            context = {"run_id": "current", "scan_base": str(base), "model_routing": ROUTING,
                       "repo_path": str(target), "source_root": str(target), "repositories": [{"path": "."}]}
            save("context.json", context)
            chain = finding(["P-A", "P-B"])
            component = finding(fid="F-002")
            save("synthesis/findings.json", {"schema_version": "2.0", "run_id": "current", "findings": [chain, component],
                 "objective_assessments": synthesis.objective_assessments(base, [chain, component])})
            save("campaign-planning/evidence-index.json", {"primitives": [{"id": pid, "contributors": [ORIGIN], "capability": {"evidence_status": "source_established"}} for pid in ("P-A", "P-B")]})
            rejected = result(chain)
            rejected["joint_conditions"] = resolution("contradicted")
            with self.assertRaisesRegex(ValueError, "jointly"):
                verification.effective_assessment(ROOT, chain, rejected, PRIMARY)
            rejected = result(chain, "rejected")
            rejected["joint_conditions"] = resolution("contradicted")
            save("final-verification/results/F-001.json", rejected)
            save("final-verification/results/F-002.json", result(component))
            env = activate_publisher(base, context, "final-verification",
                                     {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(base / "context.json")})
            subprocess.run([sys.executable, str(ROOT / "scripts/finalize-verification.py"), str(target), str(base)],
                           env=env, check=True, capture_output=True)
            final = json.loads((base / "final-verification/findings.json").read_text())
            self.assertEqual([row["id"] for row in final["findings"]], ["F-002"])
            self.assertEqual(final["findings"][0]["verdict"], "confirmed")
            self.assertEqual([row["id"] for row in final["rejections"]], ["F-001"])

    def test_prior_roots_default_to_nonrevisit_and_require_current_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve() / "current"
            base.mkdir()
            prior = completed_prior(base.parent / "prior", "prior",
                                    findings=[{"id": "F-009", "verdict": "confirmed"}])
            context = {"attempt_id": "current"}
            rows = synthesis.reconcile_prior(context, base, {"findings": []})
            self.assertEqual(rows[0]["status"], "not_revisited")
            self.assertIn("Historical conclusions", rows[0]["applicability"]["policy"])
            (base / "evidence.json").write_text("{}")
            rows[0].update(status="revalidated", evidence_refs=["evidence.json"], current_finding_ids=["F-001"])
            current = {"id": "F-001", "verdict": "needs_environment"}
            output = synthesis.reconcile_prior(context, base, {"findings": [current], "prior_run_reconciliation": rows}, final=True)
            self.assertEqual(output[0]["status"], "not_revisited")
            current["verdict"] = "confirmed"
            with self.assertRaisesRegex(ValueError, "current independent confirmation"):
                synthesis.reconcile_prior(context, base, {"findings": [current], "prior_run_reconciliation": rows}, final=True)
            current["assessment_context"] = {"attempt_id": "current"}
            output = synthesis.reconcile_prior(context, base, {"findings": [current], "prior_run_reconciliation": rows}, final=True)
            self.assertEqual(output[0]["status"], "revalidated")
            rows[0]["status"] = "superseded"
            output = synthesis.reconcile_prior(context, base, {"findings": [current], "prior_run_reconciliation": rows}, final=True)
            self.assertEqual(output[0]["status"], "superseded")
            del current["assessment_context"]
            with self.assertRaisesRegex(ValueError, "current independent confirmation"):
                synthesis.reconcile_prior(context, base, {"findings": [current], "prior_run_reconciliation": rows}, final=True)
            rows[0].update(status="contradicted", current_finding_ids=[])
            output = synthesis.reconcile_prior(context, base, {"findings": [], "prior_run_reconciliation": rows}, final=True)
            self.assertEqual(output[0]["status"], "contradicted")
            rows[0]["evidence_refs"] = []
            with self.assertRaisesRegex(ValueError, "requires current evidence"):
                synthesis.reconcile_prior(context, base, {"findings": [], "prior_run_reconciliation": rows}, final=True)
            completed_prior(base.parent / "prior", "prior",
                            historical=[{"id": "F-009", "verdict": "confirmed"}])
            self.assertEqual(synthesis.reconcile_prior(context, base, {"findings": []})[0]["prior_finding_id"], "F-009")

    def test_removed_consumed_report_limits_comparison_not_current_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve() / "current"
            base.mkdir()
            prior = completed_prior(base.parent / "prior", "prior",
                                    findings=[{"id": "F-009", "verdict": "confirmed"}])
            context = {"attempt_id": "current"}
            rows = synthesis.reconcile_prior(context, base, {"findings": []})
            rows[0].update(status="revalidated", current_finding_ids=["F-001"])
            current = {"id": "F-001", "verdict": "confirmed",
                       "assessment_context": {"attempt_id": "current"}}
            prior.unlink()
            doc = {"findings": [current], "prior_run_reconciliation": rows}
            output = synthesis.reconcile_prior(context, base, doc, final=True)
            self.assertEqual(output[0]["status"], "not_revisited")
            self.assertIn("could not be checked", output[0]["reason"])
            self.assertEqual(output[0]["current_finding_ids"], ["F-001"])
            self.assertEqual(doc["findings"], [current])
            # Legacy saved pointers are inert, even if they are malformed.
            context["prior_reports"] = [{"path": "/nonexistent/old.json"}]
            self.assertEqual(synthesis.reconcile_prior(context, base, {"findings": [current]}), [])

    def test_prior_references_cannot_escape_or_invent_available_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve() / "current"
            base.mkdir()
            completed_prior(base.parent / "prior", "prior",
                            findings=[{"id": "F-009", "verdict": "confirmed"}])
            rows = synthesis.reconcile_prior({}, base, {"findings": []})
            rows[0]["prior_finding_id"] = "F-404"
            with self.assertRaisesRegex(ValueError, "unknown prior root"):
                synthesis.reconcile_prior({}, base, {"findings": [], "prior_run_reconciliation": rows})
            rows[0]["prior_report_ref"] = str(base.parent / "outside.json")
            with self.assertRaisesRegex(ValueError, "sibling report"):
                synthesis.reconcile_prior({}, base, {"findings": [], "prior_run_reconciliation": rows})

    def test_report_distinguishes_shallow_unscheduled_and_contradicted(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            def save(ref, value):
                path = base / ref
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            context = base / "context.json"
            report_authority = report_context("current", ROUTING)
            save("final-verification/findings.json", {"findings": [], "rejections": [], "objective_assessments": [], "verifier_model": VERIFIER, **diversity_summary([])})
            save("campaign-planning/campaign-plan.json", {"campaigns": [], "scanner_accounting": []})
            save("intrusion/intrusion-results.json", {"results": []})
            save("sast/coverage-ledger.json", {"cells": [{"id": "reviewed", "status": "shallow", "task_ids": ["T-1"], "resolution": resolution("locally_unresolved")}, {"id": "never", "status": "deferred", "task_ids": [], "resolution": resolution("budget_deferred")}], "tasks": []})
            env = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context)}
            env = activate_publisher(base, report_authority, "report", env)
            save("context.json", report_authority)
            subprocess.run([sys.executable, str(ROOT / "scripts/render-report.py"), str(base)], env=env, check=True, capture_output=True)
            report = json.loads((base / "report/security-report.json").read_text())
            self.assertEqual(report["outcome_assessment"]["status"], "substantially_unresolved")
            self.assertEqual(report["summary"]["unresolved_paths"], 1)
            self.assertEqual(report["summary"]["unscheduled_work"], 1)
            self.assertEqual(report["summary"]["confirmed"], 0)
            self.assertFalse(report["model_diversity"])
            self.assertEqual(report["diversity_counts"], {"diverse": 0, "same_model": 0, "total": 0})
            self.assertEqual(report["model_routing"], ROUTING)
            save("sast/coverage-ledger.json", {"cells": [{"id": "stopped", "status": "clean", "task_ids": ["T-1"], "resolution": resolution("contradicted")}], "tasks": []})
            subprocess.run([sys.executable, str(ROOT / "scripts/render-report.py"), str(base)], env=env, check=True, capture_output=True)
            report = json.loads((base / "report/security-report.json").read_text())
            self.assertEqual(report["outcome_assessment"]["status"], "resolved_within_recorded_scope")
            self.assertEqual(report["summary"]["confirmed"], 0)
            self.assertEqual(report["investigation_accounting"]["denominators"]["planned_campaigns"], 0)
            save("campaign-planning/campaign-plan.json", {"campaigns": [], "scanner_accounting": [{"evidence_id": f"S-{index}", "status": "deferred", "reason": "Budget", "campaign_ids": []} for index in range(205)]})
            save("sast/experiments/E-001/request.json", {"obligation": "Does the parser preserve scope?", "command": ["DO-NOT-RENDER-ME"]})
            save("sast/experiments/E-001/result.json", {"experiment_id": "E-001", "status": "containment_unavailable", "resolution": resolution("externally_blocked"), "interpretation_boundary": "Isolated behavior only"})
            subprocess.run([sys.executable, str(ROOT / "scripts/render-report.py"), str(base)], env=env, check=True, capture_output=True)
            report = json.loads((base / "report/security-report.json").read_text())
            self.assertEqual(report["summary"]["unscheduled_work"], 205)
            self.assertEqual(len(report["investigation_accounting"]["unscheduled_work"]), 200)
            self.assertEqual(report["investigation_accounting"]["truncated"]["unscheduled_work"], 5)
            self.assertEqual(report["investigation_accounting"]["experiments"][0]["status"], "containment_unavailable")
            self.assertNotIn("DO-NOT-RENDER-ME", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
