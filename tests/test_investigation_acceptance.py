"""Deterministic publication of seeded source investigations and continuation.

Synthetic investigator artifacts exercise real deterministic publication commands;
no scanner, investigator model, independent verifier model or normal launcher runs.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from test_investigation_source import fixture as source_fixture, ROUTING
from sast_contract import validate_hunt_result
from harness_contract import resolved_intrusion_budget
from intrusion_contract import build_wave, reference, primitive_id, available_primitives
from model_identity import contributor_union
from model_routing import GROUP_AGENTS, resolve_routing, audit_routing
from objective_contract import stable_id
from objective_fixtures import objective_binding, record_read_registry
from test_report_outcome_categories import report_context
from test_run_lifecycle import activate_publisher


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def scenario(base):
    base = base.resolve()
    scan, target = base / "scan", base / "source"
    sources = {"gateway/handler.py": "def handler(record): return read_record(record)\n",
               "service/implementation.py": "def read_record(record): return storage[Record(record).id]\n",
               "shared/dto.py": "class Record: pass\n",
               "service/worker.py": "def consume(user, record):\n    if record.owner != user.tenant: return None\n    return record.content\n",
               "gateway/package-lock.json": "{}\n"}
    for name, text in sources.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    repositories = [{"path": name, "name": name, "remote_url": "local", "commit": "fixture"}
                    for name in ("gateway", "service", "shared")]
    registry = record_read_registry()
    write(scan / "sast/threat-model.json", registry)
    cell, task, source_result = source_fixture()
    errors = validate_hunt_result(ROOT, target, task, [cell], source_result, registry, repositories, ROUTING, scan=scan)
    if errors:
        raise AssertionError(errors)
    write(scan / "sast/deepdive/H001.json", source_result)
    write(scan / "sast/verified-findings.json", [])
    routing = audit_routing(resolve_routing({"routing": {group: "test/red:high" for group in GROUP_AGENTS}}))
    context = {**report_context("acceptance", routing), "depth": "quick",
               "codegraph_mode": "disabled", "reproduction_mode": "off",
               "scan_base": str(scan), "source_root": str(target), "repo_path": str(target),
               "target_fingerprint": "a" * 64, "repository_set_sha256": "b" * 64,
               "repositories": repositories, "intrusion_budget": resolved_intrusion_budget("quick"), "paths": {}}
    context["attempt_contexts"][context["attempt_id"]]["repositories"] = repositories
    context_path = base / "context.json"
    write(context_path, context)
    write(scan / "run-manifest.json", {**context, "status": "incomplete", "phases": {"intrusion": "running"}})
    records = [{"id": "E-000000000001", "source_kind": "sast", "source_id": "LOCAL-1",
                "artifact_ref": "sast/deepdive/H001.json", "disposition": "unresolved",
                "summary": "Complete ownership trace", "files": ["gateway/handler.py", "service/implementation.py", "shared/dto.py"],
                "source_anchors": [], "subsystems": ["ownership"], "anchor_limitations": []}]
    records[0]["contributors"] = [source_result["provenance"]]
    records[0].update(objective_binding(registry))
    for i in range(683):
        records.append({"id": f"E-{i + 100:012X}", "source_kind": "sca" if i < 269 else "secret",
                        "source_id": str(i), "artifact_ref": "tool-collection/observations.json",
                        "disposition": "unresolved", "summary": "Redacted scanner observation",
                        "files": ["gateway/package-lock.json"], "source_anchors": [], "subsystems": [], "anchor_limitations": []})
        records[-1]["contributors"] = []
    write(scan / "tool-collection/observations.json", {"observations": 683})
    index = {"schema_version": "2.0", "run_id": "acceptance", **registry, "records": records, "primitives": [], "coverage_gaps": [], "warnings": []}
    write(scan / "campaign-planning/evidence-index.json", index)
    env = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path)}
    env = activate_publisher(scan, context, "campaign-planning", env)
    def command(script, *arguments):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / script), str(scan), *arguments], env=env, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(f"{script}: {result.stderr}")
        return result
    command("build-campaign-plan.py", "--context", str(context_path), "--prepare-discovery")
    discovery_path = scan / "campaign-planning/discovery.json"
    discovery = json.loads(discovery_path.read_text())
    owner = "campaign-planning/discovery.json"
    worker_question = {**registry["investigation_questions"][0],
        "id": stable_id("Q-", owner, "worker-scope"), "owner": owner, "local_key": "worker-scope",
        "security_question": "Does the worker preserve initiating tenant ownership?",
        "route": "stored record reference to the worker", "proof_obligation": "Worker-side ownership check",
        "novelty_reason": "The separate downstream consumer may narrow the producer's granted capability.",
        "evidence_refs": ["service/worker.py:1-3", "sast/deepdive/H001.json"]}
    discovery["investigation_questions"].append(worker_question)
    discovery["question_inputs"].append({"objective_id": worker_question["objective_id"], "question_id": worker_question["id"],
        "evidence_ids": ["E-000000000001"], "primitive_ids": [], "relationship_ids": [], "lane": "gap_driven",
        "priority_band": "proof_obligation", "reason": "Resolve the separate consumer authority using the shared source trace."})
    write(discovery_path, discovery)
    command("build-campaign-plan.py", "--context", str(context_path))
    plan_path = scan / "campaign-planning/campaign-plan.json"
    plan = json.loads(plan_path.read_text())
    source_campaign = next(c for c in plan["campaigns"] if c["question_id"] == cell["question_id"])
    initial_hash = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    env = activate_publisher(scan, context, "intrusion", env)
    wave = build_wave(scan, target, context)
    evidence = ["sast/deepdive/H001.json"]
    capability = {"actor": "tenant user", "operation": "read", "resource_scope": "record reference",
                  "authority": "application storage identity", "conditions": ["Authenticated tenant user"],
                  "evidence_status": "source_established", "provenance": evidence,
                  "restrictions": ["Downstream ownership enforcement remains untested"]}
    primitive = {"type": "access", "trust": "context_only", "prerequisites": ["Authenticated tenant user"],
                 "capability_gained": "Read a supplied stored reference", "boundary": "record ownership",
                 "reachable_assets": ["record"], "conditions": [], "evidence_refs": evidence, "capability": capability}
    primitive["id"] = primitive_id(primitive)
    owner_a = next(c["id"] for c in plan["campaigns"] if c["id"] != source_campaign["id"])
    owner_b = source_campaign["id"]
    def result(owner, snapshot, outcome="established", updates=()):
        provenance = {"actor": "vulnops-intrusion-campaign", "selector": "test/red:high", "artifact_ref": f"intrusion/results/{owner}.json"}
        for item in updates:
            item["contributors"] = contributor_union([provenance], records[0]["contributors"])
        return {"schema_version": "2.0", "provenance": provenance, "campaign_id": owner, "wave": snapshot["wave"], "input_snapshot": reference(scan, snapshot),
                "assessment_context": {"attempt_id": context["attempt_id"]},
                **{key: snapshot["assignments"][owner][key] for key in ("objective_id", "question_id")},
                "status": "closed", "conclusion": "Source behavior established; composition remains separate.", "evidence_refs": evidence,
                "graph_query_receipts": [], "graph_evidence_refs": [], "graph_answers": [], "graph_limitations": ["Source-only investigation."],
                "primitive_updates": list(updates), "candidates": [],
                "resolution": {"outcome": outcome, "reason": "Source supports the scoped conclusion.", "next_action": "Inspect worker ownership.", "evidence_refs": evidence, "missing_fact": ""},
                "composition": {"outcome": "deferred", "reason": "Consumer ownership is the remaining obligation.", "evidence_refs": evidence, "primitive_ids": [p["id"] for p in updates]}}
    for owner in wave["assignments"]:
        row = result(owner, wave, updates=[primitive] if owner == owner_a else [])
        if owner == owner_b:
            row["composition"]["outcome"] = "continuation"
        write(scan / f"intrusion/results/{owner}.json", row)
    proposal = {"parent_campaign": owner_b, "triggering_evidence": [f"intrusion/results/{owner_a}.json"],
                "objective_id": source_campaign["objective_id"], "question_id": source_campaign["question_id"],
                "attack_objectives": [], "investigation_questions": [],
                "changed_hypothesis": "A stored reference may be consumed under worker authority.",
                "next_question": "Does the worker bind the reference owner to the initiating tenant?",
                "evidence_delta": [f"intrusion/results/{owner_a}.json"], "alternative_path": "", "resource_allocation": 1}
    next_wave = build_wave(scan, target, context, list(wave["assignments"]), [proposal])
    owner = next(iter(next_wave["assignments"]))
    closed = result(owner, next_wave, "contradicted")
    if primitive["id"] not in available_primitives(scan, context, index, closed):
        raise AssertionError("Validated capability was not available to continuation")
    closed["status"] = "rejected"
    closed["conclusion"] = "service/worker.py:2 rejects a reference owned by another tenant."
    closed["resolution"].update(reason=closed["conclusion"], next_action="A different route must demonstrate that it bypasses this ownership check.")
    closed["composition"].update(outcome="resolved", reason=closed["conclusion"], primitive_ids=[primitive["id"]])
    write(scan / f"intrusion/results/{owner}.json", closed)
    build_wave(scan, target, context, [owner])
    command("finalize-intrusion.py")
    env = activate_publisher(scan, context, "synthesis", env)
    command("empty-synthesis.py")
    env = activate_publisher(scan, context, "final-verification", env)
    verified = subprocess.run([sys.executable, str(ROOT / "scripts/finalize-verification.py"), str(target), str(scan)], env=env, capture_output=True, text=True)
    if verified.returncode:
        raise AssertionError(verified.stderr)
    env = activate_publisher(scan, context, "report", env)
    command("render-report.py")
    report = json.loads((scan / "report/security-report.json").read_text())
    assert hashlib.sha256(plan_path.read_bytes()).hexdigest() == initial_hash
    assert len(plan["scanner_accounting"]) == 683
    assert report["summary"]["confirmed"] == 0
    terminal = next(row for row in report["investigation_accounting"]["resolved_investigations"]
                    if row.get("id") == owner)
    source_resolution = next(row for row in report["investigation_accounting"]["resolved_investigations"]
                             if row.get("id") == source_campaign["id"])
    return {"source_repositories": len(report["repositories"]),
            "source_question_resolution": source_resolution["resolution"]["outcome"],
            "scanner_observations": len(plan["scanner_accounting"]),
            "capability_reused": terminal["composition"]["primitive_ids"][0],
            "continuation": terminal["id"], "terminal_resolution": terminal["resolution"]["outcome"],
            "closure": terminal["resolution"]["reason"], "confirmed_findings": report["summary"]["confirmed"],
            "assessment": report["outcome_assessment"]["status"],
            "initial_plan_unchanged": hashlib.sha256(plan_path.read_bytes()).hexdigest() == initial_hash}


class InvestigationAcceptanceTests(unittest.TestCase):
    def test_scanner_heavy_source_flow_drives_attributable_closed_continuation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            result = scenario(base)
            scan = base / "scan"
            report = json.loads((scan / "report/security-report.json").read_text())
            plan = json.loads((scan / "campaign-planning/campaign-plan.json").read_text())
            intrusion = json.loads((scan / "intrusion/intrusion-results.json").read_text())
            continuation = next(row for row in intrusion["results"] if row["campaign_id"] == result["continuation"])
            self.assertEqual(continuation["status"], "rejected")
            terminal = next(row for row in report["investigation_accounting"]["resolved_investigations"]
                            if row["id"] == continuation["campaign_id"])
            self.assertEqual(terminal["resolution"]["outcome"], "contradicted")
            self.assertEqual(terminal["resolution"], continuation["resolution"])
            self.assertEqual(terminal["composition"]["outcome"], "resolved")
            self.assertEqual(terminal["composition"]["primitive_ids"], [result["capability_reused"]])
            self.assertEqual(terminal["evidence_ref"], "intrusion/intrusion-results.json")
            self.assertEqual({row["path"] for row in report["repositories"]}, {"gateway", "service", "shared"})
            self.assertEqual(intrusion["attack_objectives"], plan["attack_objectives"])
            self.assertEqual(intrusion["investigation_questions"], plan["investigation_questions"])
            assessment = next(row for row in report["objective_assessments"]
                              if row["objective_id"] == continuation["objective_id"])
            self.assertEqual(assessment["status"], "unresolved")
            self.assertTrue(assessment["remaining_obligations"])
            outcome = next(row for row in assessment["question_outcomes"]
                           if row["owner_ref"] == f"intrusion/intrusion-results.json:{continuation['campaign_id']}")
            self.assertEqual(outcome["question_id"], continuation["question_id"])
            self.assertEqual(outcome["outcome"], "contradicted")
            self.assertEqual(outcome["evidence_refs"], continuation["resolution"]["evidence_refs"])
            capability = next(primitive for row in intrusion["results"] for primitive in row["primitive_updates"]
                              if primitive["id"] == result["capability_reused"])
            producer = next(row for row in intrusion["results"]
                            if any(p["id"] == capability["id"] for p in row["primitive_updates"]))
            self.assertEqual({row["artifact_ref"] for row in capability["contributors"]},
                             {"sast/deepdive/H001.json", producer["provenance"]["artifact_ref"]})
            self.assertEqual(continuation["provenance"]["actor"], "vulnops-intrusion-campaign")
            self.assertEqual(continuation["provenance"]["artifact_ref"],
                             f"intrusion/results/{continuation['campaign_id']}.json")
            self.assertEqual(len(plan["scanner_accounting"]), 683)
            self.assertTrue(all(row["status"] == "deferred" and not row["campaign_ids"]
                                for row in plan["scanner_accounting"]))
            visible = report["investigation_accounting"]["unscheduled_work"]
            self.assertEqual(len(visible), 200)
            scanner_ids = {row["evidence_id"] for row in plan["scanner_accounting"]}
            self.assertTrue(all(row["evidence_id"] in scanner_ids and row["status"] == "deferred"
                                for row in visible))
            self.assertEqual(report["summary"]["confirmed"], 0)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["outcome_assessment"]["status"], "substantially_unresolved")
            self.assertTrue(result["initial_plan_unchanged"])


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        print(json.dumps(scenario(Path(directory)), indent=2))
