"""Synthetic source-only checks for A08–A18, A21, A24 and A25."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from intrusion_contract import (OBLIGATIONS, available_primitives, build_wave, composition_resolved,
    primitive_id, publish, read_snapshot, reference, validate_intrusion, validate_result, validate_transitions)
from codegraph_contract import register_followup, _planned_question
from objective_contract import stable_id
from test_run_lifecycle import activate_publisher


class IntrusionInvestigationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.scan = Path(temporary.name).resolve()
        self.target = self.scan / "source"
        self.target.mkdir()
        (self.target / "producer.py").write_text("stored_reference = request.reference\nworker.consume(stored_reference)\n")
        self.context = {"run_id": "run", "attempt_id": "attempt-one", "source_root": str(self.target), "scan_base": str(self.scan), "intrusion_budget": {"continuation_rounds": 2, "continuation_tasks": 4, "graph_followups": 2}}
        self.context["repositories"] = [{"path": "."}]
        self.context["model_routing"] = {"agents": {"vulnops-intrusion-campaign": "test/red:high"}}
        owner = "campaign-planning/discovery.json"
        self.objective = {
            "id": stable_id("OBJ-", owner, "consume-other-tenant-reference"), "owner": owner,
            "local_key": "consume-other-tenant-reference", "starting_actor": "tenant user",
            "controlled_material": "stored reference", "resource_scope": "another tenant's record",
            "desired_effect": "Privileged worker consumes another tenant's reference",
            "success_condition": "A user-supplied reference reaches worker consumption without an ownership check",
            "evidence_refs": ["producer.py:1-2"],
        }
        self.questions = [{
            "id": stable_id("Q-", owner, key), "owner": owner, "local_key": key,
            "objective_id": self.objective["id"], "security_question": question,
            "route": route, "proof_obligation": question, "novelty_reason": reason,
            "evidence_refs": ["producer.py:1-2"],
        } for key, question, route, reason in (
            ("producer-control", "Can a tenant store the reference?", "request to storage", "Establish attacker input control"),
            ("worker-scope", "Does consumption enforce tenant ownership?", "storage to worker", "Establish consumer resource scope"),
        )]
        self.plan = {"budget": {"max_campaigns": 4}, "attack_objectives": [self.objective],
                     "investigation_questions": self.questions,
                     "campaigns": [{"id": f"CAM-{index:03d}", "graph_questions": [],
                                    "objective_id": self.objective["id"], "question_id": question["id"]}
                                   for index, question in enumerate(self.questions, 1)]}
        publish(self.scan / owner, {"attack_objectives": [self.objective], "investigation_questions": self.questions})
        publish(self.scan / "campaign-planning/campaign-plan.json", self.plan)
        publish(self.scan / "run-manifest.json", {"run_id": "run", "attempt_id": "attempt-one", "status": "incomplete", "phases": {"intrusion": "running"}})
        self.index = {"primitives": [], "records": [{"id": "E-1", "description": "inspected source"}]}
        publish(self.scan / "campaign-planning/evidence-index.json", self.index)
        publish(self.scan / "source-evidence.json", {"observation": "source inspected"})
        self.evidence = ["source-evidence.json"]
        self.wave = build_wave(self.scan, self.target, self.context)

    def resolution(self, outcome="established"):
        return {"outcome": outcome, "reason": "Inspected source proves the scoped behavior", "next_action": "Inspect next consumer", "evidence_refs": self.evidence, "missing_fact": ""}

    def primitive(self):
        primitive = {"type": "access", "trust": "context_only", "prerequisites": [], "capability_gained": "write reference", "boundary": "tenant storage", "reachable_assets": ["references"], "conditions": [], "evidence_refs": self.evidence, "capability": {"actor": "tenant user", "operation": "influence", "resource_scope": "own stored reference", "authority": "user identity", "conditions": [], "evidence_status": "source_established", "provenance": self.evidence, "restrictions": ["own tenant only"]}}
        primitive["id"] = primitive_id(primitive)
        return primitive

    def result(self, owner, wave=None, updates=()):
        wave = wave or self.wave
        provenance = {"actor": "vulnops-intrusion-campaign", "selector": "test/red:high", "artifact_ref": f"intrusion/results/{owner}.json"}
        for item in updates:
            item["contributors"] = [provenance]
        assignment = wave["assignments"][owner]
        return {"schema_version": "2.0", "assessment_context": {"attempt_id": self.context["attempt_id"]},
                "provenance": provenance, "campaign_id": owner,
                "objective_id": assignment["objective_id"], "question_id": assignment["question_id"],
                "wave": wave["wave"], "input_snapshot": reference(self.scan, wave), "status": "closed", "conclusion": "Source-established local behavior retained", "evidence_refs": self.evidence, "graph_query_receipts": [], "graph_evidence_refs": [], "graph_answers": [], "graph_limitations": [], "primitive_updates": list(updates), "candidates": [], "resolution": self.resolution(), "composition": {"outcome": "deferred", "reason": "Consumer proof requires another bounded wave", "evidence_refs": self.evidence, "primitive_ids": [p["id"] for p in updates]}}

    def proposal(self):
        return {"parent_campaign": "CAM-002", "objective_id": self.objective["id"],
                "question_id": self.questions[1]["id"], "attack_objectives": [], "investigation_questions": [],
                "triggering_evidence": ["intrusion/results/CAM-001.json"], "changed_hypothesis": "Third component consumes the stored reference", "next_question": "Does the worker enforce initiating tenant ownership?", "evidence_delta": ["intrusion/results/CAM-001.json"], "alternative_path": "", "resource_allocation": 1}

    def registered_proposal(self, changed_goal=False):
        proposal = self.proposal()
        owner = "intrusion/waves/001.json"
        refs = ["producer.py:1-2", *proposal["triggering_evidence"]]
        if changed_goal:
            objective = {**self.objective, "owner": owner, "local_key": "worker-authority",
                         "id": stable_id("OBJ-", owner, "worker-authority"),
                         "parent_objective_id": self.objective["id"],
                         "desired_effect": "Influence subsequent worker actions",
                         "success_condition": "The stored reference grants control over a subsequent privileged action",
                         "evidence_refs": refs}
            proposal["attack_objectives"] = [objective]
            proposal["objective_id"] = objective["id"]
        question = {**self.questions[1], "owner": owner, "local_key": "alternate-consumer",
                    "id": stable_id("Q-", owner, "alternate-consumer"),
                    "objective_id": proposal["objective_id"],
                    "security_question": "Does the alternate consumer preserve initiating authority?",
                    "route": "stored reference to alternate consumer",
                    "proof_obligation": "Trace initiating authority into the alternate consumer",
                    "novelty_reason": "The prior route was scoped to the direct consumer",
                    "evidence_refs": refs}
        proposal["investigation_questions"] = [question]
        proposal["question_id"] = question["id"]
        proposal["next_question"] = question["security_question"]
        proposal["alternative_path"] = question["route"]
        return proposal

    def aggregate(self, wave):
        results = []
        for record in wave["results"].values():
            result = json.loads((self.scan / record["ref"]).read_text())
            if record.get("assessment_context"):
                result["assessment_context"] = record["assessment_context"]
                result["candidates"] = [{**candidate, "assessment_context": record["assessment_context"]}
                                        for candidate in result["candidates"]]
            results.append(result)
        return {"schema_version": "2.0", "run_id": "run",
                "attack_objectives": wave["attack_objectives"],
                "investigation_questions": wave["investigation_questions"],
                "allocation_deferrals": wave.get("allocation_deferrals", []), "results": results}

    def test_alternate_route_preserves_objective_and_immutable_question_history(self):
        proposal = self.registered_proposal()
        wave = self.complete_initial([proposal])
        assignment = next(iter(wave["assignments"].values()))
        self.assertEqual(assignment["objective_id"], self.objective["id"])
        self.assertNotIn(assignment["question_id"], {q["id"] for q in self.questions})
        self.assertEqual(wave["attack_objectives"], [self.objective])
        self.assertEqual(wave["investigation_questions"][:2], self.questions)
        self.assertEqual(read_snapshot(self.scan, self.context, reference(self.scan, wave)), wave)

    def test_changed_goal_registers_parent_and_source_attribution_before_dispatch(self):
        before = (self.scan / "campaign-planning/campaign-plan.json").read_bytes()
        proposal = self.registered_proposal(changed_goal=True)
        wave = self.complete_initial([proposal])
        assignment = next(iter(wave["assignments"].values()))
        self.assertNotEqual(assignment["objective_id"], self.objective["id"])
        self.assertEqual(wave["attack_objectives"][1], proposal["attack_objectives"][0])
        self.assertEqual(wave["attack_objectives"][1]["parent_objective_id"], self.objective["id"])
        result = self.result(assignment["id"], wave)
        validate_result(self.scan, self.target, self.context, self.index, result)
        self.assertEqual(before, (self.scan / "campaign-planning/campaign-plan.json").read_bytes())
        result["objective_id"] = self.objective["id"]
        with self.assertRaisesRegex(ValueError, "assigned objective/question"):
            validate_result(self.scan, self.target, self.context, self.index, result)
        result["objective_id"] = assignment["objective_id"]
        publish(self.scan / f"intrusion/results/{assignment['id']}.json", result)
        continuation = {**proposal, "attack_objectives": [], "investigation_questions": [],
                        "triggering_evidence": [f"intrusion/results/{assignment['id']}.json"],
                        "evidence_delta": [f"intrusion/results/{assignment['id']}.json"]}
        next_wave = build_wave(self.scan, self.target, self.context, [assignment["id"]], [continuation])
        self.assertEqual(next_wave["attack_objectives"], wave["attack_objectives"])
        owner = next(iter(next_wave["assignments"]))
        unresolved = self.result(owner, next_wave)
        unresolved["resolution"] = self.resolution("locally_unresolved")
        publish(self.scan / f"intrusion/results/{owner}.json", unresolved)
        closed = build_wave(self.scan, self.target, self.context, [owner])
        wrapper = self.aggregate(closed)
        validate_intrusion(self.scan, self.target, self.context, self.index, wrapper)
        self.assertEqual(wrapper["attack_objectives"], wave["attack_objectives"])
        self.assertEqual(before, (self.scan / "campaign-planning/campaign-plan.json").read_bytes())

    def test_new_goal_requires_parent_source_and_validated_trigger(self):
        for defect in ("parent", "source", "trigger", "owner"):
            with self.subTest(defect=defect):
                proposal = self.registered_proposal(changed_goal=True)
                objective = proposal["attack_objectives"][0]
                if defect == "parent":
                    objective.pop("parent_objective_id")
                elif defect == "source":
                    objective["evidence_refs"] = proposal["triggering_evidence"]
                elif defect == "trigger":
                    objective["evidence_refs"] = ["producer.py:1-2"]
                else:
                    objective["owner"] = "intrusion/waves/002.json"
                    objective["id"] = stable_id("OBJ-", objective["owner"], objective["local_key"])
                    proposal["objective_id"] = objective["id"]
                    proposal["investigation_questions"][0]["objective_id"] = objective["id"]
                with self.assertRaises(ValueError):
                    self.complete_initial([proposal])
        self.assertFalse((self.scan / "intrusion/waves/001.json").exists())

    def test_inherited_definitions_cannot_be_overwritten_or_reregistered(self):
        for changed in (False, True):
            proposal = self.proposal()
            inherited = copy.deepcopy(self.objective)
            if changed:
                inherited["desired_effect"] = "A different unauthorized effect"
            proposal["attack_objectives"] = [inherited]
            with self.assertRaises(ValueError):
                self.complete_initial([proposal])
        wave = self.complete_initial([self.proposal()])
        forged = copy.deepcopy(wave)
        forged["attack_objectives"][0]["success_condition"] = "Worker bookkeeping is complete"
        (self.scan / "intrusion/waves/001.json").write_text(json.dumps(forged))
        with self.assertRaisesRegex(ValueError, "inherited objective/question"):
            read_snapshot(self.scan, self.context, reference(self.scan, forged))

    def test_unpublished_peer_evidence_cannot_authorize_a_goal(self):
        peer = self.result("CAM-002")
        publish(self.scan / "intrusion/results/CAM-002.json", peer)
        result = self.result("CAM-001")
        result["evidence_refs"] = ["intrusion/results/CAM-002.json"]
        with self.assertRaisesRegex(ValueError, "unvalidated peer"):
            validate_result(self.scan, self.target, self.context, self.index, result)
        proposal = self.registered_proposal(changed_goal=True)
        publish(self.scan / "intrusion/results/CAM-999.json", {"observation": "unpublished"})
        proposal["attack_objectives"][0]["evidence_refs"].append("intrusion/results/CAM-999.json")
        with self.assertRaisesRegex(ValueError, "unvalidated peer"):
            self.complete_initial([proposal])

    def test_duplicate_question_owners_cannot_consume_the_reserve(self):
        proposal = self.proposal()
        duplicate = {**proposal, "changed_hypothesis": "Same work under a different owner",
                     "next_question": "Rephrased consumer ownership question", "alternative_path": "same consumer"}
        with self.assertRaisesRegex(ValueError, "duplicate active ownership"):
            self.complete_initial([proposal, duplicate])

    def test_exhausted_reserve_retains_budget_deferral_not_objective_success(self):
        wave = self.complete_initial([self.proposal()])
        owner = next(iter(wave["assignments"]))
        publish(self.scan / f"intrusion/results/{owner}.json", self.result(owner, wave))
        proposal = {**self.proposal(), "evidence_delta": [f"intrusion/results/{owner}.json"]}
        wave = build_wave(self.scan, self.target, self.context, [owner], [proposal])
        owner = next(iter(wave["assignments"]))
        deferred = self.result(owner, wave)
        deferred["resolution"] = self.resolution("budget_deferred")
        publish(self.scan / f"intrusion/results/{owner}.json", deferred)
        proposal = {**self.proposal(), "evidence_delta": [f"intrusion/results/{owner}.json"]}
        closed = build_wave(self.scan, self.target, self.context, [owner], [proposal])
        self.assertEqual(closed["assignments"], {})
        self.assertEqual(closed["allocation_deferrals"][0]["outcome"], "budget_deferred")
        wrapper = self.aggregate(closed)
        validate_intrusion(self.scan, self.target, self.context, self.index, wrapper)
        self.assertEqual(wrapper["results"][-1]["resolution"]["outcome"], "budget_deferred")
        self.assertNotIn("objective_assessments", wrapper)

    def test_real_builder_finalizer_keep_contradicted_and_unresolved_routes(self):
        root = Path(__file__).resolve().parents[1]
        context_path = self.scan / "context.json"
        publish(context_path, self.context)
        proposal = self.registered_proposal()
        proposal_path = self.scan / "proposals.json"
        publish(proposal_path, [proposal])
        before = (self.scan / "campaign-planning/campaign-plan.json").read_bytes()
        for owner in self.wave["assignments"]:
            result = self.result(owner)
            result["status"] = "rejected"
            result["resolution"] = self.resolution("contradicted")
            publish(self.scan / f"intrusion/results/{owner}.json", result)
        command = [sys.executable, str(root / "scripts/build-intrusion-wave.py"), str(self.scan),
                   "--context", str(context_path)]
        built = subprocess.run([*command, "--results", *self.wave["assignments"],
                                "--continuations", str(proposal_path)], capture_output=True, text=True)
        self.assertEqual(built.returncode, 0, built.stderr)
        dispatched = json.loads(built.stdout)
        wave = read_snapshot(self.scan, self.context, dispatched["input_snapshot"])
        owner = next(iter(wave["assignments"]))
        result = self.result(owner, wave)
        result["resolution"] = self.resolution("locally_unresolved")
        publish(self.scan / f"intrusion/results/{owner}.json", result)
        closed = subprocess.run([*command, "--results", owner], capture_output=True, text=True)
        self.assertEqual(closed.returncode, 0, closed.stderr)
        environment = activate_publisher(self.scan, self.context, "intrusion",
            {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path)})
        finalized = subprocess.run([sys.executable, str(root / "scripts/finalize-intrusion.py"), str(self.scan)],
                                   env=environment,
                                   capture_output=True, text=True)
        self.assertEqual(finalized.returncode, 0, finalized.stderr)
        wrapper = json.loads((self.scan / "intrusion/intrusion-results.json").read_text())
        validate_intrusion(self.scan, self.target, self.context, self.index, wrapper)
        self.assertEqual({r["resolution"]["outcome"] for r in wrapper["results"]}, {"contradicted", "locally_unresolved"})
        self.assertEqual(wrapper["attack_objectives"], [self.objective])
        self.assertEqual(wrapper["investigation_questions"], [*self.questions, *proposal["investigation_questions"]])
        self.assertNotIn("objective_assessments", wrapper)
        self.assertEqual(before, (self.scan / "campaign-planning/campaign-plan.json").read_bytes())

    def test_open_wave_and_changed_aggregate_cannot_claim_terminal_closure(self):
        with self.assertRaisesRegex(ValueError, "undisposed active assignments"):
            validate_intrusion(self.scan, self.target, self.context, self.index, self.aggregate(self.wave))
        closed = self.complete_initial()
        wrapper = self.aggregate(closed)
        wrapper["attack_objectives"] = []
        with self.assertRaisesRegex(ValueError, "immutable objective/question registry"):
            validate_intrusion(self.scan, self.target, self.context, self.index, wrapper)

    def test_other_goal_cannot_dispose_actionable_composition(self):
        result = self.result("CAM-002")
        result["composition"]["outcome"] = "continuation"
        other = copy.deepcopy(result)
        other.update(campaign_id="CAM-002-C123456789ABC", wave=1, objective_id="OBJ-123456789ABC")
        other["composition"]["outcome"] = "deferred"
        wrapper = {"attack_objectives": [self.objective], "results": [result, other]}
        self.assertFalse(composition_resolved(wrapper))
        child = {**self.objective, "id": other["objective_id"], "parent_objective_id": self.objective["id"]}
        wrapper["attack_objectives"].append(child)
        self.assertTrue(composition_resolved(wrapper))

    def complete_initial(self, proposals=()):
        a = self.result("CAM-001", updates=[self.primitive()])
        b = self.result("CAM-002")
        for result in (a, b):
            publish(self.scan / f"intrusion/results/{result['campaign_id']}.json", result)
        return build_wave(self.scan, self.target, self.context, ["CAM-001", "CAM-002"], proposals)

    def test_reference_aliases_and_local_gap_preserve_other_campaigns(self):
        healthy = self.result("CAM-001")
        healthy["evidence_refs"] = ["campaign-planning/evidence-index.json#E-1"]
        validate_result(self.scan, self.target, self.context, self.index, healthy)
        limited = self.result("CAM-002")
        limited["evidence_refs"] = ["campaign-planning/evidence-index.json#missing"]
        with self.assertRaises(ValueError):
            validate_result(self.scan, self.target, self.context, self.index, limited)
        limited["non_promoted"] = [{
            "id": "CAM-002", "input_refs": ["intrusion/results/CAM-002.json:CAM-002"],
            "disposition": "evidence_limited", "reason": "Referenced observation cannot be resolved",
            "risk_context": "Tenant-controlled reference consumed by a privileged worker",
            "missing_fact": "Source evidence establishing the consumer authority",
            "next_action": "Inspect consumer authorization from the cited producer",
            "review": {"actor": "vulnops-intrusion-campaign", "selector": "test/red:high",
                       "action": "Inspect the producer handoff", "result": "Consumer authority remains unresolved",
                       "evidence_refs": ["producer.py:1,2"]}, "deferral": None,
        }]
        validate_result(self.scan, self.target, self.context, self.index, limited)
        from intrusion_contract import result_evidence_diagnostics
        self.assertEqual(result_evidence_diagnostics(self.scan, self.target, self.context, healthy), [])
        self.assertEqual(result_evidence_diagnostics(self.scan, self.target, self.context, limited)[0]["code"], "missing_record")
        limited["evidence_refs"] = ["../escape.json#missing"]
        from evidence_refs import EvidenceIssue
        with self.assertRaises(ValueError) as error:
            validate_result(self.scan, self.target, self.context, self.index, limited)
        self.assertNotIsInstance(error.exception, EvidenceIssue)

    def test_primitive_provenance_cannot_drop_owner_or_change_assigned_selector(self):
        result = self.result("CAM-001", updates=[self.primitive()])
        result["primitive_updates"][0]["contributors"] = []
        with self.assertRaisesRegex(ValueError, "contributors"):
            validate_result(self.scan, self.target, self.context, self.index, result)
        result = self.result("CAM-001")
        result["provenance"]["selector"] = "test/red:low"
        with self.assertRaisesRegex(ValueError, "route"):
            validate_result(self.scan, self.target, self.context, self.index, result)

    def test_external_blocker_cannot_close_as_ordinary_work(self):
        result = self.result("CAM-001")
        result["resolution"] = self.resolution("externally_blocked")
        result["resolution"]["missing_fact"] = "Deployment tenant binding is unavailable"
        with self.assertRaisesRegex(ValueError, "lifecycle disagrees"):
            validate_result(self.scan, self.target, self.context, self.index, result)
        result["status"] = "needs_environment"
        validate_result(self.scan, self.target, self.context, self.index, result)

    def test_prior_wave_reuse_requires_validated_snapshot(self):
        primitive = self.primitive()
        b = self.result("CAM-002")
        self.assertNotIn(primitive["id"], available_primitives(self.scan, self.context, self.index, b))
        undisposed = self.result("CAM-001", updates=[primitive])
        undisposed["composition"]["primitive_ids"] = []
        with self.assertRaisesRegex(ValueError, "account for every"):
            validate_result(self.scan, self.target, self.context, self.index, undisposed)
        undisposed["composition"].update(outcome="continuation", primitive_ids=[primitive["id"]])
        validate_result(self.scan, self.target, self.context, self.index, undisposed)
        self.assertFalse(composition_resolved({"results": [undisposed]}))
        before = (self.scan / "campaign-planning/campaign-plan.json").read_bytes()
        wave = self.complete_initial([self.proposal()])
        owner = next(iter(wave["assignments"]))
        result = self.result(owner, wave)
        self.assertIn(primitive["id"], available_primitives(self.scan, self.context, self.index, result))
        self.assertEqual(before, (self.scan / "campaign-planning/campaign-plan.json").read_bytes())
        result["status"] = "candidate"
        result["candidates"] = [{
            "id": "IC-AAAAAAAAAAAA", "finding_kind": "code", "title": "Consumer lacks tenant check",
            "objective_id": result["objective_id"], "question_id": result["question_id"],
            "attacker": {"perspective": "tenant user", "starting_access": "own reference", "boundary_crossed": "worker identity"},
            "root_causes": [{"file": "producer.py", "line": 2, "scope": "worker", "mechanism": "consumer accepts reference"}],
            "trace": [{"kind": "entrypoint", "file": "producer.py", "line": 1, "scope": "request", "description": "user influence"},
                      {"kind": "sink", "file": "producer.py", "line": 2, "scope": "worker", "description": "privileged consumption"}],
            "conditions": [], "impact": "Out-of-scope resource consumption",
            "evidence_refs": [*self.evidence, "intrusion/results/CAM-001.json"],
            "primitive_ids": [primitive["id"]], "validation_level": "source_verified", "transitions": []
        }]
        from model_identity import contributor_union
        result["candidates"][0]["contributors"] = contributor_union([result["provenance"]], wave["primitives"][0]["contributors"])
        premature = copy.deepcopy(result)
        premature.update(campaign_id="CAM-002", wave=0, input_snapshot=reference(self.scan, self.wave))
        premature["provenance"] = self.result("CAM-002")["provenance"]
        with self.assertRaisesRegex(ValueError, "unvalidated peer"):
            validate_result(self.scan, self.target, self.context, self.index, premature)
        publish(self.scan / f"intrusion/results/{owner}.json", result)
        closed = build_wave(self.scan, self.target, self.context, [owner])
        wrapper = self.aggregate(closed)
        validate_intrusion(self.scan, self.target, self.context, self.index, wrapper)
        self.assertTrue(composition_resolved(wrapper))

    def test_continuation_validation_bounds_result_reads_and_rechecks_integrity(self):
        wave = self.complete_initial([self.registered_proposal()])
        owner = next(iter(wave["assignments"]))
        publish(self.scan / f"intrusion/results/{owner}.json", self.result(owner, wave))
        closed = build_wave(self.scan, self.target, self.context, [owner])
        wrapper = self.aggregate(closed)
        read_bytes = Path.read_bytes
        result_reads = 0

        def bounded_read(path):
            nonlocal result_reads
            if path.parent == self.scan / "intrusion/results":
                result_reads += 1
                if result_reads > 2 * len(wrapper["results"]):
                    self.fail("continuation ancestry causes repeated full-result integrity reads")
            return read_bytes(path)

        with patch.object(Path, "read_bytes", bounded_read):
            self.assertEqual(validate_intrusion(
                self.scan, self.target, self.context, self.index, wrapper), closed)
        changed_wrapper = copy.deepcopy(wrapper)
        changed_wrapper["results"][0]["conclusion"] = "Changed aggregate"
        with self.assertRaisesRegex(ValueError, "aggregate differs"):
            validate_intrusion(self.scan, self.target, self.context, self.index, changed_wrapper)
        path = self.scan / "intrusion/results/CAM-001.json"
        result = json.loads(path.read_text())
        result["conclusion"] = "Changed upstream publication after successful validation"
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, "changed after wave publication"):
            validate_intrusion(self.scan, self.target, self.context, self.index, wrapper)

    def test_forged_primitive_fails_without_source_snapshot_gate(self):
        forged = copy.deepcopy(self.wave)
        forged["primitives"] = [self.primitive()]
        path = self.scan / "intrusion/waves/000.json"
        path.write_text(json.dumps(forged))
        with self.assertRaisesRegex(ValueError, "initial wave"):
            read_snapshot(self.scan, self.context, reference(self.scan, forged))
        path.write_text(json.dumps(self.wave))
        context = {**self.context, "target_fingerprint": "other-source", "repository_set_sha256": "different"}
        self.assertEqual(read_snapshot(self.scan, context, reference(self.scan, self.wave)), self.wave)

    def test_snapshot_conflict_partial_input_and_retry(self):
        with self.assertRaisesRegex(ValueError, "every assigned"):
            build_wave(self.scan, self.target, self.context, ["CAM-001"])
        wave = self.complete_initial([self.proposal()])
        retry = build_wave(self.scan, self.target, self.context, ["CAM-001", "CAM-002"], [self.proposal()])
        self.assertEqual(wave, retry)
        with self.assertRaisesRegex(ValueError, "immutable"):
            publish(self.scan / "intrusion/waves/001.json", {"partial": True})
        (self.scan / "intrusion/waves/.wave-interrupted").write_text("{")
        self.assertEqual(read_snapshot(self.scan, self.context, reference(self.scan, wave)), wave)

    def test_repeated_continuation_and_unrelated_delta_rejected(self):
        wave = self.complete_initial([self.proposal()])
        owner = next(iter(wave["assignments"]))
        publish(self.scan / f"intrusion/results/{owner}.json", self.result(owner, wave))
        with self.assertRaisesRegex(ValueError, "no evidence delta"):
            build_wave(self.scan, self.target, self.context, [owner], [self.proposal()])
        publish(self.scan / "unrelated.json", {})
        proposal = self.proposal()
        proposal["evidence_delta"] = ["unrelated.json"]
        with self.assertRaisesRegex(ValueError, "not attributable"):
            build_wave(self.scan, self.target, self.context, [owner], [proposal])

    def test_semantic_mapping_not_word_equality_and_conditions(self):
        producer, consumer = self.primitive(), self.primitive()
        producer["capability"].update(operation="emit signed message", authority="tenant publisher")
        consumer["capability"].update(operation="consume scoped credential", authority="worker service")
        primitives = {"producer": producer, "consumer": consumer}
        proof = {"outcome": "established", "reason": "Source maps reference to consumer input with tenant-preserving routing", "evidence_refs": self.evidence, "source_locations": [{"file": "producer.py", "start_line": 1, "end_line": 2}]}
        transition = {"producer_id": "producer", "consumer_id": "consumer", "resolution": self.resolution(), "obligations": {key: copy.deepcopy(proof) for key in OBLIGATIONS}}
        validate_transitions(self.scan, self.target, ["producer", "consumer"], [transition], primitives)
        for obligation in ("scope_alignment", "consumer_authority", "conditions_compatible"):
            with self.subTest(obligation=obligation):
                broken = copy.deepcopy(transition)
                broken["obligations"][obligation]["outcome"] = "contradicted"
                with self.assertRaisesRegex(ValueError, "incompatible"):
                    validate_transitions(self.scan, self.target, ["producer", "consumer"], [broken], primitives)
        blocked = copy.deepcopy(transition)
        blocked["resolution"] = self.resolution("externally_blocked")
        blocked["resolution"]["missing_fact"] = "Queue namespace deployment binding"
        blocked["obligations"]["control_preservation"]["outcome"] = "externally_blocked"
        validate_transitions(self.scan, self.target, ["producer", "consumer"], [blocked], primitives, False)
        with self.assertRaisesRegex(ValueError, "unresolved"):
            validate_transitions(self.scan, self.target, ["producer", "consumer"], [blocked], primitives)

    def test_registered_graph_followup_keeps_plan_sealed(self):
        self.context["attempt_id"] = "attempt-one"
        question = {"id": "Q-NEXT", "type": "callers", "subject": "worker", "file": "producer.py"}
        before = (self.scan / "campaign-planning/campaign-plan.json").read_bytes()
        request = register_followup(self.scan, self.context, "CAM-001", question, self.evidence, reference(self.scan, self.wave))
        self.assertEqual(request["remaining_budget"], 1)
        self.assertEqual(_planned_question(self.scan, self.context, "intrusion", "CAM-001", "Q-NEXT"), question)
        with self.assertRaises(ValueError):
            register_followup(self.scan, self.context, "CAM-999", question, self.evidence, reference(self.scan, self.wave))
        changed = {**question, "type": "callees"}
        with self.assertRaisesRegex(ValueError, "immutable"):
            register_followup(self.scan, self.context, "CAM-001", changed, self.evidence, reference(self.scan, self.wave))
        self.assertEqual(before, (self.scan / "campaign-planning/campaign-plan.json").read_bytes())

    def test_retained_waves_survive_source_routes_and_reduced_budget(self):
        wave = self.complete_initial([self.proposal()])
        owner = next(iter(wave["assignments"]))
        resumed_attempt = {**self.context, "attempt_id": "attempt-two"}
        primitives = available_primitives(self.scan, resumed_attempt, self.index, self.result(owner, wave))
        self.assertEqual(primitives[self.primitive()["id"]]["capability"]["evidence_status"], "hypothesized")
        retained = {path: path.read_bytes() for path in (self.scan / "intrusion").rglob("*.json")}
        (self.target / "producer.py").unlink()
        resumed = {**self.context, "attempt_id": "attempt-two", "repositories": [{"path": "new"}],
                   "model_routing": {"agents": {"vulnops-intrusion-campaign": "test/changed:high"}},
                   "intrusion_budget": {"continuation_rounds": 0, "continuation_tasks": 0, "graph_followups": 0}}
        self.assertEqual(read_snapshot(self.scan, resumed, reference(self.scan, wave)), wave)
        closed = build_wave(self.scan, self.target, resumed)
        self.assertEqual(closed["assignments"], {})
        self.assertEqual(closed["results"], wave["results"])
        self.assertEqual(closed["allocation_deferrals"][0]["outcome"], "budget_deferred")
        validate_intrusion(self.scan, self.target, resumed, self.index, self.aggregate(closed))
        self.assertEqual({path: path.read_bytes() for path in retained}, retained)



if __name__ == "__main__":
    unittest.main()
