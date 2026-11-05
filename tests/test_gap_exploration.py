"""Source-only supplementary admission regressions on disposable harness fixtures."""
from __future__ import annotations

from copy import deepcopy
import argparse
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import gap_exploration_contract as gap
from gap_fixture import GapFixture, save
from test_gap_config_lifecycle import RECOVERY


class GapExplorationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        patch = mock.patch.dict(os.environ, {"VULNOPS_RUNTIME_ROOT": str(self.root / "runtime")})
        patch.start()
        self.addCleanup(patch.stop)
        self.fixture = GapFixture(self.root)
        self.context, self.base = self.fixture.context, self.fixture.base

    def admit_plan(self, tasks=("GapA",)):
        authored = self.fixture.plan(tasks)
        gap.admit_plan(self.context, authored)
        return authored

    def close(self):
        result = gap.finalize_phase(self.context)
        self.fixture.accepted(result["status"])
        return gap.load_accepted(self.base, context=self.context)


    def test_no_seed_publishes_empty_without_worker_or_graph(self):
        self.admit_plan(())
        result = self.close()
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["summary"]["worker_attempts"], 0)
        self.assertEqual(result["graph_consumption"], {"preparations": [], "queries": []})
        self.assertFalse((self.base / "gap-exploration/packets").exists())

    def test_disabled_phase_uses_same_finalizer_without_plan(self):
        self.context["gap_exploration_budget"]["enabled"] = False
        self.fixture.persist()
        result = self.close()
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["results"], [])

    def test_active_ordinary_context_reads_accepted_gap_before_stale_report(self):
        self.admit_plan(())
        accepted = self.close()
        self.context["phases"]["synthesis"] = "running"
        self.fixture.persist()
        save(self.base / "report/security-report.json", {"stale": "previous final projection"})
        with mock.patch("report_bundle.read_publication", side_effect=ValueError("stale completed report")) as reader:
            self.assertEqual(gap.load_accepted(self.base, context=self.context), accepted)
            reader.assert_not_called()
            with self.assertRaisesRegex(ValueError, "attempt ownership"):
                gap.load_accepted(self.base, context={**self.context, "attempt_id": "foreign"})
            with self.assertRaisesRegex(ValueError, "stale completed report"):
                gap.load_accepted(self.base)
            self.context["status"] = "complete"
            self.fixture.persist()
            with self.assertRaisesRegex(ValueError, "stale completed report"):
                gap.load_accepted(self.base, context=self.context)

    def test_coordinator_failure_preserves_admitted_peer_without_fabrication(self):
        self.context["phases"].update(**{"final-verification": "pending", "report": "pending"})
        self.context["phases"]["gap-exploration"] = "pending"
        self.fixture.persist()
        from run_lifecycle import AUDIT_TASK_PHASES
        tasks = [{"id": identity, "phase": phase, "status": "ok", "attempts": 1}
                 for identity, phase in AUDIT_TASK_PHASES.items() if self.context["phases"][phase] == "ok"]
        save(self.base / "task-ledger.json", {"run_id": self.context["run_id"], "tasks": tasks})
        command = [sys.executable, str(ROOT / "scripts/update-run-state.py"), str(self.base),
                   "--phase", "gap-exploration", "--task", "GapExploration", "--task-phase", "gap-exploration"]
        environment = {**os.environ, "VULNOPS_LAUNCHER_PID": str(os.getpid()),
                       "VULNOPS_LAUNCHER_SESSION_ID": "gap-closure-fixture"}
        def transition(*options):
            return subprocess.run([*command, *options], capture_output=True, text=True, env=environment)
        for attempt in range(2):
            started = transition("--phase-status", "running", "--increment-attempt")
            self.assertEqual(started.returncode, 0, started.stderr)
            if attempt == 0:
                self.admit_plan(("Healthy", "Pending"))
                gap.admit_worker(self.context, "Healthy", self.fixture.result("Healthy"))
            failed = transition("--phase-status", "failed", "--failure-kind", "execution_failed",
                                "--error", "Coordinator exhausted authored fixture attempts")
            self.assertEqual(failed.returncode, 0, failed.stderr)
        consumed = json.loads((self.base / "task-ledger.json").read_text())["tasks"][-1]
        scratch = self.base / "gap-exploration/drafts/rejected.json"
        save(scratch, {"unaccepted": True})
        args = argparse.Namespace(scan_base=self.base, context=self.root / "context.json", depth="balanced",
                                  reason=None, dry_run=False, invalidate_phase=None)
        self.assertEqual(RECOVERY.recover(args), ("gap-exploration", 5, 4))
        self.assertFalse(scratch.exists())
        self.assertEqual(json.loads((self.base / "task-ledger.json").read_text())["tasks"][-1], consumed)
        before = {name: (self.base / name).read_bytes() for name in ("run-manifest.json", "task-ledger.json")}
        worker = self.base / "gap-exploration/results/Healthy.json"
        healthy = worker.read_bytes()
        worker.write_text("{}")
        refused = transition("--close-optional-failure", "--context", str(self.root / "context.json"))
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual({name: (self.base / name).read_bytes() for name in before}, before)
        worker.write_bytes(healthy)
        closed = transition("--close-optional-failure", "--context", str(self.root / "context.json"))
        self.assertEqual(closed.returncode, 0, closed.stderr)
        original_task = json.loads(before["task-ledger.json"])["tasks"][-1]
        task = json.loads((self.base / "task-ledger.json").read_text())["tasks"][-1]
        for key in ("status", "attempts", "artifact", "error", "failure_history"):
            self.assertEqual(task[key], original_task[key])
        self.assertEqual(task["optional_closure"]["status"], "degraded")
        result = gap.load_accepted(self.base, context=self.context)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["non_promoted"][0]["outcome"], "budget_deferred")
        self.assertEqual(worker.read_bytes(), healthy)
        self.assertFalse((self.base / "gap-exploration/results/Pending.json").exists())

    def test_failure_finalizer_refuses_live_descendants(self):
        self.admit_plan()
        gap.dispatch_worker(self.context, "GapA")
        self.fixture.failed_coordinator("Coordinator failed")
        with self.assertRaisesRegex(ValueError, "descendants"):
            gap.finalize_phase(self.context, failure_reason="Coordinator failed")

    def test_selected_work_cannot_close_advisory_only(self):
        authored = self.fixture.plan()
        authored["assignments"] = []
        with self.assertRaisesRegex(ValueError, "exactly one supplementary investigator"):
            gap.admit_plan(self.context, authored)
        self.admit_plan()
        with self.assertRaisesRegex(ValueError, "still has supplementary investigation capacity"):
            gap.finalize_phase(self.context)

    def test_source_proof_not_nonempty_or_graph_only(self):
        self.admit_plan()
        result = self.fixture.result()
        result["candidates"][0]["proof"]["reachability"]["source_refs"] = ["gap-exploration/codegraph-runs/GapA/Q1/context.json:1"]
        with self.assertRaises(ValueError):
            gap.admit_worker(self.context, "GapA", result)
        self.assertFalse((self.base / "gap-exploration/results/GapA.json").exists())

    def test_missing_control_or_unresolved_obligation_cannot_promote(self):
        self.admit_plan()
        result = self.fixture.result()
        result["candidates"][0]["proof"]["intervening_controls"]["outcome"] = "locally_unresolved"
        with self.assertRaises(ValueError):
            gap.admit_worker(self.context, "GapA", result)
        result["candidates"][0]["proof"]["intervening_controls"]["outcome"] = "established"
        result["candidates"][0]["inspected_controls"] = []
        with self.assertRaises(ValueError):
            gap.admit_worker(self.context, "GapA", result)

    def test_two_candidates_maximum_and_global_candidate_limit(self):
        self.admit_plan(("A", "B"))
        result = self.fixture.result("A", candidates=3)
        with self.assertRaises(ValueError):
            gap.admit_worker(self.context, "A", result)
        result["candidates"].pop()
        self.context["gap_exploration_budget"]["max_candidates"] = 2
        gap.admit_worker(self.context, "A", result)
        peer = self.fixture.result("B", candidates=1)
        with self.assertRaisesRegex(ValueError, "candidate allocation"):
            gap.admit_worker(self.context, "B", peer)
        self.assertFalse((self.base / "gap-exploration/results/B.json").exists())
        self.context["gap_exploration_budget"]["max_candidates"] = 3
        gap.admit_worker(self.context, "B", peer)
        self.assertEqual(len(self.close()["candidates"]), 3)

    def test_current_route_and_exact_source_view_are_required(self):
        self.admit_plan()
        result = self.fixture.result()
        result["provenance"]["selector"] = "fixture/another:high"
        with self.assertRaisesRegex(ValueError, "provenance"):
            gap.admit_worker(self.context, "GapA", result)
        result["provenance"]["selector"] = "fixture/investigator:high"
        result["source_view"] = "derived"
        with self.assertRaisesRegex(ValueError, "source view"):
            gap.admit_worker(self.context, "GapA", result)

    def test_missing_current_route_never_falls_back(self):
        self.admit_plan()
        self.context["model_routing"]["agents"].pop("vulnops-gap-investigator")
        with self.assertRaisesRegex(ValueError, "no generic fallback"):
            gap.dispatch_worker(self.context, "GapA")

    def test_duplicate_assignment_and_unqualified_view_rejected(self):
        authored = self.fixture.plan()
        authored["assignments"].append(deepcopy(authored["assignments"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate gap ownership"):
            gap.admit_plan(self.context, authored)
        authored["assignments"].pop()
        authored["seeds"][0]["source_view"] = "current"
        with self.assertRaises(ValueError):
            gap.admit_plan(self.context, authored)

    def test_changed_rejected_route_needs_source_evidence(self):
        authored = self.fixture.plan()
        seed = authored["seeds"][0]
        seed.update(prior_outcome="contradicted", changed_hypothesis="Alternate caller bypasses the guarded sibling", counterevidence_response="The sibling guard is not invoked by this caller")
        with self.assertRaisesRegex(ValueError, "source evidence addressing counterevidence"):
            gap.admit_plan(self.context, authored)
        seed["changed_evidence_refs"] = ["routes.py:1-12"]
        gap.admit_plan(self.context, authored)

    def test_external_blocker_is_retained_without_local_fanout(self):
        authored = self.fixture.plan()
        authored["seeds"][0]["external_blocker"] = "Deployed broker policy absent"
        with self.assertRaisesRegex(ValueError, "no authorized local answer"):
            gap.admit_plan(self.context, authored)
        authored["seeds"][0].update(external_blocker="Deployed broker policy absent", disposition="externally_blocked")
        authored["assignments"] = []
        gap.admit_plan(self.context, authored)
        result = self.close()
        self.assertEqual(result["non_promoted"][0]["outcome"], "externally_blocked")
        self.assertEqual(result["summary"]["worker_attempts"], 0)


    def test_unanchored_scanner_lead_retains_missing_source(self):
        authored = self.fixture.plan()
        authored["seeds"][0].update(source_refs=[], disposition="locally_unresolved", missing_fact="Scanner match has no affected-use source anchor")
        authored["assignments"] = []
        gap.admit_plan(self.context, authored)
        self.assertIn("no affected-use", self.close()["non_promoted"][0]["missing_fact"])

    def test_unpublished_peer_input_and_upstream_mutation_rejected(self):
        authored = self.fixture.plan()
        authored["seeds"][0]["input_refs"] = ["gap-exploration/drafts/Other/result.json"]
        with self.assertRaisesRegex(ValueError, "unaccepted or unpublished"):
            gap.admit_plan(self.context, authored)
        authored["seeds"][0]["input_refs"] = [self.fixture.predecessor]
        save(self.base / self.fixture.predecessor, {"run_id": self.context["run_id"], "changed": True})
        with self.assertRaisesRegex(ValueError, "changed after preparation"):
            gap.admit_plan(self.context, authored)

    def test_packet_proof_obligation_is_immutable(self):
        self.admit_plan()
        target = self.base / "gap-exploration/packets/GapA.json"
        value = json.loads(target.read_text())
        value["seed"]["missing_fact"] = "Unrelated hypothesis"
        save(target, value)
        with self.assertRaisesRegex(ValueError, "immutable source proof obligations"):
            gap.dispatch_worker(self.context, "GapA")

    def test_lower_resumed_limits_preserve_consumed_attempts_and_peer(self):
        self.admit_plan(("Healthy", "Unstarted"))
        gap.admit_worker(self.context, "Healthy", self.fixture.result("Healthy"))
        self.context["gap_exploration_budget"]["max_tasks"] = 1
        self.context["gap_exploration_budget"]["max_candidates"] = 2
        self.context["attempt_id"] = "attempt-2"
        self.context["model_routing"]["agents"]["vulnops-gap-investigator"] = "fixture/new:high"
        self.fixture.persist()
        with self.assertRaisesRegex(ValueError, "allocation exhausted"):
            gap.dispatch_worker(self.context, "Unstarted")
        result = self.close()
        self.assertEqual(result["candidates"][0]["provenance"]["selector"], "fixture/investigator:high")
        self.assertEqual(gap.producing_attempt(self.base, "gap-exploration/results/Healthy.json"), "attempt-1")
        self.assertEqual(result["non_promoted"][0]["outcome"], "budget_deferred")

    def test_retry_budget_and_concurrency_are_independent(self):
        self.admit_plan(("A", "B"))
        self.context["gap_exploration_budget"]["max_concurrency"] = 1
        gap.dispatch_worker(self.context, "A")
        with self.assertRaisesRegex(ValueError, "concurrency"):
            gap.dispatch_worker(self.context, "B")
        gap.fail_worker(self.context, "A", "Stopped failed attempt")
        gap.dispatch_worker(self.context, "A")
        gap.fail_worker(self.context, "A", "Stopped second attempt")
        with self.assertRaisesRegex(ValueError, "attempts exhausted"):
            gap.dispatch_worker(self.context, "A")
        gap.dispatch_worker(self.context, "B")

    def test_interrupted_cleanup_preserves_attempt_and_accepted_peers(self):
        self.admit_plan(("A", "B"))
        gap.admit_worker(self.context, "A", self.fixture.result("A"))
        gap.dispatch_worker(self.context, "B")
        draft = self.base / "gap-exploration/drafts/B/result.json"
        save(draft, {"unfinished": True})
        worker = self.base / "gap-exploration/results/A.json"
        accepted = worker.read_bytes()
        save(self.base / "gap-exploration/results.json", {"untrusted": True})
        checkpoint = gap.recovery_checkpoint(self.context)
        self.assertIn("gap-exploration/results/A.json", checkpoint["files"])
        self.assertNotIn("gap-exploration/drafts/B/result.json", checkpoint["files"])
        ledger = checkpoint["documents"]["gap-exploration/dispatch.json"]
        self.assertEqual(ledger["workers"][-1]["status"], "failed")
        operation = RECOVERY.unfinished_work(self.base, "gap-exploration", self.context)
        RECOVERY.reconcile_work(self.base, "gap-exploration", operation)
        self.assertEqual(worker.read_bytes(), accepted)
        self.assertFalse(draft.exists())
        self.assertFalse((self.base / "gap-exploration/results.json").exists())
        dispatched = gap.dispatch_worker(self.context, "B")
        self.assertEqual(dispatched["attempt"], 2)
        gap.fail_worker(self.context, "B", "Second authored attempt failed")
        aggregate = self.close()
        self.assertEqual([row["id"] for row in aggregate["candidates"]], ["GC-A-1"])


    def test_wrong_graph_receipt_owner_is_integrity_error(self):
        self.admit_plan()
        result = self.fixture.result()
        result["graph_receipt_refs"] = ["gap-exploration/codegraph-runs/Other/Q1/receipt.json"]
        with self.assertRaisesRegex(ValueError, "another gap owner"):
            gap.admit_worker(self.context, "GapA", result)

    def test_completed_aggregate_is_not_a_loose_file_or_mutable_summary(self):
        self.admit_plan(())
        gap.finalize_phase(self.context)
        with self.assertRaisesRegex(ValueError, "no accepted checkpoint"):
            gap.load_accepted(self.base)
        self.fixture.accepted("ok")
        target = self.base / "gap-exploration/results.json"
        value = json.loads(target.read_text())
        value["summary"]["candidates"] = 99
        save(target, value)
        with self.assertRaisesRegex(ValueError, "finalization receipt"):
            gap.load_accepted(self.base)



    def test_source_escape_and_redirected_control_paths_stop(self):
        authored = self.fixture.plan()
        authored["seeds"][0]["source_refs"] = ["../outside.py:1"]
        with self.assertRaises(ValueError):
            gap.admit_plan(self.context, authored)
        self.context["paths"]["gap_exploration"] = str(self.root / "elsewhere")
        with self.assertRaisesRegex(ValueError, "redirected"):
            gap.prepare_inputs(self.context)

    def test_unstarted_recovery_does_not_create_control_state(self):
        self.context["phases"]["intrusion"] = "pending"
        self.fixture.persist()
        self.assertEqual(gap.recovery_checkpoint(self.context), {"files": [], "documents": {}})
        self.assertFalse((self.base / "gap-exploration").exists())


    def test_cleanup_without_interruption_refuses_running_writer(self):
        self.admit_plan()
        gap.dispatch_worker(self.context, "GapA")
        draft = self.base / "gap-exploration/drafts/GapA/result.json"
        save(draft, {"unfinished": True})
        before = draft.read_bytes()
        with self.assertRaisesRegex(ValueError, "stop gap descendants"):
            gap.recovery_checkpoint(self.context, interrupt_running=False)
        self.assertEqual(draft.read_bytes(), before)

    def test_interrupted_graph_reservations_remain_consumed(self):
        from gap_graph import reserve_query
        self.context["gap_exploration_budget"]["graph_timeout_seconds"] = 60
        self.fixture.persist()
        authored = self.fixture.plan()
        authored["graph_questions"] = [{
            "id": "Interrupted", "owner": "GapExploration", "seed_id": "Seed-GapA",
            "operation": "callers", "subject": "guarded_route", "file": "routes.py",
            "reason": "Find the caller of the guarded operation", "expected_value": "Resolve alternate reachability",
            "source_view": "base", "source_refs": ["routes.py:8-12"]}]
        gap.admit_plan(self.context, authored)
        reserve_query(self.context, "GapExploration",
                      gap.graph_question(self.context, "GapExploration", "Interrupted"))
        with self.assertRaisesRegex(ValueError, "allowance exhausted"):
            reserve_query(self.context, "GapExploration",
                          gap.graph_question(self.context, "GapExploration", "Interrupted"))
        self.fixture.failed_coordinator("Stopped coordinator")
        with self.assertRaisesRegex(ValueError, "descendants"):
            gap.finalize_phase(self.context, failure_reason="Stopped coordinator")
        projected = gap.recovery_checkpoint(self.context)["documents"]["gap-exploration/dispatch.json"]
        self.assertEqual(projected["graph_consumption"]["queries"][0]["status"], "interrupted")
        self.assertEqual(projected["graph_consumption"]["queries"][0]["seconds"], 60)
        operation = RECOVERY.unfinished_work(self.base, "gap-exploration", self.context)
        RECOVERY.reconcile_work(self.base, "gap-exploration", operation)
        result = gap.finalize_phase(self.context, failure_reason="Stopped coordinator")
        self.assertEqual(result["graph_consumption"]["queries"][0]["seconds"], 60)

    def test_failed_coordinator_after_finalizer_preserves_worker_bytes(self):
        self.admit_plan()
        gap.admit_worker(self.context, "GapA", self.fixture.result())
        gap.finalize_phase(self.context)
        worker = self.base / "gap-exploration/results/GapA.json"
        before = worker.read_bytes()
        self.fixture.failed_coordinator("Coordinator terminal yield was malformed")
        result = gap.finalize_phase(self.context, failure_reason="Coordinator terminal yield was malformed")
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(worker.read_bytes(), before)
        self.assertEqual(len(result["candidates"]), 1)
        gap.validate_phase(self.base, self.context)


    def test_zero_current_task_allowance_defers_without_borrowing_original(self):
        self.admit_plan()
        self.context["gap_exploration_budget"].update(max_tasks=0, max_candidates=0)
        with self.assertRaisesRegex(ValueError, "allocation exhausted"):
            gap.dispatch_worker(self.context, "GapA")
        result = self.close()
        self.assertEqual(result["non_promoted"][0]["outcome"], "budget_deferred")
        self.assertEqual(result["summary"]["worker_attempts"], 0)

    def test_linked_objective_is_inherited_without_relabelling(self):
        linked = GapFixture(self.root / "linked-inherited", linked=True)
        native = {"accepted_phases": ["baseline", "planning", "investigation"], "workers": []}
        authority = mock.patch.object(gap.core, "live_call", return_value=native)
        authority.start()
        self.addCleanup(authority.stop)
        owner = "planning/plan.json"
        objective = {"id": gap.stable_id("OBJ-", owner, "existing-goal"), "owner": owner, "local_key": "existing-goal",
            "parent": None, "starting_actor": "Authenticated account", "controlled_material": "Object key",
            "resource_scope": "Stored account objects", "desired_effect": "Read another account's object",
            "success_condition": "Return a nonowned object", "evidence_refs": ["routes.py:1-6"]}
        save(linked.base / "planning/plan.json", {"schema_version": "2.0", "run_id": linked.context["run_id"],
            "objectives": [objective], "questions": [], "assignments": []})
        authored = linked.plan()
        authored["objectives"] = [objective]
        for row in [*authored["questions"], *authored["seeds"], *authored["assignments"]]:
            row["objective_id"] = objective["id"]
        gap.admit_plan(linked.context, authored)
        self.assertEqual(gap.packet(linked.context, "GapA")["objective"], objective)

    def test_changed_source_keeps_historical_peer_and_new_attempt_route(self):
        self.admit_plan(("Historical", "Current"))
        gap.admit_worker(self.context, "Historical", self.fixture.result("Historical"))
        self.context["attempt_id"] = "attempt-2"
        self.context["model_routing"]["agents"]["vulnops-gap-investigator"] = "fixture/new:high"
        source = self.fixture.source / "routes.py"
        source.write_text(source.read_text() + "\n# Current source-only fixture revision.\n")
        self.fixture.persist()
        current = self.fixture.result("Current")
        gap.admit_worker(self.context, "Current", current)
        aggregate = self.close()
        self.assertEqual({row["provenance"]["selector"] for row in aggregate["candidates"]},
                         {"fixture/investigator:high", "fixture/new:high"})
        source.unlink()
        self.assertEqual(len(gap.load_accepted_candidates(self.base)), 2)
        self.assertIn("gap-exploration/results/Historical.json", gap.accepted_support_refs(self.base))


class NativeGapEvidenceTests(unittest.TestCase):
    """Synthetic native outcomes exercise adapters, not model-led discovery."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = GapFixture(Path(temporary.name), linked=True)
        self.context, self.base = self.fixture.context, self.fixture.base
        self.call = {"accepted_phases": ["baseline", "planning", "investigation"],
                     "phase": gap.PHASE, "workers": [], "caller": {"id": "coordinator"}}
        authority = mock.patch.object(gap.core, "live_call", return_value=self.call)
        authority.start()
        self.addCleanup(authority.stop)

    def plan(self, tasks):
        gap.admit_plan(self.context, self.fixture.plan(tasks))

    def worker(self, identity, *, status="completed", attempt=1):
        return {"id": identity, "runtime_id": identity + str(attempt), "phase": gap.PHASE,
                "actor": gap.actor(self.context, True), "selector": gap.assigned_route(self.context, worker=True),
                "attempt": attempt, "status": status, "yield_valid": status == "completed",
                "input_sha256": gap.core.sha256_file(self.base / f"gap-exploration/packets/{identity}.json"),
                "artifacts": [], "artifact_sha256": {}, "error": "Synthetic native worker failed." if status == "failed" else ""}

    def admit(self, identity, *, attempt=1, status="completed", yield_valid=True, admission=None):
        packet = gap.packet(self.context, identity)
        result = self.fixture.result(identity, dispatch={
            "packet": packet, "selector": gap.assigned_route(self.context, worker=True), "attempt": attempt})
        if admission is not None:
            result["admission"] = deepcopy(admission)
        relative = f"gap-exploration/drafts/{identity}-{attempt}.json"
        save(self.base / relative, result)
        native = self.worker(identity, attempt=attempt, status=status)
        native.update(yield_valid=yield_valid, artifacts=[relative],
                      artifact_sha256={relative: gap.core.sha256_file(self.base / relative)})
        self.call["workers"].append(native)
        gap.admit_worker(self.context, identity, result)
        return result

    def test_native_admission_writes_only_analytical_evidence(self):
        self.plan(("Healthy", "Failed"))
        self.admit("Healthy")
        self.call["workers"].append(self.worker("Failed", status="failed"))
        result = gap.finalize_phase(self.context)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["non_promoted"][0]["outcome"], "execution_failed")
        self.assertNotIn("graph_consumption", result)
        self.call["accepted_phases"].append(gap.PHASE)
        self.assertEqual(gap.load_accepted(self.base, context=self.context), result)
        self.assertEqual(gap.accounting(self.base, context=self.context)["candidates"], 1)
        self.assertEqual(gap.accounting(self.base, context=self.context)["non_promoted"], result["non_promoted"])
        for name in ("advantage-manifest.json", "task-ledger.json", "gap-exploration/dispatch.json",
                     "gap-exploration/phase-manifest.json"):
            self.assertFalse((self.base / name).exists(), name)

    def test_draft_admission_metadata_does_not_block_later_admissions_or_finalization(self):
        self.plan(("WithMetadata", "WithoutMetadata", "Later"))
        supplied = {"input_sha256": "0" * 64, "source_receipts": [], "support": [],
                    "runtime_id": "worker-authored-not-authoritative"}
        draft = self.admit("WithMetadata", admission=supplied)
        original = deepcopy(draft)
        self.admit("WithoutMetadata")
        self.admit("Later")
        result = gap.finalize_phase(self.context)
        self.assertEqual({row["task_id"] for row in result["results"]},
                         {"WithMetadata", "WithoutMetadata", "Later"})
        self.assertEqual({row["id"] for row in result["candidates"]},
                         {"GC-WithMetadata-1", "GC-WithoutMetadata-1", "GC-Later-1"})
        self.assertEqual(result["non_promoted"], [])
        canonical = gap.read(self.context, "gap-exploration/results/WithMetadata.json")
        self.assertEqual(canonical["admission"], {
            "runtime_id": "WithMetadata1",
            "input_sha256": self.call["workers"][0]["input_sha256"],
            "source_receipts": [{"ref": ref, "source_view": "base",
                                 "sha256": gap.core.sha256_file(self.fixture.source / "routes.py")}
                                for ref in ("routes.py:1-12", "routes.py:1-3",
                                            "routes.py:3-12", "routes.py:4-6", "routes.py:6")],
            "support": []})
        self.assertEqual(draft, original)
        self.assertEqual(gap.read(self.context, "gap-exploration/drafts/WithMetadata-1.json"), original)
        self.call["accepted_phases"].append(gap.PHASE)
        self.assertEqual(gap.load_accepted(self.base, context=self.context), result)

    def test_draft_admission_metadata_survives_coordinator_failure_closure(self):
        self.plan(("Healthy", "Unlaunched"))
        self.admit("Healthy", admission={"input_sha256": "0" * 64,
                                         "source_receipts": [], "support": []})
        reason = "Synthetic coordinator stopped after admitted evidence."
        self.call["workers"].append({"id": gap.coordinator(self.context), "runtime_id": "coordinator",
            "actor": gap.actor(self.context), "phase": gap.PHASE, "status": "failed", "error": reason})
        result = gap.finalize_phase(self.context, failure_reason=reason)
        self.assertEqual([row["task_id"] for row in result["results"]], ["Healthy"])
        self.assertEqual([row["id"] for row in result["non_promoted"]], ["Unlaunched"])
        self.assertEqual(result["non_promoted"][0]["outcome"], "locally_unresolved")

    def test_reconciliation_rejects_changed_canonical_analysis_and_attribution(self):
        self.plan(("Healthy",))
        self.admit("Healthy")
        target = self.base / "gap-exploration/results/Healthy.json"
        original = json.loads(target.read_text())
        mutations = (
            (("resolution", "reason"), "Changed analytical conclusion"),
            (("candidates", 0, "proof", "reachability", "reason"), "Changed reachability proof"),
            (("candidates", 0, "provenance", "selector"), "fixture/foreign:high"),
            (("provenance", "selector"), "fixture/foreign:high"),
        )
        for keys, replacement in mutations:
            with self.subTest(field=keys):
                changed = deepcopy(original)
                owner = changed
                for key in keys[:-1]:
                    owner = owner[key]
                owner[keys[-1]] = replacement
                save(target, changed)
                with self.assertRaisesRegex(ValueError, "canonical gap evidence differs"):
                    gap.finalize_phase(self.context)
        self.assertFalse((self.base / "gap-exploration/results.json").exists())

    def test_reconciliation_keeps_raw_terminal_hash_binding(self):
        self.plan(("Healthy",))
        original = self.admit("Healthy")
        target = self.base / "gap-exploration/drafts/Healthy-1.json"
        for field, replacement in (
                ("admission", {"input_sha256": "0" * 64, "source_receipts": [], "support": []}),
                ("limitations", ["Changed after native terminal delivery"])):
            with self.subTest(field=field):
                changed = deepcopy(original)
                changed[field] = replacement
                save(target, changed)
                with self.assertRaisesRegex(ValueError, "native gap terminal artifact changed"):
                    gap.finalize_phase(self.context)
        self.assertFalse((self.base / "gap-exploration/results.json").exists())

    def test_reconciliation_keeps_generated_receipt_validation(self):
        self.plan(("Healthy",))
        self.admit("Healthy")
        target = self.base / "gap-exploration/results/Healthy.json"
        original = json.loads(target.read_text())
        for field, replacement, error in (
                ("input_sha256", "0" * 64, "packet changed after dispatch"),
                ("source_receipts", [], "source-proof admission receipt changed")):
            with self.subTest(field=field):
                changed = deepcopy(original)
                changed["admission"][field] = replacement
                save(target, changed)
                with self.assertRaisesRegex(ValueError, error):
                    gap.finalize_phase(self.context)
        self.assertFalse((self.base / "gap-exploration/results.json").exists())

    def rejected_publication(self, identity, attempt):
        packet = gap.packet(self.context, identity)
        result = self.fixture.result(identity, dispatch={
            "packet": packet, "selector": gap.assigned_route(self.context, worker=True), "attempt": attempt})
        result["candidates"][0]["proof"]["reachability"]["reason"] = " "
        relative = f"gap-exploration/drafts/{identity}-{attempt}.json"
        save(self.base / relative, result)
        native = self.worker(identity, attempt=attempt)
        native.update(artifacts=[relative], artifact_sha256={relative: gap.core.sha256_file(self.base / relative)})
        self.call["workers"].append(native)
        with self.assertRaisesRegex(ValueError, "complete source-established"):
            gap.admit_worker(self.context, identity, result)
        self.assertEqual(native["status"], "completed")
        self.assertFalse((self.base / f"gap-exploration/results/{identity}.json").exists())
        return native

    def test_semantically_rejected_native_publication_can_retry_within_invocation(self):
        self.plan(("Retry",))
        rejected = self.rejected_publication("Retry", 1)
        unresolved = gap.aggregate(self.context)
        self.assertEqual(unresolved["non_promoted"][0]["outcome"], "locally_unresolved")
        self.admit("Retry", attempt=2)
        result = gap.finalize_phase(self.context)
        self.assertEqual(result["summary"]["worker_attempts"], 2)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["non_promoted"], [])
        self.assertEqual(rejected["status"], "completed")
        admitted = gap.read(self.context, "gap-exploration/results/Retry.json")
        self.assertEqual(admitted["attempt"], 2)
        self.assertFalse((self.base / "gap-exploration/dispatch.json").exists())

    def test_rejected_publication_does_not_require_exhaustion_or_discard_healthy_peers(self):
        self.plan(("Healthy", "Rejected"))
        self.admit("Healthy")
        self.rejected_publication("Rejected", 1)
        result = gap.finalize_phase(self.context)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual([row["task_id"] for row in result["results"]], ["Healthy"])
        self.assertEqual(result["summary"]["worker_attempts"], 2)
        self.assertEqual(result["non_promoted"][0]["outcome"], "locally_unresolved")
        self.assertIn("no admissible analytical result", result["non_promoted"][0]["reason"])
        self.assertTrue(all(row["status"] == "completed" for row in self.call["workers"]))

    def test_unlaunched_work_closes_unreviewed_without_counting_as_execution(self):
        self.plan(("Unlaunched",))
        result = gap.finalize_phase(self.context)
        self.assertEqual(result["non_promoted"][0]["outcome"], "locally_unresolved")
        self.assertIn("never launched", result["non_promoted"][0]["reason"])
        self.assertEqual(result["summary"]["worker_attempts"], 0)
        self.assertEqual(result["summary"]["uninvestigated_leads"], 1)
        self.assertEqual(gap.native_evidence(self.context)["workers"], [])
        with self.assertRaisesRegex(ValueError, "native task"):
            gap.dispatch_worker(self.context, "Unlaunched")
        with self.assertRaisesRegex(ValueError, "native task"):
            gap.fail_worker(self.context, "Unlaunched", "Invented failure")

    def test_native_failure_defers_unlaunched_without_inventing_retry(self):
        self.plan(("Healthy", "Unlaunched"))
        self.admit("Healthy")
        reason = "Synthetic coordinator stopped after one real delivery."
        self.call["workers"].append({"id": gap.coordinator(self.context), "runtime_id": "coordinator",
            "actor": gap.actor(self.context), "phase": gap.PHASE, "status": "failed", "error": reason})
        result = gap.finalize_phase(self.context)
        self.assertIn(reason, result["limitations"])
        self.call["accepted_phases"].append(gap.PHASE)
        self.assertEqual(gap.load_accepted(self.base, context=self.context), result)
        self.assertEqual(result["summary"]["worker_attempts"], 1)
        self.assertEqual(result["non_promoted"][0]["outcome"], "locally_unresolved")
        self.assertEqual(len(result["candidates"]), 1)

    def test_38_publications_do_not_turn_20_unlaunched_tasks_and_four_retries_into_failures(self):
        self.context["gap_exploration_budget"].update(max_tasks=58, max_questions=58, max_candidates=38)
        published = tuple(f"Published{i:02}" for i in range(38))
        unlaunched = tuple(f"Unlaunched{i:02}" for i in range(20))
        self.plan((*published, *unlaunched))
        for identity in published:
            self.admit(identity)
        for identity in unlaunched[:4]:
            with self.assertRaisesRegex(ValueError, "native task"):
                gap.fail_worker(self.context, identity, "Claimed retry never ran")
        closure = gap.aggregate(self.context)
        self.assertEqual(len(closure["candidates"]), 38)
        self.assertEqual(closure["summary"]["uninvestigated_leads"], 20)
        reason = "Actual native coordinator ended before launching remaining assignments."
        self.call["workers"].append({"id": gap.coordinator(self.context), "runtime_id": "coordinator",
            "actor": gap.actor(self.context), "phase": gap.PHASE, "status": "failed", "error": reason})
        result = gap.finalize_phase(self.context, failure_reason=reason)
        self.assertEqual(result["summary"]["worker_attempts"], 38)
        self.assertEqual(len(result["candidates"]), 38)
        self.assertEqual(len(result["non_promoted"]), 20)
        self.assertEqual({row["outcome"] for row in result["non_promoted"]}, {"locally_unresolved"})
        self.assertFalse((self.base / "gap-exploration/dispatch.json").exists())

    def test_missing_or_invalid_terminal_yield_does_not_become_execution_failure(self):
        self.plan(("Healthy", "Missing", "Invalid"))
        self.admit("Healthy")
        missing = self.worker("Missing")
        invalid = self.worker("Invalid")
        invalid["yield_valid"] = False
        self.call["workers"].extend([missing, invalid])
        result = gap.finalize_phase(self.context)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual({row["id"] for row in result["non_promoted"]}, {"Missing", "Invalid"})
        self.assertEqual({row["outcome"] for row in result["non_promoted"]}, {"locally_unresolved"})
        self.assertEqual(missing["status"], "completed")
        self.assertEqual(invalid["status"], "completed")

    def test_optional_retry_after_unadmitted_terminal_delivery_keeps_healthy_peer(self):
        self.context["gap_exploration_budget"]["max_attempts"] = 1
        self.plan(("Healthy", "Retry"))
        self.admit("Healthy")
        self.call["workers"].append(self.worker("Retry"))
        self.call["workers"].append(self.worker("Retry", attempt=2))
        self.admit("Retry", attempt=3)
        result = gap.finalize_phase(self.context)
        self.assertEqual({row["task_id"] for row in result["results"]}, {"Healthy", "Retry"})
        self.assertEqual(result["summary"]["worker_attempts"], 4)
        self.assertEqual(result["non_promoted"], [])

    def test_corrupt_unadmitted_draft_does_not_block_healthy_closure(self):
        self.plan(("Healthy", "Corrupt"))
        self.admit("Healthy")
        relative = "gap-exploration/drafts/Corrupt.json"
        (self.base / relative).write_text("{invalid JSON")
        native = self.worker("Corrupt")
        native.update(artifacts=[relative], artifact_sha256={relative: gap.core.sha256_file(self.base / relative)})
        self.call["workers"].append(native)
        result = gap.finalize_phase(self.context)
        self.assertEqual([row["task_id"] for row in result["results"]], ["Healthy"])
        self.assertEqual(result["non_promoted"][0]["outcome"], "locally_unresolved")

    def cli_admit(self, identity, result_path):
        context_path = self.base / "cli-context.json"
        save(context_path, self.context)
        argv = ["gap-exploration-worker.py", "admit", "--context", str(context_path),
                "--task-id", identity, "--result", str(result_path)]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(gap.core, "load_context", return_value=self.context), \
                mock.patch("builtins.print") as printed:
            status = gap.cli("worker")
        return status, json.loads(printed.call_args.args[0])

    def test_native_cli_discards_malformed_or_missing_result_without_error(self):
        self.plan(("Unusable",))
        result_path = self.base / "unusable.json"
        for payload in (None, "{invalid JSON"):
            with self.subTest(payload=payload):
                if payload is not None:
                    result_path.write_text(payload)
                status, receipt = self.cli_admit("Unusable", result_path)
                self.assertEqual(status, 0)
                self.assertEqual(receipt, {"status": "not_admitted",
                    "reason": "No usable source-bound publication; continue other work."})
                self.assertFalse((self.base / "gap-exploration/results/Unusable.json").exists())

    def test_native_cli_keeps_ownership_runtime_and_confinement_errors_fatal(self):
        self.plan(("Unusable",))
        result_path = self.base / "missing.json"
        with mock.patch.object(sys, "stderr"):
            with self.assertRaises(SystemExit) as unsafe:
                self.cli_admit("Unusable", self.base.parent / "outside.json")
            self.assertEqual(unsafe.exception.code, 2)
            self.call["accepted_phases"] = []
            with self.assertRaises(SystemExit) as ownership:
                self.cli_admit("Unusable", result_path)
            self.assertEqual(ownership.exception.code, 2)
            self.call["accepted_phases"] = ["baseline", "planning", "investigation"]
            worker = self.worker("Unusable")
            worker["input_sha256"] = "0" * 64
            self.call["workers"].append(worker)
            with self.assertRaises(SystemExit) as runtime:
                self.cli_admit("Unusable", result_path)
            self.assertEqual(runtime.exception.code, 2)

    def test_missing_native_plan_closes_with_explicit_coverage_limitation(self):
        result = gap.finalize_phase(self.context)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["results"], [])
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["summary"]["worker_attempts"], 0)
        self.assertIn("no admitted plan", result["limitations"][0])

    def test_running_worker_still_requires_stopping_before_closure(self):
        self.plan(("Running",))
        self.call["workers"].append(self.worker("Running", status="running"))
        with self.assertRaisesRegex(ValueError, "stop and close"):
            gap.finalize_phase(self.context)

    def test_bound_valid_worker_evidence_survives_outer_terminal_delivery_errors(self):
        self.plan(("Completed", "Failed", "Cancelled"))
        for identity, status in (("Completed", "completed"), ("Failed", "failed"), ("Cancelled", "cancelled")):
            self.admit(identity, status=status, yield_valid=False)
        result = gap.finalize_phase(self.context)
        self.assertEqual({row["task_id"] for row in result["results"]}, {"Completed", "Failed", "Cancelled"})
        self.assertEqual(result["non_promoted"], [])
        self.assertEqual([row["status"] for row in self.call["workers"]], ["completed", "failed", "cancelled"])
        self.assertTrue(all(not row["yield_valid"] for row in self.call["workers"]))

    def test_running_worker_cannot_admit_even_valid_byte_bound_evidence(self):
        self.plan(("Running",))
        with self.assertRaisesRegex(ValueError, "single active"):
            self.admit("Running", status="running")
        self.assertFalse((self.base / "gap-exploration/results/Running.json").exists())

    def test_draft_without_native_artifact_binding_is_not_admitted(self):
        self.plan(("Unlaunched",))
        packet = gap.packet(self.context, "Unlaunched")
        result = self.fixture.result("Unlaunched", dispatch={
            "packet": packet, "selector": gap.assigned_route(self.context, worker=True), "attempt": 1})
        with self.assertRaisesRegex(ValueError, "single active"):
            gap.admit_worker(self.context, "Unlaunched", result)
        native = self.worker("Unlaunched")
        relative = "gap-exploration/drafts/Unlaunched.json"
        save(self.base / relative, result)
        native.update(artifacts=[relative], artifact_sha256={relative: "0" * 64})
        self.call["workers"].append(native)
        with self.assertRaisesRegex(ValueError, "exact actual native"):
            gap.admit_worker(self.context, "Unlaunched", result)

    def test_completed_bundle_retains_full_gap_cohort_without_controls(self):
        self.plan(("Healthy",))
        self.admit("Healthy")
        result = gap.finalize_phase(self.context)
        save(self.base / "report/security-report.json", {"publication": "reader fixture"})
        bundle = {**self.context, "gap_exploration": {"ref": "gap-exploration/results.json",
                   "sha256": gap.core.sha256_file(self.base / "gap-exploration/results.json")}}
        with mock.patch("report_bundle.read_publication", return_value=bundle):
            self.fixture.source.rename(self.fixture.root / "source-unavailable")
            self.assertEqual(gap.load_accepted_candidates(self.base), result["candidates"])
            self.assertIn("gap-exploration/results/Healthy.json", gap.accepted_support_refs(self.base))
            damaged = deepcopy(result)
            damaged["candidates"] = []
            save(self.base / "gap-exploration/results.json", damaged)
            with self.assertRaisesRegex(ValueError, "publication binding"):
                gap.load_accepted(self.base)


if __name__ == "__main__":
    unittest.main()
