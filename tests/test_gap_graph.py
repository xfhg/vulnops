"""Supplementary graph preparation uses disposable fixtures, never real run state."""
from __future__ import annotations

from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import codegraph_contract as graph
import gap_graph


class GapGraphTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "a.py").write_text("def helper():\n    return 1\n")
        (self.source / "b.py").write_text("def helper():\n    return 2\n")
        self.base = self.root / "run"
        (self.base / "gap-exploration").mkdir(parents=True)
        self.context = {"run_id": "gap-run", "attempt_id": "attempt-1", "scan_base": str(self.base),
                        "source_root": str(self.source), "codegraph_mode": "enabled", "paths": {},
                        "gap_exploration_budget": {"enabled": True, "max_questions": 4,
                            "graph_timeout_seconds": 120, "preparation_timeout_seconds": 60}}
        self.question = {"id": "Q1", "operation": "callers", "subject": "helper", "file": "a.py",
                         "source_view": "base", "owner_ref": "gap-exploration/plan.json"}
        self.dispatch = self.base / "gap-exploration/dispatch.json"
        self.dispatch.write_text(json.dumps({"run_id": "gap-run", "worker_state": "preserved",
                                             "graph_consumption": {"preparations": [], "queries": []}}))
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict(os.environ, {"VULNOPS_RUNTIME_ROOT": str(self.root / "runtime"),
            "VULNOPS_LAUNCHER_PID": str(os.getpid()), "VULNOPS_LAUNCHER_SESSION_ID": "gap-graph-fixture"}).start()
        mock.patch.object(gap_graph, "ROOT", self.root).start()
        self.setup = mock.patch.object(gap_graph, "_setup", side_effect=self.build).start()


    def build(self, source, runtime, seconds):
        self.assertGreater(seconds, 0)
        project = runtime / "project"
        if project.exists():
            shutil.rmtree(project)
        shutil.copytree(source, project)
        (project / ".codegraph").mkdir()
        with closing(sqlite3.connect(project / ".codegraph/codegraph.db")) as database, database:
            database.execute("CREATE TABLE nodes (id TEXT, name TEXT, qualified_name TEXT, file_path TEXT, start_line INTEGER, kind TEXT)")
            database.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?)", [
                ("a", "helper", "helper", "a.py", 1, "function"),
                ("b", "helper", "helper", "b.py", 1, "function")])
        (runtime / "index-receipt.json").write_text(json.dumps({"status": "ok"}))
        return True, None

    def consumption(self):
        document = json.loads(self.dispatch.read_text())
        self.assertEqual(document["worker_state"], "preserved")
        return document["graph_consumption"]

    def test_absent_index_is_prepared_and_current_run_view_is_reused(self):
        self.context.update(execution_kind="advantage", source_run_id="baseline")
        operation = {"kind": "graph", "id": "native-query-1", "phase": "gap-exploration",
                     "owner_id": "AdvantageGapExploration", "question_id": "Q1",
                     "timeout_seconds": 30, "preparation_timeout_seconds": 30}
        before = self.dispatch.read_bytes()
        with mock.patch("advantage_contract.live_call", return_value={"operation": operation}):
            first = gap_graph.prepare_navigation(self.context, "AdvantageGapExploration", self.question)
            operation.update(id="native-query-2", question_id="Q2")
            second = gap_graph.prepare_navigation(self.context, "AdvantageGapExploration", {**self.question, "id": "Q2"})
        self.assertEqual(first, second)
        self.assertEqual(self.setup.call_count, 1)
        self.assertEqual(self.dispatch.read_bytes(), before)
        self.assertFalse((self.source / ".codegraph").exists())

    def test_changed_source_rebuilds_without_a_resume_identity_gate(self):
        project = gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        historical = self.base / "gap-exploration/retained-receipt.json"
        historical.write_bytes(b"retained accepted evidence")
        (self.source / "a.py").write_text("def helper():\n    return 99\n")
        self.context["attempt_id"] = "attempt-2"
        gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        self.assertEqual(self.setup.call_count, 2)
        self.assertEqual((project / "a.py").read_bytes(), (self.source / "a.py").read_bytes())
        self.assertEqual(historical.read_bytes(), b"retained accepted evidence")

    def test_derived_view_never_uses_base_graph(self):
        import advantage_actions as actions
        base_project = gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        question = {**self.question, "source_view": "derived"}
        with self.assertRaisesRegex(ValueError, "no derived source authority"):
            gap_graph.prepare_navigation(self.context, "GapExploration", question)
        self.context.update(execution_kind="advantage", mode="diff",
                            repo_path=str(self.source), repositories=[{"path": "."}])
        with self.assertRaisesRegex(ValueError, "immutable patch"):
            gap_graph.prepare_navigation(self.context, "AdvantageGapExploration", question)
        patch_file = self.root / "change.patch"
        patch_file.write_text(
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,2 +1,2 @@\n def helper():\n-    return 1\n+    return 42\n")
        self.context["options"] = {"patch": str(patch_file), "repository": None}
        operation = {"kind": "graph", "id": "native-derived", "phase": "gap-exploration",
                     "owner_id": "AdvantageGapExploration", "question_id": "Q1",
                     "timeout_seconds": 30, "preparation_timeout_seconds": 30}
        with mock.patch.object(actions, "ROOT", self.root), mock.patch("advantage_contract.live_call", return_value={"operation": operation}):
            self.context["patch_binding"] = actions.prepare_patch(self.context)
            derived_project = gap_graph.prepare_navigation(self.context, "AdvantageGapExploration", question)
            self.assertNotEqual(base_project, derived_project)
            self.assertEqual((derived_project / "a.py").read_bytes(),
                             (actions.derived_root(self.context) / "a.py").read_bytes())
        self.assertEqual(self.setup.call_count, 2)

    def test_explicit_disable_rejects_navigation_without_preparation(self):
        for override in ({"codegraph_mode": "disabled"}, {"mode": "actions"}):
            with self.subTest(override=override), self.assertRaisesRegex(ValueError, "disabled"):
                gap_graph.prepare_navigation({**self.context, **override}, "GapExploration", self.question)
        self.setup.assert_not_called()
        self.assertEqual(self.consumption()["preparations"], [])

    def test_other_run_and_redirected_workspace_fail_before_build(self):
        other = self.root / ".harness/codegraph/other"
        self.context["paths"]["codegraph_runtime"] = str(other)
        with self.assertRaisesRegex(ValueError, "another run"):
            gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        self.context["paths"].clear()
        runtime = self.root / ".harness/codegraph/gap-run"
        runtime.parent.mkdir(parents=True)
        runtime.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "redirects"):
            gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        self.setup.assert_not_called()

    def test_source_escape_is_an_integrity_failure(self):
        outside = self.root / "private.py"
        outside.write_text("secret")
        (self.source / "escape.py").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes"):
            gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        self.assertEqual(self.consumption()["preparations"][0]["status"], "integrity_failed")
        self.setup.assert_not_called()

    def test_setup_failure_records_exact_source_only_limitation(self):
        self.setup.side_effect = lambda *args: (False, "fixture index refused exit 9")
        with self.assertRaisesRegex(ValueError, "fixture index refused exit 9.*source-only"):
            gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        entry = self.consumption()["preparations"][0]
        self.assertEqual(entry["status"], "unavailable")
        self.assertEqual(entry["limitation"], "fixture index refused exit 9")

    def test_fatal_and_cancelled_setup_do_not_become_optional_success(self):
        for code, status in ((2, "integrity_failed"), (130, "interrupted"), (143, "interrupted")):
            with self.subTest(code=code):
                self.setup.side_effect = SystemExit(code)
                with self.assertRaises(SystemExit) as failure:
                    gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
                self.assertEqual(failure.exception.code, code)
                entry = self.consumption()["preparations"][-1]
                self.assertEqual(entry["status"], status)
                self.assertNotIn("source-only", entry["limitation"])

    def test_shared_query_limit_reserves_and_preserves_lower_resumed_limits(self):
        request = gap_graph.reserve_query(self.context, "GapExploration", self.question)
        self.assertEqual(request["timeout_seconds"], 120)
        with self.assertRaisesRegex(ValueError, "allowance exhausted"):
            gap_graph.reserve_query(self.context, "Worker1", {**self.question, "id": "Q2"})
        request["receipt"] = self.base / "gap-exploration/codegraph-runs/GapExploration/Q1/receipt.json"
        gap_graph.finish_query(request, 17)
        self.context["gap_exploration_budget"]["graph_timeout_seconds"] = 10
        with self.assertRaisesRegex(ValueError, "allowance exhausted"):
            gap_graph.reserve_query(self.context, "Worker1", {**self.question, "id": "Q2"})
        self.assertEqual(self.consumption()["queries"][0]["seconds"], 17)

    def test_interrupted_graph_closure_preserves_reservations_and_accepted_peers(self):
        gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        accepted = self.consumption()["preparations"][0]
        request = gap_graph.reserve_query(self.context, "GapExploration", self.question)
        reason = "Coordinator stopped after descendants terminated; reservation remains consumed."
        self.assertEqual(gap_graph.fail_running(self.context, reason), 1)
        self.assertEqual(gap_graph.fail_running(self.context, reason), 0)
        consumption = self.consumption()
        self.assertEqual(consumption["preparations"][0], accepted)
        self.assertEqual(consumption["queries"][0]["status"], "interrupted")
        self.assertEqual(consumption["queries"][0]["seconds"], request["timeout_seconds"])
        self.assertEqual(consumption["queries"][0]["limitation"], reason)
        with self.assertRaisesRegex(ValueError, "allowance exhausted"):
            gap_graph.reserve_query(self.context, "Worker1", {**self.question, "id": "Q2"})
        with self.assertRaisesRegex(ValueError, "exact failure reason"):
            gap_graph.fail_running(self.context, "")

    def test_wrapper_uses_canonical_gap_owner_and_separate_allowance(self):
        import gap_exploration_contract as gap
        from gap_fixture import GapFixture
        fixture = GapFixture(self.root / "owned")
        (fixture.source / "a.py").write_text("def helper():\n    return 1\n")
        fixture.context["codegraph_mode"] = "enabled"
        fixture.context["gap_exploration_budget"]["graph_timeout_seconds"] = 120
        fixture.persist()
        plan = fixture.plan()
        plan["graph_questions"] = [{
            **self.question, "owner": "GapA", "seed_id": "Seed-GapA", "source_refs": ["a.py:1-2"],
            "reason": "Locate the exact helper caller", "expected_value": "Navigate to the ownership check"}]
        # owner_ref is assigned by the admitted-plan consumer, not authored input.
        plan["graph_questions"][0].pop("owner_ref")
        gap.admit_plan(fixture.context, plan)
        gap.dispatch_worker(fixture.context, "GapA")
        context_path = fixture.root / "context.json"
        with mock.patch.dict(os.environ, {"VULNOPS_RUNTIME_ROOT": str(self.root / "runtime"),
                "VULNOPS_LAUNCHER_PID": str(os.getpid()), "VULNOPS_LAUNCHER_SESSION_ID": "gap-wrapper-fixture"}):
            from run_lifecycle import claim_run
            claim_run(fixture.base)
            request = graph.audit_request(context_path, "gap-exploration", "GapA", "Q1")
        self.assertEqual(request["binding"]["source_view"], "base")
        self.assertEqual(request["binding"]["owner_id"], "GapA")
        self.assertNotIn("budget_ledger", request)
        self.assertEqual(request["timeout_seconds"], 120)
        graph.finish_discovery_query(request, 3)
        dispatch = json.loads((fixture.base / "gap-exploration/dispatch.json").read_text())
        self.assertEqual(dispatch["graph_consumption"]["queries"][0]["seconds"], 3)
        self.assertFalse((fixture.base / "campaign-planning/discovery-budget.json").exists())

    def test_qualified_same_name_binding_keeps_source_view(self):
        project = gap_graph.prepare_navigation(self.context, "GapExploration", self.question)
        binding = graph._binding(self.context, "gap-exploration", "GapExploration", self.question)
        self.assertEqual(binding["source_view"], "base")
        self.assertEqual([row["id"] for row in graph.resolve_subject(binding["operation"], binding["subject"], project, binding["file"])], ["a"])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            graph.resolve_subject("callers", "helper", project)

    def test_failed_query_support_is_retained_but_not_useful_navigation(self):
        directory = graph._question_directory(self.base, "gap-exploration", "GapExploration", "Q1")
        directory.mkdir(parents=True)
        request = {**gap_graph.reserve_query(self.context, "GapExploration", self.question),
                   "output": directory / "context.json", "receipt": directory / "receipt.json",
                   "question": self.question}
        request["output"].write_text("{}")
        request["receipt"].write_text(json.dumps({"status": "failed", "parse_status": "failed",
                                                   "warnings": ["fixture query timeout"]}))
        gap_graph.finish_query(request, 1)
        gap_graph.record_receipt(request)
        self.assertEqual(len(gap_graph.receipt_support(self.context)), 2)
        entry = self.consumption()["queries"][0]
        self.assertEqual(entry["receipt_health"], "failed")
        self.assertFalse(entry["meaningful"])
        self.assertEqual(entry["limitation"], "fixture query timeout")
        request["output"].write_text('{"substituted":true}')
        with self.assertRaisesRegex(ValueError, "changed after wrapper"):
            gap_graph.receipt_support(self.context)

    def test_receipt_rejects_view_owner_and_meaningfulness_substitution(self):
        question = self.question
        directory = graph._question_directory(self.base, "gap-exploration", "GapExploration", "Q1")
        directory.mkdir(parents=True)
        binding = graph._binding(self.context, "gap-exploration", "GapExploration", question)
        completeness = {"local_truncated": False, "dropped_nodes": 0, "dropped_edges": 0,
                        "upstream_truncated": False, "upstream_complete": None, "heuristic": True}
        document = {"schema_version": "2.0", "tool": "codegraph", "operation": "callers", "subject": "helper",
                    "binding": binding, "meaningful": False, "nodes": [{"id": "a", "role": "source", "synthetic": False,
                    "file": "a.py", "line": 1}], "edges": [], "completeness": completeness}
        receipt = {"schema_version": "2.0", "tool": "codegraph", "operation": "callers", "status": "ok", "version": "fixture",
                   "started_at": "fixture", "completed_at": "fixture", "parse_status": "ok", "result_count": 0,
                   "warnings": [], "binding": binding, "completeness": completeness, "meaningful": False, "elapsed_seconds": 1}
        reference = (directory / "receipt.json").relative_to(self.base).as_posix()
        def publish(doc, rec):
            (directory / "context.json").write_text(json.dumps(doc))
            rec["normalized_sha256"] = hashlib.sha256((directory / "context.json").read_bytes()).hexdigest()
            (directory / "receipt.json").write_text(json.dumps(rec))
        with mock.patch.object(graph, "_planned_question", return_value=question):
            publish(document, receipt)
            result = graph.validate_query_receipt(self.base, self.source, self.context, "gap-exploration", "GapExploration", question, reference)
            self.assertFalse(result["meaningful"])
            self.assertIsNone(result["completeness"]["upstream_complete"])
            for field, value in (("source_view", "derived"), ("owner_id", "Worker1")):
                doc, rec = copy.deepcopy(document), copy.deepcopy(receipt)
                doc["binding"][field] = rec["binding"][field] = value
                publish(doc, rec)
                with self.assertRaisesRegex(ValueError, "binding"):
                    graph.validate_query_receipt(self.base, self.source, self.context, "gap-exploration", "GapExploration", question, reference)
            doc, rec = copy.deepcopy(document), copy.deepcopy(receipt)
            doc["meaningful"] = rec["meaningful"] = True
            publish(doc, rec)
            with self.assertRaisesRegex(ValueError, "meaningful"):
                graph.validate_query_receipt(self.base, self.source, self.context, "gap-exploration", "GapExploration", question, reference)
            publish(document, receipt)
            self.context["attempt_id"] = "attempt-2"
            result = graph.validate_query_receipt(self.base, self.source, self.context, "gap-exploration", "GapExploration", question, reference)
            self.assertEqual(result["assessment_scope"], "historical")


class NativeGraphAllocationTests(unittest.TestCase):
    def test_graph_allocation_is_exact_and_never_reads_old_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            context = {"execution_kind": "advantage", "run_id": "new", "scan_base": str(base),
                       "gap_exploration_budget": {"graph_timeout_seconds": 90, "preparation_timeout_seconds": 60}}
            question = {"id": "Q1", "source_view": "derived"}
            operation = {"kind": "graph", "id": "native-1", "phase": "gap-exploration",
                         "owner_id": "Worker1", "question_id": "Q1",
                         "timeout_seconds": 25, "preparation_timeout_seconds": 30}
            with mock.patch("advantage_contract.live_call", return_value={"operation": operation}):
                request = gap_graph.reserve_query(context, "Worker1", question)
                self.assertEqual(request["timeout_seconds"], 25)
                with self.assertRaisesRegex(ValueError, "actual native operation"):
                    gap_graph.reserve_query(context, "ForeignWorker", question)
                operation["timeout_seconds"] = 0
                with self.assertRaisesRegex(ValueError, "exhausted"):
                    gap_graph.reserve_query(context, "Worker1", question)
            self.assertEqual(list(base.iterdir()), [])

    def test_graph_preparation_does_not_forward_private_native_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts/setup-codegraph.sh").write_text(
                "#!/bin/sh\n"
                "if [ \"${VULNOPS_ADVANTAGE_CALL+x}\" = x ]; then exit 91; fi\n"
                "printf 'navigation-only' > \"$VULNOPS_TEST_OBSERVATION\"\n")
            observation = root / "observed"
            with mock.patch.object(gap_graph, "ROOT", root), mock.patch.dict(os.environ, {
                    "VULNOPS_ADVANTAGE_CALL": "fd:3",
                    "VULNOPS_TEST_OBSERVATION": str(observation)}):
                ready, limitation = gap_graph._setup(root / "source", root / "runtime", 30)
            self.assertTrue(ready, limitation)
            self.assertEqual(observation.read_text(), "navigation-only")


if __name__ == "__main__":
    unittest.main()
