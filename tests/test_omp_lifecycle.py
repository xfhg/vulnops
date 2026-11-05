"""Synthetic event-parser oracles and local subprocess/resource cleanup tests.

No case here dispatches a native OMP task or proves installed-runtime readiness.
"""
from __future__ import annotations

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
from model_routing import GROUP_AGENTS
spec = importlib.util.spec_from_file_location("omp_lifecycle", ROOT / "scripts/probe-omp-lifecycle.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def call(name, arguments):
    return {"role": "assistant", "content": [{"type": "toolCall", "name": name, "arguments": arguments}]}


def spawn(*names):
    return call("task", {"context": "fixture", "tasks": [
        {"name": name, "task": "fixture", "solutionSpace": "fixed", "schemaMode": "strict"}
        for name in names]})


def delivery(name, data=None, status="valid", content="terminal delivery"):
    return {"role": "custom", "customType": "async-result", "content": content,
            "details": {"jobs": [{"jobId": name, "type": "task", "schema": {
                "mode": "strict", "status": status, "data": data}}]}}


class LifecycleTests(unittest.TestCase):
    def success(self):
        parent = [spawn("Coordinator"), delivery("Coordinator", {"status": "ok"})]
        coordinator = [spawn("Slow", "Fast"), delivery("Coordinator.Fast", {"worker": "Fast"}),
                       delivery("Coordinator.Slow", {"worker": "Slow"}),
                       call("yield", {"data": {"status": "ok"}})]
        return parent, coordinator

    def test_parser_requires_strict_child_deliveries_before_yield(self):
        parent, coordinator = self.success()
        probe.validate_delivery(parent, coordinator, "success")
        for broken in (coordinator[:2] + coordinator[3:],
                       coordinator[:2] + [coordinator[3], coordinator[2]],
                       [coordinator[0], coordinator[2], coordinator[1], coordinator[3]]):
            with self.assertRaises(probe.ProbeFailure):
                probe.validate_delivery(parent, broken, "success")
        with self.assertRaisesRegex(probe.ProbeFailure, "missing_coordinator_delivery"):
            probe.validate_delivery(parent[:1], coordinator, "success")
        with self.subTest(case="permissive-child"):
            parent, coordinator = self.success()
            coordinator[1]["details"]["jobs"][0]["schema"]["mode"] = "permissive"
            with self.assertRaises(probe.ProbeFailure):
                probe.validate_delivery(parent, coordinator, "success")

    def test_parser_accepts_wait_terminal_results_without_async_delivery(self):
        parent, coordinator = self.success()
        for records in (parent, coordinator):
            for index, msg in enumerate(records):
                if msg.get("customType") != "async-result":
                    continue
                job = msg["details"]["jobs"][0]
                records[index] = {
                    "role": "toolResult", "toolName": "wait", "isError": False,
                    "details": {"op": "wait", "jobs": [{
                        "id": job["jobId"], "type": "task", "status": "completed",
                        "structured": job["schema"],
                    }, {"id": "Pending", "type": "task", "status": "running"}]},
                }
        probe.validate_delivery(parent, coordinator, "success")
        coordinator[2] = delivery("Slow", {"worker": "Slow"})
        probe.validate_delivery(parent, coordinator, "success")
        parent[1]["details"]["jobs"][0]["status"] = "running"
        with self.assertRaisesRegex(probe.ProbeFailure, "missing_coordinator_delivery"):
            probe.validate_delivery(parent, coordinator, "success")

    def test_parser_requires_invalid_output_evidence_not_preflight(self):
        parent = [spawn("Coordinator"), delivery("Coordinator", {"status": "rejected"})]
        coordinator = [spawn("Invalid"), delivery("Coordinator.Invalid", {"worker": 123}, "invalid"),
                       call("yield", {"data": {"status": "rejected"}})]
        probe.validate_delivery(parent, coordinator, "invalid")
        for status in ("unavailable", "valid"):
            coordinator[1]["details"]["jobs"][0]["schema"]["status"] = status
            with self.assertRaisesRegex(probe.ProbeFailure, "invalid_output_not_rejected"):
                probe.validate_delivery(parent, coordinator, "invalid")

    def test_parser_distinguishes_cancel_and_deadline_evidence(self):
        coordinator = [spawn("Hold")]
        parent = [spawn("Coordinator"), call("write", {"path": "proc://Coordinator/kill"}),
                  delivery("Coordinator", status="unavailable")]
        probe.validate_delivery(parent, coordinator, "cancel")
        with self.assertRaisesRegex(probe.ProbeFailure, "native_deadline_not_observed"):
            probe.validate_delivery(parent, coordinator, "timeout")
        parent = [parent[0], delivery("Coordinator", status="unavailable",
                                    content="Subagent runtime limit exceeded (task.maxRuntimeMs=60000)")]
        probe.validate_delivery(parent, coordinator, "timeout")
        with self.assertRaisesRegex(probe.ProbeFailure, "missing_native_cancellation"):
            probe.validate_delivery(parent, coordinator, "cancel")

    def test_parser_decodes_events_and_persisted_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            msg = delivery("Coordinator", {"status": "ok"})
            for event in ({"type": "message_end", "message": msg},
                          {"type": "message", "message": msg},
                          {"type": "custom_message", **msg}):
                path.write_text(json.dumps(event) + "\n")
                self.assertEqual(probe.deliveries(probe.messages(path))[0][1]["jobId"], "Coordinator")
            for text in ('{"type":', '[]\n', '{"type":"message","message":null}\n'):
                path.write_text(text)
                with self.assertRaisesRegex(probe.ProbeFailure, "invalid_event_stream"):
                    probe.messages(path)

    def test_outer_timeout_stops_uncooperative_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            program = ("import os,signal,time; "
                       "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                       "open('pid','w').write(str(os.getpid())); time.sleep(60)")
            with self.assertRaisesRegex(probe.ProbeFailure, "outer_deadline"):
                probe.run_bounded([sys.executable, "-c", program], base, base / "events", .5)
            pid = int((base / "pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_runtime_failure_is_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self.assertRaisesRegex(probe.ProbeFailure, "^runtime_or_provider_failed$"):
                probe.run_bounded([sys.executable, "-c", "raise SystemExit('secret-provider-error')"],
                                  base, base / "events", 5)

    def test_fixture_removed_on_failure_and_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".harness").mkdir()
            (root / "config.toml").write_text("[llm.routing]\n" + "\n".join(
                f'{group} = "test/controller:high"' for group in GROUP_AGENTS))
            for failure in (True, False):
                def runtime(command, cwd, output, timeout):
                    if failure:
                        raise probe.ProbeFailure("outer_deadline")
                    parent, coordinator = self.success()
                    output.write_text("".join(json.dumps({"type": "message_end", "message": m}) + "\n"
                                              for m in parent))
                    (cwd / "Coordinator.jsonl").write_text("".join(
                        json.dumps({"type": "message", "message": m}) + "\n" for m in coordinator))
                with patch.object(probe, "run_bounded", side_effect=runtime):
                    if failure:
                        with self.assertRaises(probe.ProbeFailure):
                            probe.probe(root, "task,wait", "success", 5)
                    else:
                        probe.probe(root, "task,wait", "success", 5)
                self.assertEqual(list((root / ".harness").iterdir()), [])

    def test_failed_cancellation_cleans_holder_without_claiming_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".harness").mkdir()
            (root / "config.toml").write_text("[llm.routing]\n" + "\n".join(
                f'{group} = "test/controller:high"' for group in GROUP_AGENTS))
            holder = probe.subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                def runtime(command, cwd, output, timeout):
                    (cwd / "holding.pid").write_text(str(holder.pid))
                    parent = [spawn("Coordinator"),
                              call("write", {"path": "proc://Coordinator/kill"}),
                              delivery("Coordinator", status="unavailable")]
                    output.write_text("".join(json.dumps({"type": "message_end", "message": m}) + "\n"
                                              for m in parent))
                    (cwd / "Coordinator.jsonl").write_text(
                        json.dumps({"type": "message", "message": spawn("Hold")}) + "\n")
                with patch.object(probe, "run_bounded", side_effect=runtime):
                    with self.assertRaisesRegex(probe.ProbeFailure, "descendant_not_stopped"):
                        probe.probe(root, "task,wait", "cancel", 5)
                self.assertLess(holder.wait(timeout=5), 0)
                self.assertEqual(list((root / ".harness").iterdir()), [])
            finally:
                if holder.poll() is None:
                    holder.kill()
                    holder.wait()


if __name__ == "__main__":
    unittest.main()
