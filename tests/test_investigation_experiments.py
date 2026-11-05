"""A19/A20 contracts; mocked wrapper calls never execute target code."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import investigation_experiments as experiments
from harness_contract import resolved_experiment_budget


class InvestigationExperiments(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "scripts").mkdir()
        shutil.copy(ROOT / "scripts/validate-json.py", self.root / "scripts/validate-json.py")
        shutil.copytree(ROOT / "schemas", self.root / "schemas")
        self.scan = self.root / "scans/run"
        self.directory = self.scan / "sast/experiments/parser-binding"
        self.directory.mkdir(parents=True)
        (self.scan / "sast/hunt.json").write_text('{"question":"parser-binding"}')
        self.context = {"schema_version": "2.0", "run_id": "run", "scan_base": str(self.scan),
                        "reproduction_mode": "safe", "attempt_id": "attempt-1",
                        "experiment_budget": resolved_experiment_budget("quick")}
        self.context_path = self.root / "context.json"
        self.request = {"schema_version": "2.0", "run_id": "run", "experiment_id": "parser-binding",
                        "attempt_id": "attempt-1",
                        "owner_phase": "sast", "owner_ref": "sast/hunt.json#question",
                        "obligation": "Does the parser preserve the binding?", "static_limitation": "Framework binding is runtime-dependent.",
                        "behavior": "Parse a synthetic nonsensitive value.", "supports": "Binding preserved.",
                        "contradicts": "Binding discarded.", "input_refs": ["sast/hunt.json"],
                        "dependencies": ["python3"], "execution_policy": "safe_offline_disposable",
                        "interpretation_boundary": "Only synthetic parser binding, not production exposure.",
                        "command": ["python3", "-c", "raise SystemExit(0)"],
                        "support_exit_code": 0, "contradict_exit_code": 1}
        self.request_path = self.directory / "request.json"
        self.write_inputs()
        self.root_patch = patch.object(experiments, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.environment = patch.dict("os.environ", {"VULNOPS_RUNTIME_ROOT": str(self.root / ".harness")})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.owner_patch = patch.object(experiments, "assert_owner")
        self.owner_patch.start()
        self.addCleanup(self.owner_patch.stop)

    def write_inputs(self):
        self.context_path.write_text(json.dumps(self.context))
        (self.scan / "run-manifest.json").write_text(json.dumps({**self.context, "phases": {"sast": "running"}}))
        self.request_path.write_text(json.dumps(self.request))

    def execute(self, codes):
        with patch.object(experiments.subprocess, "run", side_effect=[subprocess.CompletedProcess([], code) for code in codes]) as wrapper:
            result = json.loads(experiments.run(self.context_path, self.request_path).read_text())
        return result, wrapper

    def test_a19_preconfirmation_without_patch(self):
        result, wrapper = self.execute([0, 0, 0, 0])
        self.assertEqual(result["status"], "supported")
        self.assertEqual(result["resolution"]["outcome"], "established")
        self.assertNotIn("patch_ref", result)
        self.assertNotIn("finding_id", result)
        self.assertEqual([call.args[0][3] for call in wrapper.call_args_list], ["detect", "prepare", "exec", "clean"])
        call = wrapper.call_args_list[2]
        self.assertEqual(call.args[0][4:], ["--", *self.request["command"]])
        self.assertEqual(call.kwargs["env"]["VULNOPS_REPRODUCTION_MAX_OUTPUT_KB"], "256")
        self.assertEqual(call.kwargs["stdout"], subprocess.DEVNULL)
        self.assertNotIn("HOME", call.kwargs["env"])
        with patch.object(experiments.subprocess, "run") as replay:
            experiments.run(self.context_path, self.request_path)
            replay.assert_not_called()
        original_result = (self.directory / "result.json").read_bytes()
        self.request["command"] = ["python3", "-c", "raise SystemExit(1)"]
        self.request_path.write_text(json.dumps(self.request))
        with patch.object(experiments.subprocess, "run") as replay:
            with self.assertRaisesRegex(ValueError, "request"):
                experiments.run(self.context_path, self.request_path)
            replay.assert_not_called()
        self.assertEqual((self.directory / "result.json").read_bytes(), original_result)

    def test_a20_disabled_executes_nothing(self):
        self.context["reproduction_mode"] = "off"
        self.write_inputs()
        result, wrapper = self.execute([])
        wrapper.assert_not_called()
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(result["resolution"]["outcome"], "locally_unresolved")
        self.assertEqual(result["sandbox"], "none")

    def test_a20_unavailable_has_no_fallback(self):
        result, wrapper = self.execute([1])
        self.assertEqual(result["status"], "containment_unavailable")
        self.assertEqual(result["resolution"]["outcome"], "externally_blocked")
        self.assertEqual(len(wrapper.call_args_list), 1)
        self.assertTrue(result["resolution"]["missing_fact"])

    def test_contradiction_and_execution_failure_are_distinct(self):
        result, _ = self.execute([0, 0, 1, 0])
        self.assertEqual(result["resolution"]["outcome"], "contradicted")
        (self.directory / "result.json").unlink()
        # Reservation survives interruption; an absent result never causes re-execution.
        result, wrapper = self.execute([])
        self.assertEqual(result["resolution"]["outcome"], "execution_failed")
        wrapper.assert_not_called()

    def test_owner_reference_escape_rejected_before_dispatch(self):
        self.request["owner_ref"] = "../outside.json"
        self.write_inputs()
        with self.assertRaises(ValueError), patch.object(experiments.subprocess, "run") as wrapper:
            experiments.run(self.context_path, self.request_path)
        wrapper.assert_not_called()

    def test_finalized_owner_is_immutable(self):
        manifest = {**self.context, "phases": {"sast": "ok"}}
        (self.scan / "run-manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError), patch.object(experiments.subprocess, "run") as wrapper:
            experiments.run(self.context_path, self.request_path)
        wrapper.assert_not_called()


    def test_new_attempt_can_retry_recreated_owner_with_remaining_budget(self):
        result, _ = self.execute([0, 0, 2, 0])
        self.assertEqual(result["status"], "execution_failed")
        (self.directory / "result.json").unlink()
        self.context["attempt_id"] = self.request["attempt_id"] = "attempt-2"
        self.write_inputs()
        result, wrapper = self.execute([0, 0, 0, 0])
        self.assertEqual(result["status"], "supported")
        self.assertEqual(len(wrapper.call_args_list), 4)

    def test_budget_funds_distinct_obligations_not_replayed_setup(self):
        with self.subTest(allowance=0):
            self.context["experiment_budget"]["max_experiments"] = 0
            self.write_inputs()
            result, wrapper = self.execute([])
            self.assertEqual(result["status"], "budget_deferred")
            wrapper.assert_not_called()
        self.context["experiment_budget"]["max_experiments"] = 2
        for index in range(3):
            self.request["experiment_id"] = "binding-" + str(index)
            self.request["obligation"] = "Named binding obligation " + str(index)
            self.directory = self.scan / "sast/experiments" / self.request["experiment_id"]
            self.directory.mkdir()
            self.request_path = self.directory / "request.json"
            self.write_inputs()
            result, wrapper = self.execute([0, 0, 0, 0] if index < 2 else [])
            self.assertEqual(result["status"], "supported" if index < 2 else "budget_deferred")
            self.assertEqual(len(wrapper.call_args_list), 4 if index < 2 else 0)
        attempts = json.loads((self.root / "work/run/experiments/experiment-attempts.json").read_text())
        self.assertEqual(len(attempts), 2)

    def test_result_cannot_broaden_observation(self):
        result, _ = self.execute([0, 0, 0, 0])
        result["resolution"]["reason"] = "Production exposure established."
        with self.assertRaises(ValueError):
            experiments.validate_result(self.context, self.request, result, self.request_path)

    def test_historical_result_uses_recorded_limits_and_containment(self):
        result, _ = self.execute([0, 0, 0, 0])
        self.context["attempt_id"] = "attempt-2"
        self.context["reproduction_mode"] = "off"
        self.context["experiment_budget"] = {**self.context["experiment_budget"], "max_experiments": 0}
        self.assertEqual(experiments.validate_result(self.context, self.request, result, self.request_path), "historical")
        result["sandbox"] = "none"
        with self.assertRaisesRegex(ValueError, "contained execution"):
            experiments.validate_result(self.context, self.request, result, self.request_path)

    def test_foreign_attempt_does_not_execute(self):
        self.request["attempt_id"] = "earlier-attempt"
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "current attempt"), patch.object(experiments.subprocess, "run") as wrapper:
            experiments.run(self.context_path, self.request_path)
        wrapper.assert_not_called()

    def test_reduced_budget_preserves_consumption_across_attempts(self):
        self.execute([0, 0, 0, 0])
        self.context["attempt_id"] = self.request["attempt_id"] = "attempt-2"
        self.context["experiment_budget"]["max_experiments"] = 1
        self.request["experiment_id"] = "new-obligation"
        self.directory = self.scan / "sast/experiments/new-obligation"
        self.directory.mkdir()
        self.request_path = self.directory / "request.json"
        self.write_inputs()
        result, wrapper = self.execute([])
        self.assertEqual(result["status"], "budget_deferred")
        wrapper.assert_not_called()

    def test_backend_prepares_current_copy_without_source_fingerprint(self):
        shutil.copytree(ROOT / "scripts", self.root / "scripts", dirs_exist_ok=True)
        (self.root / "scripts/harness-lib.sh").write_text(
            "harness_setup_containment(){ :; }\n"
            "harness_require_allowed_output(){ :; }\n"
            "harness_require_inside_root(){ :; }\n")
        probe = self.root / "scripts/probe-bubblewrap.sh"
        probe.write_text("#!/bin/sh\necho bubblewrap\n")
        probe.chmod(0o755)
        source = self.root / "source"
        source.mkdir()
        file = source / "module.txt"
        file.write_text("current synthetic source\n")
        self.context["repo_path"] = str(source)
        self.write_inputs()
        command = ["bash", str(self.root / "scripts/safe-reproduction-backend.sh"),
                   str(self.scan), "experiment-sast-parser-binding", "prepare"]
        environment = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(self.context_path),
                       "VULNOPS_EXPERIMENT_PHASE": "sast", "VULNOPS_REPRODUCTION_SANDBOX": "bubblewrap"}
        prepared = subprocess.run(command, env=environment, capture_output=True, text=True)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        copy = Path(prepared.stdout.strip()) / "module.txt"
        self.assertEqual(copy.read_bytes(), file.read_bytes())
        file.write_text("edited current synthetic source\n")
        prepared = subprocess.run(command, env=environment, capture_output=True, text=True)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertEqual(copy.read_bytes(), file.read_bytes())
        self.context["reproduction_mode"] = "off"
        self.write_inputs()
        disabled = subprocess.run(command, env=environment, capture_output=True, text=True)
        self.assertNotEqual(disabled.returncode, 0)
        self.assertIn("disabled", disabled.stderr)

class NativeInvestigationExperiments(unittest.TestCase):
    """Synthetic native containment authority; no target command is executed."""
    setUp = InvestigationExperiments.setUp
    write_inputs = InvestigationExperiments.write_inputs
    execute = InvestigationExperiments.execute

    def native_inputs(self):
        self.context.update(execution_kind="advantage", source_run_id="baseline")
        immutable_input = patch("advantage_contract.load_context", return_value=self.context)
        immutable_input.start()
        self.addCleanup(immutable_input.stop)
        self.directory = self.scan / "investigation/experiments/parser-binding"
        self.directory.mkdir(parents=True)
        packet = self.scan / "investigation/packets/Task1.json"
        packet.parent.mkdir()
        packet.write_text("{}")
        self.request.update(execution_kind="advantage", owner_phase="investigation",
            owner_id="Task1", question_id="Question1", source_view="base", baseline_execution_id="baseline",
            owner_ref="investigation/packets/Task1.json", input_refs=["source.py:1"])
        self.request_path = self.directory / "request.json"
        self.context_path.write_text(json.dumps(self.context))
        self.request_path.write_text(json.dumps(self.request))
        (self.scan / "run-manifest.json").unlink()
        import advantage_contract as core
        operation = {"id": "native-experiment", "kind": "experiment", "phase": "investigation",
                     "owner_id": "Task1", "question_id": "Question1",
                     "request_ref": self.request_path.relative_to(self.scan).as_posix(),
                     "request_sha256": core.sha256_file(self.request_path),
                     "timeout_seconds": self.context["experiment_budget"]["timeout_seconds"]}
        return operation

    def test_native_experiment_uses_no_persisted_or_inherited_reservations(self):
        operation = self.native_inputs()
        old = self.root / "work/run/experiments-generation-old/experiment-attempts.json"
        old.parent.mkdir(parents=True)
        old.write_text("unreadable old reservations")
        with patch("advantage_contract.live_call", return_value={"operation": operation}), \
                patch("advantage_owners.validate_experiment"), \
                patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": "fd:3"}), \
                patch("advantage_contract.run_native",
                      side_effect=lambda command, context, **kwargs: experiments.subprocess.run(command, **kwargs)):
            result, _ = self.execute([0, 0, 0, 0])
        self.assertEqual(result["status"], "supported")
        self.assertFalse((self.root / "work/run/experiments/experiment-attempts.json").exists())
        self.assertFalse((self.root / "work/run/experiments/experiment.lock").exists())
        self.assertEqual(old.read_text(), "unreadable old reservations")

    def test_native_experiment_rejects_foreign_request_before_backend(self):
        operation = self.native_inputs()
        operation["request_sha256"] = "0" * 64
        with patch("advantage_contract.live_call", return_value={"operation": operation}), \
                patch("advantage_owners.validate_experiment"), patch.object(experiments.subprocess, "run") as wrapper:
            with self.assertRaisesRegex(ValueError, "exact native request"):
                experiments.run(self.context_path, self.request_path)
        wrapper.assert_not_called()


if __name__ == "__main__":
    unittest.main()
