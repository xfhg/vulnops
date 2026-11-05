"""Fresh linked intake with trusted synthetic native observations, never model work."""
from __future__ import annotations

import copy
from contextlib import contextmanager
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
from advantage_contract import (PHASES, check_identity, envelope, load, load_context,
                                resolve_reference, sha256_file, validate_phase)
from advantage_baseline import admit_action_source, build_catalog, catalog_records
from advantage_lifecycle import cleanup, context_document, initialize, parser_for, resolve_source
from advantage_native_fixture import native_call, native_controller, native_worker
from test_redteam_workflow import exercise_pipeline


def tree_hashes(directory: Path) -> dict:
    return {str(path.relative_to(directory)): sha256_file(path)
            for path in directory.rglob("*") if path.is_file()}


def empty_gap_phase(context: dict) -> None:
    """Build empty analytical gap evidence under explicitly synthetic authority."""
    import gap_exploration_contract as gap
    with native_call(context, "gap-exploration"):
        if context["gap_exploration_budget"]["enabled"] and context["mode"] != "actions":
            prepared = gap.prepare_inputs(context)
            gap.admit_plan(context, gap.envelope(
                context, inputs=prepared["inputs"], budget=prepared["budget"], objectives=[],
                questions=[], seeds=[], assignments=[], graph_questions=[]))
        gap.finalize_phase(context)
        validate_phase(context["scan_base"], "gap-exploration", context)


def empty_linked_execution(context: dict, *, stop_before_report: bool = False,
                           stop_before_phase: str | None = None) -> Path:
    """Build real empty products; phase authority is a trusted synthetic fixture.

    No model/native execution is claimed. The caller may stop at an evidence
    boundary, but calling this helper again does not resume an earlier operation.
    """
    import advantage_pipeline as pipeline
    from advantage_actions import finalize_handoff
    base = Path(context["scan_base"])
    if stop_before_phase == "planning":
        return base
    with native_call(context, "planning"):
        draft = envelope(context, status="empty", reason="No additional actionable source-backed questions.",
                         provenance={"execution_id": context["run_id"], "actor": "vulnops-advantage-planning",
                                     "selector": context["model_routing"]["agents"]["vulnops-advantage-planning"],
                                     "artifact_ref": "planning/plan.json"},
                         objectives=[], questions=[], passes=[], assignments=[])
        pipeline.build_plan(context, draft)
        validate_phase(base, "planning", context)
    for phase, callback in (("investigation", pipeline.finalize_investigation),
                            ("synthesis", pipeline.finalize_synthesis),
                            ("final-verification", pipeline.finalize_verification)):
        if phase == stop_before_phase:
            return base
        with native_call(context, phase):
            callback(context)
            validate_phase(base, phase, context)
        if phase == "investigation":
            if stop_before_phase == "gap-exploration":
                return base
            empty_gap_phase(context)
    if stop_before_phase == "handoff":
        return base
    with native_call(context, "handoff"):
        finalize_handoff(base, context)
        validate_phase(base, "handoff", context)
    if stop_before_report or stop_before_phase == "report":
        return base
    with native_call(context, "report"):
        pipeline.render_report(context)
        validate_phase(base, "report", context)
        cleanup(context)
    return base


class AdvantageLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_directory = tempfile.TemporaryDirectory(prefix="advantage-audit-fixture-", dir=ROOT / "scans")
        cls.addClassCleanup(cls.fixture_directory.cleanup)
        cls.audit = exercise_pipeline(Path(cls.fixture_directory.name), git_identity=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="advantage-lifecycle-", dir=ROOT / "scans")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "source"
        self.scan = self.directory / load(self.audit["scan"] / "report/security-report.json")["run_id"]
        shutil.copytree(self.audit["source"], self.source)
        shutil.copytree(self.audit["scan"], self.scan)
        # A deliberately obsolete pointer. New intake must neither read nor write it.
        self.context_path = self.directory / "old-advantage-context.json"
        self.environment = patch.dict(os.environ, {
            "VULNOPS_ADVANTAGE_CONTEXT": str(self.context_path),
            "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "fixture-session",
            "VULNOPS_LAUNCHER_SESSION_ID": "fixture-session",
            "VULNOPS_LAUNCHER_PID": str(os.getpid()),
            "VULNOPS_RUNTIME_ROOT": str(self.directory / "runtime")})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.controller = native_controller()
        self.controller.__enter__()
        self.addCleanup(self.controller.__exit__, None, None, None)
        self.before = tree_hashes(self.scan)
        self.source_before = tree_hashes(self.source)

    def init(self, *options):
        args = parser_for("init").parse_args([str(self.scan), "--source-root", str(self.source), *options])
        return initialize(args)

    def cli(self, script, *arguments, succeeds=True):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, arguments)],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode == 0, succeeds, result.stderr + result.stdout)
        return result

    def assert_sources_unchanged(self):
        self.assertEqual(tree_hashes(self.scan), self.before)
        self.assertEqual(tree_hashes(self.source), self.source_before)

    @contextmanager
    def prepared_session(self):
        """Prepare disposable harness configuration, never operator auth."""
        from model_routing import load_routing
        routing = load_routing(ROOT)
        config = ["[harness]", 'default_depth = "balanced"', "[harness.reproduction]", 'mode = "off"',
                  "[harness.network]", 'linux_agent_egress = "policy_only"', "[llm.routing]"]
        config.extend(f'{group} = "{selector}"' for group, selector in routing["groups"].items())
        (self.directory / "config.toml").write_text("\n".join(config) + "\n")
        project = self.directory / ".omp/config.yml"
        project.parent.mkdir()
        project.write_text("task:\n  agentModelOverrides:\n" + "".join(
            f"    {actor}: '{selector}'\n" for actor, selector in routing["agents"].items()))
        overlay = self.directory / ".harness/tmp/omp-runtime-fixture.json"
        overlay.parent.mkdir(parents=True)
        overlay.write_text('{"task":{"maxRuntimeMs":1}}\n')
        environment = {
            "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "",
            "VULNOPS_LAUNCHER_SESSION_ID": "fixture-session",
            "VULNOPS_OMP_CONTROLLER_SELECTOR": routing["controllers"]["advantage"],
            "VULNOPS_MODEL_ROUTING": json.dumps(routing),
            "VULNOPS_OMP_RUNTIME_CONFIG": str(overlay),
            "VULNOPS_PROJECT_OMP_CONFIG": str(project),
            "PI_CODING_AGENT_DIR": str(project.parent),
            "VULNOPS_AUDIT_CONTEXT": str(self.directory / "audit-context.json")}
        with patch.dict(os.environ, environment), patch("advantage_lifecycle.ROOT", self.directory):
            yield overlay

    def test_repeated_identical_requests_ignore_every_old_execution_state(self):
        first = self.init("--mode", "standard")
        old = Path(first["scan_base"])
        self.context_path.write_text("{malformed stale pointer")
        identities = {first["run_id"]}
        for label, payload in (("missing", None), ("partial", "{"), ("corrupt", "[]"),
                               ("failed", '{"status":"failed","attempts":999999}'),
                               ("complete", '{"status":"complete"}')):
            with self.subTest(previous=label):
                control = old / "advantage-manifest.json"
                if payload is None:
                    control.unlink(missing_ok=True)
                else:
                    control.write_text(payload)
                (old / "task-ledger.json").write_text("{corrupt prior task bookkeeping")
                (old / "recovery-journal.json").write_text("old interruption")
                before = tree_hashes(old)
                real_open = Path.open

                def forbid_old_reads(path, mode="r", *args, **kwargs):
                    if "r" in mode and (path == self.context_path or path.is_relative_to(old)):
                        raise AssertionError(f"fresh intake read obsolete state: {path}")
                    return real_open(path, mode, *args, **kwargs)

                with patch.object(Path, "open", forbid_old_reads):
                    fresh = self.init("--mode", "standard")
                self.assertNotIn(fresh["run_id"], identities)
                identities.add(fresh["run_id"])
                self.assertNotEqual(fresh["input_path"], first["input_path"])
                self.assertTrue(fresh["assessment_id"])
                self.assertNotEqual(fresh["assessment_id"], first["assessment_id"])
                self.assertEqual(tree_hashes(old), before)
        self.assertEqual(self.context_path.read_text(), "{malformed stale pointer")
        self.assert_sources_unchanged()

    def test_complete_and_deleted_previous_products_never_select_continuation(self):
        first = self.init()
        old = empty_linked_execution(first)
        before = tree_hashes(old)
        second = self.init()
        self.assertNotEqual(second["run_id"], first["run_id"])
        self.assertEqual(tree_hashes(old), before)
        shutil.rmtree(old)
        third = self.init()
        self.assertEqual(len({first["run_id"], second["run_id"], third["run_id"]}), 3)
        self.assert_sources_unchanged()

    def test_immutable_inputs_are_explicit_isolated_and_have_no_control_history(self):
        first, second = self.init(), self.init()
        first_path, second_path = Path(first["input_path"]), Path(second["input_path"])
        original = first_path.read_bytes()
        self.assertNotEqual(first_path, second_path)
        self.assertNotEqual(first["attempt_id"], second["attempt_id"])
        for context in (first, second):
            with native_call(context, "baseline"):
                self.assertEqual(load_context(context["input_path"]), context)
            for field in ("recovery_count", "attempt_contexts", "phase_attempts", "phases", "status"):
                self.assertNotIn(field, context)
            for filename in ("advantage-manifest.json", "task-ledger.json", "dispatch.json", "phase-manifest.json"):
                self.assertFalse(list(Path(context["scan_base"]).rglob(filename)))
        with self.assertRaisesRegex(ValueError, "explicit"):
            load_context()
        empty_linked_execution(first, stop_before_report=True)
        self.assertEqual(first_path.read_bytes(), original)
        self.assertEqual(load(second_path), second)
        self.assertFalse(self.context_path.exists())
        self.assert_sources_unchanged()

    def test_input_mutation_after_native_install_is_rejected(self):
        context = self.init()
        path = Path(context["input_path"])
        before = path.read_bytes()
        with native_call(context, "planning") as call:
            self.assertEqual(call["context_sha256"], sha256_file(path))
            self.assertNotIn("context_sha256", load(path))
            changed = load(path)
            changed["options"]["hardening"] = True
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "immutable Advantage input changed"):
                load_context(path)
            path.write_bytes(before)
            self.assertEqual(load_context(path), context)
        self.assert_sources_unchanged()

    def test_direct_foreign_stale_and_wrong_phase_calls_cannot_publish(self):
        import advantage_pipeline as pipeline
        from test_advantage_pipeline import empty_plan
        first, second = self.init(), self.init()
        base = Path(second["scan_base"])
        before = tree_hashes(base)
        environments = ({"VULNOPS_ADVANTAGE_CALL": ""},
                        {"VULNOPS_ADVANTAGE_CALL": "{}"})
        for environment in environments:
            with patch.dict(os.environ, environment), self.assertRaises(ValueError):
                pipeline.build_plan(second, empty_plan(second))
        with native_call(first, "planning"), self.assertRaisesRegex(ValueError, "another"):
            pipeline.build_plan(second, empty_plan(second))
        foreign = {**second, "launcher_session_id": "foreign-session"}
        with native_call(foreign, "planning"), self.assertRaisesRegex(ValueError, "another"):
            pipeline.build_plan(second, empty_plan(second))
        with native_call(second, "investigation"), self.assertRaisesRegex(ValueError, "phase"):
            pipeline.build_plan(second, empty_plan(second))
        self.assertEqual(tree_hashes(base), before)
        self.assert_sources_unchanged()

    def test_native_fixture_distinguishes_failure_from_unlaunched_work(self):
        from advantage_contract import live_call
        context = self.init()
        failed = native_worker(context, "investigation", "TASK-FAILED", status="failed",
                               yield_valid=False, error="Synthetic child exited before publication.")
        with native_call(context, "investigation", workers=[failed]):
            rows = live_call(context)["workers"]
            self.assertEqual([row["id"] for row in rows], ["TASK-FAILED"])
            self.assertFalse(any(row["id"] == "TASK-UNLAUNCHED" for row in rows))
            self.assertEqual(rows[0]["status"], "failed")
        with self.assertRaisesRegex(ValueError, "actual native state"):
            native_worker(context, "investigation", "TASK-UNLAUNCHED", status="planned")
        fresh = self.init()
        with native_call(fresh, "investigation"):
            self.assertEqual(live_call(fresh)["workers"], [])

    def test_teardown_removes_owned_scratch_only_and_is_idempotent(self):
        first, second = self.init(), self.init()
        evidence = tree_hashes(Path(first["scan_base"]))
        other_input = Path(second["input_path"]).read_bytes()
        runtime_root = self.directory / "confined-harness"
        owned = [runtime_root / root / first["run_id"]
                 for root in ("work/advantage", ".harness/codegraph")]
        neighbors = [runtime_root / root / second["run_id"]
                     for root in ("work/advantage", ".harness/codegraph")]
        for path in owned + neighbors:
            path.mkdir(parents=True)
            (path / "keep.txt").write_text("synthetic scratch")
        shared = runtime_root / ".harness/shared-auth.json"
        shared.write_text("untouched host asset")
        with patch("advantage_lifecycle.ROOT", runtime_root):
            with native_call(first, "report"):
                cleanup(first)
                cleanup(first)
        self.assertFalse(Path(first["input_path"]).exists())
        self.assertTrue(all(not path.exists() for path in owned))
        self.assertTrue(all((path / "keep.txt").is_file() for path in neighbors))
        self.assertEqual(Path(second["input_path"]).read_bytes(), other_input)
        self.assertEqual(shared.read_text(), "untouched host asset")
        self.assertEqual(tree_hashes(Path(first["scan_base"])), evidence)
        self.assert_sources_unchanged()

    def test_teardown_does_not_require_the_current_source(self):
        context = self.init()
        evidence = tree_hashes(Path(context["scan_base"]))
        moved = self.directory / "temporarily-unavailable-source"
        self.source.rename(moved)
        try:
            with native_call(context, "investigation"):
                cleanup(context)
            self.assertFalse(Path(context["input_path"]).exists())
            self.assertEqual(tree_hashes(Path(context["scan_base"])), evidence)
        finally:
            moved.rename(self.source)
        self.assert_sources_unchanged()

    def test_teardown_rejects_foreign_input_and_symlink_scratch(self):
        first, second = self.init(), self.init()
        with native_call(first, "report"), self.assertRaisesRegex(ValueError, "does not belong"):
            cleanup({**first, "input_path": second["input_path"]})
        runtime_root = self.directory / "confined-harness"
        work = runtime_root / "work/advantage"
        work.mkdir(parents=True)
        outside = self.directory / "outside-scratch"
        outside.mkdir()
        (outside / "keep.txt").write_text("unowned")
        (work / first["run_id"]).symlink_to(outside, target_is_directory=True)
        with patch("advantage_lifecycle.ROOT", runtime_root), native_call(first, "report"):
            with self.assertRaises(ValueError):
                cleanup(first)
        self.assertEqual((outside / "keep.txt").read_text(), "unowned")
        self.assertTrue(Path(first["input_path"]).is_file())
        self.assertTrue(Path(second["input_path"]).is_file())

    def test_advantage_defaults_and_independent_overrides(self):
        with self.prepared_session():
            context = self.init("--in-session")
            self.assertEqual((context["mode"], context["depth"]), ("deep", "full"))
            self.assertEqual(context["budget"]["max_tasks"], 64)
            self.assertEqual(context["launcher_session_id"], "fixture-session")
            standard = self.init("--in-session", "--mode", "standard")
            self.assertEqual(standard["depth"], "full")
            quick = self.init("--in-session", "--depth", "quick")
            self.assertEqual((quick["mode"], quick["depth"]), ("deep", "quick"))
            self.assertEqual(len({context["run_id"], standard["run_id"], quick["run_id"]}), 3)
            self.assert_sources_unchanged()

    def test_failed_and_cancelled_invocations_release_only_their_input(self):
        for status, phase in (("failed", "investigation"), ("cancelled", "report")):
            with self.subTest(status=status):
                context = self.init()
                fresh = self.init()
                evidence = tree_hashes(Path(context["scan_base"]))
                observation = native_worker(
                    context, "investigation", "TASK-STOPPED", status=status,
                    yield_valid=False, error="Synthetic invocation stopped.")
                with native_call(context, phase, workers=[observation]):
                    cleanup(context)
                self.assertFalse(Path(context["input_path"]).exists())
                self.assertTrue(Path(fresh["input_path"]).is_file())
                self.assertEqual(tree_hashes(Path(context["scan_base"])), evidence)
        self.assert_sources_unchanged()

    def test_in_session_exact_id_and_live_baseline_selection(self):
        from advantage_lifecycle import prepare_in_session
        run_id = load(self.scan / "report/security-report.json")["run_id"]
        with self.prepared_session():
            located = self.directory / "scans/application/runs" / run_id
            shutil.copytree(self.scan, located)
            args = parser_for("init").parse_args(["--in-session", run_id])
            self.assertEqual(prepare_in_session(args), "fixture-session")
            self.assertEqual(resolve_source(args.source_scan), located.resolve())
            with native_controller(baseline=self.scan):
                self.assertEqual(resolve_source(None), self.scan.resolve())
            with self.assertRaisesRegex(ValueError, "live baseline is absent"):
                resolve_source(None)
            shutil.copytree(self.scan, self.directory / "scans/other/runs" / run_id)
            with self.assertRaisesRegex(ValueError, "absent or ambiguous"):
                resolve_source(Path(run_id))
            self.assert_sources_unchanged()

    def test_in_session_rejects_bad_preparation_without_initialization(self):
        with self.prepared_session() as overlay:
            original_overlay = overlay.read_bytes()
            for name, value in (
                ("VULNOPS_LAUNCHER_SESSION_ID", ""),
                ("VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID", "different-session"),
                ("VULNOPS_LAUNCHER_PID", "0"),
                ("VULNOPS_OMP_CONTROLLER_SELECTOR", "other/model:high"),
                ("VULNOPS_MODEL_ROUTING", "{}"),
                ("VULNOPS_OMP_RUNTIME_CONFIG", str(self.directory / "not-an-overlay"))):
                with self.subTest(name=name), patch.dict(os.environ, {name: value}):
                    with self.assertRaises((ValueError, OSError)):
                        self.init("--in-session")
                    self.assertFalse(self.context_path.exists())
            project = Path(os.environ["VULNOPS_PROJECT_OMP_CONFIG"])
            original = project.read_bytes()
            project.write_text("task:\n  agentModelOverrides: {}\n")
            with self.assertRaisesRegex(ValueError, "overrides"):
                self.init("--in-session")
            project.write_bytes(original)
            overlay.write_text('{"task":{"maxRuntimeMs":1,"agentModelOverrides":[]}}')
            with self.assertRaisesRegex(ValueError, "overlay"):
                self.init("--in-session")
            overlay.write_bytes(original_overlay)
            self.assertEqual(self.init("--in-session")["launcher_session_id"], "fixture-session")
            self.assert_sources_unchanged()

    def test_initializer_cli_binds_complete_source_without_mutation(self):
        context = json.loads(self.cli("init-advantage.py", self.scan, "--source-root", self.source).stdout)
        self.assertEqual(Path(context["source_scan"]), self.scan.resolve())
        self.assertEqual(context["baseline"]["execution_id"], context["source_run_id"])
        with native_call(context, "baseline"):
            self.assertEqual(load_context(context["input_path"]), context)
        self.assertFalse(self.context_path.exists())
        self.assert_sources_unchanged()

    def test_failed_intake_removes_only_its_new_execution_and_work(self):
        import advantage_lifecycle as lifecycle
        self.context_path.write_text("{prior malformed pointer")
        sibling = self.directory / "unrelated-execution"
        sibling.mkdir()
        (sibling / "keep.txt").write_text("unrelated user data")
        for failure in ("patch", "catalog", "schema"):
            created = []

            def partial_patch(context):
                base = Path(context["scan_base"])
                work = ROOT / "work/advantage" / context["run_id"]
                created.append((base, work, Path(context["input_path"])))
                (work / "derived").mkdir(parents=True)
                (work / "derived/partial.txt").write_text("owned incomplete derived work")
                self.addCleanup(shutil.rmtree, work, True)
                if failure == "patch":
                    raise ValueError("synthetic patch intake failure")
                return None

            original_validate, original_catalog = lifecycle.validate_schema, lifecycle.build_catalog

            def fail_schema(document, schema):
                if failure == "schema" and schema == "advantage-context":
                    raise ValueError("synthetic input schema failure")
                return original_validate(document, schema)

            def fail_catalog(context, scan):
                if failure == "catalog":
                    raise ValueError("synthetic catalog failure")
                return original_catalog(context, scan)

            with self.subTest(failure=failure), patch("advantage_actions.prepare_patch", side_effect=partial_patch), \
                    patch.object(lifecycle, "validate_schema", side_effect=fail_schema), \
                    patch.object(lifecycle, "build_catalog", side_effect=fail_catalog):
                with self.assertRaisesRegex(ValueError, "synthetic"):
                    self.init()
            self.assertEqual(len(created), 1)
            self.assertTrue(all(not path.exists() for path in created[0]))
            self.assertEqual(self.context_path.read_text(), "{prior malformed pointer")
            self.assertEqual((sibling / "keep.txt").read_text(), "unrelated user data")
            self.assert_sources_unchanged()

    def test_missing_publication_and_recursive_baseline_rejected(self):
        report = self.scan / "report/security-report.json"
        original = report.read_bytes()
        report.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.init()
        report.write_bytes(original)
        linked = self.init()
        completed = empty_linked_execution(linked)
        with self.assertRaisesRegex(ValueError, "audit"):
            initialize(parser_for("init").parse_args([str(completed), "--source-root", str(self.source)]))
        self.assert_sources_unchanged()

    def test_changed_source_is_new_scope_not_inherited_assessment(self):
        first = self.init()
        old = tree_hashes(Path(first["scan_base"]))
        (self.source / "app.py").write_text("changed source\n")
        second = self.init()
        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertNotEqual(first["assessment_id"], second["assessment_id"])
        self.assertEqual(Path(second["source_root"]), self.source)
        self.assertEqual(tree_hashes(Path(first["scan_base"])), old)
        self.assertEqual(tree_hashes(self.scan), self.before)

    def test_full_catalog_keeps_more_than_display_cap_and_statuses(self):
        path = self.scan / "sast/supporting-cohort.json"
        path.write_text(json.dumps({"schema_version": "2.0", "records": [
            {"id": f"COHORT-{index:03}", "status": "rejected" if index % 2 else "deferred",
             "reason": "Preserved upstream disposition."} for index in range(251)]}))
        run_id = load(self.scan / "report/security-report.json")["run_id"]
        catalog = build_catalog({"run_id": "linked-catalog-fixture"}, self.scan)
        cohort = [row for row in catalog["records"]
                  if row["reference"]["artifact_ref"].startswith("sast/supporting-cohort.json#")]
        self.assertEqual(len(cohort), 251)
        self.assertEqual({row["status"] for row in cohort}, {"deferred", "rejected"})
        self.assertTrue(any(row["id"] == "COHORT-250" for row in cohort))
        self.assertEqual(catalog["record_count"], sum(catalog["counts"].values()))
        duplicate = load(path)
        duplicate["records"].append(duplicate["records"][0])
        path.write_text(json.dumps(duplicate))
        records, counts = catalog_records(self.scan, run_id, [{
            "artifact_ref": "sast/supporting-cohort.json", "sha256": sha256_file(path), "size": path.stat().st_size}])
        self.assertEqual({row["id"] for row in records}, {f"COHORT-{index:03}" for index in range(1, 251)})
        self.assertEqual(counts["records"], 250)
        self.assertFalse(build_catalog({"run_id": "linked-catalog-fixture"}, self.scan)["counts_complete"])

    def test_canonical_final_findings_preserve_repeated_question_reference_rows(self):
        from advantage_contract import resolve_pointer
        relative = "final-verification/findings.json"
        path = self.scan / relative
        document = load(path)
        rows = [row for assessment in document["objective_assessments"] for row in assessment["question_outcomes"]]
        self.assertGreater(len(rows), len({row["question_id"] for row in rows}))
        run_id = load(self.scan / "report/security-report.json")["run_id"]
        catalog, counts = catalog_records(self.scan, run_id, [{
            "artifact_ref": relative, "sha256": sha256_file(path), "size": path.stat().st_size}])
        outcomes = [row for row in catalog if row["record_type"] == "question_outcomes"]
        self.assertEqual(len(outcomes), len(rows))
        self.assertEqual(counts["question_outcomes"], len(rows))
        self.assertEqual(len({row["reference"]["artifact_ref"] for row in outcomes}), len(rows))
        self.assertEqual([resolve_pointer(document, row["pointer"]) for row in outcomes], rows)

    def test_typed_reference_owner_path_and_record_fail_closed(self):
        context = self.init()
        catalog = load(Path(context["scan_base"]) / "baseline/catalog.json")
        row = next(row for row in catalog["records"] if row["record_type"] == "findings")
        self.assertEqual(resolve_reference(context, row["reference"])["id"], row["id"])
        for reference in (
            {**row["reference"], "execution_id": context["run_id"]},
            {**row["reference"], "execution_id": "unadmitted"},
            {**row["reference"], "artifact_ref": "../outside.json"},
            {**row["reference"], "artifact_ref": "/tmp/outside.json"},
            {**row["reference"], "artifact_ref": "final-verification/findings.json#missing"}):
            with self.subTest(reference=reference), self.assertRaises((ValueError, OSError)):
                resolve_reference(context, reference)
        with self.assertRaises(ValueError):
            resolve_reference(context, row["reference"], kind="source")
        self.assertEqual(resolve_reference(context, "app.py:1-2"), self.source / "app.py")
        artifact = self.scan / row["reference"]["artifact_ref"].split("#")[0]
        original = artifact.read_bytes()
        artifact.write_bytes(original + b"\n")
        self.assertEqual(resolve_reference(context, row["reference"])["id"], row["id"])
        outside = self.directory / "outside.json"
        outside.write_bytes(original)
        artifact.unlink()
        artifact.symlink_to(outside)
        with self.assertRaises(ValueError):
            resolve_reference(context, row["reference"])

    def test_multi_repository_intake_retains_all_repositories_in_fresh_scope(self):
        from advantage_baseline import current_inventory
        audit = exercise_pipeline(self.directory / "multi-audit", git_identity=True, multi_repository=True)
        before = tree_hashes(audit["scan"])
        arguments = [str(audit["scan"]), "--source-root", str(audit["source"])]
        context = initialize(parser_for("init").parse_args(arguments))
        self.assertEqual(context["repository_count"], 2)
        self.assertEqual([row["path"] for row in context["repositories"]], ["service-a", "service-b"])
        self.assertEqual(resolve_reference(context, "service-b/app.py:1-2"), audit["source"] / "service-b/app.py")
        with self.assertRaises(ValueError):
            resolve_reference(context, "app.py:1")
        inventory = current_inventory(audit["source"], "two-service-fixture")
        (audit["source"] / "service-a/app.py").write_text("changed source\n")
        self.assertEqual(current_inventory(audit["source"], "two-service-fixture")["repositories"], inventory["repositories"])
        shutil.copytree(audit["source"] / "service-b", audit["source"] / "service-c")
        shutil.rmtree(audit["source"] / "service-a")
        fresh = initialize(parser_for("init").parse_args([*arguments, "--depth", "quick"]))
        self.assertNotEqual(fresh["run_id"], context["run_id"])
        self.assertEqual([row["path"] for row in fresh["repositories"]], ["service-b", "service-c"])
        self.assertEqual(tree_hashes(audit["scan"]), before)

    def test_zero_confirmed_audit_is_valid_investigation_baseline(self):
        audit = exercise_pipeline(self.directory / "zero-audit", git_identity=True, reject_findings=True)
        self.assertEqual(load(audit["scan"] / "final-verification/findings.json")["findings"], [])
        before = tree_hashes(audit["scan"])
        context = initialize(parser_for("init").parse_args([
            str(audit["scan"]), "--source-root", str(audit["source"])]))
        catalog = load(Path(context["scan_base"]) / "baseline/catalog.json")
        self.assertTrue(any(row["record_type"] == "rejections" for row in catalog["records"]))
        self.assertEqual(empty_linked_execution(context).name, context["run_id"])
        self.assertEqual(tree_hashes(audit["scan"]), before)

    def test_input_projection_does_not_rewrite_original_or_allow_schema_bypass(self):
        context = self.init()
        before = Path(context["input_path"]).read_bytes()
        expected = copy.deepcopy(context)
        for key in ("execution_kind", "baseline", "model_routing", "budget"):
            malformed = copy.deepcopy(context)
            malformed.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                context_document(malformed)
        cached = {**context, "_source_receipts": {("base", "app.py:1"): {"reference": "app.py:1"}}}
        self.assertEqual(context_document(cached), expected)
        with self.assertRaises(ValueError):
            context_document({**context, "allow_unvalidated": True})
        self.assertEqual(Path(context["input_path"]).read_bytes(), before)

    def test_incomplete_report_is_not_zero_findings_or_resumable(self):
        context = self.init()
        base = empty_linked_execution(context, stop_before_report=True)
        before = tree_hashes(base)
        status = json.loads(self.cli("advantage-status.py", base).stdout)
        self.assertEqual(status["status"], "incomplete")
        self.assertIsNone(status["counts"])
        self.assertIsNone(status["report"])
        self.assertIn("not a zero-findings assessment", status["reason"])
        self.cli("validate-advantage.py", base, "--portable", succeeds=False)
        fresh = self.init()
        self.assertNotEqual(fresh["run_id"], context["run_id"])
        self.assertEqual(tree_hashes(base), before)
        self.assertFalse((base / "report/security-report.json").exists())
        self.assert_sources_unchanged()

    def test_completed_execution_is_immutable_portable_and_control_free(self):
        context = self.init()
        base = empty_linked_execution(context)
        before = tree_hashes(base)
        self.assertFalse(Path(context["input_path"]).exists())
        self.cli("advantage-status.py", base)
        self.cli("validate-advantage.py", base, "--portable")
        self.assertEqual(tree_hashes(base), before)
        for name in ("advantage-manifest.json", "task-ledger.json", "dispatch.json", "phase-manifest.json"):
            self.assertFalse(list(base.rglob(name)))
        delivery = self.directory / "delivery"
        delivery.mkdir()
        shutil.copytree(self.scan, delivery / context["source_run_id"])
        shutil.copytree(base, delivery / context["run_id"])
        with patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": ""}):
            self.cli("validate-advantage.py", delivery / context["run_id"], "--portable")
            self.cli("advantage-status.py", delivery / context["run_id"])
        self.assert_sources_unchanged()

    def test_actions_source_is_explicit_bound_and_rejects_unknown_selection(self):
        context = self.init()
        completed = empty_linked_execution(context)
        before = tree_hashes(completed)
        with self.assertRaisesRegex(ValueError, "selection is not accepted"):
            self.init("--mode", "actions", "--action-source", str(completed), "--track-finding", "REJECTED-ID")
        action = self.init("--mode", "actions", "--action-source", str(completed), "--hardening")
        self.assertEqual(action["action_source"]["execution_id"], context["run_id"])
        for phase in ("planning", "investigation", "synthesis", "final-verification"):
            self.assertFalse(any((Path(action["scan_base"]) / phase).iterdir()))
        wrong = copy.deepcopy(action)
        wrong["source_run_id"] = "different-audit"
        with self.assertRaisesRegex(ValueError, "different audit"):
            admit_action_source(completed, wrong)
        with native_call(action, "handoff"):
            check_identity(action)
        self.assertEqual(tree_hashes(completed), before)
        self.assert_sources_unchanged()

    def test_patch_request_shape_is_not_silently_downgraded(self):
        for options in (("--mode", "diff"), ("--verify-fix", "F-001"), ("--assess-patch-risk",),
                        ("--repository", "service-a"), ("--mode", "actions")):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.init(*options)
        self.assert_sources_unchanged()

    def test_diff_patch_is_immutable_isolated_and_owned_teardown_preserves_evidence(self):
        from advantage_actions import derived_root, validate_patch
        from test_advantage_actions import queue_patch
        expected, patch_bytes = queue_patch(self.source)
        patch_path = self.directory / "selected assessment.patch"
        patch_path.write_bytes(patch_bytes)
        first = self.init("--mode", "diff", "--patch", str(patch_path))
        first_work = derived_root(first)
        self.addCleanup(shutil.rmtree, first_work.parent, True)
        second = self.init("--mode", "diff", "--patch", str(patch_path))
        second_work = derived_root(second)
        self.addCleanup(shutil.rmtree, second_work.parent, True)
        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertNotEqual(first_work, second_work)
        self.assertEqual((first_work / "app.py").read_text(), expected)
        self.assertEqual((second_work / "app.py").read_text(), expected)
        self.assertEqual(first["patch_binding"], second["patch_binding"])
        bound = Path(first["scan_base"]) / first["patch_binding"]["patch_ref"]
        self.assertEqual(bound.read_bytes(), patch_bytes)
        validate_patch(first)
        patch_path.write_bytes(patch_bytes + b"\n")
        with self.assertRaisesRegex(ValueError, "supplied patch changed"):
            validate_patch(first)
        self.assertEqual(bound.read_bytes(), patch_bytes)
        patch_path.write_bytes(patch_bytes)
        with native_call(first, "investigation"):
            cleanup(first)
        self.assertFalse(first_work.exists())
        self.assertTrue(second_work.is_dir())
        self.assertEqual(bound.read_bytes(), patch_bytes)
        validate_patch(first, portable=True)
        self.assert_sources_unchanged()

    def test_relocated_baseline_keeps_required_authority_and_missing_support_visible(self):
        shutil.rmtree(self.scan / "repo-context")
        relocated = self.directory / "relocated baseline"
        self.scan.rename(relocated)
        self.scan = relocated
        before = tree_hashes(self.scan)
        context = self.init()
        catalog = load(Path(context["scan_base"]) / "baseline/catalog.json")
        self.assertFalse(catalog["counts_complete"])
        self.assertEqual(Path(context["source_scan"]), relocated.resolve())
        self.assertEqual(tree_hashes(self.scan), before)
        (self.scan / "final-verification/findings.json").unlink()
        with self.assertRaises((OSError, ValueError)):
            self.init()


if __name__ == "__main__":
    unittest.main()
