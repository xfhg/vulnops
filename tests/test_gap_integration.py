"""Real harness commands with authored synthetic source proof, never model/target execution.

Callable smoke: smoke_gap_integration() returns sanitized ordinary/Advantage counts.
All harness configuration, sources, runtime state and evidence are disposable.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import advantage_contract as core
import advantage_pipeline as pipeline
import gap_exploration_contract as gap
from gap_fixture import GapFixture, SOURCE, save
from model_identity import finding_diversity
from test_advantage_integration import file_snapshot
from test_advantage_pipeline import author, authored_plan, authored_result, authored_chain, authored_review, candidate, inherited_accounting
from test_dossiers import sample_finding, add_dossier, review_dossier
from test_redteam_workflow import exercise_pipeline
from advantage_native_fixture import NativeFixture, native_call, native_controller


def load(path):
    return json.loads(Path(path).read_text())


def fixture_harness(directory):
    """Copy production helpers; never change the checkout's config or runtime."""
    root = Path(directory).resolve() / "harness"
    root.mkdir()
    for name in ("scripts", "schemas", "config"):
        shutil.copytree(ROOT / name, root / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    config = (ROOT / "config.toml").read_text()
    config, count = re.subn(r'(\[harness\.scans\.gap_exploration\]\s*\nenabled\s*=\s*)(?:true|false)',
                            r'\g<1>true', config)
    if count != 1:
        raise AssertionError("fixture requires the explicit gap configuration section")
    # Only the independently configured add-on allowance changes. Original quick
    # campaign, continuation, experiment and review allocations remain untouched.
    config += ('\n[harness.scans.gap_exploration.budget.quick]\nmax_tasks = 3\n'
               '\n[harness.scans.gap_exploration.budget.full]\nmax_tasks = 3\n')
    (root / "config.toml").write_text(config)
    (root / "scans").mkdir()
    (root / "bins").mkdir()  # No graph or model executable: truthful unavailability.
    return root


class GapScenario:
    def __init__(self, root, *, resume_after_synthesis=False):
        self.root = root
        self.protected = {}
        self.original_bytes = None
        self.resume_after_synthesis = resume_after_synthesis
        self.inherited_closure = None
        self.supplement_expired = False

        self.original_retry = False
    @staticmethod
    def cohort(script, context_path, phase, cohort, action):
        context = load(context_path)
        if context.get("execution_kind") == "advantage":
            assert phase == "synthesis", "native reviewer cohorts are derived from their assignments"
            identity = "AdvantageSynthesis" + cohort.title()
            artifacts = ([f"synthesis/{'original-findings' if cohort == 'original' else 'findings'}.json"]
                         if action == "finish" else [])
            return script.native.observe(
                identity, status="completed" if action == "finish" else "running",
                yield_valid=action == "finish", artifacts=artifacts,
                actor="vulnops-advantage-synthesis")
        return script("gap-dossier.py", "--context", context_path, "--phase", phase,
                      "--cohort", cohort, "--action", action)

    def reject_original(self, context_path, script, draft, command):
        context = load(context_path); base = Path(context["scan_base"])
        original = load(draft)
        broken = copy.deepcopy(original)
        linked = context.get("execution_kind") == "advantage"
        for finding in broken["findings"] if linked else broken["findings"][:1]:
            example = next(row for row in finding["technical_examples"] if row["kind"] == "source")
            example["content"] = "synthetic authored example that is not a source excerpt"
        save(draft, broken)
        if linked:
            receipt = json.loads(script(*command))
            assert receipt["status"] == "unreviewed", receipt
            assert "artifact_ref" not in receipt, receipt
        else:
            try:
                script(*command)
            except AssertionError as exc:
                assert "source example" in str(exc), str(exc)
            else:
                raise AssertionError("invalid source-example authoring was published")
        assert not (base / "synthesis/original-findings.json").exists()
        if context.get("execution_kind") != "advantage":
            script("update-run-state.py", base, "--phase", "synthesis", "--phase-status", "failed",
                   "--task", "Synthesis", "--task-phase", "synthesis", "--task-status", "failed",
                   "--error", "Original authoring failed source-example admission.", "--run-status", "incomplete")
            script("update-run-state.py", base, "--phase", "synthesis", "--phase-status", "running",
                   "--task", "Synthesis", "--task-phase", "synthesis", "--task-status", "running", "--increment-attempt")
        self.cohort(script, context_path, "synthesis", "original", "begin")
        save(draft, original)
        self.original_retry = True

    def explore(self, context_path, script):
        context = load(context_path)
        base = Path(context["scan_base"])
        linked = context.get("execution_kind") == "advantage"
        assert context["gap_exploration_budget"]["max_tasks"] == 3
        assert context["gap_exploration_budget"]["max_candidates"] == 6
        if linked:
            assert context["budget"]["deep_passes"] == 4
            assert context["budget"]["max_tasks"] == 64
        else:
            assert context["intrusion_budget"] == {
                "continuation_rounds": 1, "continuation_tasks": 4, "graph_followups": 4}
            assert context["sast_budget"]["max_hunt_tasks"] == 12
            assert context["experiment_budget"]["max_experiments"] == 12
        directories = ("baseline", "planning", "investigation") if linked else (
            "repo-context", "tool-collection", "sast", "campaign-planning", "intrusion")
        self.protected = {name: file_snapshot(base / name) for name in directories}
        self.budgets = {key: copy.deepcopy(value) for key, value in context.items()
                        if key.endswith("budget") or key in {"orchestration", "model_routing"}}
        self.source_before = file_snapshot(Path(context["source_root"]))
        script("prepare-gap-exploration.py", "--context", context_path)
        # Reuse the authored plan convention, without creating a second execution.
        fixture = GapFixture.__new__(GapFixture)
        fixture.context = context
        fixture.predecessor = "investigation/results.json" if linked else "intrusion/intrusion-results.json"
        plan = fixture.plan(("Healthy", "Defeated", "Failed"))
        plan["questions"][1].update(
            route="guarded_route", security_question="Does the sibling guard prevent another account's object read?",
            proof_obligation="Trace the ownership comparison before store.read", evidence_refs=["routes.py:8-12"])
        plan["assignments"][1]["proof_obligation"] = plan["questions"][1]["proof_obligation"]
        plan["seeds"][1].update(source_refs=["routes.py:8-12"], missing_fact=plan["questions"][1]["proof_obligation"])
        plan["graph_questions"] = [{"id": "AlternativeCaller", "owner": "Healthy", "seed_id": "Seed-Healthy",
            "operation": "callers", "subject": "alternate_route", "file": "routes.py", "source_view": "base",
            "source_refs": ["routes.py:1-6"], "reason": "Locate the alternate caller of the object read.",
            "expected_value": "Navigate to the precise caller before inspecting its ownership checks."}]
        self.objective = plan["objectives"][0]
        draft = base.parent / "gap-plan-draft.json"
        save(draft, plan)
        script("prepare-gap-exploration.py", "--context", context_path, "--plan", draft)
        for task, outcome in (("Healthy", "established"), ("Defeated", "contradicted")):
            if linked:
                packet = load(base / f"gap-exploration/packets/{task}.json")
                dispatch = {"packet": packet, "attempt": 1,
                            "selector": context["model_routing"]["agents"][gap.actor(context, True)]}
            else:
                dispatch = json.loads(script("gap-exploration-worker.py", "dispatch", "--context", context_path, "--task-id", task))
            if linked:
                baseline = pipeline.baseline_findings({**context, "baseline": dispatch["packet"]["baseline"]})
                assert baseline
                assert baseline == pipeline.baseline_findings(context)
            if task == "Healthy":
                environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                               "VULNOPS_RUNTIME_ROOT": str(self.root / "runtime")}
                if linked:
                    script.native.observe(task, status="running", yield_valid=False)
                    call = json.loads(os.environ["VULNOPS_ADVANTAGE_CALL"])
                    call["operation"] = {
                        "kind": "graph", "id": "synthetic-gap-navigation", "phase": "gap-exploration",
                        "owner_id": task, "question_id": "AlternativeCaller",
                        "timeout_seconds": min(120, context["gap_exploration_budget"]["graph_timeout_seconds"]),
                        "preparation_timeout_seconds": context["gap_exploration_budget"]["preparation_timeout_seconds"]}
                    environment["VULNOPS_ADVANTAGE_CALL"] = json.dumps(call)
                graph_command = ([sys.executable, str(self.root / "scripts/codegraph-adapter.py")] if linked
                                 else ["bash", str(self.root / "scripts/run-codegraph.sh")])
                completed = subprocess.run([*graph_command, "--context", str(context_path),
                    "--phase", "gap-exploration", "--owner", task, "--question", "AlternativeCaller"],
                    cwd=self.root, capture_output=True, text=True, timeout=60, env=environment)
                if completed.returncode == 0:
                    raise AssertionError("an absent graph index was advertised as usable")
                self.graph_returncode = completed.returncode
                if linked:
                    assert "Codegraph explicitly disabled" in completed.stderr, completed.stderr
                    self.graph_query = {"status": "unavailable",
                                        "limitation": "Codegraph explicitly disabled; continue source-only."}
                else:
                    queries = load(base / "gap-exploration/dispatch.json")["graph_consumption"]["queries"]
                    self.graph_query = next(row for row in queries if row["owner_id"] == "Healthy")
                assert self.graph_query["status"] == "unavailable"
                assert self.graph_query["limitation"]
                assert not (base / "gap-exploration/codegraph-runs/Healthy/AlternativeCaller/receipt.json").exists()
            result = self.worker_result(context, dispatch, outcome)
            if task == "Healthy":
                result["limitations"].append(self.graph_query["limitation"])
            if linked and task == "Healthy":
                rejected = copy.deepcopy(result)
                rejected["candidates"][0]["proof"]["reachability"]["reason"] = " "
                rejected_path = base / f"gap-exploration/drafts/{task}/rejected-1.json"
                save(rejected_path, rejected)
                native = script.native.observe(task, artifacts=[str(rejected_path)])
                admission_command = [sys.executable, str(self.root / "scripts/gap-exploration-worker.py"),
                                     "admit", "--context", str(context_path), "--task-id", task]
                with native_call(context, "gap-exploration", workers=script.native.workers):
                    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                                   "VULNOPS_RUNTIME_ROOT": str(self.root / "runtime")}
                    failed = subprocess.run([*admission_command, "--result", str(rejected_path)],
                        cwd=self.root, env=environment, capture_output=True, text=True, timeout=90)
                    usage = subprocess.run(admission_command, cwd=self.root, env=environment,
                        capture_output=True, text=True, timeout=90)
                script.commands.extend([{"script": "gap-exploration-worker.py", "exit_code": command.returncode}
                                        for command in (failed, usage)])
                assert failed.returncode == 0, failed.stderr
                assert json.loads(failed.stdout) == {
                    "status": "not_admitted",
                    "reason": "No usable source-bound publication; continue other work."}, failed.stdout
                assert usage.returncode == 2 and "admit requires --result" in usage.stderr, usage.stderr
                assert not (base / f"gap-exploration/results/{task}.json").exists()
                # The discarded publication does not rewrite actual execution
                # status or require a saved rejection marker before useful work.
                assert native["status"] == "completed"
                script.native.refresh()
                result["attempt"] = 2
                # A schema-valid draft may carry publisher-only metadata. It
                # must not poison the next admission or canonical finalization.
                result["admission"] = {"input_sha256": "0" * 64,
                                       "source_receipts": [], "support": []}
            draft = base / f"gap-exploration/drafts/{task}/result.json" if linked else base.parent / f"gap-{task}.json"
            save(draft, result)
            if linked:
                script.native.observe(task, attempt=result["attempt"], artifacts=[str(draft)])
            script("gap-exploration-worker.py", "admit", "--context", context_path, "--task-id", task,
                   "--result", draft)
        healthy_bytes = (base / "gap-exploration/results/Healthy.json").read_bytes()
        for attempt in range(1, context["gap_exploration_budget"]["max_attempts"] + 1):
            if linked:
                script.native.observe("Failed", status="failed", attempt=attempt, yield_valid=False,
                                      error="Synthetic investigator exited before terminal delivery.")
            else:
                script("gap-exploration-worker.py", "dispatch", "--context", context_path, "--task-id", "Failed")
                rejected = base / "gap-exploration/drafts/Failed/result.json"
                save(rejected, {"partial": "Synthetic writer stopped before complete delivery"})
                script("gap-exploration-worker.py", "fail", "--context", context_path, "--task-id", "Failed",
                       "--reason", "Synthetic investigator exited before terminal delivery.")
                if rejected.exists():
                    raise AssertionError("failed supplementary draft survived cleanup")
        script("finalize-gap-exploration.py", "--context", context_path)
        self.aggregate = load(base / "gap-exploration/results.json")
        assert self.aggregate["status"] == "degraded"
        assert len(self.aggregate["candidates"]) == 1
        assert {row["outcome"] for row in self.aggregate["non_promoted"]} == {"contradicted", "execution_failed"}
        assert {row["task_id"] for row in self.aggregate["results"]} == {"Healthy", "Defeated"}
        assert self.aggregate["summary"]["worker_attempts"] == (5 if linked else 4)
        assert self.aggregate["summary"]["useful_navigation"] == 0
        assert (base / "gap-exploration/results/Healthy.json").read_bytes() == healthy_bytes
        assert not (base / "gap-exploration/results/Failed.json").exists()
        self.assert_preserved(load(context_path))

    @staticmethod
    def worker_result(context, dispatch, outcome):
        assignment = dispatch["packet"]["assignment"]
        task = assignment["task_id"]
        provenance = {"actor": gap.actor(context, True), "selector": dispatch["selector"],
                      "artifact_ref": f"gap-exploration/results/{task}.json"}
        if gap.linked(context):
            provenance["execution_id"] = context["run_id"]
        result = gap.envelope(context, task_id=task, objective_id=assignment["objective_id"],
            question_id=assignment["question_id"], source_view="base", attempt=dispatch["attempt"], provenance=provenance,
            resolution={"outcome": outcome, "reason": "The alternate route authenticates but omits ownership." if outcome == "established" else
                "The guarded route compares store.owner(key) with the authenticated user before the read, rejecting another owner's key.",
                "missing_fact": "", "next_action": "", "source_refs": ["routes.py:1-12"]}, candidates=[],
            graph_receipt_refs=[],
            limitations=["Navigation unavailable; the absent index supplies no proof. Exact callers and controls were inspected in source."] if task == "Healthy" else [])
        if outcome == "established":
            reasons = {
                "actor_control": "Line 2 obtains the attacker-selected object key from the request path.",
                "reachability": "Lines 3-6 allow an authenticated account to reach store.read(key).",
                "security_boundary": "Line 10 explicitly treats object ownership as the sibling operation's boundary.",
                "impact": "Line 6 returns the selected object's contents directly.",
                "intervening_controls": "Lines 3-5 check authentication only; the owner comparison at line 10 is not called.",
                "conditions_compatible": "The same authenticated actor and selected key reach read without identity conversion."}
            result["candidates"] = [{"id": "GC-Healthy-1", "classification": "new_root", "baseline_ids": [],
                "root_cause_key": "routes.py:6:object-ownership", "terminal_impact": "Authenticated cross-account object read",
                "reason": "The alternate caller omits the sibling ownership guard.", "evidence_refs": ["routes.py:1-12"],
                "source_locations": [{"file": "routes.py", "line": 6}], "objective_ids": [assignment["objective_id"]],
                "question_id": assignment["question_id"], "source_view": "base",
                "proof": {key: {"outcome": "established", "reason": reason, "source_refs": ["routes.py:1-12"]} for key, reason in reasons.items()},
                "causal_trace": [{"step": "Caller supplies the object key", "source_refs": ["routes.py:1-3"]},
                                 {"step": "Authenticated caller receives read result without ownership check", "source_refs": ["routes.py:4-6"]}],
                "inspected_controls": [{"control": "Authentication and sibling ownership guards",
                    "effect": "Only the sibling checks ownership; authentication does not establish object authority", "source_refs": ["routes.py:3-12"]}],
                "conditions": ["Attacker has an ordinary authenticated account and another object's key"]}]
        return result

    def finding(self, context):
        linked = gap.linked(context)
        finding = sample_finding()
        finding.update(id="F-002", origin="independent_discovery", title="Alternate object caller omits ownership",
            root_causes=[{"file": "routes.py", "line": 6, "scope": "alternate_route", "mechanism": "Authentication is checked, object ownership is not."}],
            trace=[{"kind": "entrypoint", "file": "routes.py", "line": 2, "scope": "alternate_route", "description": "Read caller-selected path key."},
                   {"kind": "sink", "file": "routes.py", "line": 6, "scope": "alternate_route", "description": "Return the selected object's contents without ownership authorization."}],
            source_refs=[{"kind": "gap-exploration", "source_id": "GC-Healthy-1",
                          "artifact_ref": "gap-exploration/results/Healthy.json:GC-Healthy-1"}],
            contributors=[copy.deepcopy(self.aggregate["candidates"][0]["provenance"])])
        actor = "vulnops-advantage-synthesis" if linked else "vulnops-synthesis"
        finding["verification"].update(actor=actor, model=context["model_routing"]["agents"][actor], source_validation_refs=["routes.py:1-12"])
        add_dossier(finding, objective_id=self.objective["id"], source="routes.py:1-12")
        finding["technical_examples"] = [{"id": "alternate-source", "kind": "source", "content": SOURCE.split("\n\n")[0],
            "evidence_refs": ["routes.py:1-6"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []}]
        finding["exploitation"]["steps"][0]["example_ids"] = ["alternate-source"]
        return finding

    def synthesize_ordinary(self, context_path, script):
        context = load(context_path); base = Path(context["scan_base"])
        from evidence_accounting import synthesis_inputs
        originals = synthesis_inputs(base, include_supplementary=False)
        extended = synthesis_inputs(base)
        assert set(extended) - set(originals) == {"gap-exploration/results.json:GC-Healthy-1"}
        assert all(extended[key] == value for key, value in originals.items())
        self.cohort(script, context_path, "synthesis", "original", "begin")
        save(base / "synthesis/original-draft.json", load(base / "synthesis/findings.json"))
        self.reject_original(context_path, script, base / "synthesis/original-draft.json",
                             ("finalize-synthesis.py", base, "--stage", "original"))
        script("finalize-synthesis.py", base, "--stage", "original")
        original = base / "synthesis/original-findings.json"
        self.original_bytes = original.read_bytes()
        self.cohort(script, context_path, "synthesis", "original", "finish")
        self.cohort(script, context_path, "synthesis", "supplementary", "begin")
        if self.resume_after_synthesis:
            script("gap-dossier.py", "--context", context_path, "--phase", "synthesis",
                   "--cohort", "supplementary", "--action", "fail",
                   "--reason", "Supplementary authoring stopped before terminal delivery.")
            script("finalize-synthesis.py", base, "--stage", "supplementary", "--supplementary-failed")
            return
        combined = load(original)
        combined["findings"].append(self.finding(context))
        # The finalizer extends accounting while preserving original input claims.
        combined.pop("objective_assessments", None)
        save(base / "synthesis/supplementary-draft.json", combined)
        script("finalize-synthesis.py", base, "--stage", "supplementary")
        self.cohort(script, context_path, "synthesis", "supplementary", "finish")

    def verify_ordinary(self, context_path, script):
        from run_lifecycle import assessment_ref
        context = load(context_path); base = Path(context["scan_base"])
        source = Path(context["source_root"])
        # Admit the authored original review through the same durable worker ledger
        # used by recovery; this does not claim a reviewer model was executed.
        script("gap-dossier.py", "--context", context_path, "--phase", "final-verification",
               "--action", "review-begin", "--finding", "F-001")
        script("gap-dossier.py", "--context", context_path, "--phase", "final-verification",
               "--action", "review-finish", "--finding", "F-001")
        script("finalize-verification.py", source, base, "--cohort", "original")
        self.cohort(script, context_path, "final-verification", "original", "finish")
        assert not (base / "final-verification/findings.json").exists()
        original_review = base / "final-verification/results/F-001.json"
        original_review_bytes = original_review.read_bytes()
        if self.resume_after_synthesis:
            script("finalize-verification.py", source, base)
            assert load(base / "final-verification/findings.json")["unreviewed"] == self.inherited_closure
            return
        self.cohort(script, context_path, "final-verification", "supplementary", "begin")
        script("gap-dossier.py", "--context", context_path, "--phase", "final-verification", "--action", "review-begin", "--finding", "F-002")
        finding = load(base / "synthesis/findings.json")["findings"][1]
        actor = "vulnops-independent-verify-one"
        selector = context["model_routing"]["agents"][actor]
        review = {"schema_version": "2.0", "finding_id": finding["id"], "status": "verified",
            "closure_reason": "Independent source review confirms the alternate caller lacks the sibling ownership predicate.",
            "evidence_refs": ["routes.py:1-12", finding["source_refs"][0]["artifact_ref"]], "primitive_results": [], "transition_results": [],
            "joint_conditions": {"outcome": "established", "reason": "The same authenticated account and supplied key reach the unguarded read.",
                "evidence_refs": [finding["source_refs"][0]["artifact_ref"]], "missing_fact": "", "next_action": ""},
            "corrections": [], "corrected_finding": None, "actor": actor, "model": selector,
            "model_diversity": finding_diversity(finding["contributors"], selector)}
        review["assessment_context"] = assessment_ref(context)
        review_dossier(finding, review, success_condition=self.objective["success_condition"])
        save(base / "final-verification/results/F-002.json", review)
        script("gap-dossier.py", "--context", context_path, "--phase", "final-verification", "--action", "review-finish", "--finding", "F-002")
        script("finalize-verification.py", source, base)
        self.cohort(script, context_path, "final-verification", "supplementary", "finish")
        from test_gap_config_lifecycle import RECOVERY
        scratch = base / "final-verification/supplementary-draft.json"
        save(scratch, {"unaccepted": True})
        operation = RECOVERY.unfinished_work(base, "final-verification", context)
        RECOVERY.reconcile_work(base, "final-verification", operation)
        assert not scratch.exists()
        assert original_review.read_bytes() == original_review_bytes
        assert (base / "final-verification/results/F-002.json").is_file()
        script("finalize-verification.py", source, base)
        assert original_review.read_bytes() == original_review_bytes

    def assert_preserved(self, context):
        base = Path(context["scan_base"])
        assert {name: file_snapshot(base / name) for name in self.protected} == self.protected
        assert {key: context[key] for key in self.budgets} == self.budgets
        if self.resume_after_synthesis and self.original_bytes is not None:
            manifest_path = base / "run-manifest.json"
            if manifest_path.is_file():
                manifest = load(manifest_path)
                attempt = manifest["attempt_id"]
                assert manifest["attempt_contexts"][attempt]["gap_exploration_budget"] == context["gap_exploration_budget"]
            else:
                report = load(base / "report/security-report.json")
                assert report["publication"]["execution_kind"] == "audit"
                assert report["run_id"] == context["run_id"]
                assert report["publication"]["gap_exploration"] == {
                    "ref": "gap-exploration/results.json",
                    "sha256": core.sha256_file(base / "gap-exploration/results.json")}
                assert not (base / "task-ledger.json").exists()
            assert gap.load_accepted_candidates(base)[0]["provenance"]["selector"] == self.aggregate["candidates"][0]["provenance"]["selector"]
        assert file_snapshot(Path(context["source_root"])) == self.source_before
        if self.original_bytes is not None:
            assert (base / "synthesis/original-findings.json").read_bytes() == self.original_bytes


def exercise_advantage(root, baseline, *, supplement_expires=False):
    with patch.dict(os.environ, {}):
        return _exercise_advantage(root, baseline, supplement_expires=supplement_expires)


def _exercise_advantage(root, baseline, *, supplement_expires=False):
    context = None
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "VULNOPS_RUNTIME_ROOT": str(root / "runtime"),
        "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "gap-fixture-linked",
        "VULNOPS_LAUNCHER_PID": str(os.getpid())}
    commands = []

    def script(name, *args):
        authority = (patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": ""})
                     if "--portable" in args or name == "advantage-status.py" else
                     native_controller("gap-fixture-linked") if context is None else
                     native_call(context, script.native.phase, workers=script.native.workers))
        with patch.dict(os.environ, environment), authority:
            command = subprocess.run([sys.executable, str(root / "scripts" / name), *map(str, args)], cwd=root,
                                     capture_output=True, text=True, timeout=90)
        commands.append({"script": name, "exit_code": command.returncode})
        if command.returncode:
            raise AssertionError(f"{name}: {command.stderr}\n{command.stdout}")
        return command.stdout

    script.commands = commands

    baseline_before = file_snapshot(baseline["scan"])
    context = json.loads(script("init-advantage.py", baseline["scan"], "--source-root", baseline["source"],
                                "--mode", "deep", "--depth", "full"))
    context_path = Path(context["input_path"])
    base = Path(context["scan_base"])
    script.native = NativeFixture(context)
    script.native.refresh()

    def begin(phase):
        script.native.select_phase(phase)

    def finish(phase):
        script("validate-advantage.py", base, "--context", context_path, "--phase", phase)

    begin("planning")
    plan = authored_plan(context, "app.py:11-15")
    draft = root / "linked-plan-draft.json"; save(draft, plan)
    script("build-advantage-plan.py", "--context", context_path, "--draft", draft); finish("planning")
    begin("investigation")
    for index, assignment in enumerate(plan["assignments"]):
        task = assignment["task_id"]
        current_packet = load(base / f"investigation/packets/{task}.json")
        result = authored_result(context, current_packet,
            outcome="established" if index == 0 else "locally_unresolved", source="app.py:11-15")
        if index == 0:
            packet = current_packet
            result["candidates"] = [candidate("C-CHAIN", "new_chain"), candidate("C-REJECT", "new_chain")]
            result["non_promoted"] = inherited_accounting(context, pipeline.result_path(packet))[1:]
            result["non_promoted"][-1]["input_refs"] = [pipeline.result_path(packet)]
            result["candidates"].append(candidate("C-LIMIT", "new_chain", source="app.py:999"))
        draft = base / f"investigation/drafts/{task}.json"
        save(draft, result)
        script.native.observe(task, artifacts=[str(draft)])
        script("finalize-advantage-investigation.py", "--context", context_path, "--result", draft)
    script("finalize-advantage-investigation.py", "--context", context_path); finish("investigation")
    scenario = GapScenario(root)
    begin("gap-exploration"); scenario.explore(context_path, script); finish("gap-exploration")
    begin("synthesis")
    scenario.cohort(script, context_path, "synthesis", "original", "begin")
    result_ref = pipeline.result_path(packet)
    original, original_link = authored_chain(context, plan["objectives"][0], result_ref)
    disputed, disputed_link = authored_chain(context, plan["objectives"][0], result_ref, identity="F-003", rejected=True)
    original["source_refs"][0]["artifact_ref"] += ":C-CHAIN"
    disputed["source_refs"][0]["artifact_ref"] += "#C-REJECT"
    baseline_id = next(iter(pipeline.baseline_findings(context)))
    original_link["baseline_ids"] = [baseline_id]
    original["source_refs"].append({"kind": "sast", "source_id": baseline_id, "artifact_ref": {
        "execution_id": context["baseline"]["execution_id"],
        "artifact_ref": "final-verification/findings.json#" + baseline_id}})
    original["contributors"] = pipeline.contributor_union(context, original, original_link)
    synthesis = core.envelope(context, status="completed", reason="Source-supported original queue boundary and independently discovered object boundary.",
        provenance=author(context, "vulnops-advantage-synthesis", "synthesis/findings.json"),
        findings=[original, disputed], links=[original_link, disputed_link], candidate_dispositions=[{
            "result_ref": result_ref, "candidate_id": identity, "disposition": "promoted", "finding_ids": [finding_id],
            "reason": "Complete original source dossier requires independent review."}
            for identity, finding_id in (("C-CHAIN", "F-001"), ("C-REJECT", "F-003"))],
        baseline_reconciliation=[{"baseline_id": identity,
            "status": "reused" if identity == baseline_id else "not_revisited",
            "finding_ids": [original["id"]] if identity == baseline_id else [],
            "result_refs": [result_ref] if identity == baseline_id else [],
            "reason": "Historical support retains its original scope; the additional chain requires current independent review."}
            for identity in pipeline.baseline_findings(context)])
    draft = root / "linked-synthesis-draft.json"; save(draft, synthesis)
    scenario.reject_original(context_path, script, draft,
        ("finalize-advantage-synthesis.py", "--context", context_path, "--draft", draft, "--stage", "original"))
    script("finalize-advantage-synthesis.py", "--context", context_path, "--draft", draft, "--stage", "original")
    original_path = base / "synthesis/original-findings.json"
    scenario.original_bytes = original_path.read_bytes()
    retained_accounting = load(original_path)["non_promoted"]
    assert len(retained_accounting) == 3
    assert any(row["review"] for row in retained_accounting)
    assert any(row["deferral"] for row in retained_accounting)
    assert any(row["review"] is None and row["deferral"] is None for row in retained_accounting)
    scenario.cohort(script, context_path, "synthesis", "original", "finish")
    scenario.cohort(script, context_path, "synthesis", "supplementary", "begin")
    combined = load(original_path)
    combined.pop("non_promoted")
    supplemental = scenario.finding(context)
    supplemental["source_refs"][0]["kind"] = "advantage"
    supplemental["source_refs"][0]["artifact_ref"] = "gap-exploration/results/Healthy.json#/candidates/0"
    link = {"finding_id": "F-002", "classification": "new_root", "baseline_ids": [],
            "result_refs": ["gap-exploration/results/Healthy.json"], "source_view": "base"}
    supplemental["contributors"] = pipeline.contributor_union(context, supplemental, link)
    combined["findings"].append(supplemental); combined["links"].append(link)
    combined["candidate_dispositions"].append({"result_ref": link["result_refs"][0], "candidate_id": "GC-Healthy-1",
        "disposition": "promoted", "finding_ids": ["F-002"], "reason": "Complete supplementary source dossier requires independent review."})
    save(draft, combined)
    if supplement_expires:
        # A native terminal failure, not an edited durable deadline, closes only
        # supplementary work while preserving accepted original authoring.
        # The combined draft is not a canonical publication or accepted delivery.
        reason = "Supplementary delivery arrived after its acceptance deadline."
        before_failure = file_snapshot(base)
        try:
            script("finalize-advantage-synthesis.py", "--context", context_path)
        except AssertionError as exc:
            assert "stop native supplementary descendants" in str(exc), str(exc)
        else:
            raise AssertionError("running supplementary work was accepted as a terminal failure")
        assert file_snapshot(base) == before_failure
        script.native.observe("AdvantageSynthesisSupplementary", status="failed", yield_valid=False,
                              actor="vulnops-advantage-synthesis", error=reason)
        script("finalize-advantage-synthesis.py", "--context", context_path)
        closed = load(base / "synthesis/findings.json")
        assert {row["id"] for row in closed["findings"]} == {"F-001", "F-003"}
        unresolved = next(row for row in closed["candidate_dispositions"] if row["candidate_id"] == "GC-Healthy-1")
        assert unresolved["disposition"] == "unresolved" and reason in unresolved["reason"]
        scenario.supplement_expired = True
    else:
        script("finalize-advantage-synthesis.py", "--context", context_path, "--draft", draft, "--stage", "supplementary")
        scenario.cohort(script, context_path, "synthesis", "supplementary", "finish")
    finish("synthesis")
    assert load(base / "synthesis/findings.json")["non_promoted"] == retained_accounting
    begin("final-verification")
    assignments = json.loads(script("finalize-advantage-verification.py", "--context", context_path, "--prepare"))["assignments"]
    findings = {row["id"]: row for row in load(base / "synthesis/findings.json")["findings"]}
    for identity in ("F-001", "F-003", "F-002"):
        if identity not in findings:
            continue
        assignment = next(row for row in assignments if row["finding_id"] == identity)
        review = authored_review(context, findings[identity], assignment, rejected=identity == "F-003")
        if identity == "F-002":
            review["evidence_refs"] = ["routes.py:1-12"]
            review["joint_conditions"].update(reason="The same actor and key reach the object read without ownership authorization.", evidence_refs=["routes.py:1-12"])
            review_dossier(findings[identity], review, success_condition=scenario.objective["success_condition"])
        draft = base / f"final-verification/drafts/{identity}.json"
        save(draft, review)
        script.native.observe(identity, artifacts=[str(draft)])
        script("finalize-advantage-verification.py", "--context", context_path, "--result", draft)
    script("finalize-advantage-verification.py", "--context", context_path); finish("final-verification")
    begin("handoff"); script("finalize-advantage-handoff.py", base, "--context", context_path); finish("handoff")
    begin("report"); script("render-advantage-report.py", "--context", context_path); finish("report")
    scenario.assert_preserved(load(context_path))
    script("advantage-cleanup.py", "--context", context_path)
    assert not context_path.exists()
    script("validate-advantage.py", base, "--portable")
    status = json.loads(script("advantage-status.py", base))
    assert file_snapshot(baseline["scan"]) == baseline_before
    assert status["status"] == "complete"
    assert context["mode"] == "deep" and context["depth"] == "full"
    negative = load(base / "final-verification/findings.json")["reviews"]
    assert [row["finding_id"] for row in negative if row["status"] == "rejected"] == ["F-003"]
    markdown = (base / "report/security-report.md").read_text()
    rejected_review = load(base / "final-verification/results/F-003.json")
    assert findings["F-003"]["attack_summary"] in markdown
    assert rejected_review["closure_reason"] in markdown
    assert "final-verification/results/F-003.json" in markdown
    assert "F-003" not in {row["id"] for row in load(base / "report/security-report.json")["findings"]}
    report = load(base / "report/security-report.json")
    baseline_findings = load(baseline["scan"] / "final-verification/findings.json")["findings"]
    assert [row["finding"] for row in report["historical_findings"]] == baseline_findings
    inherited = next(row["artifact_ref"] for row in report["findings"][0]["source_refs"]
                     if isinstance(row["artifact_ref"], dict))
    assert inherited == {"execution_id": context["baseline"]["execution_id"],
                         "artifact_ref": "final-verification/findings.json#" + baseline_id}
    assert "final-verification/findings.json" not in report["publication"]["producer_routes"]
    assert next(example for example in baseline_findings[0]["technical_examples"]
                if example["id"] == "whitespace-source")["content"] == " \t\n"
    if supplement_expires:
        completed = file_snapshot(base)
        refused = subprocess.run([sys.executable, str(root / "scripts/finalize-advantage-synthesis.py"),
            "--context", str(context_path)],
            cwd=root, env=environment, capture_output=True, text=True, timeout=90)
        assert refused.returncode != 0
        assert file_snapshot(base) == completed
    return summarized(base, scenario, len(commands))


def summarized(base, scenario, command_count):
    report = load(base / "report/security-report.json")
    findings = report["findings"]
    assert {row["id"] for row in findings} == ({"F-001"} if scenario.resume_after_synthesis or scenario.supplement_expired else {"F-001", "F-002"})
    assert all(row["verdict"] == "confirmed" for row in findings)
    assert all(row["independent_verification_ref"] for row in findings)
    original = load(base / "synthesis/original-findings.json")["findings"][0]
    delivered = next(row for row in findings if row["id"] == "F-001")
    for key in ("title", "severity", "root_causes", "trace", "impact", "exploitation", "remediation"):
        assert delivered[key] == original[key]
    assert all(example["execution_status"] == "not_executed" for row in findings for example in row["technical_examples"])
    accounting = report["gap_exploration"]
    accepted_supplements = 0 if scenario.resume_after_synthesis or scenario.supplement_expired else 1
    assert accounting["independently_accepted"] == accepted_supplements
    if scenario.inherited_closure is not None:
        assert load(base / "final-verification/findings.json")["unreviewed"] == scenario.inherited_closure
    return {"status": "complete", "gap_status": scenario.aggregate["status"], "confirmed_findings": len(findings),
        "supplementary_candidates": len(scenario.aggregate["candidates"]), "independently_accepted_supplements": accepted_supplements,
        "defeated_routes": 1, "failed_supplementary_workers": 1, "graph_meaningful": False,
        "source_unchanged": True, "predecessors_unchanged": True, "original_dossier_preserved": True,
        "original_authoring_retry": scenario.original_retry,
        "cross_attempt_closure_preserved": scenario.inherited_closure is not None,
        "expired_supplement_closed": scenario.supplement_expired,
        "recorded_commands": command_count + 1, "graph_status": scenario.graph_query["status"],
        "graph_wrapper_exit_code": scenario.graph_returncode, "target_executed": False, "model_calls": 0}


def smoke_gap_integration(kind="both"):
    """Run actual isolated CLIs; return sanitized evidence, no paths or raw dossiers.

    kind is 'ordinary', 'advantage', 'advantage-expired', 'continuation', or 'both'. Nothing is retained.
    """
    if kind not in {"ordinary", "advantage", "advantage-expired", "continuation", "both"}:
        raise ValueError("unknown integration kind")
    with tempfile.TemporaryDirectory(prefix="gap-command-integration-") as directory:
        root = fixture_harness(directory)
        with patch.dict(os.environ, {"PYTHONDONTWRITEBYTECODE": "1",
                "VULNOPS_RUNTIME_ROOT": str(root / "runtime"),
                "VULNOPS_LAUNCHER_PID": str(os.getpid()),
                "VULNOPS_LAUNCHER_SESSION_ID": "gap-command-fixture"}):
            results = {}
            if kind in {"ordinary", "both"}:
                scenario = GapScenario(root)
                ordinary = exercise_pipeline(root / "scans/ordinary", harness_root=root,
                    gap_scenario=scenario, extra_source_files={"routes.py": SOURCE})
                scenario.assert_preserved(ordinary["context"])
                results["ordinary"] = summarized(ordinary["scan"], scenario, len(ordinary["commands"]))
            if kind in {"continuation", "both"}:
                scenario = GapScenario(root, resume_after_synthesis=True)
                ordinary = exercise_pipeline(root / "scans/continuation", harness_root=root,
                    gap_scenario=scenario, extra_source_files={"routes.py": SOURCE})
                scenario.assert_preserved(ordinary["context"])
                results["continuation"] = summarized(ordinary["scan"], scenario, len(ordinary["commands"]))
            if kind in {"advantage", "advantage-expired", "both"}:
                baseline = exercise_pipeline(root / "scans/baseline", harness_root=root,
                    git_identity=True, extra_source_files={"routes.py": SOURCE, "spacing.txt": " \t\n"},
                    extra_example={"id": "whitespace-source", "kind": "source", "content": " \t\n",
                        "evidence_refs": ["spacing.txt:1"], "substitutions": [],
                        "execution_status": "not_executed", "observation_refs": []})
                if kind in {"advantage", "both"}:
                    results["advantage"] = exercise_advantage(root, baseline)
                if kind in {"advantage-expired", "both"}:
                    results["advantage-expired"] = exercise_advantage(root, baseline, supplement_expires=True)
            return {"fixture": "authored synthetic source proof; no target or model execution", "runs": results}


class GapCommandIntegrationTests(unittest.TestCase):
    def test_ordinary_protected_original_and_reviewed_supplement(self):
        result = smoke_gap_integration("ordinary")["runs"]["ordinary"]
        self.assertEqual(result["confirmed_findings"], 2)
        self.assertTrue(result["predecessors_unchanged"])

    def test_advantage_protected_original_and_reviewed_supplement(self):
        result = smoke_gap_integration("advantage")["runs"]["advantage"]
        self.assertEqual(result["independently_accepted_supplements"], 1)
        self.assertTrue(result["original_dossier_preserved"])

    def test_new_attempt_preserves_failed_supplement_closure_through_report(self):
        result = smoke_gap_integration("continuation")["runs"]["continuation"]
        self.assertEqual(result["confirmed_findings"], 1)
        self.assertEqual(result["independently_accepted_supplements"], 0)
        self.assertTrue(result["cross_attempt_closure_preserved"])

    def test_advantage_expired_acceptance_replaces_unaccepted_union_and_reports(self):
        result = smoke_gap_integration("advantage-expired")["runs"]["advantage-expired"]
        self.assertEqual(result["confirmed_findings"], 1)
        self.assertEqual(result["independently_accepted_supplements"], 0)
        self.assertTrue(result["expired_supplement_closed"])


if __name__ == "__main__":
    unittest.main()
