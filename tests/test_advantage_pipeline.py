"""Linked pipeline proof contracts and reusable authored-result CLI smoke.

These are deterministic contract fixtures, not evidence of a model-led audit.
No operator target is read or executed.
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import advantage_contract as core
import advantage_pipeline as pipeline
from dossier_contract import dossier_hash
from objective_contract import stable_id
from test_dossiers import sample_finding, add_dossier, review_dossier


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def project_original_with_native_author(context, draft_path):
    """Project a stopped author's real draft through the native publication seam."""
    program = r'''
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const fixture=JSON.parse(readFileSync(0,'utf8'));
const {NativeInvocation}=await import(fixture.guard);
const context=fixture.context, actor='vulnops-advantage-synthesis';
const selector=context.model_routing.agents[actor];
const live=new NativeInvocation(context,'Main');
const caller={id:'Main',kind:'main',selector:context.model_routing.controllers.advantage};
live.start({id:'AdvantageSynthesisOriginal',phase:'synthesis',cohort:'original',
  input:context.input_path,actor},'Original',actor,selector);
live.yield('Original',{artifact:'synthesis/draft.json'},true);
live.settle('Original','completed');
const script='finalize-advantage-synthesis.py';
const argv=[fixture.python,path.join(fixture.scripts,script),
  '--context',context.input_path,'--draft',fixture.draft,'--stage','original'];
const binding=live.publicationBinding(script,argv,fixture.scripts);
const python=`
import json, sys
from unittest.mock import patch
import advantage_contract as core
import advantage_pipeline as pipeline
fixture = json.load(sys.stdin)
with patch.object(core, "live_call", return_value=fixture["native_call"]), patch.object(pipeline, "owned"):
    receipt = pipeline.finalize_synthesis(fixture["context"], core.load(fixture["draft"]), stage="original")
print(json.dumps(receipt))
`;
const child=spawnSync(fixture.python,['-B','-c',python],{
  input:JSON.stringify({context,draft:fixture.draft,native_call:live.call(caller,'synthesis')}),
  encoding:'utf8',timeout:30000,
  env:{...process.env,PYTHONDONTWRITEBYTECODE:'1',PYTHONPATH:fixture.scripts}});
if (child.error) throw child.error;
assert.equal(child.status,0,child.stderr);
const receipt=JSON.parse(child.stdout);
assert.equal(receipt.status,'original_complete');
live.observePublication(binding,{code:child.status,exited:true,stdout:child.stdout});
console.log(JSON.stringify({receipt,native_call:live.call(caller,'synthesis')}));
'''
    result = subprocess.run(
        ["node", "--input-type=module", "-e", program],
        input=json.dumps({"context": context, "draft": str(draft_path.resolve()),
                          "python": sys.executable, "scripts": str(ROOT / "scripts"),
                          "guard": (ROOT / ".omp/guards/advantage-native.mjs").as_uri()}),
        text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout)


def author(context, actor, relative):
    return {"execution_id": context["run_id"], "actor": actor,
            "selector": context["model_routing"]["agents"][actor], "artifact_ref": relative}


def empty_plan(context):
    return core.envelope(context, status="empty", reason="No additional actionable source-backed question was selected.",
        provenance=author(context, "vulnops-advantage-planning", "planning/plan.json"),
        objectives=[], questions=[], passes=[], assignments=[])


def authored_plan(context, source="source.py:1-2"):
    owner = "planning/plan.json"
    objective = {"id": stable_id("OBJ-", owner, "queued-operation"), "owner": owner, "local_key": "queued-operation", "parent": None,
        "starting_actor": "ordinary tenant-a account", "controlled_material": "route and another tenant's record identifier",
        "resource_scope": "queued operations for another tenant's record", "desired_effect": "enqueue a cross-tenant operation",
        "success_condition": "Append the caller-selected tenant-b record identifier to the operation queue under the ordinary tenant-a principal.",
        "evidence_refs": [source]}
    question = {"id": stable_id("Q-", owner, "queue-guard"), "owner": owner, "local_key": "queue-guard", "objective_id": objective["id"],
        "security_question": "Does route selection reach queue append without record ownership authorization?",
        "route": "dispatcher to update queue", "proof_obligation": "actor control, route reachability and absent queue authorization",
        "novelty_reason": "Queue insertion is a separate boundary from inherited record disclosure.",
        "evidence_refs": [source], "baseline_records": [], "counterevidence": [], "prior_disposition": "none",
        "changed_hypothesis": "", "evidence_delta": [], "disposition": "admitted", "reason": "Source exposes an unreviewed operation boundary.",
        "stop_conditions": ["Stop at queue insertion; do not infer persistence or worker consumption."]}
    task = {"task_id": "TASK-001", "pass_id": "PASS-001", "question_ids": [question["id"]], "priority": 90,
        "allocation_reason": "Consequence-led review of cross-tenant queue mutation.", "initial_access": "ordinary tenant-a account",
        "known_information": ["Baseline record disclosure does not grant queue-consumer authority."], "available_capabilities": [],
        "absent_privileges": ["No administrator or queue-worker identity."], "source_view": "base", "graph_questions": []}
    plan = empty_plan(context)
    plan.update(status="planned", objectives=[objective], questions=[question], passes=[{"id": "PASS-001", "fresh_context": True}], assignments=[task])
    if context["mode"] == "deep":
        for index in range(1, context["budget"]["deep_passes"]):
            pass_id = f"PASS-{index + 1:03d}"
            plan["passes"].append({"id": pass_id, "fresh_context": True})
            assignment = copy.deepcopy(task)
            assignment.update(task_id=f"TASK-{index + 2:03d}", pass_id=pass_id)
            plan["assignments"].append(assignment)
    return plan


def resolution(outcome="established", source="source.py:1-2"):
    return {"outcome": outcome, "reason": "Inspected the exact producer, consumer and authority decision.",
        "established_facts": ["The source location is reachable from caller-controlled material."], "counterevidence": [],
        "evidence_refs": [source], "missing_fact": "Queue-consumer behavior is not established." if outcome != "established" else "",
        "next_action": "Obtain the authorized queue-consumer implementation." if outcome != "established" else ""}


def inherited_accounting(context, relative):
    rows = []
    for identity in ("NP-PARSER", "NP-REVIEW", "NP-EXTERNAL"):
        row = pipeline.excluded_item(relative, "question_outcomes[0]", [])
        row["id"] = identity
        rows.append(row)
    actor = "vulnops-advantage-investigator"
    rows[1]["review"] = {"actor": actor, "selector": context["model_routing"]["agents"][actor],
        "action": "Inspect the queue boundary.", "result": "Consumer execution remains unproved.",
        "evidence_refs": ["app.py:11-15"]}
    rows[2]["deferral"] = {"kind": "external", "reason": "The authorized queue-consumer implementation is unavailable."}
    return rows


def authored_result(context, packet, outcome="established", source="source.py:1-2"):
    task = packet["assignment"]
    return core.envelope(context, task_id=task["task_id"], pass_id=task["pass_id"],
        packet_sha256=core.sha256_file(Path(context["scan_base"]) / f"investigation/packets/{task['task_id']}.json"), attempt=1,
        provenance=author(context, "vulnops-advantage-investigator", pipeline.result_path(packet)),
        question_outcomes=[{"question_id": q["id"], "objective_id": q["objective_id"], "resolution": resolution(outcome, source)} for q in packet["questions"]],
        candidates=[], additional_baseline_refs=[], graph_receipt_refs=[], graph_limitations=[])


def candidate(identity, classification, source="app.py:11-15", baseline_ids=()):
    return {"id": identity, "classification": classification, "baseline_ids": list(baseline_ids),
        "root_cause_key": "update queue lacks a record ownership decision", "terminal_impact": "Cross-tenant operation enqueue",
        "evidence_refs": [source], "source_locations": [{"file": source.split(":")[0], "line": 12}],
        "reason": "Dispatch passes the caller-selected record identifier into an unguarded queue append."}


def authored_chain(context, objective, result_ref, identity="F-001", rejected=False):
    finding = sample_finding()
    finding.update(id=identity, finding_kind="chain", origin="composite_chain", title="Cross-tenant queued operation",
        root_causes=[{"file": "app.py", "line": 12, "scope": "update", "mechanism": "Queue append omits a record ownership decision."}],
        trace=[{"kind": "entrypoint", "file": "app.py", "line": 13, "scope": "dispatch", "description": "Accept caller-controlled route and ID."},
               {"kind": "sink", "file": "app.py", "line": 12, "scope": "update", "description": "Append the supplied ID with current principal."}],
        impact="Persist an unauthorized cross-tenant record change." if rejected else "Append an operation targeting another tenant's record to the shared queue.",
        status="needs_environment" if rejected else "verified",
        source_refs=[{"kind": "advantage", "source_id": "C-REJECT" if rejected else "C-CHAIN", "artifact_ref": result_ref}],
        primitive_steps=[{"primitive_id": pid, "input_capability": inp, "output_capability": out,
            "boundary_crossed": boundary, "evidence_refs": [source]} for pid, inp, out, boundary, source in [
            ("P-ROUTE", "caller chooses route and record ID", "update receives current user and record ID", "dispatcher to handler", "app.py:13-15"),
            ("P-QUEUE", "update receives current user and record ID", "queue contains the supplied operation", "tenant account to shared operation queue", "app.py:11-12")]])
    finding["verification"].update(actor="vulnops-advantage-synthesis", model=context["model_routing"]["agents"]["vulnops-advantage-synthesis"],
        level="environment_required" if rejected else "source_verified", source_validation_refs=["app.py:11-15"])
    add_dossier(finding, objective_id=objective["id"], source="app.py:11-15")
    finding["attack_summary"] = "Caller-controlled route and record ID flow through update into the shared queue. Persistence is not demonstrated."
    finding["intended_behavior"] = "Accept queued operations only for records owned by the current principal."
    finding["attacker"]["boundary_crossed"] = "ordinary tenant account to shared queued-operation state"
    finding["affected_components"][0].update(name="Update operation queue", entrypoints=["app.dispatch('/records/update', record_id)"])
    finding["exploitation"]["rationale"] = "The dispatcher selects update, which enqueues the supplied record ID without an ownership decision."
    finding["impact_limits"] = ["Source establishes queue insertion only; no worker, persistent mutation or target execution was established."]
    finding["remediation"]["actions"][0].update(change="Check record ownership under the current principal before appending the operation.",
        rationale="An ownership predicate blocks the unauthorized queued operation at its producer.")
    finding["remediation"]["verification_checks"][0].update(description="Exercise cross-tenant and own-tenant enqueue requests.",
        attack_expected="Reject cross-tenant identifiers without adding a queue entry.",
        legitimate_expected="Append an authorized own-tenant operation exactly once.")
    finding["exploitation"]["steps"][0].update(action="Select /records/update with a tenant-b record ID.",
        why_it_works="dispatch passes the trusted current principal and caller-selected ID to update; update appends without invoking guarded.",
        expected_result="The queue gains the supplied current-user/record-ID pair.",
        evidence_status="environment_required" if rejected else "source_established")
    joint = resolution("locally_unresolved" if rejected else "established", "app.py:11-15")
    transition_resolution = {k: joint[k] for k in ("outcome", "reason", "evidence_refs", "missing_fact", "next_action")}
    finding["transitions"] = [{"producer_id": "P-ROUTE", "consumer_id": "P-QUEUE", "resolution": transition_resolution,
        "obligations": {key: {"outcome": "established", "reason": "Exact source passes the same actor and record ID without intervening guard.",
            "evidence_refs": ["app.py:11-15"], "source_locations": [{"file": "app.py", "start_line": 11, "end_line": 15}]}
            for key in ("producer_grant", "actor_control", "scope_alignment", "control_preservation", "consumer_authority", "intervening_controls", "conditions_compatible")}}]
    finding["technical_examples"] = [{"id": "source-example", "kind": "source", "content": "def update(user, record_id):\n    queue.append((user, record_id))",
        "evidence_refs": ["app.py:11-12"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []}]
    link = {"finding_id": identity, "classification": "new_chain", "baseline_ids": [], "result_refs": [result_ref], "source_view": "base"}
    finding["contributors"] = pipeline.contributor_union(context, finding, link)
    return finding, link


def authored_review(context, finding, assignment, rejected=False):
    result = core.envelope(context, finding_id=finding["id"], status="rejected" if rejected else "verified",
        closure_reason="Source establishes queue insertion only; persistence is unproved." if rejected else "Independent source review establishes exact bounded queue insertion.",
        evidence_refs=["app.py:11-15"], primitive_results=[{"primitive_id": p["primitive_id"], "status": "verified", "reason": "Inspected exact primitive source.", "evidence_refs": p["evidence_refs"]} for p in finding["primitive_steps"]],
        transition_results=copy.deepcopy(finding["transitions"]),
        joint_conditions={k: v for k, v in resolution("locally_unresolved" if rejected else "established", "app.py:11-15").items() if k not in {"established_facts", "counterevidence"}},
        corrections=[], corrected_finding=None, actor=assignment["actor"], model=assignment["selector"],
        model_diversity=all(pipeline.split_selector(c["selector"])[:2] != pipeline.split_selector(assignment["selector"])[:2] for c in finding["contributors"]),
        assignment_sha256=core.digest(assignment), attempt=1, fresh_context=True)
    objective = pipeline.read_local(context, "planning/plan.json")["objectives"][0]
    return review_dossier(finding, result, success_condition=objective["success_condition"], satisfied=not rejected)


def exercise_linked_cli(context_path, *, empty=False):
    """Execute real pipeline CLIs from a real initialized Advantage context.

    The caller owns source-audit admission (exercise_pipeline(...,git_identity=True))
    and linked initialization. Nonempty fixtures require that helper's app.py source.
    Returns context/report and subprocess records; never mutates source or baseline.
    """
    from advantage_native_fixture import NativeFixture, native_call
    context_path = Path(context_path)
    context = core.load(context_path)
    base = Path(context["scan_base"])
    transcript = []
    phase = "planning"
    native = NativeFixture(context)
    workers = native.workers

    def command(script, *args):
        with nullcontext() if "--portable" in args else native_call(context, phase, workers=workers):
            completed = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, args)], cwd=ROOT,
                                       text=True, capture_output=True, check=False)
        transcript.append({"script": script, "returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr})
        if completed.returncode:
            raise AssertionError(f"{script}: {completed.stderr}\n{completed.stdout}")
        return json.loads(completed.stdout) if completed.stdout.strip() else None

    def begin(name):
        nonlocal phase
        phase = name
        native.select_phase(name)

    def finish(name):
        command("validate-advantage.py", base, "--context", context_path, "--phase", name)

    def delivered(identity, draft):
        native.observe(identity, artifacts=[str(draft)])

    with tempfile.TemporaryDirectory(prefix="fixture-drafts-", dir=base) as temporary, native:
        drafts = Path(temporary)
        begin("planning")
        plan = empty_plan(context) if empty else authored_plan(context, "app.py:11-15")
        if not empty:
            deferred = copy.deepcopy(plan["objectives"][0])
            deferred.update(id=stable_id("OBJ-", "planning/plan.json", "persisted-change"), local_key="persisted-change",
                desired_effect="persist a cross-tenant record change", success_condition="Persist an unauthorized tenant-b record change.")
            question = copy.deepcopy(plan["questions"][0])
            question.update(id=stable_id("Q-", "planning/plan.json", "queue-consumer"), local_key="queue-consumer", objective_id=deferred["id"],
                security_question="Does an authorized asynchronous consumer persist queued records without ownership checks?",
                route="queue to persistent store", proof_obligation="Obtain the authorized consumer and its ownership decision.",
                disposition="budget_deferred", reason="Finite allocation ends before the separate consumer obligation is established.")
            plan["objectives"].append(deferred)
            plan["questions"].append(question)
        put(drafts / "plan.json", plan)
        command("build-advantage-plan.py", "--context", context_path, "--draft", drafts / "plan.json")
        finish("planning")
        begin("investigation")
        if not empty:
            for assignment in plan["assignments"][1:]:
                task_id = assignment["task_id"]
                packet = pipeline.read_local(context, f"investigation/packets/{task_id}.json")
                result = authored_result(context, packet, "locally_unresolved", "app.py:11-15")
                result_path = drafts / f"{task_id}.json"
                put(result_path, result)
                delivered(task_id, result_path)
                command("finalize-advantage-investigation.py", "--context", context_path, "--result", result_path)
            packet = pipeline.read_local(context, "investigation/packets/TASK-001.json")
            first = authored_result(context, packet, "locally_unresolved", "app.py:11-15")
            prior_ids = list(pipeline.baseline_findings(context))
            first["candidates"] = [candidate("C-REDISCOVERY", "baseline_revalidation", baseline_ids=prior_ids)] if prior_ids else []
            if prior_ids:
                first["candidates"][0].update(root_cause_key="Legacy read omits tenant ownership", terminal_impact="Cross-tenant record disclosure",
                    evidence_refs=["app.py:9-10"], source_locations=[{"file": "app.py", "line": 10}],
                    reason="The unchanged inherited legacy read lacks the tenant ownership predicate.")
            put(drafts / "first.json", first)
            delivered("TASK-001", drafts / "first.json")
            command("finalize-advantage-investigation.py", "--context", context_path, "--result", drafts / "first.json")
            task = copy.deepcopy(plan["assignments"][0]); task["task_id"] = "TASK-002"
            continuation = {"predecessor_task_id": "TASK-001", "predecessor_sha256": core.sha256_file(base / pipeline.result_path(packet)),
                "changed_hypothesis": "Separate source-established enqueue from unproved asynchronous persistence.",
                "evidence_delta": ["app.py:11-12"], "alternative_path": "", "next_proof_obligation": "Trace producer-to-queue identity compatibility without inferring a worker."}
            wave = core.envelope(context, wave=1, tasks=[{"assignment": task, "continuation": continuation}])
            put(drafts / "wave.json", wave)
            command("build-advantage-wave.py", "--context", context_path, "--draft", drafts / "wave.json")
            packet = pipeline.read_local(context, "investigation/packets/TASK-002.json")
            second = authored_result(context, packet, "established", "app.py:11-15")
            second["candidates"] = [candidate("C-CHAIN", "new_chain"), candidate("C-REJECT", "new_chain")]
            put(drafts / "second.json", second)
            delivered("TASK-002", drafts / "second.json")
            command("finalize-advantage-investigation.py", "--context", context_path, "--result", drafts / "second.json")
        command("finalize-advantage-investigation.py", "--context", context_path)
        finish("investigation")
        from test_advantage_lifecycle import empty_gap_phase
        empty_gap_phase(context)
        begin("synthesis")
        if empty:
            command("finalize-advantage-synthesis.py", "--context", context_path)
        else:
            relative = pipeline.result_path(packet)
            accepted, accepted_link = authored_chain(context, plan["objectives"][0], relative)
            rejected, rejected_link = authored_chain(context, plan["objectives"][0], relative, "F-002", rejected=True)
            first_ref = "investigation/passes/PASS-001/results/TASK-001.json"
            synthesis = core.envelope(context, status="completed", reason="Consolidated queue boundary and rejected persistence extension without rediscovering baseline reads.",
                provenance=author(context, "vulnops-advantage-synthesis", "synthesis/findings.json"), findings=[accepted, rejected], links=[accepted_link, rejected_link],
                candidate_dispositions=([{"result_ref": first_ref, "candidate_id": "C-REDISCOVERY", "disposition": "baseline_revalidation", "finding_ids": [], "reason": "Same inherited read root and impact."}] if prior_ids else []) +
                    [{"result_ref": relative, "candidate_id": cid, "disposition": "promoted", "finding_ids": [fid], "reason": "Requires fresh independent review."} for cid, fid in (("C-CHAIN", "F-001"), ("C-REJECT", "F-002"))],
                baseline_reconciliation=[{"baseline_id": fid, "status": "revalidated", "finding_ids": [], "result_refs": [first_ref], "reason": "Original read outcome remains attributable; no new root count."} for fid in prior_ids])
            put(drafts / "synthesis.json", synthesis)
            command("finalize-advantage-synthesis.py", "--context", context_path, "--draft", drafts / "synthesis.json")
        finish("synthesis")
        begin("final-verification")
        if not empty:
            assignments = command("finalize-advantage-verification.py", "--context", context_path, "--prepare")
            for assignment in assignments["assignments"]:
                fid = assignment["finding_id"]
                finding = accepted if fid == "F-001" else rejected
                review = authored_review(context, finding, assignment, rejected=fid == "F-002")
                put(drafts / f"review-{fid}.json", review)
                delivered(fid, drafts / f"review-{fid}.json")
                command("finalize-advantage-verification.py", "--context", context_path, "--result", drafts / f"review-{fid}.json")
        command("finalize-advantage-verification.py", "--context", context_path)
        finish("final-verification")
        begin("handoff")
        command("finalize-advantage-handoff.py", base, "--context", context_path)
        finish("handoff")
        begin("report")
        command("render-advantage-report.py", "--context", context_path)
        finish("report")
        command("advantage-cleanup.py", "--context", context_path)
        assert not context_path.exists()
        command("validate-advantage.py", base, "--portable")
    return {"context": context, "report": pipeline.read_local(context, "report/security-report.json"), "commands": transcript}


class AdvantagePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        source, base, baseline = root / "source", root / "advantage", root / "audit"
        source.mkdir(); base.mkdir(); baseline.mkdir()
        (source / "source.py").write_text("def lookup(record_id):\n    return records[record_id]\n")
        (source / "app.py").write_text("\n".join(["# fixture"] * 10 + ["def update(user, record_id):", "    queue.append((user, record_id))", "def dispatch(path, record_id):", "    return ROUTES[path](CURRENT_USER, record_id)", "ROUTES = {'/records/update': update}"]) + "\n")
        put(baseline / "final-verification/findings.json", {"findings": []})
        put(baseline / "report/security-report.json", {"findings": []})
        put(base / "baseline/catalog.json", {"records": []})
        actors = ["vulnops-advantage-planning", "vulnops-advantage-investigator", "vulnops-advantage-synthesis", "vulnops-advantage-verify-one"]
        self.context = {"run_id": "linked-fixture", "execution_kind": "advantage", "scan_base": str(base), "source_root": str(source), "repo_path": str(source), "repositories": [{"path": "."}],
            "mode": "standard", "reproduction_mode": "off", "network": {"agent_egress": "policy_only", "backend": "none", "enforced": False, "limitation": "Fixture source-only policy."},
            "attempt_id": "attempt-current", "patch_binding": None, "source_run_id": "audit-fixture", "repo_name": "fixture",
            "baseline": {"execution_id": "audit-fixture", "root": str(baseline)},
            "model_routing": {"agents": {actor: "fixture/red:high" if actor != "vulnops-advantage-synthesis" else "fixture/astra:high" for actor in actors}},
            "budget": {"deep_passes": 2, "max_tasks": 12, "max_questions": 24, "max_concurrency": 4, "max_continuation_rounds": 1, "max_continuation_tasks": 4, "max_attempts": 2}}
        self.context["gap_exploration_budget"] = {
            "enabled": False, "max_questions": 0, "graph_timeout_seconds": 0,
            "preparation_timeout_seconds": 0, "max_tasks": 0, "max_concurrency": 1,
            "max_attempts": 2, "max_candidates": 0, "timeout_seconds": 1,
            "synthesis_timeout_seconds": 0, "verification_timeout_seconds": 0}
        self.base = base
        self.plan = authored_plan(self.context)
        put(base / "planning/plan.json", self.plan)
        self.packet = pipeline.packet(self.context, self.plan, self.plan["assignments"][0])
        put(base / "investigation/packets/TASK-001.json", self.packet)
        self.result = authored_result(self.context, self.packet)
        self.workers = []
        self.call = {"run_id": self.context["run_id"], "phase": "final-verification", "workers": self.workers,
                     "accepted_phases": ["baseline", "planning", "investigation", "gap-exploration", "synthesis"]}
        native = patch.object(core, "live_call", side_effect=lambda context, phase=None: self.call)
        native.start()
        self.addCleanup(native.stop)
        import gap_exploration_contract as gap
        put(base / "gap-exploration/results.json", gap.aggregate(self.context))
        gap.validate_analytical_phase(self.context)

    def native_start(self, phase, identity):
        """Synthetic child session-start, not model-authored dispatch accounting."""
        if phase == "final-verification":
            assignments = pipeline.verification_assignments(self.context)
            for assignment in assignments["assignments"]:
                put(self.base / f"final-verification/packets/{assignment['finding_id']}.json", assignment)
        _, actor, _, _ = pipeline.worker_input(self.context, phase, identity)
        prior = [row for row in self.workers if row["phase"] == phase and row["id"] == identity]
        self.assertFalse(any(row["status"] == "running" for row in prior))
        row = {"id": identity, "runtime_id": f"native-{phase}-{identity}-{len(prior) + 1}",
               "phase": phase, "actor": actor, "selector": self.context["model_routing"]["agents"][actor],
               "attempt": len(prior) + 1, "status": "running", "yield_valid": False,
               "input_sha256": pipeline.native_input_sha256(self.context, phase, identity),
               "artifacts": [], "artifact_sha256": {}, "error": ""}
        self.workers.append(row)
        return row

    def native_failure(self, phase, identity, reason):
        rows = [row for row in self.workers if row["phase"] == phase and row["id"] == identity and row["status"] == "running"]
        self.assertEqual(len(rows), 1)
        rows[0].update(status="failed", error=reason)

    def publish(self, phase, result):
        identity = result.get("task_id", result.get("finding_id"))
        rows = [row for row in self.workers if row["phase"] == phase and row["id"] == identity and row["status"] == "running"]
        row = rows[0] if rows else self.native_start(phase, identity)
        relative = f"{phase}/drafts/{identity}-{row['attempt']}.json"
        put(self.base / relative, result)
        row.update(status="completed", yield_valid=True, artifacts=[relative],
                   artifact_sha256={relative: core.sha256_file(self.base / relative)})
        with patch.object(pipeline, "owned"):
            return pipeline.admit_worker_result(self.context, phase, result)

    def test_duplicate_pass_ownership_and_global_allocations_reject(self):
        pipeline.validate_plan(self.context, self.plan)
        pipeline.validate_result(self.context, self.packet, self.result)
        before = (self.base / "investigation/packets/TASK-001.json").read_bytes()
        replacement = copy.deepcopy(self.packet)
        replacement["assignment"]["initial_access"] = "Changed access"
        with self.assertRaisesRegex(ValueError, "immutable"):
            pipeline.immutable(self.context, "investigation/packets/TASK-001.json", replacement)
        self.assertEqual((self.base / "investigation/packets/TASK-001.json").read_bytes(), before)
        duplicate = copy.deepcopy(self.plan)
        task = copy.deepcopy(duplicate["assignments"][0])
        task["task_id"] = "TASK-002"
        duplicate["assignments"].append(task)
        with self.assertRaisesRegex(ValueError, "ownership"):
            pipeline.validate_plan(self.context, duplicate)
        # The budget branch has valid ownership, unlike the duplicate above.
        self.context["budget"]["max_tasks"] = 0
        with patch.object(pipeline, "owned"), self.assertRaisesRegex(ValueError, "global"):
            pipeline.build_plan(self.context, self.plan)
        self.assertEqual((self.base / "investigation/packets/TASK-001.json").read_bytes(), before)
        self.assertFalse((self.base / "investigation/packets/TASK-002.json").exists())

    def test_gap_evidence_requires_native_acceptance_even_when_empty(self):
        self.call["accepted_phases"].remove("gap-exploration")
        with self.assertRaisesRegex(ValueError, "no native acceptance"):
            pipeline.gap_inputs(self.context)
        self.call["accepted_phases"].append("gap-exploration")
        self.assertEqual(pipeline.gap_inputs(self.context)["status"], "skipped")
        gap = pipeline.read_local(self.context, "gap-exploration/results.json")
        gap["summary"]["candidates"] = 1
        put(self.base / "gap-exploration/results.json", gap)
        with self.assertRaisesRegex(ValueError, "differs from actual native"):
            pipeline.gap_inputs(self.context)

    def test_wrong_worker_model_and_packet_binding_reject(self):
        for field, value in (("packet_sha256", "0" * 64), ("pass_id", "OTHER")):
            result = copy.deepcopy(self.result); result[field] = value
            with self.assertRaises(ValueError):
                pipeline.validate_result(self.context, self.packet, result)
        self.result["provenance"]["selector"] = "fixture/wrong:high"
        with self.assertRaisesRegex(ValueError, "provenance"):
            pipeline.validate_result(self.context, self.packet, self.result)

    def test_peer_result_consumption_is_not_independence(self):
        self.result["additional_baseline_refs"] = ["investigation/passes/PASS-002/results/PEER.json"]
        with self.assertRaisesRegex(ValueError, "peer results"):
            pipeline.validate_result(self.context, self.packet, self.result)


    def test_unadmitted_authored_result_cannot_be_consolidated(self):
        put(self.base / pipeline.result_path(self.packet), self.result)
        value = pipeline.investigation_projection(self.context)
        self.assertEqual(value["results"], [])
        self.assertEqual(value["question_outcomes"][0]["resolution"]["outcome"], "locally_unresolved")

    def test_complete_chain_requires_every_compatible_transition(self):
        candidate_result = copy.deepcopy(self.result)
        candidate_result["candidates"] = [candidate("C-CHAIN", "new_chain")]
        relative = pipeline.result_path(self.packet)
        put(self.base / relative, candidate_result)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        pipeline.validate_finding(self.context, finding, link)
        finding["transitions"][0]["obligations"]["scope_alignment"]["outcome"] = "contradicted"
        with self.assertRaisesRegex(ValueError, "obligation"):
            pipeline.validate_finding(self.context, finding, link)

    def test_full_dossier_source_example_and_remediation_proof_not_schema_only(self):
        relative = pipeline.result_path(self.packet)
        candidate_result = copy.deepcopy(self.result); candidate_result["candidates"] = [candidate("C-CHAIN", "new_chain")]
        put(self.base / relative, candidate_result)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        finding["technical_examples"][0]["content"] += "\n    authorize()"
        with self.assertRaisesRegex(ValueError, "cited range"):
            pipeline.validate_finding(self.context, finding, link)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        finding["remediation"]["actions"][0]["breaks_steps"] = ["invented"]
        with self.assertRaisesRegex(ValueError, "binding"):
            pipeline.validate_finding(self.context, finding, link)

    def test_fresh_review_cannot_invent_objective_or_model_diversity(self):
        relative = pipeline.result_path(self.packet)
        candidate_result = copy.deepcopy(self.result); candidate_result["candidates"] = [candidate("C-CHAIN", "new_chain")]
        put(self.base / relative, candidate_result)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        assignment = {"finding_id": finding["id"], "candidate_sha256": dossier_hash(finding), "actor": "vulnops-advantage-verify-one", "selector": "fixture/red:high", "fresh_context": True,
            "result_ref": "final-verification/results/F-001.json"}
        result = authored_review(self.context, finding, assignment)
        pipeline.validate_review(self.context, finding, link, assignment, result)
        self.assertFalse(result["model_diversity"])
        result["model_diversity"] = True
        with self.assertRaisesRegex(ValueError, "diversity"):
            pipeline.validate_review(self.context, finding, link, assignment, result)
        result["model_diversity"] = False
        result["objective_results"][0]["success_condition"] = "Become administrator."
        with self.assertRaisesRegex(ValueError, "success condition"):
            pipeline.validate_review(self.context, finding, link, assignment, result)


    def admit_fixture_result(self, result=None):
        result = self.result if result is None else result
        identity = result["task_id"]
        self.workers[:] = [row for row in self.workers if not (row["phase"] == "investigation" and row["id"] == identity)]
        relative = pipeline.result_path(self.packet)
        (self.base / relative).unlink(missing_ok=True)
        return self.publish("investigation", result)["result_ref"]

    def wave_fixture(self):
        relative = self.admit_fixture_result()
        task = copy.deepcopy(self.plan["assignments"][0]); task["task_id"] = "TASK-002"
        continuation = {"predecessor_task_id": "TASK-001", "predecessor_sha256": core.sha256_file(self.base / relative),
            "changed_hypothesis": "Inspect a separate consumer condition.", "evidence_delta": [], "alternative_path": "",
            "next_proof_obligation": "Identify the concrete consumer authority."}
        return core.envelope(self.context, wave=1, tasks=[{"assignment": task, "continuation": continuation}])

    def test_continuation_requires_real_progress_and_bound_predecessor(self):
        rejected = copy.deepcopy(self.plan)
        question = rejected["questions"][0]
        question["prior_disposition"] = "rejected"
        with self.assertRaisesRegex(ValueError, "rejected route"):
            pipeline.validate_plan(self.context, rejected)
        question.update(changed_hypothesis="Inspect the separate queue producer.",
                        evidence_delta=["source.py:2"], counterevidence=["source.py:1"])
        pipeline.validate_plan(self.context, rejected)
        wave = self.wave_fixture()
        with self.assertRaisesRegex(ValueError, "no evidence delta"):
            pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        wave["tasks"][0]["continuation"].update(evidence_delta=["source.py:2"], predecessor_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "predecessor hash"):
            pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        wave = self.wave_fixture()
        continuation = wave["tasks"][0]["continuation"]
        continuation["evidence_delta"] = ["source.py:999"]
        with self.assertRaisesRegex(ValueError, "no evidence delta"):
            pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        continuation["alternative_path"] = "Inspect a separately authorized consumer entrypoint."
        pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        continuation["next_proof_obligation"] = self.plan["questions"][0]["proof_obligation"]
        with self.assertRaisesRegex(ValueError, "unchanged"):
            pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})

        self.result["question_outcomes"][0]["resolution"] = resolution("externally_blocked")
        wave = self.wave_fixture()
        wave["tasks"][0]["continuation"]["alternative_path"] = "Try the same local route again."
        with self.assertRaisesRegex(ValueError, "external blockers"):
            pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        wave["wave"] = 2
        with self.assertRaisesRegex(ValueError, "allocation exhausted"):
            pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        self.result["question_outcomes"][0]["resolution"] = resolution("contradicted")
        self.result["question_outcomes"][0]["resolution"]["counterevidence"] = ["source.py:1-2"]
        wave = self.wave_fixture()
        wave["tasks"][0]["continuation"]["alternative_path"] = "Inspect the distinct queued consumer rather than the contradicted lookup route."
        pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        put(self.base / "investigation/waves/001.json", wave)
        continuation_packet = pipeline.packet(self.context, self.plan, wave["tasks"][0]["assignment"], 1,
                                              wave["tasks"][0]["continuation"])
        put(self.base / "investigation/packets/TASK-002.json", continuation_packet)
        self.assertEqual(set(pipeline.packets(self.context)), {"TASK-001", "TASK-002"})
        self.assertEqual(self.result["question_outcomes"][0]["resolution"]["outcome"], "contradicted")

    def test_mutated_successful_result_does_not_retain_admission(self):
        relative = self.admit_fixture_result()
        self.result["question_outcomes"][0]["resolution"]["reason"] = "Changed after successful admission."
        put(self.base / relative, self.result)
        projected = pipeline.investigation_projection(self.context)
        self.assertEqual(projected["results"], [])
        self.assertEqual(projected["question_outcomes"][0]["resolution"]["established_facts"], [])

    def test_deep_passes_share_baseline_but_not_question_ownership(self):
        self.context["mode"] = "deep"
        plan = authored_plan(self.context)
        pipeline.validate_plan(self.context, plan, allocating=True)
        self.context["budget"]["max_questions"] = 1
        with patch.object(pipeline, "owned"), self.assertRaisesRegex(ValueError, "global"):
            pipeline.build_plan(self.context, plan)
        peer_id = plan["assignments"][1]["task_id"]
        self.assertFalse((self.base / f"investigation/packets/{peer_id}.json").exists())
        self.context["budget"]["max_questions"] = 24
        (self.base / "planning/plan.json").unlink()
        (self.base / "investigation/packets/TASK-001.json").unlink()
        baseline_bytes = (self.base / "baseline/catalog.json").read_bytes()
        with patch.object(pipeline, "owned"), patch.object(core, "finalize_phase"):
            pipeline.build_plan(self.context, plan)
        packets = [pipeline.read_local(self.context, f"investigation/packets/{task['task_id']}.json")
                   for task in plan["assignments"]]
        self.assertEqual({packet["assignment"]["pass_id"] for packet in packets}, {"PASS-001", "PASS-002"})
        self.assertEqual([packet["baseline_catalog"] for packet in packets], ["baseline/catalog.json"] * 2)
        self.assertEqual(packets[0]["questions"], packets[1]["questions"])
        self.assertEqual((self.base / "baseline/catalog.json").read_bytes(), baseline_bytes)

    def test_dedup_uses_control_locations_not_title_or_weakness_family(self):
        draft = self.synthesis_fixture()
        first = draft["findings"][0]
        first.update(finding_kind="code", primitive_steps=[], transitions=[])
        for step in first["exploitation"]["steps"]:
            step["primitive_ids"] = []
        draft["links"][0]["classification"] = "new_root"
        duplicate = copy.deepcopy(first)
        duplicate.update(id="F-003", title="A different narrative title")
        duplicate["root_causes"][0]["mechanism"] = "Equivalent wording for the absent ownership predicate."
        sibling = copy.deepcopy(first)
        sibling["id"] = "F-004"
        sibling["root_causes"][0]["line"] = 11
        sibling["affected_components"][0]["locations"][0]["line"] = 11
        for finding in (duplicate, sibling):
            draft["findings"].append(finding)
            draft["links"].append({**draft["links"][0], "finding_id": finding["id"]})
        draft["candidate_dispositions"][0]["finding_ids"] = ["F-001", "F-003", "F-004"]
        before = copy.deepcopy(draft)
        admitted = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual([finding["id"] for finding in admitted["findings"]], ["F-002", "F-004"])
        self.assertEqual(admitted["candidate_dispositions"][0]["finding_ids"], ["F-004"])
        self.assertEqual(len(admitted["non_promoted"]), 2)
        self.assertEqual({row["code"] for row in admitted["evidence_quality"]["diagnostics"]}, {"ambiguous_record"})
        self.assertEqual(draft, before)

    def test_typed_inherited_contributors_cannot_be_laundered_by_synthesis(self):
        baseline = sample_finding()
        baseline.update(status="verified", verdict="confirmed")
        baseline["contributors"][0]["selector"] = "fixture/red:high"
        baseline_path = Path(self.context["baseline"]["root"]) / "final-verification/findings.json"
        put(baseline_path, {"findings": [baseline]})
        put(self.base / "planning/plan.json", self.plan)
        self.packet = pipeline.packet(self.context, self.plan, self.plan["assignments"][0])
        put(self.base / "investigation/packets/TASK-001.json", self.packet)
        self.result = authored_result(self.context, self.packet)
        relative = pipeline.result_path(self.packet)
        result = copy.deepcopy(self.result); result["candidates"] = [candidate("C-CHAIN", "new_chain")]
        put(self.base / relative, result)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        link["baseline_ids"] = ["F-001"]
        finding["source_refs"].append({"kind": "sast", "source_id": "F-001", "artifact_ref": {
            "execution_id": self.context["baseline"]["execution_id"], "artifact_ref": "final-verification/findings.json#/findings/0"}})
        finding["contributors"] = pipeline.contributor_union(self.context, finding, link)
        pipeline.validate_finding(self.context, finding, link)
        self.assertTrue(any(row["execution_id"] == "audit-fixture" for row in finding["contributors"]))
        finding["contributors"] = [row for row in finding["contributors"] if row["execution_id"] != "audit-fixture"]
        with self.assertRaisesRegex(ValueError, "contributor union"):
            pipeline.validate_finding(self.context, finding, link)

    def test_unstarted_work_stays_unresolved_without_fake_execution(self):
        self.context["budget"].update(max_tasks=0, max_questions=0)
        projected = pipeline.investigation_projection(self.context)
        self.assertEqual(projected["question_outcomes"][0]["resolution"]["outcome"], "locally_unresolved")
        self.assertEqual(self.workers, [])
        self.assertFalse((self.base / pipeline.result_path(self.packet)).exists())

    def test_historical_confirmed_finding_is_not_a_current_capability(self):
        baseline = sample_finding()
        baseline.update(status="verified", verdict="confirmed")
        put(Path(self.context["baseline"]["root"]) / "final-verification/findings.json", {"findings": [baseline]})
        task = copy.deepcopy(self.plan["assignments"][0])
        task["available_capabilities"] = [{"capability": "Read another account's record",
            "status": "source_established", "conditions": [], "evidence_refs": [
            "source.py:1-2", {"execution_id": "audit-fixture", "artifact_ref": "final-verification/findings.json#/findings/0"}]}]
        with self.assertRaisesRegex(ValueError, "historical evidence"):
            pipeline.validate_assignment(self.context, task, pipeline.unique(self.plan["questions"]))
        self.plan["assignments"][0]["available_capabilities"] = [{
            "capability": "Read another account's record",
            "status": "source_established", "conditions": [], "evidence_refs": ["source.py:999"]}]
        (self.base / "planning/plan.json").unlink()
        (self.base / "investigation/packets/TASK-001.json").unlink()
        with patch.object(pipeline, "owned"), patch.object(core, "finalize_phase"):
            pipeline.build_plan(self.context, self.plan)
        published = pipeline.read_local(self.context, "investigation/packets/TASK-001.json")
        capability = published["assignment"]["available_capabilities"][0]
        self.assertEqual(capability["status"], "conditional")
        self.assertTrue(capability["conditions"])
        self.assertEqual(pipeline.read_local(self.context, "planning/plan.json")["evidence_quality"]["diagnostics"][0]["code"],
                         "invalid_range")

    def report_fixture(self, current=True):
        result = copy.deepcopy(self.result)
        result["candidates"] = [candidate("C-CHAIN", "new_chain")]
        relative = self.admit_fixture_result(result)
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        synthesis = core.envelope(self.context, status="completed", reason="Source-backed queue insertion dossier.",
            provenance=author(self.context, "vulnops-advantage-synthesis", "synthesis/findings.json"),
            findings=[finding], links=[link], baseline_reconciliation=[],
            candidate_dispositions=[{"result_ref": relative, "candidate_id": "C-CHAIN", "disposition": "promoted",
                "finding_ids": [finding["id"]], "reason": "Requires independent source review."}])
        synthesis = pipeline.admitted_synthesis(self.context, synthesis)
        put(self.base / "synthesis/findings.json", synthesis)
        with patch.object(pipeline, "owned"):
            assignments = pipeline.prepare_verification(self.context)
        self.publish("final-verification", authored_review(self.context, synthesis["findings"][0],
                                                          assignments["assignments"][0]))
        final = pipeline.verification_projection(self.context)
        put(self.base / "final-verification/findings.json", final)
        return final["findings"][0]

    def test_report_projection_preserves_reviewed_dossier_without_publishing(self):
        finding = self.report_fixture(current=True)
        before = (self.base / "final-verification/findings.json").read_bytes()
        report = pipeline.report_projection(self.context)
        self.assertEqual(report["findings"], [finding])
        self.assertEqual(report["cohort_counts"]["assessed"]["total"], 1)
        self.assertEqual(report["counts"]["assessed_confirmed"], 1)
        self.assertFalse((self.base / "report/security-report.json").exists())
        self.assertEqual((self.base / "final-verification/findings.json").read_bytes(), before)

    def test_report_cannot_publish_without_live_aggregate_validation(self):
        self.report_fixture(current=True)
        investigation = pipeline.read_local(self.context, "investigation/results.json")
        investigation["results"] = []
        put(self.base / "investigation/results.json", investigation)
        with patch.object(pipeline, "owned"), self.assertRaisesRegex(ValueError, "aggregation differs"):
            pipeline.render_report(self.context)
        self.assertFalse((self.base / "report/security-report.json").exists())

    def test_report_requires_original_review_and_exact_effective_dossier(self):
        finding = self.report_fixture()
        path = self.base / "final-verification/findings.json"
        final = core.load(path)
        final["findings"][0]["impact"] += " An unreviewed expansion."
        put(path, final)
        with self.assertRaisesRegex(ValueError, "independent dossier review"):
            pipeline.report_projection(self.context)
        final["findings"] = [finding]
        put(path, final)
        (self.base / finding["independent_verification_ref"]).unlink()
        with self.assertRaisesRegex(ValueError, "final-verification/results/F-001.json"):
            pipeline.report_projection(self.context)

    def test_objectives_and_revalidation_preserve_original_impact_accounting(self):
        result = copy.deepcopy(self.result)
        result["candidates"] = [candidate("C-CHAIN", "baseline_revalidation", baseline_ids=["F-003"])]
        relative = pipeline.result_path(self.packet)
        put(self.base / relative, result)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        inherited = copy.deepcopy(finding)
        inherited.update(id="F-003", contributors=[{"actor": "vulnops-synthesis",
            "selector": "fixture/old:high", "artifact_ref": "synthesis/findings.json"}], verdict="confirmed")
        put(Path(self.context["baseline"]["root"]) / "final-verification/findings.json", {"findings": [inherited]})
        self.admit_fixture_result(result)
        link.update(classification="baseline_revalidation", baseline_ids=["F-003"])
        finding["contributors"] = pipeline.contributor_union(self.context, finding, link)
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        draft = core.envelope(self.context, status="completed", reason="Reassess the inherited root without adding impact.",
            provenance=author(self.context, "vulnops-advantage-synthesis", "synthesis/findings.json"),
            findings=[finding], links=[link],
            candidate_dispositions=[{"result_ref": relative, "candidate_id": "C-CHAIN", "disposition": "promoted",
                "finding_ids": [finding["id"]], "reason": "Requires current independent review."}],
            baseline_reconciliation=[{"baseline_id": "F-003", "status": "revalidated",
                "finding_ids": [finding["id"]], "result_refs": [relative], "reason": "Same bounded inherited capability."}])
        synthesis = pipeline.admitted_synthesis(self.context, draft)
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = pipeline.verification_assignments(self.context)
        put(self.base / "final-verification/assignments.json", assignments)
        with patch.object(pipeline, "owned"):
            self.native_start("final-verification", finding["id"])
            receipt = self.publish("final-verification",
                authored_review(self.context, finding, assignments["assignments"][0]))
        self.assertEqual(receipt["status"], "completed")
        final = pipeline.verification_projection(self.context)
        self.assertEqual(final["objective_assessments"][0]["status"], "achieved")
        final_path = self.base / "final-verification/findings.json"
        put(final_path, final)
        before = final_path.read_bytes()
        for mode in ("standard", "deep"):
            with self.subTest(mode=mode):
                self.context["mode"] = mode
                report = pipeline.report_projection(self.context)
                self.assertEqual(report["objective_assessments"], final["objective_assessments"])
                self.assertEqual(report["baseline_reconciliation"], final["baseline_reconciliation"])
                self.assertEqual(report["counts"]["assessed_confirmed"], 1)
                self.assertEqual(report["counts"]["baseline_revalidated"], 1)
                self.assertEqual(sum(report["counts"][key] for key in ("new_roots", "new_chains", "impact_expansions")), 0)
                self.assertFalse(report["assessment"]["retained"])
                self.assertEqual(final_path.read_bytes(), before)

    def test_persistent_baseline_requires_explicit_reviewable_revalidation_dossier(self):
        result = copy.deepcopy(self.result)
        result["candidates"] = [candidate("C-CHAIN", "baseline_revalidation", baseline_ids=["F-003"])]
        relative = pipeline.result_path(self.packet)
        put(self.base / relative, result)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        baseline = copy.deepcopy(finding)
        baseline.update(id="F-003", contributors=[{"actor": "vulnops-synthesis",
            "selector": "fixture/old:high", "artifact_ref": "synthesis/findings.json"}], verdict="confirmed")
        put(Path(self.context["baseline"]["root"]) / "final-verification/findings.json", {"findings": [baseline]})
        self.admit_fixture_result(result)
        link.update(classification="baseline_revalidation", baseline_ids=["F-003"])
        finding["contributors"] = pipeline.contributor_union(self.context, finding, link)
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        synthesis = core.envelope(self.context, status="completed", reason="Fresh investigation supports independent review of the persistent root.",
            provenance=author(self.context, "vulnops-advantage-synthesis", "synthesis/findings.json"),
            findings=[finding], links=[link],
            candidate_dispositions=[{"result_ref": relative, "candidate_id": "C-CHAIN", "disposition": "promoted",
                "finding_ids": [finding["id"]], "reason": "Submit the same historical root to current independent review."}],
            baseline_reconciliation=[{"baseline_id": "F-003", "status": "revalidated", "finding_ids": [finding["id"]],
                "result_refs": [relative], "reason": "Fresh source investigation; independent review still required."}])
        pipeline.validate_synthesis(self.context, synthesis)
        self.assertNotIn("assessment_context", finding)
        link["classification"] = "new_chain"
        with self.assertRaisesRegex(ValueError, "baseline rediscovery"):
            pipeline.validate_synthesis(self.context, synthesis)

    

    

    

    

    

    

    


    def test_valid_bound_evidence_survives_failed_outer_terminal_envelope(self):
        wave = self.wave_fixture()
        wave["tasks"][0]["continuation"]["alternative_path"] = "Inspect a distinct consumer."
        self.workers[0].update(status="failed", yield_valid=False, error="Native execution failed.")
        pipeline.validate_wave(self.context, wave, {"TASK-001": self.packet})
        self.assertEqual(len(pipeline.investigation_projection(self.context)["results"]), 1)

    

    def test_mixed_candidate_admission_preserves_supported_neighbor_and_draft(self):
        put(self.base / "investigation/context.json", {"reason": "Not source proof"})
        for reference, code in (("app.py:900-901", "invalid_range"),
                                ("investigation/context.json", "missing_record"),
                                ({"artifact_ref": "missing execution identity"}, "unreadable_content")):
            with self.subTest(reference=reference):
                self.result["candidates"] = [candidate("C-GOOD", "new_chain"), candidate("C-BAD", "new_chain")]
                self.result["candidates"][1]["evidence_refs"] = [reference]
                before = copy.deepcopy(self.result)
                admitted = pipeline.admitted_result(self.context, self.packet, self.result)
                self.assertEqual([row["id"] for row in admitted["candidates"]], ["C-GOOD"])
                self.assertEqual(admitted["question_outcomes"], self.result["question_outcomes"])
                self.assertEqual(self.result, before)
                self.assertEqual(admitted["non_promoted"][0]["input_refs"], [pipeline.result_path(self.packet) + "#/candidates/1"])
                self.assertIsNone(admitted["non_promoted"][0]["review"])
                self.assertIsNone(admitted["non_promoted"][0]["deferral"])
                self.assertIn(code, {row["code"] for row in admitted["evidence_quality"]["diagnostics"]})
        good = candidate("C-GOOD", "new_chain")
        bad = candidate("C-BAD", "new_chain")
        del bad["id"]
        array_id = candidate("C-ARRAY", "new_chain")
        array_id["id"] = ["not", "an", "identity"]
        duplicate = candidate("C-DUP", "new_chain")
        self.result["candidates"] = [good, bad, array_id, duplicate, copy.deepcopy(duplicate)]
        admitted = pipeline.admitted_result(self.context, self.packet, self.result)
        self.assertEqual(admitted["candidates"], [good])
        self.assertEqual(len(admitted["non_promoted"]), 4)
        self.assertEqual(len({row["id"] for row in admitted["non_promoted"]}), 4)

    def test_optional_support_requires_explicit_inspected_sufficiency(self):
        row = candidate("C-GOOD", "new_chain")
        row["evidence_refs"].append("app.py:900-901")
        self.result["candidates"] = [row]
        self.assertEqual(pipeline.admitted_result(self.context, self.packet, self.result)["candidates"], [])
        row["optional_support"] = [{"reference": "app.py:900-901",
            "obligation": "The supplied identifier reaches the queue without an ownership decision.",
            "independent_support": ["app.py:11-15"],
            "rationale": "Inspected dispatcher and queue append independently prove the same bounded insertion; the absent range adds no necessary step."}]
        admitted = pipeline.admitted_result(self.context, self.packet, self.result)
        self.assertEqual([item["id"] for item in admitted["candidates"]], ["C-GOOD"])
        self.assertNotIn("app.py:900-901", admitted["candidates"][0]["evidence_refs"])
        self.assertEqual(admitted["evidence_quality"]["diagnostics"][0]["disposition"], "optional")
        row["optional_support"][0]["independent_support"] = ["app.py:800-801"]
        self.assertEqual(pipeline.admitted_result(self.context, self.packet, self.result)["candidates"], [])


    def test_missing_or_malformed_question_is_unresolved_not_established(self):
        duplicate = copy.deepcopy(self.result)
        duplicate["question_outcomes"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pipeline.validate_result(self.context, self.packet, duplicate)
        blocked = copy.deepcopy(self.result)
        blocked["question_outcomes"][0]["resolution"]["outcome"] = "externally_blocked"
        with self.assertRaisesRegex(ValueError, "missing fact"):
            pipeline.validate_result(self.context, self.packet, blocked)
        self.result["question_outcomes"][0]["resolution"]["evidence_refs"] = ["source.py:99"]
        admitted = pipeline.admitted_result(self.context, self.packet, self.result)
        self.assertEqual(admitted["question_outcomes"][0]["resolution"]["outcome"], "locally_unresolved")
        self.assertEqual(admitted["question_outcomes"][0]["resolution"]["established_facts"], [])
        self.result["question_outcomes"] = []
        admitted = pipeline.admitted_result(self.context, self.packet, self.result)
        self.assertEqual(len(admitted["question_outcomes"]), 1)
        self.assertEqual(admitted["non_promoted"][0]["diagnostics"][0]["code"], "missing_record")

    def test_bad_candidate_does_not_hide_foreign_provenance_or_unsafe_path(self):
        self.result["candidates"] = [candidate("C-BAD", "new_chain", "app.py:999")]
        self.result["provenance"]["execution_id"] = "foreign"
        with self.assertRaisesRegex(ValueError, "provenance"):
            pipeline.admitted_result(self.context, self.packet, self.result)
        self.result["provenance"]["execution_id"] = self.context["run_id"]
        self.result["candidates"][0]["id"] = None
        self.result["candidates"][0]["source_locations"][0]["file"] = "../outside.py"
        with self.assertRaises(ValueError):
            pipeline.admitted_result(self.context, self.packet, self.result)
        self.result["candidates"] = [candidate("C-GOOD", "new_chain"), candidate("C-BAD", "new_chain")]
        self.result["candidates"][1]["evidence_refs"] = [
            {"execution_id": "foreign", "artifact_ref": "final-verification/findings.json"}]
        with self.assertRaisesRegex(ValueError, "owner"):
            pipeline.admitted_result(self.context, self.packet, self.result)

    def test_admitted_subset_is_exactly_bound_to_success_receipt(self):
        self.plan["objectives"][0]["evidence_refs"] = ["source.py:999"]
        self.plan["questions"][0]["evidence_refs"] = ["missing.py:1"]
        pipeline.validate_plan(self.context, self.plan)
        self.assertEqual({row["code"] for row in self.context["_planning_issues"]}, {"invalid_range", "missing_file"})
        self.result["candidates"] = [candidate("C-GOOD", "new_chain"), candidate("C-BAD", "new_chain", "app.py:999")]
        before = copy.deepcopy(self.result)
        with patch.object(pipeline, "owned"):
            self.native_start("investigation", "TASK-001")
            receipt = self.publish("investigation", self.result)
        self.assertEqual(self.result, before)
        canonical = pipeline.read_local(self.context, receipt["result_ref"])
        self.assertEqual([row["id"] for row in canonical["candidates"]], ["C-GOOD"])
        self.assertEqual(receipt["result_sha256"], core.sha256_file(self.base / receipt["result_ref"]))
        projection = pipeline.investigation_projection(self.context)
        self.assertEqual(len(projection["results"]), 1)
        self.assertEqual(len(projection["non_promoted"]), 1)

    def test_unadmitted_terminal_worker_closes_without_retry_exhaustion(self):
        worker = self.native_start("investigation", "TASK-001")
        worker.update(status="completed", yield_valid=True)
        projection = pipeline.investigation_projection(self.context)
        self.assertEqual(projection["results"], [])
        self.assertEqual(projection["question_outcomes"][0]["resolution"]["outcome"], "locally_unresolved")
        self.assertEqual(projection["question_outcomes"][0]["resolution"]["established_facts"], [])
        self.assertEqual(worker["attempt"], 1)
        self.assertEqual(worker["status"], "completed")
        self.assertFalse((self.base / pipeline.result_path(self.packet)).exists())

    def test_missing_review_does_not_block_independently_accepted_peer(self):
        synthesis = pipeline.admitted_synthesis(self.context, self.synthesis_fixture())
        put(self.base / "synthesis/findings.json", synthesis)
        with patch.object(pipeline, "owned"):
            assignments = pipeline.prepare_verification(self.context)["assignments"]
        accepted = self.publish("final-verification", authored_review(
            self.context, synthesis["findings"][0], assignments[0]))
        accepted_bytes = (self.base / accepted["result_ref"]).read_bytes()
        projection = pipeline.verification_projection(self.context)
        self.assertEqual([finding["id"] for finding in projection["findings"]], ["F-001"])
        self.assertEqual([(row["finding_id"], row["outcome"]) for row in projection["unconfirmed"]],
                         [("F-002", "locally_unresolved")])
        self.assertEqual((self.base / accepted["result_ref"]).read_bytes(), accepted_bytes)
        self.assertFalse(any(row["id"] == "F-002" for row in self.workers))

    def failed_investigator(self):
        self.native_start("investigation", "TASK-001")
        self.native_failure("investigation", "TASK-001", "Native worker failed before usable publication.")

    def test_actual_worker_failure_needs_no_exhaustion_to_close(self):
        self.failed_investigator()
        projection = pipeline.investigation_projection(self.context)
        self.assertEqual(projection["results"], [])
        self.assertEqual(projection["question_outcomes"][0]["resolution"]["outcome"], "execution_failed")
        self.assertEqual(projection["question_outcomes"][0]["resolution"]["established_facts"], [])
        self.assertFalse((self.base / pipeline.result_path(self.packet)).exists())

    def synthesis_fixture(self):
        self.result["candidates"] = [candidate("C-CHAIN", "new_chain"), candidate("C-REJECT", "new_chain")]
        relative = self.admit_fixture_result()
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        first, first_link = authored_chain(self.context, self.plan["objectives"][0], relative)
        second, second_link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-002", rejected=True)
        return core.envelope(self.context, status="completed", reason="Two independently reviewable bounded claims.",
            provenance=author(self.context, "vulnops-advantage-synthesis", "synthesis/findings.json"),
            findings=[first, second], links=[first_link, second_link],
            candidate_dispositions=[{"result_ref": relative, "candidate_id": cid, "disposition": "promoted",
                "finding_ids": [fid], "reason": "Requires independent review."}
                for cid, fid in (("C-CHAIN", "F-001"), ("C-REJECT", "F-002"))], baseline_reconciliation=[])

    def test_candidate_selector_forms_preserve_synthesis_and_contributors(self):
        draft = self.synthesis_fixture()
        expected = pipeline.admitted_synthesis(self.context, draft)
        for form in ("colon", "hash", "pointer"):
            variant = copy.deepcopy(draft)
            for index, finding in enumerate(variant["findings"]):
                source = finding["source_refs"][0]
                suffix = f"#/candidates/{index}" if form == "pointer" else (
                    ":" if form == "colon" else "#") + source["source_id"]
                source["artifact_ref"] += suffix
            admitted = pipeline.admitted_synthesis(self.context, variant)
            with self.subTest(form=form):
                self.assertEqual(admitted["candidate_dispositions"], expected["candidate_dispositions"])
                self.assertEqual([f["id"] for f in admitted["findings"]], ["F-001", "F-002"])
                self.assertEqual([f["contributors"] for f in admitted["findings"]],
                                 [f["contributors"] for f in expected["findings"]])

    def test_inherited_accounting_is_carried_without_reauthoring(self):
        from dossier_contract import DossierAuthoringError
        draft = self.synthesis_fixture()
        relative = pipeline.result_path(self.packet)
        inherited = inherited_accounting(self.context, relative)
        investigation = pipeline.read_local(self.context, "investigation/results.json")
        investigation["non_promoted"] = inherited
        put(self.base / "investigation/results.json", investigation)
        before = (self.base / "investigation/results.json").read_bytes()
        for echo in (False, True):
            authored = copy.deepcopy(draft)
            if echo:
                authored["non_promoted"] = copy.deepcopy(inherited)
            admitted = pipeline.admitted_synthesis(self.context, authored)
            self.assertEqual(admitted["non_promoted"], inherited)
            self.assertEqual(admitted["findings"], draft["findings"])
        changed = copy.deepcopy(draft)
        changed["non_promoted"] = copy.deepcopy(inherited)
        changed["non_promoted"][0]["reason"] = "Replacement disposition."
        with self.assertRaisesRegex(DossierAuthoringError, "protected original"):
            pipeline.admitted_synthesis(self.context, changed)
        self.assertEqual((self.base / "investigation/results.json").read_bytes(), before)
        new = copy.deepcopy(draft)
        new["non_promoted"] = [{**inherited[1], "id": "NEW-REVIEW"}]
        with self.assertRaisesRegex(ValueError, "actor differs"):
            pipeline.admitted_synthesis(self.context, new)

    def test_malformed_dossier_is_dropped_without_losing_healthy_peer(self):
        draft = self.synthesis_fixture()
        supported = copy.deepcopy(draft["findings"][0])
        del draft["findings"][1]["impact"]
        draft["findings"][1]["severity"] = "PRIVATE_AUTHORED_VALUE"
        original = (self.base / "investigation/results.json").read_bytes()
        with patch.object(pipeline, "owned"), patch.object(core, "finalize_phase"):
            pipeline.finalize_synthesis(self.context, draft)
        published = pipeline.read_local(self.context, "synthesis/findings.json")
        self.assertEqual(published["findings"], [supported])
        self.assertEqual(published["candidate_dispositions"][1]["disposition"], "unresolved")
        self.assertNotIn("PRIVATE_AUTHORED_VALUE", json.dumps(published))
        self.assertEqual((self.base / "investigation/results.json").read_bytes(), original)

    def test_invalid_evidence_link_drops_only_its_dependent_dossier(self):
        draft = self.synthesis_fixture()
        del draft["links"][1]["result_refs"]
        admitted = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual([row["id"] for row in admitted["findings"]], ["F-001"])
        self.assertEqual(admitted["candidate_dispositions"][1]["disposition"], "unresolved")

    def test_missing_authoring_preserves_unreviewed_candidates_without_fabricated_findings(self):
        self.synthesis_fixture()
        with patch.object(pipeline, "owned"), patch.object(core, "finalize_phase"):
            pipeline.finalize_synthesis(self.context)
        published = pipeline.read_local(self.context, "synthesis/findings.json")
        self.assertEqual(published["findings"], [])
        self.assertEqual({row["candidate_id"] for row in published["candidate_dispositions"]},
                         {"C-CHAIN", "C-REJECT"})
        self.assertTrue(all(row["disposition"] == "unresolved" and not row["finding_ids"]
                            for row in published["candidate_dispositions"]))


    def test_synthesis_chain_missing_transition_blocks_only_dependent_dossier(self):
        draft = self.synthesis_fixture()
        supported = copy.deepcopy(draft["findings"][0])
        draft["findings"][1]["transitions"] = []
        before = copy.deepcopy(draft)
        admitted = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual(admitted["findings"], [supported])
        self.assertEqual(admitted["candidate_dispositions"][1]["disposition"], "unresolved")
        self.assertEqual(len(admitted["non_promoted"]), 1)
        self.assertEqual(draft, before)
        draft = self.synthesis_fixture()
        draft["findings"][0]["verification"]["source_validation_refs"] = ["app.py:999"]
        draft["findings"][1]["verification"]["source_validation_refs"] = ["app.py:999"]
        admitted = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual(admitted["findings"], [])
        self.assertEqual(admitted["status"], "empty")
        self.assertEqual(len(admitted["non_promoted"]), 2)
        self.assertTrue(all(row["disposition"] == "unresolved" for row in admitted["candidate_dispositions"]))

    def test_synthesis_exclusion_keeps_resolvable_candidate_and_failed_field(self):
        draft = self.synthesis_fixture()
        draft["findings"][1]["source_refs"][0]["artifact_ref"] += ":C-MISSING"
        admitted = pipeline.admitted_synthesis(self.context, draft)
        put(self.base / "synthesis/findings.json", admitted)
        self.assertEqual([finding["id"] for finding in admitted["findings"]], ["F-001"])
        closure = admitted["non_promoted"][0]
        self.assertEqual(closure["disposition"], "evidence_limited")
        self.assertEqual(closure["diagnostics"][0]["field"], "findings[1].source_refs[0]")
        self.assertEqual(closure["diagnostics"][0]["code"], "missing_record")
        self.assertEqual(closure["diagnostics"][0]["affected_item_ids"], ["F-002"])
        self.assertEqual(core.resolve_reference(self.context, closure["input_refs"][0], kind="artifact")["id"],
                         "C-REJECT")
        self.assertIn(closure["diagnostics"][0]["field"], closure["missing_fact"])
        self.assertEqual(draft["findings"][1]["id"], "F-002")

    def test_synthesis_deferral_does_not_require_cosmetic_repair(self):
        for kind, reason in (
                ("priority", "Investigate the reachable high-impact queue consumer before cosmetic dossier repair."),
                ("external", "The authorized queue-consumer implementation is unavailable to this investigation."),
                ("budget", "The assigned synthesis invocation has exhausted its existing authoring deadline.")):
            with self.subTest(kind=kind):
                draft = self.synthesis_fixture()
                draft["findings"] = draft["findings"][:1]
                draft["links"] = draft["links"][:1]
                draft["candidate_dispositions"][1].update(disposition="unresolved", finding_ids=[], reason=reason)
                closure = pipeline.excluded_item(pipeline.result_path(self.packet), "candidates[1]", [])
                closure["deferral"] = {"kind": kind, "reason": reason}
                draft["non_promoted"] = [closure]
                admitted = pipeline.admitted_synthesis(self.context, draft)
                self.assertEqual(admitted["non_promoted"], [closure])
                self.assertEqual([finding["id"] for finding in admitted["findings"]], ["F-001"])
                self.assertEqual(admitted["candidate_dispositions"][1]["disposition"], "unresolved")

    def test_bad_source_example_is_excluded_without_forcing_repair(self):
        draft = self.synthesis_fixture()
        supported = copy.deepcopy(draft["findings"][0])
        correct_example = copy.deepcopy(draft["findings"][1]["technical_examples"][0])
        investigation = (self.base / "investigation/results.json").read_bytes()
        draft["findings"][1]["technical_examples"][0]["content"] += "\n    invented_authorization()"
        rejected = copy.deepcopy(draft)
        excluded = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual(excluded["findings"], [supported])
        self.assertEqual(excluded["candidate_dispositions"][1]["disposition"], "unresolved")
        self.assertEqual(draft, rejected)
        self.assertEqual((self.base / "investigation/results.json").read_bytes(), investigation)
        draft["findings"][1]["technical_examples"][0] = correct_example
        admitted = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual(admitted["findings"][0], supported)
        self.assertEqual([row["id"] for row in admitted["findings"]], ["F-001", "F-002"])
        self.assertTrue(all(row["disposition"] == "promoted" for row in admitted["candidate_dispositions"]))
        self.assertEqual(admitted["non_promoted"], [])

        draft = self.synthesis_fixture()
        draft["links"][1]["classification"] = "new_root"
        excluded = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual([finding["id"] for finding in excluded["findings"]], ["F-001"])
        self.assertEqual(len(draft["findings"]), 2)
        draft["links"][1]["classification"] = "new_chain"
        admitted = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual([finding["id"] for finding in admitted["findings"]], ["F-001", "F-002"])


    def test_unusable_review_never_fabricates_approval_or_requires_retry(self):
        draft = self.synthesis_fixture()
        draft["findings"][1]["transitions"] = []
        synthesis = pipeline.admitted_synthesis(self.context, draft)
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = pipeline.verification_assignments(self.context)
        put(self.base / "final-verification/assignments.json", assignments)
        assignment = assignments["assignments"][0]
        review = authored_review(self.context, synthesis["findings"][0], assignment)
        review["evidence_refs"] = ["app.py:999"]
        with self.assertRaises(ValueError):
            self.publish("final-verification", review)
        projection = pipeline.verification_projection(self.context)
        self.assertEqual(projection["findings"], [])
        self.assertEqual(projection["reviews"], [])
        self.assertEqual(projection["unconfirmed"][0]["outcome"], "locally_unresolved")
        self.assertFalse((self.base / assignment["result_ref"]).exists())
        reviews = [row for row in self.workers if row["phase"] == "final-verification"]
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["status"], "completed")

    def test_verifier_retry_preserves_admitted_peer_review_and_assignment(self):
        synthesis = pipeline.admitted_synthesis(self.context, self.synthesis_fixture())
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = pipeline.verification_assignments(self.context)
        put(self.base / "final-verification/assignments.json", assignments)
        first, second = assignments["assignments"]
        with patch.object(pipeline, "owned"):
            self.native_start("final-verification", first["finding_id"])
            accepted = self.publish("final-verification",
                authored_review(self.context, synthesis["findings"][0], first))
            original = (self.base / accepted["result_ref"]).read_bytes()
            self.native_start("final-verification", second["finding_id"])
            self.native_failure("final-verification", second["finding_id"], "Rejected independent review publication.")
            retry = self.native_start("final-verification", second["finding_id"])
        self.assertEqual(retry["attempt"], 2)
        self.assertEqual((self.base / accepted["result_ref"]).read_bytes(), original)
        self.assertEqual(pipeline.verification_assignments(self.context)["assignments"][0], first)
        self.assertEqual(self.workers[-1]["status"], "running")

    def test_rejected_terminal_publication_can_retry_without_touching_healthy_review(self):
        synthesis = pipeline.admitted_synthesis(self.context, self.synthesis_fixture())
        put(self.base / "synthesis/findings.json", synthesis)
        with patch.object(pipeline, "owned"):
            assignments = pipeline.prepare_verification(self.context)["assignments"]
        healthy = self.publish("final-verification", authored_review(
            self.context, synthesis["findings"][1], assignments[1], rejected=True))
        healthy_bytes = (self.base / healthy["result_ref"]).read_bytes()
        invalid = authored_review(self.context, synthesis["findings"][0], assignments[0])
        invalid["evidence_refs"] = ["app.py:999"]
        with self.assertRaises(ValueError):
            self.publish("final-verification", invalid)
        rejected = self.workers[-1]
        self.assertEqual(rejected["status"], "completed")
        self.assertTrue(rejected["yield_valid"])
        rejected["input_sha256"] = core.digest({"run_id": self.context["run_id"]})
        stopped = self.native_start("final-verification", assignments[0]["finding_id"])
        self.native_failure("final-verification", assignments[0]["finding_id"], "Stopped unusable review.")
        history = copy.deepcopy([rejected, stopped])
        retry = authored_review(self.context, synthesis["findings"][0], assignments[0])
        retry["attempt"] = 3
        accepted = self.publish("final-verification", retry)
        final = pipeline.verification_projection(self.context)
        self.assertEqual([finding["id"] for finding in final["findings"]], ["F-001"])
        self.assertEqual((self.base / healthy["result_ref"]).read_bytes(), healthy_bytes)
        self.assertEqual([rejected, stopped], history)
        self.assertEqual(pipeline.read_local(self.context, accepted["result_ref"])["attempt"], 3)
        for field, value in (("input_sha256", "0" * 64), ("selector", "fixture/wrong:high")):
            with self.subTest(latest_binding=field), patch.dict(self.workers[-1], {field: value}):
                invalid_latest = pipeline.verification_projection(self.context)
                self.assertEqual(invalid_latest["findings"], [])
                self.assertEqual((self.base / healthy["result_ref"]).read_bytes(), healthy_bytes)

    def test_investigator_attempt_three_survives_unusable_native_history(self):
        first = self.native_start("investigation", self.result["task_id"])
        first["input_sha256"] = core.digest({"run_id": self.context["run_id"]})
        self.native_failure("investigation", self.result["task_id"], "Wrong global input.")
        second = self.native_start("investigation", self.result["task_id"])
        self.native_failure("investigation", self.result["task_id"], "Stopped unusable draft.")
        history = copy.deepcopy(self.workers)
        self.result["attempt"] = 3
        receipt = self.publish("investigation", self.result)
        projection = pipeline.investigation_projection(self.context)
        self.assertEqual(self.workers[:2], history)
        self.assertEqual(projection["results"][0]["artifact_ref"], receipt["result_ref"])
        self.assertEqual(pipeline.read_local(self.context, receipt["result_ref"])["attempt"], 3)

    def test_report_discloses_unavailable_cohorts_without_changing_current_outcome(self):
        expected = self.report_fixture(current=True)
        import advantage_baseline
        audit = Path(self.context["baseline"]["root"])
        put(audit / "run-manifest.json", {"run_id": "audit-fixture", "execution_kind": "audit",
            "status": "complete", "repository": "fixture", "repositories": [{"path": "."}]})
        (audit / "final-verification/findings.json").write_text("{")
        catalog_context = {**self.context, "source_run_id": "audit-fixture"}
        catalog = advantage_baseline.build_catalog(catalog_context, audit)
        put(self.base / "baseline/catalog.json", catalog)
        report = pipeline.report_projection(self.context)
        pipeline.schema(report, "report", self.context)
        self.assertEqual(report["findings"], [expected])
        self.assertEqual(report["counts"]["assessed_confirmed"], 1)
        self.assertFalse(report["baseline_availability"]["counts_complete"])

    def test_optional_candidate_support_requires_independent_review_challenge(self):
        row = candidate("C-CHAIN", "new_chain")
        row["evidence_refs"].append("app.py:999")
        row["optional_support"] = [{"reference": "app.py:999", "obligation": "Queue insertion under the ordinary caller.",
            "independent_support": ["app.py:11-15"], "rationale": "Inspected dispatcher and queue producer completely establish insertion without the supplementary range."}]
        self.result["candidates"] = [row]
        admitted = pipeline.admitted_result(self.context, self.packet, self.result)
        relative = self.admit_fixture_result(admitted)
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative)
        assignment = {"finding_id": finding["id"], "candidate_sha256": dossier_hash(finding),
            "actor": "vulnops-advantage-verify-one", "selector": "fixture/red:high", "fresh_context": True,
            "result_ref": "final-verification/results/F-001.json"}
        review = authored_review(self.context, finding, assignment)
        with self.assertRaisesRegex(pipeline.EvidenceIssue, "optional-support"):
            pipeline.validate_review(self.context, finding, link, assignment, review)
        review["optional_support_reviews"] = [{"reference": "app.py:999",
            "obligation": row["optional_support"][0]["obligation"], "sufficient": False,
            "evidence_refs": ["app.py:11-15"], "reason": "The reviewer has not established sufficiency."}]
        with self.assertRaisesRegex(pipeline.EvidenceIssue, "essential obligation"):
            pipeline.validate_review(self.context, finding, link, assignment, review)
        review["optional_support_reviews"][0].update(sufficient=True,
            reason="Fresh review traces the same ordinary caller and selected identifier through dispatch to the unguarded queue append.")
        _, accepted = pipeline.validate_review(self.context, finding, link, assignment, review)
        self.assertTrue(accepted)


    def test_failed_deep_pass_does_not_cancel_running_independent_pass(self):
        self.context["mode"] = "deep"
        self.plan = authored_plan(self.context)
        put(self.base / "planning/plan.json", self.plan)
        for task in self.plan["assignments"]:
            put(self.base / f"investigation/packets/{task['task_id']}.json", pipeline.packet(self.context, self.plan, task))
        first, second = self.plan["assignments"]
        with patch.object(pipeline, "owned"):
            self.native_start("investigation", second["task_id"])
            for _ in (1, 2):
                self.native_start("investigation", first["task_id"])
                rejected = self.base / f"investigation/drafts/{first['task_id']}-{len(self.workers)}.json"
                rejected.parent.mkdir(parents=True, exist_ok=True)
                rejected.write_text("{malformed rejected draft")
                self.native_failure("investigation", first["task_id"], "No admissible analytical result.")
            second_packet = pipeline.read_local(self.context, f"investigation/packets/{second['task_id']}.json")
            result = authored_result(self.context, second_packet)
            result["candidates"] = [candidate("C-CHAIN", "new_chain")]
            receipt = self.publish("investigation", result)
        projection = pipeline.investigation_projection(self.context)
        pipeline.schema(projection, "investigation", self.context)
        self.assertEqual([row["task_id"] for row in projection["results"]], [second["task_id"]])
        self.assertEqual({row["task_id"]: row["resolution"]["outcome"] for row in projection["question_outcomes"]},
                         {first["task_id"]: "execution_failed", second["task_id"]: "established"})
        self.assertEqual(pipeline.read_local(self.context, receipt["result_ref"])["candidates"], result["candidates"])
        healthy_bytes = (self.base / receipt["result_ref"]).read_bytes()
        self.assertFalse((self.base / pipeline.result_path(self.packet)).exists())
        with patch.object(pipeline, "owned"), patch.object(core, "finalize_phase") as finalize:
            pipeline.finalize_investigation(self.context)
        self.assertEqual(finalize.call_args.kwargs["status"], "degraded")
        finding, link = authored_chain(self.context, self.plan["objectives"][0], receipt["result_ref"])
        draft = core.envelope(self.context, status="completed", reason="Independent healthy pass remains reviewable.",
            provenance=author(self.context, "vulnops-advantage-synthesis", "synthesis/findings.json"),
            findings=[finding], links=[link], baseline_reconciliation=[],
            candidate_dispositions=[{"result_ref": receipt["result_ref"], "candidate_id": "C-CHAIN",
                "disposition": "promoted", "finding_ids": [finding["id"]], "reason": "Independently source-backed queue insertion."}])
        synthesis = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual(len(synthesis["findings"]), 1)
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = pipeline.verification_assignments(self.context)
        put(self.base / "final-verification/assignments.json", assignments)
        assignment = assignments["assignments"][0]
        with patch.object(pipeline, "owned"):
            self.native_start("final-verification", finding["id"])
            review = self.publish("final-verification",
                authored_review(self.context, finding, assignment))
        self.assertEqual(review["status"], "completed")
        final = pipeline.verification_projection(self.context)
        self.assertEqual([row["id"] for row in final["findings"]], [finding["id"]])
        self.assertEqual((self.base / receipt["result_ref"]).read_bytes(), healthy_bytes)

    def test_authored_deferral_does_not_become_positive_from_valid_reference_count(self):
        self.result["candidates"] = [candidate("C-CHAIN", "new_chain")]
        closure = pipeline.excluded_item(pipeline.result_path(self.packet), "candidates[0]", [],
            missing_fact="The inspected entrypoint does not establish the queued operation's sensitive effect.")
        closure["deferral"] = {"kind": "priority",
            "reason": "A separate reachable consumer has greater impact and is selected within the remaining task allocation."}
        self.result["non_promoted"] = [closure]
        admitted = pipeline.admitted_result(self.context, self.packet, self.result)
        self.assertEqual(admitted["candidates"], [])
        self.assertEqual(admitted["non_promoted"], [closure])
        self.result["non_promoted"][0]["deferral"] = None
        with self.assertRaisesRegex(ValueError, "targeted source review|deferral"):
            pipeline.admitted_result(self.context, self.packet, self.result)

    def accepted_gap_fixture(self):
        """Mock only the upstream admission boundary; exercise real linked proof gates."""
        import gap_exploration_contract
        relative = "gap-exploration/results/GAP-001.json"
        actor = "vulnops-advantage-gap-investigator"
        self.context["model_routing"]["agents"][actor] = "fixture/gap:high"
        self.context["gap_exploration_budget"] = {"enabled": True, "max_attempts": 2, "max_concurrency": 1,
                                                "synthesis_timeout_seconds": 3600, "verification_timeout_seconds": 3600}
        row = candidate("C-CHAIN", "new_chain")
        row.update(artifact_ref=relative + ":C-CHAIN", source_view="base",
            provenance=author(self.context, actor, relative),
            contributors=[author(self.context, actor, relative)],
            objective_ids=[self.plan["objectives"][0]["id"]])
        result = core.envelope(self.context, task_id="GAP-001", source_view="base",
            provenance=row["provenance"], candidates=[row])
        put(self.base / relative, result)
        aggregate = {"results": [{"ref": relative, "source_view": "base"}],
            "candidates": [row], "objectives": [], "non_promoted": []}
        self.enterContext(patch.object(gap_exploration_contract, "load_accepted", return_value=aggregate))
        self.enterContext(patch.object(gap_exploration_contract, "accepted_support_refs",
                                      return_value={relative, "gap-exploration/results.json"}))
        return aggregate, relative

    @unittest.skipUnless(shutil.which("node"), "Node is required for native guard fixtures")
    def test_post_terminal_original_projection_survives_supplementary_fallback(self):
        import gap_dossier
        draft = self.synthesis_fixture()
        self.accepted_gap_fixture()
        draft_path = self.base / "synthesis/draft.json"
        put(draft_path, draft)
        self.context["model_routing"]["controllers"] = {
            "advantage": self.context["model_routing"]["agents"]["vulnops-advantage-synthesis"]}
        self.context["input_path"] = str((self.base.parent / "native-original-context.json").resolve())
        # Prior fixture admission collected process-local source caches, not input fields.
        self.context.pop("_source_receipts", None)
        self.context.pop("_source_examples", None)
        put(Path(self.context["input_path"]), self.context)

        projection = project_original_with_native_author(self.context, draft_path)
        self.assertEqual(projection["receipt"], {
            "status": "original_complete", "artifact_ref": "synthesis/original-findings.json"})
        self.workers.extend(projection["native_call"]["workers"])
        original = gap_dossier.load_original_draft(
            self.base, self.context, "synthesis/original-findings.json")
        self.assertIsNotNone(original, "projected original lacks native publication binding")
        self.assertEqual([row["id"] for row in original["findings"]], ["F-001", "F-002"])
        checksum = projection["native_call"]["workers"][0]["artifact_sha256"]["synthesis/original-findings.json"]
        with patch.object(pipeline, "owned"), patch.object(core, "finalize_phase"):
            pipeline.finalize_synthesis(self.context)
        synthesis = pipeline.read_local(self.context, "synthesis/findings.json")
        self.assertEqual(synthesis["findings"], original["findings"])
        self.assertEqual(synthesis["candidate_dispositions"][:2], original["candidate_dispositions"])
        self.assertEqual(synthesis["original_evidence"], {
            "ref": "synthesis/original-findings.json", "sha256": checksum})
        supplementary = synthesis["candidate_dispositions"][2:]
        self.assertEqual(len(supplementary), 1)
        self.assertEqual(supplementary[0]["disposition"], "unresolved")
        self.assertEqual(supplementary[0]["finding_ids"], [])
        with patch.object(pipeline, "owned"):
            assignments = pipeline.prepare_verification(self.context)
        self.assertEqual([row["finding_id"] for row in assignments["assignments"]], ["F-001", "F-002"])
        put(self.base / "synthesis/original-findings.json", {**original, "reason": "Changed after observation."})
        with self.assertRaisesRegex(ValueError, "exact native terminal evidence"):
            gap_dossier.load_original_draft(self.base, self.context, "synthesis/original-findings.json")

    def test_empty_original_does_not_bypass_accepted_gap_candidate(self):
        self.admit_fixture_result()
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        admitted = pipeline.admitted_synthesis(self.context, pipeline.empty_synthesis(self.context))
        self.assertEqual(admitted["status"], "empty")
        self.assertEqual(admitted["findings"], [])
        put(self.base / "gap-exploration/results.json", {"candidates": [candidate("LOOSE", "new_chain")]})
        with self.assertRaisesRegex(ValueError, "missing required field"):
            pipeline.empty_synthesis(self.context)
        self.accepted_gap_fixture()
        self.assertEqual(pipeline.empty_synthesis({**self.context, "_original_synthesis": True})["status"], "empty")
        closed = pipeline.empty_synthesis(self.context)
        self.assertEqual(closed["findings"], [])
        self.assertEqual(closed["candidate_dispositions"][0]["disposition"], "unresolved")
        with patch.object(pipeline, "owned"), patch.object(core, "finalize_phase"):
            pipeline.finalize_synthesis(self.context)
        published = pipeline.read_local(self.context, "synthesis/findings.json")
        self.assertEqual(published["findings"], [])
        self.assertEqual(published["candidate_dispositions"], closed["candidate_dispositions"])
        self.assertNotIn("original_evidence", published)
        self.assertFalse((self.base / "synthesis/original-findings.json").exists())
        (self.base / "investigation/results.json").unlink()
        with self.assertRaisesRegex((ValueError, OSError), "investigation/results.json"):
            pipeline.synthesis_inputs(self.context)

    def test_gap_source_view_and_unproven_transition_remain_strict(self):
        original = self.synthesis_fixture()
        _, relative = self.accepted_gap_fixture()
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-003")
        finding["impact"] = "Insert an additional caller-selected queued operation."
        original["findings"].append(finding)
        original["links"].append(link)
        original["candidate_dispositions"].append({"result_ref": relative, "candidate_id": "C-CHAIN",
            "disposition": "promoted", "finding_ids": ["F-003"], "reason": "Source-backed supplemental route."})
        self.assertEqual(len(pipeline.admitted_synthesis(self.context, original)["findings"]), 3)
        link["source_view"] = "derived"
        admitted = pipeline.admitted_synthesis(self.context, original)
        self.assertEqual([row["id"] for row in admitted["findings"]], ["F-001", "F-002"])
        link["source_view"] = "base"
        finding["transitions"][0]["obligations"]["actor_control"]["outcome"] = "contradicted"
        admitted = pipeline.admitted_synthesis(self.context, original)
        self.assertEqual([row["id"] for row in admitted["findings"]], ["F-001", "F-002"])

    def test_gap_cohort_membership_is_evidence_derived_and_mixed_protected(self):
        original = self.synthesis_fixture()
        aggregate, relative = self.accepted_gap_fixture()
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-003")
        self.assertTrue(pipeline.supplementary_finding(self.context, finding, link))
        finding["source_refs"].extend(original["findings"][0]["source_refs"])
        self.assertFalse(pipeline.supplementary_finding(self.context, finding, link))
        finding["source_refs"] = finding["source_refs"][:1]
        link["baseline_ids"] = ["IMPORTED"]
        self.assertFalse(pipeline.supplementary_finding(self.context, finding, link))
        link["baseline_ids"] = []
        finding["contributors"][0]["selector"] = "fixture/forged:high"
        self.assertFalse(pipeline.supplementary_finding(self.context, finding, link))
        self.assertEqual(aggregate["candidates"][0]["provenance"]["selector"], "fixture/gap:high")

    def test_supplementary_review_waits_only_for_live_original_work(self):
        synthesis = pipeline.admitted_synthesis(self.context, self.synthesis_fixture())
        _, relative = self.accepted_gap_fixture()
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-003")
        synthesis["findings"].append(finding)
        synthesis["links"].append(link)
        put(self.base / "synthesis/findings.json", synthesis)
        with patch.object(pipeline, "owned"):
            pipeline.prepare_verification(self.context)
        import gap_dossier
        self.native_start("final-verification", "F-001")
        with self.assertRaises(ValueError):
            gap_dossier.require_cohort(self.context, "final-verification", "supplementary")
        self.native_failure("final-verification", "F-001", "Stopped without usable review.")
        gap_dossier.require_cohort(self.context, "final-verification", "supplementary")

    def test_failed_supplementary_cohort_closes_unstarted_review_without_fabrication(self):
        import gap_dossier
        self.admit_fixture_result()
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        _, relative = self.accepted_gap_fixture()
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-003")
        synthesis = pipeline.empty_synthesis({**self.context, "_original_synthesis": True})
        synthesis.update(status="completed", findings=[finding], links=[link],
            candidate_dispositions=[{"result_ref": relative, "candidate_id": "C-CHAIN", "disposition": "promoted",
                "finding_ids": ["F-003"], "reason": "Requires full independent review."}])
        put(self.base / "synthesis/findings.json", synthesis)
        put(self.base / "final-verification/assignments.json", pipeline.verification_assignments(self.context))
        self.context["gap_exploration_budget"].update(enabled=True, verification_timeout_seconds=3600)
        self.context["paths"] = {"advantage_base": str(self.base),
                                 "gap_exploration": str(self.base / "gap-exploration")}
        coordinator = {"id": "AdvantageReviewSupplementary", "runtime_id": "native-review-coordinator",
                       "phase": "final-verification", "actor": "vulnops-advantage-final-verification",
                       "attempt": 1, "status": "failed", "yield_valid": False,
                       "error": "Native supplementary coordinator failed before launching reviewers.",
                       "artifacts": [], "artifact_sha256": {}}
        self.workers.append(coordinator)
        for seconds in (3600, 0):
            with self.subTest(allowance_seconds=seconds):
                self.context["gap_exploration_budget"]["verification_timeout_seconds"] = seconds
                value = pipeline.verification_projection(self.context)
                self.assertEqual(value["findings"], [])
                self.assertEqual(value["reviews"], [])
                self.assertEqual(value["unconfirmed"][0]["outcome"], "locally_unresolved")
                self.assertFalse((self.base / "final-verification/results/F-003.json").exists())
                pipeline.schema(value, "verification", self.context)
        finding["source_refs"].append({"kind": "advantage", "source_id": "ORIGINAL",
            "artifact_ref": pipeline.result_path(self.packet)})
        put(self.base / "synthesis/findings.json", synthesis)
        (self.base / "final-verification/assignments.json").unlink()
        put(self.base / "final-verification/assignments.json", pipeline.verification_assignments(self.context))
        closed = pipeline.verification_projection(self.context)
        self.assertEqual(closed["findings"], [])
        self.assertEqual(closed["unconfirmed"][0]["outcome"], "locally_unresolved")

    def test_admitted_gap_candidate_receives_complete_independent_review(self):
        import gap_dossier
        self.admit_fixture_result()
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        _, relative = self.accepted_gap_fixture()
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-003")
        synthesis = pipeline.empty_synthesis({**self.context, "_original_synthesis": True})
        synthesis.update(status="completed", findings=[finding], links=[link],
            candidate_dispositions=[{"result_ref": relative, "candidate_id": "C-CHAIN", "disposition": "promoted",
                "finding_ids": ["F-003"], "reason": "Requires complete independent review."}])
        synthesis = pipeline.admitted_synthesis(self.context, synthesis)
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = pipeline.verification_assignments(self.context)
        put(self.base / "final-verification/assignments.json", assignments)
        with patch.object(pipeline, "owned"), patch.object(gap_dossier, "require_cohort"):
            self.native_start("final-verification", "F-003")
            result = authored_review(self.context, finding, assignments["assignments"][0])
            receipt = self.publish("final-verification", result)
        self.assertEqual(receipt["status"], "completed")
        projected = pipeline.verification_projection(self.context)
        self.assertEqual([row["id"] for row in projected["findings"]], ["F-003"])
        self.assertEqual(projected["findings"][0]["contributors"], finding["contributors"])
        self.assertEqual(projected["findings"][0]["assessment_context"], {"attempt_id": self.context["attempt_id"]})
        self.assertEqual(projected["unconfirmed"], [])

    def test_accepted_original_review_survives_supplementary_cohort_failure(self):
        import gap_dossier
        synthesis = pipeline.admitted_synthesis(self.context, self.synthesis_fixture())
        _, relative = self.accepted_gap_fixture()
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-003")
        finding["impact"] = "A separate additional queued operation."
        synthesis["findings"].append(finding)
        synthesis["links"].append(link)
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = pipeline.verification_assignments(self.context)
        put(self.base / "final-verification/assignments.json", assignments)
        with patch.object(pipeline, "owned"):
            for candidate_finding, assignment in zip(synthesis["findings"][:2], assignments["assignments"][:2]):
                self.native_start("final-verification", candidate_finding["id"])
                review = authored_review(self.context, candidate_finding, assignment,
                                         rejected=candidate_finding["status"] != "verified")
                self.publish("final-verification", review)
        original_ref = self.base / "final-verification/results/F-001.json"
        original_bytes = original_ref.read_bytes()
        with patch.object(gap_dossier, "cohort_failure", return_value={"reason": "Supplementary reviewer could not start."}):
            final = pipeline.verification_projection(self.context)
        self.assertEqual([row["id"] for row in final["findings"]], ["F-001"])
        self.assertEqual(len(final["reviews"]), 2)
        self.assertEqual(original_ref.read_bytes(), original_bytes)
        self.assertEqual(next(row for row in final["unconfirmed"] if row["finding_id"] == "F-003")["outcome"],
                         "locally_unresolved")

    def test_gap_objectives_extend_but_cannot_replace_original_registry(self):
        self.admit_fixture_result()
        put(self.base / "investigation/results.json", pipeline.investigation_projection(self.context))
        aggregate, _ = self.accepted_gap_fixture()
        objective = copy.deepcopy(self.plan["objectives"][0])
        objective.update(owner="gap-exploration/plan.json", local_key="alternate-queue",
                         id=stable_id("OBJ-", "gap-exploration/plan.json", "alternate-queue"))
        aggregate["objectives"] = [objective]
        self.assertEqual(set(pipeline.synthesis_objectives(self.context)),
                         {objective["id"], self.plan["objectives"][0]["id"]})
        aggregate["objectives"][0] = {**self.plan["objectives"][0], "success_condition": "Invented stronger outcome."}
        with self.assertRaisesRegex(ValueError, "changed original authority"):
            pipeline.synthesis_objectives(self.context)

    def test_excluded_only_original_does_not_block_supported_supplement(self):
        import gap_dossier
        draft = self.synthesis_fixture()
        for finding in draft["findings"]:
            finding["transitions"] = []
        original = pipeline.admitted_synthesis(self.context, draft)
        self.assertEqual(original["findings"], [])
        _, relative = self.accepted_gap_fixture()
        finding, link = authored_chain(self.context, self.plan["objectives"][0], relative, "F-003")
        supplement = copy.deepcopy(original)
        supplement.pop("non_promoted")
        supplement.update(status="completed", findings=[finding], links=[link])
        supplement["candidate_dispositions"].append({
            "result_ref": relative, "candidate_id": "C-CHAIN", "disposition": "promoted",
            "finding_ids": ["F-003"], "reason": "Independent supplementary queue boundary."})
        combined = pipeline.admitted_synthesis(self.context, supplement, original=original)
        gap_dossier.preserve_original(original, combined)
        self.assertEqual(combined["non_promoted"], original["non_promoted"])
        self.assertEqual([row["id"] for row in combined["findings"]], ["F-003"])

    

    

    def test_negative_missing_support_retains_full_judgment_and_healthy_peer(self):
        draft = self.synthesis_fixture()
        missing = Path(self.context["source_root"]) / "withdrawn.py"
        missing.write_bytes((Path(self.context["source_root"]) / "app.py").read_bytes())
        challenged = draft["findings"][1]
        challenged["verification"]["source_validation_refs"] = ["withdrawn.py:11-15"]
        challenged["primitive_steps"][0]["evidence_refs"] = ["withdrawn.py:13-15"]
        synthesis = pipeline.admitted_synthesis(self.context, draft)
        put(self.base / "synthesis/findings.json", synthesis)
        assignments = pipeline.verification_assignments(self.context)
        put(self.base / "final-verification/assignments.json", assignments)
        missing.unlink()
        negative = authored_review(self.context, challenged, assignments["assignments"][1], rejected=True)
        negative.update(status="evidence_limited",
                        closure_reason="The queue producer remains inspectable, but the withdrawn route proof cannot establish the claimed persistent effect.")
        negative["evidence_refs"].append("final-verification/support/missing.json:route-proof")
        with patch.object(pipeline, "owned"):
            for finding, assignment in zip(synthesis["findings"], assignments["assignments"]):
                self.native_start("final-verification", finding["id"])
                review = negative if finding["id"] == challenged["id"] else authored_review(self.context, finding, assignment)
                receipt = self.publish("final-verification", review)
                self.assertEqual(receipt["status"], "completed")
        retained = pipeline.read_local(self.context, assignments["assignments"][1]["result_ref"])
        for key, value in negative.items():
            self.assertEqual(retained[key], value)
        projection = pipeline.verification_projection(self.context)
        self.assertEqual([finding["id"] for finding in projection["findings"]], ["F-001"])
        self.assertEqual([review["status"] for review in projection["reviews"]], ["verified", "evidence_limited"])
        self.assertEqual(projection["unconfirmed"][0]["reason"], negative["closure_reason"])
        for mutation in ("assignment", "escape", "secret", "objective"):
            forged = copy.deepcopy(negative)
            if mutation == "assignment":
                forged["assignment_sha256"] = "0" * 64
            elif mutation == "escape":
                forged["dossier_review"]["impact_limits"]["evidence_refs"] = ["../outside.py:1"]
            elif mutation == "secret":
                forged["closure_reason"] = "-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----"
            else:
                forged["objective_results"][0]["satisfied"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                pipeline.validate_review(self.context, challenged, synthesis["links"][1],
                                         assignments["assignments"][1], forged)
        positive = authored_review(self.context, challenged, assignments["assignments"][1])
        with self.assertRaises(ValueError):
            pipeline.validate_review(self.context, challenged, synthesis["links"][1],
                                     assignments["assignments"][1], positive)
        rejected = copy.deepcopy(negative)
        rejected.update(status="rejected", evidence_refs=["app.py:11-15"])
        rejected["primitive_results"][0]["evidence_refs"] = ["app.py:13-15"]
        self.assertFalse(pipeline.validate_review(self.context, challenged, synthesis["links"][1],
                                                 assignments["assignments"][1], rejected)[1])

    def test_never_launched_failures_and_fake_retries_cannot_close_real_publications(self):
        plan = copy.deepcopy(self.plan)
        template_question, template_task = plan["questions"][0], plan["assignments"][0]
        plan["questions"], plan["assignments"] = [], []
        for index in range(58):
            question = copy.deepcopy(template_question)
            question.update(local_key=f"obligation-{index}",
                            id=stable_id("Q-", "planning/plan.json", f"obligation-{index}"),
                            route=f"independent route {index}", proof_obligation=f"Establish operation {index} ownership.")
            task = copy.deepcopy(template_task)
            task.update(task_id=f"TASK-{index + 1:03}", question_ids=[question["id"]])
            plan["questions"].append(question)
            plan["assignments"].append(task)
        self.context["budget"].update(max_tasks=58, max_questions=58)
        put(self.base / "planning/plan.json", plan)
        for task in plan["assignments"]:
            packet = pipeline.packet(self.context, plan, task)
            put(self.base / f"investigation/packets/{task['task_id']}.json", packet)
        for task in plan["assignments"][:38]:
            packet = pipeline.read_local(self.context, f"investigation/packets/{task['task_id']}.json")
            self.publish("investigation", authored_result(self.context, packet))
        healthy = {path: path.read_bytes() for path in (self.base / "investigation/passes").glob("*/results/*.json")}
        fake = [{"id": task["task_id"], "attempt": 1, "status": "failed"} for task in plan["assignments"][38:]]
        fake.extend({"id": task["task_id"], "attempt": 2, "status": "failed"} for task in plan["assignments"][38:42])
        put(self.base / "investigation/dispatch.json", {"workers": fake})
        projected = pipeline.investigation_projection(self.context)
        self.assertEqual(len(projected["results"]), 38)
        self.assertEqual(sum(row["resolution"]["outcome"] == "locally_unresolved"
                             for row in projected["question_outcomes"]), 20)
        self.assertEqual(len(self.workers), 38)
        for task in plan["assignments"][38:]:
            self.native_start("investigation", task["task_id"])
            self.native_failure("investigation", task["task_id"], "Actual synthetic native worker failure.")
        projected = pipeline.investigation_projection(self.context)
        self.assertEqual(len(projected["results"]), 38)
        self.assertEqual(sum(row["resolution"]["outcome"] == "execution_failed"
                             for row in projected["question_outcomes"]), 20)
        self.assertEqual({path: path.read_bytes() for path in healthy}, healthy)
        fresh = {**self.context, "run_id": "new-independent-invocation",
                 "scan_base": str(self.base.parent / "fresh"), "attempt_id": "fresh-assessment"}
        fresh_plan = authored_plan(fresh)
        put(Path(fresh["scan_base"]) / "planning/plan.json", fresh_plan)
        fresh_packet = pipeline.packet(fresh, fresh_plan, fresh_plan["assignments"][0])
        put(Path(fresh["scan_base"]) / "investigation/packets/TASK-001.json", fresh_packet)
        self.workers.clear()
        self.call["run_id"] = fresh["run_id"]
        self.context, self.base, self.plan, self.packet = fresh, Path(fresh["scan_base"]), fresh_plan, fresh_packet
        self.publish("investigation", authored_result(fresh, fresh_packet))
        independent = pipeline.investigation_projection(fresh)
        self.assertEqual(len(independent["results"]), 1)
        self.assertEqual(self.workers[0]["attempt"], 1)
        self.assertEqual({path: path.read_bytes() for path in healthy}, healthy)

    def test_native_terminal_bytes_and_identity_are_required_for_admission(self):
        row = self.native_start("investigation", "TASK-001")
        with patch.object(pipeline, "owned"):
            with self.assertRaisesRegex(ValueError, "terminal native"):
                pipeline.admit_worker_result(self.context, "investigation", self.result)
            draft = "investigation/drafts/TASK-001.json"
            put(self.base / draft, self.result)
            row.update(status="completed", yield_valid=True, artifacts=[draft],
                       artifact_sha256={draft: core.sha256_file(self.base / draft)})
            forged = copy.deepcopy(self.result)
            forged["question_outcomes"][0]["resolution"]["reason"] = "Not the yielded result."
            with self.assertRaisesRegex(ValueError, "terminal yield"):
                pipeline.admit_worker_result(self.context, "investigation", forged)
            put(self.base / draft, forged)
            with self.assertRaisesRegex(ValueError, "changed"):
                pipeline.admit_worker_result(self.context, "investigation", forged)
        self.assertFalse((self.base / pipeline.result_path(self.packet)).exists())

    def test_report_json_is_last_and_companion_failure_never_completes(self):
        report = {"run_id": self.context["run_id"], "publication": {}}
        original_atomic = core.atomic_json
        observed = []
        def publish(path, value):
            if Path(path).name == "security-report.json":
                self.assertEqual((self.base / "report/security-report.md").read_text(), "validated report\n")
                self.assertTrue((self.base / "report/source-receipts.json").is_file())
            observed.append(Path(path).name)
            original_atomic(path, value)
        with patch.object(pipeline, "owned"), patch.object(pipeline, "validate_phase") as aggregates, \
             patch("advantage_actions.validate_phase"), patch.object(pipeline, "report_projection", return_value=report), \
             patch.object(pipeline, "schema"), patch.object(pipeline, "report_markdown", return_value="validated report\n"), \
             patch.object(core, "atomic_json", side_effect=publish):
            pipeline.render_report(self.context)
        self.assertEqual(aggregates.call_count, 4)
        self.assertEqual(observed[-1], "security-report.json")
        before = (self.base / "report/security-report.md").read_bytes()
        with patch.object(pipeline, "owned"), patch.object(pipeline, "validate_phase") as repeated:
            with self.assertRaisesRegex(ValueError, "completed report is immutable"):
                pipeline.render_report(self.context)
        repeated.assert_not_called()
        self.assertEqual((self.base / "report/security-report.md").read_bytes(), before)
        (self.base / "report/security-report.json").unlink()
        (self.base / "report/security-report.md").unlink()
        with patch.object(pipeline, "owned"), patch.object(pipeline, "validate_phase"), \
             patch("advantage_actions.validate_phase"), patch.object(pipeline, "report_projection", return_value=report), \
             patch.object(pipeline, "schema"), patch.object(pipeline, "report_markdown", return_value="validated report\n"), \
             patch.object(pipeline, "record_source_receipts", side_effect=OSError("companion write failed")):
            with self.assertRaisesRegex(OSError, "companion"):
                pipeline.render_report(self.context)
        self.assertFalse((self.base / "report/security-report.json").exists())


if __name__ == "__main__":
    unittest.main()
