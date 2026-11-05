"""Exercise real deterministic phases with fixed model outputs, never target execution."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from dossier_contract import objective_assessments
from intrusion_contract import snapshot_ref
from model_identity import finding_contributors, finding_diversity
from objective_contract import stable_id
from objective_fixtures import objective_binding, objective_registry
from test_dossiers import add_dossier, review_dossier, sample_finding
from test_greenfield_v2 import attack_path, attribute_recon, provenance, write as write_json
from test_sast_contextual_planning import attack_class, clean_result, mapping, threat_model
from test_investigation_source import fixture as source_fixture
from test_recovery import recover_campaign_fixture

SOURCE = '''CURRENT_USER = {"tenant": "tenant-a"}
records = {}
queue = []
def guarded(user, record_id):
    record = records[record_id]
    if record["tenant"] != user["tenant"]:
        raise PermissionError("wrong tenant")
    return record
def legacy(user, record_id):
    return records[record_id]
def update(user, record_id):
    queue.append((user, record_id))
def dispatch(path, record_id):
    return ROUTES[path](CURRENT_USER, record_id)
ROUTES = {"/records/guarded": guarded, "/records/legacy": legacy, "/records/update": update}
'''
DEPLOYMENT = '{"service": "records-service", "handler": "app.dispatch"}\n'
PHASES = [("recon", "Recon", "repo-context/repo-context.json"),
          ("tool-collection", "ToolCollection", "tool-collection/collection.json"),
          ("sast", "ThreatHunter", "sast/verified-findings.json"),
          ("campaign-planning", "CampaignPlanning", "campaign-planning/campaign-plan.json"),
          ("intrusion", "Intrusion", "intrusion/intrusion-results.json"),
          ("gap-exploration", "GapExploration", "gap-exploration/results.json"),
          ("synthesis", "Synthesis", "synthesis/findings.json"),
          ("final-verification", "FinalVerification", "final-verification/findings.json"),
          ("report", "Report", "report/security-report.json")]


def exercise_pipeline(base: Path, *, git_identity: bool = False, reject_findings: bool = False,
                      multi_repository: bool = False, resume_source_change: bool = False,
                      harness_root: Path = ROOT, gap_scenario=None, extra_source_files=None,
                      extra_example=None) -> dict:
    """Publish a synthetic audit with optional Git, multi-repository and rejected-review cases."""
    ROOT = harness_root
    source = base / "source"; source.mkdir(parents=True)
    repository_roots = [source / "service-a", source / "service-b"] if multi_repository else [source]
    for repository in repository_roots:
        repository.mkdir(exist_ok=True)
        (repository / "app.py").write_text(SOURCE)
        (repository / "deployment.json").write_text(DEPLOYMENT)
        for name, content in (extra_source_files or {}).items():
            (repository / name).write_text(content)

    def qualify(value):
        if not multi_repository:
            return value
        if isinstance(value, dict):
            return {key: qualify(item) for key, item in value.items()}
        if isinstance(value, list):
            return [qualify(item) for item in value]
        if isinstance(value, str) and any(value == name or value.startswith(name + ":")
                                          for name in ("app.py", "deployment.json")):
            return "service-a/" + value
        return value

    def write(path, value):
        document = qualify(value)
        if isinstance(document, dict) and any(path.is_relative_to(scan / directory) for directory in
                                             ("sast/deepdive", "sast/verify", "intrusion/results")):
            document["assessment_context"] = {"attempt_id": context["attempt_id"]}
        if path == scan / "sast/validation-results.json":
            document = [{**row, "assessment_context": {"attempt_id": context["attempt_id"]}} for row in document]
        if multi_repository and path == scan / "repo-context/repo-context.json":
            document["projects"][0]["base_path"] = "service-a"
            document["projects"].append({
                "id": "PRJ-2", "type": "library", "base_path": "service-b", "languages": ["python"],
                "frameworks": [], "dependency_files": [], "entry_points": [], "trust_boundary_ids": [],
                "ignore_patterns": [], "evidence_refs": ["service-b/app.py:1-15"]})
        write_json(path, document)
    scan = base / "run"; context_path = base / "context.json"
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "VULNOPS_AUDIT_CONTEXT": str(context_path),
           "VULNOPS_RUNTIME_ROOT": str(base / "runtime")}
    commands = []

    def command(*args):
        argv = [str(value) for value in args]
        completed = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True)
        if completed.returncode:
            raise AssertionError(" ".join(argv) + "\n" + completed.stderr + completed.stdout)
        commands.append({"command": " ".join(argv), "exit_code": completed.returncode})
        return completed.stdout

    def script(name, *args):
        return command(sys.executable, ROOT / "scripts" / name, *args)

    def load(ref):
        return json.loads((scan / ref).read_text())

    def begin(phase):
        task = next(row[1] for row in PHASES if row[0] == phase)
        script("update-run-state.py", scan, "--phase", phase, "--phase-status", "running",
               "--task", task, "--task-phase", phase, "--task-status", "running", "--increment-attempt")

    def finish(phase):
        task, artifact = next(row[1:] for row in PHASES if row[0] == phase)
        directory = "repo-context" if phase == "recon" else phase
        command("bash", ROOT / "scripts/validate-phase.sh", scan, phase)
        script("update-run-state.py", scan, "--phase", phase, "--phase-manifest", scan / directory / "phase-manifest.json",
               "--task", task, "--task-phase", phase, "--artifact", artifact)

    def manifest(phase, outputs):
        return {"phase": phase, "status": "ok", "started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z",
                "inputs": [], "outputs": outputs, "coverage": {}, "tool_versions": {"synthetic-input": "1"}, "warnings": [], "errors": []}

    inventory_args = ()
    revision = "abc"
    repo_id = "fixture-id"
    remote_url = "local"
    if git_identity or multi_repository:
        for repository in repository_roots:
            command("git", "-c", "init.templateDir=", "init", "-q", repository)
            command("git", "-C", repository, "add", "app.py", "deployment.json", *(extra_source_files or {}))
            command("git", "-C", repository, "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                    "commit", "--no-gpg-sign", "-qm", "Synthetic audit source")
        inventory_path = base / "inventory.json"
        script("target-inventory.py", source, "--application-name", "records-fixture",
               "--output", inventory_path)
        inventory = json.loads(inventory_path.read_text())
        inventory_args = ("--repositories-file", inventory_path)
        revision = inventory["revision"]
        repo_id = inventory["application_id"]
        remote_url = inventory["remote_url"]

    source_bytes = {path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file() and ".git" not in path.parts}
    network = tomllib.loads((ROOT / "config.toml").read_text())["harness"]["network"]["linux_agent_egress"]
    initialization = ("init-run.py", "--harness-root", ROOT, "--repo-path", source, "--scan-base", scan,
           "--run-id", "redteam-fixture", "--repo-name", "records-fixture", "--remote-url", remote_url,
           "--repo-id", repo_id, "--commit", revision, "--depth", "quick",
           "--reproduction-mode", "off", "--network-mode", network,
           "--codegraph-mode", "enabled" if gap_scenario is not None else "disabled",
           "--codegraph-limitation", "Synthetic source-only scenario; no graph executable is installed." if gap_scenario is not None
           else "Synthetic source-only scenario; graph navigation not exercised.", *inventory_args)
    script(*initialization)
    context = json.loads(context_path.read_text()); routing = context["model_routing"]
    script("update-run-state.py", scan, "--run-status", "incomplete")

    begin("recon")
    entry = {"id": "EP-1", "path": "app.py", "kind": "library", "evidence_refs": ["app.py:13-15"]}
    write(scan / "repo-context/repo-context.json", {"schema_version": "2.0", "repository": "records-fixture",
        "comparable": {"name": None, "basis": "synthetic source", "confidence": "not_applicable"},
        "projects": [{"id": "PRJ-1", "type": "library", "base_path": ".", "languages": ["python"], "frameworks": [],
                      "dependency_files": [], "entry_points": [entry], "trust_boundary_ids": ["TB-1"], "ignore_patterns": [], "evidence_refs": ["app.py:1-15"]}],
        "actors": [], "domain_tags": [], "sensitive_data_types": [], "build_ci": [], "generated_ignorable": [],
        "evidence_refs": ["app.py:1-15"], "warnings": [], "errors": []})
    write(scan / "repo-context/security-surfaces.json", {"schema_version": "2.0", "repository": "records-fixture",
        "entry_points": [{**entry, "project_id": "PRJ-1", "trust_boundary_ids": ["TB-1"]}],
        "trust_boundaries": [{"id": "TB-1", "project_id": "PRJ-1", "source_trust": "tenant caller", "target_trust": "record store",
                              "description": "Authenticated tenant must not read another tenant's records", "evidence_refs": ["app.py:4-8"]}],
        "security_relevant_files": [{"path": "app.py", "categories": ["entry_point"], "evidence_refs": ["app.py:13-15"]}],
        "attack_paths": [attack_path("app.py")], "ignore_patterns": [], "generated_ignorable": [], "sensitive_data_types": [], "domain_tags": [], "warnings": [], "errors": []})
    (scan / "repo-context/repo.md").write_text("# Synthetic records service\n")
    for name, worker in (("overview", "overview"), ("trust-boundaries", "trust-boundaries"), ("input-surfaces", "input-surfaces")):
        write(scan / f"repo-context/research/{name}.json", {"schema_version": "2.0", "worker": worker, "status": "ok",
              "started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z", "observations": [], "warnings": [], "errors": []})
    attribute_recon(scan, routing)
    write(scan / "repo-context/phase-manifest.json", manifest("recon", ["repo-context/repo.md", "repo-context/repo-context.json", "repo-context/security-surfaces.json",
        *[f"repo-context/research/{name}.json" for name in ("overview", "trust-boundaries", "input-surfaces")], "repo-context/phase-manifest.json"]))
    finish("recon")

    begin("tool-collection")
    for tool, artifact, receipt, document in (
        ("wraith", "sca-advisories.json", "wraith-receipt.json", {"schema_version": "2.0", "tool": "wraith", "packages_scanned": 0, "advisory_count": 0, "advisories": []}),
        ("poltergeist", "secrets-redacted.json", "poltergeist-receipt.json", {"schema_version": "2.0", "tool": "poltergeist", "match_count": 0, "candidate_count": 0, "candidates": []})):
        write(scan / "tool-collection" / artifact, document)
        record = {"schema_version": "2.0", "tool": tool, "operation": "synthetic-input", "status": "ok", "version": "fixture",
                  "started_at": "now", "completed_at": "now", "parse_status": "ok", "result_count": 0,
                  "normalized_sha256": hashlib.sha256((scan / "tool-collection" / artifact).read_bytes()).hexdigest(), "warnings": []}
        if tool == "wraith":record.update(packages_scanned=0, databases=[])
        write(scan / "tool-collection" / receipt, record)
    write(scan / "tool-collection/dependency-limitations.json", {"schema_version": "2.0", "limitations": []})
    write(scan / "tool-collection/collection.json", {"schema_version": "2.0", "run_id": context["run_id"],
        "sca_ref": "tool-collection/sca-advisories.json", "secrets_ref": "tool-collection/secrets-redacted.json",
        "receipts": ["tool-collection/wraith-receipt.json", "tool-collection/poltergeist-receipt.json"], "limitations": [], "warnings": []})
    (scan / "tool-collection/summary.md").write_text("# Fixed empty scanner inputs; scanners were not executed\n")
    outputs = [str(path.relative_to(scan)) for path in (scan / "tool-collection").iterdir()]
    write(scan / "tool-collection/phase-manifest.json", manifest("tool-collection", [*outputs, "tool-collection/phase-manifest.json"]))
    finish("tool-collection")

    begin("sast")
    registries = []
    mappings = []
    for key, effect in (("read", "read another tenant's record"), ("write", "modify another tenant's record")):
        registry = objective_registry(["app.py:13-15"], local_key=key, starting_actor="ordinary tenant caller",
            controlled_material="route and record identifier", resource_scope="another tenant's record", desired_effect=effect,
            success_condition=f"An ordinary tenant caller can {effect} through dispatch.",
            security_question=f"Can a dispatched route {effect}?", route="dispatch to record operation",
            proof_obligation="Trace caller-controlled selection through the tenant authority check to the record operation.",
            novelty_reason=f"Distinct {key} effect over the shared dispatch evidence.")
        registries.append(registry)
        row = mapping("HM-" + key.upper(), "access_control")
        row.update(objective_binding(registry), security_question=registry["investigation_questions"][0]["security_question"])
        mappings.append(row)
    registry = {key: [row for item in registries for row in item[key]] for key in ("attack_objectives", "investigation_questions")}
    threat = threat_model(["app.py"], mappings, [attack_class("access_control", "skill://vulnops-access-control")])
    threat.update(registry); write(scan / "sast/threat-model.json", threat)
    script("build-hunt-plan.py", source, scan, "--context", context_path)
    hunt = load("sast/hunt-plan.json")
    cells = {row["id"]: row for row in hunt["cells"]}
    for task in hunt["tasks"]:
        result = None
        for cell_id in task["cell_ids"]:
            cell = cells[cell_id]
            part = clean_result(task["id"], cell_id, [], {key: cell[key] for key in ("objective_id", "question_id")})
            row = part["cell_results"][0]
            row.update(status="shallow", reason="Shared dispatcher identified; effect-side authorization still requires focused inspection.",
                       sinks_reviewed=["ROUTES dispatch"], mitigations_checked=["Trusted principal is selected internally."], evidence_refs=["app.py:13-15"])
            row["resolution"] = {"outcome": "externally_blocked", "reason": "Deployment-specific exposure cannot be established from the source fixture.",
                "next_action": "Obtain deployment route policy.", "evidence_refs": ["app.py:13-15"], "missing_fact": "Deployment-specific route exposure"}
            row["checkpoint"].update(established_facts=["Caller controls route and record ID; principal comes from CURRENT_USER."],
                contradicted_paths=[], remaining_question=cell["security_question"], next_step="Inspect selected effect-side function.", expected_results=["Guarded or unguarded record access"])
            if cell["objective_id"] == registries[1]["attack_objectives"][0]["id"]:
                candidate = source_fixture()[2]["candidates"][0]
                candidate.update({key: cell[key] for key in ("objective_id", "question_id")})
                candidate["methodology_refs"] = cell["methodology_refs"]
                candidate.update(task_id=task["id"], cell_ids=[cell_id], title="Unverified queued record write",
                    intended_behavior="Only the owner can modify a record", root_cause="Queued consumer ownership is not established",
                    root_cause_location={"file": "app.py", "line": 12, "scope": "update", "mechanism": "unverified consumer authority"},
                    trace=[{"kind": "entrypoint", "file": "app.py", "line": 13, "scope": "dispatch", "description": "Caller selects route and record."},
                           {"kind": "propagation", "file": "app.py", "line": 14, "scope": "dispatch", "description": "Trusted principal accompanies caller input."},
                           {"kind": "sink", "file": "app.py", "line": 12, "scope": "update", "description": "Queue the requested write; eventual authorization remains unproven."}],
                    impact="Potential cross-tenant write; not established", evidence_refs=["app.py:11-16"],
                    contributors=[provenance("vulnops-deepdive-chunk", f"sast/deepdive/{task['id']}.json", routing)])
                part["candidates"] = [candidate]
                row.update(status="finding", candidate_ids=[candidate["id"]])
                row["resolution"].update(outcome="established", missing_fact="")
            if result is None:result = part
            else:
                result["cell_results"].append(row)
                result["candidates"].extend(part["candidates"])
        result["status"] = "shallow" if any(row["status"] == "shallow" for row in result["cell_results"]) else "ok"
        for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"):
            result[key] = sorted({value for row in result["cell_results"] for value in row[key]})
        write(scan / f"sast/deepdive/{task['id']}.json", result)
    script("finalize-sast.py", source, scan)
    pending = load("sast/validation-queue.json")[0]
    closure = {"id": pending["id"], "input_refs": [f"sast/validation-queue.json:{pending['id']}"],
        "disposition": "evidence_limited", "reason": "The bounded correction repair did not establish queued write authority.",
        "risk_context": "Caller-selected records cross into a queued consumer.",
        "missing_fact": "Which principal authorizes the eventual queued write",
        "next_action": "Inspect the queue consumer and its ownership predicate.", "review": None,
        "deferral": {"kind": "budget", "reason": "Both assigned review attempts were consumed investigating the consumer authority obligation."},
        "correction_repair": {"attempted": "Returned the oversized selector to the reviewer within the existing repair allowance.",
                              "diagnostics": ["app.py:11-16 exceeds the 15-line source file."]}}
    closure = qualify(closure)
    review = {"schema_version": "2.0", "id": "V-WRITE", "candidate_id": pending["id"], "status": "evidence_limited",
        "confidence": "high", "closure_reason": closure["reason"], "evidence_refs": ["app.py:11-12"],
        "corrected_candidate": None, "corrections": [], "non_promoted": closure,
        "optional_support": [{"reference": "app.py:11-16", "obligation": "Queued consumer authorization",
            "independent_support": ["app.py:11-12"], "rationale": "Inspected lines show enqueueing, not authority at the absent consumer."}],
        "mechanical_checks": dict.fromkeys(("schema", "paths", "lines", "trace_order", "target_unchanged"), True),
        "provenance": provenance("vulnops-verify-one", f"sast/verify/{pending['id']}.json", routing)}
    review["mechanical_checks"]["lines"] = False
    write(scan / review["provenance"]["artifact_ref"], review)
    write(scan / "sast/validation-results.json", [review])
    script("finalize-sast.py", source, scan, "--finalize")
    finish("sast")
    begin("campaign-planning")
    script("update-run-state.py", scan, "--phase", "campaign-planning", "--phase-status", "failed",
           "--task", "CampaignPlanning", "--task-phase", "campaign-planning", "--task-status", "failed",
           "--error", "Synthetic prior consumer failure on terminal optional metadata.", "--run-status", "incomplete")
    if resume_source_change:
        for repository in repository_roots:
            app = repository / "app.py"
            assert app.read_bytes() == source_bytes[app.relative_to(source)]
            app.write_text(app.read_text() + "\n# Operator edit while the audit is interrupted.\n")
            source_bytes[app.relative_to(source)] = app.read_bytes()
    recovery = recover_campaign_fixture(scan, context_path)
    context = json.loads(context_path.read_text())
    routing = context["model_routing"]
    script("update-run-state.py", scan, "--run-status", "incomplete")

    begin("campaign-planning")
    script("build-evidence-index.py", scan, "--context", context_path)
    index = load("campaign-planning/evidence-index.json")
    unresolved_ids = {row["id"] for row in index["records"] if row["source_id"] in {pending["id"], review["id"]}}
    assert len(unresolved_ids) == 2
    assert all(row["non_promoted"] == closure for row in index["records"] if row["id"] in unresolved_ids)
    assert not any(unresolved_ids.intersection(row["source_record_ids"]) for row in index["primitives"])
    script("build-campaign-plan.py", scan, "--context", context_path, "--prepare-discovery")
    discovery = load("campaign-planning/discovery.json")
    common_evidence = discovery["question_inputs"][0]["evidence_ids"]
    for item in discovery["question_inputs"]:
        item.update(evidence_ids=common_evidence, primitive_ids=[], relationship_ids=[], lane="gap_driven",
                    reason="The same dispatcher supports distinct read and write proof obligations.")
    write(scan / "campaign-planning/discovery.json", discovery)
    script("build-campaign-plan.py", scan, "--context", context_path)
    plan = load("campaign-planning/campaign-plan.json")
    assert len(plan["campaigns"]) == 2 and plan["budget"]["max_campaigns"] == 4
    assert plan["campaigns"][0]["starting_evidence"] == plan["campaigns"][1]["starting_evidence"]
    finish("campaign-planning")
    upstream = {str(path.relative_to(scan)): path.read_bytes() for directory in ("repo-context", "tool-collection", "sast", "campaign-planning")
                for path in (scan / directory).rglob("*") if path.is_file()}

    begin("intrusion")
    wave = json.loads(script("build-intrusion-wave.py", scan, "--context", context_path))
    read_objective = registries[0]["attack_objectives"][0]
    parent = next(row for row in plan["campaigns"] if row["objective_id"] == read_objective["id"])

    def result_for(assignment, active, outcome, reason, missing=""):
        cid = assignment["id"]; ref = f"campaign-planning/campaign-plan.json:{assignment.get('parent_campaign', cid)}"
        return {"schema_version": "2.0", "campaign_id": cid,
            **{key: assignment[key] for key in ("objective_id", "question_id")},
            "status": "rejected" if outcome == "contradicted" else "closed", "conclusion": reason,
            "provenance": provenance("vulnops-intrusion-campaign", f"intrusion/results/{cid}.json", routing),
            "evidence_refs": [ref], "graph_query_receipts": [], "graph_evidence_refs": [], "graph_answers": [],
            "graph_limitations": ["Source-only; no graph execution."], "primitive_updates": [], "candidates": [],
            "input_snapshot": active["input_snapshot"], "wave": active["wave"],
            "resolution": {"outcome": outcome, "reason": reason, "evidence_refs": [ref], "missing_fact": missing,
                           "next_action": "Trace queued write principal propagation." if missing else ""},
            "composition": {"outcome": "none_actionable", "reason": "No established composable primitive in this result.", "evidence_refs": [ref], "primitive_ids": []}}

    for assignment in wave["assignments"].values():
        is_read = assignment["objective_id"] == read_objective["id"]
        result = result_for(assignment, wave, "contradicted" if is_read else "locally_unresolved",
            "The guarded route rejects a record owned by a different tenant; legacy route remains to inspect." if is_read else
            "The update route queues the caller and record ID; consumer authority has not been established.",
            "Which principal authorizes the eventual queued write" if not is_read else "")
        write(scan / f"intrusion/results/{assignment['id']}.json", result)
    owner = snapshot_ref(1); trigger = f"intrusion/results/{parent['id']}.json"
    question = {**registries[0]["investigation_questions"][0], "owner": owner, "local_key": "legacy-read",
                "id": stable_id("Q-", owner, "legacy-read"), "route": "dispatch to legacy lookup",
                "security_question": "Does legacy bypass the tenant predicate proven in guarded?",
                "novelty_reason": "Guarded route was contradicted; the dispatcher exposes a separate legacy consumer.",
                "evidence_refs": [trigger, "app.py:9-10", "app.py:13-15"]}
    proposal = {"parent_campaign": parent["id"], "objective_id": read_objective["id"], "question_id": question["id"],
        "attack_objectives": [], "investigation_questions": [question], "triggering_evidence": [trigger],
        "changed_hypothesis": "The legacy consumer bypasses the guarded route's ownership check.",
        "next_question": question["security_question"], "evidence_delta": [trigger],
        "alternative_path": "dispatch selects legacy rather than guarded for a caller-supplied route", "resource_allocation": 1}
    write(base / "continuations.json", [proposal])
    wave = json.loads(script("build-intrusion-wave.py", scan, "--context", context_path, "--results", *wave["assignments"], "--continuations", base / "continuations.json"))
    assignment = next(iter(wave["assignments"].values()))
    result = result_for(assignment, wave, "established", "Legacy returns the selected record without the tenant check.")
    result["status"] = "candidate"
    finding = sample_finding()
    finding.update(origin="independent_discovery", contributors=[result["provenance"]])
    finding["root_causes"] = [{"file": "app.py", "line": 10, "scope": "legacy", "mechanism": "The legacy consumer omits guarded's tenant predicate."}]
    finding["trace"] = [{"kind": "entrypoint", "file": "app.py", "line": 13, "scope": "dispatch", "description": "Accept caller-controlled route and record identifier."},
        {"kind": "propagation", "file": "app.py", "line": 14, "scope": "dispatch", "description": "Select legacy with the trusted current principal."},
        {"kind": "sink", "file": "app.py", "line": 10, "scope": "legacy", "description": "Return another tenant's record without checking its owner."}]
    candidate = {key: copy.deepcopy(finding[key]) for key in ("finding_kind", "title", "attacker", "root_causes", "trace", "conditions", "impact", "contributors", "transitions")}
    candidate.update(id="IC-AAAAAAAAAAAA", objective_id=assignment["objective_id"], question_id=assignment["question_id"],
                     evidence_refs=result["evidence_refs"], primitive_ids=[], validation_level="source_verified")
    result["candidates"] = [candidate]
    write(scan / f"intrusion/results/{assignment['id']}.json", result)
    script("build-intrusion-wave.py", scan, "--context", context_path, "--results", assignment["id"])
    script("finalize-intrusion.py", scan); finish("intrusion")
    begin("gap-exploration")
    if gap_scenario is not None:
        gap_scenario.explore(context_path, script)
    else:
        import gap_exploration_contract as gap
        prepared = json.loads(script("prepare-gap-exploration.py", "--context", context_path))
        write(base / "empty-gap-plan.json", gap.envelope(
            context, inputs=prepared["inputs"], budget=prepared["budget"],
            objectives=[], questions=[], seeds=[], assignments=[], graph_questions=[]))
        script("prepare-gap-exploration.py", "--context", context_path, "--plan", base / "empty-gap-plan.json")
        script("finalize-gap-exploration.py", "--context", context_path)
    finish("gap-exploration")

    begin("synthesis")
    finding["source_refs"] = [{"kind": "intrusion", "source_id": candidate["id"], "artifact_ref": "intrusion/intrusion-results.json:" + candidate["id"]}]
    finding["verification"].update(model=routing["agents"]["vulnops-synthesis"], source_validation_refs=["app.py:4-15", "deployment.json:1"])
    add_dossier(finding, objective_id=read_objective["id"], repository="service-a" if multi_repository else ".")
    component = finding["affected_components"][0]
    component.update(name="Legacy record lookup", entrypoints=["app.dispatch('/records/legacy', record_id)"])
    component["service"] = {"name": "records-service", "binding": "established", "evidence_refs": ["deployment.json:1"],
        "limitation": "Service name and entrypoint are configuration-backed; live deployment was not exercised."}
    finding["exploitation"]["setup"] = ["In a disposable lab, seed records with distinct tenant-a and tenant-b entries; CURRENT_USER remains tenant-a.",
        "Use only synthetic record IDs and contents; invoke the declared app.dispatch interface, not a presumed live HTTP endpoint."]
    step = finding["exploitation"]["steps"][0]
    step.update(action="Call app.dispatch('/records/legacy', '<tenant-b-record-id>') using the tenant-a principal.",
                controlled_input="path=/records/legacy; record_id=<tenant-b-record-id>",
                why_it_works="ROUTES selects legacy, whose direct records lookup does not call guarded or compare tenant ownership.",
                evidence_refs=["app.py:9-15"], example_ids=["source-example", "request-example"])
    finding["technical_examples"] = [
        {"id": "source-example", "kind": "source", "content": "def legacy(user, record_id):\n    return records[record_id]", "evidence_refs": ["app.py:9-10"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []},
        {"id": "request-example", "kind": "request", "content": "CALL app.dispatch(path='/records/legacy', record_id='<tenant-b-record-id>')", "evidence_refs": ["app.py:13-15"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []},
        {"id": "config-example", "kind": "configuration", "content": DEPLOYMENT.rstrip(), "evidence_refs": ["deployment.json:1"], "substitutions": [], "execution_status": "not_executed", "observation_refs": []}]
    if extra_example is not None:
        finding["technical_examples"].append(copy.deepcopy(extra_example))
    finding["impact_limits"] = ["Source establishes cross-tenant reads only; queued writes remain unresolved.", "No target execution or live deployment exposure was demonstrated."]
    finding["remediation"]["actions"][0].update(change="Route legacy through the shared guarded lookup, preserving CURRENT_USER as the trusted principal.",
        rationale="The existing ownership predicate rejects tenant-b records before returning data.", evidence_refs=["app.py:4-10"])
    finding["remediation"]["containment"] = [{"description": "Temporarily remove the legacy route from ROUTES while fixing its shared consumer.", "component_ids": ["component-1"], "evidence_refs": ["app.py:15"]}]
    finding["remediation"]["limitations"] = ["The proposed fix and regression checks were not executed; no reliable existing detection signal was established."]
    finding = qualify(finding)
    finding["contributors"] = finding_contributors(scan, finding, routing, source_root=source, repositories=context["repositories"])
    write(scan / "synthesis/findings.json", {"schema_version": "2.0", "run_id": context["run_id"], "findings": [finding],
        "non_promoted": [closure], "objective_assessments": objective_assessments(scan, [finding])})
    if gap_scenario is None:
        script("finalize-synthesis.py", scan)
    else:
        gap_scenario.synthesize_ordinary(context_path, script)
    finish("synthesis")
    if gap_scenario is not None and gap_scenario.resume_after_synthesis:
        inherited = copy.deepcopy(load("synthesis/findings.json")["unreviewed"])
        old_attempt = context["attempt_id"]
        script(*initialization, "--resume")
        script("recover-run.py", scan, context_path, context["depth"])
        context = json.loads(context_path.read_text())
        routing = context["model_routing"]
        assert context["attempt_id"] != old_attempt
        assert load("synthesis/findings.json")["unreviewed"] == inherited
        gap_scenario.inherited_closure = inherited

    begin("final-verification")
    if gap_scenario is not None:
        gap_scenario.cohort(script, context_path, "final-verification", "original", "begin")
    finding = load("synthesis/findings.json")["findings"][0]
    reviewer = routing["agents"]["vulnops-independent-verify-one"]
    review = {"schema_version": "2.0", "finding_id": finding["id"], "status": "verified",
        "closure_reason": "Source independently establishes an unguarded legacy read; no dynamic execution is claimed.",
        "evidence_refs": [candidate_ref["artifact_ref"] for candidate_ref in finding["source_refs"]] +
                         ["app.py:4-15", "deployment.json:1"], "primitive_results": [], "transition_results": [],
        "joint_conditions": {"outcome": "established", "reason": "The dispatcher accepts route and ID while retaining the trusted principal.",
                             "evidence_refs": [finding["source_refs"][0]["artifact_ref"]], "missing_fact": "", "next_action": ""},
        "corrections": [], "corrected_finding": None, "actor": "vulnops-independent-verify-one", "model": reviewer,
        "model_diversity": finding_diversity(finding["contributors"], reviewer)}
    if reject_findings:
        review.update(status="rejected", closure_reason="Synthetic negative review does not establish the candidate's attacker reachability.")
    review_dossier(finding, review, success_condition=read_objective["success_condition"])
    review["assessment_context"] = {"attempt_id": context["attempt_id"]}
    write(scan / "final-verification/results/F-001.json", review)
    if gap_scenario is not None:
        gap_scenario.verify_ordinary(context_path, script)
    else:
        script("finalize-verification.py", source, scan)
    finish("final-verification")
    begin("report"); script("render-report.py", scan); finish("report")
    command("bash", ROOT / "scripts/validate-scan.sh", scan)
    script("update-run-state.py", scan, "--run-status", "complete")
    assert not context_path.exists()
    assert not list((base / "runtime/run-owners").glob("*.json"))
    status = command("bash", ROOT / "scripts/audit-status.sh", scan)
    report = load("report/security-report.json")
    assert report["findings"] == load("final-verification/findings.json")["findings"]
    assert report["publication"]["execution_kind"] == "audit"
    assert not (scan / "run-manifest.json").exists()
    assert not (scan / "task-ledger.json").exists()
    assert {row["status"] for row in report["objective_assessments"]} == (
        {"unresolved"} if reject_findings else {"achieved", "unresolved"})
    assert all((scan / ref).read_bytes() == value for ref, value in upstream.items())
    assert {path.relative_to(source): path.read_bytes() for path in source.rglob("*") if path.is_file() and ".git" not in path.parts} == source_bytes
    assert sorted(path.name for path in (scan / "report").iterdir()) == [
        "phase-manifest.json", "security-report.json", "security-report.md"]
    with tempfile.TemporaryDirectory(prefix="portable-audit-", dir=ROOT / "scans") as relocated:
        bundle = Path(relocated).resolve()
        for directory in {ref.split("/")[0] for _, _, ref in PHASES}:
            shutil.copytree(scan / directory, bundle / directory)
        assert not (bundle / "run-manifest.json").exists()
        assert not (bundle / "task-ledger.json").exists()
        command("bash", ROOT / "scripts/validate-scan.sh", bundle)
        relocated_status = command("bash", ROOT / "scripts/audit-status.sh", bundle)
        assert "complete" in relocated_status
        text = (bundle / "report/security-report.md").read_text()
        anchors = set(re.findall(r'<a id="([^"]+)"></a>', text))
        links = re.findall(r"\]\(([^)\n]+)\)", text)
        for link in links:
            parsed = urlsplit(link)
            assert not parsed.scheme and not parsed.netloc, link
            if parsed.path:
                destination = (bundle / "report" / unquote(parsed.path)).resolve()
                assert destination.is_relative_to(bundle) and destination.is_file(), link
                assert not parsed.fragment, link
            else:
                assert unquote(parsed.fragment) in anchors, link
        assert not (bundle / "source").exists()
    return {"scan": scan, "source": source, "report": report, "status": status, "commands": commands,
            "markdown_path": scan / "report/security-report.md", "context": context, "recovery": recovery,
            "unresolved_closure": closure}


class RedTeamWorkflow(unittest.TestCase):
    def test_two_goals_shared_evidence_alternative_route_and_complete_report(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as directory:
            result = exercise_pipeline(Path(directory), resume_source_change=True)
            report = result["report"]
            self.assertEqual(report["summary"]["confirmed"], 1)
            self.assertEqual(report["summary"]["needs_environment"], 0)
            self.assertEqual(report["findings"][0]["affected_components"][0]["service"]["name"], "records-service")
            self.assertEqual(report["findings"][0]["exploitation"]["steps"][0]["evidence_status"], "source_established")
            self.assertEqual(report["findings"][0]["remediation"]["verification_checks"][0]["status"], "proposed")
            self.assertIn(SOURCE.splitlines()[9], result["markdown_path"].read_text())
            serialized = json.dumps(report)
            self.assertIn(result["unresolved_closure"]["missing_fact"], serialized)
            self.assertIn(result["unresolved_closure"]["correction_repair"]["attempted"], serialized)
            self.assertIn(result["unresolved_closure"]["missing_fact"], result["markdown_path"].read_text())
            self.assertEqual(result["recovery"]["restart"], "campaign-planning")


if __name__ == "__main__":
    unittest.main()
