from __future__ import annotations

import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import advantage_actions as actions
import advantage_baseline as baseline
import advantage_contract as contract
import advantage_owners as owners
import investigation_experiments as experiments
import remediation_common as remediation


PATCH = b"diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-allowed = True\n+allowed = False\n"
DELETE = b"diff --git a/guard.py b/guard.py\ndeleted file mode 100644\n--- a/guard.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-check_access()\n"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def accepted_finding(identifier="F-001"):
    return {"id": identifier, "status": "verified", "verdict": "confirmed",
            "title": "Control bypass", "severity": "high", "finding_kind": "code",
            "impact": "An unauthorized caller can cross the inspected control.",
            "contributors": [{"actor": "fixture-reviewer", "selector": "fixture-model",
                              "artifact_ref": "final-verification/findings.json"}],
            "root_causes": [{"file": "app.py", "scope": "authorization", "line": 1}]}


def snapshot_files(directory):
    return {path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in Path(directory).rglob("*") if path.is_file()}


def queue_patch(source):
    """Author a fixture patch without executing the synthetic application."""
    from test_redteam_workflow import SOURCE
    original = (Path(source) / "app.py").read_text()
    if original != SOURCE:
        raise AssertionError("this helper accepts only the exact synthetic records-service fixture")
    needle = "    queue.append((user, record_id))\n"
    if original.count(needle) != 1:
        raise AssertionError("linked smoke source must contain its single known queue append")
    replacement = ('    record = records[record_id]\n'
                   '    if record["tenant"] != user["tenant"]:\n'
                   '        raise PermissionError("wrong tenant")\n' + needle)
    modified = original.replace(needle, replacement)
    patch_bytes = ("diff --git a/app.py b/app.py\n" + "".join(difflib.unified_diff(
        original.splitlines(keepends=True), modified.splitlines(keepends=True),
        fromfile="a/app.py", tofile="b/app.py"))).encode()
    return modified, patch_bytes


def exercise_actions_cli(context_path, *, fixture_root=None):
    """Real selected-action CLI closure from the nonempty linked smoke source.

    Authored conclusions are deterministic fixtures, not model or dynamic proof.
    The caller owns cleanup of returned fixture/scan/work directories.
    """
    from test_advantage_pipeline import exercise_linked_cli
    from advantage_native_fixture import native_call, native_controller
    context_path = Path(context_path).resolve()
    source_context = contract.load(context_path)
    source_base = Path(source_context["scan_base"])
    if not (source_base / "report/security-report.json").is_file():
        source_context = exercise_linked_cli(context_path)["context"]
    baseline = Path(source_context["source_scan"])
    source = Path(source_context["source_root"])
    snapshots = {"baseline": snapshot_files(baseline), "advantage": snapshot_files(source_base),
                 "source": snapshot_files(source)}
    findings = contract.load(source_base / "final-verification/findings.json")["findings"]
    if [finding["id"] for finding in findings] != ["F-001"]:
        raise AssertionError("actions smoke requires the completed nonempty linked fixture with accepted F-001")
    delivered_baseline = source_base.parent / source_context["source_run_id"]
    delivery_copy = None
    if baseline != delivered_baseline:
        if delivered_baseline.exists():
            assert snapshot_files(delivered_baseline) == snapshots["baseline"]
        else:
            shutil.copytree(baseline, delivered_baseline)
            delivery_copy = str(delivered_baseline)
    fixture_root = Path(fixture_root).resolve() if fixture_root else ROOT / "work/advantage-action-fixtures" / uuid.uuid4().hex
    fixture_root.mkdir(parents=True)
    patch_path = fixture_root / "assessment.patch"
    _, patch_bytes = queue_patch(source)
    patch_path.write_bytes(patch_bytes)
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                   "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "synthetic-actions-" + fixture_root.name}
    commands = []
    context = None
    phase = "handoff"

    def command(script, *arguments):
        authority = (patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": ""}) if "--portable" in arguments else
                     native_controller(environment["VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID"])
                     if context is None else native_call(context, phase))
        with patch.dict(os.environ, environment), authority:
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, arguments)],
                                    cwd=ROOT, capture_output=True, text=True, check=False)
        commands.append({"script": script, "returncode": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise AssertionError(f"{script}: {result.stderr}\n{result.stdout}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    context = command("init-advantage.py", delivered_baseline, "--source-root", source, "--mode", "actions",
                      "--action-source", source_base, "--patch", patch_path, "--verify-fix", "F-001",
                      "--assess-patch-risk", "--hardening", "--track-finding", "F-001")
    action_context_path = Path(context["input_path"])
    base = Path(context["scan_base"])
    binding = context["patch_binding"]
    command("prepare-advantage-patch.py", base, "--context", action_context_path)

    def citation(view):
        root = source if view == "base" else actions.derived_root(context)
        return {"view": view, "repository": ".", "path": "app.py",
                "sha256": contract.sha256_file(root / "app.py"), "start_line": 11,
                "end_line": 15 if view == "base" else 18}

    document = actions.empty_actions(context)
    document["verify_fix"] = {"status": "completed", "records": [{
        "finding_id": "F-001", "finding_execution_id": source_context["run_id"],
        "patch_sha256": binding["sha256"], "outcome": "inconclusive",
        "original_path": "established", "alternate_routes": "established",
        "legitimate_behavior": "unresolved", "checks": [{
            "name": "Authorized queue behavior and absent-record compatibility",
            "status": "not_run", "experiment_ref": None,
            "limitation": "No target command ran; compatibility of enqueueing identifiers for records not yet present is unresolved."}],
        "citations": [citation("base"), citation("derived")],
        "rationale": "The derived ownership guard blocks the selected queue path, but legitimate asynchronous record-creation behavior is not demonstrated."}]}
    document["patch_risk"] = {"status": "completed", "records": [{
        "patch_sha256": binding["sha256"], "impact": "medium", "likelihood": "unknown",
        "recoverability": "Revert the isolated guard change through normal reviewed deployment; no deployment was attempted.",
        "confidence": "medium", "checks": [{
            "name": "Legitimate queued operation regression", "status": "not_run", "experiment_ref": None,
            "limitation": "Source-only assessment; no regression suite or application code executed."}],
        "limitations": ["The source does not establish whether legitimate producers may enqueue not-yet-existing record IDs."],
        "citations": [citation("derived")],
        "rationale": "The guard introduces a synchronous record lookup before enqueueing and may reject previously accepted absent records; this is not merge authorization."}]}
    document["hardening"] = {"status": "completed", "records": [{
        "outcome": "proposal", "finding_execution_id": source_context["run_id"], "finding_ids": ["F-001"],
        "proposal": "Centralize record authorization at the queue producer boundary before accepting any routed operation.",
        "attack_transitions": ["Block caller-selected cross-tenant record IDs before shared queue append."],
        "falsifiable_invariant": "Every accepted queue entry has a record-ownership decision for the submitting principal.",
        "assumptions": ["The queue producer can consult authoritative record ownership."],
        "tradeoffs": ["Central authorization adds dependency and latency to queue producers."],
        "citations": [citation("base")],
        "rationale": "The independently accepted chain identifies the missing producer-side ownership decision; this remains a design proposal, not a verified repair."}]}
    write_json(base / "handoff/action-draft.json", document)
    command("finalize-advantage-handoff.py", base, "--context", action_context_path)
    command("validate-advantage.py", base, "--phase", "handoff", "--context", action_context_path)
    phase = "report"
    command("render-advantage-report.py", "--context", action_context_path)
    command("validate-advantage.py", base, "--phase", "report", "--context", action_context_path)
    command("advantage-cleanup.py", "--context", action_context_path)
    assert not action_context_path.exists()
    command("validate-advantage.py", base, "--portable")
    report = contract.load(base / "report/security-report.json")
    published = contract.load(base / "handoff/actions.json")
    assert not (base / "advantage-manifest.json").exists()
    assert all(contract.skip_disposition(context, item) for item in contract.SKIPPED_PHASES)
    assert report["findings"] == [] and report["coverage"]["investigation_status"] == "skipped"
    assert all(published[name]["status"] == "completed" for name in ("verify_fix", "patch_risk", "hardening", "tracking"))
    assert published["diff_review"] == {"status": "not_selected", "records": []}
    assert published["tracking"]["records"][0]["finding_execution_id"] == source_context["run_id"]
    assert snapshots == {"baseline": snapshot_files(baseline), "advantage": snapshot_files(source_base),
                         "source": snapshot_files(source)}
    return {"context": context, "context_path": str(action_context_path), "report": report,
            "actions": published, "commands": commands, "fixture_root": str(fixture_root),
            "derived_work_root": str(actions.derived_root(context).parent),
            "baseline_delivery_copy": delivery_copy,
            "source_snapshots_unchanged": True}


def exercise_derived_fixture_cli(context_path):
    """Configure only fixture authors for derived claims; production gates stay real."""
    import test_advantage_pipeline as fixture
    context = contract.load(Path(context_path))
    base = Path(context["scan_base"])
    original_plan, original_chain = fixture.authored_plan, fixture.authored_chain

    def derived_plan(*args, **kwargs):
        plan = original_plan(*args, **kwargs)
        for assignment in plan["assignments"]:
            assignment["source_view"] = "derived"
        return plan

    def derived_chain(*args, **kwargs):
        finding, link = original_chain(*args, **kwargs)
        link["source_view"] = "derived"
        finding["contributors"] = fixture.pipeline.contributor_union(args[0], finding, link)
        return finding, link

    derived = actions.derived_root(context)
    document = actions.empty_actions(context)
    document["diff_review"] = {"status": "completed", "records": [{
        "path": "app.py", "change": "modified", "patch_sha256": context["patch_binding"]["sha256"],
        "assessment": "no_security_delta", "affected_consumers": [],
        "citations": [{"view": "derived", "repository": ".", "path": "app.py",
                      "sha256": contract.sha256_file(derived / "app.py"), "start_line": 11, "end_line": 16}],
        "rationale": "The supplied patch only adds a trailing comment; the reviewed queue control remains unchanged."}]}
    write_json(base / "investigation/actions.json", document)
    fixture.authored_plan, fixture.authored_chain = derived_plan, derived_chain
    try:
        result = fixture.exercise_linked_cli(context_path)
    finally:
        fixture.authored_plan, fixture.authored_chain = original_plan, original_chain
    assert contract.load(base / "final-verification/findings.json")["links"][0]["source_view"] == "derived"
    return {"context": result["context"], "commands": result["commands"]}


def exercise_advantage_remediation_cli(scan_base, source_root):
    """A new mixed-attempt finding is not exact-source production patch authority."""
    context = contract.context_for_base(scan_base, source_root)
    scan, audit, source = map(Path, (context["scan_base"], context["source_scan"], context["source_root"]))
    before = {"audit": snapshot_files(audit), "advantage": snapshot_files(scan), "source": snapshot_files(source)}
    commands = []
    with tempfile.TemporaryDirectory(prefix="advantage-remediation-cli-") as temporary:
        harness = Path(temporary).resolve()
        for directory in ("scripts", "schemas", "config", "tests"):
            shutil.copytree(ROOT / directory, harness / directory, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for relative in ("config.toml",):
            destination = harness / relative
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
        copied_source = harness / "target" / source.name
        shutil.copytree(source, copied_source)
        copied_scan = harness / "scans" / scan.parent.name / scan.name
        copied_audit = copied_scan.parent / context["source_run_id"]
        shutil.copytree(audit, copied_audit)
        shutil.copytree(scan, copied_scan)
        copied_before = {"audit": snapshot_files(copied_audit), "advantage": snapshot_files(copied_scan),
                         "source": snapshot_files(copied_source)}
        remediation_context = harness / ".harness/remediation-context.json"
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                       "VULNOPS_REMEDIATION_CONTEXT": str(remediation_context)}
        environment.pop("VULNOPS_ADVANTAGE_CONTEXT", None)
        environment.pop("VULNOPS_AUDIT_CONTEXT", None)

        def command(script, *arguments, expect_success=True):
            result = subprocess.run([sys.executable, str(harness / "scripts" / script), *map(str, arguments)],
                                    cwd=harness, env=environment, capture_output=True, text=True, check=False)
            commands.append({"script": script, "returncode": result.returncode,
                             "stdout": result.stdout, "stderr": result.stderr})
            if expect_success and result.returncode:
                raise AssertionError(f"{script}: {result.stderr}\n{result.stdout}")
            if not expect_success:
                assert result.returncode != 0, "invalid remediation source unexpectedly admitted"
                return result
            if script == "validate-remediation.py":
                return result.stdout
            return json.loads(result.stdout) if result.stdout.strip() else None

        rejection = command("init-remediation.py", copied_scan, expect_success=False)
        assert "manual-required" in rejection.stderr
        assert "exact-source authority" in rejection.stderr
        assert "intended patch base" in rejection.stderr
        assert not remediation_context.exists()
        assert not any((harness / "remediations").rglob("*.patch"))
        assert not any((harness / "remediations").rglob("remediation-manifest.json"))
        assert copied_before == {"audit": snapshot_files(copied_audit), "advantage": snapshot_files(copied_scan),
                                 "source": snapshot_files(copied_source)}
        assert before == {"audit": snapshot_files(audit), "advantage": snapshot_files(scan), "source": snapshot_files(source)}
        return {"commands": commands, "manual_required": True,
                "rejected_source_variants": [{"variant": "historical-or-mixed-attempt-source", "stderr": rejection.stderr}],
                "source_snapshots_unchanged": True}


class AdvantageActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("allowed = True\n")
        (self.repo / "guard.py").write_text("check_access()\n")
        self.scan = self.root / "scans/repo/advantage"
        self.scan.mkdir(parents=True)
        self.source = self.root / "scans/repo/audit"
        self.source.mkdir()
        self.patch_file = self.root / "change.patch"
        self.patch_file.write_bytes(PATCH)
        self.context = {
            "schema_version": "2.0", "execution_kind": "advantage", "run_id": "advantage",
            "scan_base": str(self.scan), "source_scan": str(self.source), "source_root": str(self.repo),
            "repo_path": str(self.repo), "repositories": [{"path": "."}], "source_run_id": "audit",
            "attempt_id": "attempt-current", "mode": "diff", "patch_binding": None,
            "options": {"patch": str(self.patch_file), "repository": None, "verify_fix": [],
                        "assess_patch_risk": False, "hardening": False, "track_findings": [], "action_source": None},
            "baseline": {"execution_id": "audit", "root": str(self.source)}, "action_source": None,
            "recovery_count": 0,
            "reproduction_mode": "off", "experiment_budget": {"max_experiments": 1, "max_concurrency": 1,
                "timeout_seconds": 10, "cpu_seconds": 5, "memory_mb": 128, "max_processes": 16, "max_output_kb": 16},
        }
        self.root_patch = patch.object(actions, "ROOT", self.root)
        self.root_patch.start()
        # Replace only the experiment module's backend interface. Ownership keeps
        # the real subprocess module for read-only process-liveness probes.
        self.backend = SimpleNamespace(
            run=Mock(return_value=subprocess.CompletedProcess([], 1)),
            DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)

    def tearDown(self):
        self.root_patch.stop()
        self.temp.cleanup()

    def prepare(self, data=PATCH):
        self.patch_file.write_bytes(data)
        self.context["patch_binding"] = actions.prepare_patch(self.context)
        return self.context["patch_binding"]

    def citation(self, name="app.py", view="derived"):
        root = actions.derived_root(self.context) if view == "derived" else self.repo
        return {"view": view, "repository": ".", "path": name, "sha256": contract.sha256_file(root / name),
                "start_line": 1, "end_line": 1}

    def diff_document(self, data=PATCH):
        binding = self.prepare(data)
        doc = actions.empty_actions(self.context)
        doc["diff_review"] = {"status": "completed", "records": [
            {"path": item["path"], "change": item["status"], "patch_sha256": binding["sha256"],
             "assessment": "deleted_control" if item["status"] == "deleted" else "changed_behavior",
             "affected_consumers": [self.citation()] if item["status"] == "deleted" else [],
             "citations": [self.citation(item["path"], "base" if item["status"] == "deleted" else "derived")],
             "rationale": "Source view establishes the changed control; no target execution occurred."}
            for item in binding["changed_files"]]}
        return doc

    def selected_document(self):
        self.context["mode"] = "actions"
        self.context["options"].update(verify_fix=["F-001"], assess_patch_risk=True)
        source = self.root / "scans/repo/previous"
        self.context["action_source"] = {"root": str(source), "execution_id": "previous",
                                         "selected_findings": [{"id": "F-001"}]}
        write_json(source / "final-verification/findings.json", {"run_id": "previous", "findings": [
            accepted_finding()]})
        self._source_publication(source, "previous")
        binding = self.prepare()
        document = actions.empty_actions(self.context)
        document["verify_fix"] = {"status": "completed", "records": [{
            "finding_id": "F-001", "finding_execution_id": "previous", "patch_sha256": binding["sha256"],
            "outcome": "fixed", "original_path": "established", "alternate_routes": "established",
            "legitimate_behavior": "established", "checks": [],
            "citations": [self.citation(view="base"), self.citation()],
            "rationale": "Fixture source review establishes the original route, alternate routes and legitimate behavior."}]}
        document["patch_risk"] = {"status": "completed", "records": [{
            "patch_sha256": binding["sha256"], "impact": "medium", "likelihood": "low",
            "recoverability": "A reviewed revert restores the original behavior.", "confidence": "high",
            "checks": [], "limitations": ["Source review is not permission to merge or deploy."],
            "citations": [self.citation()], "rationale": "The independent risk assessment inspects the derived guard."}]}
        return document

    def _source_publication(self, source, execution_id):
        final = json.loads((source / "final-verification/findings.json").read_text())
        report = {"run_id": execution_id, "counts": {}, "findings": final["findings"],
                  "publication": {"execution_kind": "advantage", "repository": "repo",
                                  "repositories": [{"path": "."}], "model_routing": {}, "producer_routes": {},
                                  "mode": "standard", "source": {"source_run_id": "audit"}}}
        write_json(source / "report/security-report.json", report)
        (source / "report/security-report.md").write_text("# Completed assessment\n")
        return report

    def _source_manifest(self, source, execution_id="completed"):
        """Author a schema-valid authority fixture, not a completed native run."""
        import tomllib
        from advantage_config import resolve_budget
        from model_routing import advantage_routing, load_routing
        with (ROOT / "config.toml").open("rb") as handle:
            config = tomllib.load(handle)
        manifest = {
            "schema_version": "2.0", "execution_kind": "advantage", "workflow": "canonical-redteam-v2",
            "run_id": execution_id, "source_run_id": "audit", "repo_id": "repo", "repository": "repo",
            "commit": "fixture", "repositories": [{"name": "repo", "path": ".", "remote_url": "fixture", "commit": "fixture"}],
            "repository_count": 1, "mode": "standard", "depth": "quick",
            "model_routing": advantage_routing(load_routing(ROOT)), "budget": resolve_budget("quick", config),
            "experiment_budget": self.context["experiment_budget"], "reproduction_mode": "off",
            "network": {"agent_egress": "policy_only", "backend": "none", "enforced": False,
                        "limitation": "Authored source-only fixture."},
            "offline_package": {"manifest_sha256": None, "platform": "darwin_arm64", "release": False,
                                "osv_snapshot": "fixture", "osv_lock_sha256": None},
            "codegraph_mode": "disabled", "baseline": {"execution_id": "audit", "catalog_ref": "baseline/catalog.json"},
            "options": {"patch": None, "repository": None, "verify_fix": [], "assess_patch_risk": False,
                        "hardening": False, "track_findings": [], "action_source": None},
            "patch_binding": None, "action_source": None, "status": "complete",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            "phases": {phase: "ok" for phase in contract.PHASES if phase != "gap-exploration"},
            "recovery_count": 0, "recovery_history": [], "error": None,
        }
        write_json(source / "advantage-manifest.json", manifest)
        if not (source / "final-verification/findings.json").exists():
            write_json(source / "final-verification/findings.json", {"findings": []})
        write_json(source / "report/security-report.json", {"run_id": execution_id, "counts": {}, "findings": []})
        (source / "report/security-report.md").write_text("# Legacy completed assessment\n")
        return manifest

    def test_selected_actions_publish_independent_assessments_only_when_requested(self):
        selected = self.selected_document()
        before = snapshot_files(self.repo)
        historical = snapshot_files(Path(self.context["action_source"]["root"]))
        draft = self.scan / "handoff/action-draft.json"
        for damaged in ("verify_fix", "patch_risk"):
            with self.subTest(damaged=damaged):
                document = copy.deepcopy(selected)
                if damaged == "verify_fix":
                    document["verify_fix"]["records"][0]["citations"][1]["end_line"] = 999
                else:
                    document["patch_risk"]["records"][0]["citations"] = []
                write_json(draft, document)
                draft_bytes = draft.read_bytes()
                with patch.object(contract, "require_active"), patch("advantage_pipeline.record_source_receipts"):
                    published = actions.finalize_handoff(self.scan, self.context)
                    replay = actions.finalize_handoff(self.scan, self.context)
                self.assertEqual(published, replay)
                self.assertEqual(draft.read_bytes(), draft_bytes)
                fix = published["verify_fix"]["records"][0]
                risk = published["patch_risk"]["records"][0]
                if damaged == "verify_fix":
                    self.assertEqual((fix["outcome"], fix["assessment_status"]), ("inconclusive", "locally_unresolved"))
                    self.assertEqual(fix["citations"][1]["end_line"], 999)
                    self.assertTrue(any(row["code"] == "invalid_range" for row in fix["evidence_quality"]["diagnostics"]))
                    self.assertEqual(risk["assessment_status"], "supported")
                    self.assertEqual({key: risk[key] for key in selected["patch_risk"]["records"][0]},
                                     selected["patch_risk"]["records"][0])
                else:
                    self.assertEqual((fix["outcome"], fix["assessment_status"]), ("fixed", "supported"))
                    self.assertEqual((risk["assessment_status"], risk["likelihood"], risk["confidence"]),
                                     ("locally_unresolved", "unknown", "low"))
                self.assertEqual(published["non_promoted"][0]["id"], damaged + "/records/0")
                actions.validate_actions(self.context, published)
                self.assertFalse((self.scan / "investigation").exists())
                self.assertFalse((self.root / "remediations").exists())
                self.assertEqual(snapshot_files(self.repo), before)
                self.assertEqual(snapshot_files(Path(self.context["action_source"]["root"])), historical)
        with self.subTest(selection="absent"):
            self.context["mode"] = "standard"
            self.context["options"].update(patch=None, verify_fix=[], assess_patch_risk=False)
            self.context["patch_binding"] = None
            doc = actions.empty_actions(self.context)
            actions.validate_actions(self.context, doc)
            doc["patch_risk"]["status"] = "completed"
            with self.assertRaisesRegex(ValueError, "explicit selection"):
                actions.validate_actions(self.context, doc)

    def test_optional_support_needs_independent_obligations_not_valid_citation_count(self):
        document = self.selected_document()
        fix = document["verify_fix"]["records"][0]
        fix["citations"].append({**self.citation(), "end_line": 999})
        without_rationale = actions.assess_actions(self.context, document)
        self.assertEqual(without_rationale["verify_fix"]["records"][0]["outcome"], "inconclusive")
        fix["optional_support"] = [{
            "reference": "citations[2]", "obligation": "Redundant derived guard evidence.",
            "independent_support": ["citations[0]", "citations[1]"],
            "rationale": "The inspected base and derived source independently establish the guard, alternate route exclusion and legitimate behavior."}]
        optional = actions.assess_actions(self.context, document)
        self.assertEqual(optional["verify_fix"]["records"][0]["outcome"], "fixed")
        self.assertEqual(optional["verify_fix"]["records"][0]["evidence_quality"]["diagnostics"][0]["disposition"], "optional")
        self.assertEqual(optional["non_promoted"], [])
        fix["citations"][1]["end_line"] = 999
        essential_missing = actions.assess_actions(self.context, document)
        self.assertEqual(essential_missing["verify_fix"]["records"][0]["outcome"], "inconclusive")
        self.assertEqual(essential_missing["patch_risk"]["records"][0]["assessment_status"], "supported")


    def test_unavailable_selected_finding_is_not_replaced_or_tracked_as_accepted(self):
        document = self.selected_document()
        source = Path(self.context["action_source"]["root"])
        write_json(source / "final-verification/findings.json", {"run_id": "previous", "findings": [
            accepted_finding("F-002")]})
        self._source_publication(source, "previous")
        self.context["options"]["track_findings"] = ["F-001"]
        document["tracking"] = {"status": "completed", "records": actions.tracking_records(self.context)}
        result = actions.assess_actions(self.context, document)
        fix = result["verify_fix"]["records"][0]
        self.assertEqual((fix["finding_id"], fix["outcome"]), ("F-001", "inconclusive"))
        tracking = result["tracking"]["records"][0]
        self.assertEqual(tracking["finding_id"], "F-001")
        self.assertEqual(tracking["assessment_status"], "locally_unresolved")
        self.assertEqual(tracking["publication"], "offline_only")
        self.assertNotIn("title", tracking)
        self.assertNotIn("severity", tracking)
        self.assertEqual(result["patch_risk"]["records"][0]["assessment_status"], "supported")

    def test_bad_citation_does_not_hide_execution_patch_hash_or_scope_faults(self):
        document = self.selected_document()
        document["verify_fix"]["records"][0]["citations"][1]["end_line"] = 999
        mutations = [
            lambda row: row.update(run_id="foreign"),
            lambda row: row["verify_fix"]["records"][0].update(finding_execution_id="foreign"),
            lambda row: row["patch_risk"]["records"][0].update(patch_sha256="0" * 64),
            lambda row: row["patch_risk"]["records"][0]["citations"][0].update(path="../outside"),
            lambda row: row["patch_risk"]["records"][0]["citations"][0].update(repository="foreign"),
            lambda row: row["verify_fix"]["records"][0]["citations"][1].update(sha256="0" * 64),
        ]
        for mutate in mutations:
            broken = copy.deepcopy(document)
            mutate(broken)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                actions.assess_actions(self.context, broken)
        source = Path(self.context["action_source"]["root"])
        findings = contract.load(source / "final-verification/findings.json")
        findings["run_id"] = "foreign"
        write_json(source / "final-verification/findings.json", findings)
        with self.assertRaises(ValueError):
            actions.assess_actions(self.context, document)


    def test_hardening_proposals_are_isolated_and_historical_drafts_unchanged(self):
        document = self.selected_document()
        self.context["options"]["hardening"] = True
        proposal = {
            "outcome": "proposal", "finding_execution_id": "previous", "finding_ids": ["F-001"],
            "proposal": "Centralize authorization before accepting routed operations.",
            "attack_transitions": ["Reject unauthorized callers before dispatch."],
            "falsifiable_invariant": "Every dispatch has a caller authorization decision.",
            "assumptions": ["The caller identity is authoritative."], "tradeoffs": ["Adds an authorization dependency."],
            "citations": [self.citation(view="base")], "rationale": "The accepted finding identifies the transition."}
        unsupported = copy.deepcopy(proposal)
        unsupported["citations"][0]["end_line"] = 999
        document["hardening"] = {"status": "completed", "records": [unsupported, proposal]}
        original = copy.deepcopy(document)
        result = actions.assess_actions(self.context, document)
        self.assertEqual(document, original)
        self.assertEqual([row["outcome"] for row in result["hardening"]["records"]], ["unresolved", "proposal"])
        actions.validate_actions(self.context, document)
        self.assertEqual(document, original)
        portable = {**self.context, "source_root": None, "repo_path": None}
        actions.validate_actions(portable, result)


    def test_patch_creates_disposable_view_and_preserves_base(self):
        before = snapshot_files(self.repo)
        binding = self.prepare(PATCH + DELETE)
        self.assertEqual(before, snapshot_files(self.repo))
        self.assertEqual((self.repo / "app.py").read_text(), "allowed = True\n")
        self.assertEqual((actions.derived_root(self.context) / "app.py").read_text(), "allowed = False\n")
        self.assertFalse((actions.derived_root(self.context) / "guard.py").exists())
        self.assertEqual(binding["changed_files"][1]["status"], "deleted")
        self.assertIsNone(binding["changed_files"][1]["new_sha256"])
        self.assertEqual((self.scan / binding["patch_ref"]).read_bytes(), PATCH + DELETE)
        actions.validate_patch(self.context)

    def test_patch_preserves_unmodified_components_from_current_base(self):
        (self.repo / "new-component.py").write_text("authorized = True\n")
        before = snapshot_files(self.repo)
        binding = self.prepare()
        self.assertEqual(binding["repository"], ".")
        self.assertEqual(snapshot_files(self.repo), before)
        self.assertEqual((actions.derived_root(self.context) / "app.py").read_text(), "allowed = False\n")
        self.assertEqual((actions.derived_root(self.context) / "new-component.py").read_text(), "authorized = True\n")

    def test_fixed_current_base_yields_local_patch_error_and_preserves_audit(self):
        write_json(self.source / "run-manifest.json", {"status": "complete"})
        before = snapshot_files(self.source)
        (self.repo / "app.py").write_text("allowed = False\n")
        with self.assertRaisesRegex(ValueError, "selected current repository base"):
            self.prepare()
        self.assertEqual(snapshot_files(self.source), before)

    def test_patch_rejects_traversal_binary_symlink_modes_and_wrong_base(self):
        for data in (PATCH.replace(b"app.py", b"../outside"), PATCH + b"GIT binary patch\n", PATCH.replace(b"--- a/app.py", b"new file mode 120000\n--- a/app.py")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                actions.patch_paths(data)
        self.patch_file.write_bytes(PATCH.replace(b"allowed = True", b"missing = True"))
        with self.assertRaisesRegex(ValueError, "apply exactly"):
            actions.prepare_patch(self.context)
        self.assertFalse(actions.derived_root(self.context).exists())

    def test_patch_rejects_changed_bytes_and_derived_tree_drift(self):
        self.prepare()
        self.patch_file.write_bytes(PATCH + b"\n")
        with self.assertRaisesRegex(ValueError, "patch changed"):
            actions.validate_patch(self.context)
        self.patch_file.write_bytes(PATCH)
        (actions.derived_root(self.context) / "app.py").write_text("other = True\n")
        with self.assertRaisesRegex(ValueError, "changed-file content"):
            actions.validate_patch(self.context)

    def test_retained_diff_publication_does_not_recreate_or_reassess_disposable_source(self):
        document = actions.assess_actions(self.context, self.diff_document(), investigation=True)
        write_json(self.scan / "investigation/actions.json", document)
        manifest = self._source_manifest(self.scan, self.context["run_id"])
        manifest.update(mode="diff", patch_binding=self.context["patch_binding"])
        manifest["options"].update(patch=self.context["patch_binding"]["sha256"], repository=".")
        write_json(self.scan / "advantage-manifest.json", manifest)
        original = (self.scan / "investigation/actions.json").read_bytes()
        shutil.rmtree(actions.derived_root(self.context))
        (self.repo / "app.py").write_text("replacement_source = True\n")
        portable = copy.deepcopy(self.context)
        portable["portable"] = True
        portable["source_root"] = None
        # Read retained analytical assessments; never continue the completed execution.
        handoff = actions.assess_actions(portable, document)
        actions.validate_actions(portable, handoff)
        self.assertEqual(handoff["diff_review"], document["diff_review"])
        self.assertEqual((self.scan / "investigation/actions.json").read_bytes(), original)
        self.assertFalse(actions.derived_root(self.context).exists())
        with self.assertRaisesRegex(ValueError, "selected current repository base"):
            actions.prepare_patch(self.context)


    def test_patch_rejects_missing_unused_ambiguous_or_wrong_repository(self):
        for update in ({"patch": None}, {"repository": "other"}):
            context = copy.deepcopy(self.context)
            context["options"].update(update)
            with self.assertRaises(ValueError):
                actions.prepare_patch(context)
        context = copy.deepcopy(self.context)
        context["repositories"] = [{"path": "one"}, {"path": "two"}]
        with self.assertRaisesRegex(ValueError, "exact repository"):
            actions.prepare_patch(context)
        context = copy.deepcopy(self.context)
        context["mode"] = "standard"
        with self.assertRaisesRegex(ValueError, "unused"):
            actions.prepare_patch(context)

    def test_diff_accounts_for_deletions_and_validates_source_view(self):
        document = self.diff_document(PATCH + DELETE)
        actions.validate_actions(self.context, document, investigation=True)
        broken = copy.deepcopy(document)
        broken["diff_review"]["records"].pop()
        with self.assertRaisesRegex(ValueError, "every exact changed"):
            actions.validate_actions(self.context, broken, investigation=True)
        document["diff_review"]["records"][1]["citations"][0]["view"] = "derived"
        assessed = actions.assess_actions(self.context, document, investigation=True)
        self.assertEqual(assessed["diff_review"]["records"][1]["assessment"], "unresolved")
        self.assertEqual(assessed["diff_review"]["records"][0]["assessment"], "changed_behavior")
        self.assertEqual(actions.assess_actions(self.context, assessed, investigation=True), assessed)


    def test_fixed_requires_legitimate_behavior_and_exact_accepted_source(self):
        self.context["mode"] = "actions"
        self.context["options"]["verify_fix"] = ["F-001"]
        selected = self.root / "scans/repo/previous"
        self.context["action_source"] = {"root": str(selected), "execution_id": "previous",
                                         "selected_findings": [{"id": "F-001"}]}
        write_json(selected / "final-verification/findings.json", {"run_id": "previous", "findings": [
            accepted_finding()]})
        self._source_publication(selected, "previous")
        binding = self.prepare()
        doc = actions.empty_actions(self.context)
        record = {"finding_id": "F-001", "finding_execution_id": "previous", "patch_sha256": binding["sha256"],
                  "outcome": "fixed", "original_path": "established", "alternate_routes": "established",
                  "legitimate_behavior": "unresolved", "checks": [], "citations": [self.citation(), self.citation(view="base")],
                  "rationale": "The source blocks the route but compatibility remains unresolved."}
        doc["verify_fix"] = {"status": "completed", "records": [record]}
        with self.assertRaisesRegex(ValueError, "legitimate-behavior"):
            actions.validate_actions(self.context, doc)
        record["outcome"] = "inconclusive"
        actions.validate_actions(self.context, doc)
        record["finding_execution_id"] = "audit"
        with self.assertRaisesRegex(ValueError, "accepted finding"):
            actions.validate_actions(self.context, doc)

    def test_hardening_no_opportunity_requires_readable_exact_accepted_cohort(self):
        self.context["mode"] = "standard"
        self.context["options"].update(patch=None, hardening=True)
        authority = self.scan / "final-verification/findings.json"
        doc = actions.empty_actions(self.context)
        doc["hardening"] = {"status": "completed", "records": [{"outcome": "no_opportunity",
            "finding_execution_id": "advantage", "reviewed_finding_ids": [],
            "rationale": "No independently accepted attack transition supports a structural proposal."}]}
        for available in (False, True):
            with self.subTest(authority_available=available):
                if available:
                    write_json(authority, {"run_id": "advantage", "findings": []})
                result = actions.assess_actions(self.context, doc)
                if available:
                    self.assertEqual(result["hardening"]["records"][0]["outcome"], "no_opportunity")
                    self.assertEqual(result["non_promoted"], [])
                    actions.validate_actions(self.context, doc)
                    doc["hardening"]["records"][0]["reviewed_finding_ids"] = ["F-001"]
                    with self.assertRaises(ValueError):
                        actions.validate_actions(self.context, doc)
                else:
                    self.assertEqual(result["hardening"]["records"][0]["outcome"], "unresolved")
                    self.assertEqual(result["non_promoted"][0]["id"], "hardening/records/0")

    def test_tracking_preserves_exact_execution_ownership_and_assessment_scope(self):
        self.context["options"].update(patch=None, track_findings=["F-001"])
        (self.repo / "app.py").write_text("allowed = False\n")
        for own_execution in (False, True):
            with self.subTest(own_execution=own_execution):
                execution_id = self.context["run_id"] if own_execution else "completed"
                source = self.scan if own_execution else self.root / "scans/repo/completed"
                self.context["mode"] = "standard" if own_execution else "actions"
                self.context["action_source"] = None if own_execution else {
                    "root": str(source), "execution_id": execution_id, "selected_findings": [{"id": "F-001"}]}
                finding = accepted_finding()
                finding["assessment_context"] = {"attempt_id": "original-producer"}
                write_json(source / "final-verification/findings.json", {
                    "run_id": execution_id, "findings": [finding],
                    "links": [{"finding_id": "F-001", "baseline_ids": [] if own_execution else ["F-002"]}]})
                if not own_execution:
                    self._source_publication(source, execution_id)
                before = snapshot_files(source)
                record = actions.tracking_records(self.context)[0]
                self.assertEqual(record["publication"], "offline_only")
                self.assertEqual(record["assessment_scope"], "assessed" if own_execution else "historical")
                self.assertEqual(record["finding_execution_id"], execution_id)
                self.assertEqual(record["finding_ref"]["execution_id"], execution_id)
                self.assertEqual(snapshot_files(source), before)
                if not own_execution:
                    self.context["options"]["track_findings"] = ["F-999"]
                    with self.assertRaisesRegex(ValueError, "admitted execution binding"):
                        actions.tracking_records(self.context)
                    self.context["options"]["track_findings"] = ["F-001"]

    def test_initializer_rejects_unaccepted_selections_before_patch_work(self):
        import advantage_lifecycle as lifecycle
        from advantage_native_fixture import native_controller
        source = self.root / "scans/repo/completed"
        manifest = self._source_manifest(source)
        write_json(self.source / "final-verification/findings.json", {"run_id": "audit", "findings": []})
        write_json(self.source / "report/security-report.json", {
            "run_id": "audit", "summary": {}, "findings": [],
            "publication": {"execution_kind": "audit", "repository": "repo",
                            "repositories": manifest["repositories"], "model_routing": {}, "producer_routes": {}}})
        (self.source / "report/security-report.md").write_text("# Synthetic completed audit\n")
        inventory = {"source_root": str(self.repo), "revision": "fixture", "repositories": manifest["repositories"]}
        args = lifecycle.parser_for("init").parse_args([
            str(self.source), "--source-root", str(self.repo), "--mode", "actions",
            "--action-source", str(source), "--verify-fix", "F-001", "--patch", str(self.patch_file)])
        # Audit admission and checkout enumeration are separate prerequisites;
        # selection admission and its ordering relative to patch work stay real.
        with patch.object(lifecycle, "validate_source_audit"), \
                patch.object(lifecycle, "current_inventory", return_value=inventory), \
                patch.dict(os.environ, {"VULNOPS_RUNTIME_ROOT": str(self.root / "runtime"),
                                       "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID": "fixture-action-admission",
                                       "VULNOPS_LAUNCHER_PID": str(os.getpid())}), \
                native_controller("fixture-action-admission"), \
                patch.object(actions, "prepare_patch", side_effect=AssertionError("premature patch work")) as prepare:
            for label, document, reason in (
                ("empty", {"findings": []}, "not accepted"),
                ("rejection_only", {"findings": [], "rejections": [{"id": "F-001"}]}, "not accepted"),
                ("rejected", {"findings": [{**accepted_finding(), "verdict": "rejected"}]}, "not accepted"),
                ("malformed", None, "cannot read final-verification/findings.json"),
            ):
                with self.subTest(authority=label):
                    path = source / "final-verification/findings.json"
                    if document is None:
                        path.write_text("{")
                    else:
                        write_json(path, document)
                    before = snapshot_files(source)
                    with self.assertRaisesRegex(ValueError, reason):
                        lifecycle.initialize(args)
                    prepare.assert_not_called()
                    self.assertEqual(snapshot_files(source), before)
                    self.assertFalse(actions.derived_root(self.context).exists())

    def test_admitted_tracking_preserves_historical_scope_without_optional_support(self):
        self.context["mode"] = "actions"
        self.context["options"].update(patch=None, track_findings=["F-001"])
        source = self.root / "scans/repo/completed"
        finding = accepted_finding()
        finding["assessment_context"] = {"attempt_id": "producer"}
        finding["evidence_refs"] = ["investigation/absent.json"]
        self._source_manifest(source)
        write_json(source / "final-verification/findings.json", {"run_id": "completed", "findings": [finding]})
        self.context["action_source"] = baseline.admit_action_source(source, self.context)
        self.assertEqual({row["artifact_ref"] for row in self.context["action_source"]["files"]},
                         {"final-verification/findings.json", "report/security-report.json", "report/security-report.md"})
        self.assertFalse((source / "investigation/absent.json").exists())
        before = snapshot_files(source)
        record = actions.tracking_records(self.context)[0]
        self.assertEqual((record["finding_id"], record["finding_execution_id"], record["assessment_scope"]),
                         ("F-001", "completed", "historical"))
        self.assertEqual(record["title"], finding["title"])
        self.assertEqual(snapshot_files(source), before)

    def test_owner_rejects_wrong_inactive_and_actions_investigation_claims(self):
        from advantage_native_fixture import native_call
        self.context.update(mode="actions", launcher_session_id="fixture-action-owner",
                            input_path=str(self.root / "owner-input.json"))
        self.context["options"]["verify_fix"] = ["F-001"]
        write_json(Path(self.context["input_path"]), self.context)
        with native_call(self.context, "handoff"):
            owners.owner(self.context, "handoff", "AdvantageHandoff", "F-001")
            with self.assertRaises(ValueError):
                owners.owner(self.context, "handoff", "other", "F-001")
        with native_call(self.context, "investigation"):
            with self.assertRaisesRegex(ValueError, "require ordinary investigation or selected action handoff"):
                owners.owner(self.context, "investigation", "task", "question")
        with native_call(self.context, "planning"):
            with self.assertRaisesRegex(ValueError, "does not own"):
                owners.owner(self.context, "handoff", "AdvantageHandoff", "F-001")
        with patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": ""}):
            with self.assertRaisesRegex(ValueError, "live native runtime"):
                owners.owner(self.context, "handoff", "AdvantageHandoff", "F-001")

    def experiment_fixture(self, mode="off"):
        self.context["mode"] = "actions"
        self.context["reproduction_mode"] = mode
        self.context["options"].update(patch=None, verify_fix=["F-001"])
        request = {
            "schema_version": "2.0", "execution_kind": "advantage", "run_id": "advantage",
            "experiment_id": "bounded-check", "owner_phase": "handoff", "owner_id": "AdvantageHandoff",
            "owner_ref": "handoff/action-draft.json", "question_id": "F-001", "source_view": "base",
            "baseline_execution_id": "audit", "attempt_id": self.context["attempt_id"],
            "obligation": "Determine the isolated branch response.", "static_limitation": "Runtime dispatch is unknown.",
            "behavior": "Return the declared observation code.", "supports": "Declared support code.",
            "contradicts": "Declared contradiction code.", "input_refs": [], "dependencies": [],
            "execution_policy": "safe_offline_disposable", "interpretation_boundary": experiments.BOUNDARY,
            "command": ["python3", "app.py"], "support_exit_code": 0, "contradict_exit_code": 1,
        }
        context_path = self.root / "context.json"
        request_path = self.scan / "handoff/experiments/bounded-check/request.json"
        self.context.update(input_path=str(context_path), launcher_session_id="fixture-contained-action")
        write_json(context_path, self.context)
        write_json(request_path, request)
        write_json(self.scan / "handoff/action-draft.json", {})
        from advantage_native_fixture import native_call
        call = self.enterContext(native_call(self.context, "handoff"))
        call["operation"] = {
            "id": "fixture-native-experiment", "kind": "experiment", "phase": "handoff",
            "owner_id": "AdvantageHandoff", "question_id": "F-001",
            "request_ref": request_path.relative_to(self.scan).as_posix(),
            "request_sha256": contract.sha256_file(request_path),
            "timeout_seconds": self.context["experiment_budget"]["timeout_seconds"],
        }
        self.enterContext(patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": json.dumps(call)}))
        # This focused containment fixture supplies a minimal immutable input;
        # initializer/schema authorization is exercised by the lifecycle suite.
        self.enterContext(patch.object(contract, "load_context", return_value=self.context))
        (self.root / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
        (self.root / "schemas").symlink_to(ROOT / "schemas", target_is_directory=True)
        return context_path, request_path

    def test_off_mode_never_invokes_containment_or_target(self):
        context_path, request_path = self.experiment_fixture()
        with patch.object(experiments, "ROOT", self.root), patch.object(owners, "validate_experiment"), patch.object(experiments, "subprocess", self.backend):
            result_path = experiments.run(context_path, request_path)
            self.assertEqual(json.loads(result_path.read_text())["status"], "disabled")
            self.backend.run.assert_not_called()

    def test_exhausted_current_invocation_allowance_never_invokes_target(self):
        self.context["experiment_budget"]["max_experiments"] = 0
        context_path, request_path = self.experiment_fixture("safe")
        with patch.object(experiments, "ROOT", self.root), patch.object(owners, "validate_experiment"), patch.object(experiments, "subprocess", self.backend):
            result_path = experiments.run(context_path, request_path)
            self.assertEqual(json.loads(result_path.read_text())["status"], "budget_deferred")
            self.backend.run.assert_not_called()

    def test_unavailable_containment_only_probes_never_prepares_or_executes(self):
        context_path, request_path = self.experiment_fixture("safe")
        abandoned = self.root / "work/abandoned/experiments/experiment-attempts.json"
        abandoned.parent.mkdir(parents=True)
        abandoned.write_text("corrupt abandoned reservations are not current authority")
        with patch.object(experiments, "ROOT", self.root), patch.object(owners, "validate_experiment"), patch.object(experiments, "subprocess", self.backend):
            result_path = experiments.run(context_path, request_path)
            self.assertEqual(json.loads(result_path.read_text())["status"], "containment_unavailable")
            self.assertEqual(self.backend.run.call_count, 1)
            self.assertEqual(self.backend.run.call_args.args[0][-1], "detect")
            self.assertEqual(abandoned.read_text(), "corrupt abandoned reservations are not current authority")
            self.assertFalse((self.root / "work/advantage/experiments/experiment-attempts.json").exists())

    def test_historical_artifact_resolution_ignores_old_hashes_but_rejects_foreign_paths(self):
        source_file = self.source / "final-verification/findings.json"
        write_json(source_file, {"findings": [{"id": "F-001", "verdict": "confirmed"}]})
        reference = {"execution_id": "audit", "artifact_ref": "final-verification/findings.json", "sha256": "0" * 64}
        contract.resolve_reference(self.context, reference, "artifact")
        for change in ({"execution_id": "unadmitted"}, {"artifact_ref": "../audit/final-verification/findings.json"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                contract.resolve_reference(self.context, {**reference, **change}, "artifact")
        write_json(source_file, {"findings": []})
        self.assertEqual(contract.resolve_reference(self.context, reference, "artifact"), {"findings": []})

    def test_graph_receipt_requires_owned_packet_and_canonical_path(self):
        from codegraph_contract import validate_linked_receipt
        from test_advantage_pipeline import authored_plan, pipeline
        manifest = self._source_manifest(self.scan, self.context["run_id"])
        self.context.update(mode="standard", network=manifest["network"], model_routing=manifest["model_routing"])
        plan = authored_plan(self.context, source="app.py:1")
        question = {"id": "GRAPH-001", "type": "query", "subject": "allowed",
                    "reason": "Locate the inspected control."}
        task = plan["assignments"][0]
        task["graph_questions"] = [question]
        packet = pipeline.packet(self.context, plan, task)
        write_json(self.scan / "investigation/packets/TASK-001.json", packet)
        reference = "investigation/codegraph-runs/TASK-001/GRAPH-001/receipt.json"
        directory = self.scan / Path(reference).parent
        binding = {"run_id": self.context["run_id"], "execution_kind": "advantage",
                   "baseline_execution_id": "audit", "attempt_id": self.context["attempt_id"],
                   "phase": "investigation", "owner_id": "TASK-001", "question_id": "GRAPH-001",
                   "operation": "query", "subject": "allowed", "file": None}
        completeness = {"local_truncated": False, "dropped_nodes": 0, "dropped_edges": 0,
                        "upstream_truncated": False, "upstream_complete": True, "heuristic": False}
        document = {"schema_version": "2.0", "tool": "codegraph", "operation": "query", "subject": "allowed",
                    "binding": binding, "completeness": completeness, "meaningful": True, "edges": [],
                    "nodes": [{"id": "control", "role": "result", "synthetic": False, "file": "app.py", "line": 1}]}
        write_json(directory / "context.json", document)
        receipt = {"schema_version": "2.0", "tool": "codegraph", "operation": "query", "status": "ok",
                   "version": "authored-fixture", "started_at": "fixture", "completed_at": "fixture",
                   "parse_status": "ok", "result_count": 1, "warnings": [], "meaningful": True,
                   "elapsed_seconds": 0,
                   "binding": binding, "completeness": completeness,
                   "normalized_sha256": contract.sha256_file(directory / "context.json")}
        write_json(directory / "receipt.json", receipt)
        accepted = validate_linked_receipt(self.context, reference)
        self.assertEqual(accepted["assessment_scope"], "current")
        self.assertEqual(accepted["nodes"], document["nodes"])
        for path, reason in (
            ("../receipt.json", "canonical and relative"),
            (reference.replace("receipt.json", "not-receipt.json"), "no canonical owner"),
        ):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, reason):
                validate_linked_receipt(self.context, path)
        with self.subTest(owner="foreign packet"):
            packet["assignment"]["task_id"] = "TASK-OTHER"
            write_json(self.scan / "investigation/packets/TASK-001.json", packet)
            with self.assertRaisesRegex(ValueError, "another execution or task"):
                validate_linked_receipt(self.context, reference)
            packet["assignment"]["task_id"] = "TASK-001"
            write_json(self.scan / "investigation/packets/TASK-001.json", packet)
        with self.subTest(owner="foreign receipt"):
            receipt["binding"] = {**binding, "owner_id": "TASK-OTHER"}
            write_json(directory / "receipt.json", receipt)
            with self.assertRaisesRegex(ValueError, "bind different requests"):
                validate_linked_receipt(self.context, reference)
        write_json(directory / "receipt.json", {**receipt, "binding": binding})
        self.assertEqual(validate_linked_receipt(self.context, reference), accepted)

    def test_remediation_rejects_ambiguous_source_and_derived_or_multi_repo(self):
        write_json(self.source / "run-manifest.json", {})
        write_json(self.source / "advantage-manifest.json", {})
        with self.assertRaisesRegex(ValueError, "exactly one"):
            remediation.legacy_source_manifest(self.source)
        metadata = {"execution_kind": "advantage", "repository": "fixture", "mode": "standard",
                    "repositories": [{"path": "."}], "model_routing": {}, "producer_routes": {}}
        report = {"run_id": self.context["run_id"], "counts": {}, "findings": [{"id": "F-001"}],
                  "publication": metadata}
        write_json(self.scan / "final-verification/findings.json", {"findings": report["findings"],
            "links": [{"finding_id": "F-001", "source_view": "derived"}]})
        write_json(self.scan / "report/security-report.json", report)
        (self.scan / "report/security-report.md").write_text("# Completed assessment\n")
        with patch.object(contract, "context_for_base", return_value=self.context):
            with self.assertRaisesRegex(ValueError, "derived-patch"):
                remediation.validate_advantage_source(self.scan, self.repo)
            metadata["repositories"] = [{"path": "one"}, {"path": "two"}]
            write_json(self.scan / "report/security-report.json", report)
            with self.assertRaisesRegex(ValueError, "single-repository"):
                remediation.validate_advantage_source(self.scan, self.repo)


if __name__ == "__main__":
    unittest.main()
