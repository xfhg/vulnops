"""Real initialization and publication over disposable accepted multi-repo evidence."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_lifecycle import assessment_ref, AUDIT_PHASE_DIRS, AUDIT_TASK_PHASES
from model_identity import diversity_summary
from dossier_contract import objective_assessments
from advantage_baseline import build_catalog, effective_findings
from test_dossiers import sample_finding, seed_objective, review_dossier


def exercise_resume(base: Path) -> dict:
    base = base.resolve()
    harness = base / "harness"
    source = base / "source"
    scan = harness / "scans" / "fixture"
    harness.mkdir(); source.mkdir()
    config = (ROOT / "config.toml.example").read_text()
    config = config.replace("[harness.scans.gap_exploration]\nenabled = true",
                            "[harness.scans.gap_exploration]\nenabled = false")
    (harness / "config.toml").write_text(config)
    context_path = base / "context.json"
    env = {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path),
           "VULNOPS_RUNTIME_ROOT": str(base / "runtime"),
           "VULNOPS_LAUNCHER_PID": str(os.getpid()), "VULNOPS_LAUNCHER_SESSION_ID": "assessment-smoke"}

    def save(relative, value):
        path = scan / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def command(script, *args):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, args)],
                                env=env, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(f"{script}: {result.stderr}")
        return result.stdout

    repositories = []
    for index in range(31):
        name = f"component-{index:02d}"
        (source / name).mkdir()
        repositories.append({"name": name, "path": name, "remote_url": "local", "commit": f"reviewed-{index}"})
    inventory = {"source_root": str(source), "application_name": "fixture", "application_id": "fixture",
                 "revision": "reviewed", "remote_url": "local", "repositories": repositories}
    inventory_path = base / "inventory.json"
    inventory_path.write_text(json.dumps(inventory))
    arguments = ["--harness-root", harness, "--repo-path", source, "--scan-base", scan,
                 "--run-id", "fixture", "--repo-name", "fixture", "--remote-url", "local", "--repo-id", "fixture",
                 "--commit", "reviewed", "--depth", "balanced", "--reproduction-mode", "off",
                 "--codegraph-mode", "disabled", "--network-mode", "policy_only", "--repositories-file", inventory_path]
    command("init-run.py", *arguments)
    original = json.loads(context_path.read_text())
    manifest = json.loads((scan / "run-manifest.json").read_text())
    source_ref = "component-00/source.py:1-2"
    code = source / "component-00/source.py"
    code.write_text("def lookup(record_id):\n    return records[record_id]\n")
    seed_objective(scan, source_ref)
    # Predecessor content is authored fixture evidence, not native research.
    # Admit it through the same state transitions used by a real publisher.
    tasks = {phase: task for task, phase in AUDIT_TASK_PHASES.items()}

    def begin(phase):
        command("update-run-state.py", scan, "--phase", phase, "--phase-status", "running",
                "--task", tasks[phase], "--task-phase", phase, "--increment-attempt")

    def accept(phase, artifact):
        phase_manifest = f"{AUDIT_PHASE_DIRS[phase]}/phase-manifest.json"
        if not (scan / phase_manifest).exists():
            save(phase_manifest, {"phase": phase, "status": "ok"})
        command("update-run-state.py", scan, "--phase", phase, "--phase-manifest", phase_manifest,
                "--task", tasks[phase], "--task-phase", phase, "--artifact", artifact)

    for phase in AUDIT_PHASE_DIRS:
        if phase in {"gap-exploration", "synthesis", "final-verification", "report"}:
            continue
        artifact = f"{AUDIT_PHASE_DIRS[phase]}/accepted-fixture.json"
        save(artifact, {"fixture": True})
        begin(phase)
        accept(phase, artifact)
    begin("gap-exploration")
    command("finalize-gap-exploration.py", "--context", context_path)
    command("update-run-state.py", scan, "--phase", "gap-exploration",
            "--phase-manifest", scan / "gap-exploration/phase-manifest.json",
            "--task", "GapExploration", "--task-phase", "gap-exploration",
            "--artifact", "gap-exploration/results.json")
    manifest = json.loads((scan / "run-manifest.json").read_text())

    def qualify(value):
        if isinstance(value, dict):
            return {key: qualify(item) for key, item in value.items()}
        if isinstance(value, list):
            return [qualify(item) for item in value]
        return value.replace("source.py", "component-00/source.py") if isinstance(value, str) else value
    findings, reviews = [], {}
    for index in range(24):
        finding = qualify(sample_finding())
        finding["affected_components"][0]["repository"] = "component-00"
        finding["id"] = f"F-{index + 1:03d}"
        finding["severity"] = "high" if index < 9 else "medium" if index < 21 else "low"
        finding["verification"]["model"] = original["model_routing"]["agents"]["vulnops-synthesis"]
        finding["contributors"][0]["selector"] = original["model_routing"]["agents"]["vulnops-deepdive-chunk"]
        finding.update(verdict="confirmed", model_diversity=False,
                       independent_verification_ref=f"final-verification/results/{finding['id']}.json",
                       assessment_context=assessment_ref(original))
        status = "verified"
        if index >= 22:
            status = "needs_environment"
            finding.update(status=status, verdict=status)
            finding["verification"]["level"] = "environment_required"
        review = review_dossier(finding, {
            "schema_version": "2.0", "finding_id": finding["id"], "status": status,
            "closure_reason": finding["closure_rationale"], "evidence_refs": [source_ref],
            "primitive_results": [], "transition_results": [], "corrections": [], "corrected_finding": None,
            "actor": "vulnops-independent-verify-one",
            "model": original["model_routing"]["agents"]["vulnops-independent-verify-one"],
            "model_diversity": False, "assessment_context": assessment_ref(original),
            "joint_conditions": {"outcome": "established" if index < 22 else "externally_blocked",
                "reason": "Synthetic accepted scope", "evidence_refs": [source_ref],
                "missing_fact": "" if index < 22 else "Deployment binding", "next_action": "" if index < 22 else "Review deployment"}})
        findings.append(finding); reviews[finding["id"]] = review
        save(finding["independent_verification_ref"], review)
    save("sast/verified-findings.json", [{"id": "C-001"}])
    save("sast/deepdive/task.json", {"provenance": findings[0]["contributors"][0]})
    final = {"schema_version": "2.0", "run_id": "fixture", "findings": findings, "rejections": [],
             "non_promoted": [], "assessment_context": assessment_ref(original),
             "verifier_model": original["verifier_model"], **diversity_summary(findings),
             "objective_assessments": objective_assessments(scan, findings, results=reviews)}
    save("final-verification/findings.json", final)
    save("synthesis/findings.json", {"schema_version": "2.0", "run_id": "fixture", "findings": findings})
    for phase in ("synthesis", "final-verification"):
        begin(phase)
        accept(phase, f"{AUDIT_PHASE_DIRS[phase]}/findings.json")
    evidence = {path: path.read_bytes() for directory in ("sast", "final-verification")
                for path in (scan / directory).rglob("*") if path.is_file()}
    inventory["repositories"] = [{**row, "commit": "unreviewed"} for row in repositories]
    inventory_path.write_text(json.dumps(inventory))
    code.unlink()
    (harness / "config.toml").write_text(re.sub(r'(?m)^final_verification\s*=.*$',
        'final_verification = "fixture/new-reviewer:high"', config))
    command("init-run.py", *arguments, "--resume")
    resumed = json.loads(context_path.read_text())
    assert resumed["attempt_id"] != original["attempt_id"]
    assert resumed["assessment_id"] is None
    begin("report")
    command("render-report.py", scan)
    report = json.loads((scan / "report/security-report.json").read_text())
    assert report["findings"] == findings
    assert report["summary"]["confirmed"] == 22
    assert report["summary"]["needs_environment"] == 2
    assert [report["summary"][key] for key in ("high", "medium", "low")] == [9, 12, 1]
    assert report["repositories"] == repositories
    assert report["verifier_model"] == original["verifier_model"]
    assert report["assessment"]["retained"]
    assert all(path.read_bytes() == data for path, data in evidence.items())
    accept("report", "report/security-report.json")
    command("update-run-state.py", scan, "--run-status", "complete")
    before = {path: path.read_bytes() for path in scan.rglob("*") if path.is_file()}
    catalog = build_catalog({"run_id": "advantage-fixture", "source_run_id": "fixture"}, scan)
    accepted = effective_findings(scan, expected_execution_id="fixture")
    assert len(accepted) == 24
    assert sum(row["verdict"] == "confirmed" for row in accepted.values()) == 22
    assert all(path.read_bytes() == data for path, data in before.items())
    markdown = (scan / "report/security-report.md").read_text()
    anchors = set(re.findall(r'<a id="([^"]+)"', markdown))
    local_links = re.findall(r'\]\(#([^)]+)\)', markdown)
    assert local_links and set(local_links) <= anchors
    # Standalone intake/publication with trusted synthetic native-call fixtures.
    # This exercises deterministic empty products, not native model execution.
    from unittest.mock import patch
    from test_advantage_lifecycle import empty_linked_execution
    from advantage_native_fixture import native_call, native_controller
    from advantage_lifecycle import cleanup
    for arguments in (("init", "-q"), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                      "commit", "--allow-empty", "-qm", "synthetic source")):
        subprocess.run(["git", "-C", str(source), *arguments], check=True, capture_output=True)
    env.update(VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID="assessment-smoke")
    linked_reports = []
    with patch.dict(os.environ, env):
        for mode in ("standard", "deep"):
            with native_controller("assessment-smoke"):
                env["VULNOPS_ADVANTAGE_CALL"] = os.environ["VULNOPS_ADVANTAGE_CALL"]
                abandoned = json.loads(command("init-advantage.py", scan, "--source-root", source, "--mode", mode))
            abandoned_base = empty_linked_execution(abandoned, stop_before_report=True)
            abandoned_bytes = {path: path.read_bytes() for path in abandoned_base.rglob("*") if path.is_file()}
            with native_controller("assessment-smoke"):
                env["VULNOPS_ADVANTAGE_CALL"] = os.environ["VULNOPS_ADVANTAGE_CALL"]
                linked = json.loads(command("init-advantage.py", scan, "--source-root", source, "--mode", mode))
            assert linked["run_id"] != abandoned["run_id"]
            assert linked["attempt_id"] != abandoned["attempt_id"]
            assert linked["assessment_id"] and linked["assessment_id"] != abandoned["assessment_id"]
            assert linked["input_path"] != abandoned["input_path"]
            linked_base = empty_linked_execution(linked, stop_before_report=True)
            with native_call(linked, "report"):
                env["VULNOPS_ADVANTAGE_CALL"] = os.environ["VULNOPS_ADVANTAGE_CALL"]
                command("render-advantage-report.py", "--context", linked["input_path"])
                cleanup(linked)
            assert all(path.read_bytes() == data for path, data in abandoned_bytes.items())
            assert not (abandoned_base / "report/security-report.json").exists()
            assert not Path(linked["input_path"]).exists()
            linked_report = json.loads((linked_base / "report/security-report.json").read_text())
            assert linked_report["counts"]["assessed_confirmed"] == 0
            assert sum(linked_report["counts"][key] for key in ("new_roots", "new_chains", "impact_expansions")) == 0
            assert len(linked_report["historical_findings"]) == 24
            command("advantage-status.py", linked_base)
            linked_reports.append(str(linked_base / "report/security-report.md"))
    assert all(path.read_bytes() == data for path, data in before.items())
    return {"repositories": len(report["repositories"]), "confirmed": report["summary"]["confirmed"],
            "environment_required": report["summary"]["needs_environment"], "baseline_findings": len(accepted),
            "baseline_records": catalog["record_count"], "step_repair_links": len(local_links),
            "report": str(scan / "report/security-report.md"), "scan": str(scan), "context": str(context_path),
            "advantage_reports": linked_reports}


class AssessmentContinuationTests(unittest.TestCase):
    def test_init_resume_keeps_assessed_results_and_advantage_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            result = exercise_resume(Path(directory))
            self.assertEqual(result["repositories"], 31)
            self.assertEqual(result["baseline_findings"], 24)


if __name__ == "__main__":
    unittest.main()
