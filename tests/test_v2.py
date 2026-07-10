from __future__ import annotations

import hashlib
import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PYTHON = shutil.which("python3") or "python3"


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, check=False)


def candidate() -> dict:
    return {
        "schema_version": "2.0",
        "id": "C-001",
        "task_id": "H001",
        "cell_ids": ["CELL-1"],
        "finding_kind": "code",
        "title": "Untrusted value reaches privileged sink",
        "category": "injection",
        "attack_class_id": "injection",
        "domain": "general",
        "methodology_refs": ["skill://vulnops-attack-general#injection"],
        "severity": "high",
        "confidence": "high",
        "attacker": {"perspective": "remote caller", "starting_access": "anonymous", "boundary_crossed": "request to service process"},
        "intended_behavior": "Reject unsafe values before the sink.",
        "root_cause": "sink in app.py does not validate value, allowing privileged execution",
        "root_cause_location": {"file": "app.py", "line": 4, "scope": "sink", "mechanism": "unvalidated privileged operation"},
        "trace": [
            {"kind": "entrypoint", "file": "app.py", "line": 1, "scope": "entry", "description": "Accepts caller value."},
            {"kind": "sink", "file": "app.py", "line": 4, "scope": "sink", "description": "Uses the value."},
        ],
        "conditions": [],
        "impact": "The caller crosses the process trust boundary.",
        "remediation": "Validate the value at the boundary.",
        "evidence_refs": ["app.py:1", "app.py:4"],
        "lenses": ["vulnops-audit-core"],
        "mitigations_checked": ["No upstream allow-list exists."],
    }


def full_finding() -> dict:
    item = candidate()
    return {
        "id": "F-001",
        "verdict": "confirmed",
        "finding_kind": "code",
        "title": item["title"],
        "category": item["category"],
        "attack_class_ids": [item["attack_class_id"]],
        "methodology_refs": item["methodology_refs"],
        "lenses": item["lenses"],
        "description": item["impact"],
        "root_cause": item["root_cause"],
        "root_cause_location": item["root_cause_location"],
        "intended_behavior": item["intended_behavior"],
        "attacker": item["attacker"],
        "trace": item["trace"],
        "conditions": item["conditions"],
        "verification": {
            "level": "source_verified",
            "source_validation_ref": "sast/verify/C-001.json",
            "reproduction_ref": None,
            "reproduction_status": "not_requested",
            "model": "test-model",
            "model_diversity": False,
        },
        "remediation": {"strategy": item["remediation"], "test_ref": None, "patch_ref": None, "patch_status": "not_generated"},
        "severity": {
            "likelihood": {"score": "high", "reason": "Directly reachable."},
            "impact": {"score": "high", "reason": item["impact"]},
            "overall": "high",
        },
        "confidence": {"score": "high", "reason": "The full path was independently read."},
        "provenance": {
            "source_ids": ["C-001"],
            "raw_refs": ["sast/raw-findings.json:C-001"],
            "intelligence_refs": ["I-001"],
            "graph_refs": ["intrusion/context.json#edge-1"],
            "validation_refs": ["sast/verify/C-001.json"],
            "independent_verification_ref": "final-verification/results/F-001.json",
        },
        "closure_reason": "All source claims were independently verified.",
        "dependency": None,
        "secret": None,
    }


class V2ContractTests(unittest.TestCase):
    def phase_manifest(self, phase: str, status: str = "ok") -> dict:
        return {
            "phase": phase, "status": status, "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z", "inputs": [], "outputs": [],
            "coverage": {}, "tool_versions": {}, "warnings": [], "errors": [],
        }

    def make_sast_fixture(self, base: Path, candidates: list[dict]) -> tuple[Path, Path, Path]:
        target = base / "target"
        scan = base / "scan"
        (scan / "sast/deepdive").mkdir(parents=True)
        target.mkdir()
        (target / "app.py").write_text("def entry(value):\n    return sink(value)\n\ndef sink(value):\n    return value\n")
        plan = {
            "schema_version": "2.0", "run_id": "run", "rationale": "fixture",
            "budget": {"max_concurrency": 1, "max_hunt_tasks": 4, "max_gapfill_rounds": 1, "max_attempts": 2, "context_packet_bytes": 65536},
            "custom_attack_classes": [],
            "cells": [{
                "id": "CELL-1", "surface_id": "surface", "subsystem": "api", "attack_class_id": "injection",
                "domain": "general", "status": "planned", "priority": "high", "evidence_refs": ["app.py:1"],
                "owner": "sast", "lead_key": None, "disposition_reason": "fixture",
            }],
            "tasks": [{
                "id": "H001", "cell_ids": ["CELL-1"], "subsystem": "api", "attack_class_id": "injection",
                "domain": "general", "methodology_refs": ["skill://vulnops-attack-general#injection"], "lenses": [],
                "files": ["app.py"], "entrypoints": ["app.py:1"], "context_packet": "{}",
                "evidence_refs": ["app.py:1"], "attempt": 1, "round": 0,
            }],
            "warnings": [], "errors": [],
        }
        (scan / "sast/hunt-plan.json").write_text(json.dumps(plan))
        result = {
            "schema_version": "2.0", "task_id": "H001", "status": "ok", "files_reviewed": ["app.py"],
            "entrypoints_traced": ["app.py:1"], "sinks_reviewed": ["app.py:4"],
            "mitigations_checked": ["No allow-list."], "candidates": candidates,
            "hardening_notes": [], "positive_patterns": [], "rabbit_holes": [], "wishlist_items": [],
            "warnings": [], "errors": [],
        }
        (scan / "sast/deepdive/H001.json").write_text(json.dumps(result))
        context = base / "context.json"
        context.write_text(json.dumps({"run_id": "run", "reproduction_mode": "off", "model": "test-model"}))
        return target, scan, context

    def test_candidate_schema_and_trace_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "target"
            target.mkdir()
            (target / "app.py").write_text("def entry(value):\n    return sink(value)\n\ndef sink(value):\n    return value\n")
            document = base / "candidate.json"
            document.write_text(json.dumps(candidate()))
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/candidate-finding.schema.json", str(document), "--semantic", "candidate", "--target", str(target))
            self.assertEqual(result.returncode, 0, result.stderr)

            invalid = candidate()
            invalid["unexpected"] = True
            document.write_text(json.dumps(invalid))
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/candidate-finding.schema.json", str(document))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected field", result.stderr)

            invalid = candidate()
            invalid["id"] = "../escape"
            document.write_text(json.dumps(invalid))
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/candidate-finding.schema.json", str(document))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pattern", result.stderr)

    def test_final_schema_and_trace_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "target"
            target.mkdir()
            (target / "app.py").write_text("def entry(value):\n    return sink(value)\n\ndef sink(value):\n    return value\n")
            document = base / "findings.json"
            wrapper = {"schema_version": "2.0", "run_id": "run", "model_diversity": False, "findings": [full_finding()]}
            document.write_text(json.dumps(wrapper))
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/final-findings.schema.json", str(document), "--semantic", "final-findings", "--target", str(target))
            self.assertEqual(result.returncode, 0, result.stderr)

            wrapper["findings"][0]["trace"][0]["kind"] = "sink"
            document.write_text(json.dumps(wrapper))
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/final-findings.schema.json", str(document), "--semantic", "final-findings", "--target", str(target))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("entrypoint", result.stderr)

    def test_hunt_plan_routes_tool_owned_cells_without_sast_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scan = base / "scan"
            (scan / "sast").mkdir(parents=True)
            for phase in ("sca", "secrets"):
                (scan / phase).mkdir()
                (scan / phase / "phase-manifest.json").write_text(json.dumps({"status": "ok"}))
                (scan / phase / "summary.md").write_text("ok")
            context = base / "context.json"
            context.write_text(json.dumps({"run_id": "run", "depth": "quick"}))
            threat = {
                "repository_profile": {"kinds": ["backend"], "tags": [], "comparable": {"name": None, "basis": "fixture", "confidence": "not_applicable"}},
                "trust_boundaries": [], "entrypoints": [],
                "subsystems": [{"id": "api", "name": "API", "files": ["app.py"], "entrypoints": ["app.py:1"], "security_surface_ids": ["api-entry"], "risk": "high", "evidence_refs": ["app.py:1"]}],
                "attack_classes": [
                    {"id": "injection", "title": "Injection", "domain": "general", "owner": "sast", "methodology_ref": "skill://vulnops-attack-general", "applicable_subsystems": ["api"], "reason": "input reaches sink", "evidence_refs": ["app.py:1"], "custom": False},
                    {"id": "known_dependencies", "title": "Dependencies", "domain": "general", "owner": "sca", "methodology_ref": "config/agents/sca.md", "applicable_subsystems": ["api"], "reason": "lockfile", "evidence_refs": ["requirements.txt"], "custom": False},
                    {"id": "secret_enumeration", "title": "Secrets", "domain": "general", "owner": "secrets", "methodology_ref": "config/agents/secrets.md", "applicable_subsystems": ["api"], "reason": "config", "evidence_refs": ["app.py"], "custom": False},
                ],
            }
            (scan / "sast/threat-model.json").write_text(json.dumps(threat))
            result = run(PYTHON, "scripts/build-hunt-plan.py", str(base), str(scan), "--context", str(context))
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(len(plan["tasks"]), 1)
            self.assertEqual(plan["tasks"][0]["attack_class_id"], "injection")
            tool_cells = [cell for cell in plan["cells"] if cell["owner"] in {"sca", "secrets"}]
            self.assertTrue(tool_cells)
            self.assertTrue(all(cell["status"] == "tool_satisfied" for cell in tool_cells))

    def test_gapfill_spends_reserved_budget_and_allows_distinct_same_cell_lead(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scan = base / "scan"
            (scan / "sast/deepdive").mkdir(parents=True)
            (base / "app.py").write_text("def entry(value):\n    return value\n")
            context = base / "context.json"
            context.write_text(json.dumps({"run_id": "run", "depth": "quick"}))
            threat = {
                "subsystems": [{"id": "api", "name": "API", "files": ["app.py"], "entrypoints": ["app.py:1"], "security_surface_ids": ["surface"], "risk": "high", "evidence_refs": ["app.py:1"]}],
                "attack_classes": [
                    {"id": "injection", "title": "Injection", "domain": "general", "owner": "sast", "methodology_ref": "skill://vulnops-attack-general#injection", "applicable_subsystems": ["api"], "reason": "input", "evidence_refs": ["app.py:1"], "custom": False},
                    {"id": "business_logic", "title": "Logic", "domain": "general", "owner": "sast", "methodology_ref": "skill://vulnops-attack-general#business-logic", "applicable_subsystems": ["api"], "reason": "state", "evidence_refs": ["app.py:1"], "custom": False},
                ],
                "repository_profile": {}, "trust_boundaries": [], "entrypoints": [],
            }
            (scan / "sast/threat-model.json").write_text(json.dumps(threat))
            env = os.environ.copy()
            env.update({"VULNOPS_SAST_QUICK_MAX_HUNT_TASKS": "2", "VULNOPS_SAST_QUICK_MAX_GAPFILL_ROUNDS": "1", "VULNOPS_SAST_QUICK_MAX_ATTEMPTS": "2"})
            result = run(PYTHON, "scripts/build-hunt-plan.py", str(base), str(scan), "--context", str(context), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(len(plan["tasks"]), 1)
            self.assertEqual(sum(cell["status"] == "deferred" for cell in plan["cells"]), 1)
            (scan / "sast/coverage-ledger.json").write_text(json.dumps({"cells": []}))
            result = run(PYTHON, "scripts/build-hunt-plan.py", str(base), str(scan), "--gapfill", "--context", str(context), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(len(plan["tasks"]), 2)
            self.assertFalse(any(cell["status"] == "deferred" for cell in plan["cells"] if cell["owner"] == "sast"))

            # Rebuild with one initial task and one reserved slot, then prove a
            # distinct lead in the same subsystem/class pair is not discarded.
            threat["attack_classes"] = threat["attack_classes"][:1]
            (scan / "sast/threat-model.json").write_text(json.dumps(threat))
            for path in (scan / "sast/deepdive").glob("*.json"):
                path.unlink()
            result = run(PYTHON, "scripts/build-hunt-plan.py", str(base), str(scan), "--context", str(context), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text())
            task_id = plan["tasks"][0]["id"]
            (scan / f"sast/deepdive/{task_id}.json").write_text(json.dumps({
                "rabbit_holes": [{"subsystem": "api", "attack_class_id": "injection", "reason": "second parser path", "files": ["app.py"], "evidence_refs": ["app.py:1"]}],
            }))
            (scan / "sast/coverage-ledger.json").write_text(json.dumps({"cells": [{"id": plan["cells"][0]["id"], "status": "clean"}]}))
            result = run(PYTHON, "scripts/build-hunt-plan.py", str(base), str(scan), "--gapfill", "--context", str(context), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads((scan / "sast/hunt-plan.json").read_text())
            self.assertEqual(len(plan["tasks"]), 2)
            self.assertTrue(any(cell.get("lead_key") for cell in plan["cells"]))

    def test_fingerprint_changes_with_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            path = target / "a.txt"
            path.write_text("one")
            before = run(PYTHON, "scripts/target-fingerprint.py", str(target)).stdout.strip()
            path.write_text("two")
            after = run(PYTHON, "scripts/target-fingerprint.py", str(target)).stdout.strip()
            self.assertNotEqual(before, after)

    def test_redaction_and_size_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "output.txt"
            path.write_text("Authorization: Bearer very-secret-token\npassword=hunter2\n" + "x" * 100)
            result = run(PYTHON, "scripts/redact-output.py", str(path), "80")
            self.assertEqual(result.returncode, 0)
            self.assertNotIn("very-secret-token", result.stdout)
            self.assertNotIn("hunter2", result.stdout)
            self.assertIn("<redacted>", result.stdout)

    def test_dynamic_verification_requires_fail_pass_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document = Path(tmp) / "result.json"
            result_doc = {
                "schema_version": "2.0", "finding_id": "F-001", "status": "dynamic_verified",
                "sandbox": "bubblewrap", "sanitized_summary": "Narrow regression reproduced and fixed.",
                "test_ref": None, "patch_ref": None, "hashes": {},
                "before": {"status": "not_run", "exit_code": None, "output_ref": None},
                "after": {"status": "not_run", "exit_code": None, "output_ref": None},
                "warnings": [], "errors": [],
            }
            document.write_text(json.dumps(result_doc))
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/reproduction-result.schema.json", str(document), "--semantic", "reproduction-result")
            self.assertNotEqual(result.returncode, 0)

            result_doc.update({
                "test_ref": "sast/reproduction/F-001/test.txt",
                "patch_ref": "sast/reproduction/F-001/fix.patch",
                "hashes": {"test_sha256": "a" * 64, "patch_sha256": "b" * 64},
                "before": {"status": "expected_failure", "exit_code": 1, "output_ref": "before.log"},
                "after": {"status": "passed", "exit_code": 0, "output_ref": "after.log"},
            })
            document.write_text(json.dumps(result_doc))
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/reproduction-result.schema.json", str(document), "--semantic", "reproduction-result")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_init_run_escapes_metadata_and_state_syncs_from_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "target/repo"
            scan = base / "scans/repo-id/runs/run-1"
            repo.mkdir(parents=True)
            scan.mkdir(parents=True)
            fingerprint = "a" * 64
            result = run(
                PYTHON, "scripts/init-run.py",
                "--harness-root", str(base), "--repo-path", str(repo), "--scan-base", str(scan),
                "--run-id", "run-1", "--repo-name", 'repo "quoted"', "--remote-url", 'ssh://host/repo"x',
                "--repo-id", "repo-id", "--commit", "abc123", "--depth", "quick",
                "--target-fingerprint", fingerprint, "--reproduction-mode", "off", "--model", "test-model",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            context = json.loads((base / ".harness/audit-context.json").read_text())
            self.assertEqual(context["repo_name"], 'repo "quoted"')
            phase_dir = scan / "repo-context"
            phase_dir.mkdir()
            phase_manifest = phase_dir / "phase-manifest.json"
            phase_manifest.write_text(json.dumps({"phase": "recon", "status": "degraded"}))
            result = run(
                PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "recon",
                "--phase-manifest", "repo-context/phase-manifest.json", "--task", "Recon",
                "--task-phase", "recon", "--artifact", "repo-context/phase-manifest.json",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((scan / "run-manifest.json").read_text())
            ledger = json.loads((scan / "task-ledger.json").read_text())
            self.assertEqual(manifest["phases"]["recon"], "degraded")
            self.assertEqual(ledger["tasks"][0]["status"], "degraded")

    def test_invalid_emitted_candidate_marks_coverage_shallow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            invalid = candidate()
            invalid["unexpected"] = True
            target, scan, _ = self.make_sast_fixture(Path(tmp), [invalid])
            result = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan))
            self.assertEqual(result.returncode, 0, result.stderr)
            ledger = json.loads((scan / "sast/coverage-ledger.json").read_text())
            self.assertEqual(ledger["cells"][0]["status"], "shallow")
            self.assertEqual(ledger["funnel"]["mechanically_rejected"], 1)

    def test_rejected_dedup_preference_advances_and_applies_correction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            preferred = candidate()
            preferred["id"] = "C-HIGH"
            alternate = candidate()
            alternate["id"] = "C-ALT"
            alternate["severity"] = "medium"
            target, scan, context = self.make_sast_fixture(Path(tmp), [preferred, alternate])
            env = os.environ.copy()
            env["VULNOPS_AUDIT_CONTEXT"] = str(context)
            result = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            queue = json.loads((scan / "sast/validation-queue.json").read_text())
            self.assertEqual(len(queue), 1)
            preferred_id = queue[0]["id"]
            raw_candidates = json.loads((scan / "sast/raw-findings.json").read_text())
            alternate_canonical = next(item for item in raw_candidates if item["id"] != preferred_id)
            alternate_id = alternate_canonical["id"]

            mechanical = {"schema": True, "paths": True, "lines": True, "trace_order": True, "target_unchanged": True}
            first = {
                "schema_version": "2.0", "id": f"V-{preferred_id}", "candidate_id": preferred_id, "status": "rejected",
                "confidence": "high", "closure_reason": "Preferred trace is not reachable.", "evidence_refs": ["app.py:1"],
                "corrections": [], "corrected_candidate": None, "mechanical_checks": mechanical, "model": "test-model",
            }
            (scan / "sast/validation-results.json").write_text(json.dumps([first]))
            result = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), "--advance-alternates", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "1")

            corrected = copy.deepcopy(alternate_canonical)
            corrected["severity"] = "low"
            second = {
                "schema_version": "2.0", "id": f"V-{alternate_id}", "candidate_id": alternate_id, "status": "source_verified",
                "confidence": "high", "closure_reason": "Alternate trace is reachable with lower impact.", "evidence_refs": ["app.py:1", "app.py:4"],
                "corrections": [{"field": "severity", "before": "medium", "after": "low", "reason": "Impact is bounded."}],
                "corrected_candidate": corrected, "mechanical_checks": mechanical, "model": "test-model",
            }
            (scan / "sast/validation-results.json").write_text(json.dumps([first, second]))
            result = run(PYTHON, "scripts/finalize-sast.py", str(target), str(scan), "--finalize", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            verified = json.loads((scan / "sast/verified-findings.json").read_text())
            self.assertEqual(len(verified), 1)
            self.assertEqual(verified[0]["id"], alternate_id)
            self.assertEqual(verified[0]["severity"], "low")

    def test_report_renderer_omits_exact_proof_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scan = base / "scan"
            (scan / "final-verification").mkdir(parents=True)
            finding = full_finding()
            finding["description"] = "A request containing `exact-proof-token` reaches the sink with password=hunter2."
            (scan / "final-verification/findings.json").write_text(json.dumps({
                "schema_version": "2.0", "run_id": "run", "model_diversity": False, "findings": [finding],
            }))
            context = base / "context.json"
            context.write_text(json.dumps({
                "run_id": "run", "repo_name": "repo", "short_sha": "abc123", "reproduction_mode": "off",
            }))
            env = os.environ.copy()
            env["VULNOPS_AUDIT_CONTEXT"] = str(context)
            result = run(PYTHON, "scripts/render-report.py", str(scan), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = (scan / "report/security-report.json").read_text()
            self.assertNotIn("exact-proof-token", rendered)
            self.assertNotIn("hunter2", rendered)
            self.assertIn("<technical-token-omitted>", rendered)
            self.assertIn("<redacted>", rendered)

    def test_complete_empty_finding_scan_passes_cross_phase_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "target"
            scan = base / "scan"
            target.mkdir()
            scan.mkdir()
            (target / "app.py").write_text("def entry(value):\n    return value\n")
            fingerprint = run(PYTHON, "scripts/target-fingerprint.py", str(target)).stdout.strip()
            phases = ["recon", "sca", "secrets", "sast", "intelligence", "triage", "intrusion", "final-reconciliation", "final-verification", "report"]
            manifest = {
                "schema_version": "2.0", "run_id": "run", "repo_id": "repo-id", "repository": "repo",
                "commit": "abc123", "depth": "quick", "status": "running", "scan_base": str(scan),
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:01Z",
                "target_fingerprint": fingerprint, "model": "test-model", "model_diversity": False,
                "reproduction_mode": "off", "phases": {phase: "ok" for phase in phases},
            }
            (scan / "run-manifest.json").write_text(json.dumps(manifest))
            task_names = ["Recon", "SCA", "Secrets", "SASTLead", "Intelligence", "Triage", "Intrusion", "Reconcile", "FinalVerification", "RenderReport"]
            artifact_dirs = ["repo-context", "sca", "secrets", "sast", "intelligence", "triage", "intrusion", "final-reconciliation", "final-verification", "report"]
            tasks = [
                {"id": task_id, "phase": phase, "status": "ok", "attempts": 1, "artifact": f"{directory}/phase-manifest.json", "updated_at": "2026-01-01T00:00:01Z", "error": None}
                for phase, task_id, directory in zip(phases, task_names, artifact_dirs)
            ]
            (scan / "task-ledger.json").write_text(json.dumps({"schema_version": "2.0", "run_id": "run", "tasks": tasks}))
            context = base / "context.json"
            context.write_text(json.dumps({
                "schema_version": "2.0", "run_id": "run", "scan_base": str(scan), "repo_path": str(target),
                "repo_name": "repo", "short_sha": "abc123", "target_fingerprint": fingerprint,
                "reproduction_mode": "off", "model": "test-model",
            }))
            env = os.environ.copy()
            env["VULNOPS_AUDIT_CONTEXT"] = str(context)

            for directory in ("repo-context/research", "sca", "secrets", "sast/deepdive", "sast/verify", "sast/reproduction", "intelligence", "triage", "intrusion/codegraph-runs/S1/codegraph-out", "final-reconciliation", "final-verification/results"):
                (scan / directory).mkdir(parents=True, exist_ok=True)
            (scan / "repo-context/repo.md").write_text("# Repo\n")
            repo_context = {
                "schema_version": "2.0", "repository": "repo",
                "comparable": {"name": None, "basis": "No offline comparable.", "confidence": "not_applicable"},
                "projects": [{
                    "id": "api", "type": "backend", "base_path": "", "languages": ["Python"], "frameworks": [],
                    "dependency_files": [], "entry_points": [{"id": "EP1", "path": "app.py", "kind": "library", "evidence_refs": ["app.py:1"]}],
                    "trust_boundary_ids": ["B1"], "ignore_patterns": [], "evidence_refs": ["app.py:1"],
                }],
                "actors": [{"id": "A1", "name": "library caller", "trust_level": "lower", "evidence_refs": ["app.py:1"]}],
                "domain_tags": [], "sensitive_data_types": [], "build_ci": [], "generated_ignorable": [],
                "evidence_refs": ["app.py:1"], "warnings": [], "errors": [],
            }
            (scan / "repo-context/repo-context.json").write_text(json.dumps(repo_context))
            surfaces = {
                "schema_version": "2.0", "repository": "repo",
                "entry_points": [{"id": "EP1", "project_id": "api", "path": "app.py", "kind": "library", "trust_boundary_ids": ["B1"], "evidence_refs": ["app.py:1"]}],
                "trust_boundaries": [{"id": "B1", "project_id": "api", "source_trust": "caller", "target_trust": "library", "description": "Call boundary", "evidence_refs": ["app.py:1"]}],
                "security_relevant_files": [{"path": "app.py", "categories": ["entry_point"], "evidence_refs": ["app.py:1"]}],
                "ignore_patterns": [], "generated_ignorable": [], "sensitive_data_types": [], "domain_tags": [], "warnings": [], "errors": [],
            }
            (scan / "repo-context/security-surfaces.json").write_text(json.dumps(surfaces))
            for name, worker in (("overview.json", "overview"), ("trust-boundaries.json", "trust-boundaries"), ("input-surfaces.json", "input-surfaces")):
                (scan / "repo-context/research" / name).write_text(json.dumps({"schema_version": "2.0", "worker": worker, "status": "ok", "observations": [], "warnings": [], "errors": []}))
            (scan / "repo-context/phase-manifest.json").write_text(json.dumps(self.phase_manifest("recon")))

            (scan / "sca/summary.md").write_text("# SCA\n")
            (scan / "sca/raw-advisories.json").write_text("[]")
            (scan / "sca/phase-manifest.json").write_text(json.dumps(self.phase_manifest("sca")))
            (scan / "secrets/summary.md").write_text("# Secrets\n")
            (scan / "secrets/redacted-candidates.json").write_text(json.dumps({"schema_version": "2.0", "tool": "poltergeist", "candidates": []}))
            (scan / "secrets/phase-manifest.json").write_text(json.dumps(self.phase_manifest("secrets")))

            threat = {
                "schema_version": "2.0", "repository_profile": {"kinds": ["library"], "tags": [], "comparable": {"name": None, "basis": "fixture", "confidence": "not_applicable"}},
                "assets": [{"id": "AS1", "name": "library integrity", "sensitivity": "medium", "description": "Correct operation", "evidence_refs": ["app.py:1"]}],
                "trust_boundaries": [{"id": "B1", "source_trust": "caller", "target_trust": "library", "description": "Call boundary", "evidence_refs": ["app.py:1"]}],
                "entrypoints": [{"id": "EP1", "path": "app.py", "kind": "library", "subsystem_ids": ["api"], "trust_boundary_ids": ["B1"], "evidence_refs": ["app.py:1"]}],
                "subsystems": [{"id": "api", "name": "API", "files": ["app.py"], "entrypoints": ["app.py:1"], "security_surface_ids": ["EP1"], "risk": "medium", "evidence_refs": ["app.py:1"]}],
                "attack_classes": [{"id": "injection", "title": "Injection", "domain": "general", "owner": "sast", "methodology_ref": "skill://vulnops-attack-general#injection", "applicable_subsystems": ["api"], "reason": "Caller input", "evidence_refs": ["app.py:1"], "custom": False}],
                "threats": [{"id": "T1", "title": "Caller input", "attacker": "library caller", "asset_ids": ["AS1"], "entrypoint_ids": ["EP1"], "attack_class_ids": ["injection"], "description": "Review caller input", "evidence_refs": ["app.py:1"]}],
                "assumptions": [], "evidence_refs": ["app.py:1"], "warnings": [], "errors": [],
            }
            (scan / "sast/threat-model.json").write_text(json.dumps(threat))
            (scan / "sast/threat-model.md").write_text("# Threat\n")
            plan = {
                "schema_version": "2.0", "run_id": "run", "rationale": "fixture", "budget": {"max_concurrency": 1, "max_hunt_tasks": 1, "max_gapfill_rounds": 0, "max_attempts": 1, "context_packet_bytes": 65536}, "custom_attack_classes": [],
                "cells": [{"id": "CELL-1", "surface_id": "EP1", "subsystem": "api", "attack_class_id": "injection", "domain": "general", "status": "planned", "priority": "medium", "evidence_refs": ["app.py:1"], "owner": "sast", "lead_key": None, "disposition_reason": "fixture"}],
                "tasks": [{"id": "H001", "cell_ids": ["CELL-1"], "subsystem": "api", "attack_class_id": "injection", "domain": "general", "methodology_refs": ["skill://vulnops-attack-general#injection"], "lenses": [], "files": ["app.py"], "entrypoints": ["app.py:1"], "context_packet": "{}", "evidence_refs": ["app.py:1"], "attempt": 1, "round": 0}],
                "warnings": [], "errors": [],
            }
            (scan / "sast/hunt-plan.json").write_text(json.dumps(plan))
            (scan / "sast/task-manifest.json").write_text(json.dumps({"schema_version": "2.0", "rationale": "fixture", "chunks": []}))
            (scan / "sast/decompose.md").write_text("# Plan\n")
            hunt_result = {"schema_version": "2.0", "task_id": "H001", "status": "ok", "files_reviewed": ["app.py"], "entrypoints_traced": ["app.py:1"], "sinks_reviewed": ["app.py:2"], "mitigations_checked": ["No dangerous sink."], "candidates": [], "hardening_notes": [], "positive_patterns": [], "rabbit_holes": [], "wishlist_items": [], "warnings": [], "errors": []}
            (scan / "sast/deepdive/H001.json").write_text(json.dumps(hunt_result))
            for name in ("raw-findings.json", "validation-queue.json", "validation-results.json", "verified-findings.json", "dropped-findings.json"):
                (scan / "sast" / name).write_text("[]")
            (scan / "sast/dedup-clusters.json").write_text(json.dumps({"schema_version": "2.0", "clusters": []}))
            funnel = {name: 0 for name in ("raw_candidates", "deduplicated_candidates", "mechanically_rejected", "adversarially_rejected", "source_verified", "dynamic_verified", "environment_required", "final_rejected", "reported")}
            coverage = {"schema_version": "2.0", "run_id": "run", "rounds_completed": 0, "cells": [{"id": "CELL-1", "status": "clean", "task_ids": ["H001"], "evidence_refs": ["sast/deepdive/H001.json"], "reason": "focused review completed"}], "tasks": [{"id": "H001", "status": "ok", "attempts": 1, "files_reviewed": ["app.py"], "entrypoints_traced": ["app.py:1"], "sinks_reviewed": ["app.py:2"], "mitigations_checked": ["No dangerous sink."], "candidate_ids": [], "rabbit_holes": []}], "funnel": funnel, "warnings": [], "errors": []}
            (scan / "sast/coverage-ledger.json").write_text(json.dumps(coverage))
            (scan / "sast/wishlist.json").write_text(json.dumps({"schema_version": "2.0", "run_id": "run", "items": []}))
            (scan / "sast/hardening-notes.json").write_text("[]")
            (scan / "sast/positive-patterns.json").write_text("[]")
            (scan / "sast/summary.md").write_text("# SAST\n")
            (scan / "sast/phase-manifest.json").write_text(json.dumps(self.phase_manifest("sast")))

            intel_docs = {
                "evidence-corpus.json": {"observations": [{"id": "O1"}]},
                "attack-surface-map.json": {"components": [], "entry_points": [], "trust_boundaries": [], "files_by_category": {}},
                "intel-plan.json": {"mode": "intelligence-ooda", "scopes": []},
                "investigation-cards.json": {"cards": []}, "coverage-gaps.json": {"gaps": []}, "rule-gaps.json": {"rule_gaps": []},
            }
            for name, document in intel_docs.items():
                (scan / "intelligence" / name).write_text(json.dumps(document))
            (scan / "intelligence/summary.md").write_text("# Intelligence\n")
            (scan / "intelligence/phase-manifest.json").write_text(json.dumps(self.phase_manifest("intelligence")))
            (scan / "triage/consolidated.md").write_text("# Triage\n")
            (scan / "triage/findings.json").write_text("[]")
            (scan / "triage/intrusion-seeds.json").write_text("[]")
            (scan / "triage/phase-manifest.json").write_text(json.dumps(self.phase_manifest("triage")))
            (scan / "intrusion/summary.md").write_text("# Intrusion\n")
            (scan / "intrusion/enrichment.json").write_text("{}")
            (scan / "intrusion/intrusion-plan.json").write_text(json.dumps({"mode": "targeted-ooda", "scopes": [{"id": "S1", "required": False}]}))
            (scan / "intrusion/codegraph-runs/S1/codegraph-out/context.json").write_text(json.dumps({"nodes": [{"id": "n1", "role": "function"}], "edges": []}))
            (scan / "intrusion/phase-manifest.json").write_text(json.dumps(self.phase_manifest("intrusion")))
            empty_final = {"schema_version": "2.0", "run_id": "run", "model_diversity": False, "findings": []}
            (scan / "final-reconciliation/candidates.json").write_text(json.dumps(empty_final))
            (scan / "final-reconciliation/summary.md").write_text("# Reconciliation\n")
            (scan / "final-reconciliation/phase-manifest.json").write_text(json.dumps(self.phase_manifest("final-reconciliation")))
            (scan / "final-verification/findings.json").write_text(json.dumps(empty_final))
            (scan / "final-verification/summary.md").write_text("# Final\n")
            (scan / "final-verification/phase-manifest.json").write_text(json.dumps(self.phase_manifest("final-verification")))
            result = run(PYTHON, "scripts/render-report.py", str(scan), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = run(PYTHON, "scripts/validate-scan-v2.py", str(ROOT), str(scan), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            (target / "app.py").write_text("def entry(value):\n    return value + 'changed'\n")
            result = run(PYTHON, "scripts/validate-scan-v2.py", str(ROOT), str(scan), env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("target working tree changed", result.stderr)

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap unavailable")
    def test_safe_reproduction_is_offline_scrubbed_and_target_read_only(self) -> None:
        base = ROOT / ".harness/tmp/test-v2-sandbox"
        shutil.rmtree(base, ignore_errors=True)
        target = base / "target"
        scan = base / "scan"
        target.mkdir(parents=True)
        scan.mkdir()
        (target / "data.txt").write_text("unchanged")
        fingerprint = run(PYTHON, "scripts/target-fingerprint.py", str(target)).stdout.strip()
        context = base / "context.json"
        context.write_text(json.dumps({
            "scan_base": str(scan), "repo_path": str(target), "run_id": "sandbox-test",
            "target_fingerprint": fingerprint, "reproduction_mode": "safe",
        }))
        env = os.environ.copy()
        env.update({"VULNOPS_AUDIT_CONTEXT": str(context), "VULNOPS_REPRODUCTION_SANDBOX": "bubblewrap", "SECRET_TEST": "must-not-pass"})
        prepare = run("bash", "scripts/run-safe-reproduction.sh", str(scan), "F-001", "prepare", env=env)
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        scrub = run("bash", "scripts/run-safe-reproduction.sh", str(scan), "F-001", "exec", "--", "/bin/sh", "-c", 'test -z "${SECRET_TEST:-}"', env=env)
        self.assertEqual(scrub.returncode, 0, scrub.stderr)
        host_hidden = run("bash", "scripts/run-safe-reproduction.sh", str(scan), "F-001", "exec", "--", "/bin/sh", "-c", "test ! -e /home/ubuntu && test ! -e /etc/passwd", env=env)
        self.assertEqual(host_hidden.returncode, 0, host_hidden.stderr)
        readonly = run("bash", "scripts/run-safe-reproduction.sh", str(scan), "F-001", "exec", "--", "/usr/bin/touch", str(target / "blocked"), env=env)
        self.assertNotEqual(readonly.returncode, 0)
        writable = run("bash", "scripts/run-safe-reproduction.sh", str(scan), "F-001", "exec", "--", "/usr/bin/touch", "sandbox-write", env=env)
        self.assertEqual(writable.returncode, 0, writable.stderr)
        self.assertEqual(fingerprint, run(PYTHON, "scripts/target-fingerprint.py", str(target)).stdout.strip())
        run("bash", "scripts/run-safe-reproduction.sh", str(scan), "F-001", "clean", env=env)
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
