from __future__ import annotations

import json
import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ROLE_ARGS = ("--orchestrator-model", "p/orchestrator", "--task-model", "p/task", "--slow-model", "p/main", "--smol-model", "p/smol")
ROLE_MAP = {"orchestrator": "p/orchestrator", "task": "p/task", "slow": "p/main", "smol": "p/smol"}


def run(*args: str, input_text: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(args, cwd=ROOT, input=input_text, capture_output=True, text=True, check=False, env=merged)


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def write_minimal_recon(scan: Path, target: Path, run_id: str, dependency_files: list[str]) -> None:
    entry_file = "main.py" if (target / "main.py").is_file() else "main.go" if (target / "main.go").is_file() else "main.py"
    if not (target / entry_file).is_file():
        (target / entry_file).write_text("pass\n")
    context = {
        "schema_version": "2.0", "repository": "fixture",
        "comparable": {"name": None, "basis": "fixture", "confidence": "not_applicable"},
        "projects": [{
            "id": "PRJ-1", "type": "library", "base_path": ".", "languages": ["python"],
            "frameworks": [], "dependency_files": dependency_files,
            "entry_points": [{"id": "EP-1", "path": entry_file, "kind": "library", "evidence_refs": [f"{entry_file}:1"]}],
            "trust_boundary_ids": ["TB-1"], "ignore_patterns": [], "evidence_refs": [f"{entry_file}:1"],
        }],
        "actors": [], "domain_tags": [], "sensitive_data_types": [], "build_ci": [],
        "generated_ignorable": [], "evidence_refs": [f"{entry_file}:1"], "warnings": [], "errors": [],
    }
    surfaces = {
        "schema_version": "2.0", "repository": "fixture",
        "entry_points": [{"id": "EP-1", "project_id": "PRJ-1", "path": entry_file, "kind": "library", "trust_boundary_ids": ["TB-1"], "evidence_refs": [f"{entry_file}:1"]}],
        "trust_boundaries": [{"id": "TB-1", "project_id": "PRJ-1", "source_trust": "caller", "target_trust": "library", "description": "caller boundary", "evidence_refs": [f"{entry_file}:1"]}],
        "security_relevant_files": [{"path": entry_file, "categories": ["entry_point"], "evidence_refs": [f"{entry_file}:1"]}],
        "ignore_patterns": [], "generated_ignorable": [], "sensitive_data_types": [], "domain_tags": [], "warnings": [], "errors": [],
    }
    write(scan / "repo-context/repo-context.json", context)
    write(scan / "repo-context/security-surfaces.json", surfaces)
    (scan / "repo-context/repo.md").write_text("# Fixture\n")
    for name, worker in (("overview.json", "overview"), ("trust-boundaries.json", "trust-boundaries"), ("input-surfaces.json", "input-surfaces")):
        write(scan / "repo-context/research" / name, {"schema_version": "2.0", "worker": worker, "status": "ok", "started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z", "observations": [], "warnings": [], "errors": []})
    outputs = [
        "repo-context/repo.md", "repo-context/repo-context.json", "repo-context/security-surfaces.json",
        "repo-context/research/overview.json", "repo-context/research/trust-boundaries.json",
        "repo-context/research/input-surfaces.json",
    ]
    write(scan / "repo-context/phase-manifest.json", {
        "phase": "recon", "status": "ok", "started_at": "now", "completed_at": "now",
        "inputs": [], "outputs": outputs, "coverage": {"projects": 1},
        "tool_versions": {"fixture": "1"}, "warnings": [], "errors": [],
    })


class ScannerContractTests(unittest.TestCase):
    def test_secret_semantics_read_each_referenced_file_once(self) -> None:
        scripts_path = str(ROOT / "scripts")
        sys.path.insert(0, scripts_path)
        try:
            spec = importlib.util.spec_from_file_location("validate_json", ROOT / "scripts/validate-json.py")
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            validate_json = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(validate_json)
        finally:
            sys.path.remove(scripts_path)

        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            (target / "large-fixture.txt").write_text("first\nsecond\nthird\n")
            candidates = [
                {"id": f"SEC-{index:016x}", "file": "large-fixture.txt", "line": index % 3 + 1}
                for index in range(5000)
            ]
            candidates[-1]["line"] = 4
            document = {"match_count": len(candidates), "candidate_count": len(candidates), "candidates": candidates}
            with mock.patch.object(validate_json, "text_line_count", wraps=validate_json.text_line_count) as counter:
                errors = validate_json.semantic_errors(document, "secrets-redacted", target)

            self.assertEqual(errors, ["$.candidates[4999].line is outside 'large-fixture.txt'"])
            self.assertEqual(counter.call_count, 1)

    def test_dependency_input_contract_accepts_only_scannable_manifests(self) -> None:
        accepted = run(PYTHON, "scripts/dependency_contract.py", "go.mod", "docs/package-lock.json", "gradle/verification-metadata.xml")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for unsupported in ("go.sum", "package.json", "Dockerfile", ".github/workflows/test.yml", "missing/../../go.mod"):
            rejected = run(PYTHON, "scripts/dependency_contract.py", unsupported)
            self.assertNotEqual(rejected.returncode, 0, unsupported)

    def test_repo_context_semantics_reject_unsupported_dependency_handoff(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "main.py").write_text("pass\n"); (target / "go.sum").write_text("sum\n")
            scan = base / "scan"; write_minimal_recon(scan, target, "run", ["go.sum"])
            result = run(PYTHON, "scripts/validate-json.py", "schemas/v2/repo-context.schema.json", str(scan / "repo-context/repo-context.json"), "--semantic", "repo-context", "--target", str(target))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not a supported Wraith input", result.stderr)

    def test_recon_finalizer_replaces_model_dependency_guesses_with_complete_discovery(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base = Path(tmp); scan = base / "run"; target = base / "target"; target.mkdir()
            (target / "main.go").write_text("package main\n"); (target / "go.mod").write_text("module fixture\ngo 1.22\n"); (target / "go.sum").write_text("sum\n"); (target / "package.json").write_text("{}\n")
            fingerprint = run(PYTHON, "scripts/target-fingerprint.py", str(target)).stdout.strip(); context = base / "context.json"; env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
            initialized = run(PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target), "--scan-base", str(scan), "--run-id", "run", "--repo-name", "fixture", "--remote-url", "local", "--repo-id", "fixture", "--commit", "abc", "--depth", "quick", "--target-fingerprint", fingerprint, "--reproduction-mode", "off", "--model", "p/main", *ROLE_ARGS, "--verifier-model", "p/verifier", env=env)
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            write_minimal_recon(scan, target, "run", ["go.sum", "package.json"])
            finalized = run(PYTHON, "scripts/finalize-recon.py", str(target), str(scan), env=env)
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            document = json.loads((scan / "repo-context/repo-context.json").read_text())
            self.assertEqual(document["projects"][0]["dependency_files"], ["go.mod"])
            validated = run("bash", "scripts/validate-phase.sh", str(scan), "recon", env=env)
            self.assertEqual(validated.returncode, 0, validated.stderr)

    def test_hunt_workers_receive_hash_bound_task_packets(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def handle(value):\n    return value\n")
            scan = base / "scan"; (scan / "sast/hunt-tasks").mkdir(parents=True)
            context_path = base / "context.json"
            write(context_path, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan)})
            write(scan / "sast/threat-model.json", {
                "schema_version": "2.0",
                "repository_profile": {"kinds": ["library"], "tags": [], "comparable": {"name": None, "basis": "fixture", "confidence": "not_applicable"}},
                "assets": [{"id": "ASSET-1", "name": "handler integrity", "sensitivity": "medium", "description": "trusted processing", "evidence_refs": ["app.py:1"]}],
                "trust_boundaries": [{"id": "TB-1", "source_trust": "caller", "target_trust": "handler", "description": "caller input boundary", "evidence_refs": ["app.py:1"]}],
                "entrypoints": [{"id": "EP-1", "path": "app.py", "kind": "library", "subsystem_ids": ["SUB-1"], "trust_boundary_ids": ["TB-1"], "evidence_refs": ["app.py:1"]}],
                "subsystems": [{"id": "SUB-1", "name": "handler", "files": ["app.py"], "entrypoints": ["EP-1"], "security_surface_ids": ["EP-1"], "risk": "high", "evidence_refs": ["app.py:1"]}],
                "attack_classes": [{"id": "injection", "title": "Injection", "domain": "general", "owner": "sast", "methodology_ref": "skill://vulnops-attack-general#injection", "reason": "untrusted input reaches handler", "evidence_refs": ["app.py:1"], "custom": False}],
                "threats": [{"id": "TH-1", "title": "caller injection", "attacker": "caller", "asset_ids": ["ASSET-1"], "entrypoint_ids": ["EP-1"], "attack_class_ids": ["injection"], "description": "caller data reaches trusted handling", "evidence_refs": ["app.py:1"]}],
                "hunt_mappings": [{"id": "HM-1", "attack_class_id": "injection", "subsystem_id": "SUB-1", "surface_ids": ["EP-1"], "threat_ids": ["TH-1"], "asset_ids": ["ASSET-1"], "attacker": "untrusted caller", "entrypoint_ids": ["EP-1"], "boundary_ids": ["TB-1"], "source_files": ["app.py"], "security_question": "Can caller input reach an unsafe interpreter?", "stop_conditions": ["No interpreter or parser sink is reachable"], "priority": "high", "applicability_reason": "The public handler accepts caller-controlled data.", "evidence_refs": ["app.py:1"]}],
                "assumptions": [], "evidence_refs": ["app.py:1"], "warnings": [], "errors": [],
            })
            write(scan / "sast/hunt-tasks/orphan.json", {"stale": True})
            built = run(PYTHON, "scripts/build-hunt-plan.py", str(target), str(scan), "--context", str(context_path))
            self.assertEqual(built.returncode, 0, built.stderr)
            plan_path = scan / "sast/hunt-plan.json"; plan = json.loads(plan_path.read_text())
            self.assertEqual(len(plan["tasks"]), 1)
            task = plan["tasks"][0]; packets = list((scan / "sast/hunt-tasks").glob("*.json"))
            self.assertEqual([path.name for path in packets], [f"{task['id']}.json"])
            packet = json.loads(packets[0].read_text())
            self.assertEqual(packet["run_id"], "run")
            self.assertEqual(packet["hunt_plan_ref"], "sast/hunt-plan.json")
            self.assertEqual(packet["hunt_plan_sha256"], hashlib.sha256(plan_path.read_bytes()).hexdigest())
            self.assertEqual(packet["task"], task)
            self.assertEqual(packet["cells"], [plan["cells"][0]])

    def test_wraith_real_envelope_is_normalized_and_counts_are_checked(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp)
            (base / "go.mod").write_text("module fixture\n")
            raw = {
                "package_count": 1,
                "vulnerability_count": 1,
                "results": [{
                    "Package": "example", "Version": "1.0", "Ecosystem": "Go",
                    "FoundVulnerabilities": [{"ID": "OSV-1", "Severity": "HIGH", "Summary": "bounded", "Details": "must not persist", "References": ["https://example.invalid/OSV-1"]}],
                }],
            }
            database_args = ("--ecosystem", "Go", "--database-snapshot", "fixture", "--database-sha256", "a" * 64)
            result = run(PYTHON, "scripts/normalize-wraith.py", "--repo", str(base), "--lockfile", str(base / "go.mod"), *database_args, "--output", str(base / "out.json"), "--receipt", str(base / "receipt.json"), input_text=json.dumps(raw))
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads((base / "out.json").read_text())
            self.assertEqual(output["advisory_count"], 1)
            self.assertNotIn("Details", json.dumps(output))
            raw["vulnerability_count"] = 2
            bad = run(PYTHON, "scripts/normalize-wraith.py", "--repo", str(base), "--lockfile", str(base / "go.mod"), *database_args, "--output", str(base / "bad.json"), "--receipt", str(base / "bad-receipt.json"), input_text=json.dumps(raw))
            self.assertNotEqual(bad.returncode, 0)
            empty = run(PYTHON, "scripts/normalize-wraith.py", "--repo", str(base), "--lockfile", str(base / "go.mod"), *database_args, "--output", str(base / "empty.json"), "--receipt", str(base / "empty-receipt.json"), input_text=json.dumps({"package_count": 0, "vulnerability_count": 0, "results": None}))
            self.assertEqual(empty.returncode, 0, empty.stderr)

    def test_poltergeist_prelude_and_match_fields_never_survive(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("one\ntwo\nthree\n")
            raw = {"summary": {"total_matches": 1}, "results": [{"file_path": str(target / "app.py"), "line_number": 1, "rule_name": "API Key", "rule_id": "api-key", "redacted": "partial-sensitive-fragment", "entropy": 4.2}]}
            source = base / "scanner.txt"; source.write_text("scanner prelude\n" + json.dumps(raw))
            result = run(PYTHON, "scripts/normalize-poltergeist.py", "--target", str(target), "--input", str(source), "--scanner-exit", "1", "--output", str(base / "out.json"), "--receipt", str(base / "receipt.json"))
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (base / "out.json").read_text()
            self.assertIn('"redaction": "<redacted>"', text)
            self.assertNotIn("partial-sensitive-fragment", text)
            self.assertNotIn("entropy", text)
            repeated = raw["results"][0]
            source.write_text(json.dumps({"summary": {"matches_found": 4}, "results": [
                repeated,
                repeated,
                {**repeated, "line_number": 2},
                {**repeated, "line_number": 3},
            ]}))
            deduped = run(PYTHON, "scripts/normalize-poltergeist.py", "--target", str(target), "--input", str(source), "--scanner-exit", "1", "--output", str(base / "deduped.json"), "--receipt", str(base / "deduped-receipt.json"))
            self.assertEqual(deduped.returncode, 0, deduped.stderr)
            deduped_doc = json.loads((base / "deduped.json").read_text())
            deduped_receipt = json.loads((base / "deduped-receipt.json").read_text())
            self.assertEqual(deduped_doc["match_count"], 4)
            self.assertEqual(deduped_doc["candidate_count"], 3)
            self.assertEqual(deduped_receipt["warnings"], [])
            source.write_text(json.dumps({"summary": {"matches_found": 0}, "results": None}))
            empty = run(PYTHON, "scripts/normalize-poltergeist.py", "--target", str(target), "--input", str(source), "--scanner-exit", "0", "--output", str(base / "empty.json"), "--receipt", str(base / "empty-receipt.json"))
            self.assertEqual(empty.returncode, 0, empty.stderr)

    def test_tool_collection_deduplication_is_ok_coverage(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); scan = base / "scan"; context = base / "context.json"
            write(context, {"run_id": "run", "scan_base": str(scan)})
            sca = {"schema_version": "2.0", "tool": "wraith", "packages_scanned": 1, "advisory_count": 62, "advisories": []}
            secrets = {"schema_version": "2.0", "tool": "poltergeist", "match_count": 4, "candidate_count": 3, "candidates": []}
            write(scan / "tool-collection/sca-advisories.json", sca)
            write(scan / "tool-collection/secrets-redacted.json", secrets)
            write(scan / "tool-collection/dependency-limitations.json", {"schema_version": "2.0", "limitations": []})
            for tool, artifact, receipt in (("wraith", "sca-advisories.json", "wraith-receipt.json"), ("poltergeist", "secrets-redacted.json", "poltergeist-receipt.json")):
                digest = hashlib.sha256((scan / "tool-collection" / artifact).read_bytes()).hexdigest()
                document = {"schema_version": "2.0", "tool": tool, "operation": "fixture", "status": "ok", "version": "fixture", "started_at": "now", "completed_at": "now", "parse_status": "ok", "result_count": 0, "normalized_sha256": digest, "warnings": []}
                if tool == "wraith":
                    document.update({"packages_scanned": 1, "databases": [{"ecosystem": "Go", "snapshot": "fixture", "sha256": "a" * 64}]})
                write(scan / "tool-collection" / receipt, document)
            result = run(PYTHON, "scripts/finalize-tool-collection.py", str(scan), env={"VULNOPS_AUDIT_CONTEXT": str(context)})
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest_doc = json.loads((scan / "tool-collection/phase-manifest.json").read_text())
            collection_doc = json.loads((scan / "tool-collection/collection.json").read_text())
            self.assertEqual(manifest_doc["status"], "ok")
            self.assertEqual(manifest_doc["warnings"], [])
            self.assertEqual(manifest_doc["coverage"]["secret_matches"], 4)
            self.assertEqual(manifest_doc["coverage"]["secret_candidates"], 3)
            self.assertEqual(collection_doc["warnings"], [])


class PrimitiveCampaignTests(unittest.TestCase):
    def fixture(self, base: Path) -> tuple[Path, Path]:
        scan = base / "scan"; target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry():\n    return sink()\ndef sink():\n    return 1\n")
        context = {"schema_version": "2.0", "run_id": "run", "depth": "quick", "model": "p/main", "verifier_model": "p/verify", "model_diversity": True, "repo_path": str(target), "scan_base": str(scan)}
        write(base / "context.json", context)
        write(scan / "repo-context/security-surfaces.json", {"entry_points": [{"id": "EP-1", "kind": "http", "path": "app.py", "trust_boundary_ids": ["TB-1"]}], "trust_boundaries": [{"id": "TB-1", "source_trust": "remote", "target_trust": "service", "description": "remote to service"}]})
        write(scan / "tool-collection/sca-advisories.json", {"advisories": [{"id": "SCA-1111111111111111", "advisory_id": "OSV-1", "package": "lib", "version": "1", "source_lockfile": "go.mod"}]})
        write(scan / "tool-collection/secrets-redacted.json", {"candidates": [{"id": "SEC-1111111111111111", "type": "token", "file": "app.py", "exposure_path": "source"}]})
        verified = {"id": "C-1", "title": "Known auth bypass", "verification_level": "source_verified", "attacker": {"starting_access": "remote", "boundary_crossed": "auth"}, "impact": "user access", "root_cause_location": {"file": "app.py"}, "conditions": [], "evidence_refs": ["app.py:1"]}
        write(scan / "sast/verified-findings.json", [verified]); write(scan / "sast/dropped-findings.json", []); write(scan / "sast/raw-findings.json", [verified])
        write(scan / "sast/coverage-ledger.json", {"cells": [{"id": "CELL-1", "status": "depth_limited", "reason": "configured audit depth reached"}]})
        write(scan / "sast/hardening-notes.json", []); write(scan / "sast/positive-patterns.json", [])
        return scan, base / "context.json"

    def test_known_findings_become_composable_campaign_primitives(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            scan, context = self.fixture(Path(tmp))
            first = run(PYTHON, "scripts/build-evidence-index.py", str(scan), "--context", str(context))
            self.assertEqual(first.returncode, 0, first.stderr)
            second = run(PYTHON, "scripts/build-campaign-plan.py", str(scan), "--context", str(context))
            self.assertEqual(second.returncode, 0, second.stderr)
            index = json.loads((scan / "campaign-planning/evidence-index.json").read_text())
            self.assertTrue(any(p["trust"] == "confirmed" for p in index["primitives"]))
            plan = json.loads((scan / "campaign-planning/campaign-plan.json").read_text())
            primitive_campaigns = [c for c in plan["campaigns"] if c["lane"] == "primitive_led"]
            self.assertTrue(primitive_campaigns)
            self.assertGreaterEqual(len(primitive_campaigns[0]["primitive_ids"]), 2)
            self.assertIn("known primitive", primitive_campaigns[0]["expected_added_value"].lower())

    def test_scanner_secret_fanout_remains_evidence_only_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            scan, context = self.fixture(Path(tmp))
            candidate_count = 24_500
            write(
                scan / "tool-collection/secrets-redacted.json",
                {
                    "candidates": [
                        {
                            "id": f"SEC-{index:016x}",
                            "type": "high-volume scanner rule",
                            "file": "app.py",
                            "exposure_path": "repository source requires validation",
                        }
                        for index in range(candidate_count)
                    ]
                },
            )

            built = run(PYTHON, "scripts/build-evidence-index.py", str(scan), "--context", str(context))
            self.assertEqual(built.returncode, 0, built.stderr)
            index_path = scan / "campaign-planning/evidence-index.json"
            index = json.loads(index_path.read_text())
            secret_records = [record for record in index["records"] if record["source_kind"] == "secret"]
            self.assertEqual(len(secret_records), candidate_count)
            self.assertFalse(any(item["type"] == "credential" for item in index["primitives"]))
            self.assertLess(index_path.stat().st_size, 16 * 1024 * 1024)


class ChainVerificationTests(unittest.TestCase):
    def finding(self) -> dict:
        return {
            "id": "F-001", "finding_kind": "chain", "origin": "composite_chain", "title": "Known primitives compose into account takeover", "category": "attack-chain", "severity": "high", "risk_score": 85, "confidence": "high", "status": "verified",
            "attacker": {"perspective": "remote user", "starting_access": "remote input", "boundary_crossed": "authentication"}, "intended_behavior": "Each boundary should prevent privilege acquisition.",
            "root_causes": [{"file": "app.py", "line": 1, "scope": "entry", "mechanism": "first primitive"}, {"file": "app.py", "line": 3, "scope": "sink", "mechanism": "second primitive"}],
            "trace": [{"kind": "entrypoint", "file": "app.py", "line": 1, "scope": "entry", "description": "attacker enters"}, {"kind": "sink", "file": "app.py", "line": 3, "scope": "sink", "description": "privilege gained"}],
            "conditions": ["both verified primitives are reachable"], "impact": "account takeover", "remediation": "break both capability transitions",
            "verification": {"level": "source_verified", "model": "p/main", "source_validation_refs": ["sast/validation-results.json"], "reproduction_ref": None},
            "primitive_steps": [{"primitive_id": "P-AAAAAAAAAAAA", "input_capability": "remote input", "output_capability": "valid session", "boundary_crossed": "session", "evidence_refs": ["sast/verified-findings.json:C-1"]}, {"primitive_id": "P-BBBBBBBBBBBB", "input_capability": "valid session", "output_capability": "admin access", "boundary_crossed": "authorization", "evidence_refs": ["intrusion/intrusion-results.json"]}],
            "source_refs": [{"kind": "sast", "source_id": "C-1", "artifact_ref": "sast/verified-findings.json:C-1"}, {"kind": "intrusion", "source_id": "CAM-001", "artifact_ref": "intrusion/intrusion-results.json:CAM-001"}], "graph_receipt_refs": [], "closure_rationale": "Both known primitives form a newly proven end-to-end path.", "dependency": None, "secret": None,
        }

    def test_finalizer_requires_ordered_verification_of_every_chain_step(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base=Path(tmp);scan=base/"scan";target=base/"target";target.mkdir();(target/"app.py").write_text("def entry():\n    pass\ndef sink():\n    pass\n")
            context={"run_id":"run","model":"p/main","verifier_model":"p/verifier","model_diversity":True,"scan_base":str(scan),"repo_path":str(target)};write(base/"context.json",context)
            write(scan/"synthesis/findings.json",{"schema_version":"2.0","run_id":"run","findings":[self.finding()]})
            result={"schema_version":"2.0","finding_id":"F-001","status":"verified","closure_reason":"all claims hold","evidence_refs":["synthesis/findings.json:F-001"],"primitive_results":[{"primitive_id":"P-AAAAAAAAAAAA","status":"verified","evidence_refs":["sast/verified-findings.json:C-1"],"reason":"holds"},{"primitive_id":"P-BBBBBBBBBBBB","status":"verified","evidence_refs":["intrusion/intrusion-results.json"],"reason":"holds"}],"corrections":[],"corrected_finding":None,"model":"p/verifier","model_diversity":True}
            write(scan/"final-verification/results/F-001.json",result)
            env={"VULNOPS_AUDIT_CONTEXT":str(base/"context.json")}
            good=run(PYTHON,"scripts/finalize-verification.py",str(target),str(scan),env=env);self.assertEqual(good.returncode,0,good.stderr)
            final=json.loads((scan/"final-verification/findings.json").read_text());self.assertEqual(final["findings"][0]["origin"],"composite_chain");self.assertTrue(final["findings"][0]["model_diversity"])
            result["primitive_results"].pop();write(scan/"final-verification/results/F-001.json",result)
            bad=run(PYTHON,"scripts/finalize-verification.py",str(target),str(scan),env=env);self.assertNotEqual(bad.returncode,0)

    def test_intrusion_records_all_queries_but_cites_only_meaningful_graphs(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(dir=ROOT/".harness") as tmp:
            base=Path(tmp);scan=base/"scan";context_path=base/"context.json";write(context_path,{"run_id":"run","model":"p/main"})
            campaign={"id":"CAM-001","graph_questions":[{"id":"Q-001","type":"affected","subject":"app.py","reason":"blast radius"}]};write(scan/"campaign-planning/campaign-plan.json",{"schema_version":"2.0","run_id":"run","campaigns":[campaign]})
            graph=scan/"intrusion/codegraph-runs/CAM-001/Q-001";context={"schema_version":"2.0","tool":"codegraph","operation":"affected","subject":"app.py","nodes":[{"id":"app.py","role":"source"}],"edges":[],"meaningful":False};write(graph/"context.json",context);digest=hashlib.sha256((graph/"context.json").read_bytes()).hexdigest();write(graph/"receipt.json",{"schema_version":"2.0","tool":"codegraph","operation":"affected","status":"ok","version":"fixture","started_at":"now","completed_at":"now","parse_status":"ok","result_count":0,"normalized_sha256":digest,"meaningful":False,"warnings":[]})
            result={"schema_version":"2.0","campaign_id":"CAM-001","status":"closed","conclusion":"no downstream relationship","evidence_refs":["campaign-planning/campaign-plan.json:CAM-001"],"graph_query_receipts":["intrusion/codegraph-runs/CAM-001/Q-001/receipt.json"],"graph_evidence_refs":[],"primitive_updates":[],"candidates":[]};write(scan/"intrusion/results/CAM-001.json",result);env={"VULNOPS_AUDIT_CONTEXT":str(context_path)}
            good=run(PYTHON,"scripts/finalize-intrusion.py",str(scan),env=env);self.assertEqual(good.returncode,0,good.stderr)
            result["graph_evidence_refs"]=list(result["graph_query_receipts"]);write(scan/"intrusion/results/CAM-001.json",result);bad=run(PYTHON,"scripts/finalize-intrusion.py",str(scan),env=env);self.assertNotEqual(bad.returncode,0)


class GreenfieldContractTests(unittest.TestCase):
    def test_canonical_omp_agent_graph_is_valid(self) -> None:
        result = run(PYTHON, "scripts/validate-omp-agents.py", str(ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_legacy_runtime_or_artifact_contracts_remain(self) -> None:
        forbidden_paths = ["config/harness.yaml", "config/scan-criteria.yaml", "V2UPGRADE.md", ".omp/agents/vulnops-decompose.md", ".omp/agents/vulnops-intelligence.md", ".omp/agents/vulnops-triage.md", ".omp/agents/vulnops-reconcile.md", ".omp/agents/vulnops-tool-collection.md", ".omp/agents/vulnops-sca.md", ".omp/agents/vulnops-secrets.md", "scripts/build-intelligence.py", "scripts/build-intrusion-plan.py", "scripts/codegraph-context.sh"]
        self.assertFalse([path for path in forbidden_paths if (ROOT / path).exists()])
        manifest_schema = json.loads((ROOT / "schemas/v2/run-manifest.schema.json").read_text())
        required = set(manifest_schema["properties"]["phases"]["required"])
        self.assertEqual(required, {"recon", "tool-collection", "sast", "campaign-planning", "intrusion", "synthesis", "final-verification", "report"})

    def test_all_json_schemas_parse(self) -> None:
        for path in (ROOT / "schemas/v2").glob("*.json"):
            json.loads(path.read_text())

    def test_zero_campaign_whole_scan_is_valid(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base=Path(tmp);scan=base/"run";target=base/"target";target.mkdir();(target/"app.py").write_text("def entry():\n    return 1\n")
            fingerprint=run(PYTHON,"scripts/target-fingerprint.py",str(target)).stdout.strip();context_path=base/"context.json"
            init=[PYTHON,"scripts/init-run.py","--harness-root",str(ROOT),"--repo-path",str(target),"--scan-base",str(scan),"--run-id","run","--repo-name","fixture","--remote-url","local","--repo-id","fixture-id","--commit","abc","--depth","quick","--target-fingerprint",fingerprint,"--reproduction-mode","off","--model","p/main",*ROLE_ARGS,"--verifier-model","p/verifier"]
            env={"VULNOPS_AUDIT_CONTEXT":str(context_path)};created=run(*init,env=env);self.assertEqual(created.returncode,0,created.stderr)
            def manifest(phase:str,outputs:list[str],coverage:dict|None=None):return {"phase":phase,"status":"ok","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:01Z","inputs":[],"outputs":outputs,"coverage":coverage or {},"tool_versions":{"fixture":"1"},"warnings":[],"errors":[]}
            write(scan/"repo-context/repo-context.json",{"schema_version":"2.0","repository":"fixture","comparable":{"name":None,"basis":"fixture","confidence":"not_applicable"},"projects":[{"id":"PRJ-1","type":"library","base_path":".","languages":["python"],"frameworks":[],"dependency_files":[],"entry_points":[{"id":"EP-1","path":"app.py","kind":"library","evidence_refs":["app.py:1"]}],"trust_boundary_ids":["TB-1"],"ignore_patterns":[],"evidence_refs":["app.py:1"]}],"actors":[],"domain_tags":[],"sensitive_data_types":[],"build_ci":[],"generated_ignorable":[],"evidence_refs":["app.py:1"],"warnings":[],"errors":[]})
            write(scan/"repo-context/security-surfaces.json",{"schema_version":"2.0","repository":"fixture","entry_points":[{"id":"EP-1","project_id":"PRJ-1","path":"app.py","kind":"library","trust_boundary_ids":["TB-1"],"evidence_refs":["app.py:1"]}],"trust_boundaries":[{"id":"TB-1","project_id":"PRJ-1","source_trust":"caller","target_trust":"library","description":"caller to library","evidence_refs":["app.py:1"]}],"security_relevant_files":[{"path":"app.py","categories":["entry_point"],"evidence_refs":["app.py:1"]}],"ignore_patterns":[],"generated_ignorable":[],"sensitive_data_types":[],"domain_tags":[],"warnings":[],"errors":[]})
            (scan/"repo-context/repo.md").write_text("# Fixture\n")
            for name,worker in (("overview.json","overview"),("trust-boundaries.json","trust-boundaries"),("input-surfaces.json","input-surfaces")):write(scan/"repo-context/research"/name,{"schema_version":"2.0","worker":worker,"status":"ok","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:01Z","observations":[],"warnings":[],"errors":[]})
            recon_outputs=["repo-context/repo.md","repo-context/repo-context.json","repo-context/security-surfaces.json","repo-context/research/overview.json","repo-context/research/trust-boundaries.json","repo-context/research/input-surfaces.json","repo-context/phase-manifest.json"];write(scan/"repo-context/phase-manifest.json",manifest("recon",recon_outputs))
            sca={"schema_version":"2.0","tool":"wraith","packages_scanned":0,"advisory_count":0,"advisories":[]};secrets={"schema_version":"2.0","tool":"poltergeist","match_count":0,"candidate_count":0,"candidates":[]};write(scan/"tool-collection/sca-advisories.json",sca);write(scan/"tool-collection/secrets-redacted.json",secrets);write(scan/"tool-collection/dependency-limitations.json",{"schema_version":"2.0","limitations":[]})
            for tool,artifact_name,receipt_name in (("wraith","sca-advisories.json","wraith-receipt.json"),("poltergeist","secrets-redacted.json","poltergeist-receipt.json")):
                digest=hashlib.sha256((scan/"tool-collection"/artifact_name).read_bytes()).hexdigest();receipt={"schema_version":"2.0","tool":tool,"operation":"fixture","status":"ok","version":"fixture","started_at":"now","completed_at":"now","parse_status":"ok","result_count":0,"normalized_sha256":digest,"warnings":[]};receipt.update({"packages_scanned":0,"databases":[]} if tool=="wraith" else {});write(scan/"tool-collection"/receipt_name,receipt)
            write(scan/"tool-collection/collection.json",{"schema_version":"2.0","run_id":"run","sca_ref":"tool-collection/sca-advisories.json","secrets_ref":"tool-collection/secrets-redacted.json","receipts":["tool-collection/wraith-receipt.json","tool-collection/poltergeist-receipt.json"],"limitations":[],"warnings":[]});(scan/"tool-collection/summary.md").write_text("# Tools\n");tool_outputs=["tool-collection/collection.json","tool-collection/sca-advisories.json","tool-collection/secrets-redacted.json","tool-collection/dependency-limitations.json","tool-collection/wraith-receipt.json","tool-collection/poltergeist-receipt.json","tool-collection/summary.md","tool-collection/phase-manifest.json"];write(scan/"tool-collection/phase-manifest.json",manifest("tool-collection",tool_outputs))
            threat={"schema_version":"2.0","repository_profile":{"kinds":["library"],"tags":[],"comparable":{"name":None,"basis":"fixture","confidence":"not_applicable"}},"assets":[{"id":"A-1","name":"library integrity","sensitivity":"medium","description":"correct behavior","evidence_refs":["app.py:1"]}],"trust_boundaries":[{"id":"TB-1","source_trust":"caller","target_trust":"library","description":"caller boundary","evidence_refs":["app.py:1"]}],"entrypoints":[{"id":"EP-1","path":"app.py","kind":"library","subsystem_ids":["SUB-1"],"trust_boundary_ids":["TB-1"],"evidence_refs":["app.py:1"]}],"subsystems":[{"id":"SUB-1","name":"library","files":["app.py"],"entrypoints":["EP-1"],"security_surface_ids":["EP-1"],"risk":"low","evidence_refs":["app.py:1"]}],"attack_classes":[{"id":"dependency","title":"Dependency review","domain":"general","owner":"sca","methodology_ref":"skill://vulnops-audit-core","reason":"tool owned dependency coverage","evidence_refs":["app.py:1"],"custom":False}],"threats":[{"id":"TH-1","title":"caller misuse","attacker":"caller","asset_ids":["A-1"],"entrypoint_ids":["EP-1"],"attack_class_ids":["dependency"],"description":"fixture threat","evidence_refs":["app.py:1"]}],"hunt_mappings":[{"id":"HM-1","attack_class_id":"dependency","subsystem_id":"SUB-1","surface_ids":["EP-1"],"threat_ids":["TH-1"],"asset_ids":["A-1"],"attacker":"caller","entrypoint_ids":["EP-1"],"boundary_ids":["TB-1"],"source_files":["app.py"],"security_question":"Does validated dependency evidence cover this input?","stop_conditions":["Tool collection is valid"],"priority":"low","applicability_reason":"Dependency consumption begins at the library boundary.","evidence_refs":["app.py:1"]}],"assumptions":[],"evidence_refs":["app.py:1"],"warnings":[],"errors":[]};write(scan/"sast/threat-model.json",threat)
            hunt={"schema_version":"2.0","run_id":"run","rationale":"fixture tool-owned coverage","budget":json.loads(context_path.read_text())["sast_budget"],"custom_attack_classes":[],"cells":[{"id":"CELL-1","mapping_id":"HM-1","surface_ids":["EP-1"],"subsystem":"SUB-1","attack_class_id":"dependency","domain":"general","methodology_refs":["skill://vulnops-audit-core"],"lenses":[],"status":"tool_satisfied","priority":"low","threat_ids":["TH-1"],"asset_ids":["A-1"],"attacker":"caller","entrypoint_ids":["EP-1"],"boundary_ids":["TB-1"],"files":["app.py"],"security_question":"Does validated dependency evidence cover this input?","stop_conditions":["Tool collection is valid"],"applicability_reason":"Dependency consumption begins at the library boundary.","evidence_refs":["tool-collection/phase-manifest.json"],"owner":"sca","lead_key":None,"disposition_reason":"tool collected"}],"tasks":[],"warnings":[],"errors":[]};write(scan/"sast/hunt-plan.json",hunt)
            for name,value in (("raw-findings.json",[]),("validation-results.json",[]),("verified-findings.json",[]),("dropped-findings.json",[])):write(scan/"sast"/name,value)
            write(scan/"sast/dedup-clusters.json",{"schema_version":"2.0","clusters":[]});funnel={x:0 for x in ("raw_candidates","deduplicated_candidates","mechanically_rejected","adversarially_rejected","source_verified","dynamic_verified","environment_required","final_rejected","reported")};write(scan/"sast/coverage-ledger.json",{"schema_version":"2.0","run_id":"run","rounds_completed":0,"cells":[{"id":"CELL-1","status":"tool_satisfied","task_ids":[],"evidence_refs":["tool-collection/phase-manifest.json"],"reason":"tool collected"}],"tasks":[],"funnel":funnel,"warnings":[],"errors":[]});write(scan/"sast/wishlist.json",{"schema_version":"2.0","run_id":"run","items":[]});(scan/"sast/summary.md").write_text("# SAST\n");sast_outputs=[f"sast/{x}" for x in ("threat-model.json","hunt-plan.json","raw-findings.json","validation-results.json","verified-findings.json","dropped-findings.json","dedup-clusters.json","coverage-ledger.json","wishlist.json","summary.md","phase-manifest.json")];write(scan/"sast/phase-manifest.json",manifest("sast",sast_outputs,{"depth_limited":0}))
            built=run(PYTHON,"scripts/build-evidence-index.py",str(scan),"--context",str(context_path));self.assertEqual(built.returncode,0,built.stderr);write(scan/"campaign-planning/campaign-plan.json",{"schema_version":"2.0","run_id":"run","depth":"quick","budget":{"primitive_led":2,"gap_driven":1,"direct_validation":1},"campaigns":[],"coverage":{"evidence_records":3,"primitives":2,"campaigns":0},"warnings":[]});(scan/"campaign-planning/summary.md").write_text("# Campaigns\n");campaign_outputs=["campaign-planning/evidence-index.json","campaign-planning/campaign-plan.json","campaign-planning/summary.md","campaign-planning/phase-manifest.json"];write(scan/"campaign-planning/phase-manifest.json",manifest("campaign-planning",campaign_outputs,{"campaigns":0}))
            self.assertEqual(run(PYTHON,"scripts/finalize-intrusion.py",str(scan),env=env).returncode,0)
            self.assertEqual(run(PYTHON,"scripts/empty-synthesis.py",str(scan),env=env).returncode,0)
            self.assertEqual(run(PYTHON,"scripts/finalize-verification.py",str(target),str(scan),env=env).returncode,0)
            self.assertEqual(run(PYTHON,"scripts/render-report.py",str(scan),env=env).returncode,0)
            report=json.loads((scan/"report/security-report.json").read_text());context=json.loads(context_path.read_text());self.assertEqual(report["execution_environment"],{"network":context["network"],"offline_package":context["offline_package"]})
            phase_status={phase:json.loads((scan/("repo-context" if phase=="recon" else phase)/"phase-manifest.json").read_text())["status"] for phase in ("recon","tool-collection","sast","campaign-planning","intrusion","synthesis","final-verification","report")};run_manifest=json.loads((scan/"run-manifest.json").read_text());run_manifest["status"]="running";run_manifest["phases"]=phase_status;write(scan/"run-manifest.json",run_manifest)
            tasks=[]
            for phase,task_id in (("recon","Recon"),("tool-collection","ToolCollection"),("sast","SASTLead"),("campaign-planning","CampaignPlanning"),("intrusion","Intrusion"),("synthesis","Synthesis"),("final-verification","FinalVerification"),("report","Report")):tasks.append({"id":task_id,"phase":phase,"status":phase_status[phase],"attempts":1,"artifact":f"{('repo-context' if phase=='recon' else phase)}/phase-manifest.json","updated_at":"now","error":None})
            write(scan/"task-ledger.json",{"schema_version":"2.0","run_id":"run","tasks":tasks})
            validated=run("bash","scripts/validate-scan.sh",str(scan),env=env);self.assertEqual(validated.returncode,0,validated.stderr)


class RuntimeIsolationTests(unittest.TestCase):
    def test_run_state_enforces_phase_exclusion_stable_retries_and_fail_closure(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            scan = Path(tmp) / "run"; scan.mkdir();
            phases = {phase: "pending" for phase in ("recon", "tool-collection", "sast", "campaign-planning", "intrusion", "synthesis", "final-verification", "report")}
            write(scan / "run-manifest.json", {"schema_version": "2.0", "workflow": "canonical-redteam-v2", "run_id": "run", "status": "initialized", "updated_at": "now", "phases": phases})
            write(scan / "task-ledger.json", {"schema_version": "2.0", "run_id": "run", "tasks": []})
            self.assertEqual(run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "running").returncode, 0)
            start_recon = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "recon", "--phase-status", "running", "--task", "Recon", "--task-phase", "recon", "--task-status", "running", "--increment-attempt")
            self.assertEqual(start_recon.returncode, 0, start_recon.stderr)
            duplicate = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "recon", "--phase-status", "running", "--task", "Recon", "--task-phase", "recon", "--task-status", "running", "--increment-attempt")
            self.assertNotEqual(duplicate.returncode, 0)
            overlap = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "tool-collection", "--phase-status", "running", "--task", "ToolCollection", "--task-phase", "tool-collection", "--task-status", "running", "--increment-attempt")
            self.assertNotEqual(overlap.returncode, 0)
            (scan / "repo-context").mkdir(); (scan / "repo-context/repo-context.json").write_text("{}\n")
            write(scan / "repo-context/phase-manifest.json", {"phase": "recon", "status": "ok"})
            close_recon = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "recon", "--phase-manifest", "repo-context/phase-manifest.json", "--task", "Recon", "--task-phase", "recon", "--artifact", "repo-context/repo-context.json")
            self.assertEqual(close_recon.returncode, 0, close_recon.stderr)
            start_tools = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "tool-collection", "--phase-status", "running", "--task", "ToolCollection", "--task-phase", "tool-collection", "--task-status", "running", "--increment-attempt")
            self.assertEqual(start_tools.returncode, 0, start_tools.stderr)
            failed = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "tool-collection", "--phase-status", "failed", "--task", "ToolCollection", "--task-phase", "tool-collection", "--task-status", "failed", "--error", "sanitized collector failure")
            self.assertEqual(failed.returncode, 0, failed.stderr)
            retry = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "tool-collection", "--phase-status", "running", "--task", "ToolCollection", "--task-phase", "tool-collection", "--task-status", "running", "--increment-attempt")
            self.assertEqual(retry.returncode, 0, retry.stderr)
            stop = run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "failed", "--error", "second collector failure")
            self.assertEqual(stop.returncode, 0, stop.stderr)
            manifest = json.loads((scan / "run-manifest.json").read_text()); ledger = json.loads((scan / "task-ledger.json").read_text())
            self.assertEqual(manifest["status"], "failed"); self.assertNotIn("running", manifest["phases"].values())
            self.assertFalse(any(item["status"] == "running" for item in ledger["tasks"]))
            tool = next(item for item in ledger["tasks"] if item["id"] == "ToolCollection")
            self.assertEqual(tool["attempts"], 2); self.assertIsNone(tool["artifact"])

    def test_tool_collection_refuses_unvalidated_recon_before_scanner_outputs(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base = Path(tmp); scan = base / "run"; target = base / "target"; target.mkdir(); (target / "main.py").write_text("pass\n"); (target / "go.sum").write_text("sum\n")
            fingerprint = run(PYTHON, "scripts/target-fingerprint.py", str(target)).stdout.strip(); context = base / "context.json"; env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
            initialized = run(PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target), "--scan-base", str(scan), "--run-id", "run", "--repo-name", "fixture", "--remote-url", "local", "--repo-id", "fixture", "--commit", "abc", "--depth", "quick", "--target-fingerprint", fingerprint, "--reproduction-mode", "off", "--model", "p/main", *ROLE_ARGS, "--verifier-model", "p/verifier", env=env)
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            write_minimal_recon(scan, target, "run", ["go.sum"])
            collected = run(PYTHON, "scripts/collect-tools.py", str(scan), "--context", str(context), env=env)
            self.assertNotEqual(collected.returncode, 0)
            phase = json.loads((scan / "tool-collection/phase-manifest.json").read_text())
            self.assertEqual(phase["status"], "failed"); self.assertEqual(phase["outputs"], [])
            self.assertFalse((scan / "tool-collection/collection.json").exists())

    def test_output_path_guard_rejects_unresolved_parent_traversal_and_symlinks(self) -> None:
        def guard(path: Path | str) -> subprocess.CompletedProcess[str]:
            return run(
                "bash",
                "-c",
                'source scripts/harness-lib.sh; harness_require_allowed_output "$1" "$2"',
                "guard",
                str(ROOT),
                str(path),
            )

        unique = f"missing-containment-{os.getpid()}"
        traversal = ROOT / "scans" / unique / ".." / ".." / "target" / "file"
        rejected = guard(traversal)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("parent component", rejected.stderr)

        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as scan_tmp, tempfile.TemporaryDirectory(dir=ROOT / ".harness") as target_tmp:
            scan = Path(scan_tmp)
            target = Path(target_tmp)
            target_file = target / "real.txt"
            target_file.write_text("do not overwrite\n")

            final_link = scan / "final-link"
            final_link.symlink_to(target_file)
            final_rejected = guard(final_link)
            self.assertNotEqual(final_rejected.returncode, 0)
            self.assertIn("must not be a symbolic link", final_rejected.stderr)

            directory_link = scan / "directory-link"
            directory_link.symlink_to(target, target_is_directory=True)
            trailing_rejected = guard(f"{directory_link}//")
            self.assertNotEqual(trailing_rejected.returncode, 0)
            self.assertIn("must not be a symbolic link", trailing_rejected.stderr)

            outside_dir = ROOT / "target"
            parent_link = scan / "parent-link"
            parent_link.symlink_to(outside_dir, target_is_directory=True)
            parent_rejected = guard(parent_link / "new-file")
            self.assertNotEqual(parent_rejected.returncode, 0)
            self.assertIn("approved harness output area", parent_rejected.stderr)

            normal = guard(scan / "missing" / "nested" / "artifact.json")
            self.assertEqual(normal.returncode, 0, normal.stderr)

            remediation = guard(ROOT / "remediations" / unique / "audit" / "run" / "patches" / "F-001.patch")
            self.assertEqual(remediation.returncode, 0, remediation.stderr)

    @unittest.skipUnless(all((ROOT/f"bins/{name}").is_file() for name in ("wraith","osv-scanner","poltergeist")) and (ROOT/".harness/osv-db").is_dir(), "offline scanner toolchain unavailable")
    def test_deterministic_tool_collection_runs_parallel_phase(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT/"scans") as tmp:
            base=Path(tmp);scan=base/"run";target=base/"target";target.mkdir();(target/"go.mod").write_text("module fixture\ngo 1.22\n");(target/"main.go").write_text("package main\nfunc main() {}\n");fingerprint=run(PYTHON,"scripts/target-fingerprint.py",str(target)).stdout.strip();context=base/"context.json";env={"VULNOPS_AUDIT_CONTEXT":str(context)}
            init=run(PYTHON,"scripts/init-run.py","--harness-root",str(ROOT),"--repo-path",str(target),"--scan-base",str(scan),"--run-id","run","--repo-name","fixture","--remote-url","local","--repo-id","fixture","--commit","abc","--depth","quick","--target-fingerprint",fingerprint,"--reproduction-mode","off","--model","p/main",*ROLE_ARGS,"--verifier-model","p/verifier",env=env);self.assertEqual(init.returncode,0,init.stderr)
            write_minimal_recon(scan, target, "run", ["go.mod"])
            collected=run(PYTHON,"scripts/collect-tools.py",str(scan),"--context",str(context),env=env);self.assertEqual(collected.returncode,0,collected.stderr)
            validated=run("bash","scripts/validate-phase.sh",str(scan),"tool-collection",env=env);self.assertEqual(validated.returncode,0,validated.stderr)
            collection=json.loads((scan/"tool-collection/collection.json").read_text());self.assertEqual(len(collection["receipts"]),2)
    @unittest.skipUnless((ROOT / "bins/codegraph").is_file(), "codegraph binary unavailable")
    def test_codegraph_indexes_snapshot_and_returns_real_relationship(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base=Path(tmp);source=base/"source";source.mkdir();(source/"main.go").write_text("package main\nfunc helper() {}\nfunc main() { helper() }\n");os.symlink("main.go",source/"alias.go")
            before=run(PYTHON,"scripts/target-fingerprint.py",str(source));self.assertEqual(before.returncode,0,before.stderr)
            env={"CODEGRAPH_TARGET_DIR":str(source),"CODEGRAPH_RUNTIME_DIR":str(base/"runtime")}
            setup=run("bash","scripts/setup-codegraph.sh",env=env);self.assertEqual(setup.returncode,0,setup.stderr)
            after=run(PYTHON,"scripts/target-fingerprint.py",str(source));self.assertEqual(after.stdout,before.stdout);self.assertFalse((source/".codegraph").exists());self.assertTrue((base/"runtime/project/alias.go").is_symlink())
            for operation,subject,expect_meaningful in (("query","helper",True),("callers","helper",True),("callees","main",True),("impact","helper",True),("affected","main.go",False)):
                out=base/operation;out.mkdir();adapter=run(PYTHON,"scripts/codegraph-adapter.py",operation,subject,"--project",str(base/"runtime/project"),"--output",str(out/"context.json"),"--receipt",str(out/"receipt.json"));self.assertEqual(adapter.returncode,0,f"{operation}: {adapter.stderr}");receipt=json.loads((out/"receipt.json").read_text());self.assertEqual(receipt["status"],"ok");self.assertEqual(receipt["meaningful"],expect_meaningful)
    def test_codegraph_rejects_symlink_that_escapes_target(self) -> None:
        if not (ROOT/"bins/codegraph").is_file():self.skipTest("codegraph binary unavailable")
        with tempfile.TemporaryDirectory(dir=ROOT/".harness") as tmp:
            base=Path(tmp);source=base/"source";source.mkdir();os.symlink("/etc/passwd",source/"outside")
            result=run("bash","scripts/setup-codegraph.sh",env={"CODEGRAPH_TARGET_DIR":str(source),"CODEGRAPH_RUNTIME_DIR":str(base/"runtime")});self.assertNotEqual(result.returncode,0);self.assertFalse((source/".codegraph").exists())
    def test_reproduction_probe_fails_closed_without_bubblewrap(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT/".harness") as tmp:
            bindir=Path(tmp)/"bin";bindir.mkdir();os.symlink("/usr/bin/uname",bindir/"uname")
            result=run("/bin/bash","scripts/probe-bubblewrap.sh",env={"PATH":str(bindir)})
            self.assertNotEqual(result.returncode,0);self.assertIn("unavailable",result.stderr)
        text=(ROOT/"scripts/run-safe-reproduction.sh").read_text().lower();self.assertNotIn("docker",text);self.assertNotIn("unsandboxed",text)
    def test_bubblewrap_containment_when_functionally_supported(self) -> None:
        result=run("bash","scripts/probe-bubblewrap.sh")
        if result.returncode:self.skipTest("functional bubblewrap namespaces unavailable on this host")
        self.assertEqual(result.stdout.strip(),"bubblewrap")


if __name__ == "__main__":
    unittest.main()
