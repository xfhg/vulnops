from __future__ import annotations

import json
import hashlib
import importlib.util
import os
import subprocess
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
sys.path.insert(0, str(ROOT / "scripts"))
from model_routing import audit_routing, load_routing
from objective_fixtures import objective_registry, objective_binding
from test_dossiers import add_dossier, review_dossier, seed_objective
from dossier_contract import objective_assessments
from test_run_lifecycle import activate_publisher
ROUTING = audit_routing(load_routing(ROOT))


def provenance(actor: str, artifact_ref: str, routing: dict = ROUTING) -> dict:
    return {"actor": actor, "selector": routing["agents"][actor], "artifact_ref": artifact_ref}


def caller_registry(question, effect, success):
    return objective_registry(["app.py:1-2"], local_key="caller-control",
        starting_actor="untrusted caller", controlled_material="handler argument",
        resource_scope="the service operation reached through the handler",
        desired_effect=effect, success_condition=success, security_question=question,
        route="public handler to service operation", proof_obligation=question,
        novelty_reason="Inspect the handler's concrete caller-to-service authority decision.")


def attribute_recon(scan: Path, routing: dict = ROUTING) -> None:
    owners = {"overview": "vulnops-recon-overview", "trust-boundaries": "vulnops-recon-trust",
              "input-surfaces": "vulnops-recon-inputs"}
    contributors = {}
    for name, actor in owners.items():
        ref = f"repo-context/research/{name}.json"
        document = json.loads((scan / ref).read_text())
        contributors[name] = provenance(actor, ref, routing)
        document["provenance"] = contributors[name]
        write(scan / ref, document)
    path = scan / "repo-context/security-surfaces.json"
    surfaces = json.loads(path.read_text())
    for key, owner in (("entry_points", "input-surfaces"), ("trust_boundaries", "trust-boundaries")):
        for item in surfaces.get(key, []):
            item["contributors"] = [contributors[owner]]
    write(path, surfaces)


def run(*args: str, input_text: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(args, cwd=ROOT, input=input_text, capture_output=True, text=True, check=False, env=merged)


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def resolution(outcome="contradicted", ref="repo-context/security-surfaces.json"):
    return {"outcome": outcome, "reason": "Inspected source establishes the scoped conclusion.",
            "next_action": "Retain this scoped conclusion for downstream assessment.", "evidence_refs": [ref], "missing_fact": ""}


def checkpoint(files=()):
    return {"established_facts": [], "contradicted_paths": [], "remaining_question": "",
            "files_reviewed": list(files), "next_step": "", "expected_results": []}


def attack_path(file):
    return {"id": "PATH-1", "starting_actor": "Library caller", "entry_surface_ids": ["EP-1"],
            "controlled_material": ["Function input"], "authority_decisions": [],
            "identity_propagation": [], "sensitive_effect": "Library result",
            "handoff_evidence": [], "unknowns": ["Authorization not inspected"],
            "source_refs": [f"{file}:1"]}


def transition(left, right):
    proof = {"outcome": "established", "reason": "Source proves the scoped transition.",
             "evidence_refs": ["sast/verified-findings.json"],
             "source_locations": [{"file": "app.py", "start_line": 1, "end_line": 3}]}
    return {"producer_id": left, "consumer_id": right,
            "resolution": resolution("established", "sast/verified-findings.json"),
            "obligations": {key: dict(proof) for key in ("producer_grant", "actor_control", "scope_alignment",
                "control_preservation", "consumer_authority", "intervening_controls", "conditions_compatible")}}


def write_minimal_recon(scan: Path, target: Path, run_id: str, dependency_files: list[str], *, accepted: bool = False) -> None:
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
        "attack_paths": [attack_path(entry_file)],
        "ignore_patterns": [], "generated_ignorable": [], "sensitive_data_types": [], "domain_tags": [], "warnings": [], "errors": [],
    }
    write(scan / "repo-context/repo-context.json", context)
    write(scan / "repo-context/security-surfaces.json", surfaces)
    (scan / "repo-context/repo.md").write_text("# Fixture\n")
    for name, worker in (("overview.json", "overview"), ("trust-boundaries.json", "trust-boundaries"), ("input-surfaces.json", "input-surfaces")):
        write(scan / "repo-context/research" / name, {"schema_version": "2.0", "worker": worker, "status": "ok", "started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z", "observations": [], "warnings": [], "errors": []})
    attribute_recon(scan)
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
    if accepted:
        started = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "recon",
                      "--phase-status", "running", "--task", "Recon", "--task-phase", "recon", "--increment-attempt")
        assert started.returncode == 0, started.stderr
        checkpoint = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", "recon",
                         "--phase-manifest", "repo-context/phase-manifest.json", "--task", "Recon",
                         "--task-phase", "recon", "--artifact", "repo-context/repo-context.json")
        assert checkpoint.returncode == 0, checkpoint.stderr


class EarlyPublisherOwnershipTests(unittest.TestCase):
    def test_active_owner_can_publish_empty_alternate_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            scan = base / "scan"
            context = {"run_id": "empty-sast", "attempt_id": "active", "scan_base": str(scan)}
            context_path = base / "context.json"
            write(context_path, context)
            env = activate_publisher(scan, context, "sast",
                                     {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path)})
            result = run(PYTHON, "scripts/finalize-sast.py", str(base / "unavailable-target"),
                         str(scan), "--advance-alternates", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((scan / "sast/validation-queue.json").read_text()), [])
            self.assertEqual(json.loads((scan / "sast/alternate-queue-state.json").read_text())["added_count"], 0)

    def test_completed_stale_and_foreign_commands_preserve_all_canonical_bytes(self):
        commands = [
            ("recon", "finalize-recon.py", (), True),
            ("tool-collection", "collect-tools.py", (), False),
            ("tool-collection", "finalize-tool-collection.py", (), False),
            ("sast", "finalize-sast.py", (), True),
            ("sast", "finalize-sast.py", ("--finalize",), True),
            ("sast", "finalize-sast.py", ("--advance-alternates",), True),
            ("campaign-planning", "build-evidence-index.py", (), False),
            ("campaign-planning", "build-campaign-plan.py", (), False),
            ("campaign-planning", "build-campaign-plan.py", ("--prepare-discovery",), False),
        ]
        for phase, script, flags, takes_target in commands:
            for refusal in ("complete", "accepted-phase", "foreign-run", "stale-attempt", "foreign-destination", "unowned"):
                with self.subTest(script=script, flags=flags, refusal=refusal), tempfile.TemporaryDirectory() as tmp:
                    base = Path(tmp).resolve()
                    scan = base / "scan"
                    target = base / "unavailable-target"
                    context_path = base / "context.json"
                    context = {"run_id": "protected-run", "attempt_id": "active-attempt",
                               "scan_base": str(scan), "repo_path": str(target)}
                    env = activate_publisher(scan, context, phase,
                                             {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path)})
                    directory = "repo-context" if phase == "recon" else phase
                    write(scan / directory / "phase-manifest.json", {"protected": "accepted metadata"})
                    for relative in ("repo-context/repo-context.json", "repo-context/repo.md",
                                     "tool-collection/collection.json", "tool-collection/summary.md",
                                     "sast/validation-queue.json", "sast/verified-findings.json",
                                     "campaign-planning/evidence-index.json", "campaign-planning/campaign-plan.json"):
                        write(scan / relative, {"protected": relative})
                    manifest_path = scan / "run-manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    if refusal == "complete":
                        manifest["status"] = "complete"
                    elif refusal == "accepted-phase":
                        manifest["phases"][phase] = "ok"
                    elif refusal == "foreign-run":
                        context["run_id"] = "foreign-run"
                    elif refusal == "stale-attempt":
                        context["attempt_id"] = "stale-attempt"
                    elif refusal == "foreign-destination":
                        context["scan_base"] = str(base / "foreign-scan")
                    else:
                        env["VULNOPS_RUNTIME_ROOT"] = str(base / "unowned-runtime")
                    write(manifest_path, manifest)
                    write(context_path, context)
                    before = {str(path.relative_to(scan)): path.read_bytes() for path in scan.rglob("*") if path.is_file()}
                    arguments = [PYTHON, str(ROOT / "scripts" / script)]
                    if takes_target:
                        arguments.append(str(target))
                    arguments.append(str(scan))
                    if script in {"collect-tools.py", "build-evidence-index.py", "build-campaign-plan.py"}:
                        arguments.extend(["--context", str(context_path)])
                    result = run(*arguments, *flags, env=env)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("publication", result.stderr)
                    self.assertEqual(before, {str(path.relative_to(scan)): path.read_bytes() for path in scan.rglob("*") if path.is_file()})


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


    def test_metadata_only_npm_lockfile_requires_proven_empty_v1_inventory(self) -> None:
        from dependency_contract import discover_dependency_files, is_metadata_only_npm_lockfile

        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            repo = Path(tmp)
            lockfile = repo / "package-lock.json"
            cases = [
                ('{"lockfileVersion":1}', True),
                ('{"name":"fixture","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{}}', True),
                ('{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.20"}}}', False),
                ('{"lockfileVersion":1,"dependencies":null}', False),
                ('{"lockfileVersion":1,"dependencies":[]}', False),
                ('{"lockfileVersion":true}', False),
                ('{"lockfileVersion":1.0}', False),
                ('{"lockfileVersion":2}', False),
                ('{"lockfileVersion":3,"packages":{}}', False),
                ('{"lockfileVersion":1,"packages":{}}', False),
                ('{"lockfileVersion":1,"name":null}', False),
                ('{"lockfileVersion":1,"version":1}', False),
                ('{"lockfileVersion":1,"requires":1}', False),
                ('{"lockfileVersion":1,"dependencies":{"lodash":{}},"dependencies":{}}', False),
                ('{"lockfileVersion":1,"lockfileVersion":1}', False),
                ('{"lockfileVersion":1,', False),
                ('[]', False),
                ('{}', False),
            ]
            for content, expected in cases:
                with self.subTest(content=content):
                    lockfile.write_text(content)
                    self.assertEqual(is_metadata_only_npm_lockfile(lockfile), expected)
                    self.assertEqual(discover_dependency_files(repo), ["package-lock.json"])
            lockfile.write_bytes(b"\xff")
            self.assertFalse(is_metadata_only_npm_lockfile(lockfile))
            self.assertFalse(is_metadata_only_npm_lockfile(repo / "missing/package-lock.json"))
            other = repo / "yarn.lock"
            other.write_text('{"lockfileVersion":1}')
            self.assertFalse(is_metadata_only_npm_lockfile(other))

    def test_requirements_dispositions_do_not_guess_from_filename_or_syntax(self) -> None:
        from dependency_contract import discover_dependency_files, requirements_input_disposition

        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            repo = Path(tmp)
            path = repo / "requirements.txt"
            for data in (b"", b" \r\n# dependency notes\n", b"\xef\xbb\xbf# placeholder\n"):
                path.write_bytes(data)
                self.assertEqual(requirements_input_disposition(path), "requirements_no_dependency_inventory")
                self.assertEqual(discover_dependency_files(repo), ["requirements.txt"])
            for content in (
                "requests==2.19.0\n", "pytest>=7.4.0\n", "requests\n",
                'requests[security]>=2; python_version >= "3.9"\n',
                "-r other.txt\n", "-c constraints.txt\n", "--index-url https://example.invalid/simple\n",
                "-e ./local\n", "pkg @ https://example.invalid/pkg.whl\n",
                "git+https://example.invalid/repo.git#egg=pkg\n",
                "./local\n", "--require-hashes\n", "requests==2.19.0 \\\n --hash=sha256:abc\n",
                "requests==\n", "not valid requirement syntax\n",
                "HTTP Status Code 400\nRequest/Response field mapping\n",
            ):
                with self.subTest(content=content):
                    path.write_text(content)
                    self.assertIsNone(requirements_input_disposition(path))
            path.write_bytes(b"\xff")
            self.assertIsNone(requirements_input_disposition(path))
            path.unlink()
            with self.assertRaises(OSError):
                requirements_input_disposition(path)

    def test_requirements_review_is_bound_to_exact_content(self) -> None:
        from dependency_contract import load_requirements_input_reviews, requirements_input_disposition

        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            repo = Path(tmp)
            path = repo / "requirements.txt"
            prose = b"HTTP Status Code 400\nRequest/Response field mapping\n"
            path.write_bytes(prose)
            digest = hashlib.sha256(prose).hexdigest()
            config = repo / "config.toml"
            config.write_text(
                '[[harness.scans.reviewed_non_dependency_requirements]]\n'
                f'path = "requirements.txt"\nsha256 = "{digest}"\n'
                'reason = "Reviewed business requirements, not Python dependencies."\n'
            )
            reviews = load_requirements_input_reviews(config)
            self.assertEqual(requirements_input_disposition(path, reviews[path.name]), "requirements_reviewed_non_dependency")
            for changed in (b"requests==2.19.0\n", prose + b"Additional requirement\n"):
                path.write_bytes(changed)
                self.assertIsNone(requirements_input_disposition(path, reviews[path.name]))
            config.write_text("")
            self.assertEqual(load_requirements_input_reviews(config), {})

    def test_requirements_review_configuration_rejects_unsafe_or_ambiguous_entries(self) -> None:
        from dependency_contract import load_requirements_input_reviews

        entry = {"path": "docs/requirements.txt", "sha256": "a" * 64, "reason": "Reviewed non-dependency document."}
        cases = [
            [{**entry, "path": "../requirements.txt"}],
            [{**entry, "path": "/requirements.txt"}],
            [{**entry, "path": "docs\\requirements.txt"}],
            [{**entry, "path": "docs/package-lock.json"}],
            [{**entry, "sha256": "not-a-digest"}],
            [{**entry, "reason": ""}],
            [{**entry, "reason": "unprintable\nreason"}],
            [{**entry, "reason": "x" * 501}],
            [{**entry, "path": False}],
            [{**entry, "unknown": "field"}],
            [entry, entry],
        ]
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            config = Path(tmp) / "config.toml"
            for entries in cases:
                text = ""
                for item in entries:
                    text += "[[harness.scans.reviewed_non_dependency_requirements]]\n"
                    text += "".join(f"{key} = {json.dumps(value)}\n" for key, value in item.items())
                config.write_text(text)
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    load_requirements_input_reviews(config)
            for text in (
                "[harness.scans]\nreviewed_non_dependency_requirements = true\n",
                "[harness.scans]\nreviewed_non_dependency_requirements = [1]\n",
                "[harness]\nscans = false\n",
            ):
                config.write_text(text)
                with self.assertRaises(ValueError):
                    load_requirements_input_reviews(config)

    def test_bundled_scanner_incompatible_inputs_are_omitted_and_reported(self) -> None:
        scripts_path = str(ROOT / "scripts")
        sys.path.insert(0, scripts_path)
        try:
            import dependency_contract
        finally:
            sys.path.remove(scripts_path)

        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            repo = Path(tmp)
            fixtures = {
                "maven/pom.xml": "<project><dependencies><dependency/></dependencies></project>",
                "haskell/cabal.project.freeze": "constraints: any.base ==4.18.0.0",
            }
            (repo / "go.mod").write_text("module fixture\ngo 1.22\n")
            for relative, content in fixtures.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)

            discovered = dependency_contract.discover_dependency_files(repo)
            self.assertEqual(discovered, ["go.mod"])
            limitations = dependency_contract.discover_dependency_limitations(repo)
            unsupported = next(item for item in limitations if item["code"] == "bundled_scanner_input_unsupported")
            self.assertEqual(unsupported["files"], sorted(fixtures))
            for relative in fixtures:
                self.assertFalse(dependency_contract.is_scannable_dependency_path(repo / relative))

    @unittest.skipUnless(all((ROOT / f"bins/{name}").is_file() for name in ("wraith", "osv-scanner")) and (ROOT / ".harness/osv-db").is_dir(), "offline scanner toolchain unavailable")
    def test_wraith_wrapper_rejects_no_package_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp)
            pom = base / "pom.xml"
            pom.write_text("<project><modelVersion>4.0.0</modelVersion><packaging>pom</packaging></project>")
            output = base / "out.json"
            receipt = base / "receipt.json"
            wrapped = run("bash", "scripts/run-wraith.sh", str(base), str(pom), str(output), str(receipt))
            self.assertEqual(wrapped.returncode, 73, wrapped.stderr)
            self.assertIn("unexpected_diagnostics", wrapped.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(receipt.exists())
            supported = base / "go.mod"
            supported.write_text("module fixture\ngo 1.22\n")
            accepted = run("bash", "scripts/run-wraith.sh", str(base), str(supported), str(output), str(receipt))
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(receipt.read_text())["status"], "ok")

    def test_recon_finalizer_replaces_model_dependency_guesses_with_complete_discovery(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base = Path(tmp); scan = base / "run"; target = base / "target"; target.mkdir()
            (target / "main.go").write_text("package main\n"); (target / "go.mod").write_text("module fixture\ngo 1.22\n"); (target / "go.sum").write_text("sum\n"); (target / "package.json").write_text("{}\n")
            (target / "aggregate").mkdir(); (target / "aggregate/pom.xml").write_text("<project><packaging>pom</packaging><modules><module>child</module></modules></project>")
            (target / "aggregate/child").mkdir(); (target / "aggregate/child/pom.xml").write_text("<project><dependencies><dependency/></dependencies></project>")
            context = base / "context.json"; env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
            initialized = run(PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target), "--scan-base", str(scan), "--run-id", "run", "--repo-name", "fixture", "--remote-url", "local", "--repo-id", "fixture", "--commit", "abc", "--depth", "quick", "--reproduction-mode", "off", env=env)
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            write_minimal_recon(scan, target, "run", ["go.sum", "package.json"])
            rejected = run(PYTHON, "scripts/validate-json.py", "schemas/v2/repo-context.schema.json",
                           str(scan / "repo-context/repo-context.json"), "--semantic", "repo-context", "--target", str(target))
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not a supported Wraith input", rejected.stderr)
            env = activate_publisher(scan, json.loads(context.read_text()), "recon", env)
            finalized = run(PYTHON, "scripts/finalize-recon.py", str(target), str(scan), env=env)
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            document = json.loads((scan / "repo-context/repo-context.json").read_text())
            self.assertEqual(document["projects"][0]["dependency_files"], ["go.mod"])
            validated = run("bash", "scripts/validate-phase.sh", str(scan), "recon", env=env)
            self.assertEqual(validated.returncode, 0, validated.stderr)

    def test_hunt_plan_publishes_consistent_hash_bound_packets(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); target = base / "target"; target.mkdir(); (target / "app.py").write_text("def handle(value):\n    return value\n")
            scan = base / "scan"; (scan / "sast/hunt-tasks").mkdir(parents=True)
            context_path = base / "context.json"
            write(context_path, {"schema_version": "2.0", "run_id": "run", "depth": "quick", "repo_path": str(target), "scan_base": str(scan), "repositories": [{"path": "."}]})
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
            threat = json.loads((scan / "sast/threat-model.json").read_text())
            registry = caller_registry("Can caller input reach an unsafe interpreter?", "Run caller-controlled instructions", "Caller-controlled input is interpreted as instructions in the handler's authority.")
            threat.update(registry)
            threat["hunt_mappings"][0].update(objective_binding(registry))
            write(scan / "sast/threat-model.json", threat)
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
            normalizer_args = (PYTHON, "scripts/normalize-wraith.py", "--repo", str(base), "--lockfile", str(base / "go.mod"), *database_args)
            result = run(*normalizer_args, "--scanner-exit-status", "1", "--output", str(base / "out.json"), "--receipt", str(base / "receipt.json"), input_text=json.dumps(raw))
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads((base / "out.json").read_text())
            self.assertEqual(output["advisory_count"], 1)
            self.assertNotIn("Details", json.dumps(output))
            raw["vulnerability_count"] = 2
            bad = run(*normalizer_args, "--scanner-exit-status", "1", "--output", str(base / "bad.json"), "--receipt", str(base / "bad-receipt.json"), input_text=json.dumps(raw))
            self.assertNotEqual(bad.returncode, 0)
            positive_with_zero_status = run(*normalizer_args, "--scanner-exit-status", "0", "--output", str(base / "contradict-positive.json"), "--receipt", str(base / "contradict-positive-receipt.json"), input_text=json.dumps({**raw, "vulnerability_count": 1}))
            self.assertNotEqual(positive_with_zero_status.returncode, 0)
            self.assertFalse((base / "contradict-positive-receipt.json").exists())
            empty_envelope = {"package_count": 0, "vulnerability_count": 0, "results": None}
            empty = run(*normalizer_args, "--scanner-exit-status", "0", "--output", str(base / "empty.json"), "--receipt", str(base / "empty-receipt.json"), input_text=json.dumps(empty_envelope))
            self.assertEqual(empty.returncode, 0, empty.stderr)
            empty_with_one_status = run(*normalizer_args, "--scanner-exit-status", "1", "--output", str(base / "contradict-empty.json"), "--receipt", str(base / "contradict-empty-receipt.json"), input_text=json.dumps(empty_envelope))
            self.assertNotEqual(empty_with_one_status.returncode, 0)
            self.assertFalse((base / "contradict-empty-receipt.json").exists())

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
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp); scan = base / "scan"; context = base / "context.json"
            target = base / "target"; target.mkdir()
            (target / "app.py").write_text("one\ntwo\nthree\n")
            (target / "go.mod").write_text("module fixture\n")
            write(context, {"run_id": "run", "scan_base": str(scan), "repo_path": str(target),
                            "workflow": "canonical-redteam-v2"})
            tool_dir = scan / "tool-collection"
            normalized = run(PYTHON, "scripts/normalize-wraith.py", "--repo", str(target),
                             "--lockfile", str(target / "go.mod"), "--ecosystem", "Go",
                             "--database-snapshot", "fixture", "--database-sha256", "a" * 64,
                             "--scanner-exit-status", "0", "--output", str(tool_dir / "sca-advisories.json"),
                             "--receipt", str(tool_dir / "wraith-receipt.json"),
                             input_text=json.dumps({"package_count": 0, "vulnerability_count": 0, "results": []}))
            self.assertEqual(normalized.returncode, 0, normalized.stderr)
            match = {"file_path": str(target / "app.py"), "line_number": 1,
                     "rule_name": "API Key", "rule_id": "api-key"}
            raw = base / "scanner.json"
            write(raw, {"summary": {"matches_found": 4}, "results": [
                match, match, {**match, "line_number": 2}, {**match, "line_number": 3}]})
            normalized = run(PYTHON, "scripts/normalize-poltergeist.py", "--target", str(target),
                             "--input", str(raw), "--scanner-exit", "1",
                             "--output", str(tool_dir / "secrets-redacted.json"),
                             "--receipt", str(tool_dir / "poltergeist-receipt.json"))
            self.assertEqual(normalized.returncode, 0, normalized.stderr)
            secrets = json.loads((tool_dir / "secrets-redacted.json").read_text())
            self.assertEqual(len(secrets["candidates"]), 3)
            write(tool_dir / "dependency-limitations.json", {"schema_version": "2.0", "limitations": []})
            env = activate_publisher(scan, json.loads(context.read_text()), "tool-collection",
                                     {"VULNOPS_AUDIT_CONTEXT": str(context)})
            result = run(PYTHON, "scripts/finalize-tool-collection.py", str(scan), env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest_doc = json.loads((scan / "tool-collection/phase-manifest.json").read_text())
            collection_doc = json.loads((scan / "tool-collection/collection.json").read_text())
            self.assertEqual(manifest_doc["status"], "ok")
            self.assertEqual(manifest_doc["warnings"], [])
            self.assertEqual(manifest_doc["coverage"]["secret_matches"], 4)
            self.assertEqual(manifest_doc["coverage"]["secret_candidates"], 3)
            self.assertEqual(collection_doc["warnings"], [])
            validated = run("bash", "scripts/validate-phase.sh", str(scan), "tool-collection", env=env)
            self.assertEqual(validated.returncode, 0, validated.stderr)


class PrimitiveCampaignTests(unittest.TestCase):
    def fixture(self, base: Path) -> tuple[Path, Path]:
        scan = base / "scan"; target = base / "target"; target.mkdir(); (target / "app.py").write_text("def entry():\n    return sink()\ndef sink():\n    return 1\n")
        context = {"schema_version": "2.0", "run_id": "run", "depth": "quick", "model_routing": ROUTING, "repo_path": str(target), "scan_base": str(scan), "repositories": [{"path": "."}]}
        context["attempt_id"] = "primitive-attempt"
        write(base / "context.json", context)
        environment = mock.patch.dict(os.environ, activate_publisher(scan, context, "campaign-planning", os.environ))
        environment.start()
        self.addCleanup(environment.stop)
        registry = caller_registry("Can an unauthenticated caller acquire user access?", "Acquire unauthorized user access", "A remote caller reaches a user operation without the required authentication.")
        write(scan / "sast/threat-model.json", registry)
        write(scan / "repo-context/security-surfaces.json", {"entry_points": [{"id": "EP-1", "kind": "http", "path": "app.py", "trust_boundary_ids": ["TB-1"]}], "trust_boundaries": [{"id": "TB-1", "source_trust": "remote", "target_trust": "service", "description": "remote to service"}]})
        for name, worker in (("overview", "overview"), ("trust-boundaries", "trust-boundaries"), ("input-surfaces", "input-surfaces")):
            write(scan / f"repo-context/research/{name}.json", {"worker": worker})
        attribute_recon(scan)
        hunt = provenance("vulnops-deepdive-chunk", "sast/deepdive/T-1.json")
        review = provenance("vulnops-verify-one", "sast/verify/C-1.json")
        write(scan / hunt["artifact_ref"], {"provenance": hunt})
        review_result = {"id": "V-C-1", "candidate_id": "C-1", "status": "source_verified", "provenance": review}
        review_result["assessment_context"] = {"attempt_id": context["attempt_id"]}
        write(scan / review["artifact_ref"], review_result)
        write(scan / "sast/validation-results.json", [review_result])
        write(scan / "tool-collection/sca-advisories.json", {"advisories": [{"id": "SCA-1111111111111111", "advisory_id": "OSV-1", "package": "lib", "version": "1", "source_lockfile": "go.mod"}]})
        write(scan / "tool-collection/secrets-redacted.json", {"candidates": [{"id": "SEC-1111111111111111", "type": "token", "file": "app.py", "exposure_path": "source"}]})
        verified = {"id": "C-1", "title": "Known auth bypass", "verification_level": "source_verified", "attacker": {"starting_access": "remote", "boundary_crossed": "auth"}, "impact": "user access", "root_cause_location": {"file": "app.py"}, "conditions": [], "evidence_refs": ["app.py:1"]}
        verified["assessment_context"] = {"attempt_id": context["attempt_id"]}
        verified["contributors"] = [hunt, review]
        verified.update(objective_binding(registry))
        candidate = {**verified, "contributors": [hunt]}
        write(scan / "sast/validation-queue.json", [candidate])
        write(scan / "sast/verified-findings.json", [verified]); write(scan / "sast/dropped-findings.json", []); write(scan / "sast/raw-findings.json", [candidate])
        write(scan / "sast/coverage-ledger.json", {**registry, "cells": [{"id": "CELL-1", **objective_binding(registry), "status": "depth_limited", "reason": "configured audit depth reached"}]})
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
            known_ids={p["id"] for p in index["primitives"] if p["trust"]=="confirmed"}
            self.assertTrue(known_ids.intersection(pid for campaign in plan["campaigns"] for pid in campaign["primitive_ids"]))

    def test_idless_hardening_and_positive_patterns_receive_unique_ids(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            scan, context = self.fixture(Path(tmp))
            write(scan / "sast/hardening-notes.json", [{"description": "first"}, {"description": "second"}])
            write(scan / "sast/positive-patterns.json", [{"description": "third"}, {"description": "fourth"}])

            built = run(PYTHON, "scripts/build-evidence-index.py", str(scan), "--context", str(context))
            self.assertEqual(built.returncode, 0, built.stderr)
            index = json.loads((scan / "campaign-planning/evidence-index.json").read_text())
            records = [
                record
                for record in index["records"]
                if record["source_kind"] in {"hardening", "positive_pattern"}
            ]
            self.assertEqual(len(records), 4)
            self.assertEqual(len({record["id"] for record in records}), 4)
            self.assertEqual({record["summary"] for record in records}, {"first", "second", "third", "fourth"})
            planned = run(PYTHON, "scripts/build-campaign-plan.py", str(scan), "--context", str(context))
            self.assertEqual(planned.returncode, 0, planned.stderr)
            plan = json.loads((scan / "campaign-planning/campaign-plan.json").read_text())
            dispositions = {row["evidence_id"]: row for row in plan["evidence_dispositions"]}
            for record in records:
                with self.subTest(description=record["summary"]):
                    self.assertIn(record["id"], dispositions)
                    self.assertEqual(dispositions[record["id"]]["campaign_ids"], [])
            self.assertEqual(plan["coverage"]["evidence_records"], len(index["records"]))

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
    primary = "openai-codex/gpt-6-astra:high"
    verifier = "openai-codex/gpt-daybreak-red-latest:high"
    contributors = [
        {"actor": "vulnops-deepdive-chunk", "selector": verifier, "artifact_ref": "sast/deepdive/T-001.json"},
        {"actor": "vulnops-intrusion-campaign", "selector": verifier, "artifact_ref": "intrusion/results/CAM-001.json"},
    ]

    def finding(self) -> dict:
        return add_dossier({
            "id": "F-001", "finding_kind": "chain", "origin": "composite_chain", "title": "Known primitives compose into account takeover", "category": "attack-chain", "severity": "high", "risk_score": 85, "confidence": "high", "status": "verified",
            "attacker": {"perspective": "remote user", "starting_access": "remote input", "boundary_crossed": "authentication"}, "intended_behavior": "Each boundary should prevent privilege acquisition.",
            "root_causes": [{"file": "app.py", "line": 1, "scope": "entry", "mechanism": "first primitive"}, {"file": "app.py", "line": 3, "scope": "sink", "mechanism": "second primitive"}],
            "trace": [{"kind": "entrypoint", "file": "app.py", "line": 1, "scope": "entry", "description": "attacker enters"}, {"kind": "sink", "file": "app.py", "line": 3, "scope": "sink", "description": "privilege gained"}],
            "conditions": ["both verified primitives are reachable"], "impact": "account takeover", "remediation": "break both capability transitions",
            "verification": {"level": "source_verified", "actor": "vulnops-synthesis", "model": self.primary, "source_validation_refs": ["sast/deepdive/T-001.json"], "reproduction_ref": None},
            "contributors": self.contributors,
            "primitive_steps": [{"primitive_id": "P-AAAAAAAAAAAA", "input_capability": "remote input", "output_capability": "valid session", "boundary_crossed": "session", "evidence_refs": ["sast/verified-findings.json:C-1"]}, {"primitive_id": "P-BBBBBBBBBBBB", "input_capability": "valid session", "output_capability": "admin access", "boundary_crossed": "authorization", "evidence_refs": ["intrusion/intrusion-results.json:CAM-001"]}],
            "transitions": [transition("P-AAAAAAAAAAAA", "P-BBBBBBBBBBBB")],
            "source_refs": [{"kind": "sast", "source_id": "C-1", "artifact_ref": "sast/verified-findings.json:C-1"}, {"kind": "intrusion", "source_id": "CAM-001", "artifact_ref": "intrusion/intrusion-results.json:CAM-001"}], "graph_receipt_refs": [], "closure_rationale": "Both known primitives form a newly proven end-to-end path.", "dependency": None, "secret": None,
        })

    def test_finalizer_requires_ordered_verification_of_every_chain_step(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base=Path(tmp);scan=base/"scan";target=base/"target";target.mkdir();(target/"app.py").write_text("def entry():\n    pass\ndef sink():\n    pass\n")
            from scripts.model_routing import GROUP_AGENTS, audit_routing, resolve_routing
            routing = audit_routing(resolve_routing({"routing": {
                group: self.primary if group in {"audit_lead", "recon", "synthesis"} else self.verifier
                for group in GROUP_AGENTS
            }}))
            context={"run_id":"run","attempt_id":"chain-attempt","model_routing":routing,"scan_base":str(scan),"repo_path":str(target),"repositories":[{"path":"."}]};write(base/"context.json",context)
            seed_objective(scan, "app.py:1-4")
            write(scan/"synthesis/findings.json",{"schema_version":"2.0","run_id":"run","findings":[self.finding()], "objective_assessments": objective_assessments(scan,[self.finding()])})
            result={"schema_version":"2.0","finding_id":"F-001","status":"verified","closure_reason":"all claims hold","evidence_refs":["synthesis/findings.json:F-001"],"primitive_results":[{"primitive_id":"P-AAAAAAAAAAAA","status":"verified","evidence_refs":["sast/verified-findings.json:C-1"],"reason":"holds"},{"primitive_id":"P-BBBBBBBBBBBB","status":"verified","evidence_refs":["intrusion/intrusion-results.json"],"reason":"holds"}],"corrections":[],"corrected_finding":None,"actor":"vulnops-independent-verify-one","model":self.verifier,"model_diversity":False}
            result["assessment_context"] = {"attempt_id": context["attempt_id"]}
            result["evidence_refs"].append("app.py:1-4")
            result["transition_results"] = self.finding()["transitions"]
            result["joint_conditions"] = resolution("established", "sast/verified-findings.json")
            for provenance in self.contributors:
                write(scan / provenance["artifact_ref"], {"provenance": provenance})
            write(scan/"sast/verified-findings.json", [{"id": "C-1", "contributors": [self.contributors[0]]}])
            write(scan/"sast/validation-results.json", [])
            write(scan/"intrusion/intrusion-results.json", {"results": [{"campaign_id": "CAM-001", "provenance": self.contributors[1], "primitive_updates": []}]})
            write(scan/"campaign-planning/evidence-index.json", {"primitives": [
                {"id": pid, "contributors": [self.contributors[index]], "capability": {"evidence_status": "source_established"}}
                for index, pid in enumerate(("P-AAAAAAAAAAAA", "P-BBBBBBBBBBBB"))]})
            review_dossier(self.finding(), result)
            write(scan/"final-verification/results/F-001.json",result)
            env={"VULNOPS_AUDIT_CONTEXT":str(base/"context.json")}
            env = activate_publisher(scan, context, "final-verification", env)
            good=run(PYTHON,"scripts/finalize-verification.py",str(target),str(scan),env=env);self.assertEqual(good.returncode,0,good.stderr)
            final=json.loads((scan/"final-verification/findings.json").read_text());self.assertEqual(final["findings"][0]["origin"],"composite_chain");self.assertFalse(final["findings"][0]["model_diversity"])
            self.assertEqual(final["findings"][0]["contributors"], self.contributors)
            self.assertEqual(final["diversity_counts"], {"diverse": 0, "same_model": 1, "total": 1})
            for label, primitive_results, transition_results in (
                ("missing step", result["primitive_results"][:-1], result["transition_results"]),
                ("reordered steps", list(reversed(result["primitive_results"])), result["transition_results"]),
                ("missing transition", result["primitive_results"], []),
            ):
                with self.subTest(case=label):
                    invalid = {**result, "primitive_results": primitive_results, "transition_results": transition_results}
                    write(scan / "final-verification/results/F-001.json", invalid)
                    bad = run(PYTHON, "scripts/finalize-verification.py", str(target), str(scan), env=env)
                    self.assertNotEqual(bad.returncode, 0)
                    self.assertIn("primitive" if label != "missing transition" else "transition", bad.stderr)

    @unittest.skipUnless((ROOT / "bins/codegraph").is_file(), "codegraph binary unavailable")
    def test_intrusion_records_all_queries_but_cites_only_meaningful_graphs(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT/".harness") as tmp:
            base=Path(tmp);scan=base/"scan";context_path=base/"context.json"
            source=base/"source";source.mkdir();(source/"app.go").write_text("package main\nfunc helper() {}\n")
            runtime=base/"runtime"
            setup=run("bash","scripts/setup-codegraph.sh",env={"CODEGRAPH_TARGET_DIR":str(source),"CODEGRAPH_RUNTIME_DIR":str(runtime)})
            self.assertEqual(setup.returncode,0,setup.stderr)
            context={"run_id":"run","attempt_id":"graph-attempt","model_routing":ROUTING,"codegraph_mode":"enabled","scan_base":str(scan),
                     "repo_path":str(source),"source_root":str(source),"paths":{"codegraph_project":str(runtime/"project"),
                     "codegraph_runtime":str(runtime)}}
            sys.path.insert(0,str(ROOT/"scripts"))
            from intrusion_contract import build_wave, reference
            from harness_contract import resolved_intrusion_budget
            from campaign_contract import BUDGETS
            context["depth"] = "quick"
            context["intrusion_budget"]=resolved_intrusion_budget("quick")
            context["repositories"] = [{"path": "."}]
            write(context_path,context)
            registry=objective_registry(["app.go:1"],local_key="graph-reachability",starting_actor="caller",
                controlled_material="entry argument",resource_scope="helper",desired_effect="reach helper without authority",
                success_condition="caller reaches protected helper",security_question="Is helper reachable?",
                route="entry to helper",proof_obligation="source-backed call path",novelty_reason="initial reachability question")
            write(scan/"sast/threat-model.json",registry)
            campaign={"id":"CAM-001",**objective_binding(registry),"graph_questions":[{"id":"Q-001","type":"callers","subject":"helper","file":"app.go","reason":"Inspect attacker reachability."}]}
            write(scan/"campaign-planning/campaign-plan.json",{"schema_version":"2.0","run_id":"run","budget":BUDGETS["quick"],**registry,"campaigns":[campaign]})
            write(scan/"campaign-planning/evidence-index.json",{"primitives":[]})
            write(scan/"run-manifest.json",{"run_id":"run","attempt_id":"graph-attempt","model_routing":ROUTING,"status":"incomplete","phases":{"intrusion":"running"}})
            env = activate_publisher(scan, context, "intrusion",
                                     {**os.environ, "VULNOPS_AUDIT_CONTEXT": str(context_path),
                                      "VULNOPS_RUNTIME_ROOT": str(base / "run-runtime")})
            environment = mock.patch.dict(os.environ, env)
            environment.start()
            self.addCleanup(environment.stop)
            wave=build_wave(scan,source,context)
            query=run("bash","scripts/run-codegraph.sh","--context",str(context_path),"--phase","intrusion","--owner","CAM-001","--question","Q-001")
            self.assertEqual(query.returncode,0,query.stderr)
            ref="intrusion/codegraph-runs/CAM-001/Q-001/receipt.json"
            result={"schema_version":"2.0","campaign_id":"CAM-001","status":"closed","conclusion":"No source-backed exploit established.",
                    "evidence_refs":["campaign-planning/campaign-plan.json:CAM-001"],"graph_query_receipts":[ref],
                    "graph_evidence_refs":[],"graph_answers":[],"graph_limitations":["No useful callers returned; continue source-only."],"primitive_updates":[],"candidates":[]}
            result["assessment_context"] = {"attempt_id": context["attempt_id"]}
            result.update(objective_binding(registry))
            result["provenance"] = provenance("vulnops-intrusion-campaign", "intrusion/results/CAM-001.json")
            result.update(wave=0,input_snapshot=reference(scan,wave),resolution=resolution("contradicted","campaign-planning/campaign-plan.json"),
                          composition={"outcome":"none_actionable","reason":"No source-backed consumer found.","evidence_refs":["campaign-planning/campaign-plan.json"],"primitive_ids":[]})
            result["graph_evidence_refs"] = [ref]
            write(scan / "intrusion/results/CAM-001.json", result)
            with self.assertRaisesRegex(ValueError, "non-meaningful graph evidence"):
                build_wave(scan, source, context, ["CAM-001"])
            result["graph_evidence_refs"] = []
            write(scan / "intrusion/results/CAM-001.json", result)
            build_wave(scan,source,context,["CAM-001"])
            good=run(PYTHON,"scripts/finalize-intrusion.py",str(scan),env=env);self.assertEqual(good.returncode,0,good.stderr)


    def test_campaign_planning_omits_graph_questions_when_codegraph_disabled(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp)
            scan = base / "scan"
            context = base / "context.json"
            source = base / "source"
            source.mkdir()
            (source / "app.py").write_text("def entry():\n    return 1\n")
            write(context, {"run_id": "run", "depth": "balanced", "model_routing": ROUTING, "codegraph_mode": "disabled",
                            "scan_base": str(scan), "source_root": str(source), "repositories": [{"path": "."}]})
            record_id = "E-AAAAAAAAAAAA"
            researcher = provenance("vulnops-recon-inputs", "repo-context/research/input-surfaces.json")
            write(scan / researcher["artifact_ref"], {"provenance": researcher})
            registry = caller_registry("Can caller data cross the handler boundary?", "Change a protected service result", "Untrusted data changes a service operation under its authority.")
            write(scan / "sast/threat-model.json", registry)
            write(scan / "campaign-planning/evidence-index.json", {
                "schema_version": "2.0", "run_id": "run", "warnings": [], **registry,
                "records": [{"id": record_id, "source_kind": "recon", "source_id": "EP-1",
                             **objective_binding(registry),
                             "artifact_ref": "repo-context/security-surfaces.json", "disposition": "unresolved",
                             "summary": "boundary", "files": ["app.py"], "source_anchors": [],
                             "subsystems": [], "anchor_limitations": [], "contributors": [researcher]}],
                "primitives": [],
                "coverage_gaps": [],
            })
            env = activate_publisher(scan, json.loads(context.read_text()), "campaign-planning", os.environ)
            built = run(PYTHON, "scripts/build-campaign-plan.py", str(scan), "--context", str(context), env=env)
            self.assertEqual(built.returncode, 0, built.stderr)
            plan = json.loads((scan / "campaign-planning/campaign-plan.json").read_text())
            self.assertEqual([campaign["starting_evidence"] for campaign in plan["campaigns"]], [[record_id]])
            self.assertTrue(all(not campaign["graph_questions"] for campaign in plan["campaigns"]))

class GreenfieldContractTests(unittest.TestCase):
    def test_empty_source_only_pipeline_accepts_checkpoints_and_reports_limitations(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base=Path(tmp);scan=base/"run";target=base/"target";target.mkdir();(target/"app.py").write_text("def entry():\n    return 1\n")
            context_path=base/"context.json"
            init=[PYTHON,"scripts/init-run.py","--harness-root",str(ROOT),"--repo-path",str(target),"--scan-base",str(scan),"--run-id","run","--repo-name","fixture","--remote-url","local","--repo-id","fixture-id","--commit","abc","--depth","quick","--reproduction-mode","off"]
            network_mode = tomllib.loads((ROOT / "config.toml").read_text()).get("harness", {}).get("network", {}).get("linux_agent_egress", "enforced")
            init.extend(["--network-mode", network_mode, "--codegraph-mode", "disabled",
                         "--codegraph-limitation", "Codegraph unavailable; source-only inspection continues."])
            env = {"VULNOPS_AUDIT_CONTEXT": str(context_path),
                   "VULNOPS_RUNTIME_ROOT": str(base / "runtime"), "VULNOPS_LAUNCHER_PID": str(os.getpid())}
            created = run(*init, env=env)
            self.assertEqual(created.returncode, 0, created.stderr)
            environment = mock.patch.dict(os.environ, env)
            environment.start()
            self.addCleanup(environment.stop)
            from run_lifecycle import AUDIT_TASK_PHASES
            tasks = {phase: task for task, phase in AUDIT_TASK_PHASES.items()}
            def begin(phase):
                result = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", phase,
                             "--phase-status", "running", "--task", tasks[phase], "--task-phase", phase,
                             "--increment-attempt", env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
            def finish(phase):
                directory = "repo-context" if phase == "recon" else phase
                checked = run(PYTHON, "scripts/validate-phase-v2.py", str(ROOT), str(scan), phase, env=env)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                result = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", phase,
                             "--phase-manifest", f"{directory}/phase-manifest.json", "--task", tasks[phase],
                             "--task-phase", phase, "--artifact", f"{directory}/phase-manifest.json", env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
            begin("recon")
            def manifest(phase:str,outputs:list[str],coverage:dict|None=None):return {"phase":phase,"status":"ok","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:01Z","inputs":[],"outputs":outputs,"coverage":coverage or {},"tool_versions":{"fixture":"1"},"warnings":[],"errors":[]}
            write(scan/"repo-context/repo-context.json",{"schema_version":"2.0","repository":"fixture","comparable":{"name":None,"basis":"fixture","confidence":"not_applicable"},"projects":[{"id":"PRJ-1","type":"library","base_path":".","languages":["python"],"frameworks":[],"dependency_files":[],"entry_points":[{"id":"EP-1","path":"app.py","kind":"library","evidence_refs":["app.py:1"]}],"trust_boundary_ids":["TB-1"],"ignore_patterns":[],"evidence_refs":["app.py:1"]}],"actors":[],"domain_tags":[],"sensitive_data_types":[],"build_ci":[],"generated_ignorable":[],"evidence_refs":["app.py:1"],"warnings":[],"errors":[]})
            write(scan/"repo-context/security-surfaces.json",{"schema_version":"2.0","repository":"fixture","entry_points":[{"id":"EP-1","project_id":"PRJ-1","path":"app.py","kind":"library","trust_boundary_ids":["TB-1"],"evidence_refs":["app.py:1"]}],"trust_boundaries":[{"id":"TB-1","project_id":"PRJ-1","source_trust":"caller","target_trust":"library","description":"caller to library","evidence_refs":["app.py:1"]}],"security_relevant_files":[{"path":"app.py","categories":["entry_point"],"evidence_refs":["app.py:1"]}],"ignore_patterns":[],"generated_ignorable":[],"sensitive_data_types":[],"domain_tags":[],"warnings":[],"errors":[]})
            surfaces=json.loads((scan/"repo-context/security-surfaces.json").read_text())
            surfaces["attack_paths"]=[attack_path("app.py")]
            write(scan/"repo-context/security-surfaces.json",surfaces)
            (scan/"repo-context/repo.md").write_text("# Fixture\n")
            for name,worker in (("overview.json","overview"),("trust-boundaries.json","trust-boundaries"),("input-surfaces.json","input-surfaces")):write(scan/"repo-context/research"/name,{"schema_version":"2.0","worker":worker,"status":"ok","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:01Z","observations":[],"warnings":[],"errors":[]})
            attribute_recon(scan, json.loads(context_path.read_text())["model_routing"])
            recon_outputs=["repo-context/repo.md","repo-context/repo-context.json","repo-context/security-surfaces.json","repo-context/research/overview.json","repo-context/research/trust-boundaries.json","repo-context/research/input-surfaces.json","repo-context/phase-manifest.json"];write(scan/"repo-context/phase-manifest.json",manifest("recon",recon_outputs))
            finish("recon")
            begin("tool-collection")
            sca={"schema_version":"2.0","tool":"wraith","packages_scanned":0,"advisory_count":0,"advisories":[]};secrets={"schema_version":"2.0","tool":"poltergeist","match_count":0,"candidate_count":0,"candidates":[]};write(scan/"tool-collection/sca-advisories.json",sca);write(scan/"tool-collection/secrets-redacted.json",secrets);write(scan/"tool-collection/dependency-limitations.json",{"schema_version":"2.0","limitations":[]})
            for tool,artifact_name,receipt_name in (("wraith","sca-advisories.json","wraith-receipt.json"),("poltergeist","secrets-redacted.json","poltergeist-receipt.json")):
                digest=hashlib.sha256((scan/"tool-collection"/artifact_name).read_bytes()).hexdigest();receipt={"schema_version":"2.0","tool":tool,"operation":"fixture","status":"ok","version":"fixture","started_at":"now","completed_at":"now","parse_status":"ok","result_count":0,"normalized_sha256":digest,"warnings":[]};receipt.update({"packages_scanned":0,"databases":[]} if tool=="wraith" else {});write(scan/"tool-collection"/receipt_name,receipt)
            write(scan/"tool-collection/collection.json",{"schema_version":"2.0","run_id":"run","sca_ref":"tool-collection/sca-advisories.json","secrets_ref":"tool-collection/secrets-redacted.json","receipts":["tool-collection/wraith-receipt.json","tool-collection/poltergeist-receipt.json"],"limitations":[],"warnings":[]});(scan/"tool-collection/summary.md").write_text("# Tools\n");tool_outputs=["tool-collection/collection.json","tool-collection/sca-advisories.json","tool-collection/secrets-redacted.json","tool-collection/dependency-limitations.json","tool-collection/wraith-receipt.json","tool-collection/poltergeist-receipt.json","tool-collection/summary.md","tool-collection/phase-manifest.json"];write(scan/"tool-collection/phase-manifest.json",manifest("tool-collection",tool_outputs))
            finish("tool-collection")
            begin("sast")
            threat={"schema_version":"2.0","repository_profile":{"kinds":["library"],"tags":[],"comparable":{"name":None,"basis":"fixture","confidence":"not_applicable"}},"assets":[{"id":"A-1","name":"library integrity","sensitivity":"medium","description":"correct behavior","evidence_refs":["app.py:1"]}],"trust_boundaries":[{"id":"TB-1","source_trust":"caller","target_trust":"library","description":"caller boundary","evidence_refs":["app.py:1"]}],"entrypoints":[{"id":"EP-1","path":"app.py","kind":"library","subsystem_ids":["SUB-1"],"trust_boundary_ids":["TB-1"],"evidence_refs":["app.py:1"]}],"subsystems":[{"id":"SUB-1","name":"library","files":["app.py"],"entrypoints":["EP-1"],"security_surface_ids":["EP-1"],"risk":"low","evidence_refs":["app.py:1"]}],"attack_classes":[{"id":"dependency","title":"Dependency review","domain":"general","owner":"sca","methodology_ref":"skill://vulnops-audit-core","reason":"tool owned dependency coverage","evidence_refs":["app.py:1"],"custom":False}],"threats":[{"id":"TH-1","title":"caller misuse","attacker":"caller","asset_ids":["A-1"],"entrypoint_ids":["EP-1"],"attack_class_ids":["dependency"],"description":"fixture threat","evidence_refs":["app.py:1"]}],"hunt_mappings":[{"id":"HM-1","attack_class_id":"dependency","subsystem_id":"SUB-1","surface_ids":["EP-1"],"threat_ids":["TH-1"],"asset_ids":["A-1"],"attacker":"caller","entrypoint_ids":["EP-1"],"boundary_ids":["TB-1"],"source_files":["app.py"],"security_question":"Does validated dependency evidence cover this input?","stop_conditions":["Tool collection is valid"],"priority":"low","applicability_reason":"Dependency consumption begins at the library boundary.","evidence_refs":["app.py:1"]}],"assumptions":[],"evidence_refs":["app.py:1"],"warnings":[],"errors":[]};write(scan/"sast/threat-model.json",threat)
            hunt={"schema_version":"2.0","run_id":"run","rationale":"fixture tool-owned coverage","budget":json.loads(context_path.read_text())["sast_budget"],"custom_attack_classes":[],"cells":[{"id":"CELL-1","mapping_id":"HM-1","surface_ids":["EP-1"],"subsystem":"SUB-1","attack_class_id":"dependency","domain":"general","methodology_refs":["skill://vulnops-audit-core"],"lenses":[],"status":"tool_satisfied","priority":"low","threat_ids":["TH-1"],"asset_ids":["A-1"],"attacker":"caller","entrypoint_ids":["EP-1"],"boundary_ids":["TB-1"],"files":["app.py"],"security_question":"Does validated dependency evidence cover this input?","stop_conditions":["Tool collection is valid"],"applicability_reason":"Dependency consumption begins at the library boundary.","evidence_refs":["tool-collection/phase-manifest.json"],"owner":"sca","lead_key":None,"disposition_reason":"tool collected"}],"tasks":[],"warnings":[],"errors":[]};write(scan/"sast/hunt-plan.json",hunt)
            registry = caller_registry("Does validated dependency evidence cover this input?", "Exploit an affected dependency through caller input", "An affected dependency operation exposes a protected service resource.")
            threat.update(registry); threat["hunt_mappings"][0].update(objective_binding(registry))
            hunt.update(registry); hunt["cells"][0].update(objective_binding(registry))
            write(scan/"sast/threat-model.json",threat); write(scan/"sast/hunt-plan.json",hunt)
            finalized=run(PYTHON,"scripts/finalize-sast.py",str(target),str(scan),"--finalize",env=env)
            self.assertEqual(finalized.returncode,0,finalized.stderr)
            finish("sast")
            begin("campaign-planning")
            built=run(PYTHON,"scripts/build-evidence-index.py",str(scan),"--context",str(context_path),env=env);self.assertEqual(built.returncode,0,built.stderr)
            for flags in (("--prepare-discovery",), ()):
                planned=run(PYTHON,"scripts/build-campaign-plan.py",str(scan),"--context",str(context_path),*flags,env=env)
                self.assertEqual(planned.returncode,0,planned.stderr)
            plan=json.loads((scan/"campaign-planning/campaign-plan.json").read_text())
            sys.path.insert(0,str(ROOT/"scripts"))
            from intrusion_contract import build_wave, reference
            context=json.loads(context_path.read_text())
            finish("campaign-planning")
            begin("intrusion")
            wave=build_wave(scan,target,context)
            for campaign in plan["campaigns"]:
                write(scan/f"intrusion/results/{campaign['id']}.json",{
                    "schema_version":"2.0","campaign_id":campaign["id"],"status":"closed",
                    "objective_id":campaign["objective_id"],"question_id":campaign["question_id"],
                    "provenance": provenance("vulnops-intrusion-campaign", f"intrusion/results/{campaign['id']}.json", context["model_routing"]),
                    "assessment_context": {"attempt_id": context["attempt_id"]},
                    "conclusion":"Source inspection found a constant-return function with no sensitive operation.",
                    "evidence_refs":["repo-context/security-surfaces.json"],
                    "graph_query_receipts":[],"graph_evidence_refs":[],"graph_answers":[],
                    "graph_limitations":["Codegraph disabled; reviewed app.py directly."],
                    "primitive_updates":[],"candidates":[],
                    "input_snapshot":reference(scan,wave),"wave":0,
                    "resolution":resolution(),
                    "composition":{"outcome":"none_actionable","reason":"Constant return exposes no capability consumer.","evidence_refs":["repo-context/security-surfaces.json"],"primitive_ids":[]},
                })
            if wave["assignments"]:build_wave(scan,target,context,completed=list(wave["assignments"]))
            self.assertEqual(run(PYTHON,"scripts/finalize-intrusion.py",str(scan),env=env).returncode,0)
            finish("intrusion")
            begin("gap-exploration")
            prepared = run(PYTHON, "scripts/prepare-gap-exploration.py", "--context", str(context_path), env=env)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            gap_plan = json.loads((scan / "gap-exploration/inputs.json").read_text())
            gap_plan.update(objectives=[], questions=[], seeds=[], assignments=[], graph_questions=[])
            draft = base / "empty-gap-plan.json"
            write(draft, gap_plan)
            admitted = run(PYTHON, "scripts/prepare-gap-exploration.py", "--context", str(context_path),
                           "--plan", str(draft), env=env)
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            closed = run(PYTHON, "scripts/finalize-gap-exploration.py", "--context", str(context_path), env=env)
            self.assertEqual(closed.returncode, 0, closed.stderr)
            self.assertEqual(json.loads((scan / "gap-exploration/results.json").read_text())["candidates"], [])
            finish("gap-exploration")
            begin("synthesis")
            self.assertEqual(run(PYTHON,"scripts/empty-synthesis.py",str(scan),env=env).returncode,0)
            finish("synthesis")
            begin("final-verification")
            self.assertEqual(run(PYTHON,"scripts/finalize-verification.py",str(target),str(scan),env=env).returncode,0)
            finish("final-verification")
            begin("report")
            self.assertEqual(run(PYTHON,"scripts/render-report.py",str(scan),env=env).returncode,0)
            finish("report")
            report=json.loads((scan/"report/security-report.json").read_text());context=json.loads(context_path.read_text());self.assertEqual(report["execution_environment"],{"network":context["network"],"offline_package":context["offline_package"]})
            self.assertIn("Codegraph unavailable; source-only inspection continues.",report["limitations"])
            completed = run(PYTHON,"scripts/update-run-state.py",str(scan),"--run-status","complete",env=env)
            self.assertEqual(completed.returncode,0,completed.stderr)
            validated=run("bash","scripts/validate-scan.sh",str(scan),env=env);self.assertEqual(validated.returncode,0,validated.stderr)


class RuntimeIsolationTests(unittest.TestCase):
    def test_run_state_enforces_phase_exclusion_stable_retries_and_fail_closure(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            scan = Path(tmp) / "run"; scan.mkdir();
            phases = {phase: "pending" for phase in ("recon", "tool-collection", "sast", "campaign-planning", "intrusion", "synthesis", "final-verification", "report")}
            write(scan / "run-manifest.json", {"schema_version": "2.0", "workflow": "canonical-redteam-v2", "run_id": "run", "status": "initialized", "updated_at": "now", "phases": phases})
            write(scan / "task-ledger.json", {"schema_version": "2.0", "run_id": "run", "tasks": []})
            self.assertEqual(run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "incomplete").returncode, 0)
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
            stop = run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "incomplete", "--error", "second collector failure")
            self.assertEqual(stop.returncode, 0, stop.stderr)
            manifest = json.loads((scan / "run-manifest.json").read_text()); ledger = json.loads((scan / "task-ledger.json").read_text())
            self.assertEqual(manifest["status"], "incomplete"); self.assertNotIn("running", manifest["phases"].values())
            self.assertFalse(any(item["status"] == "running" for item in ledger["tasks"]))
            tool = next(item for item in ledger["tasks"] if item["id"] == "ToolCollection")
            self.assertEqual(tool["attempts"], 2); self.assertIsNone(tool["artifact"])

    def test_completion_requires_accepted_checkpoints_and_published_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scan = Path(tmp)
            phases = ("recon", "tool-collection", "sast", "campaign-planning", "intrusion", "synthesis", "final-verification", "report")
            tasks = ("Recon", "ToolCollection", "ThreatHunter", "CampaignPlanning", "Intrusion", "Synthesis", "FinalVerification", "Report")
            write(scan / "run-manifest.json", {"run_id": "run", "status": "incomplete", "attempt_id": "attempt", "phases": dict.fromkeys(phases, "pending")})
            write(scan / "task-ledger.json", {"run_id": "run", "tasks": []})
            write(scan / "report/security-report.json", {})
            (scan / "report/security-report.md").write_text("published\n")
            premature = run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "complete")
            self.assertNotEqual(premature.returncode, 0)
            for phase, task in zip(phases, tasks):
                directory = "repo-context" if phase == "recon" else phase
                artifact = f"{directory}/phase-manifest.json"
                write(scan / artifact, {"phase": phase, "status": "ok"})
                before_start = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", phase, "--phase-manifest", artifact, "--task", task, "--task-phase", phase, "--artifact", artifact)
                self.assertNotEqual(before_start.returncode, 0)
                started = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", phase, "--phase-status", "running", "--task", task, "--task-phase", phase, "--increment-attempt")
                self.assertEqual(started.returncode, 0, started.stderr)
                accepted = run(PYTHON, "scripts/update-run-state.py", str(scan), "--phase", phase, "--phase-manifest", artifact, "--task", task, "--task-phase", phase, "--artifact", artifact)
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
            write(scan / "final-verification/findings.json", {"run_id": "run", "findings": []})
            write(scan / "report/security-report.json", {
                "run_id": "run", "summary": {"total": 0}, "findings": [],
                "publication": {"execution_kind": "audit", "repository": "fixture",
                                "repositories": [], "model_routing": {}, "producer_routes": {},
                                "markdown_sha256": hashlib.sha256(b"published\n").hexdigest()},
            })
            (scan / "report/security-report.md").unlink()
            missing = run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "complete")
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("security-report.md", missing.stderr)
            self.assertEqual(json.loads((scan / "run-manifest.json").read_text())["status"], "incomplete")
            (scan / "report/security-report.md").write_text("published\n")
            completed = run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "complete")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((scan / "run-manifest.json").exists())
            self.assertFalse((scan / "task-ledger.json").exists())
            self.assertEqual(json.loads((scan / "report/security-report.json").read_text())["run_id"], "run")
            before = {path: path.read_bytes() for path in scan.rglob("*") if path.is_file()}
            rejected = run(PYTHON, "scripts/update-run-state.py", str(scan), "--run-status", "incomplete")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_tool_collection_refuses_unvalidated_recon_before_scanner_outputs(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base = Path(tmp); scan = base / "run"; target = base / "target"; target.mkdir(); (target / "main.py").write_text("pass\n"); (target / "go.sum").write_text("sum\n")
            context = base / "context.json"; env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
            initialized = run(PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target), "--scan-base", str(scan), "--run-id", "run", "--repo-name", "fixture", "--remote-url", "local", "--repo-id", "fixture", "--commit", "abc", "--depth", "quick", "--reproduction-mode", "off", env=env)
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            write_minimal_recon(scan, target, "run", ["go.sum"])
            env = activate_publisher(scan, json.loads(context.read_text()), "tool-collection", env)
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

    @unittest.skipUnless(all((ROOT / f"bins/{name}").is_file() for name in ("wraith", "osv-scanner", "poltergeist")) and (ROOT / ".harness/osv-db").is_dir(), "offline scanner toolchain unavailable")
    def test_tool_collection_preserves_supported_results_and_unsupported_limitations(self) -> None:
        for aggregate_only in (False, True):
            with self.subTest(aggregate_only=aggregate_only), tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
                base = Path(tmp)
                scan = base / "run"
                target = base / "target"
                target.mkdir()
                (target / "main.go").write_text("package main\nfunc main() {}\n")
                (target / "pom.xml").write_text(
                    "<project><packaging>pom</packaging><dependencies></dependencies>"
                    "<dependencyManagement></dependencyManagement></project>"
                )
                (target / "cabal.project.freeze").write_text("constraints: any.base ==4.18.0.0\n")
                dependency_files = ["cabal.project.freeze", "pom.xml"]
                if not aggregate_only:
                    (target / "go.mod").write_text("module fixture\ngo 1.22\n")
                    dependency_files.insert(0, "go.mod")
                context = base / "context.json"
                env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
                initialized = run(
                    PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target),
                    "--scan-base", str(scan), "--run-id", "run", "--repo-name", "fixture", "--remote-url", "local",
                    "--repo-id", "fixture", "--commit", "abc", "--depth", "quick",
                    "--reproduction-mode", "off", env=env,
                )
                self.assertEqual(initialized.returncode, 0, initialized.stderr)
                write_minimal_recon(scan, target, "run", dependency_files, accepted=True)
                recon_before = hashlib.sha256((scan / "repo-context/repo-context.json").read_bytes()).hexdigest()
                env = activate_publisher(scan, json.loads(context.read_text()), "tool-collection", env)
                collected = run(PYTHON, "scripts/collect-tools.py", str(scan), "--context", str(context), env=env)
                self.assertEqual(collected.returncode, 0, collected.stderr)
                self.assertEqual(hashlib.sha256((scan / "repo-context/repo-context.json").read_bytes()).hexdigest(), recon_before)
                validated = run("bash", "scripts/validate-phase.sh", str(scan), "tool-collection", env=env)
                self.assertEqual(validated.returncode, 0, validated.stderr)
                collection = json.loads((scan / "tool-collection/collection.json").read_text())
                self.assertEqual(len(collection["receipts"]), 2)
                limitations = json.loads((scan / "tool-collection/dependency-limitations.json").read_text())
                self.assertEqual(limitations["limitations"][-1]["code"], "bundled_scanner_input_unsupported")
                self.assertEqual(limitations["limitations"][-1]["files"], ["cabal.project.freeze", "pom.xml"])
                self.assertEqual(collection["limitations"], limitations["limitations"])
                wraith_receipt = json.loads((scan / "tool-collection/wraith-receipt.json").read_text())
                self.assertEqual(wraith_receipt["status"], "ok")
                self.assertEqual(wraith_receipt["warnings"], [])
                if aggregate_only:
                    self.assertEqual(wraith_receipt["operation"], "no-supported-lockfiles")
                    self.assertTrue((scan / "tool-collection/poltergeist-receipt.json").is_file())

    @unittest.skipUnless(all((ROOT / f"bins/{name}").is_file() for name in ("wraith", "osv-scanner", "poltergeist")) and (ROOT / ".harness/osv-db").is_dir(), "offline scanner toolchain unavailable")
    def test_metadata_only_collection_preserves_inventory_and_real_scan_results(self) -> None:
        for metadata_only in (False, True):
            with self.subTest(metadata_only=metadata_only), tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
                base = Path(tmp)
                run_id = base.name
                self.addCleanup(shutil.rmtree, ROOT / ".harness/tool-work" / run_id, ignore_errors=True)
                scan = base / "run"
                target = base / "source"
                target.mkdir()
                (target / "main.py").write_text("pass\n")
                write(target / "empty/package-lock.json", {"lockfileVersion": 1})
                dependency_files = ["empty/package-lock.json"]
                if not metadata_only:
                    write(target / "package-lock.json", {
                        "name": "fixture", "version": "1.0.0", "lockfileVersion": 1,
                        "requires": True, "dependencies": {"lodash": {"version": "4.17.20"}},
                    })
                    dependency_files.append("package-lock.json")
                source_before = {str(path.relative_to(target)): path.read_bytes() for path in target.rglob("*") if path.is_file()}
                context = base / "context.json"
                env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
                initialized = run(
                    PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target),
                    "--scan-base", str(scan), "--run-id", run_id, "--repo-name", "fixture", "--remote-url", "local",
                    "--repo-id", "fixture", "--commit", "abc", "--depth", "balanced",
                    "--reproduction-mode", "off", env=env,
                )
                self.assertEqual(initialized.returncode, 0, initialized.stderr)
                write_minimal_recon(scan, target, run_id, dependency_files, accepted=True)
                recon_before = {
                    str(path.relative_to(scan)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (scan / "repo-context").rglob("*") if path.is_file()
                }
                env = activate_publisher(scan, json.loads(context.read_text()), "tool-collection", env)
                collected = run(PYTHON, "scripts/collect-tools.py", str(scan), "--context", str(context), env=env)
                self.assertEqual(collected.returncode, 0, collected.stderr)
                validated = run("bash", "scripts/validate-phase.sh", str(scan), "tool-collection", env=env)
                self.assertEqual(validated.returncode, 0, validated.stderr)
                self.assertEqual({str(path.relative_to(target)): path.read_bytes() for path in target.rglob("*") if path.is_file()}, source_before)
                self.assertEqual({
                    str(path.relative_to(scan)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (scan / "repo-context").rglob("*") if path.is_file()
                }, recon_before)
                collection = json.loads((scan / "tool-collection/collection.json").read_text())
                limitations = json.loads((scan / "tool-collection/dependency-limitations.json").read_text())["limitations"]
                self.assertEqual(collection["limitations"], limitations)
                self.assertEqual([(item["code"], item["files"]) for item in limitations], [
                    ("npm_lockfile_no_dependency_inventory", ["empty/package-lock.json"]),
                ])
                manifest = json.loads((scan / "tool-collection/phase-manifest.json").read_text())
                self.assertEqual(manifest["status"], "ok")
                self.assertEqual(manifest["warnings"], [])
                self.assertEqual(collection["warnings"], [])
                sca = json.loads((scan / "tool-collection/sca-advisories.json").read_text())
                receipt = json.loads((scan / "tool-collection/wraith-receipt.json").read_text())
                secrets = json.loads((scan / "tool-collection/poltergeist-receipt.json").read_text())
                self.assertEqual(receipt["status"], "ok")
                self.assertEqual(secrets["status"], "ok")
                self.assertEqual(sca["packages_scanned"], 0 if metadata_only else 1)
                self.assertEqual(receipt["packages_scanned"], sca["packages_scanned"])
                self.assertEqual(receipt["result_count"], sca["advisory_count"])
                if metadata_only:
                    self.assertEqual(receipt["operation"], "no-supported-lockfiles")
                    self.assertEqual(sca["advisories"], [])
                else:
                    self.assertTrue(any(item["package"] == "lodash" and item["version"] == "4.17.20" for item in sca["advisories"]))
                    self.assertEqual({item["source_lockfile"] for item in sca["advisories"]}, {"package-lock.json"})

    @unittest.skipUnless(all((ROOT / f"bins/{name}").is_file() for name in ("wraith", "osv-scanner", "poltergeist")) and (ROOT / ".harness/osv-db").is_dir(), "offline scanner toolchain unavailable")
    def test_requirements_collection_accounts_for_empty_and_reviewed_inputs(self) -> None:
        for only_excluded in (False, True):
            with self.subTest(only_excluded=only_excluded), tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
                base = Path(tmp)
                run_id = base.name
                self.addCleanup(shutil.rmtree, ROOT / ".harness/tool-work" / run_id, ignore_errors=True)
                scan, target = base / "run", base / "source"
                target.mkdir()
                (target / "main.py").write_text("pass\n")
                inputs = {
                    "empty/requirements.txt": b"",
                    "comments/requirements.txt": b"# No package inventory\n",
                    "docs/requirements.txt": b"HTTP Status Code 400\nRequest/Response field mapping\n",
                }
                if not only_excluded:
                    inputs["live/requirements.txt"] = b"requests==2.19.0\n"
                for relative, data in inputs.items():
                    path = target / relative
                    path.parent.mkdir(parents=True)
                    path.write_bytes(data)
                digest = hashlib.sha256(inputs["docs/requirements.txt"]).hexdigest()
                config = base / "config.toml"
                config.write_text(
                    '[[harness.scans.reviewed_non_dependency_requirements]]\n'
                    f'path = "docs/requirements.txt"\nsha256 = "{digest}"\n'
                    'reason = "Reviewed business requirements, not Python dependencies."\n'
                )
                context = base / "context.json"
                env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
                initialized = run(
                    PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target),
                    "--scan-base", str(scan), "--run-id", run_id, "--repo-name", "fixture", "--remote-url", "local",
                    "--repo-id", "fixture", "--commit", "abc", "--depth", "full",
                    "--reproduction-mode", "off", env=env,
                )
                self.assertEqual(initialized.returncode, 0, initialized.stderr)
                write_minimal_recon(scan, target, run_id, sorted(inputs), accepted=True)
                recon_before = {path: path.read_bytes() for path in (scan / "repo-context").rglob("*") if path.is_file()}
                env = activate_publisher(scan, json.loads(context.read_text()), "tool-collection", env)
                collected = run(PYTHON, "scripts/collect-tools.py", str(scan), "--context", str(context),
                                env={**env, "VULNOPS_CONFIG_PATH": str(config)})
                self.assertEqual(collected.returncode, 0, collected.stderr)
                validated = run("bash", "scripts/validate-phase.sh", str(scan), "tool-collection", env=env)
                self.assertEqual(validated.returncode, 0, validated.stderr)
                self.assertEqual({path: path.read_bytes() for path in recon_before}, recon_before)
                self.assertEqual({relative: (target / relative).read_bytes() for relative in inputs}, inputs)
                collection = json.loads((scan / "tool-collection/collection.json").read_text())
                limitations = json.loads((scan / "tool-collection/dependency-limitations.json").read_text())["limitations"]
                self.assertEqual(collection["limitations"], limitations)
                self.assertEqual([(row["code"], row["files"]) for row in limitations], [
                    ("requirements_no_dependency_inventory", ["comments/requirements.txt", "empty/requirements.txt"]),
                    ("requirements_reviewed_non_dependency", ["docs/requirements.txt"]),
                ])
                self.assertEqual(limitations[1]["reviews"], [{
                    "file": "docs/requirements.txt", "sha256": digest,
                    "reason": "Reviewed business requirements, not Python dependencies.",
                }])
                manifest = json.loads((scan / "tool-collection/phase-manifest.json").read_text())
                self.assertEqual((manifest["status"], manifest["warnings"], collection["warnings"]), ("ok", [], []))
                sca = json.loads((scan / "tool-collection/sca-advisories.json").read_text())
                receipt = json.loads((scan / "tool-collection/wraith-receipt.json").read_text())
                self.assertEqual(receipt["status"], "ok")
                if only_excluded:
                    self.assertEqual((sca["packages_scanned"], sca["advisories"]), (0, []))
                    self.assertEqual(receipt["operation"], "no-supported-lockfiles")
                else:
                    self.assertEqual(sca["packages_scanned"], 1)
                    self.assertEqual({item["source_lockfile"] for item in sca["advisories"]}, {"live/requirements.txt"})
                # A changed review is not authority to skip an invalid input.
                (target / "docs/requirements.txt").write_bytes(inputs["docs/requirements.txt"] + b"Additional business mapping prose\n")
                changed = run(PYTHON, "scripts/collect-tools.py", str(scan), "--context", str(context),
                              env={**env, "VULNOPS_CONFIG_PATH": str(config)})
                self.assertNotEqual(changed.returncode, 0)
                failed = json.loads((scan / "tool-collection/phase-manifest.json").read_text())
                self.assertEqual(failed["status"], "failed")
                self.assertIn("docs/requirements.txt exited 73", failed["errors"][0])

    @unittest.skipUnless(all((ROOT / f"bins/{name}").is_file() for name in ("wraith", "osv-scanner", "poltergeist")) and (ROOT / ".harness/osv-db").is_dir(), "offline scanner toolchain unavailable")
    def test_tool_collection_failure_names_dependency_input_without_raw_output(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "scans") as tmp:
            base = Path(tmp)
            scan = base / "run"
            target = base / "target"
            child = target / "child"
            child.mkdir(parents=True)
            (target / "main.py").write_text("pass\n")
            (child / "package-lock.json").write_text("not valid JSON")
            context = base / "context.json"
            env = {"VULNOPS_AUDIT_CONTEXT": str(context)}
            initialized = run(
                PYTHON, "scripts/init-run.py", "--harness-root", str(ROOT), "--repo-path", str(target),
                "--scan-base", str(scan), "--run-id", "run", "--repo-name", "fixture", "--remote-url", "local",
                "--repo-id", "fixture", "--commit", "abc", "--depth", "quick",
                "--reproduction-mode", "off", env=env,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            write_minimal_recon(scan, target, "run", ["child/package-lock.json"], accepted=True)
            env = activate_publisher(scan, json.loads(context.read_text()), "tool-collection", env)
            collected = run(PYTHON, "scripts/collect-tools.py", str(scan), "--context", str(context), env=env)
            self.assertNotEqual(collected.returncode, 0)
            manifest = json.loads((scan / "tool-collection/phase-manifest.json").read_text())
            error = " ".join(manifest["errors"])
            self.assertIn("child/package-lock.json", error)
            self.assertRegex(error, r"exited (72 \(scanner_execution\)|73 \(unexpected_diagnostics\)|74 \(normalization\))")
            self.assertNotIn(str(target), error)
            self.assertNotIn("no package sources", error.lower())
            self.assertFalse((scan / "tool-collection/collection.json").exists())

    def test_collection_failure_categories_do_not_disclose_scanner_output(self) -> None:
        cases = [
            ("wraith", 64, "input_validation"),
            ("wraith", 70, "prerequisite"),
            ("wraith", 71, "database_verification"),
            ("wraith", 72, "scanner_execution"),
            ("wraith", 73, "unexpected_diagnostics"),
            ("wraith", 74, "normalization"),
            ("wraith", 1, "invocation"),
            ("poltergeist", 71, "invocation"),
        ]
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base = Path(tmp)
            scripts = base / "scripts"
            scripts.mkdir()
            for name in ("collect-tools.py", "dependency_contract.py", "run_lifecycle.py"):
                shutil.copy2(ROOT / "scripts" / name, scripts / name)
            shutil.copy2(ROOT / "config.toml", base / "config.toml")
            source = base / "source"
            source.mkdir()
            write(source / "package-lock.json", {
                "lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.20"}},
            })
            marker = "untrusted-scanner-diagnostic-must-not-survive"
            for tool, status, category in cases:
                with self.subTest(tool=tool, status=status):
                    scan = base / f"{tool}-{status}"
                    write(scan / "repo-context/repo-context.json", {
                        "projects": [{"dependency_files": ["package-lock.json"]}],
                    })
                    context = base / "context.json"
                    write(context, {"scan_base": str(scan), "repo_path": str(source), "run_id": scan.name})
                    write(scan / "run-manifest.json", {"run_id": scan.name, "status": "incomplete", "phases": {"recon": "ok"}})
                    for scanner in ("wraith", "poltergeist"):
                        code = status if scanner == tool else 0
                        (scripts / f"run-{scanner}.sh").write_text(
                            f"#!/bin/sh\nprintf '%s' '{marker}'\nprintf '%s' '{marker}' >&2\nexit {code}\n"
                        )
                    env = activate_publisher(scan, json.loads(context.read_text()), "tool-collection", os.environ)
                    result = run(PYTHON, str(scripts / "collect-tools.py"), str(scan), "--context", str(context), env=env)
                    self.assertEqual(result.returncode, 1)
                    manifest_path = scan / "tool-collection/phase-manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    label = "package-lock.json" if tool == "wraith" else "poltergeist"
                    self.assertIn(f"{label} exited {status} ({category})", " ".join(manifest["errors"]))
                    self.assertEqual(manifest["status"], "failed")
                    self.assertEqual(manifest["outputs"], [])
                    self.assertEqual(list((scan / "tool-collection").iterdir()), [manifest_path])
                    self.assertNotIn(marker, result.stdout + result.stderr + manifest_path.read_text())

    @unittest.skipUnless((ROOT / "bins/codegraph").is_file(), "codegraph binary unavailable")
    def test_codegraph_indexes_snapshot_and_returns_real_relationship(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            base=Path(tmp);source=base/"source";source.mkdir();(source/"main.go").write_text("package main\nfunc helper() {}\nfunc main() { helper() }\n");os.symlink("main.go",source/"alias.go")
            before={path.name: (os.readlink(path) if path.is_symlink() else path.read_bytes()) for path in source.iterdir()}
            env={"CODEGRAPH_TARGET_DIR":str(source),"CODEGRAPH_RUNTIME_DIR":str(base/"runtime")}
            setup=run("bash","scripts/setup-codegraph.sh",env=env);self.assertEqual(setup.returncode,0,setup.stderr)
            after={path.name: (os.readlink(path) if path.is_symlink() else path.read_bytes()) for path in source.iterdir()}
            self.assertEqual(after,before);self.assertFalse((source/".codegraph").exists());self.assertTrue((base/"runtime/project/alias.go").is_symlink())
            queries = (("query", "helper", None, True), ("callers", "helper", "main.go", True),
                       ("callees", "main", "main.go", True), ("impact", "helper", "main.go", True),
                       ("affected", "main.go", None, False), ("callees", "main.go", None, True))
            for number, (operation, subject, file, expect_meaningful) in enumerate(queries):
                out = base / str(number)
                qualifiers = ["--file", file] if file else []
                adapter = run(PYTHON, "scripts/codegraph-adapter.py", "--probe", operation, subject, "--project", str(base / "runtime/project"),
                              "--output", str(out / "context.json"), "--receipt", str(out / "receipt.json"), *qualifiers)
                receipt = json.loads((out / "receipt.json").read_text())
                self.assertEqual(adapter.returncode, 0, f"{operation}: {receipt['warnings']}")
                self.assertEqual(receipt["status"], "ok")
                self.assertEqual(receipt["meaningful"], expect_meaningful)
                document = json.loads((out / "context.json").read_text())
                if operation in {"callers", "callees"} and file:
                    nodes = {node["id"]: node for node in document["nodes"]}
                    relationships = {
                        (nodes[edge["source"]].get("name"), nodes[edge["source"]].get("file"),
                         nodes[edge["target"]].get("name"), nodes[edge["target"]].get("file"))
                        for edge in document["edges"]
                    }
                    self.assertIn(("main", "main.go", "helper", "main.go"), relationships)
    def test_codegraph_rejects_symlink_that_escapes_target(self) -> None:
        if not (ROOT/"bins/codegraph").is_file():self.skipTest("codegraph binary unavailable")
        with tempfile.TemporaryDirectory(dir=ROOT/".harness") as tmp:
            base = Path(tmp); source = base / "source"; source.mkdir()
            outside = base / "outside.txt"
            outside.write_text("outside source tree\n")
            before = outside.read_bytes()
            os.symlink(outside, source / "outside")
            result = run("bash", "scripts/setup-codegraph.sh",
                         env={"CODEGRAPH_TARGET_DIR": str(source), "CODEGRAPH_RUNTIME_DIR": str(base / "runtime")})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink that is broken or escapes the target", result.stderr)
            self.assertEqual(outside.read_bytes(), before)
            self.assertFalse((source / ".codegraph").exists())
            self.assertFalse((base / "runtime/project").exists())

    def test_reproduction_probe_distinguishes_host_and_missing_bubblewrap(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".harness") as tmp:
            bindir = Path(tmp) / "bin"; bindir.mkdir()
            uname = bindir / "uname"
            for host, diagnostic in (("Darwin", "safe reproduction requires Linux"),
                                     ("Linux", "bubblewrap is unavailable")):
                with self.subTest(host=host):
                    uname.write_text(f"#!/bin/bash\nprintf '%s\\n' {host}\n")
                    uname.chmod(0o755)
                    result = run("/bin/bash", "scripts/probe-bubblewrap.sh", env={"PATH": str(bindir)})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stderr.strip(), diagnostic)
                    self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bwrap"),
                         "Linux with bubblewrap is required for the containment integration")
    def test_bubblewrap_containment_on_linux_with_bubblewrap(self) -> None:
        result = run("bash", "scripts/probe-bubblewrap.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "bubblewrap")


if __name__ == "__main__":
    unittest.main()
