from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from model_routing import GROUP_AGENTS, audit_routing, remediation_routing, resolve_routing, validate_routing
from model_identity import model_diversity


def configuration(groups=None, endpoint='', registered=()):
    groups = groups or {group: 'builtin/main:high' for group in GROUP_AGENTS}
    return ('[llm]\n' + endpoint + '\n[llm.routing]\n' +
            ''.join(f'{key}="{value}"\n' for key, value in groups.items()) +
            '\n[llm.provider]\nname="on-prem"\nauth="none"\ndiscovery="explicit"\n' +
            ''.join(f'[[llm.provider.models]]\nid="{model}"\n' for model in registered))


class ModelRoutingTests(unittest.TestCase):
    def test_invalid_routes_fail_closed(self):
        groups = {group: 'builtin/main:high' for group in GROUP_AGENTS}
        for key in GROUP_AGENTS:
            missing = dict(groups); del missing[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                resolve_routing({'routing': missing})
        for invalid in ('builtin/main', 'builtin/main:imaginary', 'main:high', 'builtin/main: high'):
            bad = dict(groups); bad['recon'] = invalid
            with self.subTest(selector=invalid), self.assertRaises(ValueError):
                resolve_routing({'routing': bad})
        for key in ('selector', 'roles', 'verification', 'model'):
            with self.subTest(legacy=key), self.assertRaises(ValueError):
                resolve_routing({'routing': groups, key: {}})
        with self.assertRaises(ValueError):
            resolve_routing({'routing': {**groups, 'intruson': 'builtin/main:high'}})

    def test_persisted_ownership_cannot_be_forged(self):
        groups = {group: 'builtin/main:high' for group in GROUP_AGENTS}
        groups['remediation'] = 'builtin/fix:high'
        full = resolve_routing({'routing': groups})
        audit = audit_routing(full); remediation = remediation_routing(full)
        validate_routing(audit); validate_routing(remediation, 'remediation')
        for mutation in ("different-model", "legacy-coordinator"):
            with self.subTest(mutation=mutation):
                altered = copy.deepcopy(audit)
                if mutation == "different-model":
                    altered['agents']['vulnops-recon'] = 'builtin/other:high'
                else:
                    altered['agents']['vulnops-sast-lead'] = altered['agents'].pop('vulnops-threat-hunter')
                with self.assertRaisesRegex(ValueError, 'ownership'):
                    validate_routing(altered)
        groups['remediation'] = 'builtin/new-fix:high'
        changed = resolve_routing({'routing': groups})
        self.assertEqual(audit, audit_routing(changed))
        self.assertNotEqual(remediation, remediation_routing(changed))

    def test_effort_does_not_create_diversity(self):
        self.assertFalse(model_diversity('p/red:high', 'p/red:xhigh'))
        self.assertTrue(model_diversity('p/red:high', 'p/blue:high'))

    def test_custom_registration_and_builtin_routes(self):
        cases = [
            ({}, '', (), True),
            ({'sast': 'on-prem/red:high', 'remediation': 'on-prem/blue:high'}, 'base_url="http://127.0.0.1:9999/v1"\n', ('red', 'blue'), True),
            ({'final_verification': 'on-prem/red:high'}, 'base_url="http://127.0.0.1:9999/v1"\n', (), False),
            ({'sast': 'on-prem/red:high'}, '', ('red',), False),
        ]
        for changes, endpoint, registered, success in cases:
            with self.subTest(changes=changes, registered=registered), tempfile.TemporaryDirectory(dir=ROOT/'.harness') as temporary:
                base = Path(temporary)
                groups = {group: 'builtin/main:high' for group in GROUP_AGENTS}; groups.update(changes)
                config = base/'config.toml'; config.write_text(configuration(groups, endpoint, registered))
                env = {**os.environ, 'VULNOPS_CONFIG_PATH': str(config), 'VULNOPS_PROJECT_OMP_CONFIG': str(base/'project.yml'), 'VULNOPS_BOOTSTRAP_AGENT_DIR': str(base/'agent')}
                result = subprocess.run(['bash', str(ROOT/'scripts/bootstrap-omp.sh')], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    overrides = (base/'project.yml').read_text()
                    self.assertIn(f"vulnops-threat-hunter: '{groups['sast']}'", overrides)
                    for group in ("intrusion", "advantage"):
                        for actor in GROUP_AGENTS[group]:
                            self.assertIn(f"{actor}: '{groups[group]}'", overrides)
                    self.assertNotIn('vulnops-sast-lead', overrides)
                if success and registered:
                    registry = (base/'agent/models.yml').read_text()
                    for model in registered:
                        self.assertIn(f"- id: '{model}'", registry)
                    self.assertNotIn(':high', registry)

    def test_catalog_checks_exact_model_and_effort(self):
        spec = importlib.util.spec_from_file_location('routing_probe', ROOT/'scripts/probe-verifier-model.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        catalog = {'models': [{'provider': 'p', 'id': 'red', 'thinking': ['high']}]}
        module.check_catalog(catalog, 'p/red:high')
        for selector in ('p/blue:high', 'p/red:xhigh'):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                module.check_catalog(catalog, selector)

    def test_probe_oracle_sanitizes_denial_and_rejects_substituted_metadata(self):
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('routing_probe', ROOT/'scripts/probe-verifier-model.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        denied = subprocess.CompletedProcess([], 1, '', 'Bearer private-fixture-credential: access denied')
        with tempfile.TemporaryDirectory() as temporary, patch.object(module.subprocess, 'run', return_value=denied) as run:
            with self.assertRaisesRegex(ValueError, 'verify provider authentication/access') as failure:
                module.live_probe(ROOT/'bins/omp', 'p/red:high', Path(temporary))
            self.assertNotIn('private-fixture-credential', str(failure.exception))
            self.assertEqual(run.call_count, 1)
        cases = (
            ("selected", "p", "red", "p/red", "high", None),
            ("provider", "other", "red", "p/red", "high", "substituted model"),
            ("model", "p", "blue", "p/red", "high", "substituted model"),
            ("session-model", "p", "red", "p/blue", "high", "metadata mismatch"),
            ("session-effort", "p", "red", "p/red", "xhigh", "metadata mismatch"),
        )
        for name, provider, model, selected, effort, error in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                def respond(command, **kwargs):
                    self.assertEqual(command[command.index("--model") + 1], "p/red")
                    self.assertEqual(command[command.index("--thinking") + 1], "high")
                    sessions = Path(command[command.index("--session-dir") + 1])
                    sessions.mkdir()
                    (sessions / "fixture.jsonl").write_text(
                        json.dumps({"type": "model_change", "model": selected}) + "\n" +
                        json.dumps({"type": "thinking_level_change", "thinkingLevel": effort}) + "\n")
                    event = {"type": "message_end", "message": {
                        "role": "assistant", "provider": provider, "model": model, "stopReason": "stop"}}
                    return subprocess.CompletedProcess(command, 0, json.dumps(event) + "\n", "")
                with patch.object(module.subprocess, "run", side_effect=respond) as run:
                    if error:
                        with self.assertRaisesRegex(ValueError, error):
                            module.live_probe(ROOT/'bins/omp', 'p/red:high', Path(temporary))
                    else:
                        module.live_probe(ROOT/'bins/omp', 'p/red:high', Path(temporary))
                    self.assertEqual(run.call_count, 1)

    def test_initialization_records_routing_without_claiming_diversity(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary); repo=base/'repo'; repo.mkdir(); scan=base/'scans/run'
            groups = {group: f'fixture/{group}:high' for group in GROUP_AGENTS}
            (base/'config.toml').write_text(configuration(groups))
            command=[sys.executable,str(ROOT/'scripts/init-run.py'),'--harness-root',str(base),'--repo-path',str(repo),'--scan-base',str(scan),'--run-id','r','--repo-name','repo','--remote-url','local','--repo-id','repo-id','--commit','abc','--depth','quick','--reproduction-mode','off']
            result=subprocess.run(command,capture_output=True,text=True,env={**os.environ,'VULNOPS_AUDIT_CONTEXT':str(base/'context.json')})
            self.assertEqual(result.returncode,0,result.stderr)
            manifest=json.loads((scan/'run-manifest.json').read_text())
            validate_routing(manifest['model_routing'])
            expected = audit_routing(resolve_routing({'routing': groups}))
            self.assertEqual(manifest['model_routing'], expected)
            self.assertEqual(manifest['model'], groups['audit_lead'])
            self.assertEqual(manifest['verifier_model'], groups['final_verification'])
            self.assertFalse(manifest['model_diversity'])
            self.assertNotIn('model_roles',manifest)


class CanonicalConfigurationTests(unittest.TestCase):
    def validate(self, text):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.toml"
            config.write_text(text)
            return subprocess.run(
                [sys.executable, str(ROOT / "scripts/validate-configuration.py"), str(config)],
                capture_output=True, text=True,
            )

    def review(self, **changes):
        fields = {"path": "docs/requirements.txt", "sha256": "a" * 64,
                  "reason": "Reviewed business documentation."}
        fields.update(changes)
        return "\n[[harness.scans.reviewed_non_dependency_requirements]]\n" + "".join(
            f"{key} = {json.dumps(value)}\n" for key, value in fields.items()
        )

    def test_startup_accepts_optional_content_bound_reviews_without_exporting_credentials(self):
        baseline = (ROOT / "config.toml.example").read_text().replace(
            'api_key = ""', 'api_key = "fixture-private-credential"'
        )
        for suffix in ("", self.review()):
            with self.subTest(review=bool(suffix)):
                result = self.validate(baseline + suffix)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("fixture-private-credential", result.stderr)

    def test_startup_rejects_malformed_and_duplicate_reviews(self):
        baseline = (ROOT / "config.toml.example").read_text()
        for suffix, diagnostic in (
            (self.review(path="../requirements.txt"), "target-relative requirements.txt"),
            (self.review(sha256="invalid"), "SHA-256"),
            (self.review(reason=""), "reason"),
            (self.review(unrecognized=True), "requires exactly path, sha256 and reason"),
            (self.review() + self.review(), "duplicate"),
            ("\n[harness.scans]\nreviewed_non_dependency_requirements = true\n", "array"),
            ("\n[harness.scans]\nreviewed_non_dependency_requirement = []\n", "unknown harness.scans option"),
        ):
            with self.subTest(suffix=suffix):
                result = self.validate(baseline + suffix)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)

    def test_existing_canonical_configuration_constraints_remain_enforced(self):
        baseline = (ROOT / "config.toml.example").read_text()
        accepted = self.validate(baseline)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for old, new, diagnostic in (
            ('default_depth = "balanced"', 'default_depth = "unknown"', 'harness.default_depth'),
            ('linux_agent_egress = "policy_only"', 'linux_agent_egress = "unknown"', 'harness.network.linux_agent_egress'),
            ('context_packet_bytes = 65536', 'context_packet_bytes = 1', 'context_packet_bytes'),
            ('max_hunt_tasks = 12', 'max_hunt_tasks = 0', 'SAST quick budget'),
            ('mode = "off" # off | safe', 'mode = "unknown" # off | safe', 'reproduction mode or sandbox'),
        ):
            with self.subTest(setting=old):
                self.assertIn(old, baseline)
                result = self.validate(baseline.replace(old, new))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == '__main__':
    unittest.main()
