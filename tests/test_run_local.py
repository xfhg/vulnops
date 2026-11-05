"""Local routing/authentication tests using real copied shell entrypoints.

The shared fixture substitutes OMP and readiness/phase tools. These assertions
cover shell routing, streams, signals and cleanup, not installed-runtime startup.
"""
import json
import os
import pty
from pathlib import Path
import shutil
import subprocess
import unittest

from test_advantage_launch import AdvantageLauncherFixture

ROOT = Path(__file__).resolve().parents[1]


class LocalStandaloneLauncherTests(AdvantageLauncherFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        shutil.copy2(ROOT / "run_local.sh", self.root / "run_local.sh")
        self.ca = self.root / "root.pem"
        self.ca.touch()
        self.source = self.root / "previous completed audit"
        self.source.mkdir()
        self.source_manifest = self.source / "run-manifest.json"
        self.source_manifest.write_text(json.dumps({"run_id": "selected-previous-audit", "status": "complete"}))
        self.source_before = self.source_manifest.read_bytes()
        self.credential = "private-local-fixture-credential"
        self.env.update(NODE_EXTRA_CA_CERTS=str(self.ca), TOKEN_VALUE=self.credential,
                        EXPECTED_CREDENTIAL=self.credential)

    def assert_no_audit(self):
        self.assertNotIn("audit", [event["kind"] for event in self.events()])
        self.assertNotIn("close-audit", [event["kind"] for event in self.events()])
        self.assertFalse((self.root / ".harness/audit-context.json").exists())
        self.assertFalse((self.root / "scans/fixture/audit").exists())
        self.assertEqual(self.source_manifest.read_bytes(), self.source_before)

    def assert_private_output(self, result):
        self.assertFalse(self.credential in result.stdout + result.stderr,
                         "Launcher output disclosed the local credential")
        self.assertFalse(self.credential in json.dumps(self.events()),
                         "Fixture events disclosed the local credential")

    def assert_standalone_success(self, result, *, fetched):
        self.assert_private_output(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([event["kind"] for event in self.events()],
                         (["token"] if fetched else []) +
                         ["advantage", "init"])
        launched = next(event for event in self.events() if event["kind"] == "advantage")
        self.assertTrue(launched["credential_matches"])
        self.assertFalse(Path(launched["overlay"]).exists())
        self.assertIsNone(launched["linked_context"])
        self.assertEqual(json.loads(launched["request"])["argv"][0], str(self.source))
        self.assertFalse((self.root / ".harness/advantage-context.json").exists())
        self.assert_no_audit()

    def test_selected_completed_audit_launches_advantage_directly_with_global_login(self):
        result = self.invoke("run_local.sh", "--advantage", str(self.source),
                             "--mode", "deep", "--depth", "quick")
        self.assert_standalone_success(result, fetched=True)

    def test_inherited_local_credential_reaches_advantage_without_token_command(self):
        result = self.invoke("run_local.sh", "--advantage", str(self.source),
                             OPENAI_CODEX_OAUTH_TOKEN=self.credential, TOKEN_EXIT="89",
                             VULNOPS_AUDIT_FRESH="1")
        self.assert_standalone_success(result, fetched=False)

    def test_advantage_help_and_missing_source_precede_ca_and_authentication(self):
        for arguments, status in ((("--advantage", "--help"), 0),
                                  (("--advantage", "-h"), 0),
                                  (("--advantage",), 2)):
            with self.subTest(arguments=arguments):
                result = self.invoke("run_local.sh", *arguments,
                                     NODE_EXTRA_CA_CERTS=str(self.root / "missing.pem"), TOKEN_EXIT="89")
                self.assert_private_output(result)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(self.events(), [])
                self.assertFalse((self.root / ".harness").exists())
                self.assert_no_audit()

    def test_unset_or_empty_ca_uses_default_trust(self):
        for ca in (None, ""):
            with self.subTest(ca=ca):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                self.env.pop("NODE_EXTRA_CA_CERTS", None)
                if ca is not None:
                    self.env["NODE_EXTRA_CA_CERTS"] = ca
                result = self.invoke("run_local.sh", "--advantage", str(self.source))
                self.assert_standalone_success(result, fetched=True)

    def test_unreadable_ca_prevents_authentication_and_execution(self):
        result = self.invoke("run_local.sh", "--advantage", str(self.source),
                             NODE_EXTRA_CA_CERTS=str(self.root / "missing.pem"))
        self.assert_private_output(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])
        self.assertFalse((self.root / ".harness").exists())
        self.assert_no_audit()

    def test_missing_or_failed_global_login_never_starts_either_execution(self):
        for selector in ((), ("--fresh",), ("--advantage", str(self.source))):
            for token_status, value, expected in (("0", "", 1), ("1", "", 1),
                                                   ("29", self.credential, 29)):
                with self.subTest(selector=selector, token_status=token_status):
                    (self.root / "events.jsonl").unlink(missing_ok=True)
                    result = self.invoke("run_local.sh", *selector,
                                         TOKEN_EXIT=token_status, TOKEN_VALUE=value)
                    self.assert_private_output(result)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual([event["kind"] for event in self.events()], ["token"])
                    self.assertFalse((self.root / ".harness").exists())
                    self.assert_no_audit()

    def test_local_advantage_failure_preserves_completed_audit_and_cleans_overlay(self):
        for variable, status in (("INIT_EXIT", 19), ("LINKED_EXIT", 23)):
            with self.subTest(stage=variable):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("run_local.sh", "--advantage", str(self.source), **{variable: str(status)})
                self.assert_private_output(result)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual([event["kind"] for event in self.events()],
                                 ["token", "advantage", "init"])
                launched = next(event for event in self.events() if event["kind"] == "advantage")
                self.assertTrue(launched["credential_matches"])
                self.assertFalse(Path(launched["overlay"]).exists())
                self.assert_no_audit()

    def test_local_advantage_keeps_live_terminal_after_authentication(self):
        result = self.invoke_pty("run_local.sh", "--advantage", str(self.source))
        self.assert_private_output(result)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([event["kind"] for event in self.events()],
                         ["token", "advantage", "input", "init"])
        launched = self.events()[1]
        self.assertEqual(launched["terminal"], [True, True, True])
        self.assertTrue(launched["foreground"])
        self.assertIn("OMP received: typed fixture input", result.stdout)
        self.assertIn("OMP foreground stderr", result.stdout)
        self.assertFalse(Path(launched["overlay"]).exists())
        self.assert_no_audit()

    def test_local_cancellation_before_intake_preserves_selected_audit(self):
        result = self.invoke("run_local.sh", "--advantage", str(self.source), SIGNAL_BEFORE_INIT="yes")
        self.assert_private_output(result)
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertEqual([event["kind"] for event in self.events()], ["token", "advantage"])
        self.assertFalse((self.root / ".harness/advantage-context.json").exists())
        self.assert_no_audit()

    def test_stubbed_audit_dispatch_preserves_authentication_arguments_and_cleanup(self):
        result = self.invoke("run_local.sh", "ordinary audit prompt", "--label", "two words")
        self.assert_private_output(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = self.events()[1]
        self.assertEqual(audit["audit_fresh"], "0")
        self.assertTrue(audit["credential_matches"])
        prompt_index = audit["args"].index("ordinary audit prompt")
        self.assertEqual(audit["args"][prompt_index:prompt_index + 3],
                         ["ordinary audit prompt", "--label", "two words"])
        self.assertFalse(Path(audit["overlay"]).exists())
        self.assertFalse((self.root / ".harness/advantage-context.json").exists())

    def test_local_fresh_preserves_authentication_readiness_and_argument_boundaries(self):
        for name, kind in (("bootstrap-omp.sh", "bootstrap"), ("validate-config.sh", "readiness")):
            self.script("scripts/" + name,
                        "#!/usr/bin/env bash\n"
                        "printf '%s\\n' '{\"kind\":\"" + kind + "\"}' >> \"$FIXTURE_ROOT/events.jsonl\"\n")
        arguments = ("audit new target", "--label", "two words", "", "*")
        result = self.invoke("run_local.sh", "--fresh", *arguments)
        self.assert_private_output(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = self.events()[3]
        self.assertEqual(audit["audit_fresh"], "1")
        self.assertTrue(audit["credential_matches"])
        start = audit["args"].index("--approval-mode") + 2
        self.assertEqual(audit["args"][start:-4], list(arguments))
        self.assertFalse(Path(audit["overlay"]).exists())
        self.assertFalse((self.root / ".harness/advantage-context.json").exists())

    def test_local_audit_does_not_inherit_fresh_or_consume_opaque_fresh(self):
        for arguments in ((), ("--", "--fresh", "two words", ""), ("--", "--advantage")):
            with self.subTest(arguments=arguments):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("run_local.sh", *arguments, VULNOPS_AUDIT_FRESH="1")
                self.assert_private_output(result)
                self.assertEqual(result.returncode, 0, result.stderr)
                audit = self.events()[1]
                self.assertEqual(audit["audit_fresh"], "0")
                self.assertTrue(audit["credential_matches"])
                start = audit["args"].index("--approval-mode") + 2
                self.assertEqual(audit["args"][start:-4], list(arguments))
                self.assertFalse((self.root / ".harness/advantage-context.json").exists())



class LocalLauncherTests(unittest.TestCase):
    def test_loading_preserves_command_output_and_failure_status(self):
        command = [
            "bash", "-c", 'source "$1"; harness_loading 2 configuration bash -c '
            '\'printf private-stdout; sleep .25; echo diagnostic >&2; exit 7\'',
            "loader-test", str(ROOT / "scripts/harness-lib.sh"),
        ]
        env = {**os.environ, "TERM": "xterm-256color", "NO_COLOR": "1"}
        plain = subprocess.run(command, capture_output=True, env=env, timeout=10)
        self.assertEqual(plain.returncode, 7)
        self.assertEqual(plain.stdout, b"private-stdout")
        self.assertEqual(plain.stderr, b"diagnostic\n")
        master, slave = pty.openpty()
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=slave,
                                    env=env, timeout=10)
            # Darwin may discard unread PTY bytes when the last slave closes.
            os.set_blocking(master, False)
            display = b""
            while True:
                try:
                    chunk = os.read(master, 4096)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                display += chunk
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, b"private-stdout")
            self.assertNotIn(b"private-stdout", display)
            self.assertIn(b"diagnostic", display)
            self.assertIn(b"(failed)", display)
            self.assertNotIn(b"\x1b[36", display)
        finally:
            os.close(master)
            os.close(slave)
