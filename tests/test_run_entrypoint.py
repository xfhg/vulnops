"""Exercise the real bundled OMP through run.sh, without inference or target code.

Requires an installed bins/omp. These cases prove pre-readiness diagnostics and
native login dispatch, not provider entitlement or a completed OAuth exchange.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.access(ROOT / "bins/omp", os.X_OK), "bundled OMP is not installed")
class NativeEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "harness with spaces"
        (self.root / "scripts").mkdir(parents=True)
        shutil.copy2(ROOT / "run.sh", self.root / "run.sh")
        shutil.copy2(ROOT / "scripts/harness-lib.sh", self.root / "scripts/harness-lib.sh")
        (self.root / "bins").symlink_to(ROOT / "bins", target_is_directory=True)
        # Configuration and readiness deliberately cannot succeed in this checkout.
        (self.root / "config.toml").write_text("not valid TOML [")
        self.home = base / "operator home"
        self.home.mkdir()
        self.env = {
            "PATH": os.environ["PATH"], "HOME": str(self.home),
            "TMPDIR": str(base), "TERM": "dumb", "NO_COLOR": "1",
        }

    def invoke(self, *args):
        return subprocess.run(
            ["bash", str(self.root / "run.sh"), *args], cwd=self.root,
            env=self.env, stdin=subprocess.DEVNULL, text=True,
            capture_output=True, timeout=30,
        )

    def test_diagnostics_need_neither_configuration_nor_audit_state(self):
        for option in ("--help", "-h", "--version", "-v"):
            with self.subTest(option=option):
                result = self.invoke(option)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / ".harness").exists())
                self.assertFalse((self.root / "scans").exists())
        self.assertEqual((self.root / "config.toml").read_text(), "not valid TOML [")

    def test_native_login_precedes_readiness_and_leaves_audit_context_untouched(self):
        context = self.root / ".harness/agent-context.json"
        context.parent.mkdir()
        context.write_text('{"owner":"existing-session"}')
        original = context.read_bytes()
        help_result = self.invoke("login", "--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        # Native rejection exercises login's settings/auth initialization without
        # selecting a real provider, opening a browser, or contacting an IdP.
        rejected = self.invoke("login", "nonexistent-fixture-provider")
        self.assertEqual(rejected.returncode, 1, rejected.stderr)
        self.assertIn("Unknown OAuth provider", rejected.stderr)
        self.assertTrue((self.root / ".harness/home/.omp/agent/agent.db").is_file())
        self.assertEqual(context.read_bytes(), original)
        self.assertFalse((self.root / ".harness/audit-context.json").exists())
        self.assertEqual(list((self.root / "scans").iterdir()), [])
        self.assertEqual(list(self.home.iterdir()), [])

    def test_missing_bundle_does_not_use_an_unvalidated_global_binary(self):
        (self.root / "bins").unlink()
        self.env["PATH"] = str(ROOT / "bins") + os.pathsep + self.env["PATH"]
        result = self.invoke("--version")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.root / ".harness").exists())


if __name__ == "__main__":
    unittest.main()
