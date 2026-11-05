"""Exercise the real wrapper in disposable harnesses without installed tools or target/."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from osv_snapshot import ECOSYSTEMS, SCHEMA

MARKER = "ghp_SYNTHETIC_RAW_DIAGNOSTIC_DO_NOT_DISCLOSE"


class WraithFailureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "harness"
        for directory in ("scripts", "bins", "config", "work/source"):
            (self.root / directory).mkdir(parents=True)
        for name in ("run-wraith.sh", "harness-lib.sh", "dependency_contract.py",
                     "normalize-wraith.py", "osv_snapshot.py"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        self.repo = self.root / "work/source"
        self.lockfile = self.repo / "package-lock.json"
        self.lockfile.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
            "example": {"version": "1.0.0"}}}))
        self.output = self.root / "work/normalized.json"
        self.receipt = self.root / "work/receipt.json"
        self.called = self.root / ".harness/scanner-called"
        self.binary("wraith", '''#!/bin/bash
if [ "$1" = --version ]; then
    echo 'wraith fixture'
    exit 0
fi
[ "$1 $2 $3 $4" = 'scan --offline --format json' ] || exit 99
[ "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" = "$VULNOPSV3_ROOT/.harness/osv-db" ] || exit 99
: >"$VULNOPSV3_ROOT/.harness/scanner-called"
printf '%s' "$WRAITH_RAW"
printf '%s' "$WRAITH_STDERR" >&2
exit "$WRAITH_EXIT"
''')
        self.binary("osv-scanner", "#!/bin/bash\nexit 0\n")
        self.raw = {
            "package_count": 1, "vulnerability_count": 1,
            "results": [{"Package": "example", "Version": "1.0.0", "Ecosystem": "npm",
                         "FoundVulnerabilities": [{"ID": "OSV-FIXTURE", "Severity": "HIGH",
                                                   "Summary": "fixture", "Details": MARKER}]}],
        }
        self.database = self.root / ".harness/osv-db/osv-scalibr/npm/all.zip"
        self.database.parent.mkdir(parents=True)
        with zipfile.ZipFile(self.database, "w") as archive:
            archive.writestr("OSV-FIXTURE.json", '{"id":"OSV-FIXTURE"}')
        self.digest = hashlib.sha256(self.database.read_bytes()).hexdigest()
        self.snapshot = self.root / "config/osv-snapshot.lock.json"
        self.snapshot.write_text(json.dumps({
            "schema": SCHEMA, "snapshot": "fixture-offline", "generated_at": "2026-01-01T00:00:00Z",
            "ecosystems": [{"name": name,
                            "url": f"https://osv-vulnerabilities.storage.googleapis.com/{name}/all.zip",
                            "size": self.database.stat().st_size, "sha256": self.digest}
                           for name in ECOSYSTEMS],
        }))

    def binary(self, name, source):
        path = self.root / "bins" / name
        path.write_text(source)
        path.chmod(0o755)

    def invoke(self, arguments=None, **environment):
        if arguments is None:
            arguments = (self.repo, self.lockfile, self.output, self.receipt)
        result = subprocess.run(
            ["bash", str(self.root / "scripts/run-wraith.sh"), *map(str, arguments)],
            cwd=self.root, text=True, capture_output=True, check=False,
            env={**os.environ, "WRAITH_RAW": json.dumps(self.raw), "WRAITH_STDERR": "",
                 "WRAITH_EXIT": "1", **environment},
        )
        self.assertTrue(MARKER not in result.stdout + result.stderr, "raw diagnostic escaped wrapper")
        self.assertTrue(str(self.base) not in result.stdout + result.stderr, "absolute path escaped wrapper")
        self.assertTrue(result.stdout == "", "wrapper emitted unexpected stdout")
        self.assertFalse(list((self.root / ".harness/tmp").glob("wraith*")), "raw temporary files remain")
        return result

    def assert_failure(self, result, status, stage, scanned=False):
        self.assertEqual(result.returncode, status)
        self.assertTrue(result.stderr == f"Wraith {stage} failed\n", "failure explanation is not fixed")
        self.assertFalse(self.output.exists(), "failed invocation published normalized output")
        self.assertFalse(self.receipt.exists(), "failed invocation published a healthy receipt")
        self.assertEqual(self.called.exists(), scanned)

    def test_input_and_path_guards_are_preserved_and_sanitized(self):
        outside = self.base / MARKER
        outside.write_text("outside")
        linked_input = self.repo / "nested/package-lock.json"
        linked_input.parent.mkdir()
        linked_input.symlink_to(outside)
        linked_output = self.root / "work" / MARKER
        linked_output.symlink_to(self.output)
        cases = (
            (),
            (outside, self.lockfile, self.output, self.receipt),
            (self.repo, outside, self.output, self.receipt),
            (self.repo, linked_input, self.output, self.receipt),
            (self.repo, self.repo / MARKER, self.output, self.receipt),
            (self.repo, self.lockfile, linked_output, self.receipt),
            (self.repo, self.lockfile, self.output, linked_output),
            (self.repo, self.lockfile, self.root / "config" / MARKER, self.receipt),
            (self.repo, self.lockfile, self.root / "work/missing/../" / MARKER, self.receipt),
        )
        for index, arguments in enumerate(cases):
            with self.subTest(case=index):
                self.assert_failure(self.invoke(arguments), 64, "input_validation")
        self.assertEqual(outside.read_text(), "outside")
        with self.subTest(case="input-contract-exception"):
            (self.root / "scripts/dependency_contract.py").write_text(f"raise RuntimeError({MARKER!r})\n")
            self.assert_failure(self.invoke(), 64, "input_validation")

    def test_missing_prerequisites_fail_before_scanning(self):
        for name in ("wraith", "osv-scanner"):
            with self.subTest(binary=name):
                path = self.root / "bins" / name
                path.chmod(0o644)
                self.assert_failure(self.invoke(), 70, "prerequisite")
                path.chmod(0o755)

    def test_real_database_identity_verification_rejects_missing_and_corrupt_cache(self):
        data = self.database.read_bytes()
        self.database.unlink()
        self.assert_failure(self.invoke(), 71, "database_verification")
        self.database.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        self.assert_failure(self.invoke(), 71, "database_verification")

    def test_database_exceptions_and_identity_extraction_are_sanitized(self):
        verifier = self.root / "scripts/osv_snapshot.py"
        verifier.write_text(f"print({MARKER!r})\nraise RuntimeError({MARKER!r})\n")
        self.assert_failure(self.invoke(), 71, "database_verification")
        verifier.write_text("")
        self.snapshot.write_text(json.dumps({"snapshot": MARKER, "ecosystems": []}))
        self.assert_failure(self.invoke(), 71, "database_verification")

    def test_child_exits_never_impersonate_reserved_wrapper_stages(self):
        for status in (2, 64, 70, 71, 72, 73, 74, 127):
            with self.subTest(status=status):
                self.assert_failure(self.invoke(WRAITH_EXIT=str(status), WRAITH_STDERR=MARKER),
                                    72, "scanner_execution", scanned=True)

    def test_diagnostics_reject_otherwise_accepted_scanner_exits(self):
        for status in (0, 1):
            with self.subTest(status=status):
                self.assert_failure(self.invoke(WRAITH_EXIT=str(status), WRAITH_STDERR=MARKER),
                                    73, "unexpected_diagnostics", scanned=True)

    def test_normalization_parse_count_and_status_gates_remain_strict(self):
        cases = (
            (MARKER, "1"),
            (json.dumps({**self.raw, "package_count": 2}), "1"),
            (json.dumps({**self.raw, "vulnerability_count": 2}), "1"),
            (json.dumps(self.raw), "0"),
            (json.dumps({"package_count": 0, "vulnerability_count": 0, "results": None}), "1"),
        )
        for index, (raw, status) in enumerate(cases):
            with self.subTest(case=index):
                self.assert_failure(self.invoke(WRAITH_RAW=raw, WRAITH_EXIT=status),
                                    74, "normalization", scanned=True)

    def test_normalizer_exceptions_are_sanitized(self):
        (self.root / "scripts/normalize-wraith.py").write_text(
            f"print({MARKER!r})\nraise RuntimeError({MARKER!r})\n")
        self.assert_failure(self.invoke(), 74, "normalization", scanned=True)

    def test_second_temporary_file_failure_cleans_first_and_stays_generic(self):
        mktemp = shutil.which("mktemp")
        self.assertIsNotNone(mktemp)
        self.binary("mktemp", f'''#!/bin/bash
case "$1" in
    *wraith-stderr*) printf '%s' '{MARKER}' >&2; exit 74 ;;
    *) exec "{mktemp}" "$@" ;;
esac
''')
        self.assert_failure(self.invoke(), 1, "invocation")

    def test_findings_present_normalizes_with_locked_identity_and_no_raw_details(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stderr == "", "healthy wrapper emitted diagnostics")
        output_text = self.output.read_text()
        receipt_text = self.receipt.read_text()
        self.assertTrue(MARKER not in output_text + receipt_text, "raw details persisted")
        output = json.loads(output_text)
        receipt = json.loads(receipt_text)
        self.assertEqual((output["packages_scanned"], output["advisory_count"]), (1, 1))
        self.assertEqual(output["advisories"][0]["source_lockfile"], "package-lock.json")
        self.assertEqual((receipt["status"], receipt["parse_status"], receipt["result_count"]), ("ok", "ok", 1))
        self.assertEqual(receipt["databases"], [{"ecosystem": "npm", "snapshot": "fixture-offline", "sha256": self.digest}])
        self.assertEqual(receipt["normalized_sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual(receipt["warnings"], [])


if __name__ == "__main__":
    unittest.main()
