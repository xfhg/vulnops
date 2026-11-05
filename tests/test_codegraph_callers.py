"""Real optional setup exercised through its two shared navigation callers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gap_graph
from codegraph_setup import SHUTDOWN_GRACE_SECONDS
from codegraph_contract import _schema, resolve_subject


def prepare_graph_fixture(root: Path) -> None:
    """Install the real supervisor with inert containment and a disposable indexer."""
    (root / "scripts").mkdir(exist_ok=True)
    (root / "bins").mkdir(exist_ok=True)
    for name in ("setup-codegraph.sh", "codegraph_setup.py"):
        shutil.copyfile(ROOT / "scripts" / name, root / "scripts" / name)
    (root / "scripts/harness-lib.sh").write_text(
        "harness_setup_containment(){ :; }\nharness_require_inside_root(){ :; }\n")
    binary = root / "bins/codegraph"
    binary.write_text('''#!/usr/bin/env python3
import os, pathlib, signal, sqlite3, subprocess, sys, time
if sys.argv[1] == '--version':
    print('fixture-codegraph')
    raise SystemExit(0)
project = pathlib.Path(sys.argv[2])
mode = os.environ.get('CALLER_GRAPH_MODE', 'success')
if mode == 'fail':
    raise SystemExit(9)
if mode == 'wait':
    writer = subprocess.Popen([sys.executable, '-c', ''' + repr('''import pathlib, signal, sys, time
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
project = pathlib.Path(sys.argv[1])
while True:
    project.mkdir(parents=True, exist_ok=True)
    (project / 'writer').write_text('owned writer')
    time.sleep(.02)
''') + ''', str(project)])
    pathlib.Path(os.environ['CALLER_GRAPH_READY']).write_text(str(writer.pid))
    while True:
        time.sleep(.05)
database = project / '.codegraph/codegraph.db'
database.parent.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(database) as connection:
    connection.execute('CREATE TABLE nodes (id TEXT, name TEXT, qualified_name TEXT, file_path TEXT, start_line INTEGER, kind TEXT)')
    connection.execute("INSERT INTO nodes VALUES ('a', 'helper', 'helper', 'app.py', 1, 'function')")
''')
    binary.chmod(0o755)


def wait_for_file(path: Path, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 5
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise AssertionError("fixture indexer did not become ready")
        time.sleep(.02)


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def assert_process_stopped(pid: int) -> None:
    """An adopted zombie is stopped even if the host has not reaped it yet."""
    deadline = time.monotonic() + 1
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                                capture_output=True, text=True, timeout=1).stdout.strip()
        if status.startswith("Z"):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"owned descendant {pid} is still running")
        time.sleep(.02)


class CodegraphCallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        prepare_graph_fixture(self.root)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "app.py").write_text("def helper():\n    return 1\n")
        self.runtime = self.root / ".harness/codegraph/fixture"
        self.ready = self.root / "ready"
        self.env = {**os.environ, "CALLER_GRAPH_READY": str(self.ready),
                    "PYTHONDONTWRITEBYTECODE": "1"}

    def gap_command(self, seconds):
        return [sys.executable, "-c", (
            "import sys; from pathlib import Path; "
            f"sys.path.insert(0, {str(ROOT / 'scripts')!r}); import gap_graph; "
            f"gap_graph.ROOT=Path({str(self.root)!r}); "
            f"print(gap_graph._setup(Path({str(self.source)!r}), Path({str(self.runtime)!r}), {seconds!r}))")]

    def probe_command(self):
        shutil.copyfile(ROOT / "scripts/probe-toolchain.sh", self.root / "scripts/probe-toolchain.sh")
        scripts = {
            "jail.sh": '#!/bin/bash\nexec "$@"\n',
            "dependency_contract.py": "import sys\nsys.exit(1 if 'go.sum' in sys.argv else 0)\n",
            "run-wraith.sh": "printf '%s' '{\"status\":\"ok\",\"parse_status\":\"ok\",\"result_count\":1}' >\"$4\"\n",
            "run-poltergeist.sh": "printf '%s' '{\"candidates\":[]}' >\"$2\"\nprintf '%s' '{\"status\":\"ok\",\"parse_status\":\"ok\",\"result_count\":1}' >\"$3\"\n",
            "codegraph-adapter.py": '''import hashlib, json, os, sys
from pathlib import Path
if os.environ.get('CALLER_QUERY_FAIL'):
    raise SystemExit(1)
project = Path(sys.argv[sys.argv.index('--project') + 1])
assert (project / '.codegraph/codegraph.db').is_file()
output = Path(sys.argv[sys.argv.index('--output') + 1])
receipt = Path(sys.argv[sys.argv.index('--receipt') + 1])
output.write_text('{}')
receipt.write_text(json.dumps({'status':'ok', 'parse_status':'ok', 'meaningful':True,
    'binding':{'phase':'probe'}, 'normalized_sha256':hashlib.sha256(output.read_bytes()).hexdigest()}))
''',
        }
        for name, text in scripts.items():
            (self.root / "scripts" / name).write_text(text)
        binary = self.root / "bins/omp"
        binary.write_text("#!/bin/bash\nexit 0\n")
        binary.chmod(0o755)
        return ["bash", str(self.root / "scripts/probe-toolchain.sh"), "--offline"]

    def assert_disposed(self, runtime):
        self.assertFalse((runtime / "project").exists())
        self.assertEqual(json.loads((runtime / "index-receipt.json").read_text())["status"], "failed")
        time.sleep(.1)
        self.assertFalse((runtime / "project").exists(), "a descendant recreated rejected navigation")
        if self.ready.exists():
            assert_process_stopped(int(self.ready.read_text()))

    def test_gap_keeps_shorter_budget_and_disposes_descendants(self):
        with self.subTest(boundary="shutdown headroom"), patch.object(gap_graph, "run_setup_command") as launch:
            ok, reason = gap_graph._setup(self.source, self.runtime, SHUTDOWN_GRACE_SECONDS)
            self.assertFalse(ok)
            self.assertIn("shutdown", reason)
            launch.assert_not_called()
            self.assertFalse(self.runtime.exists())
        allowance = SHUTDOWN_GRACE_SECONDS + 3
        started = time.monotonic()
        result = subprocess.run(self.gap_command(allowance), env={**self.env, "CALLER_GRAPH_MODE": "wait"},
                                capture_output=True, text=True, timeout=allowance + 3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("False", result.stdout)
        self.assertLess(time.monotonic() - started, allowance + 2)
        self.assertTrue(self.ready.exists(), "indexer descendant never started")
        self.assert_disposed(self.runtime)
        self.assertEqual((self.source / "app.py").read_text(), "def helper():\n    return 1\n")

    def test_gap_success_keeps_usable_navigation(self):
        result = subprocess.run(self.gap_command(10), env=self.env, capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("True", result.stdout)
        definitions = resolve_subject("callers", "helper", self.runtime / "project", "app.py")
        self.assertEqual([(row["id"], row["file_path"], row["start_line"]) for row in definitions],
                         [("a", "app.py", 1)])
        receipt = json.loads((self.runtime / "index-receipt.json").read_text())
        self.assertEqual(receipt["status"], "ok")
        _schema(receipt, "tool-receipt.schema.json")

    def test_gap_fatal_setup_is_not_optional(self):
        self.runtime.parent.mkdir(parents=True)
        self.runtime.symlink_to(self.source, target_is_directory=True)
        result = subprocess.run(self.gap_command(10), env=self.env, capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertTrue((self.source / "app.py").is_file())

    def test_probe_success_and_ordinary_failure(self):
        command = self.probe_command()
        for mode in ("success", "fail", "wait"):
            with self.subTest(mode=mode):
                result = subprocess.run(command, env={**self.env, "CALLER_GRAPH_MODE": mode,
                    "CODEGRAPH_INIT_TIMEOUT_SECONDS": ".4" if mode == "wait" else "3"},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                probe = self.root / ".harness/probes/toolchain"
                self.assertEqual((probe / "codegraph-limitation.txt").exists(), mode != "success")
                if mode != "success":
                    self.assertIn("source-only", result.stderr)
                    self.assert_disposed(probe / "codegraph")
                else:
                    self.assertTrue((probe / "codegraph-probe/receipt.json").is_file())
        for case, environment in (
                ("query failure", {"CALLER_QUERY_FAIL": "1"}),
                ("disabled", {"VULNOPS_CODEGRAPH_MODE": "disabled"}),
                ("missing binary", {})):
            with self.subTest(case=case):
                if case == "missing binary":
                    (self.root / "bins/codegraph").unlink()
                result = subprocess.run(command, env={**self.env, **environment},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                limitation = self.root / ".harness/probes/toolchain/codegraph-limitation.txt"
                self.assertEqual(limitation.exists(), case != "disabled")
                if case != "disabled":
                    self.assertIn("source-only", result.stderr)
        (self.root / "scripts/run-wraith.sh").write_text("#!/bin/bash\nexit 1\n")
        result = subprocess.run(command, env={**self.env, "VULNOPS_CODEGRAPH_MODE": "disabled"},
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_probe_fatal_configuration_is_not_optional(self):
        result = subprocess.run(self.probe_command(), env={**self.env, "CODEGRAPH_INIT_TIMEOUT_SECONDS": "nan"},
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("functional probes passed", result.stdout)
        self.assertFalse((self.root / ".harness/probes/toolchain/codegraph-limitation.txt").exists())

    def test_callers_cancel_and_wait_for_descendants(self):
        for caller in ("gap", "probe"):
            for sig in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(caller=caller, signal=sig):
                    self.ready.unlink(missing_ok=True)
                    command = self.gap_command(30) if caller == "gap" else self.probe_command()
                    process = subprocess.Popen(command, env={**self.env, "CALLER_GRAPH_MODE": "wait",
                        "CODEGRAPH_INIT_TIMEOUT_SECONDS": "30"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.addCleanup(stop_process, process)
                    wait_for_file(self.ready, process)
                    process.send_signal(sig)
                    stdout, stderr = process.communicate(timeout=8)
                    self.assertEqual(process.returncode, 128 + sig, stderr)
                    self.assertNotIn("functional probes passed", stdout)
                    self.assertNotIn("source-only", stderr)
                    runtime = self.runtime if caller == "gap" else self.root / ".harness/probes/toolchain/codegraph"
                    self.assert_disposed(runtime)


if __name__ == "__main__":
    unittest.main()
