"""Readiness regressions isolated from target/, scans/, and installed tools."""
from pathlib import Path
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from model_routing import GROUP_AGENTS


class OptionalCodegraphTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for directory in ("scripts", "bins", "target", ".harness"):
            (self.root / directory).mkdir()
        for name in ("run-audit.sh", "probe-toolchain.sh", "codegraph_setup.py"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        self.script("harness-lib.sh", "harness_setup_containment(){ :; }\nharness_require_allowed_output(){ :; }\n")
        self.script("load-config.sh", "#!/bin/bash\necho 'export VULNOPS_LINUX_AGENT_EGRESS=policy_only'\n")
        self.script("jail.sh", '#!/bin/bash\nexec "$@"\n')
        for name in ("omp", "wraith", "poltergeist", "osv-scanner", "codegraph"):
            path = self.root / "bins" / name
            path.write_text("#!/bin/bash\nexit 0\n")
            path.chmod(0o755)
        self.script("dependency_contract.py", "import sys\nsys.exit(1 if 'go.sum' in sys.argv else 0)\n")
        self.script("probe-omp-lifecycle.py", "")
        self.script("osv_snapshot.py", "")
        self.script("run-wraith.sh", '''#!/bin/bash
printf '%s' '{"status":"ok","parse_status":"ok","result_count":1}' >"$4"
''')
        self.script("run-poltergeist.sh", '''#!/bin/bash
printf '%s' '{"candidates":[]}' >"$2"
printf '%s' '{"status":"ok","parse_status":"ok","result_count":1}' >"$3"
''')
        self.script("setup-codegraph.sh", '#!/bin/bash\nexit "${GRAPH_INDEX_EXIT:-0}"\n')
        self.script("codegraph-adapter.py", '''import hashlib, json, os, sys
from pathlib import Path
if os.environ.get("GRAPH_QUERY_EXIT"):
    sys.exit(int(os.environ["GRAPH_QUERY_EXIT"]))
output = Path(sys.argv[sys.argv.index("--output") + 1])
receipt = Path(sys.argv[sys.argv.index("--receipt") + 1])
output.write_text('{}')
receipt.write_text(json.dumps({"status":"ok", "parse_status":"ok", "meaningful":True,
    "binding":{"phase":"probe"}, "normalized_sha256":hashlib.sha256(output.read_bytes()).hexdigest()}))
''')

    def script(self, name, text):
        path = self.root / "scripts" / name
        path.write_text(text)
        path.chmod(0o755)

    def run_script(self, name, *args, **environment):
        return subprocess.run(["bash", str(self.root / "scripts" / name), *args],
                              env={**os.environ, "VULNOPS_AUDIT_FRESH": "0",
                                   "VULNOPS_RUNTIME_ROOT": str(self.root / "owners"),
                                   "VULNOPS_LAUNCHER_PID": str(os.getpid()),
                                   "VULNOPS_LAUNCHER_SESSION_ID": "optional-graph-fixture",
                                   **environment}, text=True, capture_output=True)

    def test_probe_unhealthy_graph_receipt_is_not_accepted(self):
        self.script("codegraph-adapter.py", "import sys\nfrom pathlib import Path\nPath(sys.argv[sys.argv.index('--receipt')+1]).write_text('{}')\n")
        result = self.run_script("probe-toolchain.sh", "--offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("evidence is unusable", result.stderr)
        receipt = self.root / ".harness/probes/toolchain/codegraph-probe/receipt.json"
        self.assertEqual(json.loads(receipt.read_text()), {})

    def prepare_audit(self):
        self.script("target-inventory.py", '''import json, sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
Path(sys.argv[sys.argv.index('--output')+1]).write_text(json.dumps({
    'source_root':str(root/'target'), 'application_name':'fixture', 'remote_url':'fixture',
    'application_id':'fixture', 'revision':'abc', 'repository_count':1,
    'repositories':[{'name':'fixture', 'path':'.', 'remote_url':'fixture', 'commit':'abc'}]}))
''')
        # Keep tool probes controlled, but consume their decision through the real
        # initializer and selector instead of recording forwarded arguments.
        for name in ("init-run.py", "resume-run.py"):
            self.script(name, "import runpy, sys\n"
                        f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
                        f"runpy.run_path({str(ROOT / 'scripts' / name)!r}, run_name='__main__')\n")
        (self.root / "config.toml").write_text(
            "[llm.routing]\n" + "".join(f'{group} = "fixture/model:high"\n' for group in GROUP_AGENTS))

    def test_audit_source_only_and_optional_navigation(self):
        self.prepare_audit()
        for options, environment, expected in (
                ([], {}, "enabled"),
                (["--no-codegraph"], {}, "disabled"),
                ([], {"GRAPH_INDEX_EXIT":"1"}, "disabled"),
                ([], {"GRAPH_QUERY_EXIT":"1"}, "disabled")):
            with self.subTest(options=options, environment=environment):
                result = self.run_script("run-audit.sh", *options, **environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                context = json.loads((self.root / ".harness/audit-context.json").read_text())
                manifest = json.loads((Path(context["scan_base"]) / "run-manifest.json").read_text())
                self.assertEqual(context["codegraph_mode"], expected)
                self.assertEqual(manifest["codegraph_mode"], expected)
                self.assertEqual(bool(context["codegraph_limitation"]), expected == "disabled")
                self.assertEqual(manifest["attempt_id"], context["attempt_id"])
                self.assertEqual(manifest["status"], "incomplete")
                self.assertTrue(all(status == "pending" for status in manifest["phases"].values()))
                self.assertEqual(Path(context["paths"]["codegraph_project"]),
                                 Path(context["paths"]["codegraph_runtime"]) / "project")
        (self.root / "bins/codegraph").unlink()
        result = self.run_script("run-audit.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        context = json.loads((self.root / ".harness/audit-context.json").read_text())
        self.assertEqual(context["codegraph_mode"], "disabled")
        (self.root / "bins/wraith").unlink()
        self.assertNotEqual(self.run_script("run-audit.sh").returncode, 0)

    def test_resume_uses_current_optional_availability(self):
        self.prepare_audit()
        initialized = self.run_script("run-audit.sh")
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        context_path = self.root / ".harness/audit-context.json"
        before = json.loads(context_path.read_text())
        self.assertEqual(before["codegraph_mode"], "enabled")
        scan = Path(before["scan_base"])
        ledger = (scan / "task-ledger.json").read_bytes()
        (self.root / "bins/codegraph").unlink()
        result = self.run_script("run-audit.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        after = json.loads(context_path.read_text())
        self.assertEqual(after["run_id"], before["run_id"])
        self.assertEqual(after["scan_base"], before["scan_base"])
        self.assertNotEqual(after["attempt_id"], before["attempt_id"])
        self.assertEqual(after["codegraph_mode"], "disabled")
        self.assertIn("unavailable", after["codegraph_limitation"])
        self.assertEqual((scan / "task-ledger.json").read_bytes(), ledger)
        manifest = json.loads((scan / "run-manifest.json").read_text())
        self.assertEqual(manifest["codegraph_mode"], "disabled")
        self.assertEqual(manifest["attempt_id"], after["attempt_id"])

    def prepare_real_graph_setup(self):
        shutil.copyfile(ROOT / "scripts/setup-codegraph.sh", self.root / "scripts/setup-codegraph.sh")
        self.script("harness-lib.sh", "harness_setup_containment(){ :; }\nharness_require_inside_root(){ :; }\n")
        (self.root / "target/service.py").write_text("def entry():\n    return 1\n")
        binary = self.root / "bins/codegraph"
        binary.write_text('''#!/bin/bash
if [ "$1" = "--version" ]; then echo fixture; exit 0; fi
if [ "${GRAPH_INDEX_EXIT:-0}" != 0 ]; then exit "$GRAPH_INDEX_EXIT"; fi
mkdir -p "$2/.codegraph"
printf 'fixture index' >"$2/.codegraph/codegraph.db"
''')
        binary.chmod(0o755)
        return {"CODEGRAPH_TARGET_DIR": str(self.root / "target"),
                "CODEGRAPH_RUNTIME_DIR": str(self.root / ".harness/current-graph")}

    def test_setup_rebuilds_current_navigation_without_historical_authority(self):
        environment = self.prepare_real_graph_setup()
        first = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(first.returncode, 0, first.stderr)
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        (runtime / "index-identity.json").write_text('{"snapshot_sha256":"obsolete"}')
        source = self.root / "target/service.py"
        source.write_text("def entry():\n    return 2\n")
        before = source.read_bytes()
        second = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((runtime / "project/service.py").read_bytes(), before)
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse((self.root / "target/.codegraph").exists())

    def test_setup_failure_never_writes_target(self):
        environment = self.prepare_real_graph_setup()
        before = (self.root / "target/service.py").read_bytes()
        failed = self.run_script("setup-codegraph.sh", GRAPH_INDEX_EXIT="9", **environment)
        self.assertNotEqual(failed.returncode, 0)
        receipt = json.loads((Path(environment["CODEGRAPH_RUNTIME_DIR"]) / "index-receipt.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual((self.root / "target/service.py").read_bytes(), before)
        self.assertFalse((self.root / "target/.codegraph").exists())
        environment["CODEGRAPH_RUNTIME_DIR"] = str(self.root / "target/navigation")
        unsafe = self.run_script("setup-codegraph.sh", **environment)
        self.assertNotEqual(unsafe.returncode, 0)
        self.assertFalse((self.root / "target/navigation").exists())

    def test_interrupted_rebuild_cannot_retain_a_previous_ready_receipt(self):
        environment = self.prepare_real_graph_setup()
        first = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(first.returncode, 0, first.stderr)
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        outside = self.root / "outside.py"
        outside.write_text("not authorized source")
        (self.root / "target/escape.py").symlink_to(outside)
        failed = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(failed.returncode, 2, failed.stderr)
        self.assertEqual(json.loads((runtime / "index-receipt.json").read_text())["status"], "failed")
        self.assertFalse((runtime / "project").exists())
        self.assertEqual(outside.read_text(), "not authorized source")

    def graph_binary(self, body):
        binary = self.root / "bins/codegraph"
        binary.write_text(f"#!{sys.executable}\n" + body)
        binary.chmod(0o755)

    def graph_copy_hook(self, body):
        hooks = self.root / "python-hooks"
        hooks.mkdir(exist_ok=True)
        (hooks / "sitecustomize.py").write_text(
            "import os, shutil, time\nfrom pathlib import Path\n"
            "original_copy = shutil.copy2\n"
            "def copy(source, destination, *args, **kwargs):\n"
            + "".join("    " + line + "\n" for line in body.splitlines())
            + "    return original_copy(source, destination, *args, **kwargs)\n"
            "shutil.copy2 = copy\n")
        return {"PYTHONPATH": str(hooks)}

    def assert_failed_graph(self, environment, result, code=1):
        self.assertEqual(result.returncode, code, result.stderr)
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        self.assertFalse((runtime / "project").exists())
        receipt = json.loads((runtime / "index-receipt.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["schema_version"], "2.0")
        self.assertEqual(receipt["parse_status"], "not_applicable")
        self.assertEqual(receipt["result_count"], 0)
        self.assertLess(len(json.dumps(receipt)), 1024)
        self.assertEqual((self.root / "target/service.py").read_text(), "def entry():\n    return 1\n")
        self.assertFalse((self.root / "target/.codegraph").exists())
        return receipt

    def wait_for_marker(self, marker, process):
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(marker.exists(), "fixture did not reach the controlled preparation stage")

    def assert_not_running(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        result = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
        self.assertTrue(not result.stdout.strip() or result.stdout.strip().startswith("Z"),
                        f"owned process {pid} is still running")

    def test_setup_invalid_deadlines_leave_previous_workspace_unchanged(self):
        environment = self.prepare_real_graph_setup()
        ready = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(ready.returncode, 0, ready.stderr)
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        before = {str(path.relative_to(runtime)): path.read_bytes()
                  for path in runtime.rglob("*") if path.is_file()}
        for value in ("0", "-1", "nan", "inf", "-inf", "1e309", "86400.1", "nonsense", ""):
            with self.subTest(value=value):
                result = self.run_script("setup-codegraph.sh", CODEGRAPH_INIT_TIMEOUT_SECONDS=value, **environment)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual({str(path.relative_to(runtime)): path.read_bytes()
                                  for path in runtime.rglob("*") if path.is_file()}, before)

    def test_setup_copy_timeout_is_interruptible_and_never_starts_indexer(self):
        environment = self.prepare_real_graph_setup()
        marker = self.root / ".harness/copy-started"
        index_marker = self.root / ".harness/index-started"
        hooks = self.graph_copy_hook(f"Path({str(marker)!r}).write_text(str(os.getpid()))\ntime.sleep(30)")
        self.graph_binary(f"from pathlib import Path\nPath({str(index_marker)!r}).touch()\n")
        started = time.monotonic()
        result = self.run_script("setup-codegraph.sh", CODEGRAPH_INIT_TIMEOUT_SECONDS="0.3", **hooks, **environment)
        self.assertLess(time.monotonic() - started, 6)
        receipt = self.assert_failed_graph(environment, result)
        self.assertIn("timeout", receipt["warnings"][0])
        self.assertTrue(marker.exists())
        self.assert_not_running(int(marker.read_text()))
        self.assertFalse(index_marker.exists())

    def test_setup_indexing_receives_only_remaining_copy_allowance(self):
        environment = self.prepare_real_graph_setup()
        marker = self.root / ".harness/index-started"
        # Keep executable startup out of the tiny margin: both stages individually
        # fit the allowance, but together exceed it. A restarted index budget
        # would incorrectly succeed.
        hooks = self.graph_copy_hook("time.sleep(1.2)")
        (self.root / "bins/codegraph").write_text(f"""#!/bin/bash
if [ "$1" = "--version" ]; then
    printf 'fixture\\n'
else
    printf started > "{marker}"
    sleep 1.2
fi
""")
        result = self.run_script("setup-codegraph.sh", CODEGRAPH_INIT_TIMEOUT_SECONDS="2", **hooks, **environment)
        self.assertTrue(marker.exists())
        self.assertIn("timeout", self.assert_failed_graph(environment, result)["warnings"][0])

    def test_setup_version_lookup_shares_the_deadline_and_discards_raw_output(self):
        environment = self.prepare_real_graph_setup()
        marker = self.root / ".harness/version-started"
        # Test both a finite version call that would pass with a fresh budget
        # and a blocked lookup. Shell builtins publish the stage marker without
        # another Python interpreter startup consuming the remaining allowance.
        for version_delay in ("1.2", "30"):
            with self.subTest(version_delay=version_delay):
                marker.unlink(missing_ok=True)
                (self.root / "bins/codegraph").write_text(f"""#!/bin/bash
if [ "$1" = "--version" ]; then
    printf started > "{marker}"
    printf 'RAW_PRIVATE_OUTPUT\\n'
    sleep {version_delay}
else
    sleep 1.2
fi
""")
                result = self.run_script("setup-codegraph.sh", CODEGRAPH_INIT_TIMEOUT_SECONDS="2", **environment)
                receipt = self.assert_failed_graph(environment, result)
                self.assertTrue(marker.exists())
                self.assertIn("timeout", receipt["warnings"][0])
                self.assertNotIn("RAW_PRIVATE_OUTPUT", json.dumps(receipt) + result.stdout + result.stderr)

    def writer_binary(self, parent_exit=None):
        marker = self.root / ".harness/writer-pid"
        heartbeat = self.root / ".harness/writes"
        self.graph_binary(f"""import os, signal, sys, time
from pathlib import Path
if sys.argv[1] == '--version':
    print('fixture')
    raise SystemExit
project = Path(sys.argv[2])
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path({str(marker)!r}).write_text(str(os.getpid()))
    while True:
        project.mkdir(parents=True, exist_ok=True)
        (project / 'writer').write_text('writing')
        Path({str(heartbeat)!r}).write_text(str(time.monotonic_ns()))
        time.sleep(0.01)
while not Path({str(marker)!r}).exists():
    time.sleep(0.005)
if {parent_exit!r} is not None:
    raise SystemExit({parent_exit!r})
time.sleep(30)
""")
        def stop_fixture():
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.addCleanup(stop_fixture)
        return marker, heartbeat

    def test_setup_stops_descendant_writers_on_timeout_parent_failure_and_success(self):
        environment = self.prepare_real_graph_setup()
        sibling = self.root / ".harness/other-run"
        sibling.mkdir()
        (sibling / "accepted.json").write_text('{"accepted":true}')
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        runtime.mkdir()
        (runtime / "source-view").mkdir()
        (runtime / "source-view/keep").write_text("unrelated view")
        for parent_exit in (None, 9, 0):
            with self.subTest(parent_exit=parent_exit):
                marker, heartbeat = self.writer_binary(parent_exit)
                marker.unlink(missing_ok=True)
                result = self.run_script("setup-codegraph.sh", CODEGRAPH_INIT_TIMEOUT_SECONDS="0.5", **environment)
                if parent_exit == 0:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads((runtime / "index-receipt.json").read_text())["status"], "ok")
                else:
                    self.assert_failed_graph(environment, result)
                self.assertTrue(marker.exists())
                self.assert_not_running(int(marker.read_text()))
                final_write = heartbeat.read_bytes()
                time.sleep(0.1)
                self.assertEqual(heartbeat.read_bytes(), final_write)
                self.assertEqual((runtime / "project").exists(), parent_exit == 0)
                self.assertEqual((sibling / "accepted.json").read_text(), '{"accepted":true}')
                self.assertEqual((runtime / "source-view/keep").read_text(), "unrelated view")

    def test_setup_cancellation_during_copy_and_index_stops_owned_workers(self):
        environment = self.prepare_real_graph_setup()
        for stage in ("copy", "index"):
            for sig in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(stage=stage, signal=sig):
                    if stage == "copy":
                        marker = self.root / ".harness/copy-pid"
                        hooks = self.graph_copy_hook(f"Path({str(marker)!r}).write_text(str(os.getpid()))\ntime.sleep(30)")
                    else:
                        marker, _ = self.writer_binary()
                        hooks = {}
                    marker.unlink(missing_ok=True)
                    process = subprocess.Popen(
                        ["bash", str(self.root / "scripts/setup-codegraph.sh")],
                        env={**os.environ, **environment, **hooks, "CODEGRAPH_INIT_TIMEOUT_SECONDS": "30"},
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.addCleanup(lambda p=process: p.poll() is None and p.kill())
                    self.wait_for_marker(marker, process)
                    process.send_signal(sig)
                    stdout, stderr = process.communicate(timeout=6)
                    result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
                    self.assert_failed_graph(environment, result, 128 + sig)
                    self.assert_not_running(int(marker.read_text()))

    def test_setup_redirected_project_or_receipt_cleanup_is_fatal_and_confined(self):
        environment = self.prepare_real_graph_setup()
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        sibling = self.root / ".harness/other-run"
        sibling.mkdir()
        sentinel = sibling / "accepted.json"
        sentinel.write_text('{"accepted":true}')
        for redirected in ("project", "receipt", "runtime"):
            with self.subTest(redirected=redirected):
                if runtime.is_symlink():
                    runtime.unlink()
                elif runtime.exists():
                    shutil.rmtree(runtime)
                self.graph_binary(f"""import os, shutil, sys
from pathlib import Path
project = Path(sys.argv[2])
runtime = project.parent
if {redirected!r} == 'project':
    shutil.rmtree(project)
    project.symlink_to({str(sibling)!r}, target_is_directory=True)
elif {redirected!r} == 'receipt':
    (runtime / 'index-receipt.json').symlink_to({str(sentinel)!r})
else:
    shutil.rmtree(runtime)
    runtime.symlink_to({str(sibling)!r}, target_is_directory=True)
raise SystemExit(9)
""")
                result = self.run_script("setup-codegraph.sh", **environment)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(sentinel.read_text(), '{"accepted":true}')
                self.assertEqual((self.root / "target/service.py").read_text(), "def entry():\n    return 1\n")

    def test_setup_preserves_internal_symlinks_and_excludes_tool_state(self):
        environment = self.prepare_real_graph_setup()
        source = self.root / "target"
        (source / "alias.py").symlink_to(source / "service.py")
        for name in (".git", ".codegraph", ".harness"):
            (source / name).mkdir()
            (source / name / "private").write_text("not source")
        result = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        project = Path(environment["CODEGRAPH_RUNTIME_DIR"]) / "project"
        self.assertTrue((project / "alias.py").is_symlink())
        self.assertEqual((project / "alias.py").resolve(), project / "service.py")
        for name in (".git", ".codegraph", ".harness"):
            self.assertFalse((project / name / "private").exists())

    def test_setup_project_recreation_is_inside_the_work_deadline(self):
        environment = self.prepare_real_graph_setup()
        self.assertEqual(self.run_script("setup-codegraph.sh", **environment).returncode, 0)
        hooks = self.root / "python-hooks"
        hooks.mkdir()
        marker = self.root / ".harness/delete-pid"
        (hooks / "sitecustomize.py").write_text(f"""import os, shutil, time
from pathlib import Path
parent = os.getpid()
original = shutil.rmtree
def rmtree(*args, **kwargs):
    if os.getpid() != parent:
        Path({str(marker)!r}).write_text(str(os.getpid()))
        time.sleep(30)
    return original(*args, **kwargs)
shutil.rmtree = rmtree
""")
        result = self.run_script("setup-codegraph.sh", PYTHONPATH=str(hooks),
                                 CODEGRAPH_INIT_TIMEOUT_SECONDS="0.3", **environment)
        self.assertIn("timeout", self.assert_failed_graph(environment, result)["warnings"][0])
        self.assert_not_running(int(marker.read_text()))

    def test_setup_copy_io_failure_is_optional_but_cleanup_failure_is_fatal(self):
        environment = self.prepare_real_graph_setup()
        hooks = self.graph_copy_hook("raise OSError('private filesystem details')")
        result = self.run_script("setup-codegraph.sh", **hooks, **environment)
        receipt = self.assert_failed_graph(environment, result)
        self.assertNotIn("private filesystem details", json.dumps(receipt) + result.stderr)
        hooks_path = Path(hooks["PYTHONPATH"])
        (hooks_path / "sitecustomize.py").write_text("""import os, shutil
parent = os.getpid()
original = shutil.rmtree
def rmtree(*args, **kwargs):
    if os.getpid() == parent:
        raise PermissionError('fixture cleanup refusal')
    return original(*args, **kwargs)
shutil.rmtree = rmtree
""")
        result = self.run_script("setup-codegraph.sh", GRAPH_INDEX_EXIT="9", **hooks, **environment)
        self.assertEqual(result.returncode, 2, result.stderr)
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        self.assertTrue((runtime / "project").exists())
        self.assertFalse((runtime / "index-receipt.json").exists())

    def test_setup_failed_shutdown_proof_refuses_cleanup_and_ready_receipt(self):
        environment = self.prepare_real_graph_setup()
        spec = importlib.util.spec_from_file_location("fixture_codegraph_setup", ROOT / "scripts/codegraph_setup.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        stop_workers = helper.stop_workers

        def no_shutdown_proof(pid, reaped):
            _, reaped = stop_workers(pid, reaped)
            return False, reaped

        with mock.patch.dict(os.environ, environment), mock.patch.object(helper, "stop_workers", no_shutdown_proof):
            result = helper.prepare(self.root)
        self.assertEqual(result, 2)
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        self.assertTrue((runtime / "project").exists())
        self.assertFalse((runtime / "index-receipt.json").exists())

    def test_setup_shell_containment_refusal_is_fatal(self):
        environment = self.prepare_real_graph_setup()
        self.script("harness-lib.sh", "harness_setup_containment(){ :; }\nharness_require_inside_root(){ return 1; }\n")
        result = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(Path(environment["CODEGRAPH_RUNTIME_DIR"]).exists())

    def test_setup_success_retains_only_bounded_version_metadata(self):
        environment = self.prepare_real_graph_setup()
        self.graph_binary("import sys\nif sys.argv[1] == '--version':\n    print('v' * 100000)\n")
        result = self.run_script("setup-codegraph.sh", **environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((Path(environment["CODEGRAPH_RUNTIME_DIR"]) / "index-receipt.json").read_text())
        self.assertEqual(receipt["version"], "v" * 128)
        self.assertEqual(receipt["warnings"], [])

    def test_setup_drains_result_published_between_select_and_waitpid(self):
        environment = self.prepare_real_graph_setup()
        spec = importlib.util.spec_from_file_location("fixture_codegraph_setup", ROOT / "scripts/codegraph_setup.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        waitpid = os.waitpid
        # Deterministically place successful publication after an empty select
        # and before waitpid returns; no timing-dependent repetition is needed.
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(helper.select, "select", return_value=([], [], [])), \
                mock.patch.object(helper.os, "waitpid", side_effect=lambda pid, flags: waitpid(pid, 0)):
            result = helper.prepare(self.root)
        self.assertEqual(result, 0)
        runtime = Path(environment["CODEGRAPH_RUNTIME_DIR"])
        self.assertEqual(json.loads((runtime / "index-receipt.json").read_text())["status"], "ok")

    def test_setup_rejects_preexisting_runtime_redirection_without_touching_sibling(self):
        environment = self.prepare_real_graph_setup()
        sibling = self.root / ".harness/other-run"
        (sibling / "project").mkdir(parents=True)
        (sibling / "project/accepted").write_text("accepted navigation")
        (sibling / "index-receipt.json").write_text('{"status":"ok"}')
        link = self.root / ".harness/redirect"
        link.symlink_to(sibling, target_is_directory=True)
        for suffix in ("", "/nested"):
            with self.subTest(suffix=suffix):
                result = self.run_script("setup-codegraph.sh", **{
                    **environment, "CODEGRAPH_RUNTIME_DIR": str(link) + suffix})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual((sibling / "project/accepted").read_text(), "accepted navigation")
                self.assertEqual((sibling / "index-receipt.json").read_text(), '{"status":"ok"}')
                self.assertFalse((sibling / "nested").exists())

        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / "harness-alias"
            alias.symlink_to(self.root, target_is_directory=True)
            result = self.run_script("setup-codegraph.sh", **{
                **environment, "CODEGRAPH_RUNTIME_DIR": str(alias / ".harness/current-graph")})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / ".harness/current-graph/project/service.py").is_file())

    def test_setup_command_preserves_fatal_result_even_during_cancellation(self):
        spec = importlib.util.spec_from_file_location("fixture_codegraph_setup", ROOT / "scripts/codegraph_setup.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        for exit_code in (0, 1, 2):
            with self.subTest(exit_code=exit_code):
                command = [sys.executable, "-c", f"""
import os, signal, sys
signal.signal(signal.SIGTERM, lambda *_: sys.exit({exit_code}))
signal.alarm(3)
os.kill(os.getppid(), signal.SIGTERM)
signal.pause()
"""]
                result = helper.run_setup_command(command)
                self.assertEqual(result, 2 if exit_code == 2 else 143)


if __name__ == "__main__":
    unittest.main()
