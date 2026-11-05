"""Routing, bounded configuration and launcher process-boundary regressions.

Legacy launcher fixtures substitute OMP and deterministic readiness/phase tools.
Native guard fixtures exercise current invocation ownership separately; these
fixtures cover the real launcher process boundary without invoking a provider.
"""
from __future__ import annotations

import importlib.util
import json
import errno
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from advantage_config import resolve_budget
from model_routing import GROUP_AGENTS, advantage_routing, audit_routing, remediation_routing, resolve_routing, validate_routing


class AdvantageRoutingTests(unittest.TestCase):
    def test_routes_are_explicit_and_execution_scoped(self):
        groups = {group: f"fixture/{group}:high" for group in GROUP_AGENTS}
        original = resolve_routing({"routing": groups})
        for group, actors in GROUP_AGENTS.items():
            for actor in actors:
                self.assertEqual(original["agents"][actor], groups[group])
        self.assertEqual(set(audit_routing(original)["groups"]), {
            "audit_lead", "recon", "sast", "campaign_planning", "intrusion", "synthesis",
            "final_verification", "reproduction"})
        for group in ("advantage_lead", "advantage", "advantage_verification"):
            changed = resolve_routing({"routing": groups | {group: "fixture/other:xhigh"}})
            self.assertEqual(audit_routing(original), audit_routing(changed))
            self.assertEqual(remediation_routing(original), remediation_routing(changed))
            self.assertNotEqual(advantage_routing(original), advantage_routing(changed))
            missing = dict(groups)
            del missing[group]
            with self.assertRaisesRegex(ValueError, group):
                resolve_routing({"routing": missing})
        linked = advantage_routing(original)
        validate_routing(linked, "advantage")
        linked["agents"]["vulnops-advantage-investigator"] = "fixture/unapproved:high"
        with self.assertRaisesRegex(ValueError, "ownership"):
            validate_routing(linked, "advantage")

    def test_budget_defaults_are_global_and_strict(self):
        for depth, expected in (("quick", (2, 12, 24, 4, 1, 4, 1800)),
                                ("balanced", (3, 32, 64, 8, 2, 12, 3600)),
                                ("full", (4, 64, 128, 12, 3, 24, 7200))):
            budget = resolve_budget(depth, {})
            self.assertEqual(tuple(budget[key] for key in (
                "deep_passes", "max_tasks", "max_questions", "max_concurrency",
                "max_continuation_rounds", "max_continuation_tasks", "phase_timeout_seconds")), expected)
            self.assertEqual(budget["max_attempts"], 2)
        for override in ({"max_tasks": 0}, {"max_tasks": True}, {"max_concurrency": 17},
                         {"phase_timeout_seconds": 86401}, {"phase_timeout_seconds": "1800"},
                         {"unlimited": True}, {"max_tasks": 100, "max_questions": 2}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                resolve_budget("quick", {"harness": {"advantage": {"budget": {"full": override}}}})
        with self.assertRaises(ValueError):
            resolve_budget("quick", {"harness": {"advantage": {"max_attempts": 3}}})

    def test_deadline_budget_conversion_rejects_invalid_phase_and_type(self):
        spec = importlib.util.spec_from_file_location("advantage_deadline", ROOT / "scripts/set-omp-deadline.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        context = {"execution_kind": "advantage", "budget": resolve_budget("quick", {})}
        self.assertEqual(module.deadline_ms(context, "investigation"), 1800000)
        with self.assertRaises(ValueError):
            module.deadline_ms(context, "baseline")
        context["budget"]["phase_timeout_seconds"] = True
        with self.assertRaises(ValueError):
            module.deadline_ms(context, "planning")

    def test_bootstrap_rejects_missing_advantage_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            for name in ("bootstrap-omp.sh", "harness-lib.sh", "model_routing.py", "advantage_config.py"):
                shutil.copy2(ROOT / "scripts" / name, root / "scripts" / name)
            config = "[llm.routing]\n" + "".join(
                f'{group} = "fixture/{group}:high"\n' for group in GROUP_AGENTS)
            config_path = root / "config.toml"
            config_path.write_text(config)
            env = {key: value for key, value in os.environ.items() if not key.startswith(("VULNOPS_", "VULNOPSV3_", "PI_"))}
            command = ["bash", str(root / "scripts/bootstrap-omp.sh")]
            valid = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            generated = root / ".omp/config.yml"
            before = generated.read_bytes()
            route = 'advantage = "fixture/advantage:high"\n'
            self.assertEqual(config.count(route), 1)
            config_path.write_text(config.replace(route, ""))
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("llm.routing migration required; missing keys: advantage; unknown keys: none", result.stderr)
            self.assertEqual(generated.read_bytes(), before)


FIXTURE_PROGRAM = r'''#!/usr/bin/env python3
import json,os,signal,subprocess,sys
from pathlib import Path
root=Path(os.environ['FIXTURE_ROOT'])
name=Path(sys.argv[0]).name
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value))
def event(kind,**values):
    with (root/'events.jsonl').open('a') as out:
        out.write(json.dumps(dict(kind=kind,**values))+'\n')
if name=='omp':
    if sys.argv[1:]==['token','openai-codex']:
        event('token')
        credential=os.environ.get('TOKEN_VALUE','')
        if credential:
            print(credential)
        raise SystemExit(int(os.environ.get('TOKEN_EXIT','0')))
    linked=any('vulnops-advantage-main.md' in arg for arg in sys.argv)
    kind='advantage' if linked else 'audit'
    terminal=[os.isatty(fd) for fd in (0,1,2)]
    foreground=all(terminal) and all(os.tcgetpgrp(fd)==os.getpgrp() for fd in (0,1,2))
    event(kind,args=sys.argv[1:],overlay=os.environ['VULNOPS_OMP_RUNTIME_CONFIG'],session=os.environ.get('VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID' if linked else 'VULNOPS_LAUNCHER_SESSION_ID'),controller=os.environ.get('VULNOPS_OMP_CONTROLLER_SELECTOR'),linked_context=os.environ.get('VULNOPS_ADVANTAGE_CONTEXT'),credential_matches=bool(os.environ.get('EXPECTED_CREDENTIAL')) and os.environ.get('OPENAI_CODEX_OAUTH_TOKEN')==os.environ['EXPECTED_CREDENTIAL'],terminal=terminal,foreground=foreground,request=os.environ.get('VULNOPS_ADVANTAGE_LAUNCH_REQUEST'),audit_fresh=os.environ.get('VULNOPS_AUDIT_FRESH'))
    if linked:
        if os.environ.get('SIGNAL_BEFORE_INIT')=='yes':
            os.kill(os.getppid(),signal.SIGTERM)
            raise SystemExit(143)
        if 'BEFORE_INIT_EXIT' in os.environ:
            raise SystemExit(int(os.environ['BEFORE_INIT_EXIT']))
        if os.environ.get('INTERACTIVE_FIXTURE')=='yes':
            print('OMP foreground stdout',flush=True)
            print('OMP foreground stderr',file=sys.stderr,flush=True)
            print('OMP ready for input',flush=True)
            answer=sys.stdin.readline().rstrip('\n')
            event('input',value=answer)
            print('OMP received: '+answer,flush=True)
        result=subprocess.run([sys.executable,str(root/'scripts/init-advantage.py'),'--from-launcher'],
                              env=dict(os.environ,FIXTURE_LAUNCHER_PID=str(os.getppid())))
        if result.returncode:
            raise SystemExit(result.returncode)
        # This stand-in reports only launch selection. Real native authority is
        # covered by test_advantage_session_guard, never invented by a ledger.
    elif os.environ.get('AUDIT_CONTEXT','owned')!='absent':
        base=root/'scans'/'fixture'/'audit'
        session=os.environ['VULNOPS_LAUNCHER_SESSION_ID'] if os.environ.get('AUDIT_CONTEXT','owned')=='owned' else 'stale'
        save(root/'.harness/audit-context.json',{'schema_version':'2.0','workflow':'canonical-redteam-v2','launcher_session_id':session,'run_id':'audit','scan_base':str(base)})
        save(base/'run-manifest.json',{'run_id':'audit','status':os.environ.get('AUDIT_STATE','complete')})
    if os.environ.get('SIGNAL_LAUNCHER')=='yes':
        import signal
        os.kill(os.getppid(),signal.SIGTERM)
    raise SystemExit(int(os.environ.get('LINKED_EXIT' if linked else 'AUDIT_EXIT','0')))
elif name=='init-advantage.py':
    assert sys.argv[1:]==['--from-launcher']
    request=json.loads(os.environ['VULNOPS_ADVANTAGE_LAUNCH_REQUEST'])
    assert request['launcher_session_id']==os.environ['VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID']
    os.chdir(request['cwd'])
    event('init',args=request['argv'],entrypoint=sys.argv[1:],cwd=str(Path.cwd()))
    raise SystemExit(int(os.environ.get('INIT_EXIT','0')))
elif name.startswith('close-interrupted'):
    event('close-linked' if 'advantage' in name else 'close-audit',args=sys.argv[1:])
    raise SystemExit(0)
elif name.startswith('validate-'):
    event('validate-linked' if 'advantage' in name else 'validate-audit',args=sys.argv[1:])
    raise SystemExit(int(os.environ.get('LINKED_VALIDATION' if 'advantage' in name else 'AUDIT_VALIDATION','0')))
'''


class AdvantageLauncherFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "harness with spaces"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "bins").mkdir()
        for name in ("run.sh", "advantage.sh"):
            shutil.copy2(ROOT / name, self.root / name)
        shutil.copy2(ROOT / "scripts/harness-lib.sh", self.root / "scripts/harness-lib.sh")
        self.script("scripts/load-config.sh", "#!/usr/bin/env bash\nprintf '%s\\n' 'export OMP_MODEL_SELECTOR=fixture/audit:high' 'export OMP_ADVANTAGE_MODEL_SELECTOR=fixture/advantage:high'\n")
        for name in ("bootstrap-omp.sh", "validate-config.sh"):
            self.script("scripts/" + name, "#!/usr/bin/env bash\nexit 0\n")
        for name in ("bins/omp", "scripts/init-advantage.py", "scripts/close-interrupted-run.py",
                     "scripts/validate-scan.sh", "scripts/validate-advantage.py"):
            self.script(name, FIXTURE_PROGRAM)
        shutil.copy2(ROOT / "scripts/run_lifecycle.py", self.root / "scripts/run_lifecycle.py")
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("VULNOPS_", "VULNOPSV3_", "PI_"))
                    and key != "OPENAI_CODEX_OAUTH_TOKEN"}
        self.env["FIXTURE_ROOT"] = str(self.root)

    def script(self, relative, text):
        path = self.root / relative
        path.write_text(text)
        path.chmod(0o755)

    def invoke(self, script, *arguments, cwd=None, **environment):
        return subprocess.run(["bash", str(self.root / script), *arguments],
                              cwd=cwd, env=self.env | environment, text=True, capture_output=True, timeout=15)

    def invoke_pty(self, script, *arguments, input_text="typed fixture input", **environment):
        """Run the copied launcher in a controlling foreground terminal, without OMP."""
        env = self.env | {"TERM": "xterm-256color", "NO_COLOR": "1",
                          "INTERACTIVE_FIXTURE": "yes"} | environment
        pid, master = pty.fork()
        if pid == 0:
            os.execvpe("bash", ["bash", str(self.root / script), *arguments], env)
        output = bytearray()
        sent = False
        status = None
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([master], [], [], 0.05)
                if readable:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                    if not sent and b"OMP ready for input" in output:
                        os.write(master, (input_text + "\n").encode())
                        sent = True
            else:
                self.fail("Foreground launcher timed out: " + output.decode(errors="replace"))
            while time.monotonic() < deadline:
                waited, child_status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = child_status
                    break
                time.sleep(0.01)
            else:
                self.fail("Foreground launcher did not exit")
            return subprocess.CompletedProcess(
                [script, *arguments], os.waitstatus_to_exitcode(status),
                output.decode(errors="replace"), "")
        finally:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if status is None:
                os.waitpid(pid, 0)
            os.close(master)

    def events(self):
        path = self.root / "events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class AdvantageLauncherTests(AdvantageLauncherFixture, unittest.TestCase):

    def test_ordinary_audit_preserves_omp_argument_boundaries(self):
        for arguments in ((), ("audit this exact prompt", "--label", "two words")):
            with self.subTest(arguments=arguments):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("run.sh", *arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                audit = self.events()[0]
                self.assertEqual(audit["audit_fresh"], "0")
                self.assertEqual(audit["controller"], "fixture/audit:high")
                self.assertEqual([event["args"][-1] for event in self.events()[1:]],
                                 [audit["session"]])
                start = audit["args"].index("--approval-mode") + 2
                self.assertEqual(audit["args"][start:-4], list(arguments))
                self.assertNotIn("init", [event["kind"] for event in self.events()])
                self.assertFalse(Path(audit["overlay"]).exists())

    def test_fresh_consumes_only_launcher_flags_and_preserves_omp_arguments(self):
        for arguments, forwarded, fresh in (
            (("--fresh",), (), "1"),
            (("--fresh", "audit this exact prompt", "--label", "two words", "", "*"),
             ("audit this exact prompt", "--label", "two words", "", "*"), "1"),
            (("audit prompt", "--fresh", "--fresh", "--label", "two words"),
             ("audit prompt", "--label", "two words"), "1"),
            (("--fresh", "--", "--fresh", "", "--advantage"),
             ("--", "--fresh", "", "--advantage"), "1"),
            ((), (), "0"),
            (("--", "--fresh", "two words", ""), ("--", "--fresh", "two words", ""), "0"),
            (("--", "--advantage"), ("--", "--advantage"), "0"),
        ):
            with self.subTest(arguments=arguments):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("run.sh", *arguments, VULNOPS_AUDIT_FRESH="1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([event["kind"] for event in self.events()], ["audit", "close-audit"])
                audit = self.events()[0]
                self.assertEqual(audit["audit_fresh"], fresh)
                start = audit["args"].index("--approval-mode") + 2
                self.assertEqual(audit["args"][start:-4], list(forwarded))
                self.assertFalse(Path(audit["overlay"]).exists())
                self.assertFalse((self.root / ".harness/advantage-context.json").exists())

    def test_fresh_audit_keeps_omp_in_foreground(self):
        result = self.invoke_pty("run.sh", "--fresh")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([event["kind"] for event in self.events()], ["audit", "close-audit"])
        audit = self.events()[0]
        self.assertEqual(audit["audit_fresh"], "1")
        self.assertEqual(audit["terminal"], [True, True, True])
        self.assertTrue(audit["foreground"])

    def test_audit_rejects_advantage_before_startup(self):
        for arguments in (("--advantage",), ("audit prompt", "--advantage", "completed source"),
                          ("--fresh", "--advantage", "completed source")):
            with self.subTest(arguments=arguments):
                result = self.invoke("run.sh", *arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("advantage.sh", result.stderr)
                self.assertEqual(self.events(), [])
                self.assertFalse((self.root / ".harness").exists())

    def test_ordinary_audit_failures_preserve_exit_status(self):
        for environment, status in (
            ({"AUDIT_EXIT": "7"}, 7), ({"AUDIT_EXIT": "130"}, 130),
            ({"AUDIT_EXIT": "143"}, 143), ({"SIGNAL_LAUNCHER": "yes"}, 143),
        ):
            with self.subTest(environment=environment):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("run.sh", **environment)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertNotIn("init", [event["kind"] for event in self.events()])
                self.assertEqual([event["kind"] for event in self.events()], ["audit", "close-audit"])
                self.assertFalse(Path(self.events()[0]["overlay"]).exists())

    def test_standalone_forwards_actions_and_inherited_environment_without_audit_routing(self):
        invocation = self.root / "operator working directory"
        invocation.mkdir()
        for arguments, environment, expected in (
            (("source path", "--mode", "actions", "--action-source", "linked source path",
              "--patch", "patch path.diff", "--verify-fix", "F-001", "--verify-fix", "F-002"),
             {"INIT_EXIT": "19"}, 19),
            (("source path", "--mode", "deep"), {"VULNOPS_AUDIT_FRESH": "1"}, 0),
        ):
            with self.subTest(arguments=arguments):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("advantage.sh", *arguments, cwd=invocation, **environment)
                self.assertEqual(result.returncode, expected, result.stderr)
                launched, initialized = self.events()
                self.assertEqual(launched["controller"], "fixture/advantage:high")
                self.assertEqual([event["kind"] for event in self.events()],
                                 ["advantage", "init"])
                self.assertEqual(initialized["args"], list(arguments))
                self.assertEqual(initialized["entrypoint"], ["--from-launcher"])
                self.assertEqual(json.loads(launched["request"]),
                                 {"argv": list(arguments), "cwd": str(invocation.resolve()),
                                  "launcher_session_id": launched["session"]})
                self.assertEqual(initialized["cwd"], str(invocation.resolve()))
                self.assertFalse(Path(launched["overlay"]).exists())
                self.assertFalse((self.root / ".harness/audit-context.json").exists())
                self.assertIn("--no-session", launched["args"])
                self.assertIsNone(launched["linked_context"])

    def test_standalone_does_not_delete_an_inherited_overlay(self):
        inherited = self.root / "caller-overlay.json"
        inherited.write_text("caller-owned")
        result = self.invoke("advantage.sh", "source", VULNOPS_OMP_RUNTIME_CONFIG=str(inherited))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(inherited.read_text(), "caller-owned")
        linked = next(event for event in self.events() if event["kind"] == "advantage")
        self.assertNotEqual(linked["overlay"], str(inherited))
        self.assertFalse(Path(linked["overlay"]).exists())


    def test_early_controller_error_or_cancellation_never_initializes(self):
        for environment, expected in (({"BEFORE_INIT_EXIT": "31"}, 31),
                                      ({"SIGNAL_BEFORE_INIT": "yes"}, 143)):
            with self.subTest(environment=environment):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("advantage.sh", "unopened source", **environment)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual([event["kind"] for event in self.events()], ["advantage"])
                self.assertFalse((self.root / ".harness/advantage-context.json").exists())
                self.assertFalse((self.root / "scans/fixture/linked").exists())
                self.assertFalse(Path(self.events()[0]["overlay"]).exists())

    def test_early_exit_never_reads_old_advantage_state_or_source(self):
        foreign = self.root / "foreign execution"
        foreign.mkdir()
        manifest = foreign / "advantage-manifest.json"
        manifest.write_text(json.dumps({"run_id": "foreign", "status": "running"}))
        source = self.root / "selected source"
        source.mkdir()
        source_manifest = source / "run-manifest.json"
        source_manifest.write_text(json.dumps({"run_id": "selected", "status": "complete"}))
        context_path = self.root / ".harness/advantage-context.json"
        context_path.parent.mkdir()
        context_path.write_text(json.dumps({
            "launcher_session_id": "foreign-session", "run_id": "foreign",
            "scan_base": str(foreign), "source_scan": str(source)}))
        originals = {path: path.read_bytes() for path in (manifest, source_manifest, context_path)}
        for environment, expected in (({"BEFORE_INIT_EXIT": "31"}, 31),
                                      ({"SIGNAL_BEFORE_INIT": "yes"}, 143)):
            with self.subTest(environment=environment):
                (self.root / "events.jsonl").unlink(missing_ok=True)
                result = self.invoke("advantage.sh", str(source),
                                     PYTHONPATH=str(ROOT / "scripts"), **environment)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual([event["kind"] for event in self.events()], ["advantage"])
                self.assertFalse(Path(self.events()[0]["overlay"]).exists())
                self.assertFalse((self.root / "scans/fixture/linked").exists())
                self.assertEqual({path: path.read_bytes() for path in originals}, originals)

    def test_standalone_inherits_foreground_terminal_and_visible_startup(self):
        for name in ("bootstrap-omp.sh", "validate-config.sh"):
            self.script("scripts/" + name, "#!/usr/bin/env bash\nsleep .35\n")
        result = self.invoke_pty("advantage.sh", "source")
        self.assertEqual(result.returncode, 0, result.stdout)
        launched = next(event for event in self.events() if event["kind"] == "advantage")
        self.assertEqual(launched["terminal"], [True, True, True])
        self.assertTrue(launched["foreground"])
        self.assertEqual([event["kind"] for event in self.events()],
                         ["advantage", "input", "init"])
        self.assertEqual(self.events()[1]["value"], "typed fixture input")
        for marker in ("OMP foreground stdout", "OMP foreground stderr",
                       "OMP received: typed fixture input"):
            self.assertIn(marker, result.stdout)
        startup = result.stdout.split("OMP ready for input", 1)[0]
        self.assertIn("\r\x1b[2K", startup)

    def test_help_and_bad_arguments_do_not_initialize(self):
        help_result = self.invoke("advantage.sh", "--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertTrue(help_result.stdout.strip())
        for arguments in ((), ("source", "--unknown"), ("source", "--fresh"), ("source", "--patch"),
                          ("source", "--mode", "recursive"), ("source", "--depth", "unlimited")):
            self.assertEqual(self.invoke("advantage.sh", *arguments).returncode, 2)
        self.assertEqual(self.events(), [])




if __name__ == "__main__":
    unittest.main()
