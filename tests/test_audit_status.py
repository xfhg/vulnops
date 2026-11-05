from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PHASES=("recon","tool-collection","sast","campaign-planning","intrusion","synthesis","final-verification","report")


class AuditStatusTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()
        shutil.copytree(ROOT/"scripts",self.root/"scripts",ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
        shutil.copyfile(ROOT/"config.toml",self.root/"config.toml")
        self.env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1",
                  "PATH":str(Path(sys.executable).parent)+os.pathsep+os.environ["PATH"],
                  "VULNOPS_AUDIT_CONTEXT":str(self.root/"context.json")}
        subprocess.run(["bash","-c",'source "$1/scripts/harness-lib.sh"; harness_setup_containment "$1"',
                        "status-fixture",str(self.root)],cwd=self.root,env=self.env,capture_output=True,text=True,check=True)
        self.scan=self.root/"scans/fixture";self.scan.mkdir()
        self.write(self.root/"context.json",{"scan_base":str(self.scan),"source_root":"/missing/old-source"})
        self.manifest={"schema_version":"old-format-hint","workflow":"canonical-redteam-v2","run_id":"status-fixture",
                       "repository":"fixture","status":"failed","harness_contract_sha256":"obsolete",
                       "phases":{phase:"ok" for phase in PHASES}}
        self.manifest["phases"].update(synthesis="failed",**{"final-verification":"pending","report":"pending"})
        self.save_run();self.write(self.scan/"task-ledger.json",{"tasks":[]})

    def write(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value)+"\n")

    def save_run(self):self.write(self.scan/"run-manifest.json",self.manifest)

    def snapshot(self):
        return {str(path.relative_to(self.root)):(path.read_bytes(),path.stat().st_mtime_ns) if path.is_file() else None
                for path in self.root.rglob("*")}

    def status(self,expected=1):
        before=self.snapshot()
        result=subprocess.run(["bash",str(self.root/"scripts/audit-status.sh"),str(self.scan)],
                              cwd=self.root,env=self.env,capture_output=True,text=True)
        self.assertEqual(self.snapshot(),before,"status changed files")
        self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
        self.assertNotIn("Traceback",result.stderr)
        return result

    def complete(self):
        self.manifest["status"]="complete";self.manifest["phases"]={phase:"ok" for phase in PHASES};self.save_run()
        self.write(self.scan/"task-ledger.json",{"tasks":[{"phase":phase,"status":"ok"} for phase in PHASES]})
        self.write(self.scan/"final-verification/findings.json",{"findings":[]})
        self.write(self.scan/"report/security-report.json",{"summary":{"total":0},"findings":[]})
        (self.scan/"report/security-report.md").write_text("An older renderer published this report.\n")

    def test_failed_and_pending_checkpoints_survive_missing_phase_outputs(self):
        output=self.status().stdout
        self.assertIn("- State: incomplete\n",output)
        self.assertIn("- synthesis: failed\n",output)
        self.assertIn("- final-verification: pending\n",output)
        self.assertIn("- Resume boundary: synthesis\n",output)

    def test_active_sast_displays_recorded_task(self):
        self.manifest["status"]="running";self.manifest["phases"]["sast"]="running";self.save_run()
        self.write(self.scan/"task-ledger.json",{"tasks":[{"id":"ThreatHunter","phase":"sast","status":"running"}]})
        self.assertIn("- Active phase: sast (ThreatHunter)\n",self.status().stdout)

    def test_successful_files_without_checkpoint_do_not_finish_work(self):
        self.write(self.scan/"synthesis/phase-manifest.json",{"phase":"synthesis","status":"ok"})
        self.assertIn("- synthesis: failed\n",self.status().stdout)

    def test_completed_status_does_not_require_old_source_graph_or_renderer(self):
        self.complete()
        (self.root/"scripts/render-report.py").write_text("raise RuntimeError('historical replay forbidden')\n")
        (self.root/"scripts/validate-phase-v2.py").write_text("raise RuntimeError('historical replay forbidden')\n")
        (self.root/"config.toml").write_text("changed = true\n")
        output=self.status(0).stdout
        self.assertIn("- State: complete\n",output)
        before=self.snapshot()
        result=subprocess.run([sys.executable,str(self.root/"scripts/validate-scan-v2.py"),str(self.root),str(self.scan)],
                              env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.snapshot(),before)

    def test_complete_record_with_missing_publication_names_required_input(self):
        self.complete();(self.scan/"report/security-report.md").unlink()
        self.assertIn("report/security-report.md",self.status().stderr)
        self.assertEqual(json.loads((self.scan/"run-manifest.json").read_text())["status"],"complete")

    def test_legacy_report_cannot_override_completed_execution_identity(self):
        self.complete()
        self.write(self.scan/"report/security-report.json",
                   {"run_id":"foreign-execution","summary":{"total":0},"findings":[]})
        self.assertIn("not its completed execution",self.status().stderr)

    def test_malformed_required_state_names_exact_field(self):
        original = json.loads(json.dumps(self.manifest))
        cases = [
            (f"synthesis-{value!r}", {"phases": {**original["phases"], "synthesis": value}},
             "run-manifest.json: missing or invalid phases.synthesis")
            for value in (None, [], {}, "unknown")
        ]
        cases.extend([
            ("phase-table", {"phases": None}, "run-manifest.json: missing or invalid phases"),
            ("unknown-status", {"status": "unknown"}, "run-manifest.json: invalid status"),
            ("malformed-json", None, "run-manifest.json"),
        ])
        for name, changes, diagnostic in cases:
            with self.subTest(case=name):
                self.manifest = {**original, **(changes or {})}
                self.save_run()
                if changes is None:
                    (self.scan/"run-manifest.json").write_text("{")
                self.assertIn(diagnostic, self.status().stderr)

    def test_accepted_phase_read_needs_no_current_context(self):
        (self.root/"context.json").unlink()
        before=self.snapshot()
        result=subprocess.run([sys.executable,str(self.root/"scripts/validate-phase-v2.py"),str(self.root),str(self.scan),"recon"],
                              env=self.env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("accepted checkpoint",result.stdout)
        self.assertEqual(self.snapshot(),before)

    def test_readers_reject_external_symlink_inputs(self):
        self.complete()
        outside=self.root/"outside.json";self.write(outside,{"findings":[]})
        path=self.scan/"final-verification/findings.json";path.unlink();path.symlink_to(outside)
        self.assertIn("unsafe artifact path",self.status().stderr)

if __name__=="__main__":unittest.main()
