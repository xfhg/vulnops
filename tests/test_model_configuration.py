from __future__ import annotations
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class ModelIdentityTests(unittest.TestCase):
    def bootstrap(self, config: str):
        tmp=tempfile.TemporaryDirectory(dir=ROOT/".harness");base=Path(tmp.name);config_path=base/"config.toml";config_path.write_text(config);agent=base/"agent";project=base/"project-config.yml";env=os.environ.copy();env.update({"VULNOPS_CONFIG_PATH":str(config_path),"VULNOPS_PROJECT_OMP_CONFIG":str(project),"VULNOPS_BOOTSTRAP_AGENT_DIR":str(agent)})
        result=subprocess.run(["bash",str(ROOT/"scripts/bootstrap-omp.sh")],cwd=ROOT,capture_output=True,text=True,check=False,env=env)
        return tmp,base,agent,project,result
    def test_verifier_is_required_and_both_selectors_define_resume_identity(self):
        schema=json.loads((ROOT/"schemas/v2/run-manifest.schema.json").read_text())
        self.assertIn("verifier_model",schema["required"])
        text=(ROOT/"scripts/resume-run.py").read_text()
        self.assertIn('context.get("verifier_model", "")',text)
        self.assertNotIn('context.get("verifier_model", context_model)',text)
        self.assertIn('config_lines.append(f"  primary:',(ROOT/"scripts/bootstrap-omp.sh").read_text())
        run_audit=(ROOT/"scripts/run-audit.sh").read_text()
        self.assertIn('scripts/load-config.sh',run_audit)
        self.assertLess(run_audit.index('scripts/load-config.sh'),run_audit.index('OMP_MODEL_SELECTOR'))
    def test_init_derives_boolean_diversity(self):
        with tempfile.TemporaryDirectory(dir=ROOT/"scans") as tmp:
            scan=Path(tmp)/"run";repo=Path(tmp)/"repo";repo.mkdir()
            cmd=[sys.executable,str(ROOT/"scripts/init-run.py"),"--harness-root",str(ROOT),"--repo-path",str(repo),"--scan-base",str(scan),"--run-id","r","--repo-name","repo","--remote-url","local","--repo-id","repo-id","--commit","abc","--depth","quick","--target-fingerprint","a"*64,"--reproduction-mode","off","--model","p/main","--verifier-model","p/verify"]
            env=os.environ.copy();env["VULNOPS_AUDIT_CONTEXT"]=str(Path(tmp)/"context.json")
            result=subprocess.run(cmd,capture_output=True,text=True,check=False,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            manifest=json.loads((scan/"run-manifest.json").read_text())
            self.assertIs(manifest["model_diversity"],True)
            self.assertEqual(manifest["verifier_model"],"p/verify")
    def test_primary_or_verifier_change_prevents_resume(self):
        with tempfile.TemporaryDirectory(dir=ROOT/".harness") as tmp:
            base=Path(tmp);scan=base/"scan";scan.mkdir();context={"schema_version":"2.0","workflow":"canonical-redteam-v2","run_id":"r","repo_path":str(base/"repo"),"short_sha":"abc","depth":"quick","target_fingerprint":"a"*64,"reproduction_mode":"off","model":"p/main","verifier_model":"p/verify","scan_base":str(scan)};Path(context["repo_path"]).mkdir();(base/"context.json").write_text(json.dumps(context));(scan/"run-manifest.json").write_text(json.dumps({"schema_version":"2.0","workflow":"canonical-redteam-v2","status":"running","model":"p/main","verifier_model":"p/verify","phases":{phase:"pending" for phase in ("recon","tool-collection","sast","campaign-planning","intrusion","synthesis","final-verification","report")}}));(scan/"task-ledger.json").write_text(json.dumps({"schema_version":"2.0","run_id":"r","tasks":[]}))
            args=[sys.executable,str(ROOT/"scripts/resume-run.py"),str(base/"context.json"),context["repo_path"],"abc","quick","a"*64,"off"]
            same=subprocess.run([*args,"p/main","p/verify"],capture_output=True,text=True,check=False);self.assertIn("r\t",same.stdout)
            primary=subprocess.run([*args,"p/other","p/verify"],capture_output=True,text=True,check=False);self.assertEqual(primary.stdout,"")
            verifier=subprocess.run([*args,"p/main","p/other"],capture_output=True,text=True,check=False);self.assertEqual(verifier.stdout,"")
    def test_builtin_primary_inherits_verifier(self):
        tmp,base,agent,project,result=self.bootstrap('[llm]\nselector="builtin/main"\nmodel=""\n[llm.verification]\nselector=""\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="explicit"\n')
        with tmp:
            self.assertEqual(result.returncode,0,result.stderr);text=(agent/"config.yml").read_text();self.assertIn("primary: 'builtin/main'",text);self.assertIn("verifier: 'builtin/main'",text);self.assertIn("providers: {}",(agent/"models.yml").read_text())
    def test_two_custom_models_share_one_registered_endpoint(self):
        config='[llm]\nselector="on-prem/primary"\nmodel="primary"\nbase_url="http://127.0.0.1:9999/v1"\napi_key="test"\n[llm.verification]\nselector="on-prem/verifier"\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="explicit"\n[[llm.provider.models]]\nid="primary"\n[[llm.provider.models]]\nid="verifier"\n'
        tmp,base,agent,project,result=self.bootstrap(config)
        with tmp:
            self.assertEqual(result.returncode,0,result.stderr);models=(agent/"models.yml").read_text();self.assertIn("- id: 'primary'",models);self.assertIn("- id: 'verifier'",models);self.assertEqual(models.count("baseUrl:"),1)
    def test_builtin_primary_and_custom_verifier(self):
        config='[llm]\nselector="builtin/main"\nmodel=""\nbase_url="http://127.0.0.1:9999/v1"\napi_key="test"\n[llm.verification]\nselector="on-prem/verifier"\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="explicit"\n[[llm.provider.models]]\nid="verifier"\n'
        tmp,base,agent,project,result=self.bootstrap(config)
        with tmp:
            self.assertEqual(result.returncode,0,result.stderr);roles=(agent/"config.yml").read_text();self.assertIn("primary: 'builtin/main'",roles);self.assertIn("verifier: 'on-prem/verifier'",roles);self.assertIn("- id: 'verifier'",(agent/"models.yml").read_text())
    def test_custom_selector_without_endpoint_fails(self):
        tmp,base,agent,project,result=self.bootstrap('[llm]\nselector="on-prem/main"\nmodel="main"\napi_key="test"\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="proxy"\n')
        with tmp:self.assertNotEqual(result.returncode,0)
    def test_mismatched_custom_model_metadata_fails(self):
        config='[llm]\nselector="on-prem/selected"\nmodel="different"\nbase_url="http://127.0.0.1:9999/v1"\napi_key="test"\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="proxy"\n'
        tmp,base,agent,project,result=self.bootstrap(config)
        with tmp:self.assertNotEqual(result.returncode,0)
    def test_explicit_custom_provider_must_register_verifier(self):
        config='[llm]\nselector="on-prem/primary"\nmodel="primary"\nbase_url="http://127.0.0.1:9999/v1"\napi_key="test"\n[llm.verification]\nselector="on-prem/verifier"\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="explicit"\n[[llm.provider.models]]\nid="primary"\n'
        tmp,base,agent,project,result=self.bootstrap(config)
        with tmp:self.assertNotEqual(result.returncode,0)
if __name__=="__main__":unittest.main()
