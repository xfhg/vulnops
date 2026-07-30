from __future__ import annotations
import json, os, subprocess, sys, tempfile, tomllib, unittest
from pathlib import Path
from scripts.model_identity import model_diversity
from scripts.offline_package import network_identity, package_identity
ROOT=Path(__file__).resolve().parents[1]
ROLE_ARGS=["--orchestrator-model","p/orchestrator","--task-model","p/task","--slow-model","p/main","--smol-model","p/smol"]
ROLE_MAP={"orchestrator":"p/orchestrator","task":"p/task","slow":"p/main","smol":"p/smol"}
class ModelIdentityTests(unittest.TestCase):
    def bootstrap(self, config: str):
        tmp=tempfile.TemporaryDirectory(dir=ROOT/".harness");base=Path(tmp.name);config_path=base/"config.toml";config_path.write_text(config);agent=base/"agent";project=base/"project-config.yml";env=os.environ.copy();env.update({"VULNOPS_CONFIG_PATH":str(config_path),"VULNOPS_PROJECT_OMP_CONFIG":str(project),"VULNOPS_BOOTSTRAP_AGENT_DIR":str(agent)})
        result=subprocess.run(["bash",str(ROOT/"scripts/bootstrap-omp.sh")],cwd=ROOT,capture_output=True,text=True,check=False,env=env)
        return tmp,base,agent,project,result
    def test_verifier_is_required_and_both_selectors_define_resume_identity(self):
        schema=json.loads((ROOT/"schemas/v2/run-manifest.schema.json").read_text())
        self.assertIn("verifier_model",schema["required"])
        self.assertIn("model_roles",schema["required"])
        text=(ROOT/"scripts/resume-run.py").read_text()
        self.assertIn('context.get("verifier_model", "")',text)
        self.assertNotIn('context.get("verifier_model", context_model)',text)
        self.assertIn('vulnops-independent-verify-one:',(ROOT/"scripts/bootstrap-omp.sh").read_text())
        run_audit=(ROOT/"scripts/run-audit.sh").read_text()
        self.assertIn('scripts/load-config.sh',run_audit)
        self.assertLess(run_audit.index('scripts/load-config.sh'),run_audit.index('OMP_MODEL_SELECTOR'))
    def test_init_derives_boolean_diversity(self):
        with tempfile.TemporaryDirectory(dir=ROOT/"scans") as tmp:
            scan=Path(tmp)/"run";repo=Path(tmp)/"repo";repo.mkdir()
            cmd=[sys.executable,str(ROOT/"scripts/init-run.py"),"--harness-root",str(ROOT),"--repo-path",str(repo),"--scan-base",str(scan),"--run-id","r","--repo-name","repo","--remote-url","local","--repo-id","repo-id","--commit","abc","--depth","quick","--target-fingerprint","a"*64,"--reproduction-mode","off","--model","p/main",*ROLE_ARGS,"--verifier-model","p/verify"]
            env=os.environ.copy();env["VULNOPS_AUDIT_CONTEXT"]=str(Path(tmp)/"context.json")
            result=subprocess.run(cmd,capture_output=True,text=True,check=False,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            manifest=json.loads((scan/"run-manifest.json").read_text())
            self.assertIs(manifest["model_diversity"],True)
            self.assertEqual(manifest["verifier_model"],"p/verify")
            self.assertEqual(manifest["model_roles"],ROLE_MAP)
            self.assertRegex(manifest["harness_contract_sha256"],r"^[a-f0-9]{64}$")
            self.assertEqual(manifest["sast_budget"]["max_hunt_questions"],24)
    def test_thinking_effort_is_not_model_diversity(self):
        with tempfile.TemporaryDirectory(dir=ROOT/"scans") as tmp:
            scan=Path(tmp)/"run";repo=Path(tmp)/"repo";repo.mkdir();context=Path(tmp)/"context.json"
            cmd=[sys.executable,str(ROOT/"scripts/init-run.py"),"--harness-root",str(ROOT),"--repo-path",str(repo),"--scan-base",str(scan),"--run-id","r","--repo-name","repo","--remote-url","local","--repo-id","repo-id","--commit","abc","--depth","quick","--target-fingerprint","a"*64,"--reproduction-mode","off","--model","p/model:high",*ROLE_ARGS,"--verifier-model","p/model:xhigh"]
            result=subprocess.run(cmd,capture_output=True,text=True,check=False,env={**os.environ,"VULNOPS_AUDIT_CONTEXT":str(context)})
            self.assertEqual(result.returncode,0,result.stderr);self.assertIs(json.loads((scan/"run-manifest.json").read_text())["model_diversity"],False)
    def test_example_config_uses_a_genuinely_diverse_verifier(self):
        config=tomllib.loads((ROOT/"config.toml.example").read_text())
        primary=config["llm"]["selector"];verifier=config["llm"]["verification"]["selector"]
        self.assertTrue(model_diversity(primary,verifier))
    def test_primary_or_verifier_change_prevents_resume(self):
        with tempfile.TemporaryDirectory(dir=ROOT/"scans") as tmp:
            base=Path(tmp);scan=base/"scan";scan.mkdir();contract=subprocess.run([sys.executable,str(ROOT/"scripts/harness_contract.py")],capture_output=True,text=True,check=True).stdout.strip();budget={"max_concurrency":4,"max_hunt_tasks":12,"max_hunt_questions":24,"max_gapfill_rounds":1,"max_attempts":2,"context_packet_bytes":65536};network=network_identity("enforced");package=package_identity(ROOT);context={"schema_version":"2.0","workflow":"canonical-redteam-v2","run_id":"r","repo_path":str(base/"repo"),"short_sha":"abc","depth":"quick","target_fingerprint":"a"*64,"harness_contract_sha256":contract,"sast_budget":budget,"reproduction_mode":"off","network":network,"offline_package":package,"model":"p/main","model_roles":ROLE_MAP,"verifier_model":"p/verify","scan_base":str(scan)};Path(context["repo_path"]).mkdir();(base/"context.json").write_text(json.dumps(context));(scan/"run-manifest.json").write_text(json.dumps({"schema_version":"2.0","workflow":"canonical-redteam-v2","run_id":"r","commit":"abc","depth":"quick","target_fingerprint":"a"*64,"reproduction_mode":"off","network":network,"offline_package":package,"status":"running","harness_contract_sha256":contract,"sast_budget":budget,"model":"p/main","model_roles":ROLE_MAP,"verifier_model":"p/verify","phases":{phase:"pending" for phase in ("recon","tool-collection","sast","campaign-planning","intrusion","synthesis","final-verification","report")}}));(scan/"task-ledger.json").write_text(json.dumps({"schema_version":"2.0","run_id":"r","tasks":[]}))
            args=[sys.executable,str(ROOT/"scripts/resume-run.py"),str(base/"context.json"),context["repo_path"],"abc","quick","a"*64,"off"]
            role_values=[ROLE_MAP[name] for name in ("orchestrator","task","slow","smol")]
            same=subprocess.run([*args,"p/main",*role_values,"p/verify"],capture_output=True,text=True,check=False);self.assertIn("r\t",same.stdout)
            primary=subprocess.run([*args,"p/other",*role_values,"p/verify"],capture_output=True,text=True,check=False);self.assertEqual(primary.stdout,"")
            verifier=subprocess.run([*args,"p/main",*role_values,"p/other"],capture_output=True,text=True,check=False);self.assertEqual(verifier.stdout,"")
            changed_roles=["p/other",*role_values[1:]]
            roles=subprocess.run([*args,"p/main",*changed_roles,"p/verify"],capture_output=True,text=True,check=False);self.assertEqual(roles.stdout,"")
            budget_changed=subprocess.run([*args,"p/main",*role_values,"p/verify"],capture_output=True,text=True,check=False,env={**os.environ,"VULNOPS_SAST_QUICK_MAX_HUNT_QUESTIONS":"25"});self.assertIn("\trecover",budget_changed.stdout)
    def test_builtin_primary_inherits_verifier(self):
        tmp,base,agent,project,result=self.bootstrap('[llm]\nselector="builtin/main"\nmodel=""\n[llm.verification]\nselector=""\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="explicit"\n')
        with tmp:
            self.assertEqual(result.returncode,0,result.stderr);text=(agent/"config.yml").read_text();self.assertNotIn("  primary:",text);self.assertNotIn("  verifier:",text);self.assertIn("vulnops-independent-verify-one: 'builtin/main'",text);self.assertIn("providers: {}",(agent/"models.yml").read_text())
    def test_two_custom_models_share_one_registered_endpoint(self):
        config='[llm]\nselector="on-prem/primary"\nmodel="primary"\nbase_url="http://127.0.0.1:9999/v1"\napi_key="test"\n[llm.verification]\nselector="on-prem/verifier"\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="explicit"\n[[llm.provider.models]]\nid="primary"\n[[llm.provider.models]]\nid="verifier"\n'
        tmp,base,agent,project,result=self.bootstrap(config)
        with tmp:
            self.assertEqual(result.returncode,0,result.stderr);models=(agent/"models.yml").read_text();self.assertIn("- id: 'primary'",models);self.assertIn("- id: 'verifier'",models);self.assertEqual(models.count("baseUrl:"),1)
    def test_builtin_primary_and_custom_verifier(self):
        config='[llm]\nselector="builtin/main"\nmodel=""\nbase_url="http://127.0.0.1:9999/v1"\napi_key="test"\n[llm.verification]\nselector="on-prem/verifier"\n[llm.provider]\nname="on-prem"\nauth="api-key"\ndiscovery="explicit"\n[[llm.provider.models]]\nid="verifier"\n'
        tmp,base,agent,project,result=self.bootstrap(config)
        with tmp:
            self.assertEqual(result.returncode,0,result.stderr);roles=(agent/"config.yml").read_text();self.assertNotIn("  primary:",roles);self.assertNotIn("  verifier:",roles);self.assertIn("vulnops-independent-verify-one: 'on-prem/verifier'",roles);self.assertIn("- id: 'verifier'",(agent/"models.yml").read_text())

    def test_independent_verifier_uses_supported_fallback_role(self):
        agent=(ROOT/".omp/agents/vulnops-independent-verify-one.md").read_text()
        self.assertIn("model: [pi/slow]",agent)
        self.assertNotIn("pi/verifier",agent)
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
