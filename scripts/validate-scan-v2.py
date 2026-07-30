#!/usr/bin/env python3
"""Whole-run integrity gate for the sole canonical VulnOps v2 workflow."""
from __future__ import annotations
import argparse, hashlib, json, os, re, subprocess, sys, tomllib
from pathlib import Path
from typing import Any
from artifact_policy import artifact_size_limit
from harness_contract import harness_contract_sha256
from model_identity import model_diversity
from offline_package import network_identity, package_identity
from phase_seal import directory_sha256
PHASES=("recon","tool-collection","sast","campaign-planning","intrusion","synthesis","final-verification","report")
DIRS={"recon":"repo-context",**{x:x for x in PHASES if x!="recon"}}
TASKS={"recon":"Recon","tool-collection":"ToolCollection","sast":"SASTLead","campaign-planning":"CampaignPlanning","intrusion":"Intrusion","synthesis":"Synthesis","final-verification":"FinalVerification","report":"Report"}
def load(path:Path,errors:list[str])->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:errors.append(f"missing {path}")
    except json.JSONDecodeError as exc:errors.append(f"invalid JSON {path}: {exc}")
    return None
def artifact(scan:Path,ref:str)->Path|None:
    path=(scan/ref.split(":",1)[0].split("#",1)[0]).resolve()
    try:path.relative_to(scan.resolve())
    except ValueError:return None
    return path if path.is_file() else None
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("harness_root",type=Path);p.add_argument("scan_base",type=Path);a=p.parse_args();root=a.harness_root.resolve();scan=a.scan_base.resolve();errors=[];run=load(scan/"run-manifest.json",errors) or {};ledger=load(scan/"task-ledger.json",errors) or {};context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")),errors) or {}
    if run.get("schema_version")!="2.0":errors.append("only canonical schema_version 2.0 is accepted")
    if run.get("workflow")!="canonical-redteam-v2" or context.get("workflow")!="canonical-redteam-v2":errors.append("non-canonical workflow identity is rejected")
    if run.get("status") not in {"running","degraded","complete"}:errors.append("run is not in a final-validation state")
    if context.get("run_id")!=run.get("run_id") or Path(str(context.get("scan_base",""))).resolve()!=scan:errors.append("audit context identity mismatch")
    if context.get("harness_contract_sha256")!=harness_contract_sha256(root) or run.get("harness_contract_sha256")!=harness_contract_sha256(root):errors.append("harness contract fingerprint mismatch")
    if context.get("sast_budget")!=run.get("sast_budget"):errors.append("SAST budget snapshot mismatch")
    try:
        with (root/"config.toml").open("rb") as handle:current_mode=str(tomllib.load(handle).get("harness",{}).get("network",{}).get("linux_agent_egress","enforced"))
        current_network=network_identity(current_mode);current_package=package_identity(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"cannot resolve current package or agent egress identity: {exc}");current_network={};current_package={}
    if run.get("network")!=context.get("network") or run.get("network")!=current_network:errors.append("agent egress identity mismatch")
    if run.get("offline_package")!=context.get("offline_package") or run.get("offline_package")!=current_package:errors.append("offline package identity mismatch")
    primary=str(run.get("model",""));verifier=str(run.get("verifier_model",""));diversity=model_diversity(primary,verifier)
    if not verifier:errors.append("verifier_model is required")
    if run.get("model_diversity") is not diversity or context.get("model_diversity") is not diversity:errors.append("model diversity metadata mismatch")
    if context.get("model")!=primary or context.get("model_roles")!=run.get("model_roles") or context.get("verifier_model")!=verifier or context.get("target_fingerprint")!=run.get("target_fingerprint"):errors.append("audit context model roles or fingerprint identity mismatch")
    for schema_name,document in (("run-manifest.schema.json",scan/"run-manifest.json"),("task-ledger.schema.json",scan/"task-ledger.json")):
        result=subprocess.run([sys.executable,str(root/"scripts/validate-json.py"),str(root/"schemas/v2"/schema_name),str(document)],capture_output=True,text=True,check=False)
        if result.returncode:errors.append(result.stderr.strip() or f"schema validation failed: {document}")
    current_contract=harness_contract_sha256(root);seals=run.get("phase_seals",{}) if isinstance(run.get("phase_seals"),dict) else {}
    history=run.get("recovery_history",[]) if isinstance(run.get("recovery_history"),list) else []
    if run.get("recovery_count")!=len(history):errors.append("recovery count does not match recovery history")
    if [item.get("generation") for item in history if isinstance(item,dict)]!=list(range(1,len(history)+1)):errors.append("recovery generations are not contiguous")
    for phase in PHASES:
        seal=seals.get(phase);retained=bool(isinstance(seal,dict) and seal.get("validation")=="retained_prior_gate" and seal.get("contract_sha256")!=current_contract)
        if retained:
            try:digest,count=directory_sha256(scan,phase)
            except ValueError as exc:errors.append(str(exc));digest="";count=-1
            if digest!=seal.get("artifact_sha256") or count!=seal.get("file_count"):errors.append(f"retained phase seal mismatch: {phase}")
        else:
            result=subprocess.run([sys.executable,str(root/"scripts/validate-phase-v2.py"),str(root),str(scan),phase],capture_output=True,text=True,check=False)
            if result.returncode:errors.append(result.stderr.strip() or f"{phase} validation failed")
            if isinstance(seal,dict):
                try:digest,count=directory_sha256(scan,phase)
                except ValueError as exc:errors.append(str(exc));digest="";count=-1
                if digest!=seal.get("artifact_sha256") or count!=seal.get("file_count"):errors.append(f"phase seal mismatch: {phase}")
        phase_doc=load(scan/DIRS[phase]/"phase-manifest.json",errors) or {}; actual=phase_doc.get("status")
        if retained and actual not in {"ok","degraded"}:errors.append(f"retained phase {phase} lacks a successful prior manifest")
        if (run.get("phases") or {}).get(phase)!=actual:errors.append(f"run manifest status for {phase} does not match phase manifest")
    obsolete=["sca","secrets","intelligence","triage","final-reconciliation"]
    for name in obsolete:
        if (scan/name).exists():errors.append(f"legacy artifact directory is forbidden: {name}")
    for path in (scan/"sast/task-manifest.json",scan/"sast/decompose.md"):
        if path.exists():errors.append(f"legacy artifact is forbidden: {path.relative_to(scan)}")
    task_ids=[str(x.get("id")) for x in ledger.get("tasks",[]) if isinstance(x,dict)]
    if len(task_ids)!=len(set(task_ids)):errors.append("task ledger contains duplicate task IDs")
    if any(task_id not in TASKS.values() for task_id in task_ids):errors.append("task ledger contains a noncanonical top-level task")
    if sum(1 for x in ledger.get("tasks",[]) if isinstance(x,dict) and x.get("status")=="running")>1:errors.append("task ledger contains multiple running top-level tasks")
    task_by_id={str(x.get("id")):x for x in ledger.get("tasks",[]) if isinstance(x,dict)}
    for phase,task_id in TASKS.items():
        task=task_by_id.get(task_id)
        if not task or task.get("phase")!=phase or task.get("status") not in {"ok","degraded"}:errors.append(f"task ledger missing terminal {task_id}")
        elif artifact(scan,str(task.get("artifact",""))) is None:errors.append(f"task {task_id} artifact does not resolve")
    final=load(scan/"final-verification/findings.json",errors) or {}; report=load(scan/"report/security-report.json",errors) or {}
    if final.get("model_diversity") is not diversity:errors.append("final model_diversity mismatch")
    if report.get("execution_environment")!={"network":run.get("network"),"offline_package":run.get("offline_package")}:errors.append("report execution environment differs from run identity")
    final_ids={str(x.get("id")) for x in final.get("findings",[]) if isinstance(x,dict)}; report_ids={str(x.get("id")) for x in report.get("findings",[]) if isinstance(x,dict)}
    if final_ids!=report_ids:errors.append("report finding IDs differ from final verified findings")
    for finding in final.get("findings",[]):
        fid=str(finding.get("id"));
        if finding.get("model_diversity") is not diversity:errors.append(f"{fid} diversity mismatch")
        if (finding.get("verification") or {}).get("model")!=primary:errors.append(f"{fid} source model mismatch")
        for ref in [finding.get("independent_verification_ref"),*(finding.get("verification") or {}).get("source_validation_refs",[]),*finding.get("graph_receipt_refs",[])]:
            if ref and artifact(scan,str(ref)) is None:errors.append(f"{fid} unresolved artifact reference: {ref}")
    for path in sorted((scan/"final-verification/results").glob("*.json")):
        result=load(path,errors) or {}
        if result.get("model")!=verifier or result.get("model_diversity") is not diversity:errors.append(f"verifier metadata mismatch: {path.name}")
        checked=subprocess.run([sys.executable,str(root/"scripts/validate-json.py"),str(root/"schemas/v2/independent-verification-result.schema.json"),str(path)],capture_output=True,text=True,check=False)
        if checked.returncode:errors.append(checked.stderr.strip() or f"invalid verifier result: {path.name}")
    for path in sorted((scan/"sast/reproduction").glob("*/result.json")) if (scan/"sast/reproduction").is_dir() else []:
        checked=subprocess.run([sys.executable,str(root/"scripts/validate-json.py"),str(root/"schemas/v2/reproduction-result.schema.json"),str(path),"--semantic","reproduction-result"],capture_output=True,text=True,check=False)
        if checked.returncode:errors.append(checked.stderr.strip() or f"invalid reproduction result: {path}")
        reproduction=load(path,errors) or {}
        for ref_key,hash_key in (("test_ref","test_sha256"),("patch_ref","patch_sha256")):
            ref=reproduction.get(ref_key);expected=(reproduction.get("hashes") or {}).get(hash_key)
            if ref:
                resolved=artifact(scan,str(ref))
                if resolved is None or hashlib.sha256(resolved.read_bytes()).hexdigest()!=expected:errors.append(f"reproduction artifact hash mismatch: {ref}")
    secret_patterns=(re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),re.compile(r"ghp_[A-Za-z0-9]{20,}"),re.compile(r"AKIA[0-9A-Z]{16}"),re.compile(r"sk-[A-Za-z0-9]{20,}"))
    for path in scan.rglob("*"):
        if path.is_file():
            size=path.stat().st_size
            limit=artifact_size_limit(path.relative_to(scan))
            if size>limit:errors.append(f"artifact exceeds bounded size policy: {path.relative_to(scan)} ({size}>{limit})")
            text=path.read_text(encoding="utf-8",errors="ignore")
            if any(pattern.search(text) for pattern in secret_patterns):errors.append(f"possible raw secret in {path.relative_to(scan)}")
    forbidden_terms=("include_raw","raw tool output","raw proof output")
    for path in (scan/"report/security-report.json",scan/"report/security-report.md"):
        if path.is_file() and any(term in path.read_text(encoding="utf-8",errors="ignore").lower() for term in forbidden_terms):errors.append(f"raw-output policy violation in {path.name}")
    summary=report.get("summary",{}) if isinstance(report,dict) else {}
    if summary.get("total")!=len(final.get("findings",[])) or summary.get("rejected")!=len(final.get("rejections",[])):errors.append("report total or rejection count mismatch")
    for key in ("critical","high","medium","low","informational"):
        if summary.get(key)!=sum(x.get("severity")==key for x in final.get("findings",[])):errors.append(f"report severity count mismatch: {key}")
    for key in ("standalone_known","known_impact_expansion","composite_chain","independent_discovery","cross_evidence_discovery"):
        if summary.get(key)!=sum(x.get("origin")==key for x in final.get("findings",[])):errors.append(f"report origin count mismatch: {key}")
    if errors:
        for error in errors:print(f"[validate-scan-v2] ERROR: {error}",file=sys.stderr)
        print(f"[validate-scan-v2] failed with {len(errors)} error(s)",file=sys.stderr);return 1
    print("[validate-scan-v2] scan artifacts valid");return 0
if __name__=="__main__":raise SystemExit(main())
