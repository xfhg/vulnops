#!/usr/bin/env python3
"""Render a bounded sanitized report from final verified findings only."""
from __future__ import annotations
import argparse,json,os,re
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
SEVERITIES=("critical","high","medium","low","informational")
ORIGINS=("standalone_known","known_impact_expansion","composite_chain","independent_discovery","cross_evidence_discovery")
PATTERNS=((re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",re.S),"<redacted>"),(re.compile(r"\b(?:ghp_|sk-)[A-Za-z0-9]{20,}\b"),"<redacted>"),(re.compile(r"\bAKIA[0-9A-Z]{16}\b"),"<redacted>"),(re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s]+"),r"\1<redacted>"),(re.compile(r"```.*?```",re.S),"<technical-example-omitted>"))
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def load(path:Path,fallback:Any)->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError):return fallback
def clean(value:object,limit:int=8000)->str:
    text=str(value).replace("\x00","")[:limit]
    for pattern,replacement in PATTERNS:text=pattern.sub(replacement,text)
    return text
def sanitized(value:object)->object:
    if isinstance(value,str):return clean(value)
    if isinstance(value,list):return [sanitized(x) for x in value]
    if isinstance(value,dict):return {str(k):sanitized(v) for k,v in value.items()}
    return value
def write(path:Path,value:str)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(value); tmp.replace(path)
def main()->int:
    p=argparse.ArgumentParser();p.add_argument("scan_base",type=Path);a=p.parse_args();root=Path(__file__).resolve().parent.parent;context=load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT",root/".harness/audit-context.json")),{});final=load(a.scan_base/"final-verification/findings.json",{});findings=final.get("findings",[]) if isinstance(final,dict) else [];rejections=final.get("rejections",[]) if isinstance(final,dict) else []
    summary={"total":len(findings),"rejected":len(rejections),"confirmed":sum(x.get("verdict")=="confirmed" for x in findings),"needs_environment":sum(x.get("verdict")=="needs_environment" for x in findings),**{x:0 for x in SEVERITIES},**{x:0 for x in ORIGINS}}
    rendered=[]
    for finding in findings:
        summary[finding["severity"]]+=1;summary[finding["origin"]]+=1
        rendered.append({"id":finding["id"],"title":clean(finding["title"]),"finding_kind":finding["finding_kind"],"origin":finding["origin"],"severity":finding["severity"],"risk_score":finding["risk_score"],"confidence":finding["confidence"],"verdict":finding["verdict"],"description":clean(finding["closure_rationale"]),"impact":clean(finding["impact"]),"remediation":clean(finding["remediation"]),"evidence_refs":[str(x.get("artifact_ref")) for x in finding.get("source_refs",[])]})
    limitations=[]
    if not context.get("model_diversity"):limitations.append("Discovery and independent verification used fresh contexts with the same underlying model identity; reasoning effort alone is not model diversity.")
    if context.get("reproduction_mode")=="off":limitations.append("Safe reproduction was disabled; dynamic claims are limited to other cited deterministic evidence.")
    if int(context.get("recovery_count",0)):
        limitations.append(f"The audit recovered {int(context.get('recovery_count',0))} time(s); previously validated upstream phases were retained under immutable artifact seals and failed/downstream phases were rerun.")
    scans={}
    for phase,directory in (("recon","repo-context"),("tool-collection","tool-collection"),("sast","sast"),("campaign-planning","campaign-planning"),("intrusion","intrusion"),("synthesis","synthesis"),("final-verification","final-verification")):
        manifest=load(a.scan_base/directory/"phase-manifest.json",{});scans[phase]={"status":manifest.get("status"),"coverage":manifest.get("coverage",{})}
        if manifest.get("status")=="degraded":limitations.append(f"{phase} completed in degraded mode; consult its manifest.")
    report={"schema_version":"2.0","run_id":str(context.get("run_id","")),"repository":str(context.get("repo_name","unknown")),"commit":str(context.get("short_sha","unknown")),"date":now(),"summary":summary,"findings":rendered,"hardening_notes":sanitized(load(a.scan_base/"sast/hardening-notes.json",[])),"positive_patterns":sanitized(load(a.scan_base/"sast/positive-patterns.json",[])),"coverage":sanitized(load(a.scan_base/"sast/coverage-ledger.json",{})),"limitations":limitations,"scans":scans}
    write(a.scan_base/"report/security-report.json",json.dumps(report,indent=2,sort_keys=True)+"\n")
    lines=["# Security Audit Report","",f"**Repository:** {report['repository']}",f"**Commit:** {report['commit']}",f"**Run:** {report['run_id']}","","## Executive Summary","",f"{summary['total']} verified or environment-required findings; {summary['composite_chain']} composed attack paths, {summary['known_impact_expansion']} known-issue impact expansions, and {summary['independent_discovery']+summary['cross_evidence_discovery']} other added-value discoveries.","","## Findings",""]
    for finding in rendered:lines.extend([f"### [{finding['id']}] {finding['title']}","",f"- Severity: {finding['severity']} ({finding['risk_score']}/100)",f"- Origin: {finding['origin']}",f"- Confidence: {finding['confidence']}",f"- Verdict: {finding['verdict']}","",finding["description"],"",f"**Impact:** {finding['impact']}","",f"**Remediation:** {finding['remediation']}","",f"**Evidence:** {', '.join(finding['evidence_refs'])}",""])
    lines.extend(["## Coverage and Limitations",""]+[f"- {x}" for x in limitations]+[""])
    write(a.scan_base/"report/security-report.md","\n".join(lines))
    manifest={"phase":"report","status":"degraded" if summary["needs_environment"] else "ok","started_at":now(),"completed_at":now(),"inputs":["final-verification/findings.json"],"outputs":["report/security-report.json","report/security-report.md"],"coverage":summary,"tool_versions":{"renderer":"deterministic-v2"},"warnings":limitations,"errors":[]};write(a.scan_base/"report/phase-manifest.json",json.dumps(manifest,indent=2,sort_keys=True)+"\n");return 0
if __name__=="__main__":raise SystemExit(main())
