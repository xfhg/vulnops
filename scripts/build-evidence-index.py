#!/usr/bin/env python3
"""Build the single evidence ledger and typed attack-primitive catalog."""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path
from typing import Any

def load(path: Path, fallback: Any) -> Any:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): return fallback
def write(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(json.dumps(doc,separators=(",",":"),sort_keys=True)+"\n"); tmp.replace(path)
def stable(prefix: str, *parts: object) -> str:
    return prefix+hashlib.sha256("\0".join(str(x) for x in parts).encode()).hexdigest()[:12].upper()
def strings(items: object) -> list[str]: return [str(x) for x in items] if isinstance(items,list) else []
def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("scan_base",type=Path); p.add_argument("--context",type=Path); a=p.parse_args(); root=Path(__file__).resolve().parent.parent
    context=load(a.context or root/".harness/audit-context.json",{}); run_id=str(context.get("run_id","")); records=[]; primitives=[]; gaps=[]; warnings=[]
    def record(kind:str,source_id:str,ref:str,disposition:str,summary:str,files:list[str]) -> str:
        rid=stable("E-",kind,source_id,ref); records.append({"id":rid,"source_kind":kind,"source_id":source_id,"artifact_ref":ref,"disposition":disposition,"summary":summary[:2000] or source_id,"files":list(dict.fromkeys(files))}); return rid
    def primitive(kind:str,trust:str,rid:str,prereq:list[str],capability:str,boundary:str,assets:list[str],conditions:list[str],refs:list[str]) -> None:
        primitives.append({"id":stable("P-",kind,rid,capability),"type":kind,"trust":trust,"source_record_ids":[rid],"prerequisites":prereq or ["Attacker can reach the cited surface."],"capability_gained":capability or "Access to the cited security-relevant surface.","boundary":boundary or "Repository trust boundary","reachable_assets":assets,"conditions":conditions,"evidence_refs":list(dict.fromkeys(refs or [rid]))})
    surfaces=load(a.scan_base/"repo-context/security-surfaces.json",{})
    for item in surfaces.get("entry_points",[]) if isinstance(surfaces,dict) else []:
        sid=str(item.get("id")); ref=f"repo-context/security-surfaces.json:{sid}"; rid=record("recon",sid,ref,"promoted",f"{item.get('kind')} entry point at {item.get('path')}",[str(item.get("path"))]); primitive("access","context_only",rid,["Attacker can provide input to this entry point."],f"Influence input at {item.get('path')}",",".join(strings(item.get("trust_boundary_ids"))) or "Entry-point boundary",[str(item.get("path"))],[],[ref])
    for item in surfaces.get("trust_boundaries",[]) if isinstance(surfaces,dict) else []:
        sid=str(item.get("id")); ref=f"repo-context/security-surfaces.json:{sid}"; rid=record("recon",sid,ref,"promoted",str(item.get("description")),[]); primitive("state_transition","context_only",rid,[str(item.get("source_trust"))],str(item.get("target_trust")),str(item.get("description")),[],[],[ref])
    sca=load(a.scan_base/"tool-collection/sca-advisories.json",{})
    for item in sca.get("advisories",[]) if isinstance(sca,dict) else []:
        sid=str(item.get("id")); ref=f"tool-collection/sca-advisories.json:{sid}"; rid=record("sca",sid,ref,"unresolved",f"{item.get('advisory_id')} affects {item.get('package')} {item.get('version')}",[str(item.get("source_lockfile"))]); primitive("vulnerability","candidate",rid,["Affected dependency use is reachable from an attacker-controlled path."],f"Potential capability described by {item.get('advisory_id')}","Dependency boundary",[str(item.get("package"))],[],[ref])
    secrets=load(a.scan_base/"tool-collection/secrets-redacted.json",{})
    for item in secrets.get("candidates",[]) if isinstance(secrets,dict) else []:
        # Scanner-only secret candidates have no proven credential capability.
        # Preserve every disposition in the evidence ledger, but do not inflate
        # unverified matches into attack primitives before source validation.
        sid=str(item.get("id")); ref=f"tool-collection/secrets-redacted.json:{sid}"; record("secret",sid,ref,"unresolved",f"Redacted {item.get('type')} candidate",[str(item.get("file"))])
    for receipt_name in ("wraith-receipt.json","poltergeist-receipt.json"):
        receipt=load(a.scan_base/"tool-collection"/receipt_name,{})
        for offset,message in enumerate(receipt.get("warnings",[]) if isinstance(receipt,dict) else [],1):
            record("tool_warning",f"{receipt_name}-{offset}",f"tool-collection/{receipt_name}","unresolved",str(message),[])
    dependency_limitations=load(a.scan_base/"tool-collection/dependency-limitations.json",{})
    for item in dependency_limitations.get("limitations",[]) if isinstance(dependency_limitations,dict) else []:
        sid=str(item.get("code"));rid=record("coverage",sid,f"tool-collection/dependency-limitations.json:{sid}","unresolved",str(item.get("message")),strings(item.get("files")));gaps.append(rid)
    verified=load(a.scan_base/"sast/verified-findings.json",[]); verified_ids=set()
    for item in verified if isinstance(verified,list) else []:
        sid=str(item.get("id")); verified_ids.add(sid); ref=f"sast/verified-findings.json:{sid}"; level=str(item.get("verification_level")); disposition="needs_environment" if level=="environment_required" else "promoted"; rid=record("sast",sid,ref,disposition,str(item.get("title")),[str((item.get("root_cause_location") or {}).get("file",""))]); attacker=item.get("attacker") or {}; conditions=[str(x.get("description")) for x in item.get("conditions",[]) if isinstance(x,dict)]; primitive("vulnerability","candidate" if disposition=="needs_environment" else "confirmed",rid,[str(attacker.get("starting_access","Attacker reaches the entry point."))],str(item.get("impact")),str(attacker.get("boundary_crossed","Application boundary")),[str((item.get("root_cause_location") or {}).get("file",""))],conditions,[ref,*strings(item.get("evidence_refs"))])
    dropped=load(a.scan_base/"sast/dropped-findings.json",[])
    for item in dropped if isinstance(dropped,list) else []:
        sid=str(item.get("raw_id") or item.get("id")); status=str(item.get("status")); disposition="needs_environment" if status=="deferred" else "rejected"; record("sast",sid,f"sast/dropped-findings.json:{item.get('id')}",disposition,str(item.get("reason")),[])
    validations=load(a.scan_base/"sast/validation-results.json",[])
    for item in validations if isinstance(validations,list) else []:
        sid=str(item.get("id") or item.get("candidate_id")); status=str(item.get("status")); disposition="promoted" if status=="source_verified" else "needs_environment" if status in {"deferred","environment_required"} else "rejected"; record("sast",sid,f"sast/validation-results.json:{sid}",disposition,str(item.get("closure_reason")),[])
    reproduction_dir=a.scan_base/"sast/reproduction"
    for result_path in sorted(reproduction_dir.glob("*/result.json")) if reproduction_dir.is_dir() else []:
        item=load(result_path,{}); sid=str(item.get("finding_id") or result_path.parent.name); status=str(item.get("status")); disposition="promoted" if status=="dynamic_verified" else "needs_environment" if status in {"environment_required","failed"} else "rejected" if status=="contradicted" else "unresolved"; record("reproduction",sid,str(result_path.relative_to(a.scan_base)),disposition,f"Safe reproduction status: {status}",[])
    raw=load(a.scan_base/"sast/raw-findings.json",[])
    known={r["source_id"] for r in records if r["source_kind"]=="sast"}
    for item in raw if isinstance(raw,list) else []:
        sid=str(item.get("id"));
        if sid not in known: record("sast",sid,f"sast/raw-findings.json:{sid}","unresolved",str(item.get("title")),[str((item.get("root_cause_location") or {}).get("file",""))])
    coverage=load(a.scan_base/"sast/coverage-ledger.json",{})
    for cell in coverage.get("cells",[]) if isinstance(coverage,dict) else []:
        sid=str(cell.get("id")); status=str(cell.get("status")); disposition="closed" if status in {"clean","not_applicable"} else "promoted" if status in {"finding","tool_satisfied"} else "unresolved"; rid=record("coverage",sid,f"sast/coverage-ledger.json:{sid}",disposition,str(cell.get("reason")),[])
        if disposition=="unresolved": gaps.append(rid)
    for task in coverage.get("tasks",[]) if isinstance(coverage,dict) else []:
        for offset,rabbit in enumerate(task.get("rabbit_holes",[]) if isinstance(task,dict) else [],1):
            rid=record("coverage",f"{task.get('id')}-rabbit-{offset}",f"sast/coverage-ledger.json:{task.get('id')}","unresolved",str(rabbit),strings(task.get("files_reviewed")));gaps.append(rid)
    wishlist=load(a.scan_base/"sast/wishlist.json",{})
    for item in wishlist.get("items",[]) if isinstance(wishlist,dict) else []:
        status=str(item.get("status")); disposition="closed" if status=="resolved" else "needs_environment" if status=="unavailable" else "unresolved"; rid=record("coverage",str(item.get("id")),f"sast/wishlist.json:{item.get('id')}",disposition,f"{item.get('request')}: {item.get('reason')}",[])
        if disposition!="closed":gaps.append(rid)
    for filename,kind in (("hardening-notes.json","hardening"),("positive-patterns.json","positive_pattern")):
        items=load(a.scan_base/"sast"/filename,[])
        for index,item in enumerate(items if isinstance(items,list) else [],1):
            sid=str(item.get("id") if isinstance(item,dict) else f"{kind}-{index}"); record(kind,sid,f"sast/{filename}:{sid}","closed",str(item.get("description") if isinstance(item,dict) else item),[])
    doc={"schema_version":"2.0","run_id":run_id,"records":records,"primitives":primitives,"coverage_gaps":list(dict.fromkeys(gaps)),"warnings":warnings}; write(a.scan_base/"campaign-planning/evidence-index.json",doc); print(a.scan_base/"campaign-planning/evidence-index.json"); return 0
if __name__=="__main__": raise SystemExit(main())
