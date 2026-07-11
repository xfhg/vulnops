#!/usr/bin/env python3
"""Build bounded evidence-led campaigns; novelty is an outcome, not a seed rule."""
from __future__ import annotations
import argparse, json, os
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any

BUDGETS={"quick":{"primitive_led":2,"gap_driven":1,"direct_validation":1},"balanced":{"primitive_led":5,"gap_driven":3,"direct_validation":2},"full":{"primitive_led":10,"gap_driven":7,"direct_validation":3}}
def load(path:Path,fallback:Any)->Any:
    try:return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError):return fallback
def write(path:Path,doc:object)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_name(f".{path.name}.{os.getpid()}.tmp"); tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n"); tmp.replace(path)
def now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("scan_base",type=Path); p.add_argument("--context",type=Path); a=p.parse_args(); root=Path(__file__).resolve().parent.parent
    context=load(a.context or root/".harness/audit-context.json",{}); depth=str(context.get("depth","quick")); index=load(a.scan_base/"campaign-planning/evidence-index.json",{}); records={r["id"]:r for r in index.get("records",[]) if isinstance(r,dict)}; primitives=[x for x in index.get("primitives",[]) if isinstance(x,dict)]; quotas=BUDGETS[depth]; campaigns=[]
    def add(lane:str,selected:list[dict],evidence:list[str],hypothesis:str,expected:str)->None:
        if not evidence:return
        files=[]
        for rid in evidence:files.extend(records.get(rid,{}).get("files",[]))
        files=list(dict.fromkeys(f for f in files if f))
        subject=files[0] if files else next((x for x in (p.get("reachable_assets",[]) for p in selected) for x in x if x),"")
        questions=[]
        if subject:questions=[{"id":f"Q-{len(campaigns)+1:03d}-1","type":"affected" if "." in subject else "query","subject":subject,"reason":"Test whether the suspected capability reaches another security-relevant component."}]
        capabilities="; ".join(str(x.get("capability_gained")) for x in selected) or "Attacker-controlled input"
        boundaries="; ".join(dict.fromkeys(str(x.get("boundary")) for x in selected)) or "Repository trust boundary"
        campaigns.append({"id":f"CAM-{len(campaigns)+1:03d}","lane":lane,"starting_evidence":list(dict.fromkeys(evidence)),"primitive_ids":[x["id"] for x in selected],"attacker_capability":capabilities,"target_boundary":boundaries,"hypothesis":hypothesis,"source_files":files,"graph_questions":questions,"validation_method":"Read the complete source path, verify every precondition and mitigation, and use safe reproduction only when bubblewrap is functionally available.","stop_conditions":["Close when source disproves reachability or a required precondition.","Use needs_environment when deployment-only evidence is required."],"expected_added_value":expected,"disposition":"unresolved"})
    ranked=sorted(primitives,key=lambda x:({"confirmed":0,"candidate":1,"context_only":2}.get(x.get("trust"),9),x.get("id")))
    actionable=[item for item in ranked if item.get("trust") in {"confirmed","candidate"}]
    pair_candidates=list(combinations(actionable,2))
    used=0
    for left,right in pair_candidates:
        if used>=quotas["primitive_led"]:break
        if left.get("source_record_ids")==right.get("source_record_ids"):continue
        add("primitive_led",[left,right],[*left.get("source_record_ids",[]),*right.get("source_record_ids",[])],f"Determine whether the capability from {left['id']} satisfies a prerequisite or bypass condition for {right['id']}, or the reverse, producing an attack path or impact not established by either primitive alone.","A proven transition between known primitives, new boundary crossing, or materially greater composed impact; otherwise a reasoned closure of the proposed composition."); used+=1
    if used<quotas["primitive_led"]:
        for primitive in actionable:
            if used>=quotas["primitive_led"]:break
            add("primitive_led",[primitive],primitive.get("source_record_ids",[]),f"Trace what consumes the capability granted by {primitive['id']} and determine whether it exposes a second weakness, bypasses a compensating control, or expands reachability.","A newly proven downstream weakness or impact expansion rooted in the known primitive."); used+=1
    gap_records=[records[rid] for rid in index.get("coverage_gaps",[]) if rid in records]
    recon_records=[r for r in records.values() if r.get("source_kind")=="recon"]
    for item in (gap_records+recon_records)[:quotas["gap_driven"]]:
        selected=[p for p in ranked if item["id"] in p.get("source_record_ids",[])][:1]
        add("gap_driven",selected,[item["id"]],f"Investigate {item['summary']} for state/order/replay violations, races, parser differentials, fallback paths, or implicit trust assumptions not covered by known-pattern checks.","A code-backed root cause or an evidence-backed closure of this uncovered boundary or state transition.")
    candidates=[p for p in actionable if p.get("trust")=="candidate"]
    for primitive in candidates[:quotas["direct_validation"]]:
        add("direct_validation",[primitive],primitive.get("source_record_ids",[]),f"Validate {primitive['id']} for installed/active state, attacker reachability, affected use, concrete impact, and at least one downstream consumer of the gained capability.","Reachability and impact evidence for the known issue, plus any newly proven one-hop expansion.")
    doc={"schema_version":"2.0","run_id":str(context.get("run_id","")),"depth":depth,"budget":quotas,"campaigns":campaigns,"coverage":{"evidence_records":len(records),"primitives":len(primitives),"campaigns":len(campaigns)},"warnings":[]}; write(a.scan_base/"campaign-planning/campaign-plan.json",doc)
    counts={lane:sum(x["lane"]==lane for x in campaigns) for lane in quotas}; (a.scan_base/"campaign-planning/summary.md").write_text("# Red-Team Campaign Planning\n\n"+"\n".join(f"- {k.replace('_',' ').title()}: {v}" for k,v in counts.items())+f"\n- Evidence records: {len(records)}\n- Attack primitives: {len(primitives)}\n")
    manifest={"phase":"campaign-planning","status":"ok","started_at":now(),"completed_at":now(),"inputs":["repo-context/security-surfaces.json","tool-collection/collection.json","tool-collection/wraith-receipt.json","tool-collection/poltergeist-receipt.json","sast/verified-findings.json","sast/dropped-findings.json","sast/validation-results.json","sast/coverage-ledger.json","sast/wishlist.json"],"outputs":["campaign-planning/evidence-index.json","campaign-planning/campaign-plan.json","campaign-planning/summary.md"],"coverage":{"evidence_records":len(records),"primitives":len(primitives),"campaigns":len(campaigns),**counts},"tool_versions":{"planner":"deterministic-v2","primary_model":str(context.get("model","unknown"))},"warnings":[],"errors":[]};write(a.scan_base/"campaign-planning/phase-manifest.json",manifest);print(a.scan_base/"campaign-planning/campaign-plan.json");return 0
if __name__=="__main__":raise SystemExit(main())
