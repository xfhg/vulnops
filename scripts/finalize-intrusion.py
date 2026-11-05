#!/usr/bin/env python3
"""Publish Intrusion only after all bounded waves and composition decisions close."""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from intrusion_contract import artifact, composition_resolved, load, publish, validate_intrusion, result_evidence_diagnostics
from evidence_accounting import summarize
from run_lifecycle import current_assessment, require_active_phase


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_base", type=Path)
    args = parser.parse_args()
    scan = args.scan_base.resolve()
    root = Path(__file__).resolve().parent.parent
    context = load(Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json")))
    try:
        require_active_phase(scan, context, "intrusion")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("[finalize-intrusion] ERROR: " + str(exc), file=sys.stderr)
        return 1
    errors, results = [], []
    try:
        paths = sorted((scan / "intrusion/waves").glob("[0-9][0-9][0-9].json"))
        if not paths:
            raise ValueError("initialize and close the immutable Intrusion wave first")
        latest = load(paths[-1])
        results = []
        for _, record in sorted(latest["results"].items()):
            result = load(artifact(scan, record["ref"]))
            if record.get("assessment_context"):
                result = {**result, "assessment_context": record["assessment_context"]}
                result["candidates"] = [{**candidate, "assessment_context": record["assessment_context"]}
                                        for candidate in result["candidates"]]
            results.append(result)
        extra = {p.stem for p in (scan / "intrusion/results").glob("*.json")} - set(latest["results"])
        if extra:
            raise ValueError("orphan intrusion results: " + ", ".join(sorted(extra)))
        wrapper = {"schema_version": "2.0", "run_id": context["run_id"], "results": results,
                   "attack_objectives": latest["attack_objectives"],
                   "investigation_questions": latest["investigation_questions"],
                   "allocation_deferrals": latest.get("allocation_deferrals", [])}
        index = load(artifact(scan, "campaign-planning/evidence-index.json"))
        wrapper["evidence_quality"] = summarize([
            issue for result in results for issue in result_evidence_diagnostics(
                scan, Path(context.get("source_root") or context["repo_path"]), context, result,
                historical=not current_assessment(result, context))])
        validate_intrusion(scan, Path(context.get("source_root") or context["repo_path"]), context, index, wrapper)
        if not composition_resolved(wrapper):
            raise ValueError("actionable primitive composition needs continuation or explicit deferral")
        ids = [candidate["id"] for result in results for candidate in result["candidates"]]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate intrusion candidate identity")
        publish(scan / "intrusion/intrusion-results.json", wrapper)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        errors.append(str(exc))
    counts = {name: sum(r.get("resolution", {}).get("outcome") == name for r in results) for name in ("established", "contradicted", "locally_unresolved", "externally_blocked", "budget_deferred", "execution_failed")}
    counts["needs_environment"] = sum(r.get("status") == "needs_environment" for r in results)
    counts["evidence_limited"] = sum(row["disposition"] == "evidence_limited"
                                    for result in results for row in result.get("non_promoted", []))
    summary = "# Intrusion Question Results\n\n" + "\n".join(f"- {key.replace('_', ' ').title()}: {value}" for key, value in counts.items()) + "\n\nThese are scoped question outcomes, not objective success assessments. Established capabilities and contradicted routes do not establish goal achievement or exhaustive safety; final independent verification owns objective assessment.\n"
    (scan / "intrusion").mkdir(parents=True, exist_ok=True)
    (scan / "intrusion/summary.md").write_text(summary, encoding="utf-8")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {"phase": "intrusion", "status": "failed" if errors else "degraded" if counts["needs_environment"] or counts["execution_failed"] else "ok", "started_at": now, "completed_at": now, "inputs": ["campaign-planning/evidence-index.json", "campaign-planning/campaign-plan.json"], "outputs": ["intrusion/intrusion-results.json", "intrusion/summary.md"], "coverage": {"campaigns": len(results), **counts}, "tool_versions": {"primary_model": str(context.get("model", "unknown")), "codegraph": "typed-adapter-v2"}, "warnings": [], "errors": errors}
    # Failed manifests are replaceable while the phase is active; successful evidence is not.
    path = scan / "intrusion/phase-manifest.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    for error in errors:
        print("[finalize-intrusion] ERROR: " + error, file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
