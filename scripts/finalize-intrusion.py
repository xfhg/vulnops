#!/usr/bin/env python3
"""Finalize intrusion artifacts from validated scoped codegraph runs.

This script is intentionally conservative: it records graph-backed context for
final reconciliation, but it does not invent upgrades or downgrades. Agents may
add richer analysis later, but the phase can complete without another long LLM
turn after codegraph has already extracted the scoped context.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def seed_map(scan: Path) -> dict[str, dict[str, Any]]:
    data = load_json(scan / "triage" / "intrusion-seeds.json", {})
    seeds = data.get("seeds", []) if isinstance(data, dict) else []
    return {str(seed.get("id")): seed for seed in seeds if isinstance(seed, dict) and seed.get("id")}


def graph_stats(context_path: Path) -> dict[str, int]:
    ctx = load_json(context_path, {})
    if not isinstance(ctx, dict):
        return {"nodes": 0, "edges": 0, "communities": 0}
    nodes = ctx.get("nodes", [])
    edges = ctx.get("edges", [])
    return {
        "nodes": len(nodes) if isinstance(nodes, list) else 0,
        "edges": len(edges) if isinstance(edges, list) else 0,
        "communities": 0,
    }


def validate_scope(scan: Path, scope: dict[str, Any]) -> tuple[bool, dict[str, Any], list[str]]:
    sid = str(scope.get("id", ""))
    cg_context = scan / "intrusion" / "codegraph-runs" / sid / "codegraph-out" / "context.json"
    errors: list[str] = []
    stats = graph_stats(cg_context)
    codegraph_ok = (stats["nodes"] + stats["edges"]) > 0
    if not codegraph_ok:
        if not cg_context.is_file():
            errors.append(f"{sid}: missing codegraph context.json")
        else:
            errors.append(f"{sid}: codegraph context has no nodes or edges")
    evidence_kind = "codegraph" if codegraph_ok else "none"
    merged = {
        "scope_id": sid,
        **stats,
        "evidence_kind": evidence_kind,
    }
    return not errors, merged, errors


def action_for_question_type(question_type: str) -> str:
    if question_type == "dependency_reachability":
        return "confirm"
    if question_type in {"attack_path", "credential_flow", "cross_boundary", "reachability"}:
        return "new-context"
    return "new-context"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_base")
    args = parser.parse_args()

    scan = Path(args.scan_base).resolve()
    intrusion = scan / "intrusion"
    plan = load_json(intrusion / "intrusion-plan.json", {})
    if not isinstance(plan, dict) or plan.get("mode") != "targeted-ooda":
        raise SystemExit("missing targeted-ooda intrusion/intrusion-plan.json")
    scopes = plan.get("scopes", [])
    if not isinstance(scopes, list) or not scopes:
        raise SystemExit("intrusion plan has no scopes")

    seeds = seed_map(scan)
    enrichments: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    completed = 0
    required_failed = 0
    scope_summaries: list[dict[str, Any]] = []

    findings_dir = intrusion / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    for scope in scopes:
        if not isinstance(scope, dict):
            errors.append("intrusion plan contains non-object scope")
            continue
        ok, stats, scope_errors = validate_scope(scan, scope)
        scope_id = str(scope.get("id", stats.get("scope_id", "")))
        seed_ids = scope.get("seed_ids", []) or []
        qtypes = sorted({str(s.get("question_type", "reachability")) for s in (seeds.get(str(sid), {}) for sid in seed_ids) if isinstance(s, dict)} | set(scope.get("question_types", []) or [])) or ["reachability"]
        primary_qtype = qtypes[0]
        scope_summaries.append({**stats, "scope_id": scope_id, "seed_ids": seed_ids, "required": bool(scope.get("required"))})
        if scope_errors:
            errors.extend(scope_errors)
            if scope.get("required"):
                required_failed += 1
        elif stats.get("evidence_kind") != "none":
            completed += 1
        for seed_id in seed_ids:
            seed = seeds.get(str(seed_id), {})
            evidence_refs = list(seed.get("evidence_refs", [])) if isinstance(seed.get("evidence_refs"), list) else []
            evidence_refs.extend(
                [
                    f"intrusion/codegraph-runs/{scope_id}/codegraph-out/context.json",
                ]
            )
            enrichment = {
                "triage_id": str(seed_id),
                "type": primary_qtype,
                "action": action_for_question_type(primary_qtype),
                "severity": seed.get("severity", "info"),
                "confidence": seed.get("confidence", "medium"),
                "evidence_refs": evidence_refs,
                "evidence_kind": stats.get("evidence_kind", "codegraph"),
                "summary": (
                    f"Scoped graph analysis completed for {seed_id} in {scope_id} "
                    f"({stats.get('evidence_kind', 'codegraph')} evidence: "
                    f"{stats['nodes']} nodes, {stats['edges']} edges, {stats['communities']} communities). "
                    "Graph context for reconciliation; does not by itself upgrade or downgrade severity."
                ),
            }
            enrichments.append(enrichment)

        finding_path = findings_dir / f"{scope_id}.md"
        finding_path.write_text(
            "\n".join(
                [
                    f"# Scoped Graph Context: {scope_id}",
                    "",
                    f"- **Seed IDs**: {', '.join(map(str, seed_ids))}",
                    f"- **Question Types**: {', '.join(qtypes)}",
                    f"- **Required**: {bool(scope.get('required'))}",
                    f"- **Evidence Kind**: {stats.get('evidence_kind', 'codegraph')}",
                    f"- **Nodes**: {stats['nodes']}",
                    f"- **Edges**: {stats['edges']}",
                    f"- **Communities**: {stats['communities']}",
                    "",
                    "## Interpretation",
                    f"Scoped graph extraction completed via {stats.get('evidence_kind', 'codegraph')}. "
                    "This artifact is context for reconciliation and does not by itself upgrade or downgrade severity.",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    status = "ok" if required_failed == 0 and not errors else "failed"
    write_json(intrusion / "enrichment.json", enrichments)

    summary_lines = [
        "# Intrusion Analysis Summary",
        "",
        "## Scope Coverage",
        "- Extraction mode: codegraph AST targeted scopes",
        f"- Seeds: {plan.get('coverage', {}).get('seed_count', len(seeds))}",
        f"- Scoped seeds: {plan.get('coverage', {}).get('scoped_seed_count', 'unknown')}",
        f"- Scopes planned: {len(scopes)}",
        f"- Scopes completed: {completed}",
        f"- Required scopes failed: {required_failed}",
        f"- Unresolved seed IDs: {', '.join(plan.get('coverage', {}).get('unresolved_seed_ids', [])) or 'none'}",
        "",
        "## Scoped Graphs",
    ]
    for item in scope_summaries:
        summary_lines.append(
            f"- {item['scope_id']}: {item['nodes']} nodes, {item['edges']} edges, "
            f"{item['communities']} communities; seeds: {', '.join(map(str, item.get('seed_ids', [])))}"
        )
    summary_lines.extend(
        [
            "",
            "## Enrichment",
            f"- Entries written: {len(enrichments)}",
            "- Actions are conservative graph context unless explicit evidence supports later upgrade/downgrade.",
            "",
            "## Mode Limitations",
        ]
    )
    if warnings:
        summary_lines.extend(f"- Warning: {warning}" for warning in warnings)
    if errors:
        summary_lines.extend(f"- Error: {error}" for error in errors)
    if not warnings and not errors:
        summary_lines.append("- No required scoped graph failures.")
    (intrusion / "summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    manifest = {
        "phase": "intrusion",
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": [
            "repo-context/security-surfaces.json",
            "triage/intrusion-seeds.json",
            "intrusion/intrusion-plan.json",
        ],
        "outputs": [
            "intrusion/summary.md",
            "intrusion/enrichment.json",
            "intrusion/intrusion-plan.json",
            "intrusion/findings",
        ],
        "coverage": {
            "mode": "targeted-ooda",
            "scopes_planned": len(scopes),
            "scopes_completed": completed,
            "required_scopes_failed": required_failed,
            "enrichment_entries": len(enrichments),
        },
        "tool_versions": ["codegraph AST analysis via scripts/codegraph-context.sh"],
        "warnings": warnings,
        "errors": errors,
    }
    write_json(intrusion / "phase-manifest.json", manifest)
    print(json.dumps({"status": status, "enrichments": len(enrichments), "completed_scopes": completed}))
    raise SystemExit(0 if status == "ok" else 1)


if __name__ == "__main__":
    main()
