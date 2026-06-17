#!/usr/bin/env python3
"""Finalize intrusion artifacts from validated scoped Graphify runs.

This script is intentionally conservative: it records graph-backed context for
final reconciliation, but it does not invent upgrades or downgrades. Agents may
add richer analysis later, but the phase can complete without another long LLM
turn after Graphify has already done the expensive work.
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


def graph_stats(graph_path: Path) -> dict[str, int]:
    graph = load_json(graph_path, {})
    if not isinstance(graph, dict):
        return {"nodes": 0, "edges": 0, "communities": 0}
    nodes = graph.get("nodes", [])
    edges = graph.get("links", graph.get("edges", []))
    communities = {
        node.get("community")
        for node in nodes
        if isinstance(node, dict) and node.get("community") is not None
    }
    return {
        "nodes": len(nodes) if isinstance(nodes, list) else 0,
        "edges": len(edges) if isinstance(edges, list) else 0,
        "communities": len(communities),
    }


def validate_scope(scan: Path, scope: dict[str, Any]) -> tuple[bool, dict[str, Any], list[str]]:
    sid = str(scope.get("id", ""))
    run = scan / "intrusion" / "graphify-runs" / sid
    graph_path = run / "graphify-out" / "graph.json"
    quality_path = run / "graphify-quality.json"
    marker_path = run / "graphify-out" / ".graphify_semantic_marker"
    analysis_path = run / "graphify-out" / ".graphify_analysis.json"
    errors: list[str] = []
    if not graph_path.is_file():
        errors.append(f"{sid}: missing graph.json")
    if not quality_path.is_file():
        errors.append(f"{sid}: missing graphify-quality.json")
    if not marker_path.is_file():
        errors.append(f"{sid}: missing semantic marker")
    quality = load_json(quality_path, {})
    if not isinstance(quality, dict):
        errors.append(f"{sid}: invalid quality JSON")
        quality = {}
    stats = graph_stats(graph_path)
    if stats["nodes"] <= 0:
        errors.append(f"{sid}: graph has no nodes")
    if stats["edges"] <= 0:
        errors.append(f"{sid}: graph has no edges")
    if scope.get("requires_cluster") and not analysis_path.is_file():
        errors.append(f"{sid}: cluster-required scope missing analysis")
    merged = {"scope_id": sid, **stats, "quality": quality}
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
    plan = load_json(intrusion / "graphify-plan.json", {})
    if not isinstance(plan, dict) or plan.get("mode") != "targeted-ooda":
        raise SystemExit("missing targeted-ooda intrusion/graphify-plan.json")
    scopes = plan.get("scopes", [])
    if not isinstance(scopes, list) or not scopes:
        raise SystemExit("graphify plan has no scopes")

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
            errors.append("graphify plan contains non-object scope")
            continue
        ok, stats, scope_errors = validate_scope(scan, scope)
        scope_summaries.append({**stats, "seed_ids": scope.get("seed_ids", []), "required": bool(scope.get("required"))})
        if ok:
            completed += 1
        else:
            if scope.get("required"):
                required_failed += 1
                errors.extend(scope_errors)
            else:
                warnings.extend(scope_errors)
                continue

        scope_id = str(scope.get("id"))
        qtypes = [str(item) for item in scope.get("question_types", []) if item]
        primary_qtype = qtypes[0] if qtypes else "reachability"
        for seed_id in scope.get("seed_ids", []) or []:
            seed = seeds.get(str(seed_id), {})
            evidence_refs = list(seed.get("evidence_refs", [])) if isinstance(seed.get("evidence_refs"), list) else []
            evidence_refs.extend(
                [
                    f"intrusion/graphify-runs/{scope_id}/graphify-out/graph.json",
                    f"intrusion/graphify-runs/{scope_id}/graphify-quality.json",
                ]
            )
            enrichment = {
                "triage_id": str(seed_id),
                "type": primary_qtype,
                "action": action_for_question_type(primary_qtype),
                "severity": seed.get("severity", "info"),
                "confidence": "medium",
                "evidence_refs": evidence_refs,
                "summary": (
                    f"Scoped LLM-backed Graphify analysis completed for {seed_id} in {scope_id}: "
                    f"{stats['nodes']} nodes, {stats['edges']} edges, {stats['communities']} communities. "
                    "Use as graph context only unless a human/agent adds explicit upgrade or downgrade rationale."
                ),
            }
            enrichments.append(enrichment)

        finding_path = findings_dir / f"{scope_id}.md"
        finding_path.write_text(
            "\n".join(
                [
                    f"# Scoped Graph Context: {scope_id}",
                    "",
                    f"- **Seed IDs**: {', '.join(map(str, scope.get('seed_ids', [])))}",
                    f"- **Question Types**: {', '.join(qtypes)}",
                    f"- **Required**: {bool(scope.get('required'))}",
                    f"- **Nodes**: {stats['nodes']}",
                    f"- **Edges**: {stats['edges']}",
                    f"- **Communities**: {stats['communities']}",
                    "",
                    "## Interpretation",
                    "LLM-backed scoped graph extraction completed. This artifact is context for reconciliation and does not by itself upgrade or downgrade severity.",
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
        "- Extraction mode: LLM-backed targeted scopes",
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
            "intrusion/graphify-plan.json",
        ],
        "outputs": [
            "intrusion/summary.md",
            "intrusion/enrichment.json",
            "intrusion/graphify-plan.json",
            "intrusion/findings",
        ],
        "coverage": {
            "mode": "targeted-ooda",
            "scopes_planned": len(scopes),
            "scopes_completed": completed,
            "required_scopes_failed": required_failed,
            "enrichment_entries": len(enrichments),
        },
        "tool_versions": ["graphify scoped extraction via scripts/run-graphify.sh"],
        "warnings": warnings,
        "errors": errors,
    }
    write_json(intrusion / "phase-manifest.json", manifest)
    print(json.dumps({"status": status, "enrichments": len(enrichments), "completed_scopes": completed}))
    raise SystemExit(0 if status == "ok" else 1)


if __name__ == "__main__":
    main()
