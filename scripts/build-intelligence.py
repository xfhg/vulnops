#!/usr/bin/env python3
"""Build evidence-fed OODA intelligence artifacts for VulnOps scans."""
from __future__ import annotations

import argparse
import fnmatch
from datetime import datetime, timezone
import json
import re
import subprocess
from pathlib import Path
from typing import Any


SECURITY_EXTS = {
    ".go",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
    ".rb",
    ".java",
    ".kt",
    ".rs",
    ".php",
    ".cs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".xml",
    ".proto",
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
LINE_REF_RE = re.compile(r"^([^:\s()]+)(?::\d+(?:-\d+)?)?")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def clean_rel_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or value.startswith(("http://", "https://")):
        return None
    match = LINE_REF_RE.match(value)
    if not match:
        return None
    rel = match.group(1).strip().lstrip("./")
    if not rel or rel.startswith(("/", "..")):
        return None
    return rel


def evidence_paths(*values: object) -> list[str]:
    out: list[str] = []
    for value in values:
        if isinstance(value, list):
            items = value
        else:
            items = [value]
        for item in items:
            rel = clean_rel_path(item)
            if rel and rel not in out:
                out.append(rel)
    return out


def ignore_match(path: str, patterns: list[str]) -> bool:
    normalized = path.lstrip("./")
    for pattern in patterns:
        pat = pattern.lstrip("./")
        if fnmatch.fnmatch(normalized, pat) or fnmatch.fnmatch(normalized, pat.rstrip("*")):
            return True
    return False


def file_exists(repo: Path, rel: str, ignore_patterns: list[str]) -> bool:
    path = repo / rel
    return path.is_file() and not ignore_match(rel, ignore_patterns)


def same_dir_files(repo: Path, rel: str, ignore_patterns: list[str], limit: int) -> list[str]:
    path = repo / rel
    directory = path.parent if path.is_file() else (repo / Path(rel).parent)
    if not directory.is_dir():
        return []
    out: list[str] = []
    for item in sorted(directory.iterdir()):
        if len(out) >= limit:
            break
        if not item.is_file() or item.suffix.lower() not in SECURITY_EXTS:
            continue
        candidate = str(item.relative_to(repo))
        if not ignore_match(candidate, ignore_patterns):
            out.append(candidate)
    return out


def compact_text(value: object, limit: int = 240) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text[:limit].rstrip()


def severity(value: object) -> str:
    sev = str(value or "info").lower()
    return sev if sev in SEVERITY_RANK else "info"


def source_phase_ref(source_phase: str, raw_ref: str) -> str:
    return raw_ref if raw_ref.startswith(source_phase) else f"{source_phase}/{raw_ref}"


def observation(
    *,
    oid: str,
    source_phase: str,
    otype: str,
    title: str,
    severity_value: object = "info",
    confidence: object = "medium",
    files: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    raw_refs: list[str] | None = None,
    summary: str = "",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": oid,
        "source_phase": source_phase,
        "type": otype,
        "title": compact_text(title, 160),
        "severity": severity(severity_value),
        "confidence": str(confidence or "medium").lower(),
        "files": files or [],
        "evidence_refs": evidence_refs or [],
        "raw_refs": raw_refs or [],
        "summary": compact_text(summary or title),
        "tags": tags or [],
    }


def extract_surfaces(repo: Path, surfaces: dict[str, Any]) -> tuple[list[str], dict[str, list[str]]]:
    ignore_patterns = [str(item) for item in surfaces.get("ignore_patterns", []) if isinstance(item, str)]
    by_category: dict[str, list[str]] = {}
    for item in surfaces.get("security_relevant_files", []) or []:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not isinstance(path, str) or not file_exists(repo, path, ignore_patterns):
            continue
        for cat in item.get("categories", []) or ["security_context"]:
            by_category.setdefault(str(cat), []).append(path)
    for entry in surfaces.get("entry_points", []) or []:
        if isinstance(entry, dict):
            path = entry.get("path")
            if isinstance(path, str) and file_exists(repo, path, ignore_patterns):
                by_category.setdefault("entry_point", []).append(path)
    for key in list(by_category):
        by_category[key] = sorted(set(by_category[key]))
    return ignore_patterns, by_category


def collect_observations(repo: Path, scan: Path, surfaces: dict[str, Any]) -> list[dict[str, Any]]:
    ignore_patterns, _ = extract_surfaces(repo, surfaces)
    observations: list[dict[str, Any]] = []

    surface_index = 1
    for item in surfaces.get("security_relevant_files", []) or []:
        if not isinstance(item, dict):
            continue
        path = clean_rel_path(item.get("path"))
        if not path or not file_exists(repo, path, ignore_patterns):
            continue
        categories = [str(cat) for cat in item.get("categories", []) if isinstance(cat, str)]
        if not set(categories) & {"entry_point", "auth", "authorization", "privileged_sink", "external_call", "config_secret"}:
            continue
        observations.append(
            observation(
                oid=f"OBS-RECON-{surface_index:03d}",
                source_phase="recon",
                otype="security_surface",
                title=f"Security-relevant surface: {path}",
                severity_value="medium" if "privileged_sink" in categories or "authorization" in categories else "info",
                confidence="medium",
                files=[path],
                evidence_refs=[path] + [str(ref) for ref in item.get("evidence", []) if isinstance(ref, str)],
                raw_refs=[source_phase_ref("recon", f"security-surfaces.json:{path}")],
                summary=", ".join(categories) or "security surface",
                tags=categories or ["security_context"],
            )
        )
        surface_index += 1

    raw_advisories = load_json(scan / "sca" / "raw-advisories.json", [])
    for index, adv in enumerate(raw_advisories if isinstance(raw_advisories, list) else [], start=1):
        if not isinstance(adv, dict):
            continue
        lockfile = clean_rel_path(adv.get("source_lockfile"))
        files = [lockfile] if lockfile and file_exists(repo, lockfile, ignore_patterns) else []
        advisory_id = str(adv.get("advisory_id") or f"SCA-{index:03d}")
        package = str(adv.get("package") or "unknown package")
        observations.append(
            observation(
                oid=f"OBS-SCA-{index:03d}",
                source_phase="sca",
                otype="dependency_exposure",
                title=f"{advisory_id} affects {package}",
                severity_value=adv.get("severity"),
                confidence="medium",
                files=files,
                evidence_refs=files,
                raw_refs=[source_phase_ref("sca", f"raw-advisories.json:{advisory_id}")],
                summary=adv.get("summary", ""),
                tags=["dependency_reachability", str(adv.get("ecosystem") or "").lower()],
            )
        )

    redacted = load_json(scan / "secrets" / "redacted-candidates.json", [])
    secret_items = redacted.get("candidates", redacted.get("findings", redacted)) if isinstance(redacted, dict) else redacted
    for index, item in enumerate(secret_items if isinstance(secret_items, list) else [], start=1):
        if not isinstance(item, dict):
            continue
        path = clean_rel_path(item.get("file") or item.get("path") or item.get("filename"))
        files = [path] if path and file_exists(repo, path, ignore_patterns) else []
        classification = str(item.get("classification") or item.get("confidence") or item.get("status") or "candidate").lower()
        observations.append(
            observation(
                oid=f"OBS-SEC-{index:03d}",
                source_phase="secrets",
                otype="credential_or_secret_surface",
                title=f"Secret candidate in {path or 'unknown file'}",
                severity_value=item.get("severity", "high" if classification in {"confirmed", "likely"} else "medium"),
                confidence="high" if classification in {"confirmed", "likely"} else "medium",
                files=files,
                evidence_refs=files,
                raw_refs=[source_phase_ref("secrets", f"redacted-candidates.json:{index}")],
                summary=item.get("type") or item.get("rule") or classification,
                tags=["credential_flow", "config_secret"],
            )
        )

    verified = load_json(scan / "sast" / "verified-findings.json", [])
    for index, finding in enumerate(verified if isinstance(verified, list) else [], start=1):
        if not isinstance(finding, dict):
            continue
        refs = finding.get("evidence_refs", []) or []
        files = [rel for rel in evidence_paths(finding.get("source_ref"), finding.get("sink_ref"), finding.get("entrypoint_ref"), refs) if file_exists(repo, rel, ignore_patterns)]
        observations.append(
            observation(
                oid=f"OBS-SAST-{index:03d}",
                source_phase="sast",
                otype="verified_code_finding",
                title=finding.get("title", f"SAST verified finding {index}"),
                severity_value=finding.get("severity"),
                confidence=finding.get("confidence", "high"),
                files=files,
                evidence_refs=list(dict.fromkeys([str(ref) for ref in refs] + files)),
                raw_refs=[source_phase_ref("sast", f"verified-findings.json:{finding.get('id', index)}")],
                summary=finding.get("description") or finding.get("impact") or finding.get("title", ""),
                tags=[str(item) for item in finding.get("lenses", []) if isinstance(item, str)] or ["attack_path"],
            )
        )

    return sorted(observations, key=lambda item: (SEVERITY_RANK.get(item["severity"], 9), item["id"]))


def build_evidence_corpus(scan: Path, observations: list[dict[str, Any]], surfaces: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": now(),
        "sources": {
            "recon": {
                "security_surfaces": "repo-context/security-surfaces.json",
                "entry_points": len(surfaces.get("entry_points", []) or []),
                "security_relevant_files": len(surfaces.get("security_relevant_files", []) or []),
            },
            "sca": {"raw_advisories": "sca/raw-advisories.json"},
            "secrets": {"redacted_candidates": "secrets/redacted-candidates.json"},
            "sast": {
                "verified_findings": "sast/verified-findings.json",
                "coverage_ledger": "sast/coverage-ledger.json",
            },
        },
        "observations": observations,
        "counts": {
            "observations": len(observations),
            "critical_high": sum(1 for item in observations if item["severity"] in {"critical", "high"}),
        },
    }


def build_attack_surface_map(repo: Path, scan: Path, surfaces: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    repo_context = load_json(scan / "repo-context" / "repo-context.json", {})
    _, by_category = extract_surfaces(repo, surfaces)
    components = []
    projects = repo_context.get("projects", []) if isinstance(repo_context, dict) else []
    for project in projects if isinstance(projects, list) else []:
        if not isinstance(project, dict):
            continue
        base = str(project.get("base_path") or project.get("id") or ".")
        related = [
            obs["id"]
            for obs in observations
            if any(path == base or path.startswith(base.rstrip("/") + "/") for path in obs.get("files", []))
        ]
        components.append(
            {
                "id": str(project.get("id") or base),
                "base_path": base,
                "type": project.get("type", "unknown"),
                "languages": project.get("languages", []),
                "frameworks": project.get("frameworks", []),
                "related_observation_ids": related,
            }
        )
    return {
        "schema_version": "1.0",
        "generated_at": now(),
        "components": components,
        "entry_points": surfaces.get("entry_points", []),
        "trust_boundaries": surfaces.get("trust_boundaries", []),
        "files_by_category": by_category,
        "dependency_exposure_ids": [obs["id"] for obs in observations if obs["type"] == "dependency_exposure"],
        "secret_surface_ids": [obs["id"] for obs in observations if obs["type"] == "credential_or_secret_surface"],
        "sast_finding_ids": [obs["id"] for obs in observations if obs["type"] == "verified_code_finding"],
    }


def coverage_text(scan: Path) -> str:
    chunks = load_json(scan / "sast" / "task-manifest.json", {})
    ledger = load_json(scan / "sast" / "coverage-ledger.json", {})
    return json.dumps({"chunks": chunks, "ledger": ledger}, sort_keys=True).lower()


def build_coverage_gaps(repo: Path, scan: Path, surfaces: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    ignore_patterns, by_category = extract_surfaces(repo, surfaces)
    covered_blob = coverage_text(scan)
    gaps: list[dict[str, Any]] = []
    gap_index = 1
    for path in sorted(set(by_category.get("entry_point", []) + by_category.get("authorization", []) + by_category.get("privileged_sink", []))):
        if not file_exists(repo, path, ignore_patterns):
            continue
        if path.lower() in covered_blob:
            continue
        gaps.append(
            {
                "id": f"GAP-{gap_index:03d}",
                "kind": "surface_not_covered",
                "status": "open",
                "path": path,
                "severity": "medium",
                "reason": "Security-relevant surface from recon is not clearly covered by SAST task manifest or coverage ledger.",
                "evidence_refs": [path],
            }
        )
        gap_index += 1
    for obs in observations:
        if obs["type"] == "dependency_exposure" and not obs.get("files"):
            gaps.append(
                {
                    "id": f"GAP-{gap_index:03d}",
                    "kind": "dependency_usage_unknown",
                    "status": "open",
                    "severity": obs["severity"],
                    "reason": f"Dependency advisory {obs['title']} lacks resolved usage files before codegraph intelligence.",
                    "observation_id": obs["id"],
                    "evidence_refs": obs.get("raw_refs", []),
                }
            )
            gap_index += 1
    return {"schema_version": "1.0", "generated_at": now(), "gaps": gaps}


def build_rule_gaps(observations: list[dict[str, Any]]) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    for index, obs in enumerate(observations, start=1):
        if obs["severity"] not in {"critical", "high"}:
            continue
        if obs["type"] == "dependency_exposure":
            rule_type = "dependency_reachability"
        elif obs["type"] == "credential_or_secret_surface":
            rule_type = "secret_flow"
        else:
            rule_type = "verified_finding_regression"
        gaps.append(
            {
                "id": f"RULE-GAP-{index:03d}",
                "status": "candidate",
                "rule_type": rule_type,
                "observation_id": obs["id"],
                "reason": "High-impact evidence should become a reusable detection or regression guardrail if current tools did not catch the full chain.",
                "evidence_refs": obs.get("evidence_refs", []) or obs.get("raw_refs", []) or [f"intelligence/evidence-corpus.json:{obs.get("id", "unknown")}"],
            }
        )
    return {"schema_version": "1.0", "generated_at": now(), "rule_gaps": gaps}


def qtype_for_observation(obs: dict[str, Any]) -> str:
    text = json.dumps(obs).lower()
    if obs["type"] == "dependency_exposure" or "cve-" in text or "ghsa-" in text:
        return "dependency_reachability"
    if obs["type"] == "credential_or_secret_surface" or any(word in text for word in ("secret", "credential", "password", "token")):
        return "credential_flow"
    if any(word in text for word in ("auth", "permission", "role", "policy")):
        return "cross_boundary"
    return "attack_path"


def graph_commands(obs: dict[str, Any], qtype: str) -> list[dict[str, Any]]:
    title = obs.get("title", obs["id"])
    if qtype == "dependency_reachability":
        question = f"For {obs['id']}, determine whether the vulnerable dependency evidence is imported or reachable from runtime entry points: {title}"
    elif qtype == "credential_flow":
        question = f"For {obs['id']}, trace credential or secret values from config/input to logging, process args, network, or storage sinks."
    elif qtype == "cross_boundary":
        question = f"For {obs['id']}, identify cross-boundary auth/authz or external-call paths that affect exploitability."
    else:
        question = f"For {obs['id']}, trace attacker-controllable entry points to the cited sink or vulnerable code path."
    commands = [{"type": "query", "question": question}]
    for rel in obs.get("files", [])[:2]:
        stem = Path(rel).stem
        if stem:
            commands.append({"type": "affected", "target_hint": stem, "depth": 2})
            commands.append({"type": "explain", "target_hint": stem})
    if qtype in {"attack_path", "credential_flow", "cross_boundary"}:
        commands.append({"type": "path", "from": "entry point", "to": "security-sensitive sink"})
    return commands


def _emit_codegraph_context(repo: Path, run_dir: Path, scope: dict[str, Any], depth: int = 2) -> None:
    """Best-effort codegraph context emit.
+
    Runs the codegraph-context.sh helper for the first few files in a
    scope and writes the union to <run_dir>/codegraph-out/context.json.
    This is the sole graph backend. Failures are non-fatal: we always
    write a stub so validators see a context.json for every scope.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    out_dir = run_dir / "codegraph-out"
    out_dir.mkdir(parents=True, exist_ok=True)
    context_path = out_dir / "context.json"
    helper = Path(__file__).resolve().parent / "codegraph-context.sh"
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    notes: list[str] = []
    source = "codegraph"
    for rel in list(scope.get("files", []))[:3]:
        if not helper.is_file():
            notes.append("helper missing")
            break
        try:
            proc = subprocess.run(
                ["bash", str(helper), "blast-radius", rel, str(depth)],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            notes.append(f"exec: {type(exc).__name__}")
            continue
        if proc.returncode != 0:
            notes.append(f"rc={proc.returncode}")
            continue
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            notes.append("non-json")
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("source") and payload["source"] != "codegraph":
            source = payload["source"]
        for node in payload.get("nodes", []) or []:
            if isinstance(node, dict):
                node.setdefault("origin", rel)
                nodes.append(node)
        for edge in payload.get("edges", []) or []:
            if isinstance(edge, dict):
                edge.setdefault("origin", rel)
                edges.append(edge)
    if not nodes and not edges:
        note = "; ".join(notes) or "no results"
    else:
        note = ""
    payload = {
        "schema_version": "1.0",
        "scope_id": scope.get("id", ""),
        "source": source,
        "nodes": nodes,
        "edges": edges,
        "note": note,
    }
    context_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_intel_plan(repo: Path, scan: Path, depth: str, surfaces: dict[str, Any], observations: list[dict[str, Any]], coverage_gaps: dict[str, Any]) -> dict[str, Any]:
    max_scope_files = {"quick": 40, "balanced": 100, "full": 200}[depth]
    max_scopes = {"quick": 4, "balanced": 8, "full": 16}[depth]
    ignore_patterns, by_category = extract_surfaces(repo, surfaces)
    groups: dict[str, list[dict[str, Any]]] = {}
    for obs in observations:
        groups.setdefault(qtype_for_observation(obs), []).append(obs)
    scopes: list[dict[str, Any]] = []
    group_items = sorted(groups.items(), key=lambda item: min(SEVERITY_RANK.get(obs["severity"], 9) for obs in item[1]))
    for index, (qtype, group) in enumerate(group_items[:max_scopes], start=1):
        files: list[str] = []
        commands: list[dict[str, Any]] = []
        for obs in sorted(group, key=lambda item: (SEVERITY_RANK.get(item["severity"], 9), item["id"])):
            for rel in obs.get("files", []):
                if rel not in files:
                    files.append(rel)
                for sibling in same_dir_files(repo, rel, ignore_patterns, max(1, max_scope_files // 3)):
                    if sibling not in files:
                        files.append(sibling)
            commands.extend(graph_commands(obs, qtype))
        wanted_surface = {
            "dependency_reachability": ["entry_point", "external_call", "security_context"],
            "credential_flow": ["entry_point", "config_secret", "privileged_sink", "auth"],
            "cross_boundary": ["entry_point", "authorization", "external_call", "auth"],
            "attack_path": ["entry_point", "authorization", "privileged_sink", "security_context"],
        }.get(qtype, ["entry_point", "security_context"])
        for category in wanted_surface:
            for rel in by_category.get(category, []):
                if rel not in files:
                    files.append(rel)
        for gap in coverage_gaps.get("gaps", [])[:5]:
            rel = gap.get("path") if isinstance(gap, dict) else None
            if isinstance(rel, str) and rel not in files and file_exists(repo, rel, ignore_patterns):
                files.append(rel)
        files = [rel for rel in files if file_exists(repo, rel, ignore_patterns)][:max_scope_files]
        if not files:
            continue
        observation_ids = [obs["id"] for obs in group]
        required = any(obs["severity"] in {"critical", "high"} for obs in group)
        sid = f"intel-{index:02d}-{qtype}"
        scope = {
            "id": sid,
            "seed_ids": observation_ids,
            "observation_ids": observation_ids,
            "required": required,
            "reason": f"{'required' if required else 'optional'} intelligence {qtype} scope for {', '.join(observation_ids[:6])}",
            "question_types": [qtype],
            "requires_cluster": qtype == "cross_boundary",
            "files": files,
            "commands": commands,
            "expected_evidence": ["graph query output", "source file evidence", "observation linkage"],
        }
        scopes.append(scope)
        _emit_codegraph_context(repo, scan / "intelligence" / "codegraph-runs" / sid, scope, depth=2)
    return {
        "schema_version": "1.0",
        "mode": "intelligence-ooda",
        "depth": depth,
        "full_repo": False,
        "max_scope_files": max_scope_files,
        "max_scopes": max_scopes,
        "cluster_when": "cross_module_only",
        "scopes": scopes,
        "coverage": {
            "observation_count": len(observations),
            "scoped_observation_count": len({oid for scope in scopes for oid in scope["observation_ids"]}),
            "coverage_gap_count": len(coverage_gaps.get("gaps", [])),
        },
    }


def scope_completed(scan: Path, sid: str) -> bool:
    # codegraph is the sole graph backend; empty results do not count.
    cg_context = (scan / "intelligence" / "codegraph-runs" / sid / "codegraph-out" / "context.json")
    if cg_context.is_file():
        try:
            ctx = load_json(cg_context, {})
        except Exception:
            ctx = {}
        if isinstance(ctx, dict):
            n = len(ctx.get("nodes", []) or [])
            e = len(ctx.get("edges", []) or [])
            if n + e > 0:
                return True
    return False


def build_investigation_cards(scan: Path, observations: list[dict[str, Any]], plan: dict[str, Any], coverage_gaps: dict[str, Any]) -> dict[str, Any]:
    scope_by_obs: dict[str, list[str]] = {}
    completed_by_obs: dict[str, list[str]] = {}
    for scope in plan.get("scopes", []) if isinstance(plan.get("scopes"), list) else []:
        if not isinstance(scope, dict):
            continue
        sid = str(scope.get("id"))
        completed = scope_completed(scan, sid)
        for oid in scope.get("observation_ids", []) or scope.get("seed_ids", []):
            scope_by_obs.setdefault(str(oid), []).append(sid)
            if completed:
                completed_by_obs.setdefault(str(oid), []).append(sid)
    cards: list[dict[str, Any]] = []
    for index, obs in enumerate(observations, start=1):
        completed_scopes = completed_by_obs.get(obs["id"], [])
        source = "graph_inference" if completed_scopes else "tool_evidence"
        recommendation = "triage"
        if obs["severity"] in {"critical", "high"}:
            recommendation = "triage_and_intrusion"
        cards.append(
            {
                "id": f"I-{index:03d}",
                "source": source,
                "status": "open",
                "title": obs["title"],
                "severity": obs["severity"],
                "confidence": obs["confidence"],
                "priority": SEVERITY_RANK.get(obs["severity"], 9) + 1,
                "observation_ids": [obs["id"]],
                "files": obs.get("files", []),
                "evidence_refs": list(dict.fromkeys(obs.get("evidence_refs", []) + [f"intelligence/codegraph-runs/{sid}/codegraph-out/context.json" for sid in completed_scopes])),
                "raw_refs": obs.get("raw_refs", []) + [f"intelligence/evidence-corpus.json:{obs['id']}"],
                "hypotheses": [
                    {
                        "source": source,
                        "statement": obs["summary"],
                        "must_prove_before_final": source != "tool_evidence" or not obs.get("evidence_refs"),
                    }
                ],
                "graph_scope_ids": scope_by_obs.get(obs["id"], []),
                "codegraph_answered": bool(completed_scopes),
                "downstream_recommendation": recommendation,
                "evidence_gate": {
                    "has_file_evidence": bool(obs.get("files") or obs.get("evidence_refs")),
                    "has_graph_evidence": bool(completed_scopes),
                    "has_raw_provenance": bool(obs.get("raw_refs")),
                },
            }
        )
    offset = len(cards)
    for gap_index, gap in enumerate(coverage_gaps.get("gaps", []) if isinstance(coverage_gaps.get("gaps"), list) else [], start=1):
        cards.append(
            {
                "id": f"I-{offset + gap_index:03d}",
                "source": "coverage_gap",
                "status": "open",
                "title": compact_text(gap.get("reason", "Coverage gap")),
                "severity": gap.get("severity", "medium"),
                "confidence": "medium",
                "priority": SEVERITY_RANK.get(str(gap.get("severity", "medium")), 2) + 2,
                "observation_ids": [gap.get("observation_id")] if gap.get("observation_id") else [],
                "files": [gap.get("path")] if gap.get("path") else [],
                "evidence_refs": gap.get("evidence_refs", []),
                "raw_refs": [f"intelligence/coverage-gaps.json:{gap.get('id')}"],
                "hypotheses": [{"source": "coverage_gap", "statement": gap.get("reason"), "must_prove_before_final": True}],
                "graph_scope_ids": [],
                "codegraph_answered": False,
                "downstream_recommendation": "needs_review",
                "evidence_gate": {"has_file_evidence": bool(gap.get("evidence_refs")), "has_graph_evidence": False, "has_raw_provenance": True},
            }
        )
    return {"schema_version": "1.0", "generated_at": now(), "cards": cards}


def write_summary(scan: Path, corpus: dict[str, Any], plan: dict[str, Any], cards: dict[str, Any], coverage_gaps: dict[str, Any], required_missing: list[str]) -> None:
    lines = [
        "# Intelligence Fusion Summary",
        "",
        "## Evidence Corpus",
        f"- Observations: {corpus['counts']['observations']}",
        f"- Critical/high observations: {corpus['counts']['critical_high']}",
        "",
        "## Graph Intelligence",
        f"- Scopes planned: {len(plan.get('scopes', []))}",
        f"- Required scopes missing: {len(required_missing)}",
        "",
        "## Investigation Cards",
        f"- Cards: {len(cards.get('cards', []))}",
        f"- Coverage gaps: {len(coverage_gaps.get('gaps', []))}",
        "",
        "## Open Questions",
    ]
    for gap in coverage_gaps.get("gaps", [])[:10]:
        lines.append(f"- {gap.get('id')}: {gap.get('reason')}")
    if not coverage_gaps.get("gaps"):
        lines.append("- None recorded.")
    (scan / "intelligence" / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def resolve_depth(scan: Path, repo: Path, explicit: str | None) -> str:
    if explicit in {"quick", "balanced", "full"}:
        return explicit
    harness_root = scan.parents[1] if len(scan.parents) > 1 else repo.parent
    ctx = load_json(harness_root / ".harness" / "audit-context.json", {})
    depth = str(ctx.get("depth", "balanced")) if isinstance(ctx, dict) else "balanced"
    return depth if depth in {"quick", "balanced", "full"} else "balanced"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_path")
    parser.add_argument("scan_base")
    parser.add_argument("--depth", choices=["quick", "balanced", "full"], default=None)
    parser.add_argument("--finalize", action="store_true", help="write summary and terminal phase manifest after codegraph scopes run")
    args = parser.parse_args()

    repo = Path(args.repo_path).resolve()
    scan = Path(args.scan_base).resolve()
    depth = resolve_depth(scan, repo, args.depth)
    intelligence = scan / "intelligence"
    intelligence.mkdir(parents=True, exist_ok=True)

    surfaces = load_json(scan / "repo-context" / "security-surfaces.json", {})
    if not isinstance(surfaces, dict):
        surfaces = {}
    observations = collect_observations(repo, scan, surfaces)
    corpus = build_evidence_corpus(scan, observations, surfaces)
    attack_surface = build_attack_surface_map(repo, scan, surfaces, observations)
    coverage_gaps = build_coverage_gaps(repo, scan, surfaces, observations)
    rule_gaps = build_rule_gaps(observations)
    plan = build_intel_plan(repo, scan, depth, surfaces, observations, coverage_gaps)
    cards = build_investigation_cards(scan, observations, plan, coverage_gaps)

    write_json(intelligence / "evidence-corpus.json", corpus)
    write_json(intelligence / "attack-surface-map.json", attack_surface)
    write_json(intelligence / "coverage-gaps.json", coverage_gaps)
    write_json(intelligence / "rule-gaps.json", rule_gaps)
    write_json(intelligence / "intel-plan.json", plan)
    write_json(intelligence / "investigation-cards.json", cards)

    required_missing = [
        str(scope.get("id"))
        for scope in plan.get("scopes", [])
        if isinstance(scope, dict) and scope.get("required") and not scope_completed(scan, str(scope.get("id")))
    ]
    if args.finalize:
        write_summary(scan, corpus, plan, cards, coverage_gaps, required_missing)
        manifest = {
            "phase": "intelligence",
            "status": "ok" if not required_missing else "failed",
            "started_at": now(),
            "completed_at": now(),
            "inputs": [
                "repo-context/security-surfaces.json",
                "sca/raw-advisories.json",
                "secrets/redacted-candidates.json",
                "sast/verified-findings.json",
                "sast/coverage-ledger.json",
            ],
            "outputs": [
                "intelligence/evidence-corpus.json",
                "intelligence/attack-surface-map.json",
                "intelligence/intel-plan.json",
                "intelligence/investigation-cards.json",
                "intelligence/coverage-gaps.json",
                "intelligence/rule-gaps.json",
                "intelligence/summary.md",
            ],
            "coverage": {
                "observations": corpus["counts"]["observations"],
                "cards": len(cards.get("cards", [])),
                "codegraph_scopes": len(plan.get("scopes", [])),
                "required_missing": required_missing,
            },
            "tool_versions": {"codegraph": "via scripts/run-codegraph.sh"},
            "warnings": [f"required intelligence scope missing: {sid}" for sid in required_missing],
            "errors": [f"required intelligence scope missing: {sid}" for sid in required_missing],
        }
        write_json(intelligence / "phase-manifest.json", manifest)
    print(json.dumps({"observations": len(observations), "cards": len(cards.get("cards", [])), "scopes": len(plan.get("scopes", [])), "required_missing": required_missing}))


if __name__ == "__main__":
    main()
