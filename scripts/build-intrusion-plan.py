#!/usr/bin/env python3
"""Build targeted Graphify scopes from recon and triage artifacts."""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
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
TRIAGE_ID_RE = re.compile(r"^T-\d{3}$")


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
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


def evidence_paths(refs: object) -> list[str]:
    paths: list[str] = []
    if not isinstance(refs, list):
        return paths
    for ref in refs:
        rel = clean_rel_path(ref)
        if rel and rel not in paths:
            paths.append(rel)
    return paths


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


def categorize(path: str, text: str) -> list[str]:
    haystack = f"{path} {text}".lower()
    categories: list[str] = []
    tests = [
        ("auth", ("auth", "login", "token", "session", "jwt", "ssh", "credential", "password")),
        ("authorization", ("authorize", "authorization", "rbac", "role", "permission", "policy")),
        ("privileged_sink", ("exec", "command", "subprocess", "runtime", "shell", "file read", "file write", "gossh", "goss")),
        ("external_call", ("http", "api", "webhook", "tls", "rest", "request", "response", "hmac")),
        ("config_secret", ("secret", "key", "env", "config", "vault", "private", "certificate")),
    ]
    for name, needles in tests:
        if any(needle in haystack for needle in needles):
            categories.append(name)
    return categories or ["security_context"]


def build_surfaces(repo: Path, scan: Path, repo_context: dict[str, Any]) -> dict[str, Any]:
    projects = repo_context.get("projects", [])
    ignore_patterns: list[str] = []
    entry_points: list[dict[str, Any]] = []
    trust_boundaries: list[dict[str, Any]] = []
    security_files: dict[str, dict[str, Any]] = {}

    for project in projects if isinstance(projects, list) else []:
        if not isinstance(project, dict):
            continue
        project_id = str(project.get("id", "."))
        for pattern in project.get("ignore_patterns", []) or []:
            if isinstance(pattern, str) and pattern not in ignore_patterns:
                ignore_patterns.append(pattern)
        for entry in project.get("entry_points", []) or []:
            if not isinstance(entry, dict):
                continue
            path = clean_rel_path(entry.get("path"))
            if not path:
                continue
            item = {
                "project_id": project_id,
                "path": path,
                "kind": entry.get("kind", "other"),
                "evidence": entry.get("evidence", ""),
            }
            entry_points.append(item)
            if file_exists(repo, path, ignore_patterns):
                security_files.setdefault(path, {"path": path, "categories": [], "evidence": []})
                security_files[path]["categories"].append("entry_point")
                security_files[path]["evidence"].append(str(entry.get("evidence", "entry point")))
        for boundary in project.get("trust_boundaries", []) or []:
            if isinstance(boundary, str):
                trust_boundaries.append({"project_id": project_id, "boundary": boundary})
        refs = project.get("evidence_refs", []) or []
        for ref in refs:
            path = clean_rel_path(ref)
            if not path or not file_exists(repo, path, ignore_patterns):
                continue
            cats = categorize(path, str(ref))
            slot = security_files.setdefault(path, {"path": path, "categories": [], "evidence": []})
            for cat in cats:
                if cat not in slot["categories"]:
                    slot["categories"].append(cat)
            slot["evidence"].append(str(ref))

    surfaces = {
        "schema_version": "1.0",
        "repository": repo_context.get("repository", repo.name),
        "entry_points": entry_points,
        "trust_boundaries": trust_boundaries,
        "security_relevant_files": sorted(security_files.values(), key=lambda item: item["path"]),
        "ignore_patterns": sorted(ignore_patterns),
        "generated_ignorable": repo_context.get("generated_ignorable", []),
        "sensitive_data_types": repo_context.get("sensitive_data_types", []),
    }
    write_json(scan / "repo-context" / "security-surfaces.json", surfaces)
    return surfaces


def question_type(finding: dict[str, Any]) -> str:
    text = json.dumps(finding).lower()
    sources = finding.get("source", finding.get("sources", []))
    if isinstance(sources, str):
        sources = [sources]
    if any(str(source).startswith("sca") for source in sources) or "cve-" in text:
        return "dependency_reachability"
    if any(word in text for word in ("password", "credential", "secret", "passphrase", "logged")):
        return "credential_flow"
    if any(word in text for word in ("policy", "yaml", "injection", "execution", "runtime", "rego")):
        return "attack_path"
    if any(word in text for word in ("webhook", "hmac", "tls", "signature", "api")):
        return "cross_boundary"
    return "reachability"


def seed_questions(finding: dict[str, Any], qtype: str) -> list[str]:
    fid = finding.get("id", "finding")
    title = finding.get("title", "")
    if qtype == "dependency_reachability":
        return [f"For {fid}, identify whether the vulnerable dependency is imported or reachable from runtime entry points: {title}"]
    if qtype == "credential_flow":
        return [f"For {fid}, trace credential or secret values from input/configuration to logging, process args, network, or storage sinks."]
    if qtype == "attack_path":
        return [f"For {fid}, trace attacker-controlled input from entry points or policy loading to the vulnerable sink."]
    if qtype == "cross_boundary":
        return [f"For {fid}, identify cross-boundary flow involving external endpoints, TLS, webhook, signing, or API calls."]
    return [f"For {fid}, determine whether the vulnerable code is reachable from known entry points and what depends on it."]


def build_seeds(repo: Path, scan: Path, surfaces: dict[str, Any]) -> list[dict[str, Any]]:
    triage_data = load_json(scan / "triage" / "findings.json", [])
    findings = triage_data.get("findings", triage_data) if isinstance(triage_data, dict) else triage_data
    ignore_patterns = list(surfaces.get("ignore_patterns", []))
    seeds: list[dict[str, Any]] = []
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict) or finding.get("status") != "verified":
            continue
        finding_id = str(finding.get("id", f"T-{len(seeds)+1:03d}"))
        if not TRIAGE_ID_RE.match(finding_id):
            continue
        files: list[str] = []
        for raw in finding.get("files", []) or []:
            rel = clean_rel_path(raw)
            if rel and file_exists(repo, rel, ignore_patterns) and rel not in files:
                files.append(rel)
        for rel in evidence_paths(finding.get("evidence_refs", [])):
            if file_exists(repo, rel, ignore_patterns) and rel not in files:
                files.append(rel)
        qtype = question_type(finding)
        seed = {
            "id": finding_id,
            "title": finding.get("title", ""),
            "severity": finding.get("severity", "info"),
            "confidence": finding.get("confidence", "low"),
            "question_type": qtype,
            "files": files,
            "evidence_refs": finding.get("evidence_refs", []),
            "raw_refs": finding.get("raw_refs", []),
            "graph_questions": seed_questions(finding, qtype),
            "requires_cluster": qtype == "cross_boundary",
        }
        seeds.append(seed)
    seeds.sort(key=lambda item: (SEVERITY_RANK.get(str(item.get("severity")), 9), item["id"]))
    write_json(scan / "triage" / "intrusion-seeds.json", {"schema_version": "1.0", "seeds": seeds})
    return seeds


def related_surface_files(seed: dict[str, Any], surfaces: dict[str, Any]) -> list[str]:
    qtype = seed.get("question_type")
    wanted = {
        "dependency_reachability": {"entry_point", "auth", "external_call", "security_context"},
        "credential_flow": {"entry_point", "auth", "config_secret", "privileged_sink"},
        "attack_path": {"entry_point", "authorization", "privileged_sink", "security_context"},
        "cross_boundary": {"entry_point", "external_call", "config_secret", "auth"},
        "reachability": {"entry_point", "security_context", "privileged_sink"},
    }.get(str(qtype), {"entry_point", "security_context"})
    out: list[str] = []
    for item in surfaces.get("security_relevant_files", []) or []:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        categories = set(item.get("categories", []) or [])
        if isinstance(path, str) and categories & wanted and path not in out:
            out.append(path)
    return out


def same_dir_files(repo: Path, rel: str, ignore_patterns: list[str], limit: int) -> list[str]:
    base = repo / rel
    directory = base.parent if base.is_file() else repo / Path(rel).parent
    if not directory.is_dir():
        return []
    results: list[str] = []
    for path in sorted(directory.iterdir()):
        if len(results) >= limit:
            break
        if not path.is_file() or path.suffix.lower() not in SECURITY_EXTS:
            continue
        item = str(path.relative_to(repo))
        if not ignore_match(item, ignore_patterns):
            results.append(item)
    return results


def graph_commands(seed: dict[str, Any]) -> list[dict[str, Any]]:
    commands = [{"type": "query", "question": question} for question in seed.get("graph_questions", [])]
    for rel in seed.get("files", [])[:3]:
        stem = Path(rel).stem
        if stem:
            commands.append({"type": "affected", "target_hint": stem, "depth": 2})
            commands.append({"type": "explain", "target_hint": stem})
    if seed.get("question_type") in {"attack_path", "credential_flow", "reachability"}:
        commands.append({"type": "path", "from": "entry point", "to": "finding evidence sink"})
    return commands


def intelligence_context_for_seed(scan: Path, seed: dict[str, Any]) -> dict[str, Any]:
    cards_doc = load_json(scan / "intelligence" / "investigation-cards.json", {})
    intel_plan = load_json(scan / "intelligence" / "graphify-intel-plan.json", {})
    raw_refs_text = json.dumps(
        {
            "raw_refs": seed.get("raw_refs", []),
            "evidence_refs": seed.get("evidence_refs", []),
            "intelligence_refs": seed.get("intelligence_refs", []),
            "title": seed.get("title", ""),
        }
    )
    wanted_cards = set(str(item) for item in seed.get("intelligence_refs", []) if item)
    files: list[str] = []
    commands: list[dict[str, Any]] = []
    scope_ids: set[str] = set()
    cards = cards_doc.get("cards", []) if isinstance(cards_doc, dict) else []
    for card in cards if isinstance(cards, list) else []:
        if not isinstance(card, dict):
            continue
        cid = str(card.get("id", ""))
        if cid not in wanted_cards and cid and cid not in raw_refs_text:
            continue
        for rel in card.get("files", []) or []:
            clean = clean_rel_path(rel)
            if clean and clean not in files:
                files.append(clean)
        for sid in card.get("graph_scope_ids", []) or []:
            if sid:
                scope_ids.add(str(sid))
        for hypothesis in card.get("hypotheses", []) or []:
            if isinstance(hypothesis, dict) and hypothesis.get("statement"):
                commands.append({"type": "query", "question": f"For {seed.get('id')}, validate intelligence hypothesis {cid}: {hypothesis.get('statement')}"})
    scopes = intel_plan.get("scopes", []) if isinstance(intel_plan, dict) else []
    for scope in scopes if isinstance(scopes, list) else []:
        if not isinstance(scope, dict):
            continue
        sid = str(scope.get("id", ""))
        obs_ids = scope.get("observation_ids", [])
        seed_ids = scope.get("seed_ids", [])
        if not isinstance(obs_ids, list):
            obs_ids = []
        if not isinstance(seed_ids, list):
            seed_ids = []
        observations = json.dumps(obs_ids + seed_ids)
        if sid not in scope_ids and not any(card_id in observations for card_id in wanted_cards):
            continue
        for rel in scope.get("files", []) or []:
            clean = clean_rel_path(rel)
            if clean and clean not in files:
                files.append(clean)
    return {"files": files, "commands": commands, "scope_ids": sorted(scope_ids)}


def env_depth_int(name: str, depth: str, default: int) -> int:
    value = os.environ.get(f"{name}_{depth.upper()}", str(default))
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def build_plan(repo: Path, scan: Path, depth: str, surfaces: dict[str, Any], seeds: list[dict[str, Any]]) -> dict[str, Any]:
    max_scope_files = env_depth_int("GRAPHIFY_MAX_SCOPE_FILES", depth, {"quick": 40, "balanced": 100, "full": 200}[depth])
    max_scopes = env_depth_int("GRAPHIFY_MAX_SCOPES", depth, {"quick": 4, "balanced": 8, "full": 16}[depth])
    ignore_patterns = list(surfaces.get("ignore_patterns", []))
    scopes: list[dict[str, Any]] = []

    priority_seeds = [seed for seed in seeds if str(seed.get("severity")) in {"critical", "high"}]
    lower_seeds = [seed for seed in seeds if seed not in priority_seeds]
    groups: list[list[dict[str, Any]]] = []
    group_index: dict[str, list[dict[str, Any]]] = {}

    for seed in priority_seeds:
        key = str(seed.get("question_type", "reachability"))
        group = group_index.get(key)
        if group is None:
            group = []
            group_index[key] = group
            groups.append(group)
        group.append(seed)

    for seed in lower_seeds:
        key = str(seed.get("question_type", "reachability"))
        group = group_index.get(key)
        if group is not None:
            group.append(seed)
            continue
        if len(groups) >= max_scopes:
            break
        if group is None:
            group = []
            group_index[key] = group
            groups.append(group)
        group.append(seed)

    if len(groups) > max_scopes:
        merged = groups[:max_scopes]
        for group in groups[max_scopes:]:
            target = min(merged, key=len)
            target.extend(group)
        groups = merged

    for index, group in enumerate(groups, start=1):
        if not group:
            continue
        primary = group[0]
        files: list[str] = []
        commands: list[dict[str, Any]] = []
        intelligence_scope_ids: set[str] = set()
        for seed in group:
            for rel in seed.get("files", []):
                if rel not in files:
                    files.append(rel)
                for sibling in same_dir_files(repo, rel, ignore_patterns, max(0, max_scope_files // 2)):
                    if sibling not in files:
                        files.append(sibling)
            for rel in related_surface_files(seed, surfaces):
                if rel not in files:
                    files.append(rel)
            commands.extend(graph_commands(seed))
            intel = intelligence_context_for_seed(scan, seed)
            for rel in intel["files"]:
                if rel not in files:
                    files.append(rel)
            commands.extend(intel["commands"])
            intelligence_scope_ids.update(intel["scope_ids"])
        files = [rel for rel in files if file_exists(repo, rel, ignore_patterns)]
        files = files[:max_scope_files]
        seed_ids = [seed["id"] for seed in group]
        qtypes = sorted({str(seed.get("question_type", "reachability")) for seed in group})
        sid = re.sub(r"[^a-zA-Z0-9_.-]+", "-", f"scope-{index:02d}-{'-'.join(qtypes)}").strip("-").lower()
        required = any(str(seed.get("severity")) in {"critical", "high"} for seed in group)
        scope = {
            "id": sid,
            "seed_ids": seed_ids,
            "required": required,
            "reason": f"{'required' if required else 'optional'} {'/'.join(qtypes)} check for {', '.join(seed_ids)}",
            "question_types": qtypes,
            "requires_cluster": any(bool(seed.get("requires_cluster")) for seed in group),
            "intelligence_scope_ids": sorted(intelligence_scope_ids),
            "files": files,
            "commands": commands,
            "expected_evidence": ["graph path/query output", "file:line evidence refs", "triage_id linkage"],
        }
        scopes.append(scope)
        write_json(scan / "intrusion" / "graphify-runs" / sid / "scope.json", scope)

    covered = {seed_id for scope in scopes for seed_id in scope["seed_ids"]}
    unresolved = [seed["id"] for seed in seeds if seed["id"] not in covered]
    plan = {
        "schema_version": "1.0",
        "mode": "targeted-ooda",
        "depth": depth,
        "full_repo": os.environ.get("GRAPHIFY_FULL_REPO", "0") in {"1", "true", "yes"},
        "max_scope_files": max_scope_files,
        "max_scopes": max_scopes,
        "cluster_when": os.environ.get("GRAPHIFY_CLUSTER_WHEN", "cross_module_only"),
        "scopes": scopes,
        "coverage": {
            "seed_count": len(seeds),
            "scoped_seed_count": len(covered),
            "unresolved_seed_ids": unresolved,
        },
    }
    write_json(scan / "intrusion" / "graphify-plan.json", plan)
    return plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_path")
    parser.add_argument("scan_base")
    parser.add_argument("--depth", choices=["quick", "balanced", "full"], default=None)
    args = parser.parse_args()

    repo = Path(args.repo_path).resolve()
    scan = Path(args.scan_base).resolve()
    depth = args.depth
    if depth is None:
        harness_root = scan.parents[1] if len(scan.parents) > 1 else repo.parent
        ctx = load_json(harness_root / ".harness" / "audit-context.json", {})
        depth = str(ctx.get("depth", "balanced")) if isinstance(ctx, dict) else "balanced"
    if depth not in {"quick", "balanced", "full"}:
        depth = "balanced"

    repo_context = load_json(scan / "repo-context" / "repo-context.json", {})
    if not isinstance(repo_context, dict):
        repo_context = {}
    surfaces = build_surfaces(repo, scan, repo_context)
    seeds = build_seeds(repo, scan, surfaces)
    plan = build_plan(repo, scan, depth, surfaces, seeds)
    print(
        json.dumps(
            {
                "security_surfaces": str(scan / "repo-context" / "security-surfaces.json"),
                "intrusion_seeds": str(scan / "triage" / "intrusion-seeds.json"),
                "graphify_plan": str(scan / "intrusion" / "graphify-plan.json"),
                "scopes": len(plan["scopes"]),
                "seeds": len(seeds),
            }
        )
    )


if __name__ == "__main__":
    main()
