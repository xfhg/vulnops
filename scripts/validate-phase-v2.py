#!/usr/bin/env python3
"""Validate one VulnOps v2 phase contract."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def load(path: Path, errors: list[str]) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        errors.append(f"missing {path}")
    except json.JSONDecodeError as exc:
        errors.append(f"invalid JSON {path}: {exc}")
    return None


def require_file(path: Path, errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"missing {path}")


def require_manifest(scan: Path, directory: str, phase: str, errors: list[str], allowed: set[str] | None = None) -> None:
    allowed = allowed or {"ok", "degraded"}
    manifest = load(scan / directory / "phase-manifest.json", errors)
    if not isinstance(manifest, dict):
        return
    if manifest.get("phase") != phase:
        errors.append(f"{directory}/phase-manifest.json phase must be {phase}")
    if manifest.get("status") not in allowed:
        errors.append(f"{directory}/phase-manifest.json has non-terminal status")
    for key in ("started_at", "completed_at"):
        if not isinstance(manifest.get(key), str) or not manifest.get(key):
            errors.append(f"{directory}/phase-manifest.json missing {key}")
    for key in ("inputs", "outputs", "warnings", "errors"):
        if not isinstance(manifest.get(key), list):
            errors.append(f"{directory}/phase-manifest.json missing list {key}")


def run_schema(root: Path, schema: str, document: Path, errors: list[str], *, semantic: str = "none", target: Path | None = None, each: bool = False) -> None:
    command = [sys.executable, str(root / "scripts/validate-json.py"), str(root / f"schemas/v2/{schema}"), str(document)]
    if semantic != "none":
        command.extend(["--semantic", semantic])
    if target is not None:
        command.extend(["--target", str(target)])
    if each:
        command.append("--each")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        errors.append(f"schema failure {document}: {detail}")


def context_target(root: Path, scan: Path, errors: list[str]) -> Path | None:
    context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
    context = load(context_path, errors)
    if not isinstance(context, dict):
        return None
    if Path(str(context.get("scan_base", ""))).resolve() != scan.resolve():
        errors.append("audit context does not point at requested v2 scan")
        return None
    target = Path(str(context.get("repo_path", "")))
    if not target.is_dir():
        errors.append("audit context target is unavailable")
        return None
    return target


def has_graph_evidence(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    if isinstance(document.get("edges"), list) and document["edges"]:
        return True
    nodes = document.get("nodes")
    return isinstance(nodes, list) and any(
        isinstance(node, dict) and node.get("role") not in {"source", "target"}
        for node in nodes
    )


def validate_scoped_graph(
    scan: Path,
    directory: str,
    plan: object,
    errors: list[str],
    *,
    mode: str,
    require_all_when_none_marked: bool,
) -> None:
    if not isinstance(plan, dict) or plan.get("mode") != mode:
        errors.append(f"{directory} plan mode must be {mode}")
        return
    scopes = plan.get("scopes")
    if not isinstance(scopes, list):
        errors.append(f"{directory} plan scopes must be a list")
        return
    required = [scope for scope in scopes if isinstance(scope, dict) and scope.get("required")]
    if require_all_when_none_marked and not required:
        required = [scope for scope in scopes if isinstance(scope, dict)]
    if require_all_when_none_marked and not required:
        coverage = plan.get("coverage") or {}
        if int(coverage.get("seed_count", 0)) > 0:
            errors.append(f"{directory} plan has seeds but no graph scope")
    for scope in required:
        scope_id = str(scope.get("id", ""))
        if not scope_id:
            errors.append(f"{directory} required scope is missing id")
            continue
        context_path = scan / directory / "codegraph-runs" / scope_id / "codegraph-out/context.json"
        context = load(context_path, errors)
        if not has_graph_evidence(context):
            errors.append(f"{directory} required scope {scope_id} has no graph evidence")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("harness_root", type=Path)
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("phase")
    args = parser.parse_args()
    root = args.harness_root.resolve()
    scan = args.scan_base.resolve()
    phase = args.phase
    errors: list[str] = []

    run_schema(root, "run-manifest.schema.json", scan / "run-manifest.json", errors)
    target = context_target(root, scan, errors)

    if phase == "recon":
        require_file(scan / "repo-context/repo.md", errors)
        run_schema(root, "repo-context.schema.json", scan / "repo-context/repo-context.json", errors, semantic="repo-context", target=target)
        run_schema(root, "security-surfaces.schema.json", scan / "repo-context/security-surfaces.json", errors, semantic="security-surfaces", target=target)
        for name in ("overview.json", "trust-boundaries.json", "input-surfaces.json"):
            run_schema(root, "recon-research.schema.json", scan / "repo-context/research" / name, errors)
        require_manifest(scan, "repo-context", "recon", errors)
    elif phase == "sca":
        require_file(scan / "sca/summary.md", errors)
        run_schema(root, "sca-advisories.schema.json", scan / "sca/raw-advisories.json", errors, semantic="sca-advisories", target=target)
        require_manifest(scan, "sca", "sca", errors, {"ok", "degraded", "skipped"})
    elif phase == "secrets":
        require_file(scan / "secrets/summary.md", errors)
        run_schema(root, "secrets-redacted.schema.json", scan / "secrets/redacted-candidates.json", errors, semantic="secrets-redacted", target=target)
        require_manifest(scan, "secrets", "secrets", errors, {"ok", "degraded", "skipped"})
    elif phase == "sast-threatmodel":
        require_file(scan / "sast/threat-model.md", errors)
        run_schema(root, "threat-model.schema.json", scan / "sast/threat-model.json", errors, semantic="threat-model", target=target)
    elif phase == "sast-decompose":
        require_file(scan / "sast/decompose.md", errors)
        run_schema(root, "hunt-plan.schema.json", scan / "sast/hunt-plan.json", errors, semantic="hunt-plan", target=target)
        load(scan / "sast/task-manifest.json", errors)
    elif phase == "sast-deepdive":
        plan = load(scan / "sast/hunt-plan.json", errors)
        if isinstance(plan, dict):
            for task in plan.get("tasks", []):
                if not isinstance(task, dict) or not task.get("id"):
                    continue
                run_schema(root, "hunt-result.schema.json", scan / f"sast/deepdive/{task['id']}.json", errors)
        run_schema(root, "candidate-finding.schema.json", scan / "sast/raw-findings.json", errors, semantic="candidate", target=target, each=True)
    elif phase == "sast-verify":
        run_schema(root, "validation-result.schema.json", scan / "sast/validation-results.json", errors, semantic="validation-result", each=True)
        queue = load(scan / "sast/validation-queue.json", errors)
        validations = load(scan / "sast/validation-results.json", errors)
        queue_items = queue if isinstance(queue, list) else []
        validation_items = validations if isinstance(validations, list) else []
        queue_ids = [str(item.get("id")) for item in queue_items if isinstance(item, dict)]
        validation_ids = [str(item.get("candidate_id")) for item in validation_items if isinstance(item, dict)]
        if len(validation_ids) != len(set(validation_ids)):
            errors.append("sast/validation-results.json contains duplicate candidate_id values")
        if set(queue_ids) != set(validation_ids):
            missing = sorted(set(queue_ids) - set(validation_ids))
            extra = sorted(set(validation_ids) - set(queue_ids))
            if missing:
                errors.append(f"missing SAST validation results: {', '.join(missing)}")
            if extra:
                errors.append(f"orphan SAST validation results: {', '.join(extra)}")
        load(scan / "sast/verified-findings.json", errors)
        load(scan / "sast/dropped-findings.json", errors)
        load(scan / "sast/dedup-clusters.json", errors)
    elif phase == "sast":
        for subphase in ("sast-threatmodel", "sast-decompose", "sast-deepdive", "sast-verify"):
            nested = subprocess.run(
                [sys.executable, __file__, str(root), str(scan), subphase],
                capture_output=True,
                text=True,
                check=False,
            )
            if nested.returncode:
                errors.append(nested.stderr.strip() or f"{subphase} validation failed")
        run_schema(root, "coverage-ledger.schema.json", scan / "sast/coverage-ledger.json", errors)
        run_schema(root, "wishlist.schema.json", scan / "sast/wishlist.json", errors)
        context_path = Path(os.environ.get("VULNOPS_AUDIT_CONTEXT", root / ".harness/audit-context.json"))
        context = load(context_path, errors)
        validations = load(scan / "sast/validation-results.json", errors)
        if isinstance(context, dict) and context.get("reproduction_mode") == "safe" and isinstance(validations, list):
            for item in validations:
                if not isinstance(item, dict) or item.get("status") != "source_verified":
                    continue
                finding_id = str(item.get("candidate_id", ""))
                result_path = scan / f"sast/reproduction/{finding_id}/result.json"
                run_schema(root, "reproduction-result.schema.json", result_path, errors, semantic="reproduction-result")
        require_file(scan / "sast/summary.md", errors)
        require_manifest(scan, "sast", "sast", errors)
    elif phase == "intelligence":
        documents = {
            name: load(scan / "intelligence" / name, errors)
            for name in ("evidence-corpus.json", "attack-surface-map.json", "intel-plan.json", "investigation-cards.json", "coverage-gaps.json", "rule-gaps.json")
        }
        require_file(scan / "intelligence/summary.md", errors)
        require_manifest(scan, "intelligence", "intelligence", errors, {"ok"})
        plan = documents["intel-plan.json"]
        cards = documents["investigation-cards.json"]
        corpus = documents["evidence-corpus.json"]
        surface_map = documents["attack-surface-map.json"]
        coverage_gaps = documents["coverage-gaps.json"]
        rule_gaps = documents["rule-gaps.json"]
        observations = corpus.get("observations") if isinstance(corpus, dict) else None
        if not isinstance(observations, list) or not observations:
            errors.append("intelligence evidence corpus must retain at least one observation")
        if not isinstance(surface_map, dict):
            errors.append("intelligence attack surface map must be an object")
        else:
            for key in ("components", "entry_points", "trust_boundaries", "files_by_category"):
                if key not in surface_map:
                    errors.append(f"intelligence attack surface map missing {key}")
        gaps = coverage_gaps.get("gaps") if isinstance(coverage_gaps, dict) else None
        if not isinstance(gaps, list):
            errors.append("intelligence coverage gaps must contain a gaps list")
        rules = rule_gaps.get("rule_gaps") if isinstance(rule_gaps, dict) else None
        if not isinstance(rules, list):
            errors.append("intelligence rule gaps must contain a rule_gaps list")
        validate_scoped_graph(scan, "intelligence", plan, errors, mode="intelligence-ooda", require_all_when_none_marked=False)
        allowed_sources = {"tool_evidence", "graph_inference", "agent_exploration", "coverage_gap"}
        card_items = cards.get("cards", []) if isinstance(cards, dict) else []
        if not isinstance(card_items, list):
            errors.append("intelligence investigation cards must contain a cards list")
        else:
            for index, card in enumerate(card_items):
                if not isinstance(card, dict) or card.get("source") not in allowed_sources:
                    errors.append(f"intelligence card {index} has an invalid source")
                    continue
                if not card.get("raw_refs"):
                    errors.append(f"intelligence card {index} has no raw refs")
                if card.get("source") != "coverage_gap" and not card.get("evidence_refs"):
                    errors.append(f"intelligence card {index} has no evidence refs")
    elif phase == "triage":
        require_file(scan / "triage/consolidated.md", errors)
        load(scan / "triage/findings.json", errors)
        load(scan / "triage/intrusion-seeds.json", errors)
        require_manifest(scan, "triage", "triage", errors)
    elif phase == "intrusion":
        require_file(scan / "intrusion/summary.md", errors)
        load(scan / "intrusion/enrichment.json", errors)
        plan = load(scan / "intrusion/intrusion-plan.json", errors)
        require_manifest(scan, "intrusion", "intrusion", errors, {"ok"})
        validate_scoped_graph(scan, "intrusion", plan, errors, mode="targeted-ooda", require_all_when_none_marked=True)
    elif phase == "final-reconciliation":
        run_schema(
            root,
            "final-findings.schema.json",
            scan / "final-reconciliation/candidates.json",
            errors,
            semantic="final-findings",
            target=target,
        )
        candidates = load(scan / "final-reconciliation/candidates.json", errors)
        candidate_items = candidates.get("findings", []) if isinstance(candidates, dict) else []
        for item in candidate_items:
            if not isinstance(item, dict):
                continue
            severity = (item.get("severity") or {}).get("overall")
            if severity in {"critical", "high"} and not (item.get("provenance") or {}).get("graph_refs"):
                errors.append(f"reconciled {item.get('id')} critical/high candidate has no graph evidence")
        require_file(scan / "final-reconciliation/summary.md", errors)
        require_manifest(scan, "final-reconciliation", "final-reconciliation", errors)
    elif phase == "final-verification":
        candidates = load(scan / "final-reconciliation/candidates.json", errors)
        results = scan / "final-verification/results"
        result_ids: set[str] = set()
        if results.is_dir():
            for path in sorted(results.glob("*.json")):
                run_schema(root, "independent-verification-result.schema.json", path, errors)
                result = load(path, errors)
                if isinstance(result, dict):
                    result_id = str(result.get("finding_id", ""))
                    result_ids.add(result_id)
                    if path.stem != result_id:
                        errors.append(f"{path} finding_id does not match its filename")
        candidate_items = candidates.get("findings", []) if isinstance(candidates, dict) else []
        candidate_ids = {
            str(item.get("id"))
            for item in candidate_items
            if isinstance(item, dict)
        }
        if candidate_ids != result_ids:
            missing = sorted(candidate_ids - result_ids)
            extra = sorted(result_ids - candidate_ids)
            if missing:
                errors.append(f"missing independent verification results: {', '.join(missing)}")
            if extra:
                errors.append(f"orphan independent verification results: {', '.join(extra)}")
        run_schema(root, "final-findings.schema.json", scan / "final-verification/findings.json", errors, semantic="final-findings", target=target)
        require_manifest(scan, "final-verification", "final-verification", errors)
    elif phase == "report":
        require_file(scan / "report/security-report.md", errors)
        run_schema(root, "report.schema.json", scan / "report/security-report.json", errors)
        require_manifest(scan, "report", "report", errors)
    else:
        errors.append(f"unknown v2 phase: {phase}")

    if errors:
        for error in errors:
            print(f"[validate-phase-v2] ERROR: {error}", file=sys.stderr)
        print(f"[validate-phase-v2] {phase} failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"[validate-phase-v2] {phase} artifacts valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
