#!/usr/bin/env bash
# Validate scan artifacts for schema-era harness invariants.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <scan_base>" >&2
    exit 2
fi

SCAN_BASE="$1"
harness_setup_containment "$HARNESS_ROOT"
harness_require_allowed_output "$HARNESS_ROOT" "$SCAN_BASE"

PYTHON="${HARNESS_ROOT}/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
    PYTHON="$(command -v python3 2>/dev/null || true)"
fi
if [ -z "$PYTHON" ]; then
    echo "[validate-scan] ERROR: python3 not found" >&2
    exit 1
fi

"$PYTHON" - "$HARNESS_ROOT" "$SCAN_BASE" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
scan = Path(sys.argv[2]).resolve()
errors: list[str] = []
json_cache = {}
TRIAGE_ID_RE = re.compile(r"^T-\d{3}$")


def fail(message: str) -> None:
    errors.append(message)


def load_json(path: Path):
    if path in json_cache:
        return json_cache[path]
    try:
        loaded = json.loads(path.read_text())
        json_cache[path] = loaded
        return loaded
    except FileNotFoundError:
        fail(f"missing JSON: {path.relative_to(root)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {path.relative_to(root)}: {exc}")
    json_cache[path] = None
    return None


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


if root not in scan.parents and scan != root:
    fail(f"scan path escapes harness root: {scan}")
if not scan.exists():
    fail(f"scan path does not exist: {scan}")

expected_manifests = {
    "repo-context": "recon",
    "sca": "sca",
    "sast": "sast",
    "secrets": "secrets",
    "intelligence": "intelligence",
    "triage": "triage",
    "intrusion": "intrusion",
    "final-reconciliation": "final-reconciliation",
    "report": "report",
}

for dirname, phase in expected_manifests.items():
    manifest_path = scan / dirname / "phase-manifest.json"
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        continue
    if manifest.get("phase") != phase:
        fail(f"{rel(manifest_path)} phase must be {phase!r}")
    if manifest.get("status") not in {"ok", "degraded", "failed", "skipped"}:
        fail(f"{rel(manifest_path)} has invalid status")
    if phase == "intrusion":
        if manifest.get("status") != "ok":
            fail(f"{rel(manifest_path)} must be ok; LLM-backed Graphify is required")
        manifest_text = json.dumps(manifest).lower()
        if any(marker in manifest_text for marker in ("ast-only", "llm unavailable", "llm_backend\": \"ollama (unavailable")):
            fail(f"{rel(manifest_path)} indicates AST-only or unavailable LLM")
    if phase == "intelligence":
        if manifest.get("status") != "ok":
            fail(f"{rel(manifest_path)} must be ok; intelligence fusion is required")
    for key in ("inputs", "outputs", "warnings", "errors"):
        if not isinstance(manifest.get(key), list):
            fail(f"{rel(manifest_path)} missing list field {key}")

required_outputs = [
    scan / "repo-context" / "repo-context.json",
    scan / "repo-context" / "security-surfaces.json",
    scan / "sast" / "threat-model.json",
    scan / "sast" / "task-manifest.json",
    scan / "sast" / "raw-findings.json",
    scan / "sast" / "verified-findings.json",
    scan / "sast" / "dropped-findings.json",
    scan / "sast" / "coverage-ledger.json",
    scan / "secrets" / "redacted-candidates.json",
    scan / "intelligence" / "evidence-corpus.json",
    scan / "intelligence" / "attack-surface-map.json",
    scan / "intelligence" / "graphify-intel-plan.json",
    scan / "intelligence" / "investigation-cards.json",
    scan / "intelligence" / "coverage-gaps.json",
    scan / "intelligence" / "rule-gaps.json",
    scan / "triage" / "findings.json",
    scan / "triage" / "intrusion-seeds.json",
    scan / "intrusion" / "enrichment.json",
    scan / "intrusion" / "graphify-plan.json",
    scan / "final-reconciliation" / "findings.json",
    scan / "report" / "security-report.json",
]
for path in required_outputs:
    load_json(path)

triage = load_json(scan / "triage" / "findings.json")
security_surfaces = load_json(scan / "repo-context" / "security-surfaces.json")
evidence_corpus = load_json(scan / "intelligence" / "evidence-corpus.json")
attack_surface_map = load_json(scan / "intelligence" / "attack-surface-map.json")
intelligence_plan = load_json(scan / "intelligence" / "graphify-intel-plan.json")
investigation_cards = load_json(scan / "intelligence" / "investigation-cards.json")
coverage_gaps = load_json(scan / "intelligence" / "coverage-gaps.json")
rule_gaps = load_json(scan / "intelligence" / "rule-gaps.json")
intrusion_seeds = load_json(scan / "triage" / "intrusion-seeds.json")
graphify_plan = load_json(scan / "intrusion" / "graphify-plan.json")
intrusion_enrichment = load_json(scan / "intrusion" / "enrichment.json")
final_findings = load_json(scan / "final-reconciliation" / "findings.json")
report = load_json(scan / "report" / "security-report.json")
raw_advisories = load_json(scan / "sca" / "raw-advisories.json")
threat_model = load_json(scan / "sast" / "threat-model.json")
task_manifest = load_json(scan / "sast" / "task-manifest.json")
sast_raw = load_json(scan / "sast" / "raw-findings.json")
sast_verified = load_json(scan / "sast" / "verified-findings.json")
sast_dropped = load_json(scan / "sast" / "dropped-findings.json")

if isinstance(threat_model, dict):
    for key in ("assets", "trust_boundaries", "entrypoints", "threats", "evidence_refs"):
        if key not in threat_model:
            fail(f"sast/threat-model.json missing {key}")
    if not isinstance(threat_model.get("evidence_refs"), list) or not threat_model.get("evidence_refs"):
        fail("sast/threat-model.json missing evidence_refs")

if isinstance(security_surfaces, dict):
    if not isinstance(security_surfaces.get("entry_points"), list) or not security_surfaces.get("entry_points"):
        fail("repo-context/security-surfaces.json missing entry_points")
    if not isinstance(security_surfaces.get("trust_boundaries"), list):
        fail("repo-context/security-surfaces.json missing trust_boundaries")
    if not isinstance(security_surfaces.get("security_relevant_files"), list):
        fail("repo-context/security-surfaces.json missing security_relevant_files")
    if not isinstance(security_surfaces.get("ignore_patterns"), list):
        fail("repo-context/security-surfaces.json missing ignore_patterns")
elif security_surfaces is not None:
    fail("repo-context/security-surfaces.json must be an object")

intelligence_card_ids = set()
if isinstance(evidence_corpus, dict):
    observations = evidence_corpus.get("observations")
    if not isinstance(observations, list):
        fail("intelligence/evidence-corpus.json observations must be a list")
    elif not observations:
        fail("intelligence/evidence-corpus.json must retain at least one observation")
elif evidence_corpus is not None:
    fail("intelligence/evidence-corpus.json must be an object")

if isinstance(attack_surface_map, dict):
    for key in ("components", "entry_points", "trust_boundaries", "files_by_category"):
        if key not in attack_surface_map:
            fail(f"intelligence/attack-surface-map.json missing {key}")
elif attack_surface_map is not None:
    fail("intelligence/attack-surface-map.json must be an object")

if isinstance(coverage_gaps, dict):
    gaps = coverage_gaps.get("gaps")
    if not isinstance(gaps, list):
        fail("intelligence/coverage-gaps.json gaps must be a list")
    else:
        for gap in gaps:
            if not isinstance(gap, dict):
                fail("intelligence coverage gaps must contain objects")
                continue
            if gap.get("status") not in {"open", "resolved", "deferred"}:
                fail(f"coverage gap {gap.get('id', '<unknown>')} must be open, resolved, or deferred")
            if gap.get("status") == "deferred" and not gap.get("reason"):
                fail(f"coverage gap {gap.get('id', '<unknown>')} deferred without reason")
elif coverage_gaps is not None:
    fail("intelligence/coverage-gaps.json must be an object")

if isinstance(rule_gaps, dict):
    if not isinstance(rule_gaps.get("rule_gaps"), list):
        fail("intelligence/rule-gaps.json rule_gaps must be a list")
elif rule_gaps is not None:
    fail("intelligence/rule-gaps.json must be an object")

if isinstance(intelligence_plan, dict):
    if intelligence_plan.get("mode") != "intelligence-ooda":
        fail("intelligence/graphify-intel-plan.json mode must be intelligence-ooda")
    scopes = intelligence_plan.get("scopes")
    if not isinstance(scopes, list):
        fail("intelligence/graphify-intel-plan.json scopes must be a list")
        scopes = []
    for scope in scopes:
        if not isinstance(scope, dict):
            fail("intelligence graphify scopes must contain objects")
            continue
        scope_id = scope.get("id")
        for key in ("observation_ids", "required", "reason", "files", "commands", "expected_evidence"):
            if key not in scope:
                fail(f"intelligence graphify scope {scope_id or '<unknown>'} missing {key}")
        if scope.get("required") and scope_id:
            graph_path = scan / "intelligence" / "graphify-runs" / str(scope_id) / "graphify-out" / "graph.json"
            quality_path = scan / "intelligence" / "graphify-runs" / str(scope_id) / "graphify-quality.json"
            graph = load_json(graph_path)
            load_json(quality_path)
            if isinstance(graph, dict):
                nodes = graph.get("nodes", [])
                if not isinstance(nodes, list) or not nodes:
                    fail(f"required intelligence Graphify scope {scope_id} has no nodes")
elif intelligence_plan is not None:
    fail("intelligence/graphify-intel-plan.json must be an object")

if isinstance(investigation_cards, dict):
    cards = investigation_cards.get("cards")
    if not isinstance(cards, list):
        fail("intelligence/investigation-cards.json cards must be a list")
        cards = []
    allowed_sources = {"tool_evidence", "graph_inference", "agent_exploration", "coverage_gap"}
    for card in cards:
        if not isinstance(card, dict):
            fail("intelligence cards must contain objects")
            continue
        cid = card.get("id")
        if not cid:
            fail("intelligence card missing id")
            continue
        intelligence_card_ids.add(str(cid))
        if card.get("source") not in allowed_sources:
            fail(f"intelligence card {cid} has invalid source")
        if not isinstance(card.get("hypotheses"), list) or not card.get("hypotheses"):
            fail(f"intelligence card {cid} missing hypotheses")
        if not card.get("raw_refs"):
            fail(f"intelligence card {cid} missing raw_refs")
        if card.get("source") != "coverage_gap" and not card.get("evidence_refs"):
            fail(f"intelligence card {cid} missing evidence_refs")
elif investigation_cards is not None:
    fail("intelligence/investigation-cards.json must be an object")

manifest_chunk_ids = set()
if isinstance(task_manifest, dict):
    chunks = task_manifest.get("chunks")
    if not isinstance(chunks, list):
        fail("sast/task-manifest.json chunks must be a list")
        chunks = []
    if "rationale" not in task_manifest:
        fail("sast/task-manifest.json missing rationale")
    for chunk in chunks:
        if not isinstance(chunk, dict):
            fail("sast/task-manifest.json chunks must contain objects")
            continue
        cid = chunk.get("id")
        if not cid:
            fail("task manifest chunk missing id")
            continue
        manifest_chunk_ids.add(str(cid))
        for key in ("risk_rank", "size", "files", "hypothesis", "threat_id", "lenses", "evidence_refs"):
            if key not in chunk:
                fail(f"task manifest chunk {cid} missing {key}")
        if not isinstance(chunk.get("files"), list) or not chunk.get("files"):
            fail(f"task manifest chunk {cid} missing files")
        if not isinstance(chunk.get("evidence_refs"), list) or not chunk.get("evidence_refs"):
            fail(f"task manifest chunk {cid} missing evidence_refs")

sast_raw_ids = set()
if isinstance(sast_raw, list):
    for item in sast_raw:
        if not isinstance(item, dict):
            fail("sast/raw-findings.json must contain objects")
            continue
        fid = item.get("id")
        if not fid:
            fail("raw SAST finding missing id")
            continue
        fid = str(fid)
        sast_raw_ids.add(fid)
        for key in ("chunk_id", "title", "severity", "confidence", "source_ref", "sink_ref", "entrypoint_ref", "evidence_refs", "lenses"):
            if key not in item:
                fail(f"raw SAST finding {fid} missing {key}")
        if item.get("chunk_id") and manifest_chunk_ids and str(item.get("chunk_id")) not in manifest_chunk_ids:
            fail(f"raw SAST finding {fid} references unknown chunk {item.get('chunk_id')}")
        if not isinstance(item.get("evidence_refs"), list) or not item.get("evidence_refs"):
            fail(f"raw SAST finding {fid} missing evidence_refs")
elif sast_raw is not None:
    fail("sast/raw-findings.json must be a list")

sast_verified_raw_ids = set()
sast_verified_ids = set()
if isinstance(sast_verified, list):
    for item in sast_verified:
        if not isinstance(item, dict):
            fail("sast/verified-findings.json must contain objects")
            continue
        fid = item.get("id")
        raw_id = item.get("raw_id")
        if not fid:
            fail("verified SAST finding missing id")
            continue
        fid = str(fid)
        sast_verified_ids.add(fid)
        if raw_id:
            sast_verified_raw_ids.add(str(raw_id))
            if sast_raw_ids and str(raw_id) not in sast_raw_ids:
                fail(f"verified SAST finding {fid} references unknown raw_id {raw_id}")
        for key in ("raw_id", "title", "status", "severity", "confidence", "source_ref", "sink_ref", "entrypoint_ref", "evidence_refs", "raw_refs", "closure_reason"):
            if key not in item:
                fail(f"verified SAST finding {fid} missing {key}")
        if item.get("status") != "verified":
            fail(f"verified SAST finding {fid} status is not verified")
        if not item.get("closure_reason"):
            fail(f"verified SAST finding {fid} missing closure_reason")
elif sast_verified is not None:
    fail("sast/verified-findings.json must be a list")

sast_dropped_raw_ids = set()
sast_dropped_ids = set()
if isinstance(sast_dropped, list):
    for item in sast_dropped:
        if not isinstance(item, dict):
            fail("sast/dropped-findings.json must contain objects")
            continue
        fid = item.get("id")
        raw_id = item.get("raw_id")
        if not fid:
            fail("dropped SAST finding missing id")
            continue
        fid = str(fid)
        sast_dropped_ids.add(fid)
        if raw_id:
            sast_dropped_raw_ids.add(str(raw_id))
            if sast_raw_ids and str(raw_id) not in sast_raw_ids:
                fail(f"dropped SAST finding {fid} references unknown raw_id {raw_id}")
        for key in ("raw_id", "status", "reason", "evidence_refs", "raw_refs"):
            if key not in item:
                fail(f"dropped SAST finding {fid} missing {key}")
        if item.get("status") not in {"false-positive", "deferred", "suppressed", "not_applicable"}:
            fail(f"dropped SAST finding {fid} has invalid status")
        if not item.get("reason"):
            fail(f"dropped SAST finding {fid} missing reason")
elif sast_dropped is not None:
    fail("sast/dropped-findings.json must be a list")

if sast_raw_ids:
    missing_outcome = sast_raw_ids - sast_verified_raw_ids - sast_dropped_raw_ids
    for raw_id in sorted(missing_outcome):
        fail(f"raw SAST finding {raw_id} has no verifier outcome")

triage_by_id = {}
triage_items = triage.get("findings", triage) if isinstance(triage, dict) else triage
if isinstance(triage_items, list):
    for item in triage_items:
        if not isinstance(item, dict):
            fail("triage/findings.json must contain objects")
            continue
        fid = item.get("id")
        if not fid:
            fail("triage finding missing id")
            continue
        triage_by_id[fid] = item
        status = item.get("status")
        severity = item.get("severity")
        if severity in {"critical", "high"} and status == "unverified":
            fail(f"{fid} is {severity} but remains unverified")
        if not item.get("evidence_refs"):
            fail(f"{fid} missing evidence_refs")
        if item.get("source") is None and item.get("sources") is None:
            fail(f"{fid} missing source/sources")
        sources = item.get("source", item.get("sources", []))
        if isinstance(sources, str):
            sources = [sources]
        raw_refs = item.get("raw_refs", [])
        raw_refs_text = " ".join(str(ref) for ref in raw_refs)
        if any(str(source).startswith("sast") for source in sources):
            if "sast/verified-findings.json" not in raw_refs_text and not (set(map(str, raw_refs)) & sast_verified_ids):
                fail(f"{fid} is a SAST triage finding but does not reference verified SAST output")
            if set(map(str, raw_refs)) & sast_dropped_ids:
                fail(f"{fid} references dropped SAST finding output")
elif triage_items is not None:
    fail("triage/findings.json must be a list or an object with a findings list")

verified_triage_ids = {fid for fid, item in triage_by_id.items() if item.get("status") == "verified"}
seed_ids = set()
if isinstance(intrusion_seeds, dict):
    seeds = intrusion_seeds.get("seeds")
    if not isinstance(seeds, list):
        fail("triage/intrusion-seeds.json seeds must be a list")
        seeds = []
    for seed in seeds:
        if not isinstance(seed, dict):
            fail("triage/intrusion-seeds.json seeds must contain objects")
            continue
        sid = seed.get("id")
        if not sid:
            fail("intrusion seed missing id")
            continue
        sid = str(sid)
        seed_ids.add(sid)
        if not TRIAGE_ID_RE.match(sid):
            fail(f"intrusion seed {sid} is not a canonical triage finding id")
        if sid not in verified_triage_ids:
            fail(f"intrusion seed {sid} does not map to a verified triage finding")
        for key in ("severity", "confidence", "question_type", "files", "graph_questions"):
            if key not in seed:
                fail(f"intrusion seed {sid} missing {key}")
        if not isinstance(seed.get("graph_questions"), list) or not seed.get("graph_questions"):
            fail(f"intrusion seed {sid} missing graph_questions")
elif intrusion_seeds is not None:
    fail("triage/intrusion-seeds.json must be an object")

if isinstance(graphify_plan, dict):
    if graphify_plan.get("mode") != "targeted-ooda":
        fail("intrusion/graphify-plan.json mode must be targeted-ooda")
    scopes = graphify_plan.get("scopes")
    if not isinstance(scopes, list) or not scopes:
        fail("intrusion/graphify-plan.json must contain scopes")
        scopes = []
    for scope in scopes:
        if not isinstance(scope, dict):
            fail("graphify plan scopes must contain objects")
            continue
        scope_id = scope.get("id")
        if not scope_id:
            fail("graphify plan scope missing id")
            continue
        for key in ("seed_ids", "required", "reason", "files", "commands", "expected_evidence"):
            if key not in scope:
                fail(f"graphify plan scope {scope_id} missing {key}")
        scope_seed_ids = scope.get("seed_ids", []) if isinstance(scope.get("seed_ids"), list) else []
        for seed_id in scope_seed_ids:
            if seed_ids and str(seed_id) not in seed_ids:
                fail(f"graphify plan scope {scope_id} references unknown seed {seed_id}")
        if scope.get("required"):
            graph_path = scan / "intrusion" / "graphify-runs" / str(scope_id) / "graphify-out" / "graph.json"
            quality_path = scan / "intrusion" / "graphify-runs" / str(scope_id) / "graphify-quality.json"
            graph = load_json(graph_path)
            load_json(quality_path)
            if isinstance(graph, dict):
                nodes = graph.get("nodes", [])
                edges = graph.get("links", graph.get("edges", []))
                if not isinstance(nodes, list) or not nodes:
                    fail(f"required graphify scope {scope_id} has no nodes")
                if any(isinstance(cmd, dict) and cmd.get("type") in {"query", "path", "affected"} for cmd in scope.get("commands", [])):
                    if not isinstance(edges, list) or not edges:
                        fail(f"required graphify scope {scope_id} has no traversal edges")
elif graphify_plan is not None:
    fail("intrusion/graphify-plan.json must be an object")

enriched_triage_ids = set()
if isinstance(intrusion_enrichment, list):
    for item in intrusion_enrichment:
        if isinstance(item, dict) and item.get("triage_id"):
            enriched_triage_ids.add(str(item.get("triage_id")))
elif intrusion_enrichment is not None:
    fail("intrusion/enrichment.json must be a list")

final_by_id = {}
final_uses_sca = False
if isinstance(final_findings, list):
    for item in final_findings:
        if not isinstance(item, dict):
            fail("final-reconciliation/findings.json must contain objects")
            continue
        fid = item.get("id")
        if not fid:
            fail("final finding missing id")
            continue
        final_by_id[fid] = item
        for key in ("title", "source", "status", "severity", "confidence", "evidence_refs", "raw_refs"):
            if key not in item:
                fail(f"{fid} missing normalized field {key}")
        if item.get("status") != "verified":
            fail(f"final finding {fid} is not verified")
        if not item.get("evidence_refs"):
            fail(f"final finding {fid} missing evidence_refs")
        refs_text = json.dumps({"raw_refs": item.get("raw_refs", []), "evidence_refs": item.get("evidence_refs", [])}).lower()
        if "intelligence/" not in refs_text and not any(card_id.lower() in refs_text for card_id in intelligence_card_ids):
            fail(f"final finding {fid} missing intelligence provenance")
        if item.get("severity") in {"critical", "high"} and fid not in enriched_triage_ids:
            fail(f"critical/high final finding {fid} missing intrusion enrichment for reachability, blast radius, or dependency impact")
        sources = item.get("source", [])
        if isinstance(sources, str):
            sources = [sources]
        if any(str(source).startswith("sca") for source in sources):
            final_uses_sca = True

if final_uses_sca and isinstance(raw_advisories, list) and not raw_advisories:
    fail("sca/raw-advisories.json must retain per-advisory evidence for SCA findings")

if isinstance(report, dict):
    findings = report.get("findings")
    summary = report.get("summary")
    intelligence_summary = report.get("intelligence")
    if not isinstance(findings, list):
        fail("report/security-report.json findings must be a list")
        findings = []
    if not isinstance(summary, dict):
        fail("report/security-report.json summary must be an object")
        summary = {}
    if not isinstance(intelligence_summary, dict):
        fail("report/security-report.json intelligence must be an object")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if not isinstance(finding, dict):
            fail("report finding must be an object")
            continue
        triage_id = finding.get("triage_id")
        status = finding.get("status")
        severity = finding.get("severity")
        if triage_id is None:
            fail(f"report finding {finding.get('id', '<unknown>')} missing triage_id")
        elif triage_id in final_by_id and final_by_id[triage_id].get("status") != status:
            fail(f"report finding {finding.get('id')} status disagrees with {triage_id}")
        elif triage_id not in final_by_id:
            fail(f"report finding {finding.get('id')} references missing final finding {triage_id}")
        if status != "verified":
            fail(f"report finding {finding.get('id', '<unknown>')} is not verified")
        if not finding.get("evidence_refs"):
            fail(f"report finding {finding.get('id', '<unknown>')} missing evidence_refs")
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            fail(f"report finding {finding.get('id', '<unknown>')} has invalid severity")

    if summary.get("total") != len(findings):
        fail("report summary total does not match findings length")
    for severity, count in severity_counts.items():
        if summary.get(severity) != count:
            fail(f"report summary {severity} count mismatch")

stale_intrusion_markers = (
    "ast-only",
    "llm unavailable",
    "graph extraction was ast-only",
    "semantic edge labels and community detection not available",
)
for stale_path in [
    scan / "intrusion" / "phase-manifest.json",
    scan / "intrusion" / "summary.md",
    scan / "intelligence" / "phase-manifest.json",
    scan / "intelligence" / "summary.md",
    scan / "final-reconciliation" / "phase-manifest.json",
    scan / "final-reconciliation" / "summary.md",
    scan / "report" / "phase-manifest.json",
    scan / "report" / "security-report.md",
    scan / "report" / "security-report.json",
]:
    if not stale_path.is_file():
        continue
    try:
        stale_text = stale_path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        continue
    for marker in stale_intrusion_markers:
        if marker in stale_text:
            fail(f"{rel(stale_path)} contains stale non-LLM intrusion marker: {marker}")
            break

secret_patterns = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
]
for path in scan.rglob("*"):
    if not path.is_file():
        continue
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        continue
    for pattern in secret_patterns:
        if pattern.search(text):
            fail(f"possible unredacted secret in {rel(path)}")
            break

if errors:
    for error in errors:
        print(f"[validate-scan] ERROR: {error}", file=sys.stderr)
    print(f"[validate-scan] failed with {len(errors)} error(s)", file=sys.stderr)
    sys.exit(1)

print("[validate-scan] scan artifacts valid")
PY
