#!/usr/bin/env bash
# Validate the required artifacts for one audit phase or SAST subphase.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <scan_base> <phase>" >&2
    exit 2
fi

SCAN_BASE="$1"
PHASE="$2"

harness_setup_containment "$HARNESS_ROOT"
harness_require_allowed_output "$HARNESS_ROOT" "$SCAN_BASE"

PYTHON="$(command -v python3 2>/dev/null || true)"
if [ -z "$PYTHON" ]; then
    echo "[validate-phase] ERROR: python3 not found" >&2
    exit 1
fi

errors=0

err() {
    echo "[validate-phase] ERROR: $*" >&2
    errors=$((errors + 1))
}

check_file() {
    local path="$1"
    if [ ! -f "$path" ]; then
        err "missing: $path"
    fi
}

check_json() {
    local path="$1"
    check_file "$path"
    if [ -f "$path" ]; then
        "$PYTHON" -m json.tool "$path" >/dev/null || err "invalid JSON: $path"
    fi
}

check_manifest_shape() {
    local path="$1"
    local phase="$2"
    shift 2
    check_json "$path"
    if [ ! -f "$path" ]; then
        return
    fi
    "$PYTHON" - "$path" "$phase" "$@" <<'PY' || err "invalid phase manifest: $path"
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
allowed = set(sys.argv[3:])
if not isinstance(manifest, dict):
    raise SystemExit(1)
if manifest.get("phase") != phase:
    raise SystemExit(1)
if manifest.get("status") not in allowed:
    raise SystemExit(1)
for key in ("started_at", "completed_at"):
    if not isinstance(manifest.get(key), str) or not manifest.get(key).strip():
        raise SystemExit(1)
for key in ("inputs", "outputs", "warnings", "errors"):
    if not isinstance(manifest.get(key), list):
        raise SystemExit(1)
tool_versions = manifest.get("tool_versions")
if tool_versions is not None and not isinstance(tool_versions, dict):
    raise SystemExit(1)
PY
}

validate_sca_raw_advisories() {
    local path="$1"
    "$PYTHON" - "$path" <<'PY' || err "invalid SCA raw advisories: $path"
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
if not isinstance(data, list):
    raise SystemExit(1)
allowed_severity = {"critical", "high", "medium", "low", "info"}
required = ("advisory_id", "package", "version", "ecosystem", "severity", "source_lockfile", "raw_ref", "summary")
for item in data:
    if not isinstance(item, dict):
        raise SystemExit(1)
    for key in required:
        if not isinstance(item.get(key), str):
            raise SystemExit(1)
    if item.get("severity") not in allowed_severity:
        raise SystemExit(1)
PY
}

validate_secrets_redacted_candidates() {
    local path="$1"
    "$PYTHON" - "$path" <<'PY' || err "invalid redacted secrets candidates: $path"
import json
import re
import sys
from pathlib import Path

doc = json.loads(Path(sys.argv[1]).read_text())
if not isinstance(doc, dict):
    raise SystemExit(1)
if not isinstance(doc.get("schema_version"), str) or not isinstance(doc.get("tool"), str):
    raise SystemExit(1)
candidates = doc.get("candidates")
if not isinstance(candidates, list):
    raise SystemExit(1)
allowed_classification = {"confirmed", "likely", "false-positive", "deprecated", "candidate"}
allowed_severity = {"critical", "high", "medium", "low", "info"}
secret_patterns = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
]
required = ("id", "type", "classification", "severity", "file", "line", "redacted_value", "evidence_refs", "raw_ref", "source")
for item in candidates:
    if not isinstance(item, dict):
        raise SystemExit(1)
    for key in required:
        if key not in item:
            raise SystemExit(1)
    for key in ("id", "type", "classification", "severity", "file", "redacted_value", "raw_ref", "source"):
        if not isinstance(item.get(key), str):
            raise SystemExit(1)
    if item.get("classification") not in allowed_classification or item.get("severity") not in allowed_severity:
        raise SystemExit(1)
    if not isinstance(item.get("line"), int) or item["line"] < 1:
        raise SystemExit(1)
    refs = item.get("evidence_refs")
    if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) for ref in refs):
        raise SystemExit(1)
    for value in item.values():
        strings = value if isinstance(value, list) else [value]
        for text in strings:
            if isinstance(text, str) and any(pattern.search(text) for pattern in secret_patterns):
                raise SystemExit(1)
PY
}

validate_sast_task_manifest() {
    local path="$1"
    "$PYTHON" - "$path" <<'PY' || err "invalid SAST task manifest: $path"
import json
import sys
from pathlib import Path

doc = json.loads(Path(sys.argv[1]).read_text())
chunks = doc.get("chunks")
if not isinstance(chunks, list):
    raise SystemExit(1)
if "rationale" not in doc and chunks:
    raise SystemExit(1)
required = ("id", "risk_rank", "size", "files", "focus_entry_points", "hypothesis", "threat_id", "lenses", "related_advisories", "evidence_refs")
for chunk in chunks:
    if not isinstance(chunk, dict):
        raise SystemExit(1)
    for key in required:
        if key not in chunk:
            raise SystemExit(1)
    if not isinstance(chunk.get("files"), list) or not chunk["files"]:
        raise SystemExit(1)
    if not isinstance(chunk.get("focus_entry_points"), list):
        raise SystemExit(1)
    if not isinstance(chunk.get("related_advisories"), list):
        raise SystemExit(1)
    if not isinstance(chunk.get("evidence_refs"), list) or not chunk["evidence_refs"]:
        raise SystemExit(1)
PY
}

check_sast_deepdive_chunks() {
    local manifest="${SCAN_BASE}/sast/task-manifest.json"
    local deepdive_dir="${SCAN_BASE}/sast/deepdive"

    if [ ! -f "$manifest" ]; then
        err "missing: $manifest"
        return
    fi

    "$PYTHON" - "$manifest" "$deepdive_dir" <<'PY' || err "SAST deepdive chunk validation failed"
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
deepdive_dir = Path(sys.argv[2])

try:
    data = json.loads(manifest.read_text())
except Exception as exc:
    print(f"invalid task manifest JSON: {exc}", file=sys.stderr)
    raise SystemExit(1)

chunks = data.get("chunks")
if not isinstance(chunks, list):
    print("task manifest missing chunks list", file=sys.stderr)
    raise SystemExit(1)

failed = False
for chunk in chunks:
    if not isinstance(chunk, dict) or not str(chunk.get("id", "")).strip():
        print("task manifest chunk missing id", file=sys.stderr)
        failed = True
        continue
    chunk_id = str(chunk["id"])
    path = deepdive_dir / f"{chunk_id}.json"
    if not path.is_file():
        print(f"missing deepdive chunk output: {path}", file=sys.stderr)
        failed = True
        continue
    try:
        json.loads(path.read_text())
    except Exception as exc:
        print(f"invalid deepdive chunk JSON: {path}: {exc}", file=sys.stderr)
        failed = True

raise SystemExit(1 if failed else 0)
PY
}

case "$PHASE" in
    recon)
        check_file "${SCAN_BASE}/repo-context/repo.md"
        check_json "${SCAN_BASE}/repo-context/repo-context.json"
        check_json "${SCAN_BASE}/repo-context/security-surfaces.json"
        check_manifest_shape "${SCAN_BASE}/repo-context/phase-manifest.json" recon ok degraded
        ;;
    sca)
        check_file "${SCAN_BASE}/sca/summary.md"
        check_json "${SCAN_BASE}/sca/raw-advisories.json"
        validate_sca_raw_advisories "${SCAN_BASE}/sca/raw-advisories.json"
        check_manifest_shape "${SCAN_BASE}/sca/phase-manifest.json" sca ok degraded skipped
        ;;
    secrets)
        check_file "${SCAN_BASE}/secrets/summary.md"
        check_json "${SCAN_BASE}/secrets/redacted-candidates.json"
        validate_secrets_redacted_candidates "${SCAN_BASE}/secrets/redacted-candidates.json"
        check_manifest_shape "${SCAN_BASE}/secrets/phase-manifest.json" secrets ok degraded skipped
        ;;
    sast-threatmodel)
        check_file "${SCAN_BASE}/sast/threat-model.md"
        check_json "${SCAN_BASE}/sast/threat-model.json"
        ;;
    sast-decompose)
        check_file "${SCAN_BASE}/sast/decompose.md"
        check_json "${SCAN_BASE}/sast/task-manifest.json"
        if [ -f "${SCAN_BASE}/sast/task-manifest.json" ]; then
            validate_sast_task_manifest "${SCAN_BASE}/sast/task-manifest.json"
        fi
        ;;
    sast-deepdive)
        check_sast_deepdive_chunks
        check_json "${SCAN_BASE}/sast/raw-findings.json"
        ;;
    sast-verify)
        check_json "${SCAN_BASE}/sast/verified-findings.json"
        check_json "${SCAN_BASE}/sast/dropped-findings.json"
        ;;
    sast)
        check_json "${SCAN_BASE}/sast/threat-model.json"
        check_json "${SCAN_BASE}/sast/task-manifest.json"
        if [ -f "${SCAN_BASE}/sast/task-manifest.json" ]; then
            validate_sast_task_manifest "${SCAN_BASE}/sast/task-manifest.json"
        fi
        check_sast_deepdive_chunks
        check_json "${SCAN_BASE}/sast/raw-findings.json"
        check_json "${SCAN_BASE}/sast/verified-findings.json"
        check_json "${SCAN_BASE}/sast/dropped-findings.json"
        check_json "${SCAN_BASE}/sast/coverage-ledger.json"
        check_file "${SCAN_BASE}/sast/summary.md"
        check_manifest_shape "${SCAN_BASE}/sast/phase-manifest.json" sast ok degraded
        ;;
    intelligence)
        check_json "${SCAN_BASE}/intelligence/evidence-corpus.json"
        check_json "${SCAN_BASE}/intelligence/attack-surface-map.json"
        check_json "${SCAN_BASE}/intelligence/intel-plan.json"
        check_json "${SCAN_BASE}/intelligence/investigation-cards.json"
        check_json "${SCAN_BASE}/intelligence/coverage-gaps.json"
        check_json "${SCAN_BASE}/intelligence/rule-gaps.json"
        check_file "${SCAN_BASE}/intelligence/summary.md"
        check_manifest_shape "${SCAN_BASE}/intelligence/phase-manifest.json" intelligence ok
        if [ -f "${SCAN_BASE}/intelligence/phase-manifest.json" ] && [ -f "${SCAN_BASE}/intelligence/intel-plan.json" ] && [ -f "${SCAN_BASE}/intelligence/investigation-cards.json" ]; then
            "$PYTHON" - "${SCAN_BASE}/intelligence/phase-manifest.json" "${SCAN_BASE}/intelligence/intel-plan.json" "${SCAN_BASE}/intelligence/investigation-cards.json" "${SCAN_BASE}/intelligence" <<'PY' || err "intelligence OODA validation failed"
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
plan = json.loads(Path(sys.argv[2]).read_text())
cards_doc = json.loads(Path(sys.argv[3]).read_text())
intelligence_dir = Path(sys.argv[4])
if manifest.get("phase") != "intelligence" or manifest.get("status") != "ok":
    raise SystemExit(1)
if plan.get("mode") != "intelligence-ooda":
    raise SystemExit(1)
scopes = plan.get("scopes")
if not isinstance(scopes, list):
    raise SystemExit(1)
cards = cards_doc.get("cards")
if not isinstance(cards, list):
    raise SystemExit(1)
allowed_sources = {"tool_evidence", "graph_inference", "agent_exploration", "coverage_gap"}

def has_codegraph_evidence(ctx):
    if not isinstance(ctx, dict):
        return False
    edges = ctx.get("edges")
    if isinstance(edges, list) and edges:
        return True
    nodes = ctx.get("nodes")
    if not isinstance(nodes, list):
        return False
    return any(isinstance(node, dict) and node.get("role") not in {"source", "target"} for node in nodes)

for card in cards:
    if not isinstance(card, dict) or card.get("source") not in allowed_sources:
        raise SystemExit(1)
    if not card.get("raw_refs"):
        raise SystemExit(1)
    if card.get("source") != "coverage_gap" and not card.get("evidence_refs"):
        raise SystemExit(1)
for scope in scopes:
    if not isinstance(scope, dict) or not scope.get("id"):
        raise SystemExit(1)
    if scope.get("required"):
        sid = str(scope["id"])
        cg_context = intelligence_dir / "codegraph-runs" / sid / "codegraph-out" / "context.json"
        codegraph_ok = False
        if cg_context.is_file():
            try:
                ctx = json.loads(cg_context.read_text())
            except Exception:
                ctx = {}
            codegraph_ok = has_codegraph_evidence(ctx)
        if not codegraph_ok:
            raise SystemExit(1)
PY
        fi
        ;;
    triage)
        check_file "${SCAN_BASE}/triage/consolidated.md"
        check_json "${SCAN_BASE}/triage/findings.json"
        check_json "${SCAN_BASE}/triage/intrusion-seeds.json"
        check_manifest_shape "${SCAN_BASE}/triage/phase-manifest.json" triage ok degraded
        ;;
    intrusion)
        check_file "${SCAN_BASE}/intrusion/summary.md"
        check_json "${SCAN_BASE}/intrusion/enrichment.json"
        check_json "${SCAN_BASE}/intrusion/intrusion-plan.json"
        check_manifest_shape "${SCAN_BASE}/intrusion/phase-manifest.json" intrusion ok
        if [ -f "${SCAN_BASE}/intrusion/phase-manifest.json" ] && [ -f "${SCAN_BASE}/intrusion/intrusion-plan.json" ]; then
            "$PYTHON" - "${SCAN_BASE}/intrusion/phase-manifest.json" "${SCAN_BASE}/intrusion/intrusion-plan.json" "${SCAN_BASE}/intrusion" <<'PY' || err "intrusion scoped codegraph validation failed"
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
plan = json.loads(Path(sys.argv[2]).read_text())
intrusion_dir = Path(sys.argv[3])
if plan.get("mode") != "targeted-ooda":
    raise SystemExit(1)
scopes = plan.get("scopes")
if not isinstance(scopes, list) or not scopes:
    raise SystemExit(1)

def has_codegraph_evidence(ctx):
    if not isinstance(ctx, dict):
        return False
    edges = ctx.get("edges")
    if isinstance(edges, list) and edges:
        return True
    nodes = ctx.get("nodes")
    if not isinstance(nodes, list):
        return False
    return any(isinstance(node, dict) and node.get("role") not in {"source", "target"} for node in nodes)

# When no scope is marked required (e.g. no critical/high triage findings),
# every scope is treated as required. codegraph is the sole graph backend;
# every scope must have graph edges or evidence-bearing nodes.
required_scopes = [scope for scope in scopes if isinstance(scope, dict) and scope.get("required")]
if not required_scopes:
    required_scopes = [scope for scope in scopes if isinstance(scope, dict)]
for scope in required_scopes:
    sid = scope.get("id")
    if not sid:
        raise SystemExit(1)
    cg_context = intrusion_dir / "codegraph-runs" / str(sid) / "codegraph-out" / "context.json"
    codegraph_ok = False
    if cg_context.is_file():
        try:
            ctx = json.loads(cg_context.read_text())
        except Exception:
            ctx = {}
        codegraph_ok = has_codegraph_evidence(ctx)
    if not codegraph_ok:
        raise SystemExit(1)
PY
        fi
        ;;
    final-reconciliation)
        check_json "${SCAN_BASE}/final-reconciliation/findings.json"
        check_file "${SCAN_BASE}/final-reconciliation/summary.md"
        check_manifest_shape "${SCAN_BASE}/final-reconciliation/phase-manifest.json" final-reconciliation ok degraded
        ;;
    report)
        check_file "${SCAN_BASE}/report/security-report.md"
        check_json "${SCAN_BASE}/report/security-report.json"
        check_manifest_shape "${SCAN_BASE}/report/phase-manifest.json" report ok degraded
        ;;
    *)
        err "unknown phase: $PHASE"
        ;;
esac

if [ "$errors" -gt 0 ]; then
    echo "[validate-phase] ${PHASE} failed with ${errors} error(s)" >&2
    exit 1
fi

echo "[validate-phase] ${PHASE} artifacts present"
