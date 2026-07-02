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

check_manifest_status() {
    local path="$1"
    shift
    if [ ! -f "$path" ]; then
        return
    fi
    "$PYTHON" - "$path" "$@" <<'PY' || err "invalid terminal status in $path"
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
allowed = set(sys.argv[2:])
sys.exit(0 if manifest.get("status") in allowed else 1)
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
        check_json "${SCAN_BASE}/repo-context/phase-manifest.json"
        ;;
    sca)
        check_file "${SCAN_BASE}/sca/summary.md"
        check_json "${SCAN_BASE}/sca/raw-advisories.json"
        check_json "${SCAN_BASE}/sca/phase-manifest.json"
        ;;
    secrets)
        check_file "${SCAN_BASE}/secrets/summary.md"
        check_json "${SCAN_BASE}/secrets/redacted-candidates.json"
        check_json "${SCAN_BASE}/secrets/phase-manifest.json"
        ;;
    sast-threatmodel)
        check_file "${SCAN_BASE}/sast/threat-model.md"
        check_json "${SCAN_BASE}/sast/threat-model.json"
        ;;
    sast-decompose)
        check_file "${SCAN_BASE}/sast/decompose.md"
        check_json "${SCAN_BASE}/sast/task-manifest.json"
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
        check_sast_deepdive_chunks
        check_json "${SCAN_BASE}/sast/raw-findings.json"
        check_json "${SCAN_BASE}/sast/verified-findings.json"
        check_json "${SCAN_BASE}/sast/dropped-findings.json"
        check_json "${SCAN_BASE}/sast/coverage-ledger.json"
        check_file "${SCAN_BASE}/sast/summary.md"
        check_json "${SCAN_BASE}/sast/phase-manifest.json"
        ;;
    intelligence)
        check_json "${SCAN_BASE}/intelligence/evidence-corpus.json"
        check_json "${SCAN_BASE}/intelligence/attack-surface-map.json"
        check_json "${SCAN_BASE}/intelligence/intel-plan.json"
        check_json "${SCAN_BASE}/intelligence/investigation-cards.json"
        check_json "${SCAN_BASE}/intelligence/coverage-gaps.json"
        check_json "${SCAN_BASE}/intelligence/rule-gaps.json"
        check_file "${SCAN_BASE}/intelligence/summary.md"
        check_json "${SCAN_BASE}/intelligence/phase-manifest.json"
        check_manifest_status "${SCAN_BASE}/intelligence/phase-manifest.json" ok
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
            if isinstance(ctx, dict):
                codegraph_ok = (len(ctx.get("nodes", []) or []) + len(ctx.get("edges", []) or [])) > 0
        if not codegraph_ok:
            raise SystemExit(1)
PY
        fi
        ;;
    triage)
        check_file "${SCAN_BASE}/triage/consolidated.md"
        check_json "${SCAN_BASE}/triage/findings.json"
        check_json "${SCAN_BASE}/triage/intrusion-seeds.json"
        check_json "${SCAN_BASE}/triage/phase-manifest.json"
        ;;
    intrusion)
        check_file "${SCAN_BASE}/intrusion/summary.md"
        check_json "${SCAN_BASE}/intrusion/enrichment.json"
        check_json "${SCAN_BASE}/intrusion/intrusion-plan.json"
        check_json "${SCAN_BASE}/intrusion/phase-manifest.json"
        check_manifest_status "${SCAN_BASE}/intrusion/phase-manifest.json" ok
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
        if isinstance(ctx, dict):
            codegraph_ok = (len(ctx.get("nodes", []) or []) + len(ctx.get("edges", []) or [])) > 0
    if not codegraph_ok:
        raise SystemExit(1)
PY
        fi
        ;;
    final-reconciliation)
        check_json "${SCAN_BASE}/final-reconciliation/findings.json"
        check_file "${SCAN_BASE}/final-reconciliation/summary.md"
        check_json "${SCAN_BASE}/final-reconciliation/phase-manifest.json"
        ;;
    report)
        check_file "${SCAN_BASE}/report/security-report.md"
        check_json "${SCAN_BASE}/report/security-report.json"
        check_json "${SCAN_BASE}/report/phase-manifest.json"
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
