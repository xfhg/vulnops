#!/usr/bin/env bash
# Print a compact, deterministic audit status. This is intentionally read-only:
# status questions should not restart phases, inspect subagent history, or loop.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

SCAN_BASE="${1:-}"
if [ -z "$SCAN_BASE" ]; then
    if [ ! -f "${HARNESS_ROOT}/.harness/audit-context.json" ]; then
        echo "[audit-status] no audit context found" >&2
        exit 2
    fi
    PYTHON="$(command -v python3 2>/dev/null || true)"
    if [ -z "$PYTHON" ]; then
        echo "[audit-status] python3 not found" >&2
        exit 1
    fi
    SCAN_BASE="$("$PYTHON" - <<'PY'
import json
from pathlib import Path
ctx = json.loads(Path(".harness/audit-context.json").read_text())
print(ctx["scan_base"])
PY
)"
fi

harness_require_allowed_output "$HARNESS_ROOT" "$SCAN_BASE"

PYTHON="$(command -v python3 2>/dev/null || true)"
if [ -z "$PYTHON" ]; then
    echo "[audit-status] python3 not found" >&2
    exit 1
fi

"$PYTHON" - "$HARNESS_ROOT" "$SCAN_BASE" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1]).resolve()
scan = Path(sys.argv[2]).resolve()
if not scan.exists():
    try:
        scan_label = str(scan.relative_to(root))
    except ValueError:
        scan_label = str(scan)
    print("Audit Status")
    print(f"- Scan: {scan_label}")
    print("- State: not complete")
    print("- Validation: failed")
    print("  [audit-status] stale audit context: scan_base does not exist")
    raise SystemExit(1)


phase_dirs = [
    ("recon", "repo-context"),
    ("tool-collection", "tool-collection"),
    ("sast", "sast"),
    ("campaign-planning", "campaign-planning"),
    ("intrusion", "intrusion"),
    ("synthesis", "synthesis"),
    ("final-verification", "final-verification"),
    ("report", "report"),
]


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


phases = []
run_manifest = load_json(scan / "run-manifest.json")
task_ledger = load_json(scan / "task-ledger.json")
audit_context = load_json(root / ".harness" / "audit-context.json")
is_v2 = isinstance(run_manifest, dict) and run_manifest.get("schema_version") == "2.0"
for phase, dirname in phase_dirs:
    path = scan / dirname / "phase-manifest.json"
    manifest = load_json(path)
    phases.append(
        {
            "phase": phase,
            "status": manifest.get("status") if isinstance(manifest, dict) else "missing",
            "manifest": rel(path),
        }
    )

validation = subprocess.run(
    ["bash", str(root / "scripts" / "validate-scan.sh"), str(scan)],
    cwd=root,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

report_md = scan / "report" / "security-report.md"
report_json = scan / "report" / "security-report.json"
intrusion_results = scan / "intrusion" / "intrusion-results.json"
summary = {}
report = load_json(report_json)
if isinstance(report, dict) and isinstance(report.get("summary"), dict):
    summary = report["summary"]

terminal = {"ok", "degraded", "skipped"}
complete = validation.returncode == 0 and all(item["status"] in terminal for item in phases)

print("Audit Status")
print(f"- Scan: {rel(scan)}")
print(f"- State: {'complete' if complete else 'not complete'}")
if is_v2:
    print(f"- Run ID: {run_manifest.get('run_id', 'unknown')}")
    print(f"- Run manifest: {run_manifest.get('status', 'unknown')}")
    primary_model = run_manifest.get("model", "unknown")
    verifier_model = run_manifest.get("verifier_model", "missing")
    print(f"- Primary model: {primary_model}")
    print(f"- Verifier model: {verifier_model}")
    model_roles = run_manifest.get("model_roles", {})
    if isinstance(model_roles, dict):
        print("- Model roles: " + ", ".join(f"{key}={model_roles.get(key, 'missing')}" for key in ("orchestrator", "task", "slow", "smol")))
    efforts = {"off", "minimal", "low", "medium", "high", "xhigh", "max", "auto"}
    primary_head, primary_sep, primary_effort = str(primary_model).rpartition(":")
    verifier_head, verifier_sep, verifier_effort = str(verifier_model).rpartition(":")
    primary_identity = primary_head if primary_sep and primary_effort.lower() in efforts else str(primary_model)
    verifier_identity = verifier_head if verifier_sep and verifier_effort.lower() in efforts else str(verifier_model)
    print(f"- Model diversity: {str(primary_identity != verifier_identity).lower()}")
    print(f"- Reproduction: {run_manifest.get('reproduction_mode', 'off')}")
    if run_manifest.get("status") == "running" and isinstance(task_ledger, dict):
        active = next((item for item in task_ledger.get("tasks", []) if isinstance(item, dict) and item.get("status") == "running"), None)
        if active:
            phase = str(active.get("phase", "unknown"))
            print(f"- Active phase: {phase} ({active.get('id', 'unknown')})")
            try:
                updated = datetime.fromisoformat(str(active.get("updated_at", "")).replace("Z", "+00:00"))
                age = max(0, int((datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds()))
                print(f"- Active phase age: {age}s")
                if isinstance(audit_context, dict) and audit_context.get("scan_base") == str(scan):
                    configured = audit_context.get("orchestration", {}).get("phase_timeout_seconds", {}).get(phase)
                    if isinstance(configured, dict):
                        configured = configured.get(audit_context.get("depth"))
                    if isinstance(configured, int):
                        print(f"- Active phase deadline: {configured}s ({'exceeded' if age > configured else 'within limit'})")
            except (TypeError, ValueError):
                pass
for item in phases:
    print(f"- {item['phase']}: {item['status']}")
if summary:
    print(f"- Findings: {summary.get('total', 'unknown')} total")
    counts = [
        f"{key}={summary.get(key)}"
        for key in ("critical", "high", "medium", "low", "informational", "info")
        if key in summary
    ]
    if counts:
        print(f"- Severity: {', '.join(counts)}")
print(f"- Final report: {rel(report_md)}")
print(f"- JSON report: {rel(report_json)}")
print(f"- Intrusion results: {rel(intrusion_results)}")
if validation.returncode == 0:
    print("- Validation: ok")
else:
    print("- Validation: failed")
    details = (validation.stderr or validation.stdout).strip()
    if details:
        for line in details.splitlines()[:20]:
            print(f"  {line}")

raise SystemExit(0 if complete else 1)
PY
