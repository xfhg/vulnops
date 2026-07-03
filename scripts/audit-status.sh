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
from pathlib import Path

root = Path(sys.argv[1]).resolve()
scan = Path(sys.argv[2]).resolve()

phase_dirs = [
    ("recon", "repo-context"),
    ("sca", "sca"),
    ("secrets", "secrets"),
    ("sast", "sast"),
    ("intelligence", "intelligence"),
    ("triage", "triage"),
    ("intrusion", "intrusion"),
    ("final-reconciliation", "final-reconciliation"),
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
enrichment = scan / "intrusion" / "enrichment.json"
summary = {}
report = load_json(report_json)
if isinstance(report, dict) and isinstance(report.get("summary"), dict):
    summary = report["summary"]

complete = validation.returncode == 0 and all(item["status"] == "ok" for item in phases)

print("Audit Status")
print(f"- Scan: {rel(scan)}")
print(f"- State: {'complete' if complete else 'not complete'}")
for item in phases:
    print(f"- {item['phase']}: {item['status']}")
if summary:
    print(f"- Findings: {summary.get('total', 'unknown')} total")
    counts = [
        f"{key}={summary.get(key)}"
        for key in ("critical", "high", "medium", "low", "info")
        if key in summary
    ]
    if counts:
        print(f"- Severity: {', '.join(counts)}")
print(f"- Final report: {rel(report_md)}")
print(f"- JSON report: {rel(report_json)}")
print(f"- Intrusion enrichment: {rel(enrichment)}")
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
