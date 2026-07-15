#!/usr/bin/env bash
# Build a run-local immutable snapshot before invoking codegraph. The upstream
# CLI writes .codegraph beneath the indexed project, so target/ is never used.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

CODEGRAPH_BIN="${HARNESS_ROOT}/bins/codegraph"
SOURCE="${CODEGRAPH_TARGET_DIR:-}"
RUNTIME="${CODEGRAPH_RUNTIME_DIR:-}"

if [ ! -x "$CODEGRAPH_BIN" ]; then
    echo "[setup-codegraph] codegraph is unavailable" >&2
    exit 1
fi
if [ -z "$SOURCE" ] || [ ! -d "$SOURCE" ]; then
    echo "[setup-codegraph] CODEGRAPH_TARGET_DIR must be a readable directory" >&2
    exit 1
fi
if [ -z "$RUNTIME" ]; then
    echo "[setup-codegraph] CODEGRAPH_RUNTIME_DIR is required" >&2
    exit 1
fi
harness_require_inside_root "$HARNESS_ROOT" "$SOURCE" "codegraph source"
harness_require_inside_root "$HARNESS_ROOT" "$RUNTIME" "codegraph runtime"

PROJECT="${RUNTIME}/project"
RECEIPT="${RUNTIME}/index-receipt.json"
mkdir -p "$RUNTIME"

python3 - "$SOURCE" "$PROJECT" <<'PY'
from __future__ import annotations
import os
import shutil
import sys
from pathlib import Path

source = Path(sys.argv[1]).resolve()
project = Path(sys.argv[2]).resolve()
if project.exists():
    shutil.rmtree(project)
project.mkdir(parents=True)
excluded = {".git", ".codegraph", ".harness"}
for root, dirs, files in os.walk(source, followlinks=False):
    symlink_dirs = sorted(d for d in dirs if (Path(root) / d).is_symlink())
    dirs[:] = sorted(d for d in dirs if d not in excluded and d not in symlink_dirs)
    rel_root = Path(root).relative_to(source)
    for name in [*symlink_dirs, *sorted(files)]:
        src = Path(root) / name
        if name in excluded:
            continue
        dst = project / rel_root / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            try:
                resolved = src.resolve(strict=True)
                relative_target = resolved.relative_to(source)
            except (OSError, ValueError) as exc:
                raise SystemExit(f"refusing repository symlink that is broken or escapes the target: {src}: {exc}")
            mapped_target = project / relative_target
            os.symlink(os.path.relpath(mapped_target, dst.parent), dst, target_is_directory=resolved.is_dir())
        else:
            shutil.copy2(src, dst)
PY

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status="ok"
message=""
if ! "$CODEGRAPH_BIN" init "$PROJECT" >/dev/null 2>&1; then
    status="failed"
    message="codegraph init failed"
fi
completed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
version="$($CODEGRAPH_BIN --version 2>/dev/null | head -n 1 || true)"
python3 - "$RECEIPT" "$status" "$version" "$started" "$completed" "$message" <<'PY'
import json, sys
from pathlib import Path
path, status, version, started, completed, message = sys.argv[1:]
doc = {
    "schema_version": "2.0", "tool": "codegraph", "operation": "index",
    "status": status, "version": version or "unknown", "started_at": started,
    "completed_at": completed, "parse_status": "not_applicable",
    "result_count": 0, "normalized_sha256": None,
    "warnings": [] if status == "ok" else [message],
}
Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY
if [ "$status" != "ok" ]; then
    echo "[setup-codegraph] ${message}" >&2
    exit 1
fi
echo "[setup-codegraph] indexed immutable snapshot at ${PROJECT}"
