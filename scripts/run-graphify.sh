#!/usr/bin/env bash
# run-graphify.sh — Build code knowledge graph using graphify.
# Handles: config sourcing, env var setup, tool discovery, LLM fallback.
#
# Usage: bash scripts/run-graphify.sh <repo_path> <output_dir>
# Output: graph.json in <output_dir>/graphify-out/
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <repo_path> <output_dir>" >&2
    exit 1
fi

REPO_PATH="$1"
OUTPUT_DIR="$2"
harness_require_inside_root "$HARNESS_ROOT" "$REPO_PATH" "repo path"
harness_require_allowed_output "$HARNESS_ROOT" "$OUTPUT_DIR"

# Source config if env vars not already set
if [ -z "${ON_PREM_LLM_BASE_URL:-}" ]; then
    if [ -f "${HARNESS_ROOT}/config.toml" ] && [ -x "${HARNESS_ROOT}/scripts/load-config.sh" ]; then
        eval "$("${HARNESS_ROOT}/scripts/load-config.sh")" 2>/dev/null || true
    fi
fi

# Find graphify
GRAPHIFY_CLI=""
GRAPHIFY_PY=""
if [ -x "${HARNESS_ROOT}/.venv/bin/graphify" ]; then
    GRAPHIFY_CLI="${HARNESS_ROOT}/.venv/bin/graphify"
    GRAPHIFY_PY="${HARNESS_ROOT}/.venv/bin/python"
elif command -v graphify &>/dev/null; then
    GRAPHIFY_CLI="$(command -v graphify)"
    GRAPHIFY_PY="$(head -1 "$GRAPHIFY_CLI" | sed 's/^#!//')"
fi

if [ -z "${GRAPHIFY_CLI}" ]; then
    echo '{"error":"graphify not installed","hint":"run: bash scripts/install-tools.sh"}' >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# Try LLM-enhanced extraction if endpoint is configured
if [ -n "${ON_PREM_LLM_BASE_URL:-}" ]; then
    export OLLAMA_BASE_URL="${ON_PREM_LLM_BASE_URL}"
    export OLLAMA_API_KEY="local"
    export OLLAMA_MODEL="${ON_PREM_MODEL_NAME:-default}"

    if "${GRAPHIFY_CLI}" extract "${REPO_PATH}" --backend ollama --out "${OUTPUT_DIR}" 2>/dev/null; then
        exit 0
    fi
    echo "[warn] LLM extraction failed, falling back to AST-only" >&2
fi

# AST-only fallback
"${GRAPHIFY_PY}" -c "
from graphify.extract import extract, collect_files
from graphify.detect import CODE_EXTENSIONS
from pathlib import Path
import json, sys

root = Path(sys.argv[1])
out = Path(sys.argv[2]) / 'graphify-out'
out.mkdir(parents=True, exist_ok=True)
files = [f for f in collect_files(root, follow_symlinks=True) if f.suffix in CODE_EXTENSIONS]
if not files:
    print('No code files found', file=sys.stderr); sys.exit(1)
result = extract(files)
(out / 'graph.json').write_text(json.dumps(result, indent=2))
print(f'AST extraction: {len(result[\"nodes\"])} nodes, {len(result[\"edges\"])} edges')
" "${REPO_PATH}" "${OUTPUT_DIR}"
