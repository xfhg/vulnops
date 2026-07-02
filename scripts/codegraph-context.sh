#!/usr/bin/env bash
# codegraph-context.sh — narrow helper exposing codegraph outputs as JSON.
#
# Subcommands:
#   blast-radius <file> [depth=2]
#       Maps to `codegraph affected <file> --json` — returns the set of
#       files affected by changes to the given file. Emits a stable
#       {nodes:[...], edges:[...], source:"codegraph"} JSON shape on stdout.
#       depth is currently ignored (upstream doesn't expose a numeric depth
#       knob; the caller's value is preserved in the emitted payload for
#       future use).
#
#   calls-of <symbol>
#       Maps to `codegraph callers <symbol> --json` — returns who calls a
#       given symbol. Emits the same stable JSON shape.
#
# Both subcommands are non-fatal on empty results — they emit a stub so
# the agent can decide to grep instead. Telemetry is off (inherited from
# harness-lib.sh). Any ${HOME} or .harness path is redacted from output.
#
# Exit codes:
#   0 — JSON emitted (even if the result set is empty)
#   64 — invalid usage

set -uo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

CODEGRAPH_BIN="${HARNESS_ROOT}/bins/codegraph"
PYTHON="$(command -v python3)"

# Ensure telemetry is off even if the caller exported it back on. The
# binary reads this every invocation; setting it here is belt-and-braces.
export CODEGRAPH_TELEMETRY=0
export CODEGRAPH_NO_DAEMON=1

redact() {
    sed -e "s|${HOME}|<HOME>|g" -e "s|${HARNESS_ROOT}/.harness|<HARNESS>|g" -e "s|${HARNESS_ROOT}/target|<TARGET>|g"
}

empty_context() {
    local note="$1"
    cat <<EOF
{"nodes":[],"edges":[],"source":"codegraph","note":"${note}"}
EOF
}

usage() {
    cat <<EOF >&2
Usage: $0 <blast-radius <file> [depth] | calls-of <symbol>>
EOF
    exit 64
}

if [ ! -x "${CODEGRAPH_BIN}" ]; then
    empty_context "codegraph not installed"
    exit 0
fi

cmd="${1:-}"
shift || true
case "${cmd}" in
    "") usage ;;
    blast-radius)
        target="${1:-}"
        depth="${2:-2}"
        if [ -z "${target}" ]; then
            empty_context "missing file argument"
            exit 0
        fi
        if "${PYTHON}" - "${target}" "${depth}" "${CODEGRAPH_BIN}" 2>/dev/null <<'PYEOF' | redact
import json
import subprocess
import sys

target = sys.argv[1]
try:
    depth = int(sys.argv[2])
except (TypeError, ValueError):
    depth = 2
bin_path = sys.argv[3]

nodes = []
edges = []

# Run `codegraph affected <target> --json` (best signal for blast radius)
try:
    affected = subprocess.run(
        [bin_path, "affected", target, "--json"],
        capture_output=True, text=True, timeout=30, check=False,
    )
except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
    print(json.dumps({
        "nodes": [], "edges": [],
        "source": "codegraph", "depth": depth,
        "note": f"affected exec error: {type(exc).__name__}",
    }))
    raise SystemExit(0)

try:
    parsed = json.loads(affected.stdout) if affected.stdout.strip() else {}
except json.JSONDecodeError:
    parsed = {}

if isinstance(parsed, dict):
    for path in parsed.get("changedFiles", []) or []:
        nodes.append({"id": path, "kind": "file", "role": "affected"})
    for path in parsed.get("affectedTests", []) or []:
        nodes.append({"id": path, "kind": "file", "role": "test"})

# Also run `codegraph node <target> --file` for in-file symbol map (best
# effort; this gives the agent the call graph anchored at the file).
try:
    node = subprocess.run(
        [bin_path, "node", target, "--file", target, "--symbols-only"],
        capture_output=True, text=True, timeout=20, check=False,
    )
except (FileNotFoundError, subprocess.TimeoutExpired):
    node = None
if node is not None and node.returncode == 0:
    for line in node.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(prefix in line for prefix in ("function ", "class ", "method ", "import ")):
            nodes.append({"id": line, "kind": "symbol", "role": "in_file"})

note = "" if nodes else "no affected files found"
print(json.dumps({
    "nodes": nodes, "edges": edges,
    "source": "codegraph", "depth": depth, "note": note,
}))
PYEOF
        then
            :
        else
            empty_context "codegraph blast-radius failed"
        fi
        ;;

    calls-of)
        symbol="${1:-}"
        if [ -z "${symbol}" ]; then
            empty_context "missing symbol argument"
            exit 0
        fi
        if "${PYTHON}" - "${symbol}" "${CODEGRAPH_BIN}" 2>/dev/null <<'PYEOF' | redact
import json
import subprocess
import sys

symbol = sys.argv[1]
bin_path = sys.argv[2]

nodes = [{"id": symbol, "kind": "symbol", "role": "target"}]
edges = []

try:
    res = subprocess.run(
        [bin_path, "callers", symbol, "--json"],
        capture_output=True, text=True, timeout=30, check=False,
    )
except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
    print(json.dumps({
        "nodes": nodes, "edges": edges,
        "source": "codegraph", "note": f"callers exec error: {type(exc).__name__}",
    }))
    raise SystemExit(0)

raw = res.stdout.strip()
callers = []
# Real JSON list (rare): `[{"name": "..."}]` or `[{"symbol": "..."}]`
# Friendly message: `Symbol "..." not found` — treat as no callers.
if raw.startswith("["):
    try:
        arr = json.loads(raw)
        if isinstance(arr, list):
            for item in arr:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("symbol") or item.get("id")
                    if name:
                        callers.append(name)
                elif isinstance(item, str):
                    callers.append(item)
    except json.JSONDecodeError:
        callers = []

# The upstream sometimes emits a flat "file:line caller-name" or
# "caller-name @ file:line" form. If so, the JSON path above is empty;
# try a regex extraction so the agent still gets a usable signal.
# Fallback regex pass: strip ANSI escape codes, drop info lines and the
# "not found" friendly message, then take the first token of each
# remaining line as a caller name. With these filters the "Symbol X not
# found" output becomes an empty callers list (which the JSON shape
# already handles cleanly).
if not callers and raw:
    import re
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")
    for line in raw.splitlines():
        stripped = ansi_re.sub("", line).strip()
        if not stripped:
            continue
        low = stripped.lower()
        if "not found" in low or stripped.startswith("ℹ") or stripped.startswith("✓") or stripped.startswith("✗"):
            continue
        first = stripped.split()[0] if stripped.split() else ""
        if first and first != symbol:
            callers.append(f"{first} ({stripped})")

for c in callers:
    edges.append({"from": c, "to": symbol, "kind": "calls"})

note = "" if callers else "no callers found"
print(json.dumps({
    "nodes": nodes, "edges": edges,
    "source": "codegraph", "note": note,
}))
PYEOF
        then
            :
        else
            empty_context "codegraph calls-of failed"
        fi
        ;;

    *)
        usage
        ;;
esac
