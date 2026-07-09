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
commands_run = []
seen_nodes = set()

def add_node(node_id, kind, role, **extra):
    node_id = str(node_id)
    key = (node_id, kind, role)
    if key in seen_nodes:
        return
    seen_nodes.add(key)
    node = {"id": node_id, "kind": kind, "role": role}
    node.update({k: v for k, v in extra.items() if v is not None})
    nodes.append(node)

add_node(target, "file", "source")

# Run `codegraph affected <target> --json` (best signal for blast radius).
affected_argv = [bin_path, "affected", target, "--json"]
try:
    affected = subprocess.run(
        affected_argv,
        capture_output=True, text=True, timeout=30, check=False,
    )
    commands_run.append({"argv": ["codegraph", "affected", "<target>", "--json"], "exit_code": affected.returncode})
except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
    print(json.dumps({
        "nodes": nodes, "edges": edges,
        "source": "codegraph", "target": target, "depth": depth,
        "commands_run": [{"argv": ["codegraph", "affected", "<target>", "--json"], "error": type(exc).__name__}],
        "note": f"affected exec error: {type(exc).__name__}",
    }))
    raise SystemExit(0)

try:
    parsed = json.loads(affected.stdout) if affected.stdout.strip() else {}
except json.JSONDecodeError:
    parsed = {}

if isinstance(parsed, dict):
    for path in parsed.get("changedFiles", []) or []:
        add_node(path, "file", "affected")
        edges.append({"from": target, "to": path, "kind": "blast-radius"})
    for path in parsed.get("affectedTests", []) or []:
        add_node(path, "file", "test")
        edges.append({"from": target, "to": path, "kind": "affected-test"})

# Also run `codegraph node <target> --file` for in-file symbol map (best
# effort; this gives the agent the call graph anchored at the file).
node_argv = [bin_path, "node", target, "--file", target, "--symbols-only"]
try:
    node = subprocess.run(
        node_argv,
        capture_output=True, text=True, timeout=20, check=False,
    )
    commands_run.append({"argv": ["codegraph", "node", "<target>", "--file", "<target>", "--symbols-only"], "exit_code": node.returncode})
except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
    commands_run.append({"argv": ["codegraph", "node", "<target>", "--file", "<target>", "--symbols-only"], "error": type(exc).__name__})
    node = None
if node is not None and node.returncode == 0:
    for line in node.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(prefix in line for prefix in ("function ", "class ", "method ", "import ")):
            add_node(line, "symbol", "in_file")
            edges.append({"from": target, "to": line, "kind": "defines"})

note = "" if len(nodes) > 1 or edges else "no affected files found"
print(json.dumps({
    "nodes": nodes, "edges": edges,
    "source": "codegraph", "target": target, "depth": depth,
    "commands_run": commands_run,
    "note": note,
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
commands_run = []
seen_callers = set()

try:
    res = subprocess.run(
        [bin_path, "callers", symbol, "--json"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    commands_run.append({"argv": ["codegraph", "callers", "<symbol>", "--json"], "exit_code": res.returncode})
except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
    print(json.dumps({
        "nodes": nodes, "edges": edges,
        "source": "codegraph", "target": symbol,
        "commands_run": [{"argv": ["codegraph", "callers", "<symbol>", "--json"], "error": type(exc).__name__}],
        "note": f"callers exec error: {type(exc).__name__}",
    }))
    raise SystemExit(0)

raw = res.stdout.strip()
callers = []
# Real JSON list (rare): `[{"name": "..."}]` or `[{"symbol": "..."}]`.
# Friendly message: `Symbol "..." not found` — treat as no callers.
if raw.startswith("["):
    try:
        arr = json.loads(raw)
        if isinstance(arr, list):
            for item in arr:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("symbol") or item.get("id")
                    file_path = item.get("file") or item.get("path")
                    line = item.get("line")
                    if name:
                        callers.append({"id": str(name), "file": file_path, "line": line})
                elif isinstance(item, str):
                    callers.append({"id": item})
    except json.JSONDecodeError:
        callers = []

# The upstream sometimes emits a flat "file:line caller-name" or
# "caller-name @ file:line" form. If so, the JSON path above is empty;
# try a regex extraction so the agent still gets a usable signal.
if not callers and raw:
    import re
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")
    loc_re = re.compile(r"^(?P<file>[^:\s]+):(?P<line>\d+)\s+(?P<name>\S+)")
    for line_text in raw.splitlines():
        stripped = ansi_re.sub("", line_text).strip()
        if not stripped:
            continue
        low = stripped.lower()
        if "not found" in low or stripped.startswith("ℹ") or stripped.startswith("✓") or stripped.startswith("✗"):
            continue
        match = loc_re.match(stripped)
        if match:
            caller = {
                "id": match.group("name"),
                "file": match.group("file"),
                "line": int(match.group("line")),
            }
        else:
            first = stripped.split()[0] if stripped.split() else ""
            caller = {"id": f"{first} ({stripped})"} if first and first != symbol else None
        if caller:
            callers.append(caller)

for caller in callers:
    caller_id = str(caller.get("id", ""))
    if not caller_id or caller_id in seen_callers:
        continue
    seen_callers.add(caller_id)
    node = {"id": caller_id, "kind": "symbol", "role": "caller"}
    if caller.get("file") is not None:
        node["file"] = caller["file"]
    if caller.get("line") is not None:
        node["line"] = caller["line"]
    nodes.append(node)
    edges.append({"from": caller_id, "to": symbol, "kind": "calls"})

note = "" if callers else "no callers found"
print(json.dumps({
    "nodes": nodes, "edges": edges,
    "source": "codegraph", "target": symbol,
    "commands_run": commands_run,
    "note": note,
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
