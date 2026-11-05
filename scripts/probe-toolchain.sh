#!/usr/bin/env bash
# Functional readiness probe for every audit-runtime binary and adapter.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
MODE="${1:---live}"
case "$MODE" in
    --live|--offline) ;;
    *) echo "usage: probe-toolchain.sh [--live|--offline]" >&2; exit 2 ;;
esac
PROBE="${HARNESS_ROOT}/.harness/probes/toolchain"
rm -rf "$PROBE"
mkdir -p "$PROBE/source"

if [ "$MODE" = "--offline" ]; then
    bash "${HARNESS_ROOT}/scripts/jail.sh" "${HARNESS_ROOT}/bins/omp" --help >/dev/null
    echo "[probe-toolchain] offline local OMP check only; live lifecycle not checked"
else
    python3 "${HARNESS_ROOT}/scripts/probe-omp-lifecycle.py"
fi

python3 "${HARNESS_ROOT}/scripts/dependency_contract.py" go.mod package-lock.json
if python3 "${HARNESS_ROOT}/scripts/dependency_contract.py" go.sum package.json >/dev/null 2>&1; then
    echo "[probe-toolchain] dependency contract accepted unsupported inputs" >&2
    exit 1
fi

printf '%s\n' 'module vulnops-probe' 'go 1.22' 'require golang.org/x/crypto v0.26.0' >"${PROBE}/source/go.mod"
printf '%s\n' 'golang.org/x/crypto v0.26.0 h1:RrRspgV4mU+YwB4FYnuBoKsUapNIL5cohGAmSH3azsw=' >"${PROBE}/source/go.sum"
bash "${HARNESS_ROOT}/scripts/run-wraith.sh" "${PROBE}/source" "${PROBE}/source/go.mod" "${PROBE}/wraith.json" "${PROBE}/wraith-receipt.json"

printf 'token = "ghp_%s%s"\n' '0123456789ABCDEFGHIJ' 'KLMNOPQRSTUVWXYZ' >"${PROBE}/source/secret-fixture.txt"
bash "${HARNESS_ROOT}/scripts/run-poltergeist.sh" "${PROBE}/source" "${PROBE}/poltergeist.json" "${PROBE}/poltergeist-receipt.json"

# Keep the probe PID as the shared supervisor's caller so cancellation cannot
# strand a preparation child behind a waiting shell.
exec python3 - "$HARNESS_ROOT" "$PROBE" "$MODE" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

harness = Path(sys.argv[1])
root = Path(sys.argv[2])
mode = sys.argv[3]
sys.path.insert(0, str(harness / "scripts"))
from codegraph_setup import OPTIONAL_FAILURE, run_setup_command

limitation = ""
if os.environ.get("VULNOPS_CODEGRAPH_MODE", "enabled") == "enabled":
    (root / "source/main.go").write_text("package main\nfunc helper() {}\nfunc main() { helper() }\n")
    graph_probe = root / "codegraph-probe"
    graph_probe.mkdir(exist_ok=True)
    if not os.access(harness / "bins/codegraph", os.X_OK):
        limitation = "Codegraph binary is unavailable; graph-assisted coverage was not performed."
    else:
        result = run_setup_command(["bash", str(harness / "scripts/setup-codegraph.sh")],
            env={**os.environ, "CODEGRAPH_TARGET_DIR": str(root / "source"),
                 "CODEGRAPH_RUNTIME_DIR": str(root / "codegraph")})
        if result == OPTIONAL_FAILURE:
            limitation = "Codegraph preparation probe failed; graph-assisted coverage was not performed."
        elif result:
            raise SystemExit(result)
        else:
            query = subprocess.run([sys.executable, str(harness / "scripts/codegraph-adapter.py"),
                "--probe", "callers", "helper", "--project", str(root / "codegraph/project"),
                "--output", str(graph_probe / "context.json"), "--receipt", str(graph_probe / "receipt.json")],
                check=False)
            if query.returncode:
                limitation = "Codegraph query probe failed; graph-assisted coverage was not performed."
            else:
                try:
                    doc = json.loads((graph_probe / "receipt.json").read_text())
                    if (doc.get("status") != "ok" or doc.get("parse_status") != "ok"
                            or not doc.get("meaningful") or (doc.get("binding") or {}).get("phase") != "probe"
                            or doc.get("normalized_sha256") != hashlib.sha256((graph_probe / "context.json").read_bytes()).hexdigest()):
                        raise ValueError("Codegraph functional receipt is unhealthy or lacks probe integrity")
                except (OSError, ValueError, AttributeError):
                    limitation = "Codegraph probe evidence is unusable; graph-assisted coverage was not performed."
if limitation:
    (root / "codegraph-limitation.txt").write_text(limitation + "\n")
    print(f"[probe-toolchain] WARN: {limitation} Continuing source-only.", file=sys.stderr)

names=["wraith-receipt.json","poltergeist-receipt.json"]
for name in names:
    doc=json.loads((root/name).read_text())
    if doc.get("status")!="ok" or doc.get("parse_status")!="ok":
        raise SystemExit(f"unhealthy functional receipt: {name}")
    if name.startswith("wraith") and doc.get("result_count",0)<1:
        raise SystemExit("Wraith functional probe did not return its expected offline advisory fixture")
    if name.startswith("poltergeist") and doc.get("result_count",0)<1:
        raise SystemExit("Poltergeist functional probe did not return its expected synthetic fixture")
secrets=json.loads((root/"poltergeist.json").read_text())
if any(item.get("redaction")!="<redacted>" for item in secrets.get("candidates",[])):
    raise SystemExit("Poltergeist functional output is not exactly redacted")
print(f"[probe-toolchain] {mode.removeprefix('--')} functional probes passed")
PY
