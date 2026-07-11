#!/usr/bin/env bash
# Functional readiness probe for every audit-runtime binary and adapter.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
PROBE="${HARNESS_ROOT}/.harness/probes/toolchain"
rm -rf "$PROBE"
mkdir -p "$PROBE/source"

bash "${HARNESS_ROOT}/scripts/jail.sh" "${HARNESS_ROOT}/bins/omp" --help >/dev/null

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

printf '%s\n' 'package main' 'func helper() {}' 'func main() { helper() }' >"${PROBE}/source/main.go"
CODEGRAPH_TARGET_DIR="${PROBE}/source" CODEGRAPH_RUNTIME_DIR="${PROBE}/codegraph" bash "${HARNESS_ROOT}/scripts/setup-codegraph.sh" >/dev/null
mkdir -p "${PROBE}/codegraph-probe"
python3 "${HARNESS_ROOT}/scripts/codegraph-adapter.py" callers helper --project "${PROBE}/codegraph/project" --output "${PROBE}/codegraph-probe/context.json" --receipt "${PROBE}/codegraph-probe/receipt.json"

python3 - "$PROBE" <<'PY'
import json, sys
from pathlib import Path
root=Path(sys.argv[1])
for name in ("wraith-receipt.json","poltergeist-receipt.json","codegraph-probe/receipt.json"):
    doc=json.loads((root/name).read_text())
    if doc.get("status")!="ok" or doc.get("parse_status")!="ok":
        raise SystemExit(f"unhealthy functional receipt: {name}")
    if name.startswith("wraith") and doc.get("result_count",0)<1:
        raise SystemExit("Wraith functional probe did not return its expected offline advisory fixture")
    if name.startswith("poltergeist") and doc.get("result_count",0)<1:
        raise SystemExit("Poltergeist functional probe did not return its expected synthetic fixture")
    if name.startswith("codegraph") and not doc.get("meaningful"):
        raise SystemExit("codegraph functional probe did not return a real relationship")
    if name.startswith("codegraph"):
        import hashlib
        if doc.get("normalized_sha256") != hashlib.sha256((root/"codegraph-probe/context.json").read_bytes()).hexdigest():
            raise SystemExit("codegraph functional receipt hash mismatch")
secrets=json.loads((root/"poltergeist.json").read_text())
if any(item.get("redaction")!="<redacted>" for item in secrets.get("candidates",[])):
    raise SystemExit("Poltergeist functional output is not exactly redacted")
PY
echo "[probe-toolchain] functional probes passed"
