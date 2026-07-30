#!/usr/bin/env bash
# Verify and configure an extracted VulnOps offline package without downloading.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
COMMAND="${1:-}"
cd "$HARNESS_ROOT"

log() { echo "[setup] $*"; }
die() { echo "[setup] ERROR: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage:
  bash setup.sh verify
  bash setup.sh login [provider]
  bash setup.sh configure

verify     Validate the immutable package, bundled tools and libraries, OSV
           snapshot, Python, platform, and relocatability.
login      Authenticate OMP to an OAuth-backed LLM provider inside this
           installation. Defaults to the provider in llm.selector.
configure  Re-run verification, generate harness-local OMP state, and validate
           the configured LLM/runtime without downloading anything.
EOF
}

login_provider=""
case "$COMMAND" in
    verify|configure)
        [ "$#" -eq 1 ] || die "unexpected setup arguments"
        ;;
    login)
        [ "$#" -le 2 ] || die "login accepts at most one provider"
        login_provider="${2:-}"
        ;;
    "") usage; exit 64 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown command: $COMMAND" ;;
esac

detect_platform() {
    local os_name machine
    os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64) machine="amd64" ;;
        aarch64|arm64) machine="arm64" ;;
        *) die "unsupported host architecture: $machine" ;;
    esac
    printf '%s_%s\n' "$os_name" "$machine"
}

platform="$(detect_platform)"
case "$platform" in
    linux_amd64|darwin_arm64) ;;
    *) die "unsupported package host: $platform" ;;
esac

python_bin="$(command -v python3 2>/dev/null || true)"
[ -n "$python_bin" ] || die "system Python 3.11 or newer is required"
"$python_bin" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
    || die "system Python 3.11 or newer is required"

manifest="${HARNESS_ROOT}/offline-pack-manifest.json"
tool_lock="${HARNESS_ROOT}/config/offline-pack.${platform}.lock.json"
osv_lock="${HARNESS_ROOT}/config/osv-snapshot.lock.json"
config="${HARNESS_ROOT}/config.toml"
[ -f "$manifest" ] || die "offline package manifest is missing"
[ -f "$tool_lock" ] || die "platform tool lock is missing: $tool_lock"
[ -f "$osv_lock" ] || die "OSV snapshot lock is missing"
[ -f "$config" ] || die "config.toml is missing"

if [ "$(uname -s)" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
    xattr -dr com.apple.quarantine "$HARNESS_ROOT" 2>/dev/null || true
    xattr -dr com.apple.provenance "$HARNESS_ROOT" 2>/dev/null || true
fi

log "verifying complete immutable package inventory"
verification="$("$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" verify-manifest "$HARNESS_ROOT" "$manifest")"
"$python_bin" - "$manifest" "$platform" <<'PY' || die "offline package platform does not match this host"
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(document.get("platform") != sys.argv[2])
PY
"$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" validate-tool-lock "$tool_lock" --platform "$platform"

for binary in omp wraith poltergeist osv-scanner codegraph; do
    [ -x "${HARNESS_ROOT}/bins/${binary}" ] || die "bundled executable is missing: bins/${binary}"
    marker="${HARNESS_ROOT}/bins/.${binary}.version"
    [ -f "$marker" ] || die "bundled version marker is missing: bins/.${binary}.version"
    expected="$("$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" tool-field "$tool_lock" "$binary" version)"
    actual="$(sed -n '1p' "$marker")"
    [ "$actual" = "$expected" ] || die "${binary} marker ${actual:-missing} does not match lock ${expected}"
    "${HARNESS_ROOT}/bins/${binary}" --version >/dev/null 2>&1 \
        || die "bundled ${binary} cannot execute its version probe"
done

for binary in omp osv-scanner; do
    expected_sha="$("$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" tool-field "$tool_lock" "$binary" sha256)"
    expected_size="$("$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" tool-field "$tool_lock" "$binary" size)"
    "$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" verify-asset \
        "${HARNESS_ROOT}/bins/${binary}" "$expected_size" "$expected_sha"
done
runtime_version="$("$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" runtime-field "$tool_lock" omp-natives version)"
[ "$(sed -n '1p' "${HARNESS_ROOT}/bins/.omp-natives.version" 2>/dev/null || true)" = "$runtime_version" ] \
    || die "OMP native runtime marker is missing or does not match the lock"
"$python_bin" "${HARNESS_ROOT}/scripts/offline_package.py" verify-runtime-install \
    "$tool_lock" omp-natives "${HARNESS_ROOT}/bins"

if grep -E -q '/tmp/|/private/var/|/home/.*/bins/codegraph-bundle' "${HARNESS_ROOT}/bins/codegraph"; then
    die "Codegraph launcher contains an absolute build path"
fi
CODEGRAPH_NO_DOWNLOAD=1 "${HARNESS_ROOT}/bins/codegraph" --version >/dev/null

mkdir -p "${HARNESS_ROOT}/.harness"
omp_smoke_home="$(mktemp -d "${HARNESS_ROOT}/.harness/omp-smoke.XXXXXX")"
if ! HOME="$omp_smoke_home" PI_CODING_AGENT_DIR="${omp_smoke_home}/.omp" \
    "${HARNESS_ROOT}/bins/omp" --no-extensions \
    --help >/dev/null 2>&1; then
    rm -rf "$omp_smoke_home"
    die "OMP cannot start from the bundled native runtime without provisioning"
fi
rm -rf "$omp_smoke_home"

log "verifying every locked OSV ecosystem database"
"$python_bin" "${HARNESS_ROOT}/scripts/osv_snapshot.py" verify \
    --lock "$osv_lock" \
    --cache-root "${HARNESS_ROOT}/.harness/osv-db"

IFS=$'\t' read -r network_mode reproduction_mode < <("$python_bin" - "$config" <<'PY'
import sys, tomllib
from pathlib import Path
with Path(sys.argv[1]).open("rb") as handle:
    config = tomllib.load(handle)
print("\t".join([
    str(config.get("harness", {}).get("network", {}).get("linux_agent_egress", "enforced")),
    str(config.get("harness", {}).get("reproduction", {}).get("mode", "off")),
]))
PY
)
log "package verification complete (${platform}; runtime policy is config-driven)"

if [ "$COMMAND" = "login" ]; then
    if [ -z "$login_provider" ]; then
        login_provider="$("$python_bin" - "$config" <<'PY'
import sys, tomllib
from pathlib import Path
with Path(sys.argv[1]).open("rb") as handle:
    selector = str(tomllib.load(handle).get("llm", {}).get("selector", ""))
provider, separator, _ = selector.partition("/")
if not separator or not provider:
    raise SystemExit("llm.selector must use provider/model syntax")
print(provider)
PY
        )" || die "cannot derive the login provider from llm.selector"
    fi
    [[ "$login_provider" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
        || die "invalid OMP login provider: $login_provider"
    # Store OAuth state beneath this installation's mutable .harness directory.
    # No credentials are copied from or written to the immutable package.
    # shellcheck source=scripts/harness-lib.sh
    source "${HARNESS_ROOT}/scripts/harness-lib.sh"
    harness_setup_containment "$HARNESS_ROOT"
    bash "${HARNESS_ROOT}/scripts/bootstrap-omp.sh"
    log "starting OMP login for ${login_provider}; no harness dependencies will be downloaded"
    exec "${HARNESS_ROOT}/bins/omp" auth-broker login "$login_provider"
fi

if [ "$COMMAND" = "configure" ]; then
    log "generating harness-local OMP configuration"
    bash "${HARNESS_ROOT}/scripts/bootstrap-omp.sh"
    bash "${HARNESS_ROOT}/scripts/validate-config.sh"
    mkdir -p "${HARNESS_ROOT}/.harness"
    "$python_bin" - "$manifest" "$verification" "$network_mode" "$reproduction_mode" "${HARNESS_ROOT}/.harness/offline-install.json" <<'PY'
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path
manifest, verification, network, reproduction, output = sys.argv[1:]
document = {
    "schema": "vulnops.offline-install.v3",
    "verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "manifest": json.loads(verification),
    "manifest_path": str(Path(manifest).resolve()),
    "network_mode": network,
    "reproduction_mode": reproduction,
    "runtime_policy": "configured",
}
path = Path(output)
temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
temporary.replace(path)
PY
    log "configuration complete; no downloads were performed"
fi
