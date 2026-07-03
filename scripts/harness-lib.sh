#!/usr/bin/env bash
# Shared harness runtime helpers. Keep this file dependency-free: audit startup
# uses it before agents or language-specific tooling are available.

set -euo pipefail

harness_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

harness_setup_containment() {
    local root="${1:-$(harness_root)}"
    local hdir="${root}/.harness"

    mkdir -p \
        "${hdir}/tmp" \
        "${hdir}/cache" \
        "${hdir}/home" \
        "${hdir}/home/.omp/agent" \
        "${hdir}/home/.omp/config" \
        "${hdir}/logs" \
        "${root}/work" \
        "${root}/scans"

    export VULNOPSV3_ROOT="${root}"
    export VULNOPSV3_SCANS="${root}/scans"
    export VULNOPSV3_TARGET="${root}/target"
    export VULNOPSV3_WORK="${root}/work"
    export VULNOPSV3_HOME="${hdir}/home"

    export TMPDIR="${hdir}/tmp"
    export TMP="${hdir}/tmp"
    export TEMP="${hdir}/tmp"
    export XDG_CACHE_HOME="${hdir}/cache"
    export XDG_CONFIG_HOME="${hdir}/config"
    export XDG_DATA_HOME="${hdir}/data"
    export PIP_CACHE_DIR="${hdir}/cache/pip"
    export NPM_CONFIG_CACHE="${hdir}/cache/npm"
    export CARGO_HOME="${hdir}/cache/cargo"
    export GOMODCACHE="${hdir}/cache/go/pkg/mod"
    export GOCACHE="${hdir}/cache/go-build"
    export OMP_AGENT_HOME="${hdir}/home/.omp/agent"
    export PI_CODING_AGENT_DIR="${hdir}/home/.omp/agent"
    export PI_CONFIG_DIR="${hdir}/home/.omp"
    # codegraph runs offline-only; never phone home, never spawn a daemon
    export CODEGRAPH_TELEMETRY=0
    export CODEGRAPH_NO_DAEMON=1

    mkdir -p \
        "${XDG_CONFIG_HOME}" \
        "${XDG_DATA_HOME}" \
        "${PIP_CACHE_DIR}" \
        "${NPM_CONFIG_CACHE}" \
        "${CARGO_HOME}" \
        "${GOMODCACHE}" \
        "${GOCACHE}"

    # HOME is intentionally harness-local so agent/tool side effects do not
    # spill into the operator's user profile.
    export HOME="${VULNOPSV3_HOME}"
    export PATH="${root}/bins:${PATH}"
}

harness_path_is_inside_root() {
    local root="$1"
    local path="$2"
    local resolved_root
    local resolved_path

    resolved_root="$(cd "$root" && pwd -P)"
    if [ -e "$path" ]; then
        resolved_path="$(cd "$(dirname "$path")" && pwd -P)/$(basename "$path")"
    else
        resolved_path="$(cd "$(dirname "$path")" && pwd -P)/$(basename "$path")"
    fi

    case "$resolved_path" in
        "$resolved_root"|"$resolved_root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

harness_require_inside_root() {
    local root="$1"
    local path="$2"
    local label="${3:-path}"

    if ! harness_path_is_inside_root "$root" "$path"; then
        echo "[harness] ${label} escapes harness root: ${path}" >&2
        return 1
    fi
}

harness_require_allowed_output() {
    local root="$1"
    local path="$2"
    local resolved

    harness_require_inside_root "$root" "$path" "output path"
    resolved="$(cd "$(dirname "$path")" && pwd -P)/$(basename "$path")"

    case "$resolved" in
        "$root/scans"|"$root/scans"/*|\
        "$root/.harness"|"$root/.harness"/*|\
        "$root/work"|"$root/work"/*|\
        "$root/bins"|"$root/bins"/*)
            return 0
            ;;
        *)
            echo "[harness] output path is not an approved harness output area: ${path}" >&2
            return 1
            ;;
    esac
}
