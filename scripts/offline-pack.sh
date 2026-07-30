#!/usr/bin/env bash
# Build a deterministic, relocatable, integrity-checked offline release.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PACKAGE_TOOL="${HARNESS_ROOT}/scripts/offline_package.py"
CHUNK_SIZE_BYTES=$((45 * 1024 * 1024))
PLATFORM="linux_amd64"
OUTPUT=""
FORCE=false
ALLOW_DIRTY=false
INCLUDE_CONFIG=false

log() { echo "[pack] $*"; }
die() { echo "[pack] ERROR: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: scripts/offline-pack.sh [options]

Options:
  --platform <linux_amd64|darwin_arm64>
  --output <archive.tar.gz>
  --force
  --allow-dirty       Build a development artifact from tracked/untracked source
  --include-config    Include the local mutable config.toml (may contain secrets)
  --help
EOF
}

detect_platform() {
    local os_name machine
    os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64) machine="amd64" ;;
        aarch64|arm64) machine="arm64" ;;
        *) die "unsupported architecture: $machine" ;;
    esac
    printf '%s_%s\n' "$os_name" "$machine"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --platform) [ "$#" -ge 2 ] || die "--platform requires a value"; PLATFORM="$2"; shift 2 ;;
        --output) [ "$#" -ge 2 ] || die "--output requires a value"; OUTPUT="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        --allow-dirty) ALLOW_DIRTY=true; shift ;;
        --include-config) INCLUDE_CONFIG=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$PLATFORM" in
    linux_amd64|darwin_arm64) ;;
    *) die "unsupported platform: $PLATFORM" ;;
esac
[ "$(detect_platform)" = "$PLATFORM" ] || die "builds must run on the matching ${PLATFORM} host"

for command in git curl python3; do
    command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
    || die "Python 3.11 or newer is required"

source_state="release"
source_changes="$(git -C "$HARNESS_ROOT" status --porcelain --untracked-files=all -- \
    . \
    ':(exclude)offline/*/offline-pack-chunks.json' \
    ':(exclude)offline/*/*.part-*' \
    ':(exclude)vulnops-offline-*.tar.gz')"
if [ -n "$source_changes" ]; then
    if [ "$ALLOW_DIRTY" != true ]; then
        die "release builds require a clean worktree; use --allow-dirty only for development artifacts"
    fi
    source_state="development"
fi

commit="$(git -C "$HARNESS_ROOT" rev-parse HEAD)"
source_epoch="$(git -C "$HARNESS_ROOT" show -s --format=%ct HEAD)"
created_at="$(git -C "$HARNESS_ROOT" show -s --format=%cI HEAD)"
lock="${HARNESS_ROOT}/config/offline-pack.${PLATFORM}.lock.json"
osv_lock="${HARNESS_ROOT}/config/osv-snapshot.lock.json"
python3 "$PACKAGE_TOOL" validate-tool-lock "$lock" --platform "$PLATFORM"
[ -f "$osv_lock" ] || die "missing locked OSV snapshot: $osv_lock"

if [ -z "$OUTPUT" ]; then
    OUTPUT="${HARNESS_ROOT}/vulnops-offline-${PLATFORM//_/-}-${commit:0:12}.tar.gz"
fi
OUTPUT="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTPUT")"
[ "$FORCE" = true ] || [ ! -e "$OUTPUT" ] || die "output exists: $OUTPUT"
case "$OUTPUT" in
    "${HARNESS_ROOT}/offline/"*) die "archive output must not be inside offline/" ;;
esac

staging="$(mktemp -d)"
smoke_root="$(mktemp -d)"
build_output="${OUTPUT}.candidate.$$"
cleanup() {
    rm -rf "$staging" "$smoke_root"
    rm -f "$build_output"
}
trap cleanup EXIT

copy_candidate() {
    local relative="$1"
    case "$relative" in
        offline/*|bins/*|.git/*|.harness/*|target/*|scans/*|remediations/*|work/*) return ;;
        vulnops-offline-*.tar.gz|*.tar.gz.part-*) return ;;
    esac
    [ -e "${HARNESS_ROOT}/${relative}" ] || [ -L "${HARNESS_ROOT}/${relative}" ] || return
    mkdir -p "${staging}/$(dirname "$relative")"
    cp -pP "${HARNESS_ROOT}/${relative}" "${staging}/${relative}"
}

log "copying explicit source inventory"
while IFS= read -r relative; do
    copy_candidate "$relative"
done < <(git -C "$HARNESS_ROOT" ls-files)
if [ "$ALLOW_DIRTY" = true ]; then
    while IFS= read -r relative; do
        copy_candidate "$relative"
    done < <(git -C "$HARNESS_ROOT" ls-files --others --exclude-standard)
fi
# This generated file contains an installation-specific absolute shellPath.
# setup.sh configure regenerates it at the destination.
rm -f "${staging}/.omp/config.yml"

if [ "$INCLUDE_CONFIG" = true ]; then
    [ -f "${HARNESS_ROOT}/config.toml" ] || die "--include-config requested but config.toml is missing"
    cp "${HARNESS_ROOT}/config.toml" "${staging}/config.toml"
else
    cp "${staging}/config.toml.example" "${staging}/config.toml"
fi
python3 "$PACKAGE_TOOL" validate-package-config "${staging}/config.toml"

log "installing hash-locked platform tools"
bash "${staging}/scripts/install-tools.sh" --lock "${staging}/config/offline-pack.${PLATFORM}.lock.json" all

log "copying the pre-verified hash-locked OSV snapshot"
python3 "${HARNESS_ROOT}/scripts/osv_snapshot.py" verify \
    --lock "$osv_lock" --cache-root "${HARNESS_ROOT}/.harness/osv-db"
mkdir -p "${staging}/.harness"
cp -a "${HARNESS_ROOT}/.harness/osv-db" "${staging}/.harness/osv-db"
python3 "${staging}/scripts/osv_snapshot.py" verify \
    --lock "${staging}/config/osv-snapshot.lock.json" \
    --cache-root "${staging}/.harness/osv-db"

manifest="${staging}/offline-pack-manifest.json"
manifest_args=(
    create-manifest "$staging" "$manifest"
    --platform "$PLATFORM"
    --tool-lock "${staging}/config/offline-pack.${PLATFORM}.lock.json"
    --tool-lock-relative "config/offline-pack.${PLATFORM}.lock.json"
    --osv-lock "${staging}/config/osv-snapshot.lock.json"
    --osv-lock-relative "config/osv-snapshot.lock.json"
    --source-commit "$commit"
    --source-state "$source_state"
    --source-date-epoch "$source_epoch"
    --created-at "$created_at"
)
if [ "$INCLUDE_CONFIG" = true ]; then
    manifest_args+=(--live-config)
fi
python3 "$PACKAGE_TOOL" "${manifest_args[@]}"
python3 "$PACKAGE_TOOL" scan-path-leaks "$staging" "$staging"
python3 "$PACKAGE_TOOL" scan-path-leaks "$staging" "$HARNESS_ROOT"

log "creating normalized deterministic archive"
python3 "$PACKAGE_TOOL" create-archive "$staging" "$build_output" --source-date-epoch "$source_epoch"

log "extracting into a second path for release smoke tests"
python3 "$PACKAGE_TOOL" extract-tool "$build_output" "$smoke_root"
python3 "${smoke_root}/scripts/offline_package.py" verify-manifest \
    "$smoke_root" "${smoke_root}/offline-pack-manifest.json"
for binary in omp wraith poltergeist osv-scanner codegraph; do
    "${smoke_root}/bins/${binary}" --version >/dev/null 2>&1 \
        || die "relocated ${binary} smoke test failed"
done
bash "${smoke_root}/setup.sh" verify

mv -f "$build_output" "$OUTPUT"
chunk_dir="${HARNESS_ROOT}/offline/${PLATFORM}"
mkdir -p "$chunk_dir"
python3 "$PACKAGE_TOOL" write-chunks "$OUTPUT" "$chunk_dir" \
    --platform "$PLATFORM" --chunk-size "$CHUNK_SIZE_BYTES"
python3 "$PACKAGE_TOOL" validate-chunks "${chunk_dir}/offline-pack-chunks.json" --platform "$PLATFORM"

log "created $OUTPUT"
log "published platform chunks under ${chunk_dir}"
