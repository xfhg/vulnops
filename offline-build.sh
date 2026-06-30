#!/usr/bin/env bash
# offline-build.sh — Rebuild the offline tarball from Git-friendly chunks.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
OFFLINE_DIR="${HARNESS_ROOT}/offline"
SHELL_MANIFEST="${OFFLINE_DIR}/offline-pack-chunks.sh"
JSON_MANIFEST="${OFFLINE_DIR}/offline-pack-chunks.json"
FORCE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[offline-build]${NC} $*"; }
warn() { echo -e "${YELLOW}[offline-build]${NC} $*" >&2; }
err()  { echo -e "${RED}[offline-build]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<EOF
Usage: $0 [options]

Rebuild the vulnops offline tarball from chunks in offline/.

Options:
  --force    Overwrite an existing rebuilt tarball
  --help     Show this help
EOF
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "Missing sha256 tool: install sha256sum or shasum"
    fi
}

chunk_var() {
    local name="$1"
    printf '%s' "${!name:-}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --force) FORCE=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

if [ ! -f "$SHELL_MANIFEST" ]; then
    die "Missing shell chunk manifest: $SHELL_MANIFEST. Rebuild the offline pack with the current scripts/offline-pack.sh."
fi
[ -f "$JSON_MANIFEST" ] || warn "JSON chunk manifest missing: $JSON_MANIFEST"

log "Reading manifest: $SHELL_MANIFEST"
# shellcheck source=/dev/null
source "$SHELL_MANIFEST"

[ "${OFFLINE_CHUNKS_SCHEMA:-}" = "vulnops.offline-pack-chunks.v1" ] || die "Unsupported chunk manifest schema: ${OFFLINE_CHUNKS_SCHEMA:-missing}"
[ -n "${TAR_NAME:-}" ] || die "Manifest missing TAR_NAME"
[ -n "${TAR_SIZE:-}" ] || die "Manifest missing TAR_SIZE"
[ -n "${TAR_SHA256:-}" ] || die "Manifest missing TAR_SHA256"
[ -n "${CHUNK_COUNT:-}" ] || die "Manifest missing CHUNK_COUNT"

case "$TAR_NAME" in
    */*|""|.*) die "Unsafe TAR_NAME in manifest: $TAR_NAME" ;;
esac
case "$CHUNK_COUNT" in
    ''|*[!0-9]*) die "Invalid CHUNK_COUNT in manifest: $CHUNK_COUNT" ;;
esac

output="${HARNESS_ROOT}/${TAR_NAME}"
if [ -e "$output" ] && [ "$FORCE" != true ]; then
    die "Output already exists: $output (use --force to overwrite)"
fi

tmp_output="${output}.tmp.$$"
trap 'rm -f "$tmp_output"' EXIT

log "Rebuilding: $output"
: >"$tmp_output"
index=0
while [ "$index" -lt "$CHUNK_COUNT" ]; do
    file_var="CHUNK_${index}_FILE"
    size_var="CHUNK_${index}_SIZE"
    sha_var="CHUNK_${index}_SHA256"
    chunk_file="$(chunk_var "$file_var")"
    expected_size="$(chunk_var "$size_var")"
    expected_sha="$(chunk_var "$sha_var")"

    [ -n "$chunk_file" ] || die "Manifest missing ${file_var}"
    [ -n "$expected_size" ] || die "Manifest missing ${size_var}"
    [ -n "$expected_sha" ] || die "Manifest missing ${sha_var}"
    case "$chunk_file" in
        */*|""|.*) die "Unsafe chunk file name: $chunk_file" ;;
    esac

    chunk_path="${OFFLINE_DIR}/${chunk_file}"
    [ -f "$chunk_path" ] || die "Missing chunk: $chunk_path"
    actual_sha="$(sha256_file "$chunk_path")"
    [ "$actual_sha" = "$expected_sha" ] || die "sha256 mismatch for $chunk_path"
    actual_size="$(wc -c <"$chunk_path" | tr -d ' ')"
    [ "$actual_size" = "$expected_size" ] || die "size mismatch for $chunk_path"
    cat "$chunk_path" >>"$tmp_output"
    index=$((index + 1))
done

actual_size="$(wc -c <"$tmp_output" | tr -d ' ')"
[ "$actual_size" = "$TAR_SIZE" ] || die "rebuilt size mismatch: ${actual_size} != ${TAR_SIZE}"
rebuilt_sha="$(sha256_file "$tmp_output")"
[ "$rebuilt_sha" = "$TAR_SHA256" ] || die "rebuilt tarball sha256 mismatch"

mv "$tmp_output" "$output"
trap - EXIT

log "Created: $output"
log "SHA256: $rebuilt_sha"
echo ""
echo "  Next steps:"
echo "    mkdir -p /opt/vulnops"
echo "    tar -xzf ${TAR_NAME} -C /opt/vulnops"
echo "    cd /opt/vulnops"
echo "    vi config.toml"
echo "    bash setup.sh"
