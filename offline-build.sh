#!/usr/bin/env bash
# offline-build.sh — Rebuild the offline tarball from Git-friendly chunks.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
OFFLINE_DIR="${HARNESS_ROOT}/offline"
MANIFEST="${OFFLINE_DIR}/offline-pack-chunks.json"
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

while [ $# -gt 0 ]; do
    case "$1" in
        --force) FORCE=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

[ -f "$MANIFEST" ] || die "Missing chunk manifest: $MANIFEST"
command -v python3 >/dev/null 2>&1 || die "Missing required command: python3"

log "Reading manifest: $MANIFEST"
tar_name="$(python3 - "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
print(manifest.get("tar_name", ""))
PY
)"
[ -n "$tar_name" ] || die "Manifest missing tar_name"

case "$tar_name" in
    */*|""|.*) die "Unsafe tar_name in manifest: $tar_name" ;;
esac

output="${HARNESS_ROOT}/${tar_name}"
if [ -e "$output" ] && [ "$FORCE" != true ]; then
    die "Output already exists: $output (use --force to overwrite)"
fi

tmp_output="${output}.tmp.$$"
trap 'rm -f "$tmp_output"' EXIT

log "Rebuilding: $output"
python3 - "$MANIFEST" "$OFFLINE_DIR" "$tmp_output" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
offline_dir = Path(sys.argv[2])
output = Path(sys.argv[3])

manifest = json.loads(manifest_path.read_text())
if manifest.get("schema") != "vulnops.offline-pack-chunks.v1":
    raise SystemExit("unsupported chunk manifest schema")

chunks = manifest.get("chunks")
if not isinstance(chunks, list) or not chunks:
    raise SystemExit("chunk manifest has no chunks")

def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

tar_hash = hashlib.sha256()
total = 0
with output.open("wb") as dst:
    for entry in chunks:
        if not isinstance(entry, dict):
            raise SystemExit("invalid chunk entry")
        name = entry.get("file")
        expected_size = entry.get("size")
        expected_sha = entry.get("sha256")
        if not isinstance(name, str) or "/" in name or name.startswith("."):
            raise SystemExit(f"unsafe chunk file name: {name!r}")
        chunk_path = offline_dir / name
        if not chunk_path.is_file():
            raise SystemExit(f"missing chunk: {chunk_path}")
        data = chunk_path.read_bytes()
        actual_sha = sha_bytes(data)
        if actual_sha != expected_sha:
            raise SystemExit(f"sha256 mismatch for {chunk_path}")
        if len(data) != expected_size:
            raise SystemExit(f"size mismatch for {chunk_path}")
        dst.write(data)
        tar_hash.update(data)
        total += len(data)

expected_total = manifest.get("tar_size")
if total != expected_total:
    raise SystemExit(f"rebuilt size mismatch: {total} != {expected_total}")

actual_tar_sha = tar_hash.hexdigest()
if actual_tar_sha != manifest.get("tar_sha256"):
    raise SystemExit("rebuilt tarball sha256 mismatch")
PY

mv "$tmp_output" "$output"
trap - EXIT

rebuilt_sha="$(python3 - "$output" <<'PY'
import hashlib
import sys
from pathlib import Path

h = hashlib.sha256()
with Path(sys.argv[1]).open("rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
print(h.hexdigest())
PY
)"

log "Created: $output"
log "SHA256: $rebuilt_sha"
echo ""
echo "  Next steps:"
echo "    mkdir -p /opt/vulnops"
echo "    tar -xzf ${tar_name} -C /opt/vulnops"
echo "    cd /opt/vulnops"
echo "    vi config.toml"
echo "    bash setup.sh"
