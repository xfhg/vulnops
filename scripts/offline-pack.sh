#!/usr/bin/env bash
# offline-pack.sh — Build a self-contained offline bundle for airgapped deployment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCK_FILE="${HARNESS_ROOT}/config/offline-pack.lock"
OFFLINE_DIR="${HARNESS_ROOT}/offline"
CHUNK_SIZE_BYTES=$((45 * 1024 * 1024))
CHUNK_SIZE_LABEL="45MiB"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[pack]${NC} $*"; }
warn() { echo -e "${YELLOW}[pack]${NC} $*" >&2; }
err()  { echo -e "${RED}[pack]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<EOF
Usage: $0 [options]

Build a self-contained offline bundle for airgapped Linux AMD64 deployment.
Also writes 45MiB Git-friendly chunks under ./offline/.

Options:
  --output <path>        Output tar.gz path
  --force                Overwrite an existing output file
  --include-config       Include local config.toml with credentials
  --include-untracked    Include untracked critical harness files
  --version latest       Build with latest upstream tool/package versions
  --refresh-lock         Build with latest versions and update config/offline-pack.lock
  --help                 Show this help

Default output:
  ./vulnops-offline-<timestamp>.tar.gz
  ./offline/<tar-name>.part-aa, ./offline/<tar-name>.part-ab, ...
  ./offline/offline-pack-chunks.json

Default security posture:
  config.toml.example is packaged as config.toml. Live config.toml is included
  only with --include-config.
EOF
}

require_arg() {
    local opt="$1"
    local value="${2:-}"
    if [ -z "$value" ] || [[ "$value" == --* ]]; then
        usage >&2
        die "$opt requires a value"
    fi
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

load_lock() {
    [ -f "$LOCK_FILE" ] || die "Missing offline pack lock file: $LOCK_FILE"
    # shellcheck source=/dev/null
    source "$LOCK_FILE"

    : "${OFFLINE_PACK_PLATFORM:?missing OFFLINE_PACK_PLATFORM in lock}"
    : "${OFFLINE_PACK_PYTHON_VERSION:?missing OFFLINE_PACK_PYTHON_VERSION in lock}"
    : "${OFFLINE_PACK_PYTHON_TAG:?missing OFFLINE_PACK_PYTHON_TAG in lock}"
    : "${OFFLINE_PACK_WHEEL_PLATFORM:?missing OFFLINE_PACK_WHEEL_PLATFORM in lock}"
    : "${WRAITH_VERSION:?missing WRAITH_VERSION in lock}"
    : "${POLTERGEIST_VERSION:?missing POLTERGEIST_VERSION in lock}"
    : "${OMP_VERSION:?missing OMP_VERSION in lock}"
    : "${OSV_SCANNER_VERSION:?missing OSV_SCANNER_VERSION in lock}"
    : "${GRAPHIFYY_VERSION:?missing GRAPHIFYY_VERSION in lock}"
    : "${MIN_OSV_DB_FILES:?missing MIN_OSV_DB_FILES in lock}"
    : "${MIN_OSV_DB_SIZE_KB:?missing MIN_OSV_DB_SIZE_KB in lock}"
    : "${MIN_WHEEL_COUNT:?missing MIN_WHEEL_COUNT in lock}"
}

copy_file_to_staging() {
    local rel="$1"
    mkdir -p "$STAGING/$(dirname "$rel")"
    cp "$HARNESS_ROOT/$rel" "$STAGING/$rel"
}

copy_tracked_source() {
    git -C "$HARNESS_ROOT" ls-files | while IFS= read -r rel; do
        copy_file_to_staging "$rel"
    done
}

copy_untracked_critical_source() {
    [ "$INCLUDE_UNTRACKED" = true ] || return 0
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        copy_file_to_staging "$rel"
    done < <(git -C "$HARNESS_ROOT" ls-files --others --exclude-standard -- \
        .omp scripts schemas config AGENTS.md README.md run.sh config.toml.example)
}

check_untracked_critical_source() {
    local report="${TMPDIR:-/tmp}/vulnops-offline-untracked.txt"
    git -C "$HARNESS_ROOT" ls-files --others --exclude-standard -- \
        .omp scripts schemas config AGENTS.md README.md run.sh config.toml.example >"$report"
    if [ -s "$report" ] && [ "$INCLUDE_UNTRACKED" != true ]; then
        err "Critical untracked files would be omitted from the offline pack:"
        sed 's/^/[pack]   /' "$report" >&2
        die "Commit/stage the files, or rerun with --include-untracked."
    fi
    if [ -s "$report" ]; then
        warn "Including untracked critical files because --include-untracked was set:"
        sed 's/^/[pack]   /' "$report" >&2
    fi
}

read_version_file() {
    local path="$1"
    [ -f "$path" ] && sed -n '1p' "$path" || true
}

detect_graphify_wheel_version() {
    local wheel
    wheel="$(find "$STAGING/wheels" -maxdepth 1 -name 'graphifyy-*.whl' | sort | head -1)"
    [ -n "$wheel" ] || return 1
    basename "$wheel" | sed -E 's/^graphifyy-([^-]+)-.*$/\1/'
}

write_lock_file() {
    local path="$1"
    cat >"$path" <<EOF
# offline-pack.lock — exact versions used by scripts/offline-pack.sh
# Refresh intentionally with: bash scripts/offline-pack.sh --refresh-lock

OFFLINE_PACK_PLATFORM=linux_amd64
OFFLINE_PACK_PYTHON_VERSION=3.12
OFFLINE_PACK_PYTHON_TAG=cp312
OFFLINE_PACK_WHEEL_PLATFORM=manylinux2014_x86_64

WRAITH_VERSION=${ACTUAL_WRAITH_VERSION}
POLTERGEIST_VERSION=${ACTUAL_POLTERGEIST_VERSION}
OMP_VERSION=${ACTUAL_OMP_VERSION}
OSV_SCANNER_VERSION=${ACTUAL_OSV_SCANNER_VERSION}
GRAPHIFYY_VERSION=${ACTUAL_GRAPHIFYY_VERSION}

MIN_OSV_DB_FILES=${MIN_OSV_DB_FILES}
MIN_OSV_DB_SIZE_KB=${MIN_OSV_DB_SIZE_KB}
MIN_WHEEL_COUNT=${MIN_WHEEL_COUNT}
EOF
}

write_pack_manifest() {
    python3 - "$STAGING" \
        "$ACTUAL_WRAITH_VERSION" \
        "$ACTUAL_POLTERGEIST_VERSION" \
        "$ACTUAL_OMP_VERSION" \
        "$ACTUAL_OSV_SCANNER_VERSION" \
        "$ACTUAL_GRAPHIFYY_VERSION" \
        "$db_file_count" \
        "$db_size_kb" \
        "$wheel_count" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
versions = {
    "wraith": sys.argv[2],
    "poltergeist": sys.argv[3],
    "omp": sys.argv[4],
    "osv_scanner": sys.argv[5],
    "graphifyy": sys.argv[6],
    "python": "3.12",
    "python_tag": "cp312",
    "platform": "linux_amd64",
    "wheel_platform": "manylinux2014_x86_64",
}

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

files = {}
for rel in [
    "bins/omp",
    "bins/wraith",
    "bins/poltergeist",
    "bins/osv-scanner",
    "setup.sh",
    "config/offline-pack.lock",
]:
    path = root / rel
    if path.is_file():
        files[rel] = sha(path)

wheels = {}
for path in sorted((root / "wheels").glob("*.whl")):
    wheels[f"wheels/{path.name}"] = sha(path)

manifest = {
    "schema": "vulnops.offline-pack-manifest.v1",
    "versions": versions,
    "counts": {
        "osv_db_files": int(sys.argv[7]),
        "osv_db_size_kb": int(sys.argv[8]),
        "wheels": int(sys.argv[9]),
    },
    "hashes": {
        "files": files,
        "wheels": wheels,
    },
    "security": {
        "config_toml_contains_live_credentials": (root / ".pack-included-live-config").exists(),
    },
}
(root / "offline-pack-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
}

write_chunk_manifest() {
    python3 - "$OUTPUT" "$OFFLINE_DIR" "$CHUNK_SIZE_BYTES" "$CHUNK_SIZE_LABEL" <<'PY'
import hashlib
import json
import string
import sys
from pathlib import Path

tar_path = Path(sys.argv[1])
offline_dir = Path(sys.argv[2])
chunk_size = int(sys.argv[3])
chunk_size_label = sys.argv[4]

alphabet = string.ascii_lowercase

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def suffix(index: int) -> str:
    if index >= len(alphabet) * len(alphabet):
        raise SystemExit("too many chunks for two-letter suffixes")
    return alphabet[index // len(alphabet)] + alphabet[index % len(alphabet)]

tar_name = tar_path.name
chunks = []
with tar_path.open("rb") as src:
    index = 0
    while True:
        data = src.read(chunk_size)
        if not data:
            break
        chunk_name = f"{tar_name}.part-{suffix(index)}"
        chunk_path = offline_dir / chunk_name
        chunk_path.write_bytes(data)
        chunks.append(
            {
                "file": chunk_name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        index += 1

manifest = {
    "schema": "vulnops.offline-pack-chunks.v1",
    "tar_name": tar_name,
    "tar_size": tar_path.stat().st_size,
    "tar_sha256": sha(tar_path),
    "chunk_size_bytes": chunk_size,
    "chunk_size_label": chunk_size_label,
    "chunks": chunks,
}
(offline_dir / "offline-pack-chunks.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n"
)
print(len(chunks))
PY
}

# ── Parse arguments ──────────────────────────────────────────────────────

OUTPUT=""
FORCE=false
INCLUDE_CONFIG=false
INCLUDE_UNTRACKED=false
USE_LATEST=false
REFRESH_LOCK=false

while [ $# -gt 0 ]; do
    case "$1" in
        --output|-o) require_arg "$1" "${2:-}"; OUTPUT="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        --include-config) INCLUDE_CONFIG=true; shift ;;
        --include-untracked) INCLUDE_UNTRACKED=true; shift ;;
        --version)
            require_arg "$1" "${2:-}"
            [ "$2" = "latest" ] || die "Only --version latest is supported; default uses $LOCK_FILE"
            USE_LATEST=true
            shift 2
            ;;
        --refresh-lock) USE_LATEST=true; REFRESH_LOCK=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

if [ -z "$OUTPUT" ]; then
    OUTPUT="${HARNESS_ROOT}/vulnops-offline-$(date +%Y%m%d-%H%M%S).tar.gz"
fi

mkdir -p "$(dirname "$OUTPUT")"
OUTPUT="$(cd "$(dirname "$OUTPUT")" && pwd)/$(basename "$OUTPUT")"
case "$OUTPUT" in
    "$OFFLINE_DIR"|"$OFFLINE_DIR"/*)
        die "--output must not be inside $OFFLINE_DIR because that directory is replaced with chunk files"
        ;;
esac
if [ -e "$OUTPUT" ] && [ "$FORCE" != true ]; then
    die "Output already exists: $OUTPUT (use --force to overwrite)"
fi

# ── Platform and prerequisite checks ──────────────────────────────────────

os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch_name="$(uname -m)"
if [ "$os_name" != "linux" ] || [ "$arch_name" != "x86_64" ]; then
    die "This script must run on Linux x86_64 (detected: ${os_name}/${arch_name}).
The airgapped target is Linux AMD64 — bundling a different architecture would
produce binaries that cannot run."
fi

for cmd in git curl tar pip3 python3 sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || die "Missing required command: $cmd"
done

load_lock
if [ "$OFFLINE_PACK_PLATFORM" != "linux_amd64" ]; then
    die "Unsupported lock platform: $OFFLINE_PACK_PLATFORM"
fi
if [ "$USE_LATEST" = true ]; then
    WRAITH_VERSION=latest
    POLTERGEIST_VERSION=latest
    OMP_VERSION=latest
    OSV_SCANNER_VERSION=latest
    GRAPHIFYY_VERSION=latest
fi

check_untracked_critical_source

# ── Step 1: Create staging directory ─────────────────────────────────────

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
log "Staging directory: $STAGING"

# ── Step 2: Copy source ──────────────────────────────────────────────────

log "Copying harness source..."
copy_tracked_source
copy_untracked_critical_source

if [ "$INCLUDE_CONFIG" = true ]; then
    [ -f "$HARNESS_ROOT/config.toml" ] || die "--include-config requested but config.toml is missing"
    cp "$HARNESS_ROOT/config.toml" "$STAGING/config.toml"
    : >"$STAGING/.pack-included-live-config"
    warn "  config.toml: included with live credentials because --include-config was set"
else
    [ -f "$STAGING/config.toml.example" ] || die "config.toml.example missing from staged source"
    cp "$STAGING/config.toml.example" "$STAGING/config.toml"
    log "  config.toml: redacted template included"
fi
log "  Source copy complete."

# ── Step 3: Download Linux AMD64 binaries ────────────────────────────────

log "Downloading locked binaries..."
WRAITH_VERSION="$WRAITH_VERSION" \
POLTERGEIST_VERSION="$POLTERGEIST_VERSION" \
OMP_VERSION="$OMP_VERSION" \
OSV_SCANNER_VERSION="$OSV_SCANNER_VERSION" \
SKIP_GRAPHIFY_INSTALL=1 \
    bash "$STAGING/scripts/install-tools.sh" all

for bin in omp wraith poltergeist osv-scanner; do
    [ -x "$STAGING/bins/$bin" ] || die "Binary not found after install: bins/$bin"
done

ACTUAL_WRAITH_VERSION="$(read_version_file "$STAGING/bins/.wraith.version")"
ACTUAL_POLTERGEIST_VERSION="$(read_version_file "$STAGING/bins/.poltergeist.version")"
ACTUAL_OMP_VERSION="$(read_version_file "$STAGING/bins/.omp.version")"
ACTUAL_OSV_SCANNER_VERSION="$(read_version_file "$STAGING/bins/.osv-scanner.version")"
log "  Binaries: wraith ${ACTUAL_WRAITH_VERSION}, poltergeist ${ACTUAL_POLTERGEIST_VERSION}, omp ${ACTUAL_OMP_VERSION}, osv-scanner ${ACTUAL_OSV_SCANNER_VERSION}"

# ── Step 4: Download OSV database ────────────────────────────────────────

log "Downloading OSV vulnerability database..."
bash "$STAGING/scripts/fetch-osv-db.sh" || die "fetch-osv-db.sh failed"

DB_DIR="$STAGING/.harness/osv-db"
db_file_count="$(find "$DB_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
db_size_kb="$(du -sk "$DB_DIR" 2>/dev/null | awk '{print $1}')"
if [ "$db_file_count" -lt "$MIN_OSV_DB_FILES" ] || [ "${db_size_kb:-0}" -lt "$MIN_OSV_DB_SIZE_KB" ]; then
    die "OSV database verification failed: ${db_file_count} files, ${db_size_kb} KB"
fi
log "  OSV database: ${db_file_count} files, $((db_size_kb / 1024)) MB"

# ── Step 5: Download Python wheels ───────────────────────────────────────

log "Downloading Python wheels for ${OFFLINE_PACK_PYTHON_TAG} / ${OFFLINE_PACK_WHEEL_PLATFORM}..."
mkdir -p "$STAGING/wheels"

if [ "$GRAPHIFYY_VERSION" = "latest" ]; then
    graphify_spec="graphifyy[openai]"
else
    graphify_spec="graphifyy[openai]==${GRAPHIFYY_VERSION}"
fi

pip3 download \
    "$graphify_spec" \
    --dest "$STAGING/wheels" \
    --only-binary :all: \
    --implementation cp \
    --python-version "$OFFLINE_PACK_PYTHON_VERSION" \
    --abi "$OFFLINE_PACK_PYTHON_TAG" \
    --platform "$OFFLINE_PACK_WHEEL_PLATFORM" \
    --prefer-binary \
    || die "pip download failed for graphifyy and dependencies"

wheel_count="$(find "$STAGING/wheels" -name '*.whl' | wc -l | tr -d ' ')"
if [ "$wheel_count" -lt "$MIN_WHEEL_COUNT" ]; then
    die "Wheel count verification failed: ${wheel_count} wheels found (expected >= ${MIN_WHEEL_COUNT})"
fi
ACTUAL_GRAPHIFYY_VERSION="$(detect_graphify_wheel_version)" || die "Could not detect graphifyy wheel version"
log "  Python wheels: ${wheel_count} packages; graphifyy ${ACTUAL_GRAPHIFYY_VERSION}"

if [ "$REFRESH_LOCK" = true ]; then
    write_lock_file "$LOCK_FILE"
    log "Updated lock file: $LOCK_FILE"
fi
write_lock_file "$STAGING/config/offline-pack.lock"

# ── Step 6: Generate setup.sh ────────────────────────────────────────────

log "Generating setup.sh..."
cat > "$STAGING/setup.sh" <<'SETUP_EOF'
#!/usr/bin/env bash
# setup.sh — One-time setup for airgapped deployment.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn() { echo -e "${YELLOW}[setup]${NC} $*" >&2; }
err()  { echo -e "${RED}[setup]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

check_file() {
    [ -f "$1" ] || die "$2 missing: $1"
}

check_exec() {
    [ -x "$1" ] || die "$2 missing or not executable: $1"
}

check_config_ready() {
    python3 - "$HARNESS_ROOT/config.toml" <<'PY'
import sys
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:
    print("Python 3.12+ is required for tomllib", file=sys.stderr)
    raise SystemExit(1)
cfg = tomllib.loads(Path(sys.argv[1]).read_text())
llm = cfg.get("llm", {})
missing = [key for key in ("base_url", "api_key", "model") if not str(llm.get(key, "")).strip()]
if missing:
    print("config.toml still has empty [llm] fields: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(2)
PY
}

if ! command -v python3 >/dev/null 2>&1; then
    die "python3 not found. Python 3.12 is required to install the bundled wheels."
fi

py_ver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [ "$py_ver" != "3.12" ]; then
    die "Python 3.12 required; bundled wheels are cp312-specific (found ${py_ver})."
fi
log "Python ${py_ver} detected."

for bin in omp wraith poltergeist osv-scanner; do
    check_exec "${HARNESS_ROOT}/bins/${bin}" "binary ${bin}"
done
check_file "${HARNESS_ROOT}/config.toml" "config.toml"
check_file "${HARNESS_ROOT}/offline-pack-manifest.json" "offline-pack manifest"
check_config_ready || die "Edit config.toml with the on-prem LLM endpoint/API key before running setup.sh."

db_files="$(find "${HARNESS_ROOT}/.harness/osv-db" -type f 2>/dev/null | wc -l | tr -d ' ')"
[ "$db_files" -ge 3 ] || die "OSV database missing or incomplete: ${db_files} files"

wheel_count="$(find "${HARNESS_ROOT}/wheels" -name '*.whl' 2>/dev/null | wc -l | tr -d ' ')"
[ "$wheel_count" -ge 31 ] || die "Wheel cache missing or incomplete: ${wheel_count} wheels"

log "Recreating Python venv from bundled wheels..."
rm -rf "${HARNESS_ROOT}/.venv"
python3 -m venv "${HARNESS_ROOT}/.venv"
"${HARNESS_ROOT}/.venv/bin/pip" install \
    --no-index \
    --find-links "${HARNESS_ROOT}/wheels/" \
    "graphifyy[openai]"

if ! "${HARNESS_ROOT}/.venv/bin/graphify" --help >/dev/null 2>&1; then
    die "graphify failed to launch after venv creation. Check wheel integrity."
fi
log "graphify installed: ${HARNESS_ROOT}/.venv/bin/graphify"

log "Seeding OMP config from config.toml..."
bash "${HARNESS_ROOT}/scripts/bootstrap-omp.sh"
check_file "${HARNESS_ROOT}/.harness/home/.omp/agent/config.yml" "OMP config"
check_file "${HARNESS_ROOT}/.harness/home/.omp/agent/models.yml" "OMP models"

log "Validating audit readiness..."
bash "${HARNESS_ROOT}/scripts/validate-config.sh"

echo ""
log "Setup complete. The harness is ready for offline audits."
echo ""
echo "  Next steps:"
echo "    1. Copy or clone the target repo under: ${HARNESS_ROOT}/target/"
echo "    2. Run: bash run.sh \"audit the target repo\""
echo "    3. Optional after setup succeeds: rm -rf ${HARNESS_ROOT}/wheels"
echo ""
SETUP_EOF
chmod +x "$STAGING/setup.sh"

# ── Step 7: Manifest and package ─────────────────────────────────────────

write_pack_manifest
manifest_sha="$(sha256_file "$STAGING/offline-pack-manifest.json")"
log "offline-pack-manifest.json sha256: $manifest_sha"

log "Packaging tar.gz..."
tar -czf "$OUTPUT" -C "$STAGING" .
pack_size="$(du -sh "$OUTPUT" | awk '{print $1}')"
pack_sha="$(sha256_file "$OUTPUT")"

# ── Step 8: Split pack for Git transport ─────────────────────────────────

log "Writing ${CHUNK_SIZE_LABEL} chunks to offline/..."
rm -rf "$OFFLINE_DIR"
mkdir -p "$OFFLINE_DIR"
chunk_count="$(write_chunk_manifest)"
chunks_manifest="${OFFLINE_DIR}/offline-pack-chunks.json"
chunks_manifest_sha="$(sha256_file "$chunks_manifest")"
log "  Chunks: ${chunk_count}"
log "  Manifest: ${chunks_manifest}"
log "  Manifest SHA256: ${chunks_manifest_sha}"

echo ""
log "Created: $OUTPUT"
log "Size: $pack_size"
log "SHA256: $pack_sha"
log "Chunks: $OFFLINE_DIR (${chunk_count} files, ${CHUNK_SIZE_LABEL} each except final)"
echo ""
echo "  Manifest:"
echo "    File:          offline-pack-manifest.json"
echo "    SHA256:        $manifest_sha"
echo "    Chunks:        offline/offline-pack-chunks.json"
echo "    Chunks SHA256: $chunks_manifest_sha"
echo "    Binaries:      omp, wraith, poltergeist, osv-scanner (linux_amd64)"
echo "    OSV database:  ${db_file_count} files, $((db_size_kb / 1024)) MB"
echo "    Python wheels: ${wheel_count} packages (graphifyy ${ACTUAL_GRAPHIFYY_VERSION})"
echo "    Config:        $([ "$INCLUDE_CONFIG" = true ] && echo 'live config.toml included' || echo 'redacted config.toml template')"
echo ""
echo "  Git transport:"
echo "    git add offline/ offline-build.sh"
echo "    git commit -m \"Update offline pack chunks\""
echo ""
echo "  Rebuild tarball from chunks:"
echo "    bash offline-build.sh"
echo ""
echo "  Airgapped deployment:"
echo "    mkdir -p /opt/vulnops"
echo "    tar -xzf $(basename "$OUTPUT") -C /opt/vulnops"
echo "    cd /opt/vulnops"
echo "    vi config.toml"
echo "    bash setup.sh"
echo "    bash run.sh \"audit the target repo\""
echo ""
