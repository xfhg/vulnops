#!/usr/bin/env bash
# offline-pack.sh — Build a self-contained offline bundle for airgapped deployment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OFFLINE_DIR="${HARNESS_ROOT}/offline"
CHUNK_SIZE_BYTES=$((45 * 1024 * 1024))
CHUNK_SIZE_LABEL="45MiB"
DEFAULT_PLATFORM="linux_amd64"

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

Build a self-contained offline bundle for airgapped deployment.
Default platform is linux_amd64 for backward compatibility.

Options:
  --platform <name>      Target platform: linux_amd64 or darwin_arm64
  --output <path>        Output tar.gz path
  --force                Overwrite an existing output file
  --include-config       Include local config.toml with credentials
  --include-untracked    Include untracked critical harness files
  --version latest       Build with latest upstream tool/package versions
  --refresh-lock         Build with latest versions and update the platform lock
  --help                 Show this help

Default output:
  ./vulnops-offline-<platform>-<timestamp>.tar.gz
  ./offline/<tar-name>.part-aa, ./offline/<tar-name>.part-ab, ...
  ./offline/offline-pack-chunks.json
  ./offline/offline-pack-chunks.sh

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
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "Missing sha256 tool: install sha256sum or shasum"
    fi
}

detect_host_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$os" in
        linux) os="linux" ;;
        darwin) os="darwin" ;;
        *) die "Unsupported host OS: $os" ;;
    esac
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) die "Unsupported host arch: $arch" ;;
    esac
    echo "${os}_${arch}"
}

lock_for_platform() {
    local platform="$1"
    local platform_lock="${HARNESS_ROOT}/config/offline-pack.${platform}.lock"
    if [ -f "$platform_lock" ]; then
        echo "$platform_lock"
        return
    fi
    if [ "$platform" = "linux_amd64" ] && [ -f "${HARNESS_ROOT}/config/offline-pack.lock" ]; then
        echo "${HARNESS_ROOT}/config/offline-pack.lock"
        return
    fi
    die "Missing offline pack lock for ${platform}: ${platform_lock}"
}

load_lock() {
    LOCK_FILE="$(lock_for_platform "$TARGET_PLATFORM")"
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

    if [ "$OFFLINE_PACK_PLATFORM" != "$TARGET_PLATFORM" ]; then
        die "Lock platform ${OFFLINE_PACK_PLATFORM} does not match requested ${TARGET_PLATFORM}: ${LOCK_FILE}"
    fi
    if [ "$TARGET_PLATFORM" = "darwin_arm64" ]; then
        : "${CPYTHON_STANDALONE_RELEASE:?missing CPYTHON_STANDALONE_RELEASE in macOS lock}"
        : "${CPYTHON_STANDALONE_ASSET:?missing CPYTHON_STANDALONE_ASSET in macOS lock}"
    fi
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
        .omp scripts schemas config AGENTS.md README.md run.sh config.toml.example offline-build.sh)
}

check_untracked_critical_source() {
    local report="${TMPDIR:-/tmp}/vulnops-offline-untracked.txt"
    git -C "$HARNESS_ROOT" ls-files --others --exclude-standard -- \
        .omp scripts schemas config AGENTS.md README.md run.sh config.toml.example offline-build.sh >"$report"
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
# Refresh intentionally with: bash scripts/offline-pack.sh --platform ${TARGET_PLATFORM} --refresh-lock

OFFLINE_PACK_PLATFORM=${TARGET_PLATFORM}
OFFLINE_PACK_PYTHON_VERSION=${OFFLINE_PACK_PYTHON_VERSION}
OFFLINE_PACK_PYTHON_TAG=${OFFLINE_PACK_PYTHON_TAG}
OFFLINE_PACK_WHEEL_PLATFORM=${OFFLINE_PACK_WHEEL_PLATFORM}

WRAITH_VERSION=${ACTUAL_WRAITH_VERSION}
POLTERGEIST_VERSION=${ACTUAL_POLTERGEIST_VERSION}
OMP_VERSION=${ACTUAL_OMP_VERSION}
OSV_SCANNER_VERSION=${ACTUAL_OSV_SCANNER_VERSION}
GRAPHIFYY_VERSION=${ACTUAL_GRAPHIFYY_VERSION}
EOF
    if [ "$TARGET_PLATFORM" = "darwin_arm64" ]; then
        cat >>"$path" <<EOF
CPYTHON_STANDALONE_RELEASE=${CPYTHON_STANDALONE_RELEASE}
CPYTHON_STANDALONE_ASSET=${CPYTHON_STANDALONE_ASSET}
EOF
    fi
    cat >>"$path" <<EOF

MIN_OSV_DB_FILES=${MIN_OSV_DB_FILES}
MIN_OSV_DB_SIZE_KB=${MIN_OSV_DB_SIZE_KB}
MIN_WHEEL_COUNT=${MIN_WHEEL_COUNT}
EOF
}

download_cpython_runtime() {
    [ "$TARGET_PLATFORM" = "darwin_arm64" ] || return 0

    local url tmpdir archive
    url="https://github.com/astral-sh/python-build-standalone/releases/download/${CPYTHON_STANDALONE_RELEASE}/${CPYTHON_STANDALONE_ASSET}"
    tmpdir="$(mktemp -d)"
    archive="${tmpdir}/${CPYTHON_STANDALONE_ASSET}"
    log "Downloading bundled CPython ${CPYTHON_STANDALONE_ASSET}..."
    curl -sfL -o "$archive" "$url" || die "Failed to download CPython runtime: $url"
    mkdir -p "$STAGING/vendor"
    tar -xzf "$archive" -C "$STAGING/vendor" || die "Failed to extract CPython runtime"
    [ -x "$STAGING/vendor/python/bin/python3" ] || die "Bundled Python missing after extraction"
    CPYTHON_ARCHIVE_SHA256="$(sha256_file "$archive")"
    rm -rf "$tmpdir"
}

write_pack_manifest() {
    python3 - "$STAGING" \
        "$TARGET_PLATFORM" \
        "$OFFLINE_PACK_PYTHON_VERSION" \
        "$OFFLINE_PACK_PYTHON_TAG" \
        "$OFFLINE_PACK_WHEEL_PLATFORM" \
        "$ACTUAL_WRAITH_VERSION" \
        "$ACTUAL_POLTERGEIST_VERSION" \
        "$ACTUAL_OMP_VERSION" \
        "$ACTUAL_OSV_SCANNER_VERSION" \
        "$ACTUAL_GRAPHIFYY_VERSION" \
        "${CPYTHON_STANDALONE_RELEASE:-}" \
        "${CPYTHON_STANDALONE_ASSET:-}" \
        "${CPYTHON_ARCHIVE_SHA256:-}" \
        "$db_file_count" \
        "$db_size_kb" \
        "$wheel_count" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
versions = {
    "platform": sys.argv[2],
    "python": sys.argv[3],
    "python_tag": sys.argv[4],
    "wheel_platform": sys.argv[5],
    "wraith": sys.argv[6],
    "poltergeist": sys.argv[7],
    "omp": sys.argv[8],
    "osv_scanner": sys.argv[9],
    "graphifyy": sys.argv[10],
}
if sys.argv[11]:
    versions["cpython_standalone_release"] = sys.argv[11]
    versions["cpython_standalone_asset"] = sys.argv[12]
    versions["cpython_standalone_archive_sha256"] = sys.argv[13]

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
    "vendor/python/bin/python3",
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
        "osv_db_files": int(sys.argv[14]),
        "osv_db_size_kb": int(sys.argv[15]),
        "wheels": int(sys.argv[16]),
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

def q(value: object) -> str:
    text = str(value)
    return "'" + text.replace("'", "'\"'\"'") + "'"

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

lines = [
    "# Generated by scripts/offline-pack.sh. Source with bash only.",
    "OFFLINE_CHUNKS_SCHEMA='vulnops.offline-pack-chunks.v1'",
    f"TAR_NAME={q(tar_name)}",
    f"TAR_SIZE={tar_path.stat().st_size}",
    f"TAR_SHA256={q(manifest['tar_sha256'])}",
    f"CHUNK_COUNT={len(chunks)}",
]
for index, entry in enumerate(chunks):
    lines.extend(
        [
            f"CHUNK_{index}_FILE={q(entry['file'])}",
            f"CHUNK_{index}_SIZE={entry['size']}",
            f"CHUNK_{index}_SHA256={q(entry['sha256'])}",
        ]
    )
(offline_dir / "offline-pack-chunks.sh").write_text("\n".join(lines) + "\n")
print(len(chunks))
PY
}

# ── Parse arguments ──────────────────────────────────────────────────────

TARGET_PLATFORM="$DEFAULT_PLATFORM"
OUTPUT=""
FORCE=false
INCLUDE_CONFIG=false
INCLUDE_UNTRACKED=false
USE_LATEST=false
REFRESH_LOCK=false
LOCK_FILE=""
CPYTHON_ARCHIVE_SHA256=""

while [ $# -gt 0 ]; do
    case "$1" in
        --platform) require_arg "$1" "${2:-}"; TARGET_PLATFORM="$2"; shift 2 ;;
        --output|-o) require_arg "$1" "${2:-}"; OUTPUT="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        --include-config) INCLUDE_CONFIG=true; shift ;;
        --include-untracked) INCLUDE_UNTRACKED=true; shift ;;
        --version)
            require_arg "$1" "${2:-}"
            [ "$2" = "latest" ] || die "Only --version latest is supported; default uses the platform lock"
            USE_LATEST=true
            shift 2
            ;;
        --refresh-lock) USE_LATEST=true; REFRESH_LOCK=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

case "$TARGET_PLATFORM" in
    linux_amd64|darwin_arm64) ;;
    *) die "Unsupported platform: $TARGET_PLATFORM" ;;
esac

if [ -z "$OUTPUT" ]; then
    OUTPUT="${HARNESS_ROOT}/vulnops-offline-${TARGET_PLATFORM//_/-}-$(date +%Y%m%d-%H%M%S).tar.gz"
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

HOST_PLATFORM="$(detect_host_platform)"
if [ "$HOST_PLATFORM" != "$TARGET_PLATFORM" ]; then
    die "Build host ${HOST_PLATFORM} cannot create ${TARGET_PLATFORM}; build on the matching platform."
fi

for cmd in git curl tar pip3 python3; do
    command -v "$cmd" >/dev/null 2>&1 || die "Missing required command: $cmd"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    die "Missing required command: sha256sum or shasum"
fi

load_lock
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
log "Target platform: $TARGET_PLATFORM"
log "Lock file: $LOCK_FILE"

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

# ── Step 3: Download platform binaries ───────────────────────────────────

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

# ── Step 4: Download bundled CPython when required ───────────────────────

download_cpython_runtime

# ── Step 5: Download OSV database ────────────────────────────────────────

log "Downloading OSV vulnerability database..."
bash "$STAGING/scripts/fetch-osv-db.sh" || die "fetch-osv-db.sh failed"

DB_DIR="$STAGING/.harness/osv-db"
db_file_count="$(find "$DB_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
db_size_kb="$(du -sk "$DB_DIR" 2>/dev/null | awk '{print $1}')"
if [ "$db_file_count" -lt "$MIN_OSV_DB_FILES" ] || [ "${db_size_kb:-0}" -lt "$MIN_OSV_DB_SIZE_KB" ]; then
    die "OSV database verification failed: ${db_file_count} files, ${db_size_kb} KB"
fi
log "  OSV database: ${db_file_count} files, $((db_size_kb / 1024)) MB"

# ── Step 6: Download Python wheels ───────────────────────────────────────

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

# ── Step 7: Generate setup.sh ────────────────────────────────────────────

log "Generating setup.sh..."
cat > "$STAGING/setup.sh" <<'SETUP_EOF'
#!/usr/bin/env bash
# setup.sh — One-time setup for airgapped deployment.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")" && pwd)"
LOCK_FILE="${HARNESS_ROOT}/config/offline-pack.lock"

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

fix_macos_runtime_bits() {
    [ "$(uname -s)" = "Darwin" ] || return 0
    if command -v xattr >/dev/null 2>&1; then
        xattr -dr com.apple.quarantine "$HARNESS_ROOT" 2>/dev/null || true
        xattr -dr com.apple.provenance "$HARNESS_ROOT" 2>/dev/null || true
    fi
    command -v codesign >/dev/null 2>&1 || return 0
    while IFS= read -r -d '' file; do
        codesign --force --sign - "$file" >/dev/null 2>&1 || true
    done < <(find "${HARNESS_ROOT}/bins" "${HARNESS_ROOT}/vendor/python/bin" -type f -perm -111 -print0 2>/dev/null)
}

select_python() {
    if [ -x "${HARNESS_ROOT}/vendor/python/bin/python3" ]; then
        echo "${HARNESS_ROOT}/vendor/python/bin/python3"
        return
    fi
    command -v python3 2>/dev/null || true
}

check_config_ready() {
    "$PYTHON" - "$HARNESS_ROOT/config.toml" <<'PY'
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

check_file "$LOCK_FILE" "offline pack lock"
# shellcheck source=/dev/null
source "$LOCK_FILE"

fix_macos_runtime_bits

PYTHON="$(select_python)"
[ -n "$PYTHON" ] || die "python3 not found. This pack requires Python ${OFFLINE_PACK_PYTHON_VERSION}."
check_exec "$PYTHON" "Python runtime"

py_ver="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [ "$py_ver" != "$OFFLINE_PACK_PYTHON_VERSION" ]; then
    die "Python ${OFFLINE_PACK_PYTHON_VERSION} required; bundled wheels are ${OFFLINE_PACK_PYTHON_TAG}-specific (found ${py_ver})."
fi
log "Python ${py_ver} detected: $PYTHON"

for bin in omp wraith poltergeist osv-scanner; do
    check_exec "${HARNESS_ROOT}/bins/${bin}" "binary ${bin}"
done
check_file "${HARNESS_ROOT}/config.toml" "config.toml"
check_file "${HARNESS_ROOT}/offline-pack-manifest.json" "offline-pack manifest"
check_config_ready || die "Edit config.toml with the local/LAN LLM endpoint/API key before running setup.sh."

db_files="$(find "${HARNESS_ROOT}/.harness/osv-db" -type f 2>/dev/null | wc -l | tr -d ' ')"
[ "$db_files" -ge "$MIN_OSV_DB_FILES" ] || die "OSV database missing or incomplete: ${db_files} files"

wheel_count="$(find "${HARNESS_ROOT}/wheels" -name '*.whl' 2>/dev/null | wc -l | tr -d ' ')"
[ "$wheel_count" -ge "$MIN_WHEEL_COUNT" ] || die "Wheel cache missing or incomplete: ${wheel_count} wheels"

log "Recreating Python venv from bundled wheels..."
rm -rf "${HARNESS_ROOT}/.venv"
"$PYTHON" -m venv "${HARNESS_ROOT}/.venv"
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

# ── Step 8: Manifest and package ─────────────────────────────────────────

write_pack_manifest
manifest_sha="$(sha256_file "$STAGING/offline-pack-manifest.json")"
log "offline-pack-manifest.json sha256: $manifest_sha"

log "Packaging tar.gz..."
tar -czf "$OUTPUT" -C "$STAGING" .
pack_size="$(du -sh "$OUTPUT" | awk '{print $1}')"
pack_sha="$(sha256_file "$OUTPUT")"

# ── Step 9: Split pack for Git transport ─────────────────────────────────

log "Writing ${CHUNK_SIZE_LABEL} chunks to offline/..."
rm -rf "$OFFLINE_DIR"
mkdir -p "$OFFLINE_DIR"
chunk_count="$(write_chunk_manifest)"
chunks_manifest="${OFFLINE_DIR}/offline-pack-chunks.json"
chunks_shell_manifest="${OFFLINE_DIR}/offline-pack-chunks.sh"
chunks_manifest_sha="$(sha256_file "$chunks_manifest")"
chunks_shell_manifest_sha="$(sha256_file "$chunks_shell_manifest")"
log "  Chunks: ${chunk_count}"
log "  JSON manifest: ${chunks_manifest}"
log "  Shell manifest: ${chunks_shell_manifest}"

echo ""
log "Created: $OUTPUT"
log "Size: $pack_size"
log "SHA256: $pack_sha"
log "Chunks: $OFFLINE_DIR (${chunk_count} files, ${CHUNK_SIZE_LABEL} each except final)"
echo ""
echo "  Manifest:"
echo "    File:             offline-pack-manifest.json"
echo "    SHA256:           $manifest_sha"
echo "    Chunks JSON:      offline/offline-pack-chunks.json"
echo "    Chunks JSON SHA:  $chunks_manifest_sha"
echo "    Chunks shell:     offline/offline-pack-chunks.sh"
echo "    Chunks shell SHA: $chunks_shell_manifest_sha"
echo "    Platform:         ${TARGET_PLATFORM}"
echo "    Binaries:         omp, wraith, poltergeist, osv-scanner"
echo "    OSV database:     ${db_file_count} files, $((db_size_kb / 1024)) MB"
echo "    Python wheels:    ${wheel_count} packages (graphifyy ${ACTUAL_GRAPHIFYY_VERSION})"
if [ "$TARGET_PLATFORM" = "darwin_arm64" ]; then
    echo "    Bundled Python:   ${CPYTHON_STANDALONE_ASSET}"
fi
echo "    Config:           $([ "$INCLUDE_CONFIG" = true ] && echo 'live config.toml included' || echo 'redacted config.toml template')"
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
