#!/usr/bin/env bash
# fetch-osv-db.sh — Download the OSV vulnerability database for offline SCA scanning.
# Requires internet for initial download only. After this, wraith runs fully offline.
#
# Usage: bash scripts/fetch-osv-db.sh
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB_DIR="${HARNESS_ROOT}/.harness/osv-db"
WRAITH="${HARNESS_ROOT}/bins/wraith"
OSV_SCANNER="${HARNESS_ROOT}/bins/osv-scanner"
VERSION_FILE="${HARNESS_ROOT}/.harness/.osv-db-version"
LOG_DIR="${HARNESS_ROOT}/.harness/logs"
LOG_FILE="${LOG_DIR}/fetch-osv-db.log"
TMP_BASE="${HARNESS_ROOT}/.harness/tmp"
MIN_DB_FILES=3
MIN_DB_SIZE_KB=51200

# Check if wraith is installed
if [[ ! -x "${WRAITH}" ]]; then
    echo "ERROR: wraith binary not found at ${WRAITH}"
    echo "Run: bash scripts/install-tools.sh wraith"
    exit 1
fi

if [[ ! -x "${OSV_SCANNER}" ]]; then
    echo "ERROR: osv-scanner binary not found at ${OSV_SCANNER}"
    echo "Run: bash scripts/install-tools.sh"
    exit 1
fi

echo "=== OSV Vulnerability Database Download ==="
echo "Target directory: ${DB_DIR}"
echo "This requires internet and may take several minutes."
echo ""

# Point osv-scanner at our local DB directory via environment variable
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="${DB_DIR}"
export PATH="${HARNESS_ROOT}/bins:${PATH}"
mkdir -p "${DB_DIR}" "${LOG_DIR}" "${TMP_BASE}"
: > "${LOG_FILE}"

# Create a temporary project under the harness root. This is bootstrap-only and
# only exists to make osv-scanner populate the offline vulnerability cache.
TMPDIR=$(mktemp -d "${TMP_BASE}/osv-db.XXXXXX")
trap 'rm -rf "${TMPDIR}"' EXIT

echo "Priming OSV offline database cache."
echo "Raw tool output: ${LOG_FILE}"
echo ""

db_file_count() {
    find "${DB_DIR}" -type f | wc -l | tr -d ' '
}

db_size_kb() {
    du -sk "${DB_DIR}" 2>/dev/null | awk '{print $1}'
}

db_ready() {
    local count size
    count="$(db_file_count)"
    size="$(db_size_kb)"
    [ "${count}" -ge "${MIN_DB_FILES}" ] && [ "${size}" -ge "${MIN_DB_SIZE_KB}" ]
}

write_primer_files() {
    # Valid non-empty manifests are needed because osv-scanner/wraith downloads
    # ecosystem databases based on detected package ecosystems. All scan output
    # is logged, not printed, because these are primers, not audit evidence.
    cat > "${TMPDIR}/package-lock.json" << 'EOFPKG'
{
  "name": "osv-db-primer",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "osv-db-primer",
      "version": "1.0.0",
      "dependencies": {
        "is-number": "7.0.0"
      }
    },
    "node_modules/is-number": {
      "version": "7.0.0",
      "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"
    }
  }
}
EOFPKG

    cat > "${TMPDIR}/go.mod" << 'EOFGO'
module example.com/osv-db-primer

go 1.22

require github.com/google/uuid v1.6.0
EOFGO

    cat > "${TMPDIR}/requirements.txt" << 'EOFPY'
idna==3.7
EOFPY

    cat > "${TMPDIR}/Cargo.lock" << 'EOFCARGO'
version = 3

[[package]]
name = "itoa"
version = "1.0.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
EOFCARGO

    cat > "${TMPDIR}/Gemfile.lock" << 'EOFRUBY'
GEM
  remote: https://rubygems.org/
  specs:
    rake (13.2.1)

PLATFORMS
  ruby

DEPENDENCIES
  rake

BUNDLED WITH
   2.5.0
EOFRUBY
}

write_primer_files

DOWNLOAD_METHOD="osv-scanner"
echo "  Running osv-scanner offline database download..."
DIRECT_STATUS=0
"${OSV_SCANNER}" scan source \
    --offline-vulnerabilities \
    --download-offline-databases \
    --allow-no-lockfiles \
    --lockfile "${TMPDIR}/package-lock.json" \
    --lockfile "${TMPDIR}/go.mod" \
    --lockfile "${TMPDIR}/requirements.txt" \
    --lockfile "${TMPDIR}/Cargo.lock" \
    --lockfile "${TMPDIR}/Gemfile.lock" \
    "${TMPDIR}" >> "${LOG_FILE}" 2>&1 || DIRECT_STATUS=$?

if db_ready; then
    if [ "${DIRECT_STATUS}" -ne 0 ]; then
        echo "  osv-scanner exited ${DIRECT_STATUS} after priming; cache looks complete."
    fi
else
    echo "  osv-scanner direct pass did not fully hydrate the cache; trying wraith fallback."
    DOWNLOAD_METHOD="wraith-fallback"

    # Fallback for older tool combinations: wraith forwards --download-db to
    # osv-scanner. Keep noisy scan summaries out of stdout; this is not an
    # audit scan and these primer files are not target evidence.
    for LOCKFILE in package-lock.json go.mod requirements.txt Cargo.lock Gemfile.lock; do
        if [[ -f "${TMPDIR}/${LOCKFILE}" ]]; then
            echo "  Priming via ${LOCKFILE}..."
            "${WRAITH}" scan --offline --download-db "${TMPDIR}/${LOCKFILE}" >> "${LOG_FILE}" 2>&1 || true
        fi
    done
fi

echo ""

# Verify download
if [[ -d "${DB_DIR}" ]]; then
    DB_SIZE=$(du -sh "${DB_DIR}" 2>/dev/null | cut -f1)
    FILE_COUNT="$(db_file_count)"

    if db_ready; then
        echo "Done. Database size: ${DB_SIZE} (${FILE_COUNT} files)"
        echo "Location: ${DB_DIR}"

        # Record version
        echo "downloaded: $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${VERSION_FILE}"
        echo "source: osv-scanner" >> "${VERSION_FILE}"
        echo "method: ${DOWNLOAD_METHOD}" >> "${VERSION_FILE}"
        echo "ecosystems: npm, go, pypi, crates.io, rubygems" >> "${VERSION_FILE}"
        echo "log: ${LOG_FILE}" >> "${VERSION_FILE}"

        echo ""
        echo "Offline scanning is now available."
        echo "Wraith will automatically use the local DB when --offline is set."
    else
        echo "ERROR: OSV DB appears incomplete: ${DB_SIZE} (${FILE_COUNT} files)." >&2
        echo "Expected at least ${MIN_DB_FILES} files and $((MIN_DB_SIZE_KB / 1024))M." >&2
        echo "Check log: ${LOG_FILE}" >&2
        exit 1
    fi
else
    echo "ERROR: DB directory not created at ${DB_DIR}"
    exit 1
fi
