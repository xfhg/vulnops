#!/usr/bin/env bash
# setup-codegraph.sh — Idempotent codegraph index bootstrap for the harness.
#
# Builds a per-audit codegraph index for the target repo. Resolution order:
#   1. $CODEGRAPH_TARGET_DIR — explicit clone path (set by run-audit.sh)
#   2. $VULNOPSV3_TARGET     — the harness's resolved target root
#   3. ${HARNESS_ROOT}/target — legacy fallback
#
# Index root resolution:
#   1. $CODEGRAPH_INDEX_DIR          — explicit override
#   2. ${VULNOPSV3_SCANS}/.codegraph  — per-audit isolation
#   3. ${HARNESS_ROOT}/.codegraph    — last-resort shared root
#
# Per-audit isolation is the recommended layout: two audits against
# different repos must not clobber each other. The shared fallback exists
# only so the script is usable outside the run-audit.sh orchestrator.
#
# Telemetry is off and the daemon is disabled by harness-lib.sh. codegraph is
# the harness's sole graph backend and a required binary; a missing binary is
# a setup failure (validate-config enforces it).

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

CODEGRAPH_BIN="${HARNESS_ROOT}/bins/codegraph"
CODEGRAPH_TARGET_DIR="${CODEGRAPH_TARGET_DIR:-${VULNOPSV3_TARGET:-${HARNESS_ROOT}/target}}"
CODEGRAPH_INDEX_DIR="${CODEGRAPH_INDEX_DIR:-${VULNOPSV3_SCANS:-${HARNESS_ROOT}/scans}/.codegraph}"
MARKER="${CODEGRAPH_INDEX_DIR}/.codegraph-init-marker"
TARGET_MTIME_FILE="${CODEGRAPH_INDEX_DIR}/.target-mtime"

mkdir -p "${CODEGRAPH_INDEX_DIR}"

if [ ! -x "${CODEGRAPH_BIN}" ]; then
    echo "[setup-codegraph] bins/codegraph not installed; skipping (agents will fall back to grep/Read)"
    exit 0
fi

if [ ! -d "${CODEGRAPH_TARGET_DIR}" ]; then
    echo "[setup-codegraph] target directory not present: ${CODEGRAPH_TARGET_DIR} (will be indexed on next audit run)"
    exit 0
fi

# Latest mtime of any file under the target (seconds since epoch). Empty
# when the target is empty or unreadable; the empty string cannot match a
# stored mtime so we always re-init in that case.
target_mtime() {
    # Portable across GNU/BSD find: use stat on every file and take the
    # max mtime. stat's %m gives whole-second modification time, which is
    # enough for the change-detection heuristic.
    find "${CODEGRAPH_TARGET_DIR}" -type f -print 2>/dev/null \
        | while IFS= read -r f; do
            stat -f %m "$f" 2>/dev/null || stat -c %Y "$f" 2>/dev/null
        done \
        | sort -n | tail -n 1
}

# Skip re-indexing when the marker exists and the target mtime has not
# changed since last init. A full re-index on every run is wasteful on
# large repos and a real audit can take minutes.
if [ -f "${MARKER}" ] && [ -f "${TARGET_MTIME_FILE}" ]; then
    last_mtime="$(cat "${TARGET_MTIME_FILE}" 2>/dev/null || echo 0)"
    current_mtime="$(target_mtime || true)"
    if [ -n "${current_mtime}" ] && [ "${current_mtime}" = "${last_mtime}" ]; then
        echo "[setup-codegraph] index up to date for ${CODEGRAPH_TARGET_DIR}"
        exit 0
    fi
fi

if "${CODEGRAPH_BIN}" init "${CODEGRAPH_TARGET_DIR}" >"${CODEGRAPH_INDEX_DIR}/init.log" 2>&1; then
    touch "${MARKER}"
    current_mtime="$(target_mtime || true)"
    if [ -n "${current_mtime}" ]; then
        echo "${current_mtime}" > "${TARGET_MTIME_FILE}"
    fi
    echo "[setup-codegraph] indexed ${CODEGRAPH_TARGET_DIR} -> ${CODEGRAPH_INDEX_DIR}"
else
    echo "[setup-codegraph] codegraph init failed; see ${CODEGRAPH_INDEX_DIR}/init.log"
    # Marker is NOT written on failure so a later re-run can retry.
    exit 0
fi

# Best-effort status print for the harness log; non-fatal if status fails.
"${CODEGRAPH_BIN}" status >>"${CODEGRAPH_INDEX_DIR}/init.log" 2>&1 || true
