#!/usr/bin/env bash
# Run Poltergeist with its documented clean/matches exit semantics and persist
# only exact-redacted normalized candidates.
set -uo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
if [ "$#" -ne 3 ]; then echo "Usage: $0 <target> <normalized-json> <receipt-json>" >&2; exit 64; fi
target="$1"; output="$2"; receipt="$3"
harness_require_inside_root "$HARNESS_ROOT" "$target" "target"
harness_require_allowed_output "$HARNESS_ROOT" "$output"
harness_require_allowed_output "$HARNESS_ROOT" "$receipt"
tmp="$(mktemp "${TMPDIR}/poltergeist.XXXXXX")"; trap 'rm -f "$tmp"' EXIT
set +e
"${HARNESS_ROOT}/bins/poltergeist" --format json "$target" >"$tmp" 2>&1
status=$?
set -e
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
    echo "Poltergeist operational failure (exit ${status})" >&2
    exit "$status"
fi
python3 "${HARNESS_ROOT}/scripts/normalize-poltergeist.py" --target "$target" --input "$tmp" --scanner-exit "$status" --output "$output" --receipt "$receipt"
