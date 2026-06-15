#!/usr/bin/env bash
# Validate that the harness can run an audit without bootstrap/network setup.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"

errors=0
MIN_OSV_DB_FILES=3
MIN_OSV_DB_SIZE_KB=51200

err() {
    echo "[validate-config] ERROR: $*" >&2
    errors=$((errors + 1))
}

ok() {
    echo "[validate-config] OK: $*"
}

check_file() {
    local path="$1"
    local label="$2"
    if [ -f "$path" ]; then
        ok "$label"
    else
        err "$label missing: $path"
    fi
}

check_exec() {
    local path="$1"
    local label="$2"
    if [ -x "$path" ]; then
        ok "$label"
    else
        err "$label missing or not executable: $path"
    fi
}

check_nonempty_dir() {
    local path="$1"
    local label="$2"
    if [ -d "$path" ] && [ -n "$(find "$path" -mindepth 1 -print -quit 2>/dev/null)" ]; then
        ok "$label"
    else
        err "$label missing or empty: $path"
    fi
}

check_osv_db() {
    local path="$1"
    local count size
    if [ ! -d "$path" ]; then
        err "OSV local database missing: $path"
        return
    fi
    count="$(find "$path" -type f | wc -l | tr -d ' ')"
    size="$(du -sk "$path" 2>/dev/null | awk '{print $1}')"
    if [ "${count}" -ge "${MIN_OSV_DB_FILES}" ] && [ "${size}" -ge "${MIN_OSV_DB_SIZE_KB}" ]; then
        ok "OSV local database"
    else
        err "OSV local database incomplete: ${count} files, ${size:-0}KB; run: bash scripts/fetch-osv-db.sh"
    fi
}

check_env_path_inside() {
    local name="$1"
    local value="${!name:-}"
    if [ -z "$value" ]; then
        return 0
    fi
    case "$value" in
        "$HARNESS_ROOT"|"$HARNESS_ROOT"/*) ok "$name contained" ;;
        *) err "$name escapes harness root: $value" ;;
    esac
}

harness_setup_containment "$HARNESS_ROOT"

check_file "${HARNESS_ROOT}/config.toml" "config.toml"
check_file "${HARNESS_ROOT}/scripts/load-config.sh" "load-config script"
check_exec "${HARNESS_ROOT}/scripts/validate-phase.sh" "phase validation script"
check_exec "${HARNESS_ROOT}/scripts/wait-phase.sh" "phase wait script"

eval "$("${HARNESS_ROOT}/scripts/load-config.sh")"

if [ -n "${ON_PREM_LLM_BASE_URL:-}" ]; then
    ok "LLM endpoint configured (${ON_PREM_LLM_BASE_URL%%://*}://...)"
else
    err "llm.base_url is empty"
fi

if [ -n "${ON_PREM_MODEL_NAME:-}" ]; then
    ok "LLM model configured"
else
    err "llm.model is empty"
fi

check_exec "${HARNESS_ROOT}/bins/omp" "OMP binary"
check_exec "${HARNESS_ROOT}/bins/wraith" "Wraith binary"
check_exec "${HARNESS_ROOT}/bins/poltergeist" "Poltergeist binary"
check_exec "${HARNESS_ROOT}/bins/osv-scanner" "OSV scanner binary"
check_exec "${HARNESS_ROOT}/.venv/bin/graphify" "Graphify CLI"
check_exec "${HARNESS_ROOT}/.venv/bin/python" "Harness Python"

check_osv_db "${HARNESS_ROOT}/.harness/osv-db"

for agent in recon sca sast secrets triage intrusion reconcile reporter; do
    check_file "${HARNESS_ROOT}/config/agents/${agent}.md" "agent prompt: ${agent}"
done

check_file "${HARNESS_ROOT}/.omp/main/vulnops-main.md" "OMP main prompt"

if [ -e "${HARNESS_ROOT}/.omp/agents/vulnops-lead.md" ]; then
    err "vulnops-lead must be a main-process prompt, not a subagent"
else
    ok "vulnops-lead subagent absent"
fi

for agent in \
    vulnops-recon \
    vulnops-sca \
    vulnops-secrets \
    vulnops-sast-lead \
    vulnops-threatmodel \
    vulnops-decompose \
    vulnops-deepdive-chunk \
    vulnops-verify-one \
    vulnops-triage \
    vulnops-intrusion \
    vulnops-reconcile \
    vulnops-reporter; do
    check_file "${HARNESS_ROOT}/.omp/agents/${agent}.md" "OMP agent: ${agent}"
done

for skill in \
    vulnops-exclusion-rules \
    vulnops-self-verification \
    vulnops-severity-guidance \
    vulnops-access-control \
    vulnops-iac \
    vulnops-batch-etl \
    vulnops-logic-bug \
    vulnops-deserialization \
    vulnops-crypto; do
    check_file "${HARNESS_ROOT}/.omp/skills/${skill}/SKILL.md" "OMP skill: ${skill}"
done

agent_tool_report="${TMPDIR}/vulnops-omp-agent-web-tools.txt"
if grep -R -n -E '^[[:space:]]*-[[:space:]]*(web_search|browser)[[:space:]]*$' "${HARNESS_ROOT}/.omp/agents"/vulnops-*.md >"$agent_tool_report" 2>/dev/null; then
    err "OMP audit agents must not enable web_search or browser tools"
    sed 's/^/[validate-config]   /' "$agent_tool_report" >&2
else
    ok "OMP audit agents exclude web/browser tools"
fi

lead_launch_report="${TMPDIR}/vulnops-lead-launch.txt"
if grep -R -n -E 'agent:[[:space:]]*"vulnops-lead"|task\([^)]*vulnops-lead' "${HARNESS_ROOT}/AGENTS.md" "${HARNESS_ROOT}/.omp/main" >"$lead_launch_report" 2>/dev/null; then
    err "Main/docs must not launch vulnops-lead as a subagent"
    sed 's/^/[validate-config]   /' "$lead_launch_report" >&2
else
    ok "no active vulnops-lead subagent launch instruction"
fi

check_file "${HARNESS_ROOT}/schemas/phase-manifest.schema.json" "phase manifest schema"
check_file "${HARNESS_ROOT}/schemas/finding.schema.json" "finding schema"
check_file "${HARNESS_ROOT}/schemas/report.schema.json" "report schema"
check_file "${HARNESS_ROOT}/schemas/threat-model.schema.json" "threat model schema"
check_file "${HARNESS_ROOT}/schemas/task-manifest.schema.json" "task manifest schema"
check_file "${HARNESS_ROOT}/schemas/sast-raw-finding.schema.json" "SAST raw finding schema"
check_file "${HARNESS_ROOT}/schemas/sast-verified-finding.schema.json" "SAST verified finding schema"
check_file "${HARNESS_ROOT}/schemas/dropped-finding.schema.json" "dropped finding schema"
check_file "${HARNESS_ROOT}/schemas/agent-yield.schema.json" "agent yield schema"

check_file "${HARNESS_ROOT}/.omp/config.yml" "project OMP config"
check_file "${HARNESS_ROOT}/.omp/models.yml" "project OMP models"

for dir in \
    "$TMPDIR" \
    "$XDG_CACHE_HOME" \
    "$XDG_CONFIG_HOME" \
    "$XDG_DATA_HOME" \
    "$PIP_CACHE_DIR" \
    "$NPM_CONFIG_CACHE" \
    "$CARGO_HOME" \
    "$GOMODCACHE" \
    "$GOCACHE" \
    "$OMP_AGENT_HOME" \
    "$PI_CODING_AGENT_DIR" \
    "$PI_CONFIG_DIR"; do
    harness_require_inside_root "$HARNESS_ROOT" "$dir" "containment path" || errors=$((errors + 1))
done

for env_name in TMPDIR TMP TEMP XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME PIP_CACHE_DIR NPM_CONFIG_CACHE CARGO_HOME GOMODCACHE GOCACHE OMP_AGENT_HOME PI_CODING_AGENT_DIR PI_CONFIG_DIR HOME; do
    check_env_path_inside "$env_name"
done

if [ "$errors" -gt 0 ]; then
    echo "[validate-config] failed with ${errors} error(s)" >&2
    exit 1
fi

echo "[validate-config] ready for audit runtime"
