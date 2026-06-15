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
check_exec "${HARNESS_ROOT}/scripts/bootstrap-omp.sh" "OMP bootstrap script"
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

OMP_PROVIDER_NAME="${ON_PREM_PROVIDER_NAME:-on-prem}"
OMP_MODEL_SELECTOR="${OMP_PROVIDER_NAME}/${ON_PREM_MODEL_NAME:-}"

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

agent_irc_report="${TMPDIR}/vulnops-omp-agent-missing-irc.txt"
grep -L -E '^[[:space:]]*-[[:space:]]*irc[[:space:]]*$' "${HARNESS_ROOT}/.omp/agents"/vulnops-*.md >"$agent_irc_report" 2>/dev/null || true
if [ -s "$agent_irc_report" ]; then
    err "OMP audit agents must enable irc for live progress"
    sed 's/^/[validate-config]   /' "$agent_irc_report" >&2
else
    ok "OMP audit agents enable irc"
fi

if grep -q -- '--tools "[^"]*irc' "${HARNESS_ROOT}/run.sh"; then
    ok "run.sh exposes irc tool"
else
    err "run.sh --tools must include irc"
fi

lead_launch_report="${TMPDIR}/vulnops-lead-launch.txt"
if grep -R -n -E 'agent:[[:space:]]*"vulnops-lead"|task\([^)]*vulnops-lead' "${HARNESS_ROOT}/AGENTS.md" "${HARNESS_ROOT}/.omp/main" >"$lead_launch_report" 2>/dev/null; then
    err "Main/docs must not launch vulnops-lead as a subagent"
    sed 's/^/[validate-config]   /' "$lead_launch_report" >&2
else
    ok "no active vulnops-lead subagent launch instruction"
fi

main_polling_report="${TMPDIR}/vulnops-main-polling.txt"
if grep -R -n -E 'sleep[[:space:]]+[0-9]|find[[:space:]].*scans|ls[[:space:]].*scans|wait and check files|wait-phase\.sh[[:space:]].*(1800|3600)' "${HARNESS_ROOT}/AGENTS.md" "${HARNESS_ROOT}/.omp/main" >"$main_polling_report" 2>/dev/null; then
    err "Main/docs contain active Bash polling orchestration patterns"
    sed 's/^/[validate-config]   /' "$main_polling_report" >&2
else
    ok "Main/docs avoid Bash polling orchestration patterns"
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
check_file "${PI_CODING_AGENT_DIR}/config.yml" "harness-local OMP config"
check_file "${PI_CODING_AGENT_DIR}/models.yml" "harness-local OMP models"

if [ -f "${PI_CODING_AGENT_DIR}/config.yml" ]; then
    if grep -q '^setupVersion:[[:space:]]*1[[:space:]]*$' "${PI_CODING_AGENT_DIR}/config.yml" &&
        grep -q '^[[:space:]]*setupWizard:[[:space:]]*false[[:space:]]*$' "${PI_CODING_AGENT_DIR}/config.yml"; then
        ok "OMP onboarding disabled in harness-local config"
    else
        err "harness-local OMP config must disable setup wizard and set setupVersion: 1"
    fi
    if grep -F -q "${OMP_MODEL_SELECTOR}" "${PI_CODING_AGENT_DIR}/config.yml"; then
        ok "harness-local OMP config enables ${OMP_MODEL_SELECTOR}"
    else
        err "harness-local OMP config missing model selector: ${OMP_MODEL_SELECTOR}"
    fi
fi

if [ -f "${PI_CODING_AGENT_DIR}/models.yml" ]; then
    if grep -F -q "  ${OMP_PROVIDER_NAME}:" "${PI_CODING_AGENT_DIR}/models.yml" &&
        grep -F -q "baseUrl:" "${PI_CODING_AGENT_DIR}/models.yml" &&
        grep -F -q "${ON_PREM_MODEL_NAME:-}" "${PI_CODING_AGENT_DIR}/models.yml"; then
        ok "harness-local OMP models include configured on-prem model"
    else
        err "harness-local OMP models missing configured provider/model"
    fi
    if grep -q 'apiKey:' "${PI_CODING_AGENT_DIR}/models.yml" || [ "${ON_PREM_PROVIDER_AUTH:-api-key}" = "none" ]; then
        ok "harness-local OMP models include auth material or no-auth mode"
    else
        err "harness-local OMP models missing apiKey for authenticated provider"
    fi
fi

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
