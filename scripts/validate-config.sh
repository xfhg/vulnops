#!/usr/bin/env bash
# Validate that the harness can run an audit without bootstrap/network setup.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"

errors=0
warnings=0
MIN_OSV_DB_FILES=3
MIN_OSV_DB_SIZE_KB=51200

err() {
    echo "[validate-config] ERROR: $*" >&2
    errors=$((errors + 1))
}

ok() {
    echo "[validate-config] OK: $*"
}

warn() {
    echo "[validate-config] WARN: $*" >&2
    warnings=$((warnings + 1))
}

check_exec_or_warn() {
    local path="$1"
    local label="$2"
    if [ -x "$path" ]; then
        echo "[validate-config] OK: $label"
    else
        warn "$label missing or not executable: $path"
    fi
}

check_codegraph_init() {
    local cg_index="${CODEGRAPH_INDEX_DIR:-${VULNOPSV3_SCANS:-${HARNESS_ROOT}/scans}/.codegraph}"
    local marker="${cg_index}/.codegraph-init-marker"
    if [ ! -x "${HARNESS_ROOT}/bins/codegraph" ]; then
        err "codegraph binary missing or not executable: ${HARNESS_ROOT}/bins/codegraph"
    elif [ ! -f "$marker" ]; then
        warn "codegraph not yet initialized (marker absent: $marker). It is indexed on the next audit run via scripts/setup-codegraph.sh; the binary check above is the hard gate, and phase gates enforce real codegraph output."
    fi
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

check_version_command() {
    local path="$1"
    local label="$2"
    local version
    if [ ! -x "$path" ]; then
        return
    fi
    version="$("$path" --version 2>/dev/null | head -n 1 || true)"
    if [ -n "$version" ]; then
        ok "${label} version: ${version}"
    else
        err "${label} --version produced no output"
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

check_scan_tool_config() {
    local py
    py="$(command -v python3 2>/dev/null || true)"
    if [ -z "$py" ]; then
        err "python3 not found for config consistency checks"
        return
    fi
    "$py" - "${HARNESS_ROOT}/config.toml" <<'PY' || err "scan tool config inconsistent"
from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    print("tomllib unavailable", file=sys.stderr)
    raise SystemExit(1)

path = Path(sys.argv[1])
with path.open("rb") as handle:
    cfg = tomllib.load(handle)

scans = cfg.get("harness", {}).get("scans", {})
errors: list[str] = []

sca = scans.get("sca", {})
if sca.get("binary") != "bins/wraith":
    errors.append("[harness.scans.sca].binary must be 'bins/wraith'")
sca_flags = sca.get("extra_flags", [])
if "--offline" not in sca_flags:
    errors.append("[harness.scans.sca].extra_flags must include '--offline'")

secrets = scans.get("secrets", {})
if secrets.get("binary") != "bins/poltergeist":
    errors.append("[harness.scans.secrets].binary must be 'bins/poltergeist'")
if secrets.get("extra_flags", []) != []:
    errors.append("[harness.scans.secrets].extra_flags must be []")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)
PY
    ok "scan tool config matches wrapper defaults"
}

check_model_roles() {
    local path="$1"
    local label="$2"
    local py
    py="$(command -v python3 2>/dev/null || true)"
    if [ -z "$py" ]; then
        err "python3 not found for OMP model role checks"
        return
    fi
    if "$py" - "$path" "${OMP_MODEL_SELECTOR:-}" <<'PY'; then
from __future__ import annotations

import sys
from pathlib import Path

path = Path(sys.argv[1])
expected = sys.argv[2]
required = [
    "default",
    "task",
    "slow",
    "smol",
    "plan",
    "advisor",
    "vision",
    "designer",
    "commit",
    "tiny",
]

roles: dict[str, str] = {}
in_roles = False
for raw in path.read_text().splitlines():
    if raw.startswith("modelRoles:"):
        in_roles = True
        continue
    if in_roles and raw and not raw.startswith((" ", "	")):
        in_roles = False
        continue
    if not in_roles:
        continue
    stripped = raw.strip()
    if not stripped or stripped.startswith("#") or ":" not in stripped:
        continue
    key, value = stripped.split(":", 1)
    roles[key.strip()] = value.strip().strip("'\"")

missing = [role for role in required if role not in roles]
wrong = [f"{role}={roles.get(role)!r}" for role in required if roles.get(role) != expected]
if missing or wrong:
    if missing:
        print("missing roles: " + ", ".join(missing), file=sys.stderr)
    if wrong:
        print("wrong roles: " + ", ".join(wrong), file=sys.stderr)
    raise SystemExit(1)
PY
        ok "${label} model roles use ${OMP_MODEL_SELECTOR}"
    else
        err "${label} model roles must all use ${OMP_MODEL_SELECTOR}"
    fi
}


harness_setup_containment "$HARNESS_ROOT"

check_file "${HARNESS_ROOT}/config.toml" "config.toml"
check_file "${HARNESS_ROOT}/scripts/load-config.sh" "load-config script"
check_exec "${HARNESS_ROOT}/scripts/bootstrap-omp.sh" "OMP bootstrap script"
check_exec "${HARNESS_ROOT}/scripts/audit-status.sh" "audit status script"
check_exec "${HARNESS_ROOT}/scripts/build-intelligence.py" "intelligence builder script"
check_exec "${HARNESS_ROOT}/scripts/validate-phase.sh" "phase validation script"
check_exec "${HARNESS_ROOT}/scripts/wait-phase.sh" "phase wait script"

eval "$("${HARNESS_ROOT}/scripts/load-config.sh")"

if [ "${OMP_MODEL_SELECTOR:-}" = "openai-codex/gpt-5.5:xhigh" ]; then
    ok "OMP model selector configured (${OMP_MODEL_SELECTOR})"
else
    err "llm.selector must be openai-codex/gpt-5.5:xhigh"
fi

if [[ "${OMP_MODEL_SELECTOR:-}" = openai-codex/* ]]; then
    ok "custom LLM endpoint not required for selected built-in provider"
elif [ -n "${ON_PREM_LLM_BASE_URL:-}" ]; then
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

check_exec "${HARNESS_ROOT}/bins/omp" "OMP binary"
check_exec "${HARNESS_ROOT}/bins/wraith" "Wraith binary"
check_exec "${HARNESS_ROOT}/bins/poltergeist" "Poltergeist binary"
check_exec "${HARNESS_ROOT}/bins/osv-scanner" "OSV scanner binary"
check_exec "${HARNESS_ROOT}/bins/codegraph" "codegraph AST toolkit (required)"
check_version_command "${HARNESS_ROOT}/bins/omp" "OMP binary"
check_version_command "${HARNESS_ROOT}/bins/wraith" "Wraith binary"
check_version_command "${HARNESS_ROOT}/bins/poltergeist" "Poltergeist binary"
check_version_command "${HARNESS_ROOT}/bins/osv-scanner" "OSV scanner binary"
check_version_command "${HARNESS_ROOT}/bins/codegraph" "codegraph AST toolkit"
check_scan_tool_config
check_codegraph_init
check_osv_db "${HARNESS_ROOT}/.harness/osv-db"

for agent in recon sca sast secrets intelligence triage intrusion reconcile; do
    check_file "${HARNESS_ROOT}/config/agents/${agent}.md" "agent prompt: ${agent}"
done

check_file "${HARNESS_ROOT}/.omp/main/vulnops-main.md" "OMP main prompt"

if [ -e "${HARNESS_ROOT}/.omp/agents/vulnops-lead.md" ]; then
    err "vulnops-lead must be a main-process prompt, not a subagent"
else
    ok "vulnops-lead subagent absent"
fi

for obsolete_reporter in \
    "${HARNESS_ROOT}/.omp/agents/vulnops-reporter.md" \
    "${HARNESS_ROOT}/config/agents/reporter.md"; do
    if [ -e "$obsolete_reporter" ]; then
        err "model-authored reporter must be absent: $obsolete_reporter"
    else
        ok "model-authored reporter absent"
    fi
done

for agent in \
    vulnops-recon \
    vulnops-recon-overview \
    vulnops-recon-trust \
    vulnops-recon-inputs \
    vulnops-sca \
    vulnops-secrets \
    vulnops-sast-lead \
    vulnops-threatmodel \
    vulnops-decompose \
    vulnops-deepdive-chunk \
    vulnops-verify-one \
    vulnops-reproduce-one \
    vulnops-intelligence \
    vulnops-triage \
    vulnops-intrusion \
    vulnops-reconcile \
    vulnops-final-verification \
    vulnops-independent-verify-one; do
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

for skill in \
    vulnops-audit-core \
    vulnops-attack-general \
    vulnops-attack-ai-llm \
    vulnops-attack-http-auth \
    vulnops-attack-client \
    vulnops-attack-native \
    vulnops-attack-mobile; do
    check_file "${HARNESS_ROOT}/.omp/skills/${skill}/SKILL.md" "OMP v2 skill: ${skill}"
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

history_uri_report="${TMPDIR}/vulnops-history-uri.txt"
if grep -R -n -E 'agent://|history://' "${HARNESS_ROOT}/.omp/main" >"$history_uri_report" 2>/dev/null; then
    err "Main prompt must not use agent:// or history:// transcript URIs; use OMP yield, IRC, and validation artifacts"
    sed 's/^/[validate-config]   /' "$history_uri_report" >&2
else
    ok "Main prompt avoids transcript URI tool-call hazards"
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

for schema in \
    run-manifest task-ledger recon-research repo-context security-surfaces \
    sca-advisories secrets-redacted \
    threat-model hunt-plan hunt-result \
    candidate-finding validation-result reproduction-result coverage-ledger \
    wishlist independent-verification-result final-findings report; do
    check_file "${HARNESS_ROOT}/schemas/v2/${schema}.schema.json" "v2 schema: ${schema}"
done

for script in \
    validate-json.py validate-phase-v2.py validate-scan-v2.py \
    target-fingerprint.py init-run.py update-run-state.py build-hunt-plan.py \
    finalize-sast.py run-safe-reproduction.sh redact-output.py \
    finalize-verification.py render-report.py; do
    check_exec "${HARNESS_ROOT}/scripts/${script}" "v2 runtime: ${script}"
done

case "${VULNOPS_DEFAULT_DEPTH:-quick}" in
    quick|balanced|full) ok "default audit depth is valid" ;;
    *) err "harness.default_depth must be quick, balanced, or full" ;;
esac
case "${VULNOPS_REPRODUCTION_MODE:-off}" in
    off|safe) ok "reproduction mode is valid" ;;
    *) err "harness.reproduction.mode must be off or safe" ;;
esac
case "${VULNOPS_REPRODUCTION_SANDBOX:-auto}" in
    auto|bubblewrap) ok "reproduction sandbox setting is valid" ;;
    *) err "harness.reproduction.sandbox must be auto or bubblewrap" ;;
esac
for numeric_var in \
    VULNOPS_REPRODUCTION_TIMEOUT_SECONDS \
    VULNOPS_REPRODUCTION_CPU_SECONDS \
    VULNOPS_REPRODUCTION_MEMORY_MB \
    VULNOPS_REPRODUCTION_MAX_PROCESSES \
    VULNOPS_REPRODUCTION_MAX_OUTPUT_KB \
    VULNOPS_REPRODUCTION_MAX_PARALLEL \
    VULNOPS_SAST_CONTEXT_PACKET_BYTES \
    VULNOPS_SAST_QUICK_MAX_HUNT_TASKS VULNOPS_SAST_QUICK_MAX_ATTEMPTS \
    VULNOPS_SAST_BALANCED_MAX_HUNT_TASKS VULNOPS_SAST_BALANCED_MAX_ATTEMPTS \
    VULNOPS_SAST_FULL_MAX_HUNT_TASKS VULNOPS_SAST_FULL_MAX_ATTEMPTS; do
    numeric_value="${!numeric_var:-}"
    if [[ "$numeric_value" =~ ^[1-9][0-9]*$ ]]; then
        ok "${numeric_var} is a positive integer"
    else
        err "${numeric_var} must be a positive integer"
    fi
done
for rounds_var in \
    VULNOPS_SAST_QUICK_MAX_GAPFILL_ROUNDS \
    VULNOPS_SAST_BALANCED_MAX_GAPFILL_ROUNDS \
    VULNOPS_SAST_FULL_MAX_GAPFILL_ROUNDS; do
    rounds_value="${!rounds_var:-}"
    if [[ "$rounds_value" =~ ^[0-9]+$ ]]; then
        ok "${rounds_var} is a non-negative integer"
    else
        err "${rounds_var} must be a non-negative integer"
    fi
done

if [ "${VULNOPS_REPRODUCTION_MODE:-off}" = "safe" ]; then
    if bash "${HARNESS_ROOT}/scripts/run-safe-reproduction.sh" "${HARNESS_ROOT}/scans" readiness detect >/dev/null 2>&1; then
        ok "safe reproduction sandbox available"
    else
        warn "safe reproduction requested but no proven sandbox is currently available; runtime findings will be environment-required"
    fi
fi

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
    missing_roles=()
    for role in default task slow smol plan advisor; do
        if ! grep -q "^[[:space:]]*${role}:[[:space:]]*[^[:space:]]" "${PI_CODING_AGENT_DIR}/config.yml"; then
            missing_roles+=("$role")
        fi
    done
    if [ "${#missing_roles[@]}" -eq 0 ]; then
        ok "harness-local OMP config has non-empty model roles"
    else
        err "harness-local OMP config missing model role(s): ${missing_roles[*]}"
    fi
    check_model_roles "${PI_CODING_AGENT_DIR}/config.yml" "harness-local OMP config"
fi

if [ -f "${HARNESS_ROOT}/.omp/config.yml" ]; then
    check_model_roles "${HARNESS_ROOT}/.omp/config.yml" "project OMP config"
fi

if [ -f "${PI_CODING_AGENT_DIR}/models.yml" ]; then
    if [[ "${OMP_MODEL_SELECTOR:-}" = openai-codex/* ]]; then
        if grep -F -q "claude-opus-4-6" "${PI_CODING_AGENT_DIR}/models.yml" ||
            grep -F -q "  on-prem:" "${PI_CODING_AGENT_DIR}/models.yml"; then
            err "harness-local OMP models contain stale custom provider state for built-in selector"
        else
            ok "harness-local OMP models neutral for built-in selector"
        fi
    else
        if grep -F -q "  ${OMP_PROVIDER_NAME}:" "${PI_CODING_AGENT_DIR}/models.yml" &&
            grep -F -q "baseUrl:" "${PI_CODING_AGENT_DIR}/models.yml" &&
            grep -F -q "${ON_PREM_MODEL_NAME:-}" "${PI_CODING_AGENT_DIR}/models.yml"; then
            ok "harness-local OMP models include configured custom provider/model"
        else
            err "harness-local OMP models missing configured custom provider/model"
        fi
        if grep -q 'apiKey:' "${PI_CODING_AGENT_DIR}/models.yml" || [ "${ON_PREM_PROVIDER_AUTH:-api-key}" = "none" ]; then
            ok "harness-local OMP models include auth material or no-auth mode"
        else
            err "harness-local OMP models missing apiKey for authenticated provider"
        fi
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

if [ "$errors" -gt 0 ] || [ "$warnings" -gt 0 ]; then
    if [ "$errors" -gt 0 ]; then
        echo "[validate-config] failed with ${errors} error(s), ${warnings} warning(s)" >&2
        exit 1
    fi
    echo "[validate-config] ready for audit runtime with ${warnings} warning(s)"
fi

if [ "$errors" -eq 0 ] && [ "$warnings" -eq 0 ]; then
    echo "[validate-config] ready for audit runtime"
fi
