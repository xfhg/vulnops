#!/usr/bin/env bash
# VulnOps V5 readiness gate: configuration, generated roles, contracts, and
# required contained tool probes must succeed; Codegraph is optional.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
CONFIG_PATH="${VULNOPS_CONFIG_PATH:-${HARNESS_ROOT}/config.toml}"
MODE="${1:---live}"
case "$MODE" in
    --live|--offline) ;;
    *) echo "usage: validate-config.sh [--live|--offline]" >&2; exit 2 ;;
esac
errors=0
ok(){ echo "[validate-config] OK: $*"; }
err(){ echo "[validate-config] ERROR: $*" >&2; errors=$((errors+1)); }
check_file(){ [ -f "$1" ] && ok "$2" || err "$2 missing: $1"; }
check_exec(){ [ -x "$1" ] && ok "$2" || err "$2 missing or not executable: $1"; }

check_file "$CONFIG_PATH" "configuration"
if python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
    ok "system Python is 3.11 or newer"
else
    err "system Python 3.11 or newer is required"
fi
config_exports="$("${HARNESS_ROOT}/scripts/load-config.sh")" || exit 1
eval "$config_exports"

python3 "${HARNESS_ROOT}/scripts/validate-configuration.py" "$CONFIG_PATH" \
    || err "canonical configuration is invalid"

offline_package=false
if [ -f "${HARNESS_ROOT}/offline-pack-manifest.json" ]; then
    offline_package=true
    if python3 "${HARNESS_ROOT}/scripts/offline_package.py" validate-package-config \
        "$CONFIG_PATH"; then
        ok "offline package configuration parses"
    else
        err "offline package configuration is invalid"
    fi
fi

for binary in omp wraith poltergeist osv-scanner; do check_exec "${HARNESS_ROOT}/bins/${binary}" "binary ${binary}"; done
if [ "${VULNOPS_CODEGRAPH_MODE:-enabled}" = "disabled" ]; then
    ok "optional Codegraph disabled; source-only audit"
elif [ -x "${HARNESS_ROOT}/bins/codegraph" ]; then
    ok "optional Codegraph binary available"
else
    echo "[validate-config] WARN: optional Codegraph unavailable; source-only audit" >&2
fi
platform="$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')"
tool_lock="${HARNESS_ROOT}/config/offline-pack.${platform}.lock.json"
if [ -f "$tool_lock" ] && python3 "${HARNESS_ROOT}/scripts/offline_package.py" validate-tool-lock "$tool_lock" --platform "$platform"; then
    expected_omp_version="$(python3 "${HARNESS_ROOT}/scripts/offline_package.py" tool-field "$tool_lock" omp version)"
    actual_omp_version="v$("${HARNESS_ROOT}/bins/omp" --version 2>/dev/null | sed -n 's#^omp/##p' | sed -n '1p')"
    if [ "$actual_omp_version" != "$expected_omp_version" ]; then
        err "OMP upgrade required: installed ${actual_omp_version}, required ${expected_omp_version}. Run: bash scripts/install-tools.sh omp"
        exit 1
    fi
    ok "OMP version ${expected_omp_version}"
    expected_omp_sha="$(python3 "${HARNESS_ROOT}/scripts/offline_package.py" tool-field "$tool_lock" omp sha256)"
    if command -v sha256sum >/dev/null 2>&1; then actual_omp_sha="$(sha256sum "${HARNESS_ROOT}/bins/omp" | awk '{print $1}')"; else actual_omp_sha="$(shasum -a 256 "${HARNESS_ROOT}/bins/omp" | awk '{print $1}')"; fi
    if [ "$actual_omp_sha" != "$expected_omp_sha" ]; then
        err "OMP executable differs from the verified release. Reinstall it with: bash scripts/install-tools.sh omp"
        exit 1
    fi
    expected_runtime_version="$(python3 "${HARNESS_ROOT}/scripts/offline_package.py" runtime-field "$tool_lock" omp-natives version)"
    actual_runtime_version="$(sed -n '1p' "${HARNESS_ROOT}/bins/.omp-natives.version" 2>/dev/null || true)"
    if [ "$actual_runtime_version" != "$expected_runtime_version" ] || ! python3 "${HARNESS_ROOT}/scripts/offline_package.py" verify-runtime-install "$tool_lock" omp-natives "${HARNESS_ROOT}/bins" >/dev/null 2>&1; then
        err "OMP ${expected_omp_version} dependencies are incomplete or from another release. Run: bash scripts/install-tools.sh omp"
        exit 1
    fi
    ok "OMP executable and native dependencies verified"
else
    err "strict platform tool lock missing or invalid: $tool_lock"
fi
for script in run-audit.sh run-remediation.sh validate-phase.sh validate-scan.sh validate-remediation.py validate-omp-agents.py init-run.py init-remediation.py resume-run.py recover-run.py update-run-state.py update-remediation-state.py dependency_contract.py finalize-recon.py build-hunt-plan.py finalize-sast.py sast_contract.py harness_contract.py remediation_contract.py build-remediation-plan.py prepare-remediation-work.py publish-remediation-patch.py finalize-remediation.py remediation-status.sh collect-tools.py run-wraith.sh run-poltergeist.sh normalize-wraith.py normalize-poltergeist.py setup-codegraph.sh codegraph-adapter.py build-evidence-index.py build-campaign-plan.py finalize-intrusion.py empty-synthesis.py finalize-synthesis.py finalize-verification.py render-report.py agent-shell.sh agent-shell-isolator.sh run-safe-reproduction.sh safe-reproduction-backend.sh probe-agent-isolation.sh probe-bubblewrap.sh probe-toolchain.sh probe-verifier-model.py offline_package.py osv_snapshot.py; do check_exec "${HARNESS_ROOT}/scripts/${script}" "runtime ${script}"; done
for module in artifact_policy.py campaign_contract.py codegraph_contract.py codegraph_setup.py close-interrupted-run.py close-interrupted-remediation.py model_identity.py remediation_common.py run_lifecycle.py probe-omp-lifecycle.py set-omp-deadline.py validate-configuration.py; do check_file "${HARNESS_ROOT}/scripts/${module}" "runtime ${module}"; done
check_exec "${HARNESS_ROOT}/remediate.sh" "linked remediation launcher"
check_file "${HARNESS_ROOT}/.omp/main/vulnops-remediation-main.md" "linked remediation controller"
for schema in run-manifest task-ledger phase-manifest recon-research repo-context security-surfaces sca-advisories secrets-redacted tool-receipt codegraph-context tool-collection dependency-limitations threat-model hunt-plan hunt-result candidate-finding validation-result reproduction-result coverage-ledger wishlist evidence-index campaign-discovery campaign-plan intrusion-results synthesis-findings independent-verification-result final-findings report remediation-manifest remediation-plan remediation-packet remediation-worker-result remediation-patch-receipt remediation; do check_file "${HARNESS_ROOT}/schemas/v2/${schema}.schema.json" "schema ${schema}"; done
for agent in recon recon-overview recon-trust recon-inputs threat-hunter threatmodel deepdive-chunk verify-one reproduce-one campaign-planning intrusion intrusion-campaign synthesis final-verification independent-verify-one remediation remediate-one; do check_file "${HARNESS_ROOT}/.omp/agents/vulnops-${agent}.md" "OMP agent ${agent}"; done
if python3 "${HARNESS_ROOT}/scripts/validate-omp-agents.py" "$HARNESS_ROOT"; then ok "canonical OMP agent graph"; else err "canonical OMP agent graph invalid"; fi
if python3 "${HARNESS_ROOT}/scripts/offline_package.py" verify-advantage-sources "$HARNESS_ROOT"; then
    ok "native Advantage launchers, contracts, agents, and fourteen skills"
else
    err "native Advantage source inventory is incomplete"
fi
if grep -F -q 'scripts/finalize-recon.py' "${HARNESS_ROOT}/.omp/agents/vulnops-recon.md"; then ok "Recon uses deterministic finalization"; else err "Recon must use deterministic finalization"; fi
if grep -F -q 'from dependency_contract import' "${HARNESS_ROOT}/scripts/collect-tools.py" && grep -F -q 'discover_dependency_files' "${HARNESS_ROOT}/scripts/validate-json.py"; then ok "dependency handoff is single-sourced and semantically enforced"; else err "dependency handoff contract is not enforced end to end"; fi

for forbidden in "${HARNESS_ROOT}/config/harness.yaml" "${HARNESS_ROOT}/config/scan-criteria.yaml" "${HARNESS_ROOT}/V2UPGRADE.md" "${HARNESS_ROOT}/.omp/agents/vulnops-intelligence.md" "${HARNESS_ROOT}/.omp/agents/vulnops-triage.md" "${HARNESS_ROOT}/.omp/agents/vulnops-reconcile.md" "${HARNESS_ROOT}/.omp/agents/vulnops-decompose.md" "${HARNESS_ROOT}/.omp/agents/vulnops-tool-collection.md" "${HARNESS_ROOT}/.omp/agents/vulnops-sca.md" "${HARNESS_ROOT}/.omp/agents/vulnops-secrets.md"; do [ ! -e "$forbidden" ] && ok "obsolete artifact absent: ${forbidden#${HARNESS_ROOT}/}" || err "obsolete artifact must be removed: $forbidden"; done
if grep -R -n -E '(^|[[:space:]])(web_search|browser)([[:space:]]|$)' "${HARNESS_ROOT}/.omp/agents" >/dev/null 2>&1; then err "audit agents may not enable web or browser tools"; else ok "audit agents are offline-only"; fi
if [ -e "${HARNESS_ROOT}/.omp/agents/vulnops-reporter.md" ]; then err "model-authored reporting agent is forbidden"; else ok "reporting remains deterministic"; fi

python3 - "${PI_CODING_AGENT_DIR}/config.yml" "${HARNESS_ROOT}" <<'PY' || err "generated model configuration does not match routing or configured shell"
import re,sys
from pathlib import Path
path=Path(sys.argv[1]); root=Path(sys.argv[2])
sys.path.insert(0,str(root/"scripts"))
from model_routing import load_routing, split_selector, read_agent_overrides
routing=load_routing(root); primary=routing["groups"]["audit_lead"]; shell_path=str(root/"scripts/agent-shell.sh")
if not path.is_file():raise SystemExit("generated OMP config missing")
text=path.read_text()
roles={};overrides=read_agent_overrides(path);section=None;configured_shell=None
for line in text.splitlines():
    if line.startswith("shellPath:"):configured_shell=line.split(":",1)[1].strip().strip("'\"")
    if line.startswith("modelRoles:"):section="roles";continue
    if line.startswith("task:"):section="task";continue
    if section and line and not line.startswith((" ","\t")):section=None
    if section=="roles" and ":" in line:
        k,v=line.strip().split(":",1);roles[k]=v.strip().strip("'\"")
expected={role:primary for role in ("default","task","slow","smol","plan","advisor","vision","designer","commit","tiny")}
for role,value in expected.items():
    if roles.get(role)!=value:raise SystemExit(f"{role} mismatch")
for unsupported in ("primary","verifier"):
    if unsupported in roles:raise SystemExit(f"unsupported OMP model role present: {unsupported}")
if overrides!=routing["agents"]:raise SystemExit("canonical agent model overrides mismatch")
if f"defaultThinkingLevel: {split_selector(primary)[2]}" not in text.splitlines():raise SystemExit("default reasoning mismatch")
if configured_shell!=shell_path:raise SystemExit("offline shellPath mismatch")
PY

if python3 "${HARNESS_ROOT}/scripts/probe-verifier-model.py" "${HARNESS_ROOT}/bins/omp" --root "$HARNESS_ROOT" "$MODE"; then
    ok "all model routes ${MODE#--} readiness"
else
    err "model routing readiness failed"
fi

custom_provider="${ON_PREM_PROVIDER_NAME:-on-prem}"
custom_models=()
while IFS= read -r model_id; do
    custom_models+=("$model_id")
done < <(python3 - "$HARNESS_ROOT" "$custom_provider" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1])/"scripts"))
from model_routing import load_routing, split_selector
for provider,model,effort in sorted(set(map(split_selector,load_routing(Path(sys.argv[1]))["groups"].values()))):
    if provider==sys.argv[2]:print(model)
PY
)
models_file="${PI_CODING_AGENT_DIR}/models.yml"
if [ "${#custom_models[@]}" -gt 0 ]; then
    check_file "$models_file" "generated custom model registry"
    if [ -f "$models_file" ] && grep -F -q "  ${custom_provider}:" "$models_file"; then ok "configured custom provider registered"; else err "configured custom provider missing from models.yml"; fi
    for model_id in "${custom_models[@]}"; do
        if [ -f "$models_file" ] && grep -F -q -- "- id: '${model_id}'" "$models_file"; then ok "custom model registered: ${custom_provider}/${model_id}"; else err "selected custom model missing from models.yml: ${custom_provider}/${model_id}"; fi
    done
elif [ -f "$models_file" ] && grep -F -q "  ${custom_provider}:" "$models_file"; then
    err "stale custom provider remains in models.yml"
else
    ok "built-in selectors require no generated custom provider"
fi

if python3 "${HARNESS_ROOT}/scripts/osv_snapshot.py" verify --lock "${HARNESS_ROOT}/config/osv-snapshot.lock.json" --cache-root "${HARNESS_ROOT}/.harness/osv-db"; then
    ok "complete checksum-pinned OSV database snapshot"
else
    err "complete checksum-pinned OSV database snapshot missing or invalid"
fi
if [ "$offline_package" = true ]; then
    if python3 "${HARNESS_ROOT}/scripts/offline_package.py" verify-manifest "$HARNESS_ROOT" "${HARNESS_ROOT}/offline-pack-manifest.json" >/dev/null; then
        ok "offline package immutable inventory"
    else
        err "offline package immutable inventory mismatch"
    fi
fi
if [ "${VULNOPS_SKIP_FUNCTIONAL_PROBES:-0}" = "1" ]; then
    ok "functional probes explicitly bypassed for fixture testing; NOT live readiness"
elif bash "${HARNESS_ROOT}/scripts/probe-toolchain.sh" "$MODE"; then ok "contained toolchain ${MODE#--} functional probe"; else err "contained toolchain functional probe failed"; fi
case "${VULNOPS_LINUX_AGENT_EGRESS:-enforced}" in
    enforced|policy_only) ;;
    *) err "invalid Linux agent egress mode" ;;
esac
if [ "$(uname -s)" = "Linux" ] && [ "${VULNOPS_LINUX_AGENT_EGRESS:-enforced}" = "enforced" ]; then
    if [ "${VULNOPS_SKIP_FUNCTIONAL_PROBES:-0}" = "1" ]; then
        ok "agent network-isolation probe explicitly skipped for fixture testing"
    elif "${HARNESS_ROOT}/scripts/probe-agent-isolation.sh" >/dev/null; then
        ok "Linux agent network isolation"
    else
        err "enforced Linux agent egress requires working bubblewrap network isolation"
    fi
elif [ "$(uname -s)" = "Darwin" ] && [ "${VULNOPS_LINUX_AGENT_EGRESS:-enforced}" != "policy_only" ]; then
    err "Darwin requires explicit policy_only agent egress mode"
else
    ok "agent egress policy mode: ${VULNOPS_LINUX_AGENT_EGRESS:-enforced}"
fi
if [ "${VULNOPS_REPRODUCTION_MODE:-off}" = "safe" ]; then
    if "${HARNESS_ROOT}/scripts/probe-bubblewrap.sh" >/dev/null 2>&1; then ok "bubblewrap isolation probe"; else echo "[validate-config] WARN: safe reproduction unavailable; findings will require environment evidence" >&2; fi
fi

if [ "$errors" -gt 0 ]; then echo "[validate-config] failed with ${errors} error(s)" >&2; exit 1; fi
if [ "${VULNOPS_SKIP_FUNCTIONAL_PROBES:-0}" = "1" ]; then
    echo "[validate-config] fixture configuration accepted; live readiness NOT checked"
elif [ "$MODE" = "--offline" ]; then
    echo "[validate-config] offline configuration valid; live readiness NOT checked"
else
    echo "[validate-config] ready for canonical VulnOps V5 audit runtime"
fi
