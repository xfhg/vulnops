#!/usr/bin/env bash
# Greenfield V2 readiness gate: configuration, generated roles, contracts, and
# real contained tool probes must all succeed before an audit starts.
set -euo pipefail
HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"
errors=0
ok(){ echo "[validate-config] OK: $*"; }
err(){ echo "[validate-config] ERROR: $*" >&2; errors=$((errors+1)); }
check_file(){ [ -f "$1" ] && ok "$2" || err "$2 missing: $1"; }
check_exec(){ [ -x "$1" ] && ok "$2" || err "$2 missing or not executable: $1"; }

check_file "${HARNESS_ROOT}/config.toml" "config.toml"
eval "$("${HARNESS_ROOT}/scripts/load-config.sh")"

python3 - "${HARNESS_ROOT}/config.toml" <<'PY' || err "canonical configuration is invalid"
import re,sys,tomllib
from pathlib import Path
cfg=tomllib.loads(Path(sys.argv[1]).read_text())
def only(mapping,allowed,label):
    extra=set(mapping)-set(allowed)
    if extra:raise SystemExit(f"unknown {label} option(s): {', '.join(sorted(extra))}")
only(cfg,{"llm","harness"},"top-level")
llm=cfg.get("llm",{}); selector=str(llm.get("selector","")).strip(); verifier=str(llm.get("verification",{}).get("selector","")).strip() or selector;roles=llm.get("roles",{})
only(llm,{"base_url","api_key","selector","model","roles","verification","provider"},"llm")
only(roles,{"orchestrator","task","slow","smol"},"llm.roles")
only(llm.get("verification",{}),{"selector"},"llm.verification")
pattern=re.compile(r"^[^/\s]+/[^\s]+$")
role_values=[str(roles.get(name,selector)).strip() for name in ("orchestrator","task","slow","smol")]
if any(not pattern.fullmatch(value) for value in [selector,*role_values,verifier]):raise SystemExit("selectors must use provider/model syntax")
provider=llm.get("provider",{}); custom=str(provider.get("name","on-prem")); selected=[x for x in (selector,*role_values,verifier) if x.startswith(custom+"/")]
only(provider,{"name","api","auth","discovery","models"},"llm.provider")
for index,item in enumerate(provider.get("models",[])):
    only(item,{"id","name","context_window","max_tokens","contextWindow","maxTokens"},f"llm.provider.models[{index}]")
if selected and not str(llm.get("base_url","")).strip():raise SystemExit("selected custom provider requires llm.base_url")
if selected and provider.get("auth","api-key")!="none" and not str(llm.get("api_key","")).strip():raise SystemExit("selected custom provider requires llm.api_key")
harness=cfg.get("harness",{});only(harness,{"default_depth","scans","reproduction"},"harness")
if harness.get("default_depth") not in {"quick","balanced","full"}:raise SystemExit("harness.default_depth is invalid")
scans=harness.get("scans",{});only(scans,{"sast"},"harness.scans");sast=scans.get("sast",{});only(sast,{"context_packet_bytes","budget"},"harness.scans.sast")
if int(sast.get("context_packet_bytes",65536))<1024:raise SystemExit("SAST context_packet_bytes must be at least 1024")
for depth,item in sast.get("budget",{}).items():
    if depth not in {"quick","balanced","full"}:raise SystemExit(f"unknown SAST budget depth: {depth}")
    only(item,{"max_hunt_tasks","max_gapfill_rounds","max_attempts"},f"SAST {depth} budget")
    if int(item.get("max_hunt_tasks",0))<1 or int(item.get("max_attempts",0))<1 or int(item.get("max_gapfill_rounds",-1))<0:raise SystemExit(f"invalid SAST {depth} budget")
reproduction=harness.get("reproduction",{});only(reproduction,{"mode","sandbox","timeout_seconds","cpu_seconds","memory_mb","max_processes","max_output_kb","max_parallel"},"harness.reproduction")
if reproduction.get("mode","off") not in {"off","safe"} or reproduction.get("sandbox","auto") not in {"auto","bubblewrap"}:raise SystemExit("reproduction mode or sandbox is invalid")
for key in ("timeout_seconds","cpu_seconds","memory_mb","max_processes","max_output_kb","max_parallel"):
    if int(reproduction.get(key,1))<1:raise SystemExit(f"harness.reproduction.{key} must be positive")
text=Path(sys.argv[1]).read_text()
for obsolete in ("include_raw","scans.intelligence","scans.reconciliation"):
    if obsolete in text:raise SystemExit(f"obsolete configuration is forbidden: {obsolete}")
PY

for binary in omp wraith poltergeist osv-scanner codegraph; do check_exec "${HARNESS_ROOT}/bins/${binary}" "binary ${binary}"; done
omp_lock="${HARNESS_ROOT}/config/offline-pack.$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/').lock"
if [ ! -f "$omp_lock" ] && [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ]; then omp_lock="${HARNESS_ROOT}/config/offline-pack.lock"; fi
if [ -f "$omp_lock" ]; then
    expected_omp_version="$(sed -n 's/^OMP_VERSION=//p' "$omp_lock" | sed -n '1p')"
    expected_omp_sha="$(sed -n 's/^OMP_SHA256=//p' "$omp_lock" | sed -n '1p')"
    actual_omp_version="v$("${HARNESS_ROOT}/bins/omp" --version 2>/dev/null | sed -n 's#^omp/##p' | sed -n '1p')"
    if command -v sha256sum >/dev/null 2>&1; then actual_omp_sha="$(sha256sum "${HARNESS_ROOT}/bins/omp" | awk '{print $1}')"; else actual_omp_sha="$(shasum -a 256 "${HARNESS_ROOT}/bins/omp" | awk '{print $1}')"; fi
    [ "$actual_omp_version" = "$expected_omp_version" ] && ok "pinned OMP version ${expected_omp_version}" || err "OMP version ${actual_omp_version} does not match ${expected_omp_version}"
    [ "$actual_omp_sha" = "$expected_omp_sha" ] && ok "pinned OMP checksum" || err "OMP checksum does not match platform lock"
else
    err "OMP platform lock missing: $omp_lock"
fi
for script in run-audit.sh validate-phase.sh validate-scan.sh validate-omp-agents.py init-run.py resume-run.py update-run-state.py dependency_contract.py finalize-recon.py build-hunt-plan.py finalize-sast.py collect-tools.py run-wraith.sh run-poltergeist.sh normalize-wraith.py normalize-poltergeist.py setup-codegraph.sh codegraph-adapter.py build-evidence-index.py build-campaign-plan.py finalize-intrusion.py empty-synthesis.py finalize-synthesis.py finalize-verification.py render-report.py probe-bubblewrap.sh probe-toolchain.sh; do check_exec "${HARNESS_ROOT}/scripts/${script}" "runtime ${script}"; done
for schema in run-manifest task-ledger phase-manifest recon-research repo-context security-surfaces sca-advisories secrets-redacted tool-receipt tool-collection threat-model hunt-plan hunt-result candidate-finding validation-result reproduction-result coverage-ledger wishlist evidence-index campaign-plan intrusion-results synthesis-findings independent-verification-result final-findings report; do check_file "${HARNESS_ROOT}/schemas/v2/${schema}.schema.json" "schema ${schema}"; done
for agent in recon recon-overview recon-trust recon-inputs sast-lead threatmodel deepdive-chunk verify-one reproduce-one campaign-planning intrusion intrusion-campaign synthesis final-verification independent-verify-one; do check_file "${HARNESS_ROOT}/.omp/agents/vulnops-${agent}.md" "OMP agent ${agent}"; done
if python3 "${HARNESS_ROOT}/scripts/validate-omp-agents.py" "$HARNESS_ROOT"; then ok "canonical OMP agent graph"; else err "canonical OMP agent graph invalid"; fi
if grep -F -q 'scripts/finalize-recon.py' "${HARNESS_ROOT}/.omp/agents/vulnops-recon.md"; then ok "Recon uses deterministic finalization"; else err "Recon must use deterministic finalization"; fi
if grep -F -q 'from dependency_contract import' "${HARNESS_ROOT}/scripts/collect-tools.py" && grep -F -q 'discover_dependency_files' "${HARNESS_ROOT}/scripts/validate-json.py"; then ok "dependency handoff is single-sourced and semantically enforced"; else err "dependency handoff contract is not enforced end to end"; fi

for forbidden in "${HARNESS_ROOT}/config/harness.yaml" "${HARNESS_ROOT}/config/scan-criteria.yaml" "${HARNESS_ROOT}/V2UPGRADE.md" "${HARNESS_ROOT}/.omp/agents/vulnops-intelligence.md" "${HARNESS_ROOT}/.omp/agents/vulnops-triage.md" "${HARNESS_ROOT}/.omp/agents/vulnops-reconcile.md" "${HARNESS_ROOT}/.omp/agents/vulnops-decompose.md" "${HARNESS_ROOT}/.omp/agents/vulnops-tool-collection.md" "${HARNESS_ROOT}/.omp/agents/vulnops-sca.md" "${HARNESS_ROOT}/.omp/agents/vulnops-secrets.md"; do [ ! -e "$forbidden" ] && ok "obsolete artifact absent: ${forbidden#${HARNESS_ROOT}/}" || err "obsolete artifact must be removed: $forbidden"; done
if grep -R -n -E '(^|[[:space:]])(web_search|browser)([[:space:]]|$)' "${HARNESS_ROOT}/.omp/agents" >/dev/null 2>&1; then err "audit agents may not enable web or browser tools"; else ok "audit agents are offline-only"; fi
if [ -e "${HARNESS_ROOT}/.omp/agents/vulnops-reporter.md" ]; then err "model-authored reporting agent is forbidden"; else ok "reporting remains deterministic"; fi

for selector_name in OMP_MODEL_SELECTOR OMP_ORCHESTRATOR_MODEL_SELECTOR OMP_TASK_MODEL_SELECTOR OMP_SLOW_MODEL_SELECTOR OMP_SMOL_MODEL_SELECTOR OMP_VERIFIER_MODEL_SELECTOR; do
    value="${!selector_name:-}"; [[ "$value" =~ ^[^/[:space:]]+/[^[:space:]]+$ ]] && ok "$selector_name syntax" || err "$selector_name syntax invalid"
done

python3 - "${PI_CODING_AGENT_DIR}/config.yml" "${OMP_MODEL_SELECTOR:-}" "${OMP_ORCHESTRATOR_MODEL_SELECTOR:-}" "${OMP_TASK_MODEL_SELECTOR:-}" "${OMP_SLOW_MODEL_SELECTOR:-}" "${OMP_SMOL_MODEL_SELECTOR:-}" "${OMP_VERIFIER_MODEL_SELECTOR:-}" <<'PY' || err "generated model roles do not match selectors"
import sys
from pathlib import Path
path=Path(sys.argv[1]); primary,orchestrator,task,slow,smol,verifier=sys.argv[2:]
if not path.is_file():raise SystemExit("generated OMP config missing")
roles={};active=False
for line in path.read_text().splitlines():
    if line.startswith("modelRoles:"):active=True;continue
    if active and line and not line.startswith((" ","\t")):active=False
    if active and ":" in line:
        k,v=line.strip().split(":",1);roles[k]=v.strip().strip("'\"")
expected={"default":orchestrator,"task":task,"slow":slow,"smol":smol,"plan":task,"advisor":orchestrator,"vision":primary,"designer":primary,"commit":smol,"tiny":smol,"primary":primary}
for role,value in expected.items():
    if roles.get(role)!=value:raise SystemExit(f"{role} mismatch")
if roles.get("verifier")!=verifier:raise SystemExit("verifier role mismatch")
PY

custom_provider="${ON_PREM_PROVIDER_NAME:-on-prem}"
custom_models=()
for selector in "${OMP_MODEL_SELECTOR:-}" "${OMP_ORCHESTRATOR_MODEL_SELECTOR:-}" "${OMP_TASK_MODEL_SELECTOR:-}" "${OMP_SLOW_MODEL_SELECTOR:-}" "${OMP_SMOL_MODEL_SELECTOR:-}" "${OMP_VERIFIER_MODEL_SELECTOR:-}"; do
    if [[ "$selector" = "${custom_provider}/"* ]]; then custom_models+=("${selector#*/}"); fi
done
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

if [ ! -d "${HARNESS_ROOT}/.harness/osv-db" ]; then err "local OSV database missing"; else ok "local OSV database present"; fi
if [ "${VULNOPS_SKIP_FUNCTIONAL_PROBES:-0}" = "1" ]; then
    ok "functional probes explicitly skipped for fixture testing"
elif bash "${HARNESS_ROOT}/scripts/probe-toolchain.sh"; then ok "contained toolchain functional probe"; else err "contained toolchain functional probe failed"; fi
if [ "${VULNOPS_REPRODUCTION_MODE:-off}" = "safe" ]; then
    if "${HARNESS_ROOT}/scripts/probe-bubblewrap.sh" >/dev/null 2>&1; then ok "bubblewrap isolation probe"; else echo "[validate-config] WARN: safe reproduction unavailable; findings will require environment evidence" >&2; fi
fi

if [ "$errors" -gt 0 ]; then echo "[validate-config] failed with ${errors} error(s)" >&2; exit 1; fi
echo "[validate-config] ready for canonical V2 audit runtime"
