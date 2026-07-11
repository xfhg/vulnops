#!/usr/bin/env bash
# Seed harness-local OMP state from config.toml without interactive setup.

set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# shellcheck source=scripts/harness-lib.sh
source "${HARNESS_ROOT}/scripts/harness-lib.sh"
harness_setup_containment "$HARNESS_ROOT"

PYTHON="$(command -v python3 2>/dev/null || true)"

if [ -z "$PYTHON" ]; then
    echo "[bootstrap-omp] python3 not found" >&2
    exit 1
fi

CONFIG_PATH="${VULNOPS_CONFIG_PATH:-${HARNESS_ROOT}/config.toml}"
PROJECT_CONFIG_PATH="${VULNOPS_PROJECT_OMP_CONFIG:-${HARNESS_ROOT}/.omp/config.yml}"
AGENT_DIR="${VULNOPS_BOOTSTRAP_AGENT_DIR:-${PI_CODING_AGENT_DIR}}"
"$PYTHON" - "$HARNESS_ROOT" "$CONFIG_PATH" "$PROJECT_CONFIG_PATH" "$AGENT_DIR" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    print("[bootstrap-omp] Python 3.11+ tomllib is required", file=sys.stderr)
    raise SystemExit(1)


def q(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text.replace("'", "''") + "'"


def normalize_auth(value: object) -> str:
    raw = str(value or "api-key").strip().lower().replace("_", "-")
    if raw in {"none", "no-auth", "noauth", "anonymous"}:
        return "none"
    return "apiKey"


def as_optional_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        return
    path.write_text(content)


root = Path(sys.argv[1]).resolve()
config_path = Path(sys.argv[2]).resolve()
project_config_path = Path(sys.argv[3]).resolve()
if not config_path.exists():
    print(f"[bootstrap-omp] missing config.toml: {config_path}", file=sys.stderr)
    raise SystemExit(1)

with config_path.open("rb") as handle:
    cfg = tomllib.load(handle)

llm = cfg.get("llm", {})
provider = llm.get("provider", {})

provider_name = str(provider.get("name") or "on-prem")
base_url = str(llm.get("base_url") or "").rstrip("/")
api_key = str(llm.get("api_key") or "")
model_id = str(llm.get("model") or "")
selector = str(llm.get("selector") or "").strip()
roles = llm.get("roles") or {}
orchestrator_selector = str(roles.get("orchestrator") or selector).strip()
task_selector = str(roles.get("task") or selector).strip()
slow_selector = str(roles.get("slow") or selector).strip()
smol_selector = str(roles.get("smol") or selector).strip()
verifier_selector = str(llm.get("verification", {}).get("selector") or "").strip()
api = str(provider.get("api") or "openai-completions")
auth = normalize_auth(provider.get("auth", "api-key"))

if not selector:
    print("[bootstrap-omp] llm.selector is required", file=sys.stderr)
    raise SystemExit(1)

if not verifier_selector:
    verifier_selector = selector

def split_selector(value: str, label: str) -> tuple[str, str]:
    selected_provider, sep, selected_model = value.partition("/")
    if (
        not sep
        or not selected_provider
        or not selected_model
        or any(char.isspace() for char in value)
    ):
        print(f"[bootstrap-omp] invalid {label}: {value!r}", file=sys.stderr)
        raise SystemExit(1)
    return selected_provider, selected_model

selector_provider, selector_model = split_selector(selector, "llm.selector")
orchestrator_provider, orchestrator_model = split_selector(orchestrator_selector, "llm.roles.orchestrator")
task_provider, task_model = split_selector(task_selector, "llm.roles.task")
slow_provider, slow_model = split_selector(slow_selector, "llm.roles.slow")
smol_provider, smol_model = split_selector(smol_selector, "llm.roles.smol")
verifier_provider, verifier_model = split_selector(verifier_selector, "llm.verification.selector")
custom_models = list(dict.fromkeys(
    selected_model
    for selected_provider, selected_model in (
        (selector_provider, selector_model),
        (orchestrator_provider, orchestrator_model),
        (task_provider, task_model),
        (slow_provider, slow_model),
        (smol_provider, smol_model),
        (verifier_provider, verifier_model),
    )
    if selected_provider == provider_name
))
custom_provider_selected = bool(custom_models)
if custom_provider_selected and not base_url:
    print("[bootstrap-omp] llm.base_url is empty for selected custom provider", file=sys.stderr)
    raise SystemExit(1)
if custom_provider_selected and auth != "none" and not api_key:
    print("[bootstrap-omp] llm.api_key is empty for authenticated custom provider", file=sys.stderr)
    raise SystemExit(1)
if selector_provider == provider_name and model_id and model_id != selector_model:
    print("[bootstrap-omp] llm.model does not match the custom llm.selector model", file=sys.stderr)
    raise SystemExit(1)

agent_dir = Path(sys.argv[4]).resolve()

role_selectors = {
    "default": orchestrator_selector,
    "task": task_selector,
    "slow": slow_selector,
    "smol": smol_selector,
    "plan": task_selector,
    "advisor": orchestrator_selector,
    "vision": selector,
    "designer": selector,
    "commit": smol_selector,
    "tiny": smol_selector,
}

config_lines = [
    "# Auto-generated by scripts/bootstrap-omp.sh. Do not edit.",
    "# Source of truth: config.toml.",
    "",
    "setupVersion: 1",
    "startup:",
    "  setupWizard: false",
    "",
    "modelRoles:",
]
config_lines.extend(f"  {role}: {q(value)}" for role, value in role_selectors.items())
config_lines.append(f"  primary: {q(selector)}")
config_lines.append(f"  verifier: {q(verifier_selector)}")
config_lines.extend(
    [
        "",
        "memory:",
        "  enabled: false",
        "autolearn:",
        "  enabled: false",
        "web_search:",
        "  enabled: false",
        "browser:",
        "  enabled: false",
        "search:",
        "  enabled: false",
        "remote:",
        "  enabled: false",
        "defaultThinkingLevel: low",
        "async:",
        "  enabled: true",
        "  maxJobs: 32",
        "  pollWaitDuration: smart",
        "task:",
        "  batch: true",
        "  maxConcurrency: 16",
        "  maxRecursionDepth: 2",
        "  isolation:",
        "    mode: none",
        "tools:",
        "  approvalMode: yolo",
        "advisor:",
        "  enabled: false",
        "  subagents: false",
        "  immuneTurns: 3",
        "",
    ]
)

models = provider.get("models") or []
model_records = {
    str(item.get("id") or ""): item
    for item in models
    if isinstance(item, dict) and str(item.get("id") or "")
}
discovery = str(provider.get("discovery") or "proxy").strip().lower()
if custom_provider_selected and discovery == "explicit":
    missing = [selected for selected in custom_models if selected not in model_records]
    if missing:
        print(
            "[bootstrap-omp] explicit custom provider is missing selected model(s): "
            + ", ".join(missing),
            file=sys.stderr,
        )
        raise SystemExit(1)

if custom_provider_selected:
    models_lines = [
        "# Auto-generated by scripts/bootstrap-omp.sh. Do not edit.",
        "# Source of truth: config.toml.",
        "",
        "providers:",
        f"  {provider_name}:",
        f"    baseUrl: {q(base_url)}",
        f"    api: {q(api)}",
        f"    auth: {q(auth)}",
    ]
    if auth != "none":
        models_lines.append(f"    apiKey: {q(api_key)}")
    models_lines.append("    models:")
    for selected_model in custom_models:
        model_record = model_records.get(selected_model, {})
        model_name = str(model_record.get("name") or selected_model.split("/")[-1])
        context_window = as_optional_int(model_record.get("contextWindow", model_record.get("context_window")))
        max_tokens = as_optional_int(model_record.get("maxTokens", model_record.get("max_tokens")))
        models_lines.extend(
            [
                f"      - id: {q(selected_model)}",
                f"        name: {q(model_name)}",
            ]
        )
        # Emit endpoint limits only when explicitly pinned for that model.
        if context_window is not None:
            models_lines.append(f"        contextWindow: {context_window}")
        if max_tokens is not None:
            models_lines.append(f"        maxTokens: {max_tokens}")
    models_lines.append("")
else:
    models_lines = [
        "# Auto-generated by scripts/bootstrap-omp.sh. Do not edit.",
        "# Source of truth: config.toml.",
        f"# Model roles select {selector} (primary) and {verifier_selector} (verifier); no custom provider registry is required.",
        "",
        "providers: {}",
        "",
    ]

write_if_changed(agent_dir / "config.yml", "\n".join(config_lines))
write_if_changed(agent_dir / "models.yml", "\n".join(models_lines))
# Mirror the secret-free project config to the harness root .omp/ so the project-level
# config (.omp/config.yml) stays in lockstep with the agent-home copy. models.yml is
# intentionally NOT mirrored to root: it carries the live apiKey and the tracked .omp/
# must stay secret-free. The agent-home copy (.harness/home, gitignored) retains models.yml.
write_if_changed(project_config_path, "\n".join(config_lines))
PY
