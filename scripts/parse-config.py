#!/usr/bin/env python3
"""parse-config.py — Read config.toml and emit shell export lines.

Usage:
    python3 scripts/parse-config.py [HARNESS_ROOT]

If HARNESS_ROOT is omitted, defaults to the script's parent-of-parent directory.
Output is one `export KEY=VALUE` line per variable, suitable for shell eval.
No config.toml = no output (silent exit 0).
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+ stdlib
except ModuleNotFoundError:
    # Python < 3.11 fallback — shouldn't happen on the supported host, but
    # fail gracefully rather than crashing.
    sys.exit(0)


def _find_root(argv: list[str]) -> Path:
    if len(argv) > 1:
        return Path(argv[1]).resolve()
    return Path(__file__).resolve().parent.parent


def _dquote(val: str) -> str:
    """Escape double-quote characters inside a shell double-quoted string."""
    return val.replace("\\", "\\\\").replace('"', '\\"')


def main() -> None:
    root = _find_root(sys.argv)
    config_path = root / "config.toml"
    if not config_path.exists():
        return

    with open(config_path, "rb") as f:
        cfg = tomllib.load(f)

    llm = cfg.get("llm", {})
    harness = cfg.get("harness", {})
    reproduction = harness.get("reproduction", {})
    sast = harness.get("scans", {}).get("sast", {})

    # ── Core LLM vars ─────────────────────────────────────────────────
    base_url = str(llm.get("base_url", "") or "")
    api_key = str(llm.get("api_key", "") or "")
    model = str(llm.get("model", "") or "")
    provider = llm.get("provider", {})
    provider_name = str(provider.get("name", "on-prem") or "on-prem")
    provider_api = str(provider.get("api", "openai-completions") or "openai-completions")
    provider_auth = str(provider.get("auth", "api-key") or "api-key")
    selector = str(llm.get("selector", "") or "").strip()
    roles = llm.get("roles", {})
    orchestrator_selector = str(roles.get("orchestrator", selector) or selector).strip()
    task_selector = str(roles.get("task", selector) or selector).strip()
    slow_selector = str(roles.get("slow", selector) or selector).strip()
    smol_selector = str(roles.get("smol", selector) or selector).strip()
    verifier_selector = str(llm.get("verification", {}).get("selector", "") or "").strip() or selector

    exports: list[tuple[str, str]] = [
        ("VULNOPS_DEFAULT_DEPTH", str(harness.get("default_depth", "quick") or "quick")),
        ("ON_PREM_LLM_BASE_URL", base_url),
        ("ON_PREM_API_KEY", api_key),
        ("ON_PREM_MODEL_NAME", model),
        ("ON_PREM_PROVIDER_NAME", provider_name),
        ("ON_PREM_PROVIDER_API", provider_api),
        ("ON_PREM_PROVIDER_AUTH", provider_auth),
        ("OMP_MODEL_SELECTOR", selector),
        ("OMP_ORCHESTRATOR_MODEL_SELECTOR", orchestrator_selector),
        ("OMP_TASK_MODEL_SELECTOR", task_selector),
        ("OMP_SLOW_MODEL_SELECTOR", slow_selector),
        ("OMP_SMOL_MODEL_SELECTOR", smol_selector),
        ("OMP_VERIFIER_MODEL_SELECTOR", verifier_selector),
        ("VULNOPS_REPRODUCTION_MODE", str(reproduction.get("mode", "off") or "off")),
        ("VULNOPS_REPRODUCTION_SANDBOX", str(reproduction.get("sandbox", "auto") or "auto")),
        ("VULNOPS_REPRODUCTION_TIMEOUT_SECONDS", str(reproduction.get("timeout_seconds", 120))),
        ("VULNOPS_REPRODUCTION_CPU_SECONDS", str(reproduction.get("cpu_seconds", 60))),
        ("VULNOPS_REPRODUCTION_MEMORY_MB", str(reproduction.get("memory_mb", 1024))),
        ("VULNOPS_REPRODUCTION_MAX_PROCESSES", str(reproduction.get("max_processes", 64))),
        ("VULNOPS_REPRODUCTION_MAX_OUTPUT_KB", str(reproduction.get("max_output_kb", 256))),
        ("VULNOPS_REPRODUCTION_MAX_PARALLEL", str(reproduction.get("max_parallel", 1))),
        ("VULNOPS_SAST_CONTEXT_PACKET_BYTES", str(sast.get("context_packet_bytes", 65536))),
    ]
    budget_defaults = {
        "quick": (12, 1, 2),
        "balanced": (32, 2, 2),
        "full": (64, 3, 2),
    }
    budgets = sast.get("budget", {})
    for depth, defaults in budget_defaults.items():
        item = budgets.get(depth, {})
        prefix = f"VULNOPS_SAST_{depth.upper()}"
        exports.extend(
            [
                (f"{prefix}_MAX_HUNT_TASKS", str(item.get("max_hunt_tasks", defaults[0]))),
                (f"{prefix}_MAX_GAPFILL_ROUNDS", str(item.get("max_gapfill_rounds", defaults[1]))),
                (f"{prefix}_MAX_ATTEMPTS", str(item.get("max_attempts", defaults[2]))),
            ]
        )

    # ── Emit ──────────────────────────────────────────────────────────
    for key, val in exports:
        print(f'export {key}="{_dquote(val)}"')


if __name__ == "__main__":
    main()
