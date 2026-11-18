#!/usr/bin/env python3
"""parse-config.py — Read config.toml and emit shell export lines.

Usage:
    python3 scripts/parse-config.py [HARNESS_ROOT]

If HARNESS_ROOT is omitted, defaults to the script's parent-of-parent directory.
Output is one `export KEY=VALUE` line per variable, suitable for shell eval.
No config.toml = no output (silent exit 0).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
import json
import shlex
from model_routing import resolve_routing
from harness_contract import resolved_recon_timeout, resolved_gap_exploration_budget
from advantage_config import resolve_budget

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



def main() -> None:
    root = _find_root(sys.argv)
    config_path = Path(os.environ.get("VULNOPS_CONFIG_PATH", root / "config.toml"))
    if not config_path.exists():
        return

    with open(config_path, "rb") as f:
        cfg = tomllib.load(f)

    llm = cfg.get("llm", {})
    harness = cfg.get("harness", {})
    reproduction = harness.get("reproduction", {})
    network = harness.get("network", {})
    sast = harness.get("scans", {}).get("sast", {})
    resolved_recon_timeout(root, harness.get("default_depth", "quick"), 1)
    advantage_budgets = {depth: resolve_budget(depth, cfg) for depth in ("quick", "balanced", "full")}
    gap_budgets = {depth: resolved_gap_exploration_budget(root, depth) for depth in ("quick", "balanced", "full")}

    # ── Core LLM vars ─────────────────────────────────────────────────
    base_url = str(llm.get("base_url", "") or "")
    api_key = str(llm.get("api_key", "") or "")
    provider = llm.get("provider", {})
    provider_name = str(provider.get("name", "on-prem") or "on-prem")
    provider_api = str(provider.get("api", "openai-completions") or "openai-completions")
    provider_auth = str(provider.get("auth", "api-key") or "api-key")
    routing = resolve_routing(llm)
    groups = routing["groups"]

    exports: list[tuple[str, str]] = [
        ("VULNOPS_DEFAULT_DEPTH", str(harness.get("default_depth", "quick") or "quick")),
        ("ON_PREM_LLM_BASE_URL", base_url),
        ("ON_PREM_API_KEY", api_key),
        ("VULNOPS_MODEL_ROUTING", json.dumps(routing, sort_keys=True)),
        ("ON_PREM_PROVIDER_NAME", provider_name),
        ("ON_PREM_PROVIDER_API", provider_api),
        ("ON_PREM_PROVIDER_AUTH", provider_auth),
        ("OMP_MODEL_SELECTOR", groups["audit_lead"]),
        ("OMP_VERIFIER_MODEL_SELECTOR", groups["final_verification"]),
        ("OMP_REMEDIATION_MODEL_SELECTOR", groups["remediation"]),
        ("OMP_ADVANTAGE_MODEL_SELECTOR", groups["advantage_lead"]),
        ("VULNOPS_ADVANTAGE_BUDGETS", json.dumps(advantage_budgets, sort_keys=True)),
        ("VULNOPS_GAP_EXPLORATION_BUDGETS", json.dumps(gap_budgets, sort_keys=True)),
        ("VULNOPS_REPRODUCTION_MODE", str(reproduction.get("mode", "off") or "off")),
        ("VULNOPS_LINUX_AGENT_EGRESS", str(network.get("linux_agent_egress", "enforced") or "enforced")),
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
                (f"{prefix}_MAX_HUNT_QUESTIONS", str(item.get("max_hunt_questions", defaults[0] * 2))),
                (f"{prefix}_MAX_GAPFILL_ROUNDS", str(item.get("max_gapfill_rounds", defaults[1]))),
                (f"{prefix}_MAX_ATTEMPTS", str(item.get("max_attempts", defaults[2]))),
            ]
        )

    # ── Emit ──────────────────────────────────────────────────────────
    for key, val in exports:
        print(f"export {key}={shlex.quote(val)}")


if __name__ == "__main__":
    main()
