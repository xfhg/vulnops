#!/usr/bin/env python3
"""Validate canonical configuration without invoking tools or exporting secrets."""
from __future__ import annotations

import argparse
from pathlib import Path
import tomllib

from advantage_config import resolve_budget
from dependency_contract import load_requirements_input_reviews
from harness_contract import resolve_gap_exploration_budget
from model_routing import resolve_routing


def only(mapping, allowed, label):
    extra = set(mapping) - set(allowed)
    if extra:
        raise SystemExit(f"unknown {label} option(s): {', '.join(sorted(extra))}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    path = parser.parse_args().config
    text = path.read_text()
    cfg = tomllib.loads(text)
    only(cfg, {"llm", "harness"}, "top-level")
    llm = cfg.get("llm", {})
    only(llm, {"base_url", "api_key", "routing", "provider"}, "llm")
    routing = resolve_routing(llm)
    provider = llm.get("provider", {})
    custom = str(provider.get("name", "on-prem"))
    selected = [x for x in routing["groups"].values() if x.startswith(custom + "/")]
    only(provider, {"name", "api", "auth", "discovery", "models"}, "llm.provider")
    for index, item in enumerate(provider.get("models", [])):
        only(item, {"id", "name", "context_window", "max_tokens", "contextWindow", "maxTokens"}, f"llm.provider.models[{index}]")
    if selected and not str(llm.get("base_url", "")).strip():
        raise SystemExit("selected custom provider requires llm.base_url")
    if selected and provider.get("auth", "api-key") != "none" and not str(llm.get("api_key", "")).strip():
        raise SystemExit("selected custom provider requires llm.api_key")
    harness = cfg.get("harness", {})
    only(harness, {"default_depth", "scans", "reproduction", "network", "advantage"}, "harness")
    for depth in ("quick", "balanced", "full"):
        resolve_budget(depth, cfg)
        resolve_gap_exploration_budget(cfg, depth)
    if harness.get("default_depth") not in {"quick", "balanced", "full"}:
        raise SystemExit("harness.default_depth is invalid")
    network = harness.get("network", {})
    only(network, {"linux_agent_egress"}, "harness.network")
    if network.get("linux_agent_egress", "enforced") not in {"enforced", "policy_only"}:
        raise SystemExit("harness.network.linux_agent_egress is invalid")
    scans = harness.get("scans", {})
    only(scans, {"sast", "recon", "gap_exploration", "reviewed_non_dependency_requirements"}, "harness.scans")
    load_requirements_input_reviews(path)
    sast = scans.get("sast", {})
    only(sast, {"context_packet_bytes", "budget"}, "harness.scans.sast")
    if int(sast.get("context_packet_bytes", 65536)) < 1024:
        raise SystemExit("SAST context_packet_bytes must be at least 1024")
    for depth, item in sast.get("budget", {}).items():
        if depth not in {"quick", "balanced", "full"}:
            raise SystemExit(f"unknown SAST budget depth: {depth}")
        only(item, {"max_hunt_tasks", "max_hunt_questions", "max_gapfill_rounds", "max_attempts"}, f"SAST {depth} budget")
        if int(item.get("max_hunt_tasks", 0)) < 1 or int(item.get("max_hunt_questions", 0)) < 1 or int(item.get("max_attempts", 0)) < 1 or int(item.get("max_gapfill_rounds", -1)) < 0:
            raise SystemExit(f"invalid SAST {depth} budget")
    reproduction = harness.get("reproduction", {})
    only(reproduction, {"mode", "sandbox", "timeout_seconds", "cpu_seconds", "memory_mb", "max_processes", "max_output_kb", "max_parallel"}, "harness.reproduction")
    if reproduction.get("mode", "off") not in {"off", "safe"} or reproduction.get("sandbox", "auto") not in {"auto", "bubblewrap"}:
        raise SystemExit("reproduction mode or sandbox is invalid")
    for key in ("timeout_seconds", "cpu_seconds", "memory_mb", "max_processes", "max_output_kb", "max_parallel"):
        if int(reproduction.get(key, 1)) < 1:
            raise SystemExit(f"harness.reproduction.{key} must be positive")
    for obsolete in ("include_raw", "scans.intelligence", "scans.reconciliation"):
        if obsolete in text:
            raise SystemExit(f"obsolete configuration is forbidden: {obsolete}")


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
