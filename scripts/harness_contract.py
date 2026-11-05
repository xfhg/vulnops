#!/usr/bin/env python3
"""Resolve current per-attempt execution budgets and deadlines."""

from __future__ import annotations

import os
from pathlib import Path
import tomllib


DEFAULT_SAST_BUDGETS = {
    "quick": {"max_concurrency": 4, "max_hunt_tasks": 12, "max_hunt_questions": 24, "max_gapfill_rounds": 1, "max_attempts": 2},
    "balanced": {"max_concurrency": 8, "max_hunt_tasks": 32, "max_hunt_questions": 64, "max_gapfill_rounds": 2, "max_attempts": 2},
    "full": {"max_concurrency": 16, "max_hunt_tasks": 64, "max_hunt_questions": 128, "max_gapfill_rounds": 3, "max_attempts": 2},
}

DEFAULT_GAP_EXPLORATION_BUDGETS = {
    depth: dict(zip(
        ("max_questions", "graph_timeout_seconds", "preparation_timeout_seconds",
         "max_tasks", "max_concurrency", "max_attempts", "max_candidates",
         "timeout_seconds", "synthesis_timeout_seconds", "verification_timeout_seconds"),
        values,
    ))
    for depth, values in {
        "quick": (4, 120, 600, 2, 2, 2, 4, 1800, 300, 900),
        "balanced": (8, 240, 600, 4, 4, 2, 8, 2700, 600, 1800),
        "full": (12, 360, 600, 8, 4, 2, 16, 5400, 900, 3600),
    }.items()
}


def resolved_gap_exploration_budget(root: Path, depth: str) -> dict:
    with (root / "config.toml").open("rb") as stream:
        return resolve_gap_exploration_budget(tomllib.load(stream), depth)


def resolve_gap_exploration_budget(config: dict, depth: str) -> dict:
    """Resolve one application-wide supplementary allowance, never per pass."""
    if depth not in DEFAULT_GAP_EXPLORATION_BUDGETS:
        raise ValueError(f"invalid gap exploration depth: {depth!r}")
    if (not isinstance(config, dict) or not isinstance(config.get("harness", {}), dict)
            or not isinstance(config.get("harness", {}).get("scans", {}), dict)):
        raise ValueError("gap exploration configuration requires harness and scans tables")
    settings = config.get("harness", {}).get("scans", {}).get("gap_exploration", {})
    if not isinstance(settings, dict) or set(settings) - {"enabled", "budget"}:
        raise ValueError("harness.scans.gap_exploration accepts only enabled and budget")
    enabled = settings.get("enabled", True)
    if type(enabled) is not bool:
        raise ValueError("gap_exploration.enabled must be a boolean")
    overrides = settings.get("budget", {})
    if not isinstance(overrides, dict) or set(overrides) - DEFAULT_GAP_EXPLORATION_BUDGETS.keys():
        raise ValueError("gap_exploration.budget accepts only quick, balanced and full")
    resolved = {}
    for name, defaults in DEFAULT_GAP_EXPLORATION_BUDGETS.items():
        override = overrides.get(name, {})
        if not isinstance(override, dict) or set(override) - defaults.keys():
            raise ValueError(f"gap_exploration.budget.{name} contains unknown limits")
        budget = defaults | override
        if "max_candidates" not in override:
            budget["max_candidates"] = 2 * budget["max_tasks"] if type(budget["max_tasks"]) is int else None
        for key, value in budget.items():
            maximum = 16 if key == "max_concurrency" else 2 if key == "max_attempts" else 2147483
            minimum = 1 if key in {"max_concurrency", "max_attempts", "timeout_seconds"} else 0
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"gap_exploration.budget.{name}.{key} must be an integer in {minimum}..{maximum}")
        if budget["max_candidates"] > 2 * budget["max_tasks"]:
            raise ValueError(f"gap_exploration.budget.{name}.max_candidates exceeds two per task")
        resolved[name] = {"enabled": enabled, **budget}
    return resolved[depth]


def resolved_recon_timeout(root: Path, depth: str, repository_count: int) -> int:
    """Resolve one end-to-end deadline, retaining the repository-count floor."""
    with (root / "config.toml").open("rb") as stream:
        config = tomllib.load(stream)
    settings = config.get("harness", {}).get("scans", {}).get("recon", {})
    if not isinstance(settings, dict) or set(settings) - {"timeout_seconds"}:
        raise ValueError("harness.scans.recon accepts only timeout_seconds")
    configured = settings.get("timeout_seconds", {})
    defaults = {"quick": 1800, "balanced": 2700, "full": 5400}
    if not isinstance(configured, dict) or set(configured) - defaults.keys():
        raise ValueError("recon.timeout_seconds accepts only quick, balanced and full")
    timeouts = defaults | configured
    for name, seconds in timeouts.items():
        if type(seconds) is not int or not 0 < seconds <= 2147483:
            raise ValueError(f"recon.timeout_seconds.{name} must be a positive integer <= 2147483")
    return max(timeouts[depth], 900 + 300 * (repository_count - 1))


def resolved_sast_budget(depth: str) -> dict[str, int]:
    defaults = DEFAULT_SAST_BUDGETS[depth]
    prefix = f"VULNOPS_SAST_{depth.upper()}"
    return {
        "max_concurrency": defaults["max_concurrency"],
        "max_hunt_tasks": int(os.environ.get(f"{prefix}_MAX_HUNT_TASKS", defaults["max_hunt_tasks"])),
        "max_hunt_questions": int(os.environ.get(f"{prefix}_MAX_HUNT_QUESTIONS", defaults["max_hunt_questions"])),
        "max_gapfill_rounds": int(os.environ.get(f"{prefix}_MAX_GAPFILL_ROUNDS", defaults["max_gapfill_rounds"])),
        "max_attempts": int(os.environ.get(f"{prefix}_MAX_ATTEMPTS", defaults["max_attempts"])),
        "context_packet_bytes": int(os.environ.get("VULNOPS_SAST_CONTEXT_PACKET_BYTES", "65536")),
    }


def resolved_intrusion_budget(depth: str) -> dict[str, int]:
    rounds, tasks = {"quick": (1, 4), "balanced": (2, 12), "full": (3, 24)}[depth]
    return {"continuation_rounds": rounds, "continuation_tasks": tasks, "graph_followups": tasks}


def resolved_experiment_budget(depth: str) -> dict[str, int]:
    return {"max_experiments": DEFAULT_SAST_BUDGETS[depth]["max_hunt_tasks"],
            "max_concurrency": 1, "timeout_seconds": 120, "cpu_seconds": 60,
            "memory_mb": 1024, "max_processes": 64, "max_output_kb": 256}

