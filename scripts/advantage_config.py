"""Finite, depth-resolved Advantage allocations (global across all passes)."""
from __future__ import annotations

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = {
    "quick": (2, 12, 24, 4, 1, 4, 1800),
    "balanced": (3, 32, 64, 8, 2, 12, 3600),
    "full": (4, 64, 128, 12, 3, 24, 7200),
}
LIMITS = {
    "deep_passes": 16,
    "max_tasks": 1024,
    "max_questions": 2048,
    "max_concurrency": 16,
    "max_continuation_rounds": 16,
    "max_continuation_tasks": 256,
    "phase_timeout_seconds": 86400,
}


def resolve_budget(depth: str, config: dict | None = None) -> dict:
    """Validate every configured depth and resolve one, without multiplying passes."""
    if depth not in DEFAULTS:
        raise ValueError("Advantage depth must be quick, balanced, or full")
    if config is None:
        with (ROOT / "config.toml").open("rb") as stream:
            config = tomllib.load(stream)
    if not isinstance(config, dict) or not isinstance(config.get("harness", {}), dict):
        raise ValueError("Advantage configuration requires a harness table")
    settings = config.get("harness", {}).get("advantage", {})
    if not isinstance(settings, dict) or set(settings) - {"max_attempts", "budget"}:
        raise ValueError("harness.advantage permits only max_attempts and budget")
    attempts = settings.get("max_attempts", 2)
    if type(attempts) is not int or attempts != 2:
        raise ValueError("harness.advantage.max_attempts must be exactly 2")
    budgets = settings.get("budget", {})
    if not isinstance(budgets, dict) or set(budgets) - set(DEFAULTS):
        raise ValueError("harness.advantage.budget permits only quick, balanced, and full")
    resolved = {}
    for name, defaults in DEFAULTS.items():
        override = budgets.get(name, {})
        if not isinstance(override, dict) or set(override) - set(LIMITS):
            raise ValueError(f"unknown harness.advantage.budget.{name} settings")
        values = dict(zip(LIMITS, defaults)) | override
        for key, maximum in LIMITS.items():
            if type(values[key]) is not int or not 1 <= values[key] <= maximum:
                raise ValueError(f"harness.advantage.budget.{name}.{key} must be an integer in 1..{maximum}")
        if values["max_questions"] < values["max_tasks"]:
            raise ValueError(f"Advantage {name} question allocation must cover every task")
        if values["deep_passes"] > values["max_tasks"]:
            raise ValueError(f"Advantage {name} deep passes must not exceed the global task allocation")
        resolved[name] = values | {"max_attempts": attempts}
    return resolved[depth]
