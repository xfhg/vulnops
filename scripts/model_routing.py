"""Canonical model ownership for audit and explicitly scoped linked executions."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

EFFORTS = frozenset({"off", "minimal", "low", "medium", "high", "xhigh", "max", "auto"})
GROUP_AGENTS = {
    "audit_lead": (),
    "recon": ("vulnops-recon", "vulnops-recon-overview", "vulnops-recon-trust", "vulnops-recon-inputs"),
    "sast": ("vulnops-threat-hunter", "vulnops-threatmodel", "vulnops-deepdive-chunk", "vulnops-verify-one"),
    "campaign_planning": ("vulnops-campaign-planning",),
    "intrusion": ("vulnops-intrusion", "vulnops-intrusion-campaign", "vulnops-gap-exploration", "vulnops-gap-investigator"),
    "synthesis": ("vulnops-synthesis",),
    "final_verification": ("vulnops-final-verification", "vulnops-independent-verify-one"),
    "reproduction": ("vulnops-reproduce-one",),
    "remediation": ("vulnops-remediation", "vulnops-remediate-one"),
    "advantage_lead": (),
    "advantage": ("vulnops-advantage-planning", "vulnops-advantage-investigation", "vulnops-advantage-investigator", "vulnops-advantage-synthesis", "vulnops-advantage-gap-exploration", "vulnops-advantage-gap-investigator"),
    "advantage_verification": ("vulnops-advantage-final-verification", "vulnops-advantage-verify-one"),
}
SCOPE_GROUPS = {
    "audit": ("audit_lead", "recon", "sast", "campaign_planning", "intrusion", "synthesis",
              "final_verification", "reproduction"),
    "remediation": ("remediation",),
    "advantage": ("advantage_lead", "advantage", "advantage_verification", "reproduction"),
}
CONTROLLER_GROUPS = {"audit": "audit_lead", "remediation": "remediation", "advantage": "advantage_lead"}


def split_selector(value: str) -> tuple[str, str, str]:
    if not isinstance(value, str) or not re.fullmatch(r"[^/\s]+/[^\s]+", value):
        raise ValueError("model routes must use provider/model:effort syntax")
    provider, model_effort = value.split("/", 1)
    model, colon, effort = model_effort.rpartition(":")
    if not colon or not model or effort not in EFFORTS:
        raise ValueError("model routes require an explicit supported reasoning effort")
    return provider, model, effort


def resolve_routing(llm: dict) -> dict:
    if not isinstance(llm, dict):
        raise ValueError("llm must be a table")
    if set(llm) & {"selector", "roles", "verification", "model"}:
        raise ValueError("legacy llm model settings are unsupported; migrate to the complete [llm.routing] table")
    groups = llm.get("routing")
    if not isinstance(groups, dict):
        raise ValueError("llm.routing must be a table with explicit routes: " + ", ".join(GROUP_AGENTS))
    missing, extra = set(GROUP_AGENTS) - set(groups), set(groups) - set(GROUP_AGENTS)
    if missing or extra:
        raise ValueError("llm.routing migration required; missing keys: "
                         + (", ".join(sorted(missing)) or "none")
                         + "; unknown keys: " + (", ".join(sorted(extra)) or "none"))
    for selector in groups.values():
        split_selector(selector)
    return {
        "groups": {group: groups[group] for group in GROUP_AGENTS},
        "agents": {agent: groups[group] for group, agents in GROUP_AGENTS.items() for agent in agents},
        "controllers": {scope: groups[group] for scope, group in CONTROLLER_GROUPS.items()},
    }


def scoped_routing(routing: dict, scope: str) -> dict:
    groups = {key: routing["groups"][key] for key in SCOPE_GROUPS[scope]}
    return {"groups": groups, "agents": {agent: groups[group] for group in groups for agent in GROUP_AGENTS[group]},
            "controllers": {scope: groups[CONTROLLER_GROUPS[scope]]}}


def audit_routing(routing: dict) -> dict:
    return scoped_routing(routing, "audit")


def remediation_routing(routing: dict) -> dict:
    return scoped_routing(routing, "remediation")


def advantage_routing(routing: dict) -> dict:
    return scoped_routing(routing, "advantage")


def load_routing(root: Path) -> dict:
    with (root / "config.toml").open("rb") as handle:
        return resolve_routing(tomllib.load(handle).get("llm", {}))


def validate_routing(routing: dict, scope: str = "audit") -> None:
    if scope not in SCOPE_GROUPS:
        raise ValueError("unknown model routing scope")
    if not isinstance(routing, dict) or set(routing) != {"groups", "agents", "controllers"}:
        raise ValueError("model routing requires groups, agents and controllers")
    groups = routing["groups"]
    expected_groups = set(SCOPE_GROUPS[scope])
    if not isinstance(groups, dict) or set(groups) != expected_groups:
        raise ValueError(f"incomplete {scope} routing groups")
    for selector in groups.values():
        split_selector(selector)
    agents = {agent: groups[group] for group in groups for agent in GROUP_AGENTS[group]}
    controller = groups[CONTROLLER_GROUPS[scope]]
    if routing["agents"] != agents or routing["controllers"] != {scope: controller}:
        raise ValueError(f"{scope} routing ownership does not match its groups")


def read_agent_overrides(path: Path) -> dict[str, str]:
    """Read the task routes emitted by bootstrap-omp.sh's generated YAML."""
    overrides = {}
    section = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("task:"):
            section = "task"
            continue
        if line and not line.startswith((" ", "\t")):
            section = None
        if section == "task" and line.strip() == "agentModelOverrides:":
            section = "overrides"
            continue
        if section == "overrides" and line.startswith("  ") and not line.startswith("    "):
            section = "task"
        if section == "overrides" and line.startswith("    ") and ":" in line:
            agent, selector = line.strip().split(":", 1)
            if agent in overrides:
                raise ValueError("duplicate generated agent model override")
            overrides[agent] = selector.strip().strip("'\"")
    return overrides
