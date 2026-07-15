#!/usr/bin/env python3
"""Validate the canonical OMP agent graph and its orchestration contracts."""

from __future__ import annotations

import sys
import re
from pathlib import Path


EXPECTED = {
    "vulnops-recon",
    "vulnops-recon-overview",
    "vulnops-recon-trust",
    "vulnops-recon-inputs",
    "vulnops-sast-lead",
    "vulnops-threatmodel",
    "vulnops-deepdive-chunk",
    "vulnops-verify-one",
    "vulnops-reproduce-one",
    "vulnops-campaign-planning",
    "vulnops-intrusion",
    "vulnops-intrusion-campaign",
    "vulnops-synthesis",
    "vulnops-final-verification",
    "vulnops-independent-verify-one",
}
SPAWNS = {
    "vulnops-recon": {
        "vulnops-recon-overview",
        "vulnops-recon-trust",
        "vulnops-recon-inputs",
    },
    "vulnops-sast-lead": {
        "vulnops-threatmodel",
        "vulnops-deepdive-chunk",
        "vulnops-verify-one",
        "vulnops-reproduce-one",
    },
    "vulnops-intrusion": {"vulnops-intrusion-campaign"},
    "vulnops-final-verification": {"vulnops-independent-verify-one"},
}
PHASE_AGENTS = {
    "vulnops-recon",
    "vulnops-sast-lead",
    "vulnops-campaign-planning",
    "vulnops-intrusion",
    "vulnops-synthesis",
    "vulnops-final-verification",
}
ALLOWED_TOOLS = {"read", "write", "grep", "glob", "bash", "task", "irc", "yield"}
ROLE_CONTRACT = {
    "vulnops-recon": ("pi/task", "medium"),
    "vulnops-sast-lead": ("pi/task", "medium"),
    "vulnops-campaign-planning": ("pi/slow", "high"),
    "vulnops-intrusion": ("pi/task", "medium"),
    "vulnops-synthesis": ("pi/slow", "high"),
    "vulnops-final-verification": ("pi/task", "medium"),
    "vulnops-independent-verify-one": ("pi/slow", "xhigh"),
}


def scalar(value: str) -> object:
    value = value.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
    return value.strip("'\"")


def frontmatter(path: Path) -> dict:
    """Parse the small top-level subset used by OMP agent frontmatter.

    This deliberately has no package dependency: readiness runs on prepared
    offline hosts before any optional Python environment is installed.
    """
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("missing opening frontmatter delimiter")
    try:
        raw, body = text[4:].split("\n---\n", 1)
    except ValueError as exc:
        raise ValueError("missing closing frontmatter delimiter") from exc
    value: dict[str, object] = {}
    lines = raw.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*):(?:\s*(.*))?", line)
        if not match:
            index += 1
            continue
        key, remainder = match.group(1), (match.group(2) or "").strip()
        if remainder:
            value[key] = scalar(remainder)
            index += 1
            continue
        child_lines: list[str] = []
        index += 1
        while index < len(lines) and (not lines[index].strip() or lines[index][0].isspace()):
            child_lines.append(lines[index])
            index += 1
        if key in {"tools", "model", "spawns"}:
            value[key] = [
                item.group(1).strip().strip("'\"")
                for child in child_lines
                if (item := re.fullmatch(r"\s+-\s+(.+)", child))
            ]
        elif key == "output":
            properties_index = next((i for i, child in enumerate(child_lines) if child.strip() == "properties:"), None)
            has_property = properties_index is not None and any(
                re.fullmatch(r"\s{4,}[A-Za-z_][A-Za-z0-9_]*:\s*.*", child)
                for child in child_lines[properties_index + 1 :]
            )
            value[key] = {"properties": {"validated": True}} if has_property else {}
        else:
            value[key] = ""
    if not value or not body.strip():
        raise ValueError("frontmatter or prompt body is empty")
    return value


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    directory = root / ".omp" / "agents"
    errors: list[str] = []
    agents: dict[str, dict] = {}
    for path in sorted(directory.glob("vulnops-*.md")):
        try:
            metadata = frontmatter(path)
        except (OSError, ValueError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        name = metadata.get("name")
        if not isinstance(name, str) or name != path.stem:
            errors.append(f"{path.name}: name must match filename")
            continue
        if name in agents:
            errors.append(f"{path.name}: duplicate agent name")
        agents[name] = metadata

    missing = EXPECTED - set(agents)
    extra = set(agents) - EXPECTED
    if missing:
        errors.append(f"missing canonical agents: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"unexpected VulnOps agents: {', '.join(sorted(extra))}")

    for name, metadata in agents.items():
        tools = metadata.get("tools")
        models = metadata.get("model")
        output = metadata.get("output")
        actual_spawns = set(metadata.get("spawns", []))
        expected_spawns = SPAWNS.get(name, set())
        if not isinstance(metadata.get("description"), str) or not metadata["description"].strip():
            errors.append(f"{name}: description is required")
        if not isinstance(tools, list) or not tools or not set(tools) <= ALLOWED_TOOLS:
            errors.append(f"{name}: tools are missing or unsupported")
            tools = []
        if len(tools) != len(set(tools)):
            errors.append(f"{name}: tools must be unique")
        if metadata.get("blocking") is not False:
            errors.append(f"{name}: blocking must be false for supervised jobs")
        if not isinstance(models, list) or len(models) != 1 or not str(models[0]).startswith("pi/"):
            errors.append(f"{name}: exactly one generated pi role is required")
        if metadata.get("thinkingLevel") not in {"minimal", "low", "medium", "high", "xhigh"}:
            errors.append(f"{name}: invalid thinkingLevel")
        if not isinstance(output, dict) or not isinstance(output.get("properties"), dict) or not output["properties"]:
            errors.append(f"{name}: structured output properties are required")
        if actual_spawns != expected_spawns:
            errors.append(f"{name}: spawns do not match the canonical graph")
        if actual_spawns and "task" not in tools:
            errors.append(f"{name}: spawning coordinator lacks task tool")
        if name in PHASE_AGENTS and "irc" not in tools:
            errors.append(f"{name}: top-level phase agent lacks IRC progress")
        if name not in PHASE_AGENTS and "irc" in tools:
            errors.append(f"{name}: leaf worker must not use IRC as a scheduler")
        if name in ROLE_CONTRACT:
            expected_model, expected_thinking = ROLE_CONTRACT[name]
            actual_model = models[0] if isinstance(models, list) and models else None
            if (actual_model, metadata.get("thinkingLevel")) != (expected_model, expected_thinking):
                errors.append(f"{name}: role or reasoning tier does not match the canonical contract")
        for child in actual_spawns:
            if child not in agents:
                errors.append(f"{name}: unresolved spawned agent {child}")

    if errors:
        for error in errors:
            print(f"[validate-omp-agents] ERROR: {error}", file=sys.stderr)
        return 1
    print(f"[validate-omp-agents] OK: {len(agents)} canonical agents and {sum(map(len, SPAWNS.values()))} spawn edges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
