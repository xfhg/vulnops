#!/usr/bin/env python3
"""Shared semantic checks for contextual SAST hunt worker results."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


def _validator_module(root: Path):
    spec = importlib.util.spec_from_file_location("vulnops_validate_json_sast", root / "scripts/validate-json.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load validate-json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source_path(value: str) -> str:
    return value.split(":", 1)[0].split("#", 1)[0]


def _entrypoint_id(value: str) -> str:
    return value.split(":", 1)[0].strip()


def _ordered_union(rows: list[dict], key: str) -> list[str]:
    return list(dict.fromkeys(str(item) for row in rows for item in row.get(key, [])))


def validate_hunt_result(root: Path, repo: Path, task: dict, cells: list[dict], result: Any, threat: dict | None = None) -> list[str]:
    module = _validator_module(root)
    schema = json.loads((root / "schemas/v2/hunt-result.schema.json").read_text(encoding="utf-8"))
    errors = module.Validator(schema).collect(result, schema)
    if not isinstance(result, dict):
        return errors
    task_id = str(task.get("id", ""))
    if result.get("task_id") != task_id:
        errors.append(f"$.task_id must match assigned task {task_id!r}")
    expected_ids = [str(cell.get("id")) for cell in cells]
    cell_map = {str(cell.get("id")): cell for cell in cells}
    rows = [row for row in result.get("cell_results", []) if isinstance(row, dict)]
    row_ids = [str(row.get("cell_id", "")) for row in rows]
    if len(row_ids) != len(set(row_ids)):
        errors.append("$.cell_results contains duplicate cell IDs")
    if set(row_ids) != set(expected_ids) or len(row_ids) != len(expected_ids):
        errors.append("$.cell_results must contain exactly one result for every assigned cell")
    elif row_ids != expected_ids:
        errors.append("$.cell_results must preserve assigned cell order")

    candidates = [item for item in result.get("candidates", []) if isinstance(item, dict)]
    candidate_schema = json.loads((root / "schemas/v2/candidate-finding.schema.json").read_text(encoding="utf-8"))
    candidate_validator = module.Validator(candidate_schema)
    for index, candidate in enumerate(candidates):
        errors.extend(message.replace("$", f"$.candidates[{index}]", 1) for message in candidate_validator.collect(candidate, candidate_schema))
        errors.extend(message.replace("$", f"$.candidates[{index}]", 1) for message in module.semantic_errors(candidate, "candidate", repo))
    candidate_ids = [str(item.get("id", "")) for item in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        errors.append("$.candidates contains duplicate worker-local IDs")
    candidate_map = {str(item.get("id", "")): item for item in candidates}
    for index, candidate in enumerate(candidates):
        if candidate.get("task_id") != task_id:
            errors.append(f"$.candidates[{index}].task_id must match the assigned task")
        referenced = [str(item) for item in candidate.get("cell_ids", [])]
        if not referenced or any(cell_id not in cell_map for cell_id in referenced):
            errors.append(f"$.candidates[{index}].cell_ids must resolve within the assigned task")
            continue
        for cell_id in referenced:
            if candidate.get("attack_class_id") != cell_map[cell_id].get("attack_class_id"):
                errors.append(f"$.candidates[{index}].attack_class_id does not match cell {cell_id!r}")
        referenced_cells = [cell_map[cell_id] for cell_id in referenced if cell_id in cell_map]
        expected_domain = referenced_cells[0].get("domain") if referenced_cells else None
        expected_methods = list(dict.fromkeys(str(ref) for cell in referenced_cells for ref in cell.get("methodology_refs", [])))
        expected_lenses = list(dict.fromkeys(str(ref) for cell in referenced_cells for ref in cell.get("lenses", [])))
        if candidate.get("domain") != expected_domain:
            errors.append(f"$.candidates[{index}].domain does not match its cells")
        if candidate.get("methodology_refs") != expected_methods:
            errors.append(f"$.candidates[{index}].methodology_refs do not match its cells")
        if candidate.get("lenses") != expected_lenses:
            errors.append(f"$.candidates[{index}].lenses do not match its cells")
        assigned_files = {str(path) for cell in referenced_cells for path in cell.get("files", [])}
        locations = [candidate.get("root_cause_location", {}), *candidate.get("trace", [])]
        for location in locations:
            if isinstance(location, dict) and str(location.get("file", "")) not in assigned_files:
                errors.append(f"$.candidates[{index}] cites a source location outside its assigned cells")

    for index, row in enumerate(rows):
        cell_id = str(row.get("cell_id", ""))
        cell = cell_map.get(cell_id)
        if cell is None:
            continue
        expected_candidates = [
            candidate_id
            for candidate_id, candidate in candidate_map.items()
            if cell_id in {str(item) for item in candidate.get("cell_ids", [])}
        ]
        if row.get("candidate_ids") != expected_candidates:
            errors.append(f"$.cell_results[{index}].candidate_ids do not match candidates for {cell_id!r}")
        status = row.get("status")
        if expected_candidates and status != "finding":
            errors.append(f"$.cell_results[{index}].status must be finding when candidates reference the cell")
        if not expected_candidates and status == "finding":
            errors.append(f"$.cell_results[{index}].status cannot be finding without a candidate")
        assigned_files = {str(item) for item in cell.get("files", [])}
        for reviewed in row.get("files_reviewed", []):
            relative = _source_path(str(reviewed))
            if relative not in assigned_files:
                errors.append(f"$.cell_results[{index}] reviewed unassigned file {relative!r}; return it as a rabbit hole")
            path = module.safe_repo_file(repo, relative)
            if path is None or not path.is_file():
                errors.append(f"$.cell_results[{index}] references missing target file {relative!r}")
        assigned_entrypoints = {str(item) for item in cell.get("entrypoint_ids", [])}
        for traced in row.get("entrypoints_traced", []):
            entrypoint = _entrypoint_id(str(traced))
            if entrypoint not in assigned_entrypoints:
                errors.append(f"$.cell_results[{index}] traced unassigned entrypoint {entrypoint!r}")
        if status in {"finding", "clean"}:
            for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"):
                if not row.get(key):
                    errors.append(f"$.cell_results[{index}].{key} is required for {status}")
        if status == "not_applicable":
            if not row.get("files_reviewed") or not row.get("entrypoints_traced"):
                errors.append(f"$.cell_results[{index}] not_applicable requires source and entrypoint review")
            if len(str(row.get("reason", "")).strip()) < 12:
                errors.append(f"$.cell_results[{index}] not_applicable requires a substantive source-backed reason")

    for key in ("files_reviewed", "entrypoints_traced", "sinks_reviewed", "mitigations_checked"):
        if result.get(key) != _ordered_union(rows, key):
            errors.append(f"$.{key} must equal the ordered union of cell_results.{key}")
    statuses = {str(row.get("status")) for row in rows}
    expected_status = "failed" if "failed" in statuses else "shallow" if "shallow" in statuses else "ok"
    if result.get("status") != expected_status:
        errors.append(f"$.status must be {expected_status!r} for its cell results")
    if isinstance(threat, dict):
        classes = {str(item.get("id")): item for item in threat.get("attack_classes", []) if isinstance(item, dict)}
        subsystems = {str(item.get("id")): item for item in threat.get("subsystems", []) if isinstance(item, dict)}
        threats = {str(item.get("id")): item for item in threat.get("threats", []) if isinstance(item, dict)}
        assets = {str(item.get("id")) for item in threat.get("assets", []) if isinstance(item, dict)}
        entrypoints = {str(item.get("id")): item for item in threat.get("entrypoints", []) if isinstance(item, dict)}
        boundaries = {str(item.get("id")) for item in threat.get("trust_boundaries", []) if isinstance(item, dict)}
        for index, rabbit in enumerate(result.get("rabbit_holes", [])):
            if not isinstance(rabbit, dict):
                continue
            attack_id = str(rabbit.get("attack_class_id", ""))
            subsystem_id = str(rabbit.get("subsystem", ""))
            attack_class = classes.get(attack_id)
            subsystem = subsystems.get(subsystem_id)
            if attack_class is None or attack_class.get("owner") != "sast":
                errors.append(f"$.rabbit_holes[{index}] must reference a SAST-owned attack class")
            if subsystem is None:
                errors.append(f"$.rabbit_holes[{index}] references an unknown subsystem")
                continue
            allowed_surfaces = {str(item) for item in subsystem.get("security_surface_ids", [])}
            if not set(str(item) for item in rabbit.get("surface_ids", [])).issubset(allowed_surfaces):
                errors.append(f"$.rabbit_holes[{index}] references a surface outside its subsystem")
            files = {str(item) for item in rabbit.get("files", [])}
            if not files.intersection(str(item) for item in subsystem.get("files", [])):
                errors.append(f"$.rabbit_holes[{index}] has no source file in its subsystem")
            for relative in files:
                path = module.safe_repo_file(repo, relative)
                if path is None or not path.is_file():
                    errors.append(f"$.rabbit_holes[{index}] references missing target file {relative!r}")
            rabbit_entrypoints = {str(item) for item in rabbit.get("entrypoint_ids", [])}
            for entrypoint_id in rabbit_entrypoints:
                entrypoint = entrypoints.get(entrypoint_id)
                if entrypoint is None or subsystem_id not in {str(item) for item in entrypoint.get("subsystem_ids", [])}:
                    errors.append(f"$.rabbit_holes[{index}] entrypoint does not resolve in its subsystem")
            rabbit_boundaries = {str(item) for item in rabbit.get("boundary_ids", [])}
            if not rabbit_boundaries.issubset(boundaries):
                errors.append(f"$.rabbit_holes[{index}] references an unknown boundary")
            connected = {
                str(boundary)
                for entrypoint_id in rabbit_entrypoints
                for boundary in (entrypoints.get(entrypoint_id) or {}).get("trust_boundary_ids", [])
            }
            if not rabbit_boundaries.intersection(connected):
                errors.append(f"$.rabbit_holes[{index}] has no boundary connected to its entrypoints")
            cited_threats = [threats.get(str(item)) for item in rabbit.get("threat_ids", [])]
            if any(item is None for item in cited_threats):
                errors.append(f"$.rabbit_holes[{index}] references an unknown threat")
            if not set(str(item) for item in rabbit.get("asset_ids", [])).issubset(assets):
                errors.append(f"$.rabbit_holes[{index}] references an unknown asset")
            for cited in (item for item in cited_threats if item is not None):
                if attack_id not in {str(item) for item in cited.get("attack_class_ids", [])}:
                    errors.append(f"$.rabbit_holes[{index}] attack class is absent from its cited threat")
    return errors


__all__ = ["validate_hunt_result"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_path", type=Path)
    parser.add_argument("packet", type=Path)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
        result = json.loads(args.result.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[sast-contract] ERROR: {exc}", file=sys.stderr)
        return 1
    threat_path = args.packet.parent.parent / "threat-model.json"
    try:
        threat = json.loads(threat_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        threat = None
    errors = validate_hunt_result(root, args.repo_path.resolve(), packet.get("task", {}), packet.get("cells", []), result, threat)
    if errors:
        for message in errors:
            print(f"[sast-contract] ERROR: {message}", file=sys.stderr)
        return 1
    print("[sast-contract] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
