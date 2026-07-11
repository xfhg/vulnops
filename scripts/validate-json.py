#!/usr/bin/env python3
"""Dependency-free JSON Schema subset and VulnOps v2 semantic validator."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from dependency_contract import discover_dependency_files, is_supported_dependency_file


class Validator:
    def __init__(self, schema: dict[str, Any]) -> None:
        self.root = schema

    def resolve(self, ref: str) -> dict[str, Any]:
        if not ref.startswith("#/"):
            raise ValueError(f"unsupported external $ref: {ref}")
        node: Any = self.root
        for raw in ref[2:].split("/"):
            key = raw.replace("~1", "/").replace("~0", "~")
            node = node[key]
        if not isinstance(node, dict):
            raise ValueError(f"$ref does not resolve to a schema object: {ref}")
        return node

    def collect(self, value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
        errors: list[str] = []
        self.validate(value, schema, path, errors)
        return errors

    def validate(self, value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
        if "$ref" in schema:
            self.validate(value, self.resolve(str(schema["$ref"])), path, errors)
            return

        if "allOf" in schema:
            for branch in schema["allOf"]:
                self.validate(value, branch, path, errors)

        if "oneOf" in schema:
            branch_errors = [self.collect(value, branch, path) for branch in schema["oneOf"]]
            passing = [index for index, branch in enumerate(branch_errors) if not branch]
            if len(passing) != 1:
                if not passing:
                    shortest = min(branch_errors, key=len, default=[])
                    errors.append(f"{path}: does not match any allowed schema")
                    errors.extend(f"{message} (closest branch)" for message in shortest[:8])
                else:
                    errors.append(f"{path}: matches more than one allowed schema")
            return

        if "anyOf" in schema:
            if not any(not self.collect(value, branch, path) for branch in schema["anyOf"]):
                errors.append(f"{path}: does not match any allowed schema")
            return

        if "const" in schema and value != schema["const"]:
            errors.append(f"{path}: must equal {schema['const']!r}, got {value!r}")
        if "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: invalid value {value!r}; expected one of {schema['enum']!r}")

        expected = schema.get("type")
        if expected is not None:
            allowed = expected if isinstance(expected, list) else [expected]
            if not any(self._matches_type(value, name) for name in allowed):
                errors.append(f"{path}: expected {allowed!r}, got {self._type_name(value)}")
                return

        if isinstance(value, dict):
            required = schema.get("required", [])
            for key in required:
                if key not in value:
                    errors.append(f"{path}: missing required field {key!r}")
            properties = schema.get("properties", {})
            additional = schema.get("additionalProperties", True)
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if key in properties:
                    self.validate(child, properties[key], child_path, errors)
                elif additional is False:
                    errors.append(f"{path}: unexpected field {key!r}")
                elif isinstance(additional, dict):
                    self.validate(child, additional, child_path, errors)

        if isinstance(value, list):
            if len(value) < int(schema.get("minItems", 0)):
                errors.append(f"{path}: requires at least {schema['minItems']} item(s)")
            if "maxItems" in schema and len(value) > int(schema["maxItems"]):
                errors.append(f"{path}: allows at most {schema['maxItems']} item(s)")
            if schema.get("uniqueItems"):
                rendered = [json.dumps(item, sort_keys=True) for item in value]
                if len(rendered) != len(set(rendered)):
                    errors.append(f"{path}: array items must be unique")
            item_schema = schema.get("items")
            if isinstance(item_schema, dict):
                for index, child in enumerate(value):
                    self.validate(child, item_schema, f"{path}[{index}]", errors)

        if isinstance(value, str):
            if len(value) < int(schema.get("minLength", 0)):
                errors.append(f"{path}: string is shorter than {schema['minLength']}")
            if "maxLength" in schema and len(value) > int(schema["maxLength"]):
                errors.append(f"{path}: string is longer than {schema['maxLength']}")
            pattern = schema.get("pattern")
            if pattern and re.search(str(pattern), value) is None:
                errors.append(f"{path}: does not match pattern {pattern!r}")

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(f"{path}: must be >= {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(f"{path}: must be <= {schema['maximum']}")

    @staticmethod
    def _matches_type(value: Any, expected: str) -> bool:
        return {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "null": value is None,
        }.get(expected, True)

    @staticmethod
    def _type_name(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "number"
        return type(value).__name__


def safe_repo_file(repo: Path, relative: str) -> Path | None:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    resolved = (repo / candidate).resolve()
    try:
        resolved.relative_to(repo.resolve())
    except ValueError:
        return None
    return resolved


def validate_trace(trace: Any, label: str, repo: Path | None, errors: list[str]) -> None:
    if not isinstance(trace, list) or len(trace) < 2:
        errors.append(f"{label}: code trace must have at least entrypoint and sink steps")
        return
    if trace[0].get("kind") != "entrypoint":
        errors.append(f"{label}[0].kind must be 'entrypoint'")
    if trace[-1].get("kind") != "sink":
        errors.append(f"{label}[-1].kind must be 'sink'")
    for index, step in enumerate(trace[1:-1], start=1):
        if step.get("kind") != "propagation":
            errors.append(f"{label}[{index}].kind must be 'propagation'")

    if repo is None:
        return
    for index, step in enumerate(trace):
        relative = str(step.get("file", ""))
        path = safe_repo_file(repo, relative)
        if path is None:
            errors.append(f"{label}[{index}].file escapes target: {relative!r}")
            continue
        if not path.is_file():
            errors.append(f"{label}[{index}].file does not exist: {relative!r}")
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            errors.append(f"{label}[{index}].file cannot be read: {exc}")
            continue
        line = step.get("line")
        if not isinstance(line, int) or line < 1 or line > max(1, len(lines)):
            errors.append(f"{label}[{index}].line is outside {relative!r}")
        scope = str(step.get("scope", "")).strip()
        if scope and scope not in {"<module>", "module", "global", "<global>"}:
            if not any(scope in source_line for source_line in lines):
                errors.append(f"{label}[{index}].scope {scope!r} not found in {relative!r}")


def validate_source_location(location: Any, label: str, repo: Path | None, errors: list[str]) -> None:
    if not isinstance(location, dict) or repo is None:
        return
    relative = str(location.get("file", ""))
    path = safe_repo_file(repo, relative)
    if path is None:
        errors.append(f"{label}.file escapes target: {relative!r}")
        return
    if not path.is_file():
        errors.append(f"{label}.file does not exist: {relative!r}")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    line = location.get("line")
    if not isinstance(line, int) or line < 1 or line > max(1, len(lines)):
        errors.append(f"{label}.line is outside {relative!r}")
    scope = str(location.get("scope", "")).strip()
    if scope and scope not in {"<module>", "module", "global", "<global>"}:
        if not any(scope in source_line for source_line in lines):
            errors.append(f"{label}.scope {scope!r} not found in {relative!r}")


def semantic_errors(document: Any, kind: str, repo: Path | None) -> list[str]:
    errors: list[str] = []
    if kind == "candidate":
        validate_trace(document.get("trace") if isinstance(document, dict) else None, "$.trace", repo, errors)
        validate_source_location(document.get("root_cause_location") if isinstance(document, dict) else None, "$.root_cause_location", repo, errors)
        if isinstance(document, dict):
            location = document.get("root_cause_location") or {}
            trace_locations = {
                (str(step.get("file")), step.get("line"), str(step.get("scope")))
                for step in document.get("trace", [])
                if isinstance(step, dict)
            }
            key = (str(location.get("file")), location.get("line"), str(location.get("scope")))
            if key not in trace_locations:
                errors.append("$.root_cause_location must identify a cited trace step")
    elif kind == "validation-result" and isinstance(document, dict):
        corrections = document.get("corrections", [])
        corrected = document.get("corrected_candidate")
        status = document.get("status")
        if corrections and status in {"source_verified", "environment_required"} and not isinstance(corrected, dict):
            errors.append("$.corrected_candidate is required when a promoted result contains corrections")
        if isinstance(corrected, dict) and corrected.get("id") != document.get("candidate_id"):
            errors.append("$.corrected_candidate.id must equal candidate_id")
        if not corrections and corrected is not None:
            errors.append("$.corrected_candidate must be null when corrections is empty")
    elif kind == "reproduction-result" and isinstance(document, dict):
        if document.get("status") == "dynamic_verified":
            if document.get("sandbox") == "none":
                errors.append("$.sandbox must be an isolation backend for dynamic_verified")
            if not isinstance(document.get("test_ref"), str) or not isinstance(document.get("patch_ref"), str):
                errors.append("dynamic_verified requires test_ref and patch_ref")
            hashes = document.get("hashes") or {}
            if not hashes.get("test_sha256") or not hashes.get("patch_sha256"):
                errors.append("dynamic_verified requires test and patch hashes")
            if (document.get("before") or {}).get("status") != "expected_failure":
                errors.append("dynamic_verified requires an expected unpatched failure")
            if (document.get("before") or {}).get("exit_code") in {None, 0}:
                errors.append("dynamic_verified requires a nonzero unpatched exit code")
            if (document.get("after") or {}).get("status") != "passed":
                errors.append("dynamic_verified requires a patched pass")
            if (document.get("after") or {}).get("exit_code") != 0:
                errors.append("dynamic_verified requires a zero patched exit code")
            if document.get("errors"):
                errors.append("dynamic_verified may not contain errors")
    elif kind == "repo-context" and isinstance(document, dict):
        project_ids: set[str] = set()
        entrypoint_ids: set[str] = set()
        dependency_files: set[str] = set()
        for index, project in enumerate(document.get("projects", [])):
            if not isinstance(project, dict):
                continue
            project_id = str(project.get("id", ""))
            if project_id in project_ids:
                errors.append(f"$.projects[{index}].id is duplicated")
            project_ids.add(project_id)
            if repo is not None:
                base = safe_repo_file(repo, str(project.get("base_path", "")) or ".")
                if base is None or not base.is_dir():
                    errors.append(f"$.projects[{index}].base_path is not target-relative")
                for file_index, relative in enumerate(project.get("dependency_files", [])):
                    relative_text = str(relative)
                    path = safe_repo_file(repo, relative_text)
                    if path is None or not path.is_file():
                        errors.append(f"$.projects[{index}].dependency_files[{file_index}] does not exist")
                    if not is_supported_dependency_file(relative_text):
                        errors.append(f"$.projects[{index}].dependency_files[{file_index}] is not a supported Wraith input")
                    if relative_text in dependency_files:
                        errors.append(f"$.projects[{index}].dependency_files[{file_index}] is assigned to more than one project")
                    dependency_files.add(relative_text)
                    if base is not None and path is not None:
                        try:
                            path.relative_to(base)
                        except ValueError:
                            errors.append(f"$.projects[{index}].dependency_files[{file_index}] is outside the project base_path")
        if repo is not None:
            discovered = set(discover_dependency_files(repo))
            declared = dependency_files
            for relative in sorted(discovered - declared):
                errors.append(f"$.projects is missing supported dependency input {relative!r}")
            for relative in sorted(declared - discovered):
                errors.append(f"$.projects declares dependency input that deterministic discovery did not find: {relative!r}")
            for entry_index, entrypoint in enumerate(project.get("entry_points", [])):
                if not isinstance(entrypoint, dict):
                    continue
                entrypoint_id = str(entrypoint.get("id", ""))
                if entrypoint_id in entrypoint_ids:
                    errors.append(f"$.projects[{index}].entry_points[{entry_index}].id is duplicated")
                entrypoint_ids.add(entrypoint_id)
                if repo is not None:
                    path = safe_repo_file(repo, str(entrypoint.get("path", "")))
                    if path is None or not path.is_file():
                        errors.append(f"$.projects[{index}].entry_points[{entry_index}].path does not exist")
    elif kind == "security-surfaces" and isinstance(document, dict):
        entrypoint_ids: set[str] = set()
        boundary_ids = {str(item.get("id")) for item in document.get("trust_boundaries", []) if isinstance(item, dict)}
        for index, entrypoint in enumerate(document.get("entry_points", [])):
            if not isinstance(entrypoint, dict):
                continue
            entrypoint_id = str(entrypoint.get("id", ""))
            if entrypoint_id in entrypoint_ids:
                errors.append(f"$.entry_points[{index}].id is duplicated")
            entrypoint_ids.add(entrypoint_id)
            if repo is not None:
                path = safe_repo_file(repo, str(entrypoint.get("path", "")))
                if path is None or not path.is_file():
                    errors.append(f"$.entry_points[{index}].path does not exist")
            for boundary_id in entrypoint.get("trust_boundary_ids", []):
                if str(boundary_id) not in boundary_ids:
                    errors.append(f"$.entry_points[{index}] references unknown trust boundary {boundary_id!r}")
        if repo is not None:
            for index, item in enumerate(document.get("security_relevant_files", [])):
                if not isinstance(item, dict):
                    continue
                path = safe_repo_file(repo, str(item.get("path", "")))
                if path is None or not path.is_file():
                    errors.append(f"$.security_relevant_files[{index}].path does not exist")
    elif kind == "sca-advisories" and isinstance(document, dict) and repo is not None:
        seen: set[tuple[str, str, str, str]] = set()
        advisories = document.get("advisories", [])
        if document.get("advisory_count") != len(advisories):
            errors.append("$.advisory_count does not match advisories")
        for index, advisory in enumerate(advisories):
            if not isinstance(advisory, dict):
                continue
            key = tuple(str(advisory.get(name, "")) for name in ("advisory_id", "package", "version", "source_lockfile"))
            if key in seen:
                errors.append(f"$.advisories[{index}] duplicates an advisory/package/version/lockfile record")
            seen.add(key)
            path = safe_repo_file(repo, str(advisory.get("source_lockfile", "")))
            if path is None or not path.is_file():
                errors.append(f"$.advisories[{index}].source_lockfile does not exist")
    elif kind == "secrets-redacted" and isinstance(document, dict) and repo is not None:
        if document.get("candidate_count") != len(document.get("candidates", [])):
            errors.append("$.candidate_count does not match candidates")
        seen: set[str] = set()
        for index, candidate in enumerate(document.get("candidates", [])):
            if not isinstance(candidate, dict):
                continue
            candidate_id = str(candidate.get("id", ""))
            if candidate_id in seen:
                errors.append(f"$.candidates[{index}].id is duplicated")
            seen.add(candidate_id)
            relative = str(candidate.get("file", ""))
            path = safe_repo_file(repo, relative)
            if path is None or not path.is_file():
                errors.append(f"$.candidates[{index}].file does not exist")
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            line = candidate.get("line")
            if not isinstance(line, int) or line < 1 or line > max(1, len(lines)):
                errors.append(f"$.candidates[{index}].line is outside {relative!r}")
    elif kind == "hunt-plan" and isinstance(document, dict):
        cell_ids = [str(cell.get("id")) for cell in document.get("cells", []) if isinstance(cell, dict)]
        if len(cell_ids) != len(set(cell_ids)):
            errors.append("$.cells contains duplicate IDs")
        known = set(cell_ids)
        task_ids: set[str] = set()
        budget = document.get("budget", {})
        tasks = document.get("tasks", [])
        if isinstance(budget, dict) and len(tasks) > int(budget.get("max_hunt_tasks", len(tasks))):
            errors.append("$.tasks exceeds budget.max_hunt_tasks")
        for index, task in enumerate(tasks):
            task_id = str(task.get("id", ""))
            if task_id in task_ids:
                errors.append(f"$.tasks[{index}].id is duplicated")
            task_ids.add(task_id)
            for cell_id in task.get("cell_ids", []):
                if str(cell_id) not in known:
                    errors.append(f"$.tasks[{index}] references unknown cell {cell_id!r}")
            packet = str(task.get("context_packet", ""))
            limit = int(budget.get("context_packet_bytes", 65536)) if isinstance(budget, dict) else 65536
            if len(packet.encode("utf-8")) > limit:
                errors.append(f"$.tasks[{index}].context_packet exceeds {limit} bytes")
            if repo is not None:
                for file_index, relative in enumerate(task.get("files", [])):
                    path = safe_repo_file(repo, str(relative))
                    if path is None or not path.is_file():
                        errors.append(f"$.tasks[{index}].files[{file_index}] is not an existing target-relative file")
    elif kind == "threat-model" and isinstance(document, dict):
        subsystems = document.get("subsystems", [])
        subsystem_ids = [str(item.get("id")) for item in subsystems if isinstance(item, dict)]
        if len(subsystem_ids) != len(set(subsystem_ids)):
            errors.append("$.subsystems contains duplicate IDs")
        known = set(subsystem_ids)
        for index, subsystem in enumerate(subsystems):
            if not isinstance(subsystem, dict):
                continue
            if repo is not None:
                for file_index, relative in enumerate(subsystem.get("files", [])):
                    path = safe_repo_file(repo, str(relative))
                    if path is None or not path.is_file():
                        errors.append(f"$.subsystems[{index}].files[{file_index}] is not an existing target-relative file")
        class_ids: set[str] = set()
        for index, attack_class in enumerate(document.get("attack_classes", [])):
            if not isinstance(attack_class, dict):
                continue
            attack_id = str(attack_class.get("id", ""))
            if attack_id in class_ids:
                errors.append(f"$.attack_classes[{index}].id is duplicated")
            class_ids.add(attack_id)
            for subsystem_id in attack_class.get("applicable_subsystems", []):
                if str(subsystem_id) not in known:
                    errors.append(f"$.attack_classes[{index}] references unknown subsystem {subsystem_id!r}")
        boundary_ids = {str(item.get("id")) for item in document.get("trust_boundaries", []) if isinstance(item, dict)}
        asset_ids = {str(item.get("id")) for item in document.get("assets", []) if isinstance(item, dict)}
        entrypoint_ids: set[str] = set()
        for index, entrypoint in enumerate(document.get("entrypoints", [])):
            if not isinstance(entrypoint, dict):
                continue
            entrypoint_id = str(entrypoint.get("id", ""))
            if entrypoint_id in entrypoint_ids:
                errors.append(f"$.entrypoints[{index}].id is duplicated")
            entrypoint_ids.add(entrypoint_id)
            if repo is not None:
                path = safe_repo_file(repo, str(entrypoint.get("path", "")))
                if path is None or not path.is_file():
                    errors.append(f"$.entrypoints[{index}].path is not an existing target-relative file")
            for subsystem_id in entrypoint.get("subsystem_ids", []):
                if str(subsystem_id) not in known:
                    errors.append(f"$.entrypoints[{index}] references unknown subsystem {subsystem_id!r}")
            for boundary_id in entrypoint.get("trust_boundary_ids", []):
                if str(boundary_id) not in boundary_ids:
                    errors.append(f"$.entrypoints[{index}] references unknown trust boundary {boundary_id!r}")
        for index, threat in enumerate(document.get("threats", [])):
            if not isinstance(threat, dict):
                continue
            for asset_id in threat.get("asset_ids", []):
                if str(asset_id) not in asset_ids:
                    errors.append(f"$.threats[{index}] references unknown asset {asset_id!r}")
            for entrypoint_id in threat.get("entrypoint_ids", []):
                if str(entrypoint_id) not in entrypoint_ids:
                    errors.append(f"$.threats[{index}] references unknown entrypoint {entrypoint_id!r}")
            for attack_id in threat.get("attack_class_ids", []):
                if str(attack_id) not in class_ids:
                    errors.append(f"$.threats[{index}] references unknown attack class {attack_id!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("schema", type=Path)
    parser.add_argument("document", type=Path)
    parser.add_argument(
        "--semantic",
        choices=["none", "candidate", "validation-result", "reproduction-result", "repo-context", "security-surfaces", "sca-advisories", "secrets-redacted", "hunt-plan", "threat-model"],
        default="none",
    )
    parser.add_argument("--target", type=Path)
    parser.add_argument("--each", action="store_true", help="validate each item in a top-level array against the schema")
    args = parser.parse_args()

    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        document = json.loads(args.document.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[validate-json] ERROR: {exc}", file=sys.stderr)
        return 1

    if args.each:
        if not isinstance(document, list):
            errors = ["$: --each requires a top-level array"]
        else:
            errors = []
            validator = Validator(schema)
            for index, item in enumerate(document):
                errors.extend(
                    message.replace("$", f"$[{index}]", 1)
                    for message in validator.collect(item, schema)
                )
                if args.semantic != "none":
                    errors.extend(
                        message.replace("$", f"$[{index}]", 1)
                        for message in semantic_errors(item, args.semantic, args.target)
                    )
    else:
        errors = Validator(schema).collect(document, schema)
        if args.semantic != "none":
            errors.extend(semantic_errors(document, args.semantic, args.target))
    if errors:
        for error in errors:
            print(f"[validate-json] ERROR: {error}", file=sys.stderr)
        print(f"[validate-json] failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"[validate-json] valid: {args.document}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
