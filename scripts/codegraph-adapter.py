#!/usr/bin/env python3
"""Typed, bounded adapter for the actual offline codegraph JSON contracts."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from codegraph_contract import SYMBOL_OPERATIONS, audit_request, finish_discovery_query, resolve_subject


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_json(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    tmp.write_bytes(data)
    tmp.replace(path)
    return data


def bounded_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512 or "\x00" in value:
        raise ValueError(f"{label} must be a nonempty string of at most 512 characters")
    return value


def node_id(item: Any) -> str:
    if isinstance(item, dict):
        if item.get("id") is not None:
            return bounded_text(item["id"], "graph identifier")
        file = item.get("filePath", item.get("file_path"))
        name = item.get("qualifiedName", item.get("qualified_name", item.get("name")))
        line = item.get("startLine", item.get("start_line"))
        if file and name and line is not None:
            identity = json.dumps([file, name, line], ensure_ascii=False, separators=(",", ":"))
            return bounded_text("symbol:" + identity, "graph identifier")
        if file and not name:
            return bounded_text(file, "graph identifier")
        raise ValueError("graph symbol lacks a stable ID or qualified location")
    return bounded_text(item, "graph identifier")


class Accumulator:
    """One retained graph budget shared by every expanded subprocess response."""
    def __init__(self, operation: str):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], dict] = {}
        self.completeness = {"local_truncated": False, "dropped_nodes": 0, "dropped_edges": 0,
                             "upstream_truncated": False, "upstream_complete": True,
                             "heuristic": operation in {"query", "impact", "affected"}}

    def add_node(self, item: Any, role: str, synthetic: bool = False) -> str:
        identifier = node_id(item)
        node = {"id": identifier, "role": role, "synthetic": synthetic}
        if isinstance(item, dict):
            for keys, target in ((('name',), 'name'), (('qualifiedName', 'qualified_name'), 'qualified_name'),
                                 (('filePath', 'file_path'), 'file'), (('kind',), 'kind')):
                value = next((item[key] for key in keys if item.get(key) is not None), None)
                if value is not None:
                    node[target] = bounded_text(value, f"graph {target}")
            line = item.get("startLine", item.get("start_line"))
            if line is not None:
                if type(line) is not int or line < 1:
                    raise ValueError("graph line must be a positive integer")
                node["line"] = line
        if identifier in self.nodes:
            existing = self.nodes[identifier]
            for key in ("name", "qualified_name", "file", "line", "kind"):
                if key in node:
                    existing.setdefault(key, node[key])
            if role == "result":
                existing["role"] = role
        elif len(self.nodes) < 500:
            self.nodes[identifier] = node
        else:
            self.completeness["dropped_nodes"] += 1
        return identifier

    def add_edge(self, source: str, target: str, kind: str) -> None:
        key = (source, target, kind)
        if key in self.edges:
            return
        if source not in self.nodes or target not in self.nodes or len(self.edges) >= 1000:
            self.completeness["dropped_edges"] += 1
        else:
            self.edges[key] = {"source": source, "target": target, "kind": kind}

    def consume(self, operation: str, subject: str, raw: object, sources: list[dict] | None = None) -> None:
        metadata = raw if isinstance(raw, dict) else {}
        truncated = metadata.get("truncated") is True
        self.completeness["upstream_truncated"] |= truncated
        complete = False if truncated else metadata.get("complete")
        prior = self.completeness["upstream_complete"]
        self.completeness["upstream_complete"] = (False if complete is False or prior is False else
                                                  True if complete is True and prior is True else None)
        self.completeness["heuristic"] |= metadata.get("heuristic") is True
        if sources:
            source_ids = [self.add_node(item, "source") for item in sources]
        else:
            source_ids = [self.add_node({"id": f"{operation}:" + hashlib.sha256(subject.encode()).hexdigest()}, "source", True)]
        if operation == "query":
            items = raw if isinstance(raw, list) else metadata.get("results", [])
            groups = [("search_match", items)]
        else:
            keys = {"callers": ("callers",), "callees": ("callees",), "impact": ("affected",),
                    "affected": ("changedFiles", "affectedTests", "affectedFiles")}[operation]
            groups = [(key if operation == "affected" else operation, metadata.get(key, [])) for key in keys]
        for kind, items in groups:
            for item in items:
                candidate = item.get("node", item) if isinstance(item, dict) else item
                if operation == "affected" and node_id(candidate) == subject:
                    continue
                identifier = self.add_node(candidate, "result")
                for source in source_ids:
                    if source != identifier:
                        self.add_edge(identifier, source, kind) if operation == "callers" else self.add_edge(source, identifier, kind)

    def result(self) -> tuple[list[dict], list[dict], list[str], dict]:
        self.completeness["local_truncated"] = bool(self.completeness["dropped_nodes"] or self.completeness["dropped_edges"])
        warnings = []
        if self.completeness["local_truncated"]:
            warnings.append("Graph navigation output exceeded the normalized node or edge bound")
        if self.completeness["upstream_truncated"]:
            warnings.append("Codegraph returned bounded, truncated navigation results")
        return list(self.nodes.values()), list(self.edges.values()), warnings, self.completeness


def normalize(operation: str, subject: str, raw: object) -> tuple[list[dict], list[dict], list[str], dict]:
    accumulator = Accumulator(operation)
    accumulator.consume(operation, subject, raw)
    return accumulator.result()


def execute(binary: Path, project: Path, operation: str, subject: str, file: str | None = None,
            timeout_seconds: float = 120) -> tuple[list[dict], list[dict], list[str], dict]:
    bounded_text(subject, "graph subject")
    if file is not None:
        bounded_text(file, "graph file")
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ValueError("graph timeout must be greater than zero and at most 120 seconds")
    deadline = time.monotonic() + timeout_seconds
    definitions = resolve_subject(operation, subject, project, file)
    requests = [(subject, None)] if operation not in SYMBOL_OPERATIONS else list(dict.fromkeys(
        (item["name"], item["file_path"]) for item in definitions))
    accumulator = Accumulator(operation)
    environment = {key: value for key, value in os.environ.items() if key != "VULNOPS_ADVANTAGE_CALL"}
    for symbol, scope in requests:
        command = [str(binary), operation, "-p", str(project), symbol, "--json"]
        if scope is not None:
            command.extend(["--file", scope])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Codegraph query exceeded its time bound")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=remaining, env=environment)
        except subprocess.TimeoutExpired:
            raise ValueError("Codegraph query exceeded its time bound") from None
        if result.returncode:
            raise ValueError(f"codegraph exited {result.returncode}")
        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise ValueError("codegraph emitted malformed JSON") from None
        keys = {"callers": ("callers",), "callees": ("callees",), "impact": ("affected",),
                "affected": ("changedFiles", "affectedTests")}
        if operation == "query":
            items = raw if isinstance(raw, list) else raw.get("results") if isinstance(raw, dict) else None
            valid = isinstance(items, list) and all(isinstance(item, dict) for item in items)
        else:
            valid = isinstance(raw, dict) and all(isinstance(raw.get(key), list) for key in keys[operation])
            if valid and "affectedFiles" in raw:
                valid = isinstance(raw["affectedFiles"], list)
        if operation in SYMBOL_OPERATIONS and valid:
            valid = all(isinstance(item, dict) and isinstance(item.get("name"), str)
                        and isinstance(item.get("filePath"), str) for item in raw[keys[operation][0]])
        if not valid:
            raise ValueError("codegraph emitted an incompatible JSON shape")
        sources = None
        if scope is not None:
            targets = raw.get("targets")
            if not isinstance(targets, list) or not targets or any(
                not isinstance(item, dict) or item.get("filePath") != scope for item in targets
            ):
                raise ValueError("Codegraph did not honor the resolved symbol file")
            sources = [item for item in definitions if item["file_path"] == scope and item["name"] == symbol]
            if any(not isinstance(item.get("id"), str) for item in targets) or {item["id"] for item in targets} != {item["id"] for item in sources}:
                raise ValueError("Codegraph resolved a different or ambiguous symbol set")
        accumulator.consume(operation, subject, raw, sources)
    return accumulator.result()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", nargs="?", choices=("query", "callers", "callees", "impact", "affected"))
    parser.add_argument("subject", nargs="?")
    parser.add_argument("--probe", action="store_true")
    for name in ("project", "output", "receipt", "context"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--file")
    parser.add_argument("--phase", choices=("intrusion", "campaign-planning", "investigation", "gap-exploration"))
    parser.add_argument("--owner")
    parser.add_argument("--question")
    args = parser.parse_args()
    if args.probe:
        if not all((args.operation, args.subject, args.project, args.output, args.receipt)) or any((args.context, args.phase, args.owner, args.question)):
            parser.error("--probe requires operation, subject, --project, --output and --receipt, without audit options")
        project, output, receipt_path = args.project.resolve(), args.output, args.receipt
        operation, subject, file = args.operation, args.subject, args.file
        binding = {"run_id": "probe", "attempt_id": "probe",
                   "phase": "probe", "owner_id": "probe", "question_id": "probe",
                   "operation": operation, "subject": subject, "file": file}
    else:
        if not all((args.context, args.phase, args.owner, args.question)) or any(value is not None for value in (args.operation, args.subject, args.project, args.output, args.receipt, args.file)):
            parser.error("audit queries require --context, --phase, --owner and --question only")
        try:
            request = audit_request(args.context, args.phase, args.owner, args.question)
        except (ValueError, OSError) as exc:
            parser.error(str(exc))
        project, output, receipt_path, binding = (request[key] for key in ("project", "output", "receipt", "binding"))
        operation, subject, file = (binding[key] for key in ("operation", "subject", "file"))
    bounded_text(subject, "graph subject")
    if file is not None:
        bounded_text(file, "graph file")
    binary = Path(__file__).resolve().parent.parent / "bins/codegraph"
    started, clock = now(), time.monotonic()
    try:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("optional Codegraph binary is unavailable; continue source-only")
        if not (project / ".codegraph").exists():
            raise ValueError("optional Codegraph project is unavailable; continue source-only")
        timeout_seconds = 120 if args.probe else request.get("timeout_seconds", 120)
        nodes, edges, warnings, completeness = execute(binary, project, operation, subject, file, timeout_seconds=timeout_seconds)
        parse_status = "ok"
    except (ValueError, OSError) as exc:
        nodes, edges, warnings, completeness = Accumulator(operation).result()
        completeness["upstream_complete"] = None
        warnings = [str(exc) if isinstance(exc, ValueError) else "Codegraph execution failed"]
        parse_status = "failed"
    elapsed = time.monotonic() - clock
    if not args.probe:
        finish_discovery_query(request, elapsed)
    meaningful = bool(edges) or any(node["role"] == "result" for node in nodes)
    document = {"schema_version": "2.0", "tool": "codegraph", "operation": operation, "subject": subject,
                "nodes": nodes, "edges": edges, "meaningful": meaningful, "binding": binding, "completeness": completeness}
    rendered = atomic_json(output, document)
    try:
        environment = {key: value for key, value in os.environ.items() if key != "VULNOPS_ADVANTAGE_CALL"}
        version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=False, timeout=5, env=environment).stdout.strip().splitlines()
    except (OSError, subprocess.TimeoutExpired):
        version = []
    receipt = {"schema_version": "2.0", "tool": "codegraph", "operation": operation,
               "status": "ok" if parse_status == "ok" else "failed", "version": version[0] if version else "unknown",
               "started_at": started, "completed_at": now(), "parse_status": parse_status,
               "result_count": sum(node["role"] == "result" for node in nodes),
               "normalized_sha256": hashlib.sha256(rendered).hexdigest(), "meaningful": meaningful,
               "warnings": warnings, "binding": binding, "completeness": completeness, "elapsed_seconds": elapsed}
    atomic_json(receipt_path, receipt)
    if not args.probe and "gap_query" in request:
        from gap_graph import record_receipt
        record_receipt(request)
    return 0 if parse_status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
