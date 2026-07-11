#!/usr/bin/env python3
"""Typed, bounded adapter for the actual offline codegraph JSON contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_json(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    tmp.write_bytes(data)
    tmp.replace(path)
    return data


def node_id(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("name") or item.get("filePath") or item.get("id") or "").strip()
    return str(item).strip()


def normalize(operation: str, subject: str, raw: object) -> tuple[list[dict], list[dict], list[str]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    warnings: list[str] = []
    seen: set[str] = set()

    def add_node(identifier: str, role: str, item: object | None = None) -> None:
        identifier = identifier.strip()
        if not identifier or identifier in seen:
            return
        seen.add(identifier)
        node = {"id": identifier[:512], "role": role}
        if isinstance(item, dict):
            for source, target in (("kind", "kind"), ("filePath", "file"), ("startLine", "line")):
                if source in item:
                    node[target] = item[source]
        nodes.append(node)

    source_id = f"query:{subject}" if operation == "query" else subject
    add_node(source_id, "source")
    if operation in {"callers", "callees"}:
        key = operation
        items = raw.get(key, []) if isinstance(raw, dict) else []
        for item in items if isinstance(items, list) else []:
            identifier = node_id(item)
            add_node(identifier, "result", item)
            if identifier and identifier != subject:
                source, target = (identifier, subject) if operation == "callers" else (subject, identifier)
                edges.append({"source": source, "target": target, "kind": operation})
    elif operation == "impact":
        items = raw.get("affected", []) if isinstance(raw, dict) else []
        for item in items if isinstance(items, list) else []:
            identifier = node_id(item)
            add_node(identifier, "result", item)
            if identifier and identifier != subject:
                edges.append({"source": subject, "target": identifier, "kind": "impact"})
    elif operation == "affected":
        if isinstance(raw, dict):
            values: list[tuple[str, str]] = []
            for key in ("changedFiles", "affectedTests", "affectedFiles"):
                for item in raw.get(key, []) if isinstance(raw.get(key), list) else []:
                    values.append((node_id(item), key))
            for identifier, kind in values:
                if identifier == subject:
                    continue
                add_node(identifier, "result")
                if identifier:
                    edges.append({"source": subject, "target": identifier, "kind": kind})
    elif operation == "query":
        items = raw if isinstance(raw, list) else raw.get("results", []) if isinstance(raw, dict) else []
        for item in items if isinstance(items, list) else []:
            candidate = item.get("node", item) if isinstance(item, dict) else item
            identifier = node_id(candidate)
            add_node(identifier, "result", candidate)
            if identifier:
                edges.append({"source": source_id, "target": identifier, "kind": "search_match"})
    else:
        warnings.append(f"unsupported operation: {operation}")
    return nodes[:500], edges[:1000], warnings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("query", "callers", "callees", "impact", "affected"))
    parser.add_argument("subject")
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    binary = root / "bins/codegraph"
    project = args.project.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit("codegraph binary is unavailable")
    if not (project / ".codegraph").exists():
        raise SystemExit("codegraph project is not initialized")

    started = now()
    command = [str(binary), args.operation, "-p", str(project), args.subject, "--json"]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    warnings: list[str] = []
    parse_status = "ok"
    raw: object = {}
    if result.returncode:
        parse_status = "failed"
        warnings.append(f"codegraph exited {result.returncode}")
    else:
        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            parse_status = "failed"
            warnings.append("codegraph emitted malformed JSON")
    nodes, edges, parse_warnings = normalize(args.operation, args.subject, raw) if parse_status == "ok" else ([], [], [])
    warnings.extend(parse_warnings)
    meaningful = bool(edges) or any(node.get("role") == "result" for node in nodes)
    document = {
        "schema_version": "2.0", "tool": "codegraph", "operation": args.operation,
        "subject": args.subject[:512], "nodes": nodes, "edges": edges,
        "meaningful": meaningful,
    }
    rendered = atomic_json(args.output, document)
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=False).stdout.strip().splitlines()
    receipt = {
        "schema_version": "2.0", "tool": "codegraph", "operation": args.operation,
        "status": "ok" if parse_status == "ok" else "failed",
        "version": version[0] if version else "unknown", "started_at": started,
        "completed_at": now(), "parse_status": parse_status,
        "result_count": len(nodes) - 1 if nodes else 0,
        "normalized_sha256": hashlib.sha256(rendered).hexdigest(), "meaningful": meaningful,
        "warnings": warnings,
    }
    atomic_json(args.receipt, receipt)
    return 0 if parse_status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
