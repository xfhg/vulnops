#!/usr/bin/env python3
"""Fail closed unless OMP resolves the independent verifier's exact model."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


AGENT = "vulnops-independent-verify-one"
EFFORTS = {"off", "minimal", "low", "medium", "high", "xhigh", "max", "auto"}


def run_json(command: list[str]) -> dict:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RuntimeError(f"command failed ({' '.join(command)}){suffix}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"command returned invalid JSON ({' '.join(command)})") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"command returned a non-object ({' '.join(command)})")
    return value


def split_selector(selector: str) -> tuple[str, str, str | None]:
    provider, slash, model_with_effort = selector.partition("/")
    if not slash or not provider or not model_with_effort:
        raise RuntimeError("verifier selector must use provider/model syntax")
    model, colon, suffix = model_with_effort.rpartition(":")
    if colon and suffix.lower() in EFFORTS:
        if not model:
            raise RuntimeError("verifier selector has an empty model ID")
        return provider, model, suffix.lower()
    return provider, model_with_effort, None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("omp", type=Path)
    parser.add_argument("selector")
    args = parser.parse_args()

    try:
        resolved = run_json([str(args.omp), "config", "get", "task.agentModelOverrides", "--json"])
        overrides = resolved.get("value")
        if not isinstance(overrides, dict):
            raise RuntimeError("OMP task.agentModelOverrides did not resolve to a record")
        actual = overrides.get(AGENT)
        if actual != args.selector:
            raise RuntimeError(
                f"OMP verifier override mismatch: expected {args.selector!r}, resolved {actual!r}"
            )

        provider, model_id, effort = split_selector(args.selector)
        catalog = run_json([str(args.omp), "models", provider, "--json", "--no-extensions"])
        models = catalog.get("models")
        if not isinstance(models, list):
            raise RuntimeError(f"OMP model catalog for {provider!r} is malformed")
        match = next(
            (
                item
                for item in models
                if isinstance(item, dict)
                and item.get("provider") == provider
                and item.get("id") == model_id
            ),
            None,
        )
        if match is None:
            raise RuntimeError(f"verifier model is absent from OMP catalog: {provider}/{model_id}")
        supported = match.get("thinking")
        if effort and (not isinstance(supported, list) or effort not in supported):
            raise RuntimeError(
                f"verifier effort {effort!r} is unsupported by {provider}/{model_id}"
            )
    except RuntimeError as exc:
        print(f"[probe-verifier-model] ERROR: {exc}", file=sys.stderr)
        return 1

    effort_note = f" at {effort}" if effort else ""
    print(f"[probe-verifier-model] verifier resolved: {provider}/{model_id}{effort_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
