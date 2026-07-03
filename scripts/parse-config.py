#!/usr/bin/env python3
"""parse-config.py — Read config.toml and emit shell export lines.

Usage:
    python3 scripts/parse-config.py [HARNESS_ROOT]

If HARNESS_ROOT is omitted, defaults to the script's parent-of-parent directory.
Output is one `export KEY=VALUE` line per variable, suitable for shell eval.
No config.toml = no output (silent exit 0).
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+ stdlib
except ModuleNotFoundError:
    # Python < 3.11 fallback — shouldn't happen on the target venv, but
    # fail gracefully rather than crashing.
    sys.exit(0)


def _find_root(argv: list[str]) -> Path:
    if len(argv) > 1:
        return Path(argv[1]).resolve()
    return Path(__file__).resolve().parent.parent


def _dquote(val: str) -> str:
    """Escape double-quote characters inside a shell double-quoted string."""
    return val.replace("\\", "\\\\").replace('"', '\\"')


def main() -> None:
    root = _find_root(sys.argv)
    config_path = root / "config.toml"
    if not config_path.exists():
        return

    with open(config_path, "rb") as f:
        cfg = tomllib.load(f)

    llm = cfg.get("llm", {})

    # ── Core LLM vars ─────────────────────────────────────────────────
    base_url = str(llm.get("base_url", "") or "")
    api_key = str(llm.get("api_key", "") or "")
    model = str(llm.get("model", "") or "")
    provider = llm.get("provider", {})
    provider_name = str(provider.get("name", "on-prem") or "on-prem")
    provider_api = str(provider.get("api", "openai-completions") or "openai-completions")
    provider_auth = str(provider.get("auth", "api-key") or "api-key")

    exports: list[tuple[str, str]] = [
        ("ON_PREM_LLM_BASE_URL", base_url),
        ("ON_PREM_API_KEY", api_key),
        ("ON_PREM_MODEL_NAME", model),
        ("ON_PREM_PROVIDER_NAME", provider_name),
        ("ON_PREM_PROVIDER_API", provider_api),
        ("ON_PREM_PROVIDER_AUTH", provider_auth),
    ]

    # ── Emit ──────────────────────────────────────────────────────────
    for key, val in exports:
        print(f'export {key}="{_dquote(val)}"')


if __name__ == "__main__":
    main()
