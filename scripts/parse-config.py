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


def _boolish(val: object, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _depth_value(section: object, depth: str, default: int) -> int:
    if isinstance(section, dict):
        raw = section.get(depth, default)
    else:
        raw = default
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def main() -> None:
    root = _find_root(sys.argv)
    config_path = root / "config.toml"
    if not config_path.exists():
        return

    with open(config_path, "rb") as f:
        cfg = tomllib.load(f)

    llm = cfg.get("llm", {})
    graphify = cfg.get("graphify", {})

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

    # ── Graphify resolved LLM vars ────────────────────────────────────
    # Empty graphify fields inherit the same endpoint/key/model used by OMP.
    g_backend_raw = str(graphify.get("backend", "") or "").strip()
    g_base_url = str(graphify.get("base_url", "") or "").strip() or base_url
    g_api_key = str(graphify.get("api_key", "") or "")
    g_model = str(graphify.get("model", "") or "").strip() or model
    g_provider_name = "vulnops-onprem"
    g_backend = g_backend_raw or g_provider_name
    g_auth = str(graphify.get("auth", "") or "").strip() or provider_auth

    # The OpenAI SDK used by Graphify requires a non-empty key string even for
    # no-auth local gateways. Keep real keys intact; use a placeholder only when
    # the configured auth mode says no Authorization header is needed.
    g_resolved_key = g_api_key if g_api_key else api_key
    if not g_resolved_key and g_auth == "none":
        g_resolved_key = "local"

    exports.extend(
        [
            ("GRAPHIFY_BACKEND", g_backend),
            ("GRAPHIFY_BASE_URL", g_base_url),
            ("GRAPHIFY_MODEL", g_model),
            ("GRAPHIFY_PROVIDER_NAME", g_provider_name),
            ("GRAPHIFY_PROVIDER_AUTH", g_auth),
            ("GRAPHIFY_GENERATED_PROVIDER", "1" if g_backend == g_provider_name else "0"),
            ("VULNOPS_GRAPHIFY_API_KEY", g_resolved_key),
            ("GRAPHIFY_FULL_REPO", "1" if _boolish(graphify.get("full_repo"), False) else "0"),
            ("GRAPHIFY_CLUSTER_WHEN", str(graphify.get("cluster_when", "cross_module_only") or "cross_module_only")),
            ("GRAPHIFY_MAX_SCOPE_FILES_QUICK", str(_depth_value(graphify.get("max_scope_files"), "quick", 40))),
            ("GRAPHIFY_MAX_SCOPE_FILES_BALANCED", str(_depth_value(graphify.get("max_scope_files"), "balanced", 100))),
            ("GRAPHIFY_MAX_SCOPE_FILES_FULL", str(_depth_value(graphify.get("max_scope_files"), "full", 200))),
            ("GRAPHIFY_MAX_SCOPES_QUICK", str(_depth_value(graphify.get("max_scopes"), "quick", 4))),
            ("GRAPHIFY_MAX_SCOPES_BALANCED", str(_depth_value(graphify.get("max_scopes"), "balanced", 8))),
            ("GRAPHIFY_MAX_SCOPES_FULL", str(_depth_value(graphify.get("max_scopes"), "full", 16))),
        ]
    )

    if g_backend == "ollama":
        exports.append(("OLLAMA_BASE_URL", g_base_url))
        if g_resolved_key:
            exports.append(("OLLAMA_API_KEY", g_resolved_key))
        exports.append(("OLLAMA_MODEL", g_model))

    if g_backend == "openai" and g_resolved_key:
        exports.append(("OPENAI_API_KEY", g_resolved_key))

    # ── Emit ──────────────────────────────────────────────────────────
    for key, val in exports:
        print(f'export {key}="{_dquote(val)}"')


if __name__ == "__main__":
    main()
