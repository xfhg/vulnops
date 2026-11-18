#!/usr/bin/env python3
"""Verify canonical model routes; live mode additionally proves bounded inference."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import importlib.util
from pathlib import Path

from model_routing import load_routing, split_selector


def run_json(command: list[str]) -> dict:
    result = subprocess.run(command, input="", text=True, capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise ValueError("OMP configuration/catalog command failed; provider output withheld")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("OMP returned malformed configuration/catalog data")
    return value


def check_catalog(catalog: dict, selector: str) -> None:
    provider, model, effort = split_selector(selector)
    match = next((item for item in catalog.get("models", [])
                  if item.get("provider") == provider and item.get("id") == model), None)
    if match is None:
        raise ValueError(f"model absent from catalog: {selector}")
    if effort not in match.get("thinking", []):
        raise ValueError(f"unsupported reasoning effort: {selector}")


def _failure_detail(messages: list[dict], stderr: str) -> str:
    # Classify only known error markers; never echo provider-controlled text.
    errors = [stderr, *(message.get("errorMessage", "") for message in messages)]
    text = "\n".join(value for value in errors if isinstance(value, str)).lower()
    tls_codes = (
        "unable_to_get_issuer_cert_locally", "unable_to_verify_leaf_signature",
        "self_signed_cert_in_chain", "depth_zero_self_signed_cert",
        "cert_has_expired", "certificate_verify_failed",
    )
    if any(code in text for code in tls_codes):
        return ("TLS certificate verification failed; set NODE_EXTRA_CA_CERTS to an "
                "administrator-approved PEM CA bundle; do not disable TLS verification")
    if "requires a sandbox with reviewed escalations" in text:
        return ("the selected model requires a sandbox with reviewed escalations; "
                "use a supported client with enforced sandboxing and approval review; "
                "a model selector or Daybreak toggle alone cannot satisfy this requirement")
    for code, advice in (
        ("access_program_not_enabled", "enable the approved Daybreak tier for the authenticated workspace/project"),
        ("invalid_access_program", "check the model-specific Daybreak request program"),
        ("unsupported_access_program", "the selected model does not support that Daybreak request program"),
    ):
        if code in text:
            return f"{code}; {advice}"
    return "verify provider authentication/access; provider failure was not classified"


def live_probe(omp: Path, selector: str, work: Path) -> None:
    provider, model, effort = split_selector(selector)
    with tempfile.TemporaryDirectory(prefix="model-readiness-", dir=work) as temporary:
        directory = Path(temporary)
        result = subprocess.run([
            str(omp), "--cwd", str(directory), "--model", f"{provider}/{model}",
            "--thinking", effort, "--no-tools", "--no-extensions", "--no-skills",
            "--no-rules", "--no-lsp", "--no-title", "--session-dir", str(directory / "sessions"),
            "--max-time", "45s", "--mode", "json", "-p", "Reply only OK.",
        ], input="", text=True, capture_output=True, timeout=60, check=False)
        # Never publish raw model output, provider errors or transcripts.
        messages = []
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            message = event.get("message", {})
            if event.get("type") == "message_end" and message.get("role") == "assistant":
                messages.append(message)
        if result.returncode or not messages or any(message.get("stopReason") == "error" for message in messages):
            raise ValueError(f"live inference failed: {selector}; {_failure_detail(messages, result.stderr)}")
        if any(message.get("provider") != provider or message.get("model") != model for message in messages):
            raise ValueError(f"live inference failed or substituted model: {selector}")
        selected_model = selected_effort = None
        for session in (directory / "sessions").rglob("*.jsonl"):
            for line in session.read_text().splitlines():
                event = json.loads(line)
                if event.get("type") == "model_change":
                    selected_model = event.get("model")
                if event.get("type") == "thinking_level_change":
                    selected_effort = event.get("thinkingLevel")
        if selected_model != f"{provider}/{model}" or selected_effort != effort:
            raise ValueError(f"runtime model/effort metadata mismatch: {selector}")


def dispatch_probe(root: Path, omp: Path, routing: dict) -> None:
    """Exercise every canonical override with disposable, non-audit agent bodies."""
    spec = importlib.util.spec_from_file_location("omp_lifecycle", root / "scripts/probe-omp-lifecycle.py")
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    coordinator = "vulnops-intrusion"
    workers = [agent for agent in routing["agents"] if agent != coordinator]
    with tempfile.TemporaryDirectory(prefix="routing-dispatch-", dir=root / ".harness") as temporary:
        base = Path(temporary)
        agents = base / ".omp/agents"
        agents.mkdir(parents=True)
        for agent in workers:
            (agents / f"{agent}.md").write_text(
                f"---\nname: {agent}\ndescription: Synthetic routing worker\nmodel: [pi/task]\n"
                "thinkingLevel: high\nblocking: false\ntools: [yield]\noutput:\n"
                "  properties:\n    status:\n      enum: [ok]\n---\n"
                "Synthetic routing check only. Immediately yield {data:{status:'ok'}}. Do not access files or tools other than yield.\n")
        assignments = [{"name": f"Route{index}", "agent": agent,
                        "task": "Follow the synthetic routing definition and yield status ok.",
                        "solutionSpace": "One fixed synthetic response", "schemaMode": "strict"}
                       for index, agent in enumerate(workers)]
        (agents / f"{coordinator}.md").write_text(
            f"---\nname: {coordinator}\ndescription: Synthetic routing coordinator\nmodel: [pi/task]\n"
            "thinkingLevel: high\nblocking: false\ntools: [task, wait, yield]\n"
            f"spawns: [{', '.join(workers)}]\noutput:\n  properties:\n    status:\n      enum: [ok]\n---\n"
            "Spawn these exact tasks in one batch with shared context 'Synthetic routing only'. "
            "Never supply model or outputSchema. Await every terminal delivery before yielding status ok: "
            + json.dumps(assignments))
        guard = base / "guard.ts"
        guard.write_text('export default function(pi) { pi.on("tool_call", async e => {'
                         'if (!["task","wait","yield"].includes(e.toolName)) return {block:true,reason:"Synthetic routing only"};'
                         'if(e.toolName==="task" && e.input.tasks.some(t=>t.model!=null)) return {block:true,reason:"Use canonical override"};'
                         '}); }')
        provider, model, effort = split_selector(routing["controllers"]["audit"])
        prompt = (f"Run only this synthetic routing check: spawn one {coordinator} named RoutingCoordinator, "
                  "schemaMode strict, no model or outputSchema. Tell it to follow its definition. "
                  "Wait for terminal completion; never finish on a spawn acknowledgement. Do not access files.")
        try:
            lifecycle.run_bounded([
                str(omp), "--model", f"{provider}/{model}", "--thinking", effort,
                "--no-title", "--no-skills", "--no-rules", "--no-extensions",
                "--extension", str(guard), "--tools", "task,wait",
                "--session-dir", str(base / "sessions"), "--mode", "json", "-p", prompt,
            ], base, base / "events.jsonl", 240)
            expected = {"RoutingCoordinator": routing["agents"][coordinator],
                        **{f"RoutingCoordinator.Route{index}": routing["agents"][agent] for index, agent in enumerate(workers)}}
            for name, selector in expected.items():
                sessions = list(base.rglob(f"{name}.jsonl"))
                if len(sessions) != 1:
                    raise ValueError(f"missing or duplicate routing session: {name}")
                records = [json.loads(line) for line in sessions[0].read_text().splitlines()]
                selected = [item.get("model") for item in records if item.get("type") == "model_change"]
                efforts = [item.get("thinkingLevel") for item in records if item.get("type") == "thinking_level_change"]
                p, m, e = split_selector(selector)
                if not selected or any(value != f"{p}/{m}" for value in selected) or not efforts or any(value != e for value in efforts):
                    raise ValueError(f"nested runtime routing mismatch: {name}")
            deliveries = lifecycle.deliveries(lifecycle.messages(base / "events.jsonl"))
            if not any(lifecycle.valid(job, {"status": "ok"}) for _, job in deliveries):
                raise ValueError("routing coordinator did not deliver a valid terminal result")
        except lifecycle.ProbeFailure as exc:
            raise ValueError(f"nested routing dispatch failed: {exc}") from None
        print(f"[model-routing] nested dispatch verified for {len(expected)} canonical agents")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("omp", type=Path)
    parser.add_argument("--root", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true")
    mode.add_argument("--offline", action="store_true")
    parser.add_argument("--dispatch", action="store_true", help="Exercise synthetic nested canonical agent dispatch (live only)")
    args = parser.parse_args()
    try:
        if args.dispatch and not args.live:
            raise ValueError("--dispatch requires --live")
        routing = load_routing(args.root)
        overrides = run_json([str(args.omp), "config", "get", "task.agentModelOverrides", "--json"])
        if overrides.get("value") != routing["agents"]:
            raise ValueError("OMP effective agent overrides differ from canonical routing")
        catalogs = {}
        for selector in sorted(set(routing["groups"].values())):
            provider, _, _ = split_selector(selector)
            if provider not in catalogs:
                catalogs[provider] = run_json([str(args.omp), "models", provider, "--json", "--no-extensions"])
            check_catalog(catalogs[provider], selector)
            if args.live:
                live_probe(args.omp.resolve(), selector, args.root / ".harness")
            print(f"[model-routing] {selector}: {'live inference and runtime effort verified' if args.live else 'catalog resolved; live access not checked'}")
        if args.dispatch:
            dispatch_probe(args.root.resolve(), args.omp.resolve(), routing)
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(f"[model-routing] ERROR: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
