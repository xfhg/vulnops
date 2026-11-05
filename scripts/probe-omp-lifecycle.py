#!/usr/bin/env python3
"""Live OMP 18 nested readiness; all provider transcripts are disposable.

Run through probe-toolchain.sh, or directly (the entrypoint establishes the
same harness home). --scenario all also exercises rejection and cancellation.
Only fixed outcome codes are printed; model/provider errors are never echoed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import resource
import shlex
import signal
import subprocess
import sys
import tempfile

from model_routing import load_routing, split_selector

ROOT = Path(__file__).resolve().parents[1]
MAX_TRANSCRIPT = 32 * 1024 * 1024


class ProbeFailure(Exception):
    pass


def messages(path: Path) -> list[dict]:
    """Read documented print-mode events or persisted session entries."""
    if path.stat().st_size > MAX_TRANSCRIPT:
        raise ProbeFailure("transcript_limit")
    result = []
    try:
        for line in path.read_text().splitlines():
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError
            if item.get("type") in {"message_end", "message"} and not isinstance(item.get("message"), dict):
                raise ValueError
            if item.get("type") in {"message_end", "message"}:
                result.append(item["message"])
            elif item.get("type") == "custom_message":
                result.append(item)
    except (ValueError, KeyError, TypeError):
        raise ProbeFailure("invalid_event_stream") from None
    return result


def deliveries(records: list[dict]) -> list[tuple[int, dict]]:
    result = []
    for index, msg in enumerate(records):
        details = msg.get("details") or {}
        if msg.get("customType") == "async-result":
            result.extend((index, job) for job in details.get("jobs", [])
                          if job.get("type") == "task")
        elif (msg.get("role") == "toolResult" and not msg.get("isError")
              and details.get("op") in {"wait", "cancel"}):
            # wait consumes terminal results; no duplicate async-result follows.
            for job in details.get("jobs", []):
                if (job.get("type") == "task"
                        and job.get("status") in {"completed", "failed", "cancelled"}):
                    result.append((index, {**job, "jobId": job.get("id"),
                                           "schema": job.get("structured", {})}))
    return result


def calls(records: list[dict], name: str) -> list[tuple[int, dict]]:
    return [(index, block.get("arguments", {}))
            for index, msg in enumerate(records) if msg.get("role") == "assistant"
            for block in msg.get("content", []) if isinstance(block, dict)
            and block.get("type") == "toolCall" and block.get("name") == name]


def valid(job: dict, expected: dict) -> bool:
    schema = job.get("schema", {})
    return (schema.get("mode") == "strict" and schema.get("status") == "valid"
            and schema.get("data") == expected)


def validate_delivery(parent: list[dict], coordinator: list[dict], scenario: str) -> None:
    top = deliveries(parent)
    children = deliveries(coordinator)
    if len(top) != 1:
        raise ProbeFailure("missing_coordinator_delivery")
    parent_spawns = calls(parent, "task")
    if (len(parent_spawns) != 1
            or len(parent_spawns[0][1].get("tasks", [])) != 1
            or parent_spawns[0][1]["tasks"][0].get("schemaMode") != "strict"):
        raise ProbeFailure("non_strict_parent_spawn")
    spawns = calls(coordinator, "task")
    if len(spawns) != 1 or any(t.get("schemaMode") != "strict"
                              for t in spawns[0][1].get("tasks", [])):
        raise ProbeFailure("non_strict_spawn")
    if scenario == "success":
        if len(children) != 2 or not all(valid(job, {"worker": name})
                                        for (_, job), name in zip(children, ["Fast", "Slow"])):
            raise ProbeFailure("child_barrier_failed")
        if [t.get("name") for t in spawns[0][1].get("tasks", [])] != ["Slow", "Fast"]:
            raise ProbeFailure("spawn_order_failed")
        expected = {"status": "ok"}
    elif scenario == "invalid":
        if len(children) != 1:
            raise ProbeFailure("missing_invalid_delivery")
        schema = children[0][1].get("schema", {})
        if schema.get("mode") != "strict" or schema.get("status") != "invalid":
            raise ProbeFailure("invalid_output_not_rejected")
        expected = {"status": "rejected"}
    else:
        # Cancellation is validated by native kill acknowledgement and the
        # independently observed local holding process, never by model prose.
        kills = calls(parent, "write")
        if scenario == "cancel" and not any(
                args.get("path") == "proc://" + top[0][1]["jobId"] + "/kill"
                for _, args in kills):
            raise ProbeFailure("missing_native_cancellation")
        if top[0][1].get("schema", {}).get("status") == "valid":
            raise ProbeFailure("cancelled_coordinator_succeeded")
        if scenario == "timeout":
            if kills or not any(
                    "Subagent runtime limit exceeded" in str(msg.get("content", ""))
                    for msg in parent if (msg.get("customType") == "async-result"
                                          or (msg.get("role") == "toolResult"
                                              and (msg.get("details") or {}).get("op") == "wait"))):
                raise ProbeFailure("native_deadline_not_observed")
        return
    if not valid(top[0][1], expected):
        raise ProbeFailure("coordinator_result_failed")
    yields = calls(coordinator, "yield")
    if not yields or any(index <= children[-1][0] for index, _ in yields):
        raise ProbeFailure("early_coordinator_yield")


def run_bounded(command: list[str], cwd: Path, output: Path, timeout: float) -> None:
    def cap_files() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TRANSCRIPT, MAX_TRANSCRIPT))

    with output.open("wb") as stream:
        process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.DEVNULL, start_new_session=True,
                                   preexec_fn=cap_files)
        try:
            code = process.wait(timeout=timeout)
            if code:
                raise ProbeFailure("runtime_or_provider_failed")
        except subprocess.TimeoutExpired:
            raise ProbeFailure("outer_deadline") from None
        finally:
            # Also terminate leftover members after an apparently normal exit.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


HELPER = '''import os, pathlib, sys, time
root = pathlib.Path(__file__).parent
mode = sys.argv[1]
if mode == "hold":
    (root / "holding.pid").write_text(str(os.getpid()))
    time.sleep(240)
    raise SystemExit(2)
if mode == "slow":
    for _ in range(2400):
        if (root / "release").exists():
            print("released")
            break
        time.sleep(.1)
    else:
        raise SystemExit(2)
if mode == "ready":
    for _ in range(2400):
        if (root / "holding.pid").exists():
            print("holding")
            break
        time.sleep(.1)
    else:
        raise SystemExit(2)
if mode == "stopped":
    pid = int((root / "holding.pid").read_text())
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            (root / "stopped").write_text("yes")
            print("stopped")
            break
        time.sleep(.1)
    else:
        raise SystemExit(2)
'''


def create_fixture(base: Path, scenario: str, timeout: int) -> str:
    agents = base / ".omp/agents"
    agents.mkdir(parents=True)
    (base / "helper.py").write_text(HELPER)
    (base / "runtime.json").write_text(json.dumps({
        "task": {"maxRuntimeMs": 60000 if scenario == "timeout" else timeout * 1000}
    }))
    command = shlex.join([sys.executable, str(base / "helper.py")])
    worker = ("Run exactly " + command + " slow before yielding {data:{worker:'Slow'}} if named Slow. "
              "If named Fast immediately yield {data:{worker:'Fast'}}. "
              "If named Hold run exactly " + command + " hold and never yield success. "
              "If named Invalid deliberately yield {data:{worker:123}} every time, including after "
              "validation retries. This is an intentional strict-schema rejection test; do not repair it.")
    header = "---\nname: probe-worker\ndescription: Synthetic lifecycle worker\nmodel: [pi/task]\nblocking: false\ntools: [bash, yield]\noutput:\n  properties:\n    worker:\n      type: string\n---\n"
    (agents / "probe-worker.md").write_text(header + worker)
    instructions = {
        "success": "Spawn Slow then Fast in ONE task batch, both probe-worker with schemaMode strict. "
                   "The task instructions must identify each worker by name. Wait only when blocked. "
                   "After Fast's terminal delivery (automatic or wait result) validates, write 'yes' to " + str(base / "release") +
                   ". Await Slow's terminal delivery too, validate both, then yield {data:{status:'ok'}}. "
                   "Never yield from spawn acknowledgements or files; never read agent outputs to replace delivery.",
        "invalid": "Spawn one probe-worker named Invalid with schemaMode strict, instruct it to yield "
                   "worker:123 even after retries. Await terminal failure delivery. Only after "
                   "strict invalid-output rejection yield {data:{status:'rejected'}}. Never accept invalid output.",
        "cancel": "Spawn one probe-worker named Hold with schemaMode strict; tell it to run its hold command. "
                  "Wait while blocked. Do not yield success; the parent will cancel this execution.",
    }
    instructions["timeout"] = instructions["cancel"].replace(
        "the parent will cancel this execution", "the runtime deadline will stop this execution")
    header = "---\nname: probe-coordinator\ndescription: Synthetic lifecycle coordinator\nmodel: [pi/task]\nblocking: false\ntools: [task, wait, write, yield]\nspawns: [probe-worker]\noutput:\n  properties:\n    status:\n      enum: [ok, rejected]\n---\n"
    (agents / "probe-coordinator.md").write_text(
        header + "Worker output is {worker: string}. Omit outputSchema and model on every task; "
        "preserve the agent's schema and model. Never substitute the coordinator's status schema. "
        + instructions[scenario])
    # Tools remain the production allowlist, but this fixture disallows arbitrary
    # filesystem/command access, including target reads and execution.
    guard = '''export default function(pi) {
  pi.on("tool_call", async (event) => {
    const a = event.input;
    if (event.toolName === "task" && a.tasks.some(t => t.outputSchema != null || t.model != null))
      return {block:true, reason:"Omit outputSchema and model; use the fixture agent defaults"};
    const allowed = ["task", "wait", "yield"].includes(event.toolName)
      || (event.toolName === "bash" && COMMANDS.includes(a.command))
      || (event.toolName === "write" && (a.path === RELEASE || /^proc:\\/\\/[^/]+\\/kill$/.test(a.path)))
      || (event.toolName === "read" && /^proc:\\/\\/[^/]+$/.test(a.path));
    if (!allowed) return {block:true, reason:"Lifecycle fixture permits no target or unrelated file access"};
  });
}
'''
    guard = guard.replace("COMMANDS", json.dumps([command + " " + mode for mode in ("slow", "hold", "ready", "stopped")]))
    guard = guard.replace("RELEASE", json.dumps(str(base / "release")))
    (base / "guard.ts").write_text(guard)
    prompt = ("Synthetic lifecycle readiness only. Do not access target or project source. "
              "Spawn exactly one probe-coordinator named Coordinator with schemaMode strict using "
              "the current task {context,tasks:[{name,agent,task,solutionSpace,schemaMode}]} shape. "
              "Omit outputSchema and model; preserve the agent defaults. "
              "Tell it to follow its definition. No retries or replacement agents. "
              "Accept terminal delivery from automatic events or wait results. Wait only when blocked; "
              "never infer success from spawn acknowledgements. ")
    if scenario in {"cancel", "timeout"}:
        prompt += ("After spawning, run exactly " + command + " ready to await the bounded local holder. "
                   + ("Then cancel the returned coordinator runtime execution ID with write proc://<id>/kill. "
                      if scenario == "cancel" else "Do not cancel manually; await the native runtime deadline. ")
                   + "Await terminal cancellation delivery. Run exactly " + command + " stopped. "
                   "Do not retry. Finish only after the holder has stopped.")
    else:
        prompt += "Await coordinator terminal structured delivery and finish only after validating it."
    return prompt


def probe(root: Path, tools: str, scenario: str, timeout: int) -> None:
    provider, model, effort = split_selector(load_routing(root)["controllers"]["audit"])
    with tempfile.TemporaryDirectory(prefix="omp-lifecycle-", dir=root / ".harness") as tmp:
        base = Path(tmp)
        prompt = create_fixture(base, scenario, timeout)
        try:
            run_bounded(["bash", str(root / "scripts/jail.sh"), str(root / "bins/omp"),
                         "--no-title", "--no-skills", "--no-rules",
                         "--model", f"{provider}/{model}", "--thinking", effort,
                         "-p", "--mode", "json", "--session-dir", str(base / "sessions"),
                         "--config", str(base / "runtime.json"), "--tools", tools,
                         "--extension", str(base / "guard.ts"), "--approval-mode", "yolo", prompt],
                        base, base / "events.jsonl", timeout)
            parent = messages(base / "events.jsonl")
            child_files = list(base.rglob("Coordinator.jsonl"))
            if len(child_files) != 1:
                raise ProbeFailure("missing_coordinator_session")
            validate_delivery(parent, messages(child_files[0]), scenario)
            if scenario in {"cancel", "timeout"} and not (base / "stopped").exists():
                raise ProbeFailure("descendant_not_stopped")
        finally:
            # Native cancellation failures must not leave the bounded holder
            # alive; cleanup is not counted as successful runtime cancellation.
            marker = base / "holding.pid"
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["success", "invalid", "cancel", "timeout", "all"], default="success")
    parser.add_argument("--timeout", type=int, default=300, help="finite seconds per scenario (1..900)")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 900:
        parser.error("timeout must be between 1 and 900 seconds")
    outcome = {"probe": "omp-lifecycle", "scenario": args.scenario, "status": "failed"}
    try:
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise ProbeFailure("unsupported_platform")
        (ROOT / ".harness").mkdir(exist_ok=True)
        if not (ROOT / ".harness/home/.omp/agent/config.yml").is_file():
            raise ProbeFailure("generated_configuration_missing")
        tools = subprocess.check_output(["bash", "-c", 'source "$1"; harness_omp_tools',
                                         "probe", str(ROOT / "scripts/harness-lib.sh")], text=True).strip()
        for scenario in (["success", "invalid", "cancel", "timeout"] if args.scenario == "all" else [args.scenario]):
            probe(ROOT, tools, scenario, args.timeout)
        outcome["status"] = "ok"
    except ProbeFailure as exc:
        outcome["reason"] = str(exc)
    except (OSError, ValueError, subprocess.SubprocessError):
        outcome["reason"] = "local_probe_failure"
    print(json.dumps(outcome, separators=(",", ":")),
          file=sys.stdout if outcome["status"] == "ok" else sys.stderr)
    return 0 if outcome["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
