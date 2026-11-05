#!/usr/bin/env python3
"""Private, bounded preparation behind the setup-codegraph.sh containment entrypoint."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

OPTIONAL_FAILURE = 1
FATAL_FAILURE = 2
DEFAULT_TIMEOUT_SECONDS = 7200
SHUTDOWN_GRACE_SECONDS = 5.0


def run_setup_command(command: list[str], *, env: dict[str, str] | None = None) -> int:
    """Await the contained supervisor; cancellation must give it time to stop writers."""
    child = None
    cancelled = 0

    def cancel(signum, _frame):
        nonlocal cancelled
        cancelled = cancelled or signum
        if child is not None and child.poll() is None:
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                pass

    previous = {sig: signal.signal(sig, cancel) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=sys.stderr)
        if cancelled:
            try:
                child.send_signal(cancelled)
            except ProcessLookupError:
                pass
        result = child.wait()
        if result == FATAL_FAILURE:
            return FATAL_FAILURE
        return 128 + cancelled if cancelled else (128 - result if result < 0 else result)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def timeout_value(raw: str) -> float:
    try:
        value = float(raw)
        if not math.isfinite(value) or not 0 < value <= 86400:
            raise ValueError
        return value
    except ValueError:
        raise ValueError("CODEGRAPH_INIT_TIMEOUT_SECONDS must be finite, greater than 0 and at most 86400") from None


class UnsafePreparation(Exception):
    pass


def guarded_paths(root: Path, requested_source: Path, requested_runtime: Path):
    source = requested_source.resolve()
    runtime = requested_runtime.resolve()
    # Resolve platform aliases above the harness (for example Darwin /var), but
    # never accept a redirected runtime or ancestor within the harness itself.
    cursor = requested_runtime.absolute()
    if cursor.is_symlink():
        raise UnsafePreparation("Codegraph runtime may not redirect")
    while cursor.resolve() != root and cursor.parent != cursor:
        if cursor.is_symlink():
            raise UnsafePreparation("Codegraph runtime ancestor may not redirect")
        cursor = cursor.parent
    project = runtime / "project"
    receipt = runtime / "index-receipt.json"
    if (".." in requested_source.parts or ".." in requested_runtime.parts
            or not source.is_relative_to(root) or not runtime.is_relative_to(root)
            or runtime.is_relative_to(source) or source.is_relative_to(project)
            or project.is_symlink() or project.resolve() != project
            or receipt.is_symlink() or receipt.resolve() != receipt):
        raise UnsafePreparation("Codegraph source, project or receipt path is unsafe or redirects")
    if not source.is_dir():
        raise UnsafePreparation("CODEGRAPH_TARGET_DIR must be a readable directory")
    return source, runtime, project, receipt


def copy_source(source: Path, project: Path) -> None:
    def walk_error(error):
        raise error

    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    excluded = {".git", ".codegraph", ".harness"}
    for root, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
        symlink_dirs = sorted(d for d in dirs if (Path(root) / d).is_symlink())
        dirs[:] = sorted(d for d in dirs if d not in excluded and d not in symlink_dirs)
        rel_root = Path(root).relative_to(source)
        for name in [*symlink_dirs, *sorted(files)]:
            if name in excluded:
                continue
            src = Path(root) / name
            dst = project / rel_root / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_symlink():
                try:
                    resolved = src.resolve(strict=True)
                    relative_target = resolved.relative_to(source)
                except (OSError, ValueError, RuntimeError):
                    raise UnsafePreparation("refusing repository symlink that is broken or escapes the target") from None
                os.symlink(os.path.relpath(project / relative_target, dst.parent), dst,
                           target_is_directory=resolved.is_dir())
            else:
                shutil.copy2(src, dst)


def prepare_worker(binary: Path, source: Path, project: Path, deadline: float) -> dict:
    def check_deadline():
        if time.monotonic() >= deadline:
            raise TimeoutError

    try:
        check_deadline()
        copy_source(source, project)
        check_deadline()
        result = subprocess.run([str(binary), "init", str(project)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        check_deadline()
        if result.returncode:
            return {"code": OPTIONAL_FAILURE, "message": f"codegraph init failed with exit {result.returncode}"}
        # Only the bounded first line is retained; the supervisor also bounds a stuck version call.
        version_process = subprocess.Popen([str(binary), "--version"], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        with version_process.stdout as stream:
            first = stream.readline(256)
            while stream.read(65536):
                pass
        version_process.wait()
        check_deadline()
        version = "".join(c for c in first.decode("utf-8", "replace").strip() if c.isprintable())[:128]
        return {"code": 0, "version": version or "unknown", "message": ""}
    except UnsafePreparation as error:
        return {"code": FATAL_FAILURE, "message": str(error)}
    except TimeoutError:
        return {"code": OPTIONAL_FAILURE, "message": "codegraph preparation exceeded the configured timeout"}
    except (OSError, shutil.Error):
        return {"code": OPTIONAL_FAILURE, "message": "codegraph preparation failed during filesystem or tool access"}


def group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_workers(pid: int, reaped: bool) -> tuple[bool, bool]:
    """Stop the group even when its original leader has already exited."""
    deadline = time.monotonic() + SHUTDOWN_GRACE_SECONDS
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    force_at = time.monotonic() + 0.25
    forced = False
    while time.monotonic() < deadline:
        if not reaped:
            reaped = os.waitpid(pid, os.WNOHANG)[0] == pid
        if reaped and not group_exists(pid):
            return True, reaped
        if not forced and time.monotonic() >= force_at:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            forced = True
        if forced and reaped:
            # Orphan zombies cannot write. Some container PID 1 implementations do not reap them.
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                state = subprocess.run(["ps", "-axo", "pgid=,stat="], capture_output=True,
                                       text=True, timeout=remaining, check=True)
                members = [fields[1] for line in state.stdout.splitlines()
                           if len(fields := line.split()) == 2 and fields[0] == str(pid)]
                if all(status.startswith("Z") for status in members):
                    return True, reaped
            except (OSError, subprocess.SubprocessError):
                return False, reaped
        time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    return False, reaped


def prepare(root: Path) -> int:
    try:
        timeout = timeout_value(os.environ.get("CODEGRAPH_INIT_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)))
        if not os.environ.get("CODEGRAPH_TARGET_DIR") or not os.environ.get("CODEGRAPH_RUNTIME_DIR"):
            raise UnsafePreparation("CODEGRAPH_TARGET_DIR and CODEGRAPH_RUNTIME_DIR are required")
        requested_source = Path(os.environ["CODEGRAPH_TARGET_DIR"])
        requested_runtime = Path(os.environ["CODEGRAPH_RUNTIME_DIR"])
        paths = guarded_paths(root, requested_source, requested_runtime)
    except (ValueError, OSError, RuntimeError, UnsafePreparation) as error:
        print(f"[setup-codegraph] {error}", file=sys.stderr)
        return FATAL_FAILURE
    source, runtime, project, receipt = paths
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    deadline = time.monotonic() + timeout
    cancelled = 0
    pid = None
    reaped = False
    shutdown_attempted = False
    safe_to_clean = True
    result = {"code": OPTIONAL_FAILURE, "message": "codegraph is unavailable"}

    def cancel(signum, _frame):
        nonlocal cancelled
        cancelled = cancelled or signum

    def recheck():
        if guarded_paths(root, requested_source, requested_runtime) != paths:
            raise UnsafePreparation("Codegraph cleanup paths changed or redirected")

    previous = {sig: signal.signal(sig, cancel) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        receipt.unlink(missing_ok=True)
        binary = root / "bins/codegraph"
        if os.access(binary, os.X_OK) and not cancelled:
            read_fd, write_fd = os.pipe()
            try:
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(read_fd)
                        os.setpgid(0, 0)
                        for sig in previous:
                            signal.signal(sig, signal.SIG_DFL)
                        result = prepare_worker(binary, source, project, deadline)
                        os.write(write_fd, json.dumps(result).encode())
                    finally:
                        os._exit(0)
                os.close(write_fd)
                write_fd = None
                try:
                    os.setpgid(pid, pid)
                except (ProcessLookupError, PermissionError):
                    pass
                payload = b""
                while not cancelled:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        result = {"code": OPTIONAL_FAILURE, "message": "codegraph preparation exceeded the configured timeout"}
                        break
                    readable, _, _ = select.select([read_fd], [], [], min(0.02, remaining))
                    if readable:
                        chunk = os.read(read_fd, 4096)
                        payload += chunk
                    reaped = os.waitpid(pid, os.WNOHANG)[0] == pid
                    if reaped:
                        # The worker can publish after select times out but before
                        # waitpid observes its exit. Its pipe is now closed: drain
                        # the bounded result rather than mistaking this race for failure.
                        while chunk := os.read(read_fd, 4096):
                            payload += chunk
                        if payload:
                            result = json.loads(payload)
                        else:
                            result = {"code": OPTIONAL_FAILURE, "message": "codegraph preparation worker exited unexpectedly"}
                        break
                shutdown_attempted = True
                safe_to_clean, reaped = stop_workers(pid, reaped)
            finally:
                os.close(read_fd)
                if write_fd is not None:
                    os.close(write_fd)
        if not safe_to_clean:
            raise UnsafePreparation("Codegraph worker shutdown could not be established; cleanup refused")
        recheck()
        if cancelled:
            result = {"code": 128 + cancelled, "message": "codegraph preparation cancelled"}
        if result["code"]:
            if project.exists():
                shutil.rmtree(project)
        recheck()
        receipt_doc = {
            "schema_version": "2.0", "tool": "codegraph", "operation": "index",
            "status": "failed" if result["code"] else "ok", "version": result.get("version", "unknown"),
            "started_at": started, "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "parse_status": "not_applicable", "result_count": 0, "normalized_sha256": None,
            "warnings": [result["message"]] if result["code"] else [],
        }
        try:
            runtime.mkdir(parents=True, exist_ok=True)
            recheck()
            descriptor = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(json.dumps(receipt_doc, indent=2, sort_keys=True) + "\n")
        except OSError:
            if not result["code"]:
                if project.exists():
                    recheck()
                    shutil.rmtree(project)
                result = {"code": OPTIONAL_FAILURE, "message": "codegraph receipt could not be written"}
    except UnsafePreparation as error:
        result = {"code": FATAL_FAILURE, "message": str(error)}
    except (OSError, shutil.Error):
        result = {"code": FATAL_FAILURE, "message": "Codegraph cleanup or receipt invalidation failed"}
    finally:
        if pid is not None and not shutdown_attempted:
            stopped, reaped = stop_workers(pid, reaped)
            if not stopped:
                result = {"code": FATAL_FAILURE, "message": "Codegraph worker shutdown failed"}
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if cancelled and result["code"] != FATAL_FAILURE:
        return 128 + cancelled
    if result["message"]:
        print(f"[setup-codegraph] {result['message']}", file=sys.stderr)
    return result["code"]


if __name__ == "__main__":
    if sys.argv[1:] == ["--validate-timeout"]:
        try:
            timeout_value(os.environ.get("CODEGRAPH_INIT_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)))
        except ValueError as error:
            print(f"[setup-codegraph] {error}", file=sys.stderr)
            raise SystemExit(FATAL_FAILURE)
    else:
        raise SystemExit(prepare(Path(__file__).resolve().parents[1]))
