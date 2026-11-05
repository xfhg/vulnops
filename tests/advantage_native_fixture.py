"""Trusted synthetic native-call inputs for deterministic tests, never model execution.

These helpers stand in for the native wrapper's private environment boundary. They
must not be used as evidence that an OMP child ran or discovered a vulnerability.
Every observation is supplied explicitly and remains process-local.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
from unittest.mock import patch

from advantage_contract import PHASES, sha256_file


@contextmanager
def native_controller(session_id="fixture-session", baseline=None):
    """Authorize synthetic initialization, before an invocation has a run ID."""
    call = {"launcher_session_id": session_id,
            "caller": {"id": "trusted-fixture-controller", "name": "Main", "kind": "main"}}
    if baseline is not None:
        call["baseline"] = str(baseline)
    with patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": json.dumps(call)}):
        yield call


@contextmanager
def native_call(context, phase, *, workers=(), accepted_phases=None, caller=None):
    """Provide one trusted-fixture operation, restoring the prior env on exit.

The default accepted predecessors describe the synthetic fixture's prepared
phase sequence, not runtime discovery or inferred authority from file presence.
Pass an explicit list to exercise missing/unaccepted predecessor observations.
"""
    call = {"run_id": context["run_id"], "launcher_session_id": context["launcher_session_id"],
            "phase": phase, "context_sha256": sha256_file(Path(context["input_path"])),
            "caller": caller if caller is not None else {
                "id": f"trusted-fixture-{phase}", "name": f"vulnops-advantage-{phase}",
                "kind": "sub", "parentId": "trusted-fixture-controller"},
            "accepted_phases": list(PHASES[:PHASES.index(phase)] if accepted_phases is None else accepted_phases),
            "workers": list(workers)}
    with patch.dict(os.environ, {"VULNOPS_ADVANTAGE_CALL": json.dumps(call)}):
        yield call


def native_worker(context, phase, identity, *, status="completed", attempt=1,
                  artifacts=(), input_sha256=None, actor=None, error=None,
                  yield_valid=True):
    """Describe an explicitly synthetic terminal/running native child observation.

There is deliberately no planned/unlaunched state: absent native execution is
represented by no observation. Artifact hashes bind the exact authored bytes.
"""
    if status not in {"running", "completed", "failed", "cancelled"}:
        raise ValueError("synthetic observation must represent an actual native state")
    actor = actor or {"investigation": "vulnops-advantage-investigator",
                      "final-verification": "vulnops-advantage-verify-one",
                      "gap-exploration": "vulnops-advantage-gap-investigator"}.get(
                          phase, f"vulnops-advantage-{phase}")
    base = Path(context["scan_base"])
    artifacts = [str(path) for path in artifacts]
    row = {"id": identity, "runtime_id": f"trusted-fixture-{phase}-{identity}-{attempt}",
           "phase": phase, "actor": actor, "selector": context["model_routing"]["agents"][actor],
           "attempt": attempt, "status": status, "yield_valid": yield_valid,
           "artifacts": artifacts,
           "artifact_sha256": {name: sha256_file(base / name) for name in artifacts}}
    packet = base / phase / "packets" / f"{identity}.json"
    if input_sha256 is not None:
        row["input_sha256"] = input_sha256
    elif packet.is_file():
        row["input_sha256"] = sha256_file(packet)
    if error is not None:
        row["error"] = error
    return row


class NativeFixture:
    """Scope explicitly authored native observations to one synthetic invocation.

    This is a test-only environment adapter, not an executor or saved scheduler.
    Callers must explicitly supply each observation and update its terminal state.
    """

    def __init__(self, context, phase="planning"):
        self.context = context
        self.phase = phase
        self.workers = []
        self.context_sha256 = sha256_file(Path(context["input_path"]))
        self._scope = None

    def __enter__(self):
        self._scope = patch.dict(os.environ, {})
        self._scope.__enter__()
        self.refresh()
        return self

    def __exit__(self, *exc):
        return self._scope.__exit__(*exc)

    def refresh(self):
        with native_call(self.context, self.phase, workers=self.workers) as call:
            call["context_sha256"] = self.context_sha256
            payload = json.dumps(call)
        os.environ["VULNOPS_ADVANTAGE_CALL"] = payload

    def select_phase(self, phase):
        self.phase = phase
        self.refresh()

    def observe(self, identity, **fields):
        row = native_worker(self.context, self.phase, identity, **fields)
        self.workers[:] = [item for item in self.workers
                           if (item["phase"], item["id"], item["attempt"]) !=
                           (row["phase"], row["id"], row["attempt"])]
        self.workers.append(row)
        self.refresh()
        return row
