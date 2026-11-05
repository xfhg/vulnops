#!/usr/bin/env python3
"""Arm the launcher's OMP overlay from the active context before a phase spawn."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile


def deadline_ms(context: dict, phase: str, *, cohort: str = "original") -> int:
    if cohort not in {"original", "supplementary"}:
        raise ValueError("unknown phase cohort")
    if cohort != "original":
        if phase not in {"synthesis", "final-verification"}:
            raise ValueError("supplementary deadlines require synthesis or final verification")
        budget = context["gap_exploration_budget"]
        if budget.get("enabled") is not True or not context.get("paths", {}).get("gap_exploration"):
            raise ValueError("execution does not own enabled supplementary work")
        key = "synthesis_timeout_seconds" if phase == "synthesis" else "verification_timeout_seconds"
        seconds = budget[key]
        if type(seconds) is not int or seconds <= 0:
            raise ValueError("supplementary deadline must be a positive integer")
        from gap_dossier import remaining_ms
        remaining = remaining_ms(context, phase, cohort)
        milliseconds = min(seconds * 1000, remaining) if remaining is not None else seconds * 1000
        if milliseconds <= 0:
            raise ValueError("supplementary cohort has no remaining native allowance")
        return milliseconds
    if phase == "gap-exploration":
        budget = context["gap_exploration_budget"]
        if budget.get("enabled") is not True or not context.get("paths", {}).get("gap_exploration"):
            raise ValueError("execution does not own enabled gap exploration")
        seconds = budget["timeout_seconds"]
    elif context.get("execution_kind") == "advantage":
        if phase not in {"planning", "investigation", "synthesis", "final-verification", "handoff"}:
            raise ValueError("Advantage native deadline requires a model-owned phase")
        seconds = context["budget"]["phase_timeout_seconds"]
    elif phase == "remediation":
        orchestration = context["orchestration"]
        seconds = orchestration["timeout_seconds"]
    else:
        orchestration = context["orchestration"]
        seconds = orchestration["phase_timeout_seconds"][phase]
        if isinstance(seconds, dict):
            seconds = seconds[context["depth"]]
    if type(seconds) is not int or seconds <= 0:
        raise ValueError("phase deadline must be a positive integer")
    return seconds * 1000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("context", type=Path)
    parser.add_argument("phase")
    parser.add_argument("--cohort", choices=("original", "supplementary"), default="original")
    args = parser.parse_args()
    temporary = None
    try:
        overlay = Path(os.environ["VULNOPS_OMP_RUNTIME_CONFIG"])
        runtime_dir = Path(__file__).resolve().parent.parent / ".harness" / "tmp"
        if (overlay.is_symlink() or not overlay.is_file()
                or overlay.resolve().parent != runtime_dir.resolve()
                or not overlay.name.startswith("omp-runtime-")):
            raise ValueError("not a launcher-owned runtime overlay")
        context = json.loads(args.context.read_text(encoding="utf-8"))
        if context.get("execution_kind") == "advantage":
            from advantage_contract import load_context, live_call
            context = load_context(args.context)
            live_call(context, args.phase)
        milliseconds = deadline_ms(context, args.phase, cohort=args.cohort)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=runtime_dir,
                                         prefix=".omp-runtime-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump({"task": {"maxRuntimeMs": milliseconds}}, stream)
            stream.write("\n")
        temporary.replace(overlay)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "[omp-deadline] cannot arm phase deadline from context and launcher overlay\n")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f"[omp-deadline] armed native task deadline: {milliseconds} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
