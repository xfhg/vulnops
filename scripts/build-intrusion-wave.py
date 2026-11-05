#!/usr/bin/env python3
"""Initialize or atomically advance the phase-owned Intrusion evidence wave."""
import argparse
import json
from pathlib import Path
from intrusion_contract import build_wave, load, reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_base", type=Path)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--results", nargs="*", default=[])
    parser.add_argument("--continuations", type=Path)
    args = parser.parse_args()
    context = load(args.context)
    if Path(context["scan_base"]).resolve() != args.scan_base.resolve():
        parser.error("scan differs from active run authority")
    proposals = load(args.continuations) if args.continuations else []
    snapshot = build_wave(args.scan_base, Path(context.get("source_root") or context["repo_path"]), context, args.results, proposals)
    print(json.dumps({"input_snapshot": reference(args.scan_base, snapshot), "wave": snapshot["wave"],
                      "assignments": snapshot["assignments"], "attack_objectives": snapshot["attack_objectives"],
                      "investigation_questions": snapshot["investigation_questions"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
