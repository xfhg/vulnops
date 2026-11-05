#!/usr/bin/env python3
"""Run one approved, phase-owned isolated experiment without confirmation or patching."""
import argparse
from pathlib import Path
from investigation_experiments import run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = run(args.context, args.request)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
