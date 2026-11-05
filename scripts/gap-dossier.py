#!/usr/bin/env python3
"""Control separately bounded downstream work inside its canonical phase."""
import argparse
import json
from pathlib import Path
from gap_dossier import begin_cohort, finish_cohort, fail_cohort, review_cohorts, accepted_candidates, review_worker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--phase", choices=("synthesis", "final-verification"), required=True)
    parser.add_argument("--cohort", choices=("original", "supplementary"), default="original")
    parser.add_argument("--action", choices=("begin", "finish", "fail", "partition", "review-begin", "review-fail", "review-finish"), required=True)
    parser.add_argument("--reason")
    parser.add_argument("--finding")
    args = parser.parse_args()
    context = json.loads(args.context.read_text(encoding="utf-8"))
    if context.get("execution_kind") == "advantage":
        from advantage_contract import load_context
        context = load_context(args.context)
        if args.action != "partition":
            parser.error("Advantage cohorts are actual native tasks, not mutable registrations")
        from advantage_pipeline import verification_cohorts
        cohorts = verification_cohorts(context)
        print(json.dumps({name: [identity for identity, cohort in cohorts.items() if cohort == name]
                          for name in ("original", "supplementary")}, sort_keys=True))
        return 0
    if args.action.startswith("review-"):
        if args.phase != "final-verification" or not args.finding:
            parser.error("reviewer execution requires final-verification and --finding")
        result = review_worker(context, args.finding, args.action.removeprefix("review-"), args.reason or "")
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.action == "partition":
        from gap_dossier import _base
        base = _base(context)
        findings = json.loads((base / "synthesis/findings.json").read_text(encoding="utf-8"))["findings"]
        result = review_cohorts(findings, accepted_candidates(base, context=context))
    elif args.action == "fail":
        result = fail_cohort(context, args.phase, args.cohort, args.reason)
    else:
        result = (begin_cohort if args.action == "begin" else finish_cohort)(context, args.phase, args.cohort)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
