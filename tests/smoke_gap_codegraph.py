"""Opt-in real wrapper smoke for a parent-authored, harness-owned tiny gap fixture.

Usage: python3 tests/smoke_gap_codegraph.py --fixture-root work/<disposable-fixture>
       --context work/<disposable-fixture>/context.json --owner GapExploration --question Q1
The fixture must have accepted gap plan/dispatch and active lifecycle ownership.
No target code is executed; only the installed Codegraph indexer/query tool runs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from codegraph_contract import validate_query_receipt
from gap_exploration_contract import graph_question, source_context
from gap_graph import source_digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", required=True, type=Path)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--question", required=True)
    args = parser.parse_args()
    fixture = args.fixture_root.resolve(strict=True)
    if not fixture.is_relative_to(ROOT / "work") or fixture == ROOT / "work":
        parser.error("smoke fixture must be a disposable child of harness work/")
    context_path = args.context.resolve(strict=True)
    if not context_path.is_relative_to(fixture):
        parser.error("smoke context must belong to the disposable fixture")
    context = json.loads(context_path.read_text())
    if not context["run_id"].startswith("gap-smoke-"):
        parser.error("smoke run identity must start with gap-smoke-")
    base = Path(context["scan_base"]).resolve(strict=True)
    question = graph_question(context, args.owner, args.question)
    selected = source_context(context, question["source_view"])
    source = Path(selected.get("source_root") or selected["repo_path"]).resolve(strict=True)
    if not base.is_relative_to(fixture) or not source.is_relative_to(fixture):
        parser.error("smoke source and execution must both be fixture-owned")
    files = [path for path in source.rglob("*") if path.is_file()]
    if not files or len(files) > 8 or sum(path.stat().st_size for path in files) > 65536:
        parser.error("smoke source must be a tiny fixture (1-8 files, at most 64 KiB)")
    runtime = ROOT / ".harness/codegraph" / context["run_id"]
    if runtime.exists() or runtime.is_symlink():
        parser.error("smoke runtime already exists; refusing to reuse or remove existing state")
    before = source_digest(source, time.monotonic() + 30)
    try:
        result = subprocess.run(["bash", str(ROOT / "scripts/run-codegraph.sh"), "--context", str(context_path),
                                 "--phase", "gap-exploration", "--owner", args.owner, "--question", args.question],
                                check=False, timeout=context["gap_exploration_budget"]["preparation_timeout_seconds"] + 150)
        if result.returncode:
            return result.returncode
        reference = f"gap-exploration/codegraph-runs/{args.owner}/{args.question}/receipt.json"
        document = validate_query_receipt(base, source, context, "gap-exploration", args.owner, question, reference)
        if not document["meaningful"]:
            raise ValueError("tiny graph smoke must produce meaningful source navigation")
        if source_digest(source, time.monotonic() + 30) != before or (source / ".codegraph").exists():
            raise ValueError("tiny graph smoke modified its source fixture")
        print(json.dumps({"status": "ok", "receipt": reference, "meaningful": True,
                          "source_view": question["source_view"], "source_unchanged": True}))
    finally:
        if runtime.exists() and not runtime.is_symlink():
            shutil.rmtree(runtime)
    # Delivered evidence must remain readable without its runtime index.
    validate_query_receipt(base, source, context, "gap-exploration", args.owner, question, reference)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
