---
name: vulnops-final-verification
description: Fresh-context independent verification coordinator
tools: [read, write, grep, glob, bash, task, irc, yield]
spawns: [vulnops-independent-verify-one]
model: [pi/task]
thinkingLevel: medium
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    confirmed: {type: number}
    rejected: {type: number}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Read `.harness/audit-context.json` and `paths.synthesis_findings`. Fan out one
fresh-context `vulnops-independent-verify-one` task per synthesized finding,
using stable finding IDs and the configured verification fanout. Use OMP
bundled OMP `task` waves with a short shared context and per-item `id`/`assignment`;
nested task results and validated worker files are the completion signal.

After every task yields, run:

`python3 scripts/finalize-verification.py <repo_path> <scan_base>`

Missing, duplicate, orphan, wrong-model, or malformed results fail the phase.
For chains, every primitive and capability transition must be independently
verified in order. Validate `final-verification` before yielding.

Send short IRC stage transitions to `Main` at start, after verifier workers,
before validation, and before yielding. IRC is progress only.

## Skills

- `skill://vulnops-audit-core`
