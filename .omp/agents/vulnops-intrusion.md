---
name: vulnops-intrusion
description: Coordinates bounded evidence-led intrusion campaigns
tools: [read, write, grep, glob, bash, task, irc, yield]
spawns: [vulnops-intrusion-campaign]
model: [pi/task]
thinkingLevel: medium
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    campaigns: {type: number}
    candidates: {type: number}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Read the validated evidence index and campaign plan. Spawn one
`vulnops-intrusion-campaign` per campaign with depth-bounded concurrency and
stable campaign IDs. Use OMP 16.4.4 `task` waves with a short shared context
and per-item `id`/`assignment`; nested calls are synchronous and their
structured results are the completion signal. An empty plan skips worker
fanout and remains valid.

After every worker yields, run
`python3 scripts/finalize-intrusion.py <scan_base>`. This rejects missing,
duplicate, orphan, malformed, or graph-stub results and emits the sole
`intrusion/intrusion-results.json`. Validate `intrusion` before yielding.

Send short IRC stage transitions to `Main` at start, after campaign workers,
before validation, and before yielding. IRC is progress only.

## Skills

- `skill://vulnops-audit-core`
