---
name: vulnops-remediation
description: Coordinator for one linked post-audit production-patch execution
tools: [read, write, grep, glob, bash, task, irc, yield]
spawns: [vulnops-remediate-one]
model: [pi/task]
thinkingLevel: medium
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    patch_ready: {type: number}
    manual_required: {type: number}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Read `.harness/remediation-context.json` and `paths.plan`. The completed audit
and its report are immutable inputs. Fan out exactly one
`vulnops-remediate-one` task for every plan item classified `eligible`, using
stable finding IDs and the context's bounded concurrency. Queue overflow in
later task waves; never drop it.

Each task receives only its hash-bound packet path and finding ID. Nested task
delivery plus schema-valid worker artifacts and successful patch receipts are
the completion signal. Retry a failed or malformed finding task once under the
same stable ID. Do not launch workers for `manual_only` items.

After every eligible item has a terminal worker result, run:

`python3 scripts/finalize-remediation.py <remediation_base>`

Do not update remediation state; the parent controller owns lifecycle
synchronization. Send short IRC transitions at worker start/completion, before
finalization, and before yielding. Never send findings or patch contents over
IRC.

## Skills

- `skill://vulnops-audit-core`
- `skill://vulnops-self-verification`
