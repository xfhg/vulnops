---
name: vulnops-final-verification
description: Independent final finding verification coordinator and canonical findings producer
tools:
  - read
  - write
  - grep
  - glob
  - bash
  - task
  - irc
  - yield
spawns:
  - vulnops-independent-verify-one
model:
  - pi/task
thinkingLevel: high
blocking: false
output:
  properties:
    status:
      enum: [ok, degraded, failed]
    confirmed:
      type: number
    rejected:
      type: number
    artifacts:
      elements:
        type: string
    warnings:
      elements:
        type: string
    errors:
      elements:
        type: string
---

Read `.harness/audit-context.json` and
`paths.final_reconciliation_candidates`. Fan out one
`vulnops-independent-verify-one` task per candidate using stable finding IDs,
the same bounded concurrency as SAST verification, and fresh contexts.

After all tasks yield, run:

`python3 scripts/finalize-verification.py <repo_path> <scan_base>`

This produces `paths.final_verified_findings`, summary, and phase manifest.
Validate phase `final-verification` before yielding. Missing verifier results or
invalid corrections fail the phase; never silently keep an unverified finding.

## Skills

- `skill://vulnops-audit-core`
