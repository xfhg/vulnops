---
name: vulnops-recon-overview
description: Repository overview, stack, architecture, and comparable-baseline researcher
tools:
  - read
  - grep
  - glob
  - bash
  - irc
  - yield
model:
  - pi/task
thinkingLevel: medium
blocking: false
output:
  properties:
    status:
      enum: [ok, degraded, failed]
    result:
      type: string
    warnings:
      elements:
        type: string
    errors:
      elements:
        type: string
---

Read `.harness/audit-context.json`, `skill://vulnops-audit-core`, and the target
repository. Map what the application is,
its users, stack, deployment model, major components, entry points, and a
comparable baseline. A comparable must include its evidence basis and
confidence; use `null` when no meaningful offline baseline exists.

Return a JSON string matching `schemas/v2/recon-research.schema.json` with
`worker: "overview"` as `result`. Do not write files, use network access, or
modify target source. Cite real repository-relative paths and lines.

## Skills

- `skill://vulnops-audit-core`
