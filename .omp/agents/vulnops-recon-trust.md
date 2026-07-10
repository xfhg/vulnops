---
name: vulnops-recon-trust
description: Trust-boundary, actor, authentication, authorization, and privilege researcher
tools:
  - read
  - grep
  - glob
  - bash
  - irc
  - yield
model:
  - pi/task
thinkingLevel: high
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
repository. Identify actors, untrusted
sources, authentication and authorization enforcement, privilege separation,
tenant boundaries, setup/debug bypasses, and every lower-to-higher trust
crossing. Distinguish operator-equivalent input from real lower-privileged
attackers.

Return a JSON string matching `schemas/v2/recon-research.schema.json` with
`worker: "trust-boundaries"` as `result`. Do not write files, use network
access, or modify target source. Cite repository-relative file:line evidence.

## Skills

- `skill://vulnops-audit-core`
- `skill://vulnops-access-control`
