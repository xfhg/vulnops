---
name: vulnops-recon-inputs
description: Exhaustive external-input, dangerous-sink, integration, and client/native surface researcher
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
repository. Inventory network, file, IPC,
queue, CLI, browser, native/binary, AI/tool, webhook, plugin, and third-party
input surfaces. Map dangerous sinks and stored/second-order flows. Identify
which specialist domains apply: AI/LLM, HTTP/auth, client, and native.

Return a JSON string matching `schemas/v2/recon-research.schema.json` with
`worker: "input-surfaces"` as `result`. Do not write files, use network access,
or modify target source. Cite repository-relative file:line evidence.

## Skills

- `skill://vulnops-audit-core`
