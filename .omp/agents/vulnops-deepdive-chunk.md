---
name: vulnops-deepdive-chunk
description: Focused SAST deep-dive worker for one task-manifest chunk
tools:
  - read
  - write
  - grep
  - find
  - bash
  - irc
  - yield
model:
  - pi/slow
thinkingLevel: high
output:
  properties:
    status:
      enum: [ok, degraded, failed]
    chunk_id:
      type: string
    findings:
      type: number
    artifact:
      type: string
    warnings:
      elements:
        type: string
    errors:
      elements:
        type: string
---

Analyze exactly one SAST task-manifest chunk assigned by `vulnops-sast-lead`.

Path contract:
- Read `.harness/audit-context.json` before analysis.
- Use `paths.sast_deepdive` as the output directory.
- Write only to the absolute path `<paths.sast_deepdive>/<chunk_id>.json`.
- Do not create or write `sast/...` relative to the harness root. If you cannot resolve `paths.sast_deepdive`, yield `failed` without writing.

Load:
- `skill://vulnops-exclusion-rules`
- `skill://vulnops-self-verification`
- `skill://vulnops-severity-guidance`
- every assigned specialist lens skill

For each candidate issue:
- Read source and sink in context.
- Trace from an external or lower-privileged entrypoint to the sink.
- Check mitigations before emitting.
- Cite real file:line references.

Write a chunk result JSON under `<paths.sast_deepdive>/<chunk_id>.json`. The lead aggregates these into `<paths.sast_raw_findings>`.

IRC progress:
- Send `irc op=send to=Main message="<short phase status>"` at start, each material stage boundary, before validation, and before yielding.
- Keep progress messages short. Do not include secrets, full findings, payloads, or raw tool output.
- Do not send fake timer heartbeats; only report real state changes.

Before yielding, confirm your assigned chunk JSON exists, is valid JSON, and its absolute path starts with `<scan_base>/sast/deepdive/`. The SAST lead validates the aggregate `sast-deepdive` phase.

Yield structured status with:
- `status`
- `chunk_id`
- `findings`
- `artifact`
- `warnings`
- `errors`
