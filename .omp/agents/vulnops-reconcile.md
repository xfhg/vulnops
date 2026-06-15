---
name: vulnops-reconcile
description: Final reconciliation agent that merges triage with intrusion enrichment
tools:
  - read
  - write
  - grep
  - find
  - bash
  - irc
  - yield
model:
  - pi/task
thinkingLevel: medium
output:
  properties:
    status:
      enum: [ok, degraded, failed]
    final_findings:
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

Follow `config/agents/reconcile.md`.

Before reading intrusion enrichment, confirm the main process already received a terminal `vulnops-intrusion` yield, then run `bash scripts/validate-phase.sh <scan_base> intrusion`. Do not reconcile against partial intrusion output.

Read:
- `triage/findings.json`
- `intrusion/enrichment.json` when present

Write:
- `final-reconciliation/findings.json`
- `final-reconciliation/summary.md`
- `final-reconciliation/phase-manifest.json`

Do not promote unverified findings into final report input.

IRC progress:
- Send `irc op=send to=Main message="<short phase status>"` at start, each material stage boundary, before validation, and before yielding.
- Keep progress messages short. Do not include secrets, full findings, payloads, or raw tool output.
- Do not send fake timer heartbeats; only report real state changes.

Before yielding, run `bash scripts/validate-phase.sh <scan_base> final-reconciliation`.

Yield only after validation completes. Yield structured status with:
- `status`
- `final_findings`
- `artifacts`
- `warnings`
- `errors`
