---
name: vulnops-intrusion
description: Additive graph-guided intrusion enrichment agent for VulnOps audits
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
thinkingLevel: high
blocking: false
output:
  properties:
    status:
      enum: [ok, degraded, failed, skipped]
    enrichments:
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

Follow `config/agents/intrusion.md`. This phase is additive; failure degrades the scan but does not block reconciliation.

Do not yield while graphify extraction is still running or only partial `graphify-out/` artifacts exist. Intrusion is terminal only when `intrusion/enrichment.json` exists and `intrusion/phase-manifest.json` has status `ok`, `degraded`, `skipped`, or `failed`.

If graphify times out or cannot complete, write a degraded `intrusion/phase-manifest.json`, a safe empty `intrusion/enrichment.json`, and `intrusion/summary.md` explaining the degradation.

Write:
- `intrusion/summary.md`
- `intrusion/enrichment.json`
- `intrusion/phase-manifest.json`

IRC progress:
- Send `irc op=send to=Main message="<short phase status>"` at start, each material stage boundary, before validation, and before yielding.
- Keep progress messages short. Do not include secrets, full findings, payloads, or raw tool output.
- Do not send fake timer heartbeats; only report real state changes.

Before yielding, run `bash scripts/validate-phase.sh <scan_base> intrusion`.

Yield only after validation completes. Yield structured status with:
- `status`
- `enrichments`
- `artifacts`
- `warnings`
- `errors`
