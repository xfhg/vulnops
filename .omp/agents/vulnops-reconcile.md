---
name: vulnops-reconcile
description: Final reconciliation agent that merges triage with intrusion enrichment
tools:
  - read
  - write
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

Preserve intelligence provenance from `intelligence/investigation-cards.json`; do not upgrade or downgrade from intelligence alone unless intrusion or triage supplied evidence refs.

Before reading intrusion enrichment, confirm the main process already received a terminal `vulnops-intrusion` yield, then run `bash scripts/validate-phase.sh <scan_base> intrusion`. Do not reconcile against partial intrusion output.

Read:
- `triage/findings.json`
- `intrusion/enrichment.json` when present

Write:
- `final-reconciliation/candidates.json`
- `final-reconciliation/summary.md`
- `final-reconciliation/phase-manifest.json`

Each candidate must already match the non-rejected full-finding branch of
`schemas/v2/final-findings.schema.json`, including the source-specific code,
dependency, or redacted-secret payload. Use
`provenance.independent_verification_ref: "pending"`; the next phase replaces
it. Preserve category, attack-class IDs, methodology references, selected
lenses, structured root-cause location, ordered traces, and evidence tiers.
Every `raw_refs`, `intelligence_refs`, `graph_refs`, and `validation_refs`
entry must be a scan-relative artifact path with an optional JSON fragment or
record suffix; bare IDs are not provenance.
Do not promote unverified findings into final verification input.

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

## Skills

None. This phase does not load SAST specialist lens skills.
