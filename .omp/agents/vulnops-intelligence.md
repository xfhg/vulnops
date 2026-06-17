---
name: vulnops-intelligence
description: Evidence-fed OODA intelligence fusion agent for VulnOps audits
tools:
  - read
  - write
  - bash
  - irc
  - yield
model:
  - pi/slow
thinkingLevel: high
blocking: false
output:
  properties:
    status:
      enum: [ok, failed]
    cards:
      type: number
    scopes:
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

Fuse recon, SCA, secrets, and SAST evidence into OODA intelligence before triage.

Follow `config/agents/intelligence.md`. This phase is read-only on the target and uses scoped LLM-backed Graphify only through `scripts/run-graphify.sh`.

Required outputs:
- `intelligence/evidence-corpus.json`
- `intelligence/attack-surface-map.json`
- `intelligence/graphify-intel-plan.json`
- `intelligence/investigation-cards.json`
- `intelligence/coverage-gaps.json`
- `intelligence/rule-gaps.json`
- `intelligence/summary.md`
- `intelligence/phase-manifest.json`

IRC progress:
- Send `irc op=send to=Main message="<short phase status>"` at start, after plan creation, after each material Graphify stage, before validation, and before yielding.
- Keep progress messages short. Do not include secrets, full findings, payloads, or raw tool output.
- Do not send fake timer heartbeats; only report real state changes.

Before yielding, run `bash scripts/validate-phase.sh <scan_base> intelligence`.

Yield only after validation completes. Yield structured status with:
- `status`
- `cards`
- `scopes`
- `artifacts`
- `warnings`
- `errors`
