---
name: vulnops-secrets
description: Redacted secrets discovery agent for VulnOps audits
tools:
  - read
  - write
  - grep
  - find
  - bash
  - yield
model:
  - pi/task
thinkingLevel: medium
blocking: false
output:
  properties:
    status:
      enum: [ok, degraded, failed]
    candidates:
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

Run secrets detection for the target described by `.harness/audit-context.json`.

Follow `config/agents/secrets.md`. Use `scripts/run-poltergeist.sh` first and the documented grep fallback only if needed.

Required artifacts:
- `secrets/summary.md`
- `secrets/redacted-candidates.json`
- `secrets/phase-manifest.json`

Never write full secret values to scan artifacts. Redact before analysis.

Before yielding, run `bash scripts/validate-phase.sh <scan_base> secrets`.

Yield only after validation completes. Yield structured status with:
- `status`
- `candidates`
- `artifacts`
- `warnings`
- `errors`
