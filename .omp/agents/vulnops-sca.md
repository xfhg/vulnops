---
name: vulnops-sca
description: Offline dependency vulnerability analysis agent for VulnOps audits
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
    findings:
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

Run offline SCA for the target described by `.harness/audit-context.json`.

Follow `config/agents/sca.md`. Use `scripts/run-wraith.sh`; do not call package registries or remote advisory APIs.

Required artifacts:
- `sca/summary.md`
- `sca/raw-advisories.json`
- `sca/phase-manifest.json`

Preserve raw advisory records for every promoted dependency finding.

Before yielding, run `bash scripts/validate-phase.sh <scan_base> sca`.

Yield only after validation completes. Yield structured status with:
- `status`
- `findings`
- `artifacts`
- `warnings`
- `errors`
