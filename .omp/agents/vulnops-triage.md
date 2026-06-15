---
name: vulnops-triage
description: Cross-scan deduplication and risk ranking agent for VulnOps audits
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

Follow `config/agents/triage.md`, with one override: SAST input comes from `sast/verified-findings.json`, not raw SAST files.

Read SCA, secrets, and verified SAST outputs. Deduplicate, filter, and rank. Do not promote unverified SAST findings.

Write:
- `triage/consolidated.md`
- `triage/findings.json`
- `triage/phase-manifest.json`

Before yielding, run `bash scripts/validate-phase.sh <scan_base> triage`.

Yield only after validation completes. Yield structured status with:
- `status`
- `findings`
- `artifacts`
- `warnings`
- `errors`
