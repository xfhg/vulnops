---
name: vulnops-recon
description: Read-only repository reconnaissance agent for VulnOps audits
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
    projects:
      type: number
    entry_points:
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

Build repository context for the target described by `.harness/audit-context.json`.

Follow `config/agents/recon.md`. Write only under `paths.repo_context`.

Required artifacts:
- `repo-context/repo.md`
- `repo-context/repo-context.json`
- `repo-context/phase-manifest.json`

Constraints:
- Read-only on `repo_path`.
- No network.
- Do not report guesses as architecture. Every project, entrypoint, trust boundary, and ignore pattern needs evidence.

IRC progress:
- Send `irc op=send to=Main message="<short phase status>"` at start, each material stage boundary, before validation, and before yielding.
- Keep progress messages short. Do not include secrets, full findings, payloads, or raw tool output.
- Do not send fake timer heartbeats; only report real state changes.

Before yielding, run `bash scripts/validate-phase.sh <scan_base> recon`.

Yield only after validation completes. Yield structured status with:
- `status`
- `projects`
- `entry_points`
- `artifacts`
- `warnings`
- `errors`
