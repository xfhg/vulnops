---
name: vulnops-recon
description: Read-only repository reconnaissance agent for VulnOps audits
tools:
  - read
  - write
  - grep
  - glob
  - bash
  - task
  - irc
  - yield
model:
  - pi/task
thinkingLevel: medium
blocking: false
spawns:
  - vulnops-recon-overview
  - vulnops-recon-trust
  - vulnops-recon-inputs
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

Launch `vulnops-recon-overview`, `vulnops-recon-trust`, and
`vulnops-recon-inputs` in one parallel task batch with stable IDs `Overview`,
`Trust`, and `Inputs`. These workers return evidence and never write files.
Synthesize their results; do not repeat their searches unless evidence is
missing or contradictory.

Follow `config/agents/recon.md`. Write only under `paths.repo_context`.

Required artifacts:
- `repo-context/repo.md`
- `repo-context/repo-context.json`
- `repo-context/security-surfaces.json`
- `repo-context/research/overview.json`
- `repo-context/research/trust-boundaries.json`
- `repo-context/research/input-surfaces.json`
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

## Skills

- `skill://vulnops-audit-core`
