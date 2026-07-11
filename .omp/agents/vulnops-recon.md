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
`vulnops-recon-inputs` in one `task` batch with stable IDs `Overview`, `Trust`,
and `Inputs`. Use the OMP 16.4.4 batch fields `agent`, `context`, and per-item
`id`/`assignment`. The workers write only their three disjoint research files.
Nested OMP task batches are synchronous, so the task result is the worker
completion signal; do not IRC-poll while the call is blocked. Verify every
structured yield and research artifact before synthesis.

Write aggregate artifacts only under `paths.repo_context`. Merge validated worker observations into the
strict repository and security-surface schemas without inventing files,
entrypoints, or boundaries. Preserve target-relative evidence references and
validate `recon` before yielding.

`projects[].dependency_files` is a machine handoff to deterministic Wraith
collection, not a general inventory of dependency/build files. You may leave these
arrays empty in the draft. After writing `repo-context.json` and
`security-surfaces.json`, run
`python3 scripts/finalize-recon.py <repo_path> <scan_base>`. The finalizer discovers
every supported target input, assigns it to the most specific compatible project,
rewrites only these arrays, deterministically renders `repo.md`, and writes the
phase manifest. Do not hand-author or edit `repo.md` or
`repo-context/phase-manifest.json`. Put `go.sum`, `package.json`, build
scripts, Dockerfiles, CI workflows, and other unsupported metadata in `build_ci`
or evidence prose.

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
- As the top-level coordinator, send `irc op=send to=Main message="<short phase status>"` at start, after the worker batch, before validation, and before yielding.
- Keep progress messages short. Do not include secrets, full findings, payloads, or raw tool output.
- Do not use IRC as a completion signal and do not send fake timer heartbeats.

Before yielding, run the deterministic Recon finalizer, then
`bash scripts/validate-phase.sh <scan_base> recon`.

Yield only after validation completes. Yield structured status with:
- `status`
- `projects`
- `entry_points`
- `artifacts`
- `warnings`
- `errors`

## Skills

- `skill://vulnops-audit-core`
