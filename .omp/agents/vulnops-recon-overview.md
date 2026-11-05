---
name: vulnops-recon-overview
description: Repository overview, stack, architecture, and comparable-baseline researcher
tools:
  - read
  - write
  - grep
  - glob
  - bash
  - yield
model:
  - pi/task
thinkingLevel: high
blocking: false
output:
  properties:
    status:
      enum: [ok, degraded, failed]
    observations:
      type: number
    artifact:
      type: string
    warnings:
      elements:
        type: string
    errors:
      elements:
        type: string
---

Use this actor's resolved `recon` route in audit `model_routing.agents` through
the generated override, with High reasoning. Never substitute models/effort or
rely on generic roles; follow AGENTS.md's routing and attribution contract.
Record root `provenance` with actor `vulnops-recon-overview`, its full assigned
selector and `artifact_ref: "repo-context/research/overview.json"`.

Read `.harness/audit-context.json`, `skill://vulnops-audit-core`, and the
application source root. Use `repositories` to identify component repository
boundaries. Map what the application is, its users, stack, deployment model,
major components, entry points, and cross-repository integration points, and a
comparable baseline. A comparable must include its evidence basis and
confidence; use `null` when no meaningful offline baseline exists.

When identifying project dependency inputs, distinguish package-manager files
from build and CI metadata. Only paths accepted by
`python3 scripts/dependency_contract.py <path>` may be proposed for a project's
`dependency_files`. In particular, companion manifests such as `package.json`,
checksums such as `go.sum`, Dockerfiles, Makefiles, workflows, and general config
belong in architecture/build evidence, never in `dependency_files`.

Write `paths.repo_context/research/overview.json` matching
`schemas/v2/recon-research.schema.json` with `worker: "overview"`, UTC
`started_at`/`completed_at`, and real source-root-relative path:line evidence.
Multi-repository paths must include their repository prefix. Write no other
file, use no network access, and never modify target source.
Yield only `status`, observation count, the absolute artifact path, warnings,
and errors.

## Skills

- `skill://vulnops-audit-core`
