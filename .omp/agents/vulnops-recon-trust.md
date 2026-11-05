---
name: vulnops-recon-trust
description: Trust-boundary, actor, authentication, authorization, and privilege researcher
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
Record root `provenance` with actor `vulnops-recon-trust`, its full assigned
selector and `artifact_ref: "repo-context/research/trust-boundaries.json"`.

Read `.harness/audit-context.json`, `skill://vulnops-audit-core`, and the
application source root. Use `repositories` to identify component boundaries.
Identify actors, untrusted sources, authentication and authorization
enforcement, privilege separation, tenant boundaries, setup/debug bypasses,
cross-repository trust assumptions, and every lower-to-higher trust
crossing. Distinguish operator-equivalent input from real lower-privileged
attackers.

Publish compact source-backed `attack_paths` for important actor-to-asset flows:
starting_actor, entry_surface_ids, controlled_material, authority_decisions,
identity_propagation, sensitive_effect, handoff_evidence and exact unknowns.
Each handoff names producer and consumer source paths, material, and source_refs;
do not infer deployment binding from matching names. Preserve repository prefixes.
The coordinator resolves worker surface identifiers into aggregate entrypoints.

Write `paths.repo_context/research/trust-boundaries.json` matching
`schemas/v2/recon-research.schema.json` with `worker: "trust-boundaries"`, UTC
`started_at`/`completed_at`, and source-root-relative path:line evidence.
Multi-repository paths must include their repository prefix. Write no other
file, use no network access, and never modify target source. Yield
only `status`, observation count, the absolute artifact path, warnings, and
errors.

## Skills

- `skill://vulnops-audit-core`
- `skill://vulnops-access-control`
