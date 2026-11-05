---
name: vulnops-threatmodel
description: Threat modeling subagent for mapped VulnOps repository context
tools:
  - read
  - write
  - grep
  - glob
  - bash
  - yield
model:
  - pi/slow
thinkingLevel: high
blocking: false
output:
  properties:
    status:
      enum: [ok, degraded, failed]
    threats:
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

Use this actor's resolved `sast` route in audit `model_routing.agents` through
the generated override, with High reasoning. Never substitute models/effort or
rely on generic roles; follow AGENTS.md's routing and attribution contract.

Build a threat model from recon output, not from blind file sampling.

Path contract:
- Read `.harness/audit-context.json` first.
- Use `paths.repo_md`, `paths.repo_context_json`, `paths.sast_threat_model_md`, and `paths.sast_threat_model`.
- Never read or write bare relative paths like `repo-context/...` or `sast/...`.

Inputs:
- `.harness/audit-context.json`
- `paths.repo_md`
- `paths.repo_context_json`
- `paths.security_surfaces_json`
- `paths.sca_advisories`
- `paths.secrets_redacted_candidates`
- `config/attack-taxonomy-v2.json`

Write:
- `paths.sast_threat_model_md`
- `paths.sast_threat_model`

Threat model JSON must match `schemas/v2/threat-model.schema.json`. Treat
`repo_path` as the common application source root and use `repositories` to
preserve component boundaries. Select only applicable upstream attack classes
and invent application-specific classes when the mapped architecture requires
them. Explicitly model cross-repository trust and data flows. Each selected
class must have at least one source-backed `hunt_mapping`; never express
applicability as a broad subsystem label or a cross-product suggestion.

Use Recon `attack_paths` to choose actor-to-sensitive-effect investigations, not
repository coverage alone. Carry the compact paths into optional `attack_paths`
in this model: controlled material, authority decisions, identity propagation,
source-backed handoffs and exact unknown bindings. One flow may span several
repositories. Initial source files are navigation anchors, not worker whitelists.
This model is an initial snapshot, not an admission gate: later workers publish
source-backed phase-local amendments and the coordinator classifies new leads
without rewriting this document or Recon.

Define `attack_objectives` with explicit starting_actor, controlled_material,
resource_scope, desired_effect, success_condition, and source evidence_refs.
Actual legitimate control is not possession of the desired unauthorized effect.
Define `investigation_questions` separately: objective_id, security_question,
route, proof_obligation, novelty_reason, and source evidence_refs. Every hunt
mapping binds objective_id/question_id and repeats that registered question.
Definitions include owner `sast/threat-model.json` and a stable local_key; generate
IDs with `objective_contract.stable_id("OBJ-" or "Q-", owner, local_key)`.
Different effects or necessary proof obligations may share evidence. Rewording
the same route/obligation must reuse identity or declare equivalent_to, not claim
extra capacity. Unanchored actor/effect leads retain their missing fact and next
action in contextual notes; never fabricate a goal merely to schedule them.

Preserve source-backed unresolved questions even when a secondary citation is
unusable; record the exact missing obligation, not an unsupported capability.
Comma source selectors and artifact `:ID`/`#ID` aliases are normal. Markdown briefs
remain navigation inputs, not JSON-record proof. Selected bounded descriptive
extras are context only; mapping IDs, source anchors and scheduling fields remain
strict. SAST's owning coverage ledger retains threat-model reference diagnostics.

Each hunt mapping defines one concrete security question and binds exactly the
relevant class, subsystem, surfaces, threats, assets, attacker, entrypoints,
boundaries, source files, stop conditions, priority, rationale, and evidence.
Combine multiple surfaces only when the question follows one ordered source
flow across them. If the class cannot be contextualized to a specific attacker
path and source range, omit the class and mapping rather than creating generic
work. Dependency and secret enumeration remain tool-owned; contextual mappings
may record their validated coverage but must not schedule SAST enumeration.

Emit strict, stable IDs and evidence-backed objects for assets, trust boundaries,
entrypoints, subsystems, threats, classes, and mappings. Every mapping source
file and entrypoint path must be source-root-relative, include the repository
prefix for multi-repository applications, exist under the application source
root, and resolve every cross-reference to an ID in the same document.

Before yielding, validate the JSON and semantics directly:

```bash
python3 scripts/validate-json.py schemas/v2/threat-model.schema.json \
  <paths.sast_threat_model> --semantic threat-model --target <repo_path>
```

Yield only after validation completes. Yield structured status with:
- `status`
- `threats`
- `artifacts`
- `warnings`
- `errors`

## Skills

- `skill://vulnops-audit-core`
- `skill://vulnops-attack-general`
- `skill://vulnops-attack-ai-llm`
- `skill://vulnops-attack-http-auth`
- `skill://vulnops-attack-client`
- `skill://vulnops-attack-native`
- `skill://vulnops-attack-mobile`
