---
name: vulnops-advantage-verify-fix
description: Independently assess explicitly selected accepted findings against an immutable Advantage patch, returning fixed, still vulnerable, or inconclusive without editing.
---

# Advantage Verify Fix

Read the [Advantage execution context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. When challenging the selected claim against source, use the
[static assessment method](../vulnops-self-verification/references/static-assessment.md).
Assessment is read-only; patch generation or a request to run tests does not
implicitly select it.

## Exact selected inputs

Require explicit `--verify-fix <finding-id>` selection, immutable `--patch`,
repository ownership, exact selected current patch base, native patch binding, and the
selected accepted finding's complete dossier/evidence. Repeated selections are
handled by native admission, not fuzzy title matching.

In standard/deep/diff modes the selected IDs refer to accepted original-audit
findings; assessment belongs to investigation. For a finding selected **after
Advantage completion**, use a new execution through **Shared top-level entry**
in the shared context reference. Inside OMP:

`python3 scripts/init-advantage.py --in-session [<original-audit-path-or-run-id>] --mode actions --action-source <completed-advantage-base> --patch <immutable.patch> --verify-fix <finding-id>`

Only the controller initializes this explicit request; assigned workers never
launch top-level work. Preserve explicit depth (otherwise full) and required
repository/selection options. Terminal startup remains in the shared entry
contract, not a nested launcher.

The action source must be completed, non-actions, and linked to the same original
audit, without historical fingerprint equality. Both evidence closures remain read-only. The
finding's execution identity is part of its identity; do not require that an
Advantage-origin ID exist in the original audit or confuse equal IDs across runs.
Actions-only assessment belongs to handoff and cannot confirm a new finding.

## Independent assessment

1. Read the original invariant, attack sequence, conditions, root controls,
   inherited primitives, impact limits, and legitimate workflows. Do not accept
   patch-author assurances, ticket status, absent new scan findings, or unrelated
   passing checks as proof.
2. Trace the original attack through the exact derived view. Follow moved,
   refactored, deleted, or renamed code to the protected consumer; a missing
   filename or changed function name does not establish closure.
3. Test the actual enforcement boundary against equivalent representations,
   parser/canonicalization differences, alternate callers, fallback branches,
   state copies, and validation-to-use changes. Preserve source-qualified base
   and derived citations using the native citation object.
4. Trace at least one relevant legitimate input or workflow through the changed
   code and direct callers. Verify APIs, error behavior, optional modes, and
   state compatibility material to the fix. A blocked attack with an unresolved
   legitimate-behavior obligation is not a complete fix.
5. Use existing source and actual admitted contained observations. Runtime checks
   are requests through the safe wrapper only when the selected phase/owner is
   admitted; never run target code, imports, builds, tests, or a PoC directly.
   If a required behavioral fact cannot be proved safely, record that fact and
   return inconclusive rather than weakening the read-only boundary.

## Native verdicts and output

Return one native `verify_fix.records` entry per exact selected finding, in the
native action schema, with immutable patch/finding binding, citations from both
base and derived views, original exploit evidence, bypass assessment,
legitimate-behavior evidence, actual checks/limitations, and verdict:

- `fixed`: the original security boundary is closed and relevant legitimate
  behavior is established; describe whether proof is static or contained.
- `still_vulnerable`: positive evidence shows the original vulnerable path or a
  materially equivalent bypass remains reachable.
- `inconclusive`: a material source, context, compatibility, runtime, or
  legitimate-control fact remains unresolved.
Apply the shared per-action quality rules. A local essential citation defect
keeps the selected record `inconclusive` / `assessment_status: locally_unresolved`
with its missing obligation; unrelated selected fixes continue. Unavailable
historical support cannot be substituted by another finding. Only attributed
independently sufficient optional support can preserve a positive assessment.

In ordinary modes the coordinator aggregates the owned assessment into
`investigation/actions.json`; in actions mode it uses `handoff/action-draft.json`,
as specified by the shared reference. Never edit patch bytes, derived source,
target, source findings, or
tracking state. New investigation-mode candidates still need synthesis and fresh
verification; actions-only surprises go to typed `unconfirmed_followups` with a
request for an original-baseline investigation, not an automatic scan.
