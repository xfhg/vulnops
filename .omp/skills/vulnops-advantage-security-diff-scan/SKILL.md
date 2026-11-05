---
name: vulnops-advantage-security-diff-scan
description: Review every changed or deleted source path in an immutable Advantage patch against its explicitly selected current base and derived source view.
---

# Advantage Security Diff Scan

Read the [Advantage execution context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. Native patch admission and canonical results own this review.

## Inputs and authority

Use **Shared top-level entry** in the shared context reference. Inside OMP the
controller selects
`python3 scripts/init-advantage.py --in-session [<completed-audit-path-or-run-id>] --mode diff --patch <immutable.patch> --repository <inventory-key>`.
Preserve explicit depth; omitted depth is full. Terminal startup is documented
only in that shared entry contract. Assigned investigators never initialize
top-level work or invoke launchers.
Repository selection can default only for a single-repository current inventory.
`vulnops-advantage-investigation` coordinates; native investigators review the
assigned patch questions. Require the admitted `patch_binding`, exact patch
SHA-256, selected current repository/base binding, derived identity, and changed-path
inventory. These exact patch-operation protections do not require equality to the
historical audit source. An unbound working tree, PR URL, moving branch or author
claim is not an assessment input. Initialization prepares the disposable derived
view; workers do not apply, regenerate or alter the patch or read-only target.

Use the full baseline for architecture, accepted roots, unresolved obligations,
and counterevidence. Baseline findings describe historical source, not automatically the current base or supplied patch.
Every citation states base versus derived view with the native source citation
contract and preserves the owning repository. Read only the admitted views.

## Review the actual change

1. Account for every admitted changed source file, including deleted paths.
   Native patch admission accepts ordinary text additions, modifications and
   deletions, not rename metadata. Do not rank away a changed file. Read deletions
   in the selected current base and follow the surviving operation in the derived view.
2. Describe the semantic delta: changed input or authority, control placement,
   interpretation, default, state transition, failure path, and sensitive
   consumer. Commit messages and patch commentary are claims, not evidence.
3. For a deleted authorization guard, identify the base invariant and protected
   operation, then prove whether the derived path still has equivalent
   enforcement. A `deleted_control` record requires base guard evidence and a
   derived-view citation in `affected_consumers`. File disappearance alone is
   neither a fix nor a vulnerability.
4. Trace necessary supporting callers, implementations, dispatch/registration,
   configuration, and downstream consumers. Expand a changed shared helper to
   each materially affected sibling operation; unchanged siblings are context
   or negative controls unless the change alters their reachability or control.
   Do not drift into an unrelated repository-wide hunt.
5. Preserve independently triggerable controls and sinks as addressable
   candidate instances. Identify the exact changed line when the bug overlaps
   the diff, but retain the root-control and consumer locations even when outside
   the hunk. New reachability of an old sink must be proved from the change.
6. When challenging a concrete candidate, use the
   [static assessment method](../vulnops-self-verification/references/static-assessment.md)
   for its source/control/sink/boundary tuple, counterevidence and proof gaps.
   Follow with causal transition analysis and existing severity doctrine.
   Dynamic work is optional and only through the admitted safe wrapper;
   reading tests is not executing them.
7. Close every changed path with a review disposition and every allocated
   question with a precise terminal resolution. If the allocation prevents
   review, name the exact path and missing obligation rather than claiming
   complete changed-file coverage.
   Apply the shared local-defect rules per path/obligation: an unusable citation
   leaves that path explicitly unresolved without blocking unrelated changed
   paths. Preserve exact changed/deleted-file accounting; do not repair patch
   identity, widen scope or claim that unresolved review is a clean diff.

## Output and follow-on

Write the assigned native packet/result, including the exact patch identity,
source-view-qualified evidence and changed-file accounting required by the
shared reference. Distinguish introduced or newly reachable vulnerabilities,
removed controls, still-present baseline weaknesses, and demonstrated fixes.
Fix-verification and risk verdicts are separate selected action assessments,
not vulnerability acceptance. New findings proceed through synthesis and fresh
final verification. Never edit baseline findings, auto-publish a patch, or
claim regression protection from clean textual application.

Actions-only patch assessment is not diff discovery: it produces handoff action
outcomes and unconfirmed follow-up evidence only, with no new finding promotion.
