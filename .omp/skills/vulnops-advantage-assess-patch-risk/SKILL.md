---
name: vulnops-advantage-assess-patch-risk
description: Assess the exact selected Advantage patch's semantic impact, regression likelihood, protection, recoverability, and confidence without merge authority.
---

# Advantage Assess Patch Risk

Read the [native Advantage context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. When reviewing the selected patch or assigning its risk dimensions, read
the [patch-risk rubric](references/patch-risk-rubric.md).

## Selected input and ownership

Require `--assess-patch-risk --patch <immutable.patch>`, admitted repository,
exact selected current base binding, patch SHA-256, and read-only derived source view.
Ordinary modes assess under investigation; post-completion selection uses
**Shared top-level entry** in the shared context reference with
`--mode actions --action-source <completed-non-actions-advantage-base>` and the
original audit baseline, performing assessment only under handoff. Inside OMP
only the controller invokes `init-advantage.py --in-session` with those options;
assigned workers never initialize top-level work. Preserve explicit depth
(otherwise full), patch and repository requirements; never invoke a nested launcher.
Do not fetch a PR, inspect a moving branch as the subject, trust patch-author
claims, regenerate the patch, or infer authority from a small diff.

## Source-backed assessment

Describe semantic changes, trace affected runtime consumers, and challenge each
material boundary with a concrete malicious case and an independently grounded
legitimate control. Assess impact if wrong, regression likelihood, regression
protection, recoverability and confidence separately. Strong tests never lower
impact; unrun checks do not establish regression protection.

Inspect source and admitted observations only. Request material execution solely
through the native contained path when admitted; no direct tests, builds,
installation or credentials. Preserve the selected patch and read-only derived
view. Resolve accessible decisive gaps within the allocation, not through a new
hunt or environment.

## Native outcome

Populate the selected `patch_risk` record in the native action document with the
exact patch binding, all five dimensions, source-view-qualified citations
including derived source, actual checks, concrete defects versus missing proof,
and limitations. An
established bypass/regression requires a negative assessment, not merely a request
for more evidence. Unavailable tests are not affirmative defect evidence either.
Use only the native schema's rating/outcome values; there is no auto-merge label
or merge permission. Never apply, modify, push, commit, merge, publish or close a
finding. In actions mode retain unexpected hypotheses as unconfirmed follow-ups;
only a separate original-baseline investigation may promote them.
Apply shared action-quality accounting when necessary support is unavailable:
`assessment_status: locally_unresolved` retains uncertainty, with unknown
likelihood and low confidence rather than approval. Keep exact missing facts
and unrun checks; continue unrelated selected action records without a repair
phase, invented clean assessment or additional hunt.
