---
name: vulnops-advantage-fix-finding
description: Apply Advantage finding context only within separately authorized Blue production remediation and its existing disposable-copy publisher.
---

# Advantage Fix Finding

Read the [Advantage execution context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. Retain boundary-first repair and bypass/compatibility review; the existing
VulnOps production-only remediation contract controls every write and outcome.

## Explicit separate authority

This skill is not an Advantage phase or handoff action. It may be selected only
after an operator separately requests remediation from a completed, validated
Advantage bundle using `bash remediate.sh <completed-advantage-base>`.
The existing `vulnops-remediation` coordinator and `vulnops-remediate-one`
worker use the bound Blue remediation route. Advantage's Red investigators and
Astra controller must not implement or publish fixes.

Require an eligible remediation packet, selected independently accepted finding,
complete verified dossier, bound original audit plus linked evidence closure,
matching audited source, and remediation context. Findings about a supplied
**derived patch** cannot be patched against the unchanged audited target; they
need an audit of that changed target before automated production remediation.
Preserve the existing explicit multi-repository automated-remediation restriction.
Missing accepted source or unsupported ownership is not permission to bypass
admission or create an unbound patch.
Simplified audit/Advantage completion is not exact-source remediation authority.
Historical-only claims or mixed-attempt inputs lacking the authority required by
this separate policy need the precise manual-required prerequisite; do not infer
eligibility from a current report, add audit admission gates, or broaden Blue
authorization. Supported exact-source remediation protections remain unchanged.

## Establish the repair contract

1. Read all cited evidence and decisive source. Establish the original attacker's
   input, source-to-sink path, failed invariant, exact root control, prerequisites,
   and strongest counterevidence. A completed dossier is input to engineering,
   not an excuse to skip current source identity or caller checks.
2. Inspect direct callers, implementations, relevant existing tests as text,
   error conventions, APIs, state transitions, and supported optional modes.
   Identify the narrowest shared enforcement boundary and legitimate behavior
   that must remain. Existing tests guide the design but are not executed here.
3. Challenge alternate encodings, parser forms, aliases, sibling consumers,
   validation-to-use gaps, and copies of security-sensitive state. A patch
   blocking one example while preserving the dangerous capability is incomplete.
4. If the claim is contradicted, source drifted, the required decision is missing,
   or a coherent safe production fix cannot be made, use the existing
   `manual_required` result with exact evidence and next engineering action.
   Do not add speculative source changes or invent a `fixed` outcome.

## Produce only the authorized patch

Run `python3 scripts/prepare-remediation-work.py <finding-id>` and edit only its
returned disposable `working` copy. Keep `original`, target, original audit,
and completed Advantage bundle unchanged. Use the smallest repository-native
change closing the actual boundary while preserving legitimate behavior.
Production source/configuration/dependency changes only: no tests, fixtures,
specs, examples, documentation, or unrelated cleanup in the patch. No target
execution, builds, tests, package manager, dependency download, or live probing.

Before publication, challenge the candidate as an adversary: inspect both
branches of changed conditions, each direct caller, at least one plausible
alternate malicious representation, and an ordinary/default legitimate input.
Revise a concrete in-scope bypass/regression, not speculative redesign. Do not
spawn an unauthorized reviewer pool or import upstream apply/verify stages.

Write the existing `remediation-worker-result` and invoke only
`python3 scripts/publish-remediation-patch.py <finding-id>` to publish the
production patch and receipt. That publisher is the sole patch authority under
`remediations/`; never author `patches/*.patch` or receipts directly. Follow the
existing bounded publisher revision rule, not indefinite patch attempts.

## Honest output

Return the existing worker's `patch_ready`, `manual_required`, or `failed`
structured yield with exact artifact, addressed root causes, changed files,
static rationale, and limitations. An application check means patch applicability,
not semantic correctness or dynamic repair. Recommend malicious and legitimate
regression checks in the permitted result text without adding or executing them.
Independent fix verification is a separately selected immutable-patch assessment;
this skill cannot close a vulnerability, apply a patch to target, commit, push,
merge, or claim a runtime fix.
