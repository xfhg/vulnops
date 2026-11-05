---
name: vulnops-advantage-finding-discovery
description: Discover source-backed Advantage roots, independent sibling operations, alternate routes, and capability extensions within a bound question packet.
---

# Advantage Finding Discovery

Read the [Advantage execution context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. Use existing VulnOps audit, exclusion, self-verification and applicable
vulnerability-family doctrine. When assessing a concrete candidate, read the
[static assessment method](../vulnops-self-verification/references/static-assessment.md).

## Packet, scope, and permissions

`vulnops-advantage-investigator` owns exactly one immutable task packet and its
native result. Inputs include full bound baseline access, relevant source,
objective/question, initial attacker/access, known and conditional capabilities,
counterevidence, proof obligation, and stop conditions. Inspect authorized source
and admitted evidence; no nested scan, target edits, network access, direct
execution, credential use, or policy authoring. Actions-only handoff does not
invoke discovery; record unexpected hypotheses as unconfirmed follow-up instead.

## Seek the additional proof, not a repeated title

1. Restate what the baseline actually established and what additional outcome
   would matter. A new root, independent sibling operation, alternate route,
   materially stronger chain, impact extension, and baseline contradiction each
   require their own proof. A repeated root and impact are revalidation only.
2. Start at the assigned source/control/sink anchors. Follow attacker influence
   through decoding, validation, binding, storage, re-parsing, dispatch, fallback,
   error, retry, cleanup, and eventual consumption. Work backward from the
   sensitive capability to its reachable callers as a second perspective.
3. Identify the closest enforcing control, its actual semantics, and the strongest
   counterexample to the claim. Preserve baseline rejection and deferred status.
   Reopen rejection only with a changed hypothesis or evidence addressing that
   exact countercontrol; uncertainty is not proof that the control is absent.
4. Enumerate concrete independently reachable operations when a pattern spans a
   family: routes/protected actions, parser or codec registrations, templates,
   query modes, path helpers, handler subclasses, or shared-control callers.
   Keep each distinct sink/control/impact tuple addressable. A shared wrapper
   proves reachability; it does not replace the vulnerable child operation.
5. Retain both the entrypoint and reusable root-control location. Include
   branch-local transforms, fallback/append/from-path behavior, concrete
   implementations, and the final consumer when they select dangerous semantics.
   Do not assert 'all implementations' without source-backed enumeration.
6. Compare sibling safe paths without transferring their protections. For
   validation-to-use mismatches, follow the exact validated object/value into
   later selection, mutation, redirect, alias resolution, or consumption. For
   archive/path writes, check containment before the first side effect, not
   a later import gate. For network destinations, examine redirects and the
   final requested destination. For stateful auth, inspect principal rebinding
   and the consumed assertion, not just an earlier successful validation.
7. Respect exact seeded records. An advisory hit needs local affected-use and
   reachability proof; a nearby same-family bug does not resolve its obligation.
   Do not repeat SCA or Secrets scanning. Use inherited records as leads and
   preserve their evidence limitations, without retaining literal secrets.
8. When a material prerequisite is missing, inspect one bounded adjacent set of
   likely callers/configuration/contracts if within the packet. Otherwise retain
   the exact fact and next action; never spin into unbounded repository search.
Apply the shared attack-value rule: an unusable baseline reference is a local
lead limitation, not a required repair task. Preserve independently supported
sibling candidates and name the blocked capability fact; investigate an alternate
route only within this packet or the coordinator's admitted continuation.

## Native candidate output

In the packet-bound result, preserve stable candidate identity, baseline relation
and references, question/objective links, the exact failed invariant, attacker
input, source-to-sink evidence, conditions, independent root/affected locations,
counterevidence, proof gaps, and provenance. Use the live `advantage-result`
candidate schema, not an upstream discovery ledger or invented supplementary
fields. Give every assigned question a terminal outcome even when no candidate
survives; a discovery candidate is not final finding authority.

Separate root-control, wrapper/entrypoint, sink, and concrete implementation in
the evidence narrative and locations. Family similarity alone does not justify
merging independent operations. A bounded discovery result may retain useful
primitive evidence without a finding; propose only an evidenced next question,
leaving continuation admission to the coordinator.
