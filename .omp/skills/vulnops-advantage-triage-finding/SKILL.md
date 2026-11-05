---
name: vulnops-advantage-triage-finding
description: Triage selected immutable baseline claims into exact source-backed Advantage proof obligations while preserving input identities and dispositions.
---

# Advantage Triage Finding

Read the [Advantage execution context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. Native baseline and planning schemas own triage; external intake
transports and standalone triage schemas are not used.

## Inputs, owner, and permissions

`vulnops-advantage-planning` triages selected canonical baseline records and
explicitly supplied local claims admitted by the execution. Require their source
identity, original status, exact record reference, available evidence and actual
current source under the shared assessment contract. Preserve external identifiers as contextual data;
never invent missing scanner fields or turn report prose into canonical evidence.
Use the full catalog rather than rendered report caps. Read-only, offline,
inline triage only: no external ticket retrieval, provider credentials, build,
test, PoC, source edit, worker delegation, or automatic remediation.

## Assess the exact claim

1. Normalize mentally into actor, controlled source, component/version,
   closest control or sink, prerequisites, claimed consequence, supplied
   locations, evidence, counterevidence, and missing facts. Keep one addressable
   disposition per selected input, even for duplicate-looking records.
2. Use the [static assessment method](../vulnops-self-verification/references/static-assessment.md)
   to inspect the selected claim. An advisory alone does not establish reachable
   affected use, and a neighboring weakness cannot replace the selected source,
   control and impact tuple.
3. Read applicable local policy as evidence about supported behavior and
   boundaries, without changing it or giving it workflow/suppression authority.
   Missing policy neither proves nor defeats a finding. Apply existing VulnOps
   exclusions and preserve the policy basis for material judgments.
4. Trace the actual input through every material interpretation and check to
   the consequence. Verify denial/fallback behavior and validated-versus-consumed
   identities. Names such as admin, local, plugin, or configuration do not by
   themselves establish trust; source must show who controls the input and what
   new authority the failure grants.
5. Check plausible shipped paths and supported conditions. One safe default
   cannot dismiss a supported alternative, and an insecure opt-in does not prove
   a supported attacker boundary by itself. Treat deployment/version ambiguity
   as a precise proof obligation, not scanner severity or inherited privilege.
6. Distinguish static support, positive counterevidence, and unresolved facts.
   Baseline-accepted claims remain attributed history; a proposed contradiction
   needs linked evidence and fresh review, never editing the prior verdict.
   Rejected routes require a substantive changed hypothesis or new evidence.

## Prioritize and preserve

Rank actionable obligations by reachability, required privilege, attainable
conditions, attacker control, guard strength, and evidence quality, with impact
as a further prioritization input. Keep source-supported and unresolved queues
distinguishable. Do not deduplicate away supplied identities or manufacture a
capability because an advisory sounds severe. An inaccessible external source
is an unavailable fact, not permission to fetch it.
Use the shared fallible-baseline rules for malformed or ambiguous records:
preserve origin and limitation without inventing an accepted finding identity.
A defective reference earns investigation only if its missing fact changes a
consequential attacker conclusion. Otherwise prioritize another actionable route,
not cosmetic repair or replay of the source audit.

## Native output

Record each considered input's exact disposition and reason in the native plan,
with original baseline reference/status intact. Selected questions retain their
own source anchors, counterevidence, next proof obligation, and stop condition.
Unselected or redundant inputs receive explicit accounting, not false reviewed
coverage. Native labels and schemas govern; do not emit `triage-finding/v0` or
publish a second confirmed-finding list. The planner may propose an investigation
of a supported claim, but only synthesis plus fresh verification can establish a
new Advantage finding. Separate Blue remediation is never launched by triage.
