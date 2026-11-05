---
name: vulnops-advantage-threat-model
description: Derive source-backed informed-attacker objectives from an immutable completed-audit baseline during Advantage planning.
---

# Advantage Threat Model

Read the [Advantage execution context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. This skill belongs to `vulnops-advantage-planning`; it does not launch a
scan, revise the source threat model, or author security policy.

## Inputs and permissions

Use the validated Advantage context, full baseline catalog, original threat
model/objectives and their statuses, relevant findings and counterevidence,
current source repositories and resolved allocation under the shared context contract. Source and
baseline are read-only; no execution, credential use, network lookup, policy
write, shared-model cache, or new worker pool is authorized. Actions-only mode
skips planning; never regenerate a model to expand a selected action.

## Establish the actual boundary

When mapping or challenging architecture, use
[source-backed threat modeling](../vulnops-audit-core/references/threat-modeling.md)
for effective resources, authority, configuration and boundary evidence.

1. Read the baseline architecture and the exact current source consumers material
   to the proposed outcome. Preserve inherited facts separately from current proof.
2. Identify plausible lower-privileged actors and their initial controlled
   material. Separately record baseline knowledge, source-established
   capabilities, conditional capabilities, demonstrated capabilities, and
   privileges the actor lacks. A known file-read weakness supplies a lead, not
   credentials; readable scope, credential presence, authority, and consumer
   acceptance are separate obligations.

## Derive actionable objectives

For each material route, state the exact security invariant and desired attacker
outcome; attach baseline objective/question links without editing their
original definitions. Record the entrypoint, protected asset, expected control,
capability gain, necessary conditions, strongest counterevidence, exact missing
proof, and stop condition. Preserve repository prefixes across services and
prove concrete route/topic/storage/configuration handoffs rather than matching
symbol names.

Choose work by impact, realistic reachability, evidence quality, and ability to
settle consequential missing facts. Cover distinct actors and boundaries fairly;
maxima are ceilings, not a requested number of hypotheses. A zero-finding
baseline can support unresolved source-backed questions without an invented
primitive. Reopening a rejected route requires evidence or a changed hypothesis
that addresses its decisive rejection; otherwise disposition it as redundant.
A missing local fact and an unavailable deployment fact are different limits.
Apply the shared attack-progress rules when intelligence is defective: unknown
cohorts are not zero findings, and ambiguous IDs supply no uniquely accepted
primitive. Choose the missing capability or consumer fact that could change an
outcome; citation cleanup alone is neither an objective nor mandatory planning.

## Native output

Supply the planner's `advantage-plan` draft: linked objectives, questions,
attacker knowledge/access distinctions, baseline references, source anchors,
proof/stop conditions, pass assignments, and considered-record dispositions.
Use the exact schema fields described in the shared reference. Preserve a
material architecture discrepancy in the relevant objective/question reasoning;
do not create a competing standalone threat-model authority. The planner owns
`build-advantage-plan.py`, canonical packets, and the terminal phase yield.
Architecture mapping is not completed investigation coverage and hypotheses are
not accepted findings. An empty plan still explains what was considered and why
no actionable question was allocated.
