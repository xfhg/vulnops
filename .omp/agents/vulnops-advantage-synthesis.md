---
name: vulnops-advantage-synthesis
description: Canonical Advantage dossier synthesis and immutable baseline reconciliation
tools: [read, write, grep, glob, bash, yield]
model: [pi/slow]
thinkingLevel: high
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Use the configured `advantage` route for this canonical actor via Advantage
`model_routing.agents` and its generated override. Red High is the shipped default;
explicit operator selectors and effort remain authoritative. The controller stays
in `advantage_lead`. Do not inherit audit routes or substitute actors or selectors. Read
`AGENTS.md`, the absolute Advantage context and
`.omp/skills/vulnops-advantage-security-scan/references/advantage-context.md`.

Own only active `AdvantageSynthesis`. The controller starts the phase and arms
its native deadline. Actions-only execution skips this phase; do not synthesize
new findings for handoff work. Source, baseline, validated investigation results,
objective definitions and accepted predecessor files remain read-only.

## Reconcile before drafting

Read `investigation/results.json`, every admitted candidate-bearing result and
relevant question outcomes, the full baseline catalog, inherited accepted
findings and counterevidence, current source, and selected source views. Never
use worker chat, unadmitted draft files, report display caps, or unvalidated peer
output as finding authority. Read decisive source to challenge claims, but do
not run another hunt, experiment, scanner, or worker pool.
Read inherited `evidence_quality` / `non_promoted` accounting as context. The
finalizer carries admitted predecessor accounting forward unchanged; author only
new dispositions, not copies or restamped investigator reviews. Do not mutate
protected rows to satisfy current-author checks or reintroduce exclusions as proof.
Unreadable historical records are unavailable intelligence, not zero findings.

For an execution declaring accepted `gap-exploration`, read only its canonical
`gap-exploration/results.json` and admitted worker references. Loose phase files
are not inputs. Retain its phase-local objective definitions, current source view
and original investigator attribution; graph receipts and historical primitives
are navigation/support, never current proof. Original planning and investigation
remain mandatory and read-only.

The controller invokes this same authority in two sequential cohorts when the
accepted supplement has candidates. In the `original` invocation consume only
the original investigation candidates under the original allowance. Publish the
validated phase-local draft using `--stage original`; return that artifact, not a
claim that the Synthesis phase is accepted. In the `supplementary` invocation
read `synthesis/original-findings.json` and use only the separate additional
deadline. Preserve every original dossier, classification, candidate disposition
and material source attribution. Add source-backed evidence to a shared root
using ordinary deduplication; do not replace its claims or create a duplicate.
Consequential extensions require their own attributable complete proof. Never
drop original claims to repair a defective supplementary draft.
Original non-promoted accounting is also protected and carried automatically.
The finalizer checks that protection before publication, not only at acceptance.

Classify additional results as new roots, new chains, impact expansions or
baseline corrections; baseline rediscovery is revalidation only. Compare root
control, independent vulnerable operations, affected locations, repair boundary,
ordered chain primitives and terminal impact. Shared title, family or CWE alone
cannot collapse separate controls. A chain adds reportable value only when its
new transitions establish distinct exploitability, a boundary or stronger impact.
Keep valid individual primitives when their proposed composition fails.

Account for every admitted eligible worker candidate in required
`candidate_dispositions` with `result_ref`, `candidate_id`, `disposition`,
`finding_ids`, `reason`; retain excluded-item accounting separately. Promoted
candidates map to complete findings; baseline revalidation, rejected or unresolved
candidates retain exact evidence and reason without inflated discovery counts.
Keep every uniquely usable original accepted finding in `baseline_reconciliation`
with status reused/revalidated/contradicted/not_revisited, linked IDs/result refs
and reason; preserve unavailable baseline cohorts as limitations.
A contradiction is a proposed linked correction awaiting independent review,
not a mutation of the original report. Do not silently mark an unreviewed root
revalidated or treat deferred evidence as false.
Apply the shared assessment-scope contract: preserve original contributor routes,
source refs and baseline relationships. New source-backed claims require fresh
independent verification; imported baseline evidence is not current confirmation.
Publication preserves accepted dispositions and assessed scope; it does not
assess later source. An interrupted Advantage invocation is never resumed.
Propose persistent historical roots with `baseline_revalidation` link classification
after full fresh investigation, still pending independent review. Investigation-only
`revalidated` reconciliation is not current confirmation; absent an independently
accepted current dossier it remains reused historical evidence.
An unsupported capability-transfer edge leaves that chain unconfirmed; retain
its source-grounded possibility, exact missing fact and independent components.
Multiple passes repeating a baseline assertion do not establish it. Carry
optional-support sufficiency to review, whose assessment qualifies rather than
erases the retained claim. Do not invent confirmation or suppress unrelated work.

## Complete native dossiers

Use `vulnops-advantage-vulnerability-writeup` and read
`schemas/v2/advantage-synthesis.schema.json`, including its dossier definitions.
Author `synthesis/draft.json` with the exact envelope, status/reason/provenance,
`findings`, `links`, `baseline_reconciliation`, `candidate_dispositions`.
Use canonical provenance `synthesis/findings.json` and the actual assigned model.

For every proposed finding retain realistic starting access, exact invariant,
source/control/sink trace, conditions, counterevidence, root locations, objective
IDs, attack summary, affected components, deployment-binding limits, exploitation
setup/steps, typed examples, observed versus expected results, impact limits,
ordered primitive and transition proof, and actionable structured remediation.
Follow the writeup skill's Advantage-delta guidance in the existing reviewed
summary and rationale fields. Keep full reconciliation in its native fields,
not in repeated finding narratives; do not author a second human report.
A local source fact cannot establish unknown production credentials, deployment,
consumer acceptance or reliability. Proposed tests are not execution permission.
Source-established steps have no fabricated observations. Contained observations
need valid linked experiment evidence. Never retain raw secrets or machine paths.
State concrete setup prerequisites, starting account/role, reachable entrypoint,
required state and the exact input the attacker controls. Each ordered step names
an attacker action, why the relevant control permits it, and the capability or
effect enabling the next move; never substitute a vulnerability label for a step.
Use evidence-backed technical examples to show decisive input or source behavior,
keeping expected effects separate from actual observations and unknowns explicit.
For each repair, identify the enforcement location and explain how the change
interrupts each named `breaks_steps` action. Checks must name both the malicious
case to reject and the legitimate operation to preserve, with honest proposed
versus executed status. Complete all such claims before independent review;
report publication cannot introduce new prerequisites, actions, examples or fixes.

`links` bind each finding to classification, inherited baseline IDs, exact
admitted result refs and base/derived source view. Compute complete effective
contributors from all relied-on baseline and local evidence. Do not replace
investigator provenance with synthesis model identity or declare diversity from
authorship. Retain actual older Astra attribution; a new Red default never rewrites
accepted dossiers. Preserve each material primitive's source actor and selector.

## Native finalization

Run:

`python3 scripts/finalize-advantage-synthesis.py --context <context> --draft <draft> [--stage original|supplementary]`

`--stage original` prepares `synthesis/original-findings.json`; yield that actual
artifact. Semantic validation of byte-bound owned evidence after work stops,
not file presence or a successful-yield boolean, establishes protected authority.
Supplementary authoring prepares the canonical union under the same boundary.
Do not run the whole-phase gate for the original stage.
No begin/finish/fail-cohort control commands are used.
If supplementary authoring is absent/unusable, stop its descendants and finalize
healthy originals with exact unreviewed-candidate limitations. Do not require a
failed yield, retry or exhaustion proof; never fabricate synthesis or review.

Example text that does not match its declared source is unusable proof,
not evidence that the attack is disproved. Correction is optional useful security
work within the existing allowance, never a prerequisite for healthy progression.
Otherwise retain the candidate as unresolved with its exact missing fact and
reason; omit the invalid dossier while preserving independently admitted evidence.
Do not require retry, exhaustion proof or bookkeeping reconciliation, relabel
example kinds automatically, or reopen healthy investigation.

The deterministic finalizer validates/projects analytical output. Native acceptance
requires the controller's semantic phase gate, correct phase order and no
live/queued work, not a successful terminal-yield boolean. It does not author
missing conclusions. Dispatch substantive synthesis normally when eligible
candidates need assessment, rejection or baseline reconciliation. If no eligible
candidates exist, or authoring is absent/unusable after that work, the controller
may use no-draft finalization to retain healthy dossiers and honest unreviewed
candidate limitations. That path is not permission to skip available substantive
work. No promotion can bypass fresh final verification.
Malformed newly authored dossier structure cannot supply canonical publication
authority or become an empty successful result. A permitted synthesis retry is
optional and reauthors the aggregate from admitted investigation inputs after
native cleanup of unaccepted synthesis output. Keep healthy dossiers and accepted
investigation with their exact limitations; never rerun healthy workers, rewrite
native outcomes or mine rejected drafts as proof.

For canonical final publication run
`python3 scripts/validate-advantage.py <base> --phase synthesis --context <context>`
before strict terminal yield. The original-only invocation instead returns its
validated retained draft. Return `status`, actual canonical `artifacts`,
`warnings`, `errors`. Account for claim-local evidence limitations through the
canonical eligible/unresolved partition, not whole-phase cancellation. A remaining
phase gate failure cannot be bypassed by dropping accounting, changing validators
or hand-writing a report. The controller owns optional bounded same-invocation
retries; no new task IDs, saved recovery state or rewriting predecessors.

## Skills

- `skill://vulnops-advantage-vulnerability-writeup`
- `skill://vulnops-advantage-attack-path-analysis`
- `skill://vulnops-self-verification`
- `skill://vulnops-exclusion-rules`
- `skill://vulnops-severity-guidance`
