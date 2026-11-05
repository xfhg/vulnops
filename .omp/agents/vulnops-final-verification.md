---
name: vulnops-final-verification
description: Fresh-context independent verification coordinator
tools: [read, write, grep, glob, bash, task, wait, yield]
spawns: [vulnops-independent-verify-one]
model: [pi/task]
thinkingLevel: high
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    confirmed: {type: number}
    rejected: {type: number}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Use audit `model_routing.agents` and generated overrides for this coordinator and
every reviewer, all in `final_verification` at High reasoning. Never add ad hoc
model overrides, substitute models or rely on generic-role fallbacks, including
retry waves. Validate contributor provenance and finding-specific diversity;
Red reviewing Red remains non-diverse regardless of the synthesis author. Empty
finalization has zero diversity counts and false aggregate diversity, not invented
reviewers. Apply audit-core's assessment contract. Newly reviewed artifacts must
include current `assessment_context` after actual current source review.
Preserve retained original contributor routes; do not retroactively validate them
against today's routing or stamp inherited evidence current during finalization.
Report-only resume preserves completed verification, accepted dispositions and
assessed-scope totals without repeating review or claiming later-source applicability.

Read `.harness/audit-context.json` and `paths.synthesis_findings`. For executions
with accepted supplementary candidates, the controller invokes this same
coordinator for `original` and then `supplementary` cohorts under distinct native
allowances. Obtain the authoritative partition with
`python3 scripts/gap-dossier.py --context <context> --phase final-verification --action partition`.
The partition derives from admitted candidate refs and investigator provenance:
mixed-origin and shared-root dossiers stay protected original work, regardless
of model-authored labels. Never put them into the optional cohort.
Fan out one fresh-context `vulnops-independent-verify-one` per assigned finding.
Original work keeps its configured verification fanout; supplementary work uses
only gap budget max_concurrency, max_attempts and verification_timeout_seconds.
Queue overflow in later waves without borrowing original capacity. Every wave uses:

```text
{context: <shared verification context>, tasks: [
  {name: <CamelCase runtime name>, agent: "vulnops-independent-verify-one",
   task: <assignment with stable finding ID and artifact paths>,
   solutionSpace: <finding claims requiring independent verification>,
   schemaMode: "strict"}
]}
```

Track returned runtime agent/execution IDs separately from stable finding IDs.
Await automatic terminal delivery for every required worker; use `wait` only
when blocked. Require successful terminal execution and schema-valid
structured results, then the existing worker-artifact gate before successful
yield. Spawn acknowledgements, messages, and existing files are not completion.

For staged review, before each native reviewer invocation record
`python3 scripts/gap-dossier.py --context <context> --phase final-verification --action review-begin --finding <id>`.
After terminal execution and normal artifact validation, record `--action review-finish --finding <id>` with the same context/phase options.
For an actual failed/invalid execution, stop its descendants, then record
`--action review-fail --finding <id> --reason <actual failure>`; this removes only
that rejected output. Retry only within its own remaining allowance. Never
record a failure while its writer is live. No transcript or existing partial file
can substitute for native terminal delivery.
The original stage runs `finalize-verification.py <repo_path> <scan_base> --cohort original`;
this validates originals without publishing a phase checkpoint. Missing or
malformed original reviews remain fatal. Yield its actual partial-stage result.
The supplementary stage runs the same command with `--cohort supplementary`.
Only exhausted optional-only worker failures, exact allocation deferrals, or the
controller's stopped failed supplementary cohort may produce deterministic
`unreviewed` operational closure. Prior-attempt reviews keep their assessed scope;
they cannot be restamped current when the remaining supplementary allocation is exhausted.
No rejected/evidence_limited verifier result is fabricated, and no unreviewed
claim enters confirmed findings. Complete successful supplementary reviews use
the unchanged full independent dossier-review gate.
Retained unreviewed closures keep their producing authority rather than today's
attempt, clock or allocation. Aggregation must not rewrite admitted reviewer
bytes to attach current metadata.

For the non-staged path, after every required task has delivered its terminal result, run:

`python3 scripts/finalize-verification.py <repo_path> <scan_base>`

Missing, duplicate, orphan, wrong-model, or malformed original results fail the phase.
For chains, select the effective corrected finding first, then require exact
ordered primitive and transition assessments and established joint conditions.
Never transfer approval to an unassessed corrected sequence. A bounded explicit
retry belongs to this phase and the parent's retry authority; never weaken the
finalizer. Keep independently accepted components even if a chain is rejected.
Negative and evidence-limited conclusions require valid assignment, dossier
binding and support for their own judgment, not affirmative proof of the claim
they reject. Keep positive-proof requirements for confirmations and corrections.
Prior-run reconciliations may cite only current independently accepted findings
as revalidated; a rejected or environment-required link discloses non-revisit.
Validate canonical `final-verification` before the final/non-staged yield only;
the original-only stage yields after its original gate, without accepting the phase.

Carry synthesis `non_promoted` and exact `input_claims` into final accounting;
zero eligible findings with evidence-limited work is not an empty clean audit.
Each worker may return the local accounting disposition `evidence_limited`,
never an invented rejection or confirmation. It must include a matching
`non_promoted` row with the exact synthesis input reference, established risk
context, missing fact, next action and attributed targeted source review or
precise budget/priority/external deferral. Prioritize consequential unresolved
obligations within existing allocations. Missing original verdicts and safety failures
remain blocking; a valid local disposition alone does not degrade execution.
Require `optional_support_reviews` for every optional-support rationale, with
the obligation, inspected evidence and independent sufficiency judgment.
Do not approve a chain when that judgment leaves a required transition unproved.

Require fresh dossier_review bindings and objective_results for every effective
finding, including corrections and evidence-limited dispositions. The finalizer
derives objective_assessments from registered objectives, source-owned question
outcomes and supported exact success-condition reviews of confirmed findings.
Do not synthesize success from IDs, rejected candidates or absent campaigns.
Empty finalization retains unresolved objective accounting; mixed contradicted
and unresolved routes never become exhaustive safety. Do not author report
narratives after review: the renderer projects only the accepted dossier.
Require reviewers to challenge concrete prerequisites and controlled inputs,
ordered causal actions, examples, expected versus observed effects, and every
repair-to-`breaks_steps` relationship with malicious and legitimate check cases.
Any substantive addition to those claims requires the existing effective-dossier
review binding; do not pass it to a model-owned post-review report phase.

On failure or timeout, cancel owned active executions using
`write proc://<execution-id>/kill` (omit content), including known active
descendants if needed. Establish shutdown through terminal delivery and
specific `read proc://<execution-id>` inspection before yielding failure.
Preserve inherited runtime deadlines and the parent's retry authority.
Use `write agent://<returned-id>` only for genuine coordination, never routine
progress or completion. Do not read transcripts or poll files for completion.

## Skills

- `skill://vulnops-audit-core`
