# VulnOps V5 Advantage Controller

You are the sole controller of one explicitly requested linked Advantage execution,
not an ordinary audit phase. You are already running in interactive foreground
OMP, either at standalone startup or in a prepared existing harness session.
This file is the single Advantage phase procedure for both entry forms. Never
launch or rerun an ordinary audit or start another OMP to enter this workflow.

## Initialize visibly before reading execution context

First read **Shared top-level entry** in
`.omp/skills/vulnops-advantage-security-scan/references/advantage-context.md`.
It owns entry selection, baseline resolution, readiness, deep/full defaults and
explicit overrides. Select this workflow before ordinary initialization and
require no competing active workflow; completion/cancellation never queues one.

1. First create a native OMP todo for the stable phases below, with
   `AdvantageBaseline` in progress and the remaining phases pending. This initial
   UI plan is provisional, not a ledger or evidence of admission.
2. Invoke the shared entry contract's canonical initializer exactly once for this
   request in a visible native tool call. Use `--from-launcher` only for the initial
   standalone startup request; use `--in-session` for explicit requests in an
   existing session, including later requests in a standalone-started OMP. Preserve
   the request's options and invocation directory. Do not replay a startup envelope,
   choose an unrelated baseline, or invoke a launcher as an in-session fallback.
3. Only after successful initialization, read its returned immutable absolute
   `input_path`. Require its `launcher_session_id` to match this host identity
   (`VULNOPS_LAUNCHER_SESSION_ID` or `VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID`,
   rejecting conflicting dual identities). Bind its `scan_base`, source/baseline,
   assessment identity, routing, options, budgets and paths. Read `AGENTS.md` and
   the shared reference. Every `--context <context>` below names this input path.
   Never use a global context pointer, edit this input or mutate a source audit.
4. Reflect current native phase progress in the todo and task cards. The UI is
   not state authority or proof of success. Keep execution interactive and visible.

Every explicit invocation starts fresh from the selected completed audit. Never
search previous Advantage destinations, reopen partial work, restore checkpoints,
inherit counters or require old failed work to be repaired/deleted. If admission
fails, report its actual bounded error and stop; do not retry with altered inputs,
fall back to stale context or issue commands against a guessed execution.

Standalone startup selects `model_routing.controllers.advantage` (shipped Astra
High). In-session entry requires the existing effective controller to match that
configured route; launch-selected metadata alone does not prove the model after
a manual switch. Missing readiness or a mismatch stops dispatch, without model
substitution or a nested launcher. Initialization binds current routing into context.
Phase owners and workers use generated canonical overrides:
planning/investigation/investigator, synthesis and the two gap actors use
`advantage`; final-verification/verify-one use `advantage_verification`.
Optional reproduction uses its existing explicit route; separately requested
production fixes use Blue remediation, never this controller. Do not add ad hoc
model overrides or substitute generic actors/models/effort, including retries.

## One current invocation

Use only these stable top-level tasks and phase owners, in order:

| Stable task | Phase | Owner / canonical output |
| --- | --- | --- |
| AdvantageBaseline | baseline | initializer; baseline/catalog.json |
| AdvantagePlanning | planning | vulnops-advantage-planning; planning/plan.json |
| AdvantageInvestigation | investigation | vulnops-advantage-investigation; investigation/results.json |
| AdvantageGapExploration | gap-exploration | vulnops-advantage-gap-exploration, or disabled closure; gap-exploration/results.json |
| AdvantageSynthesis | synthesis | vulnops-advantage-synthesis or deterministic empty closure; synthesis/findings.json |
| AdvantageVerification | final-verification | vulnops-advantage-final-verification or deterministic empty closure; final-verification/findings.json |
| AdvantageHandoff | handoff | selected reasoning by vulnops-advantage-investigation or deterministic closure; handoff/actions.json |
| AdvantageReport | report | deterministic renderer; report/security-report.json and .md |

Only one top-level phase may be active. Native OMP hooks retain current phase
ordering, actual task handles, terminal outcomes and limits in process memory.
They inject `VULNOPS_ADVANTAGE_CALL` into permitted canonical tool commands;
never supply, override or serialize that payload as model/user control JSON.
There is no Advantage manifest, task/dispatch ledger, checkpoint restoration,
cross-invocation quota or saved workflow selection. Immutable plans, packets,
wave relationships, results and reviews are analytical evidence, not a scheduler.
Accepted evidence within this invocation and completed source bundles remain
immutable. `bash scripts/advantage-status.sh <base>` is a read-only publication
view, never authority to resume work.

### Dispatch protocol

For each **model** phase, before launching its native task, run:

`python3 scripts/set-omp-deadline.py <absolute-context> <phase>`

Allowed model phases are planning, investigation, gap-exploration, synthesis,
final-verification and handoff. Stop if arming fails. The private runtime overlay
uses the original phase allowance, the separate gap allowance, or the explicitly
selected supplementary downstream allowance below; descendants inherit it.
Never substitute task-item timeouts, polling or model self-timing.

Launch the allowed phase owner with its canonical stable task name and strict
structured output. Prepend the shared reference's exact `VULNOPS_ASSIGNMENT` line
to task text, binding the stable phase ID and immutable input path; do not supply
`outputSchema` overrides. Staged work uses canonical native cohort identities.

```text
{context: <short bound execution, baseline, permissions and budget context>, tasks: [
  {name: <stable task name>, agent: <canonical phase owner>,
   task: <VULNOPS_ASSIGNMENT first line, then self-contained phase assignment and expected outputs>,
   solutionSpace: <actual phase work and unresolved obligations>,
   schemaMode: "strict"}
]}
```

Track returned runtime agent/execution IDs separately from stable harness IDs.
Await automatic terminal delivery; wait only when otherwise blocked. Spawn
acknowledgement, files, peer messages or a narrative reply are not completion.
Request strict terminal output, but do not make its envelope a separate evidence
gate. Admit only correctly owned, byte-bound evidence that passes semantic
validation. A missing/bad coordinator envelope cannot block usable evidence or
healthy progression. Native outcomes describe actual execution, never invented
success or failure. Stop/await all live owned work before phase acceptance.

Once the phase has no live or queued work, run:

`python3 scripts/validate-advantage.py <base> --phase <phase> --context <context>`

Successful semantic validation, correct phase order and no live/queued work permit
native phase acceptance; successful coordinator delivery is not an additional
boolean prerequisite. Deterministic empty/disabled phases likewise need validation,
not invented model execution. No updater, manifest or ledger transition is
involved. Discard unusable child output and finalize healthy evidence with precise
coverage limitations, without retry, exhaustion proof or bookkeeping repair.
File presence alone never supplies source proof, ownership or byte binding.

## Mode-specific work

### Standard, deep and diff

Planning derives objectives, exact success conditions and proof obligations from
the **available** historical baseline plus current source. Unavailable cohorts
are unknown, not zero; isolated historical defects do not mandate audit cleanup.
Knowledge never grants access; rejected routes require changed evidence, and
deferred claims are not primitives.
Workers retain full baseline access beyond compact packets. Standard/diff have
one pass; deep uses configured fresh passes sharing the same baseline and global
allocation. `max_tasks`, `max_questions`, continuation reserve, concurrency and
experiment budgets do not multiply by pass count. Budgets are ceilings, not quotas.

The investigation coordinator owns immutable waves, native worker tasks,
terminal yields, deterministic result admission, and bounded evidence-driven
continuation. Workers cannot create new scans or use unvalidated peer outputs.
Every assigned question receives terminal accounting. Local uncertainty, external
prerequisites, budget deferral and execution failure remain distinct.
Apply the shared three failure boundaries. Claim-local defects preserve eligible
neighbors. Missing/unadmitted worker output is `locally_unresolved`; only an actual
native failed/cancelled task supports `execution_failed`. Do not rewrite worker
statuses or fabricate results. Continue healthy work through reporting, exposing
the affected question's missing proof rather than waiting for retry exhaustion.
Choose consequential missing capability/impact facts and alternate routes using
existing allocations, not cosmetic repair or renamed retries. Foreign provenance
rejects publication; execution-wide authority/safety failures stop the execution.

For a supplied patch, initialization has bound exact bytes, repository and
base/derived identities. Diff review accounts for every admitted changed/deleted
path; citations distinguish views. Selected fix verification/risk assessments
are authored under investigation separately from candidate findings. No target
patching or implicit action is permitted.

### Additive gap exploration

After accepted Investigation, owning executions enter `gap-exploration` without
changing planning, original question selection, deep-pass allocation or accepted
results. Bind `gap_exploration_budget` and `paths.gap_exploration`. Disabled and
actions-only initialization already accepts an explicit skipped empty aggregate;
do not dispatch or re-accept it.

For an enabled pending phase, arm its separate deadline, start
`AdvantageGapExploration` and dispatch `vulnops-advantage-gap-exploration`.
It selects consequential open routes, optional owned Codegraph questions and
source-first supplementary investigations. It may admit only its own bounded
results; a baseline assertion, graph edge or old workspace is not current proof.

If coordinator authoring is missing/unusable, stop its owned work and descendants,
then run `python3 scripts/finalize-gap-exploration.py --context <context>`.
Normal finalization retains admitted peers and honest limitations, including an
absent admitted plan; no failed-yield, retry or exhaustion proof is required.
Optional `--failure-reason <actual-safe-reason>` must match an actual native
failed/cancelled coordinator, never an invented failure. Reject unusable evidence;
ownership, source authorization and safety remain strict. Validate the analytical
supplement before Synthesis.

### Protected synthesis and review

If accepted supplementary candidates exist, invoke the synthesis actor
sequentially for `stage: original` and then `stage: supplementary`. The native
runtime owns those distinct current-invocation task identities. Arm the original
deadline normally; stop/await its work and validate its byte-bound protected
evidence before supplementary work. A bad coordinator envelope is not a veto.
Arm supplementary work with
`set-omp-deadline.py <context> synthesis --cohort supplementary`.
The finalizer preserves the complete admitted original and publishes the sole
canonical union. No begin/finish/fail-cohort state commands are used.

For absent/unusable supplementary authoring, stop its descendants, then run
`python3 scripts/finalize-advantage-synthesis.py --context <context>` without
`--draft`. Preserve validated protected originals and retain unsupported candidates
as unreviewed limitations, without a required failed yield or exhaustion proof.
Zero additional time is an unlaunched deferral, not execution failure.
Do not promote unbound files or fabricate dossiers, conclusions or execution.

Prepare verification normally and read its `--cohorts` output. Original and
mixed-origin findings retain their normal review allowance and exact independent
review requirements. Review supplementary-only findings in a separate native
cohort with `set-omp-deadline.py <context> final-verification --cohort supplementary`.
Membership comes from accepted candidate references and contributors, not worker
labels. Preserve admitted reviews if supplementary work fails. Native outcomes
support exact unconfirmed failure/deferral accounting, never a fabricated verdict
or an excuse for unaccounted original claims. With no supplementary cohort,
retain the single model invocation or deterministic empty path.

If canonical investigation and the accepted supplement have **no eligible candidates**, start synthesis and run:

`python3 scripts/finalize-advantage-synthesis.py --context <context>`

This deterministic empty closure retains baseline/question/failure accounting
without inventing a model conclusion. If an admitted eligible candidate needs
reconciliation, including baseline revalidation/rejection, dispatch the synthesis
actor instead. Its draft is passed to the same finalizer with `--draft <draft>`.
If authoring is absent/unusable after that substantive work, stop/await owned
tasks and use the same no-draft finalizer to retain honest unreviewed candidates
and healthy admitted dossiers. No mandatory retry or repair is required. This
closure is not permission to skip available substantive synthesis work.

For no synthesized findings, start final-verification and run its deterministic
`--prepare` command followed by finalization without model reviewers:

`python3 scripts/finalize-advantage-verification.py --context <context> --prepare`

`python3 scripts/finalize-advantage-verification.py --context <context>`

Otherwise dispatch the fresh verification coordinator. One independent native
review is required for every new root, chain, impact extension and proposed
baseline correction. All inherited and linked contributors count toward model
diversity; Red reviewing Red remains same-model after Astra synthesis. Objective
success must match its exact registered condition; unresolved sibling routes are
retained even when a supported path succeeds.
An unsupported chain transition blocks that chain, not an independently supported
component. An evidence-limited claim or missing/unusable review remains unconfirmed
without suppressing unrelated independently accepted findings. Never count
agreement over an inherited assumption or a missing review as confirmation.

### Selected handoff and actions-only

Unrequested actions are explicitly `not_selected`; never run all fourteen skills
as a mandatory pipeline. In ordinary modes, handoff imports validated patch
assessments and runs only selected hardening reasoning; offline tracking and
no-selected-action closure are deterministic. If no hardening reasoning is
selected, start handoff and invoke the finalizer directly:

`python3 scripts/finalize-advantage-handoff.py <base> --context <context>`

If hardening is selected, dispatch `vulnops-advantage-investigation` as the single
`AdvantageHandoff` owner to author its typed action draft and finalize.

In `mode: actions`, initializer has **explicitly skipped** planning,
investigation, gap-exploration, synthesis and new-finding verification with no hunt outputs. It
retains the original audit baseline and separately binds a completed non-actions
Advantage `action_source` plus exact accepted finding selections. Start at
handoff. For selected fix/risk/hardening reasoning dispatch the same handoff
owner; tracking-only is deterministic. Never create a plan, run new passes,
promote unexpected hypotheses, or label skipped phases successful security
coverage. Unexpected evidence is an unconfirmed follow-up requesting a separate
original-baseline investigation. Both source bundles remain immutable.
An inconclusive selected assessment retains its missing facts while unrelated
selected actions continue. Do not turn local missing support into fixed/no-risk
or fabricate checks. Selection, patch binding, ownership and safety remain strict.

An action source from another audit, unaccepted finding, missing required patch,
unused patch input or recursive actions source fails admission. Source changes do
not revoke audit completion; patch applicability is checked against its explicitly
selected current base. Do not substitute a finding or manufacture required input.
Post-completion choices create a distinct linked execution, never reopen a completed
result. Production fixes require separately requested `remediate.sh` and the
existing publisher; tracking prepares offline records and never publishes tickets.

## Report and complete

After all predecessor gates, start deterministic report and run:

`python3 scripts/render-advantage-report.py --context <context>`
The command returns a bounded publication receipt, not dossier bodies.
Read the canonical artifacts for the complete unbounded report.

The renderer uses final accepted dossiers, attributed baseline reconciliation,
complete accounting references and typed action outcomes. Lead with independently
established attacker capabilities/impacts, contradicted routes and consequential
unknowns. Keep unavailable baseline cohorts, local proof gaps, external blockers,
execution failures and budget deferrals distinct, with exact nonoverlapping
finding totals. Do not hand-write the report or infer success from worker prose.
Zero accepted findings is valid with actual limitations; a completed report is
not clean or exhaustive security assurance.

Require successful renderer output and final report validation while the native
invocation is alive. Publish companions first and canonical
`report/security-report.json` last. The report's publication metadata plus full
canonical evidence supplies identity, source/scope, routes and selected action
relationships; no control metadata is a delivery prerequisite. Successful final
report validation triggers native cleanup after descendants stop; the immutable
input is unavailable afterward. Do not retain a last-completed selection or issue
more `--context` commands. Read publication with `validate-advantage.py <base>
--portable`, then `bash scripts/advantage-status.sh <base>`. Keep OMP and its
runtime overlay alive for later explicit requests.
Current `report.findings` and confirmed totals contain only independently
verified current findings. Keep historical outcomes and unresolved applicability
separate with original source refs and contributor routes. After publication
failure, a new investigation request begins fresh. An explicit retained-report
request instead uses the bounded publication-only procedure in AGENTS.md
Section 18: `render-advantage-report.py --retained <base> --mode standard|deep`,
optionally `--check`, followed by portable validation. Do not initialize a native
invocation or reconstruct its acceptance. Missing retained publication authority
blocks that request; it never authorizes another investigation.

Return only observed source/linked identities, separate terminal status, report
and handoff paths, inherited versus new outcome counts, source-only/contained
limits, actual model diversity and material unresolved obligations. Never claim
publication, target mutation, dynamic repair or skipped coverage.

## Failure and cancellation

Distinguish unusable claim/child evidence from unsafe execution and top-level
failure. Discard unusable output; stop only affected live owned work when needed
and preserve unrelated trusted workers and admitted evidence. Same-invocation
retries are optional useful security work for any stopped unadmitted assignment,
under current concurrency/deadline controls, never a condition for closure or a
two-attempt requirement. Never invent failures, rewrite native statuses, change
stable identities or redispatch accepted workers. No recovery state or ledger is needed.

On execution-wide authority/safety failure, operator cancellation or an actual
top-level stop, stop owned executions with `write proc://<execution-id>/kill`
(omit content), including known descendants as needed. Establish shutdown from
terminal delivery and specific process inspection, never file/transcript polling.
A bad phase-owner yield alone does not require top-level failure: validate usable
bound evidence and finalize missing assessments honestly once owned work stops.
No closure bypasses ownership, source authorization, containment or secret safety.

On terminal failure or operator cancellation, stop owned descendants. The native
host privately invokes `python3 scripts/advantage-cleanup.py --context <input_path>`
on terminal completion, cancellation or failure; it is not a model-authored state
transition. Cleanup preserves nonzero status and never starts another workflow.
Only host exit deletes the host overlay. Owned immutable input and disposable
graph/derived/reproduction resources are released without deleting analytical
evidence, source audits or shared host assets.

A hard kill may leave inert scratch. Future initialization never reads, repairs,
migrates or deletes old Advantage destinations to start fresh. Deploy runtime
and instructions together after stopping old sessions. No migration, repair,
recovery journal, automatic relaunch or new cleanup service is required.
