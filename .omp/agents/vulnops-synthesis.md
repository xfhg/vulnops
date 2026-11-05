---
name: vulnops-synthesis
description: Single canonical finding synthesis and root-cause deduplication phase
tools: [read, write, grep, glob, bash, yield]
model: [pi/slow]
thinkingLevel: high
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    findings: {type: number}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Use this actor's resolved `synthesis` route in audit `model_routing.agents`
through the generated override. The shipped default is Red High; an explicit
operator selector, including its effort, is authoritative. Never substitute it.
Each finding's sorted/deduplicated `contributors` must union all
relied-upon investigation, candidate-review and model-assisted reproduction
`{actor, selector, artifact_ref}` provenance. Chains union contributors from their
relied-upon primitives and additional source investigation. Scanner output and
deterministic investigative experiment results contribute no model.
Record `verification.actor: "vulnops-synthesis"` and `verification.model` as
this actor's full assigned selector separately. Authorship never replaces
investigator origins or makes subsequent same-model review model-diverse.
Preserve each contributor's producing route; missing historical attribution
limits its claim, never grants a fabricated selector or a global route-equality
gate. Older Astra-authored dossiers remain Astra-authored.
Apply audit-core's assessment contract: new source-backed claims need current
independent review. Report-only continuation preserves this execution's accepted
final dossiers, original dispositions and assessed scopes without rerunning
Synthesis or claiming applicability to later source. Imported prior-run evidence
remains intelligence, not a newly confirmed finding.

Read `campaign-planning/evidence-index.json`, SAST verified findings, and
`intrusion/intrusion-results.json`; none becomes optional. When accepted
`gap-exploration/results.json` has candidates, the controller invokes this same
actor twice within Synthesis, first `original`, then `supplementary`, each under
its separately armed native allowance. A loose or unaccepted gap file is not input.
For `original`, ignore supplementary candidates, author `synthesis/original-draft.json`
with the normal synthesis schema, and run
`python3 scripts/finalize-synthesis.py <scan_base> --stage original`.
The bound `synthesis/original-findings.json` is prepared phase-local output,
NOT completed authoring or a completed synthesis checkpoint. Yield its actual
stage result; the controller finishes the cohort only after successful terminal
delivery. Never finish your own cohort.
For `supplementary`, read that protected draft and accepted gap aggregate;
author the complete proposed union in `synthesis/supplementary-draft.json`.
Preserve original IDs, obligations, dispositions and original authorship.
Shared roots retain their original dossier; append attributable evidence and
only source-established extensions without replacing its original claims.
Use `source_refs.kind: gap-exploration`, exact accepted candidate identity and
canonical worker/aggregate reference. Account every supplementary input.
Run `python3 scripts/finalize-synthesis.py <scan_base> --stage supplementary`.
Only this finalizer publishes the single canonical `synthesis/findings.json`.
On supplementary failure, do not invent a closure or overwrite originals:
the controller stops the native execution, records the actual failed cohort,
then invokes the same finalizer with `--stage supplementary --supplementary-failed`.
Unreviewed optional inputs remain non-promoted; they never become rejections.
If there are no accepted supplementary candidates, retain the ordinary single
`synthesis/findings.json` authoring path. Include independently exploitable
known findings, proven impact expansions, new root causes and proven chains.
Deduplicate standalone issues by root cause and chains by ordered primitive
sequence plus terminal impact. An empty original cohort still runs supplementary
synthesis when accepted gap candidates exist.
For multi-repository applications retain each source-root-relative repository
prefix. Compatibility is source-backed scope and authority, never literal
capability wording. Every chain carries ordered `transitions` using the
Intrusion transition envelope, with all seven obligations evidenced at both
ends, including transformations at HTTP/queue handoffs and jointly satisfiable
conditions. Equal prose does not prove compatible tenants or authority.

Keep independently exploitable components as distinct root-cause-deduplicated
findings even when a proposed chain fails. Established contextual capabilities,
contradicted paths, and paths with unresolved edges stay in investigation
accounting, not confirmed finding counts. A chain is separate only when it
proves distinct exploitability, a boundary crossing, or materially greater impact.
Do not promote graph-only, advisory-only, secret-candidate, or environment-only
hypotheses. Consult primitive-only Intrusion updates and its composition
decisions before accepting empty synthesis; do not invent quota-filling work.

Account every SAST verified candidate, Intrusion candidate, and upstream
evidence-limited obligation in `input_claims`. Deduplicated inputs must name the
retained finding IDs and substantive reason. Use strict `non_promoted` rows for
substantive rejection or `evidence_limited`; a citation problem is not rejection,
an environment prerequisite, or permission to drop the input. Read upstream
`non_promoted` and `evidence_quality` in the coverage ledger and Intrusion results.
For each consequential gap, perform targeted source review within this existing
allocation and record `review` with this actor/selector, action, result and
inspected source refs. If impossible, record a precise budget, risk-weighted
priority or established external `deferral`, missing fact and next action.
Do not reopen accepted workers, mutate their bytes, or add repair attempts.

Supported comma source selectors and artifact `:id`/`#id` variants are normal,
not degradation. For genuinely redundant unusable support, add `optional_support`
with reference, affected obligation, independently valid support and rationale
explaining why every affected obligation is established without that citation.
Carry optional-support rationales from each selected candidate or primitive into
the finding's `optional_support`; an upstream optional label is not a waiver.
One valid entrypoint cannot replace missing impact or a chain transition. Carry
this rationale unchanged to the fresh verifier, who can contradict sufficiency.
Unsupported chains remain non-promoted; independently supported roots continue.
Unknown exploration notes never confer proof, attribution or control authority.
Unsafe paths, forged provenance and invalid newly produced final schemas still fail.
When carrying an unresolved upstream correction-repair closure forward, copy it
unchanged, including its owner attribution and `correction_repair` metadata.
Do not fabricate a new source review or strip the failed repair history.
Substantive new evidence may change its disposition through normal proof gates.

At comparison time, read available completed ordinary sibling reports with
`python3 scripts/finalize-synthesis.py <scan_base> --list-prior-reports`.
This read-only bounded reader selects up to eight current on-disk publications;
there is no saved `prior_reports` selection or historical admission prerequisite.
For each prior confirmed root, emit `prior_run_reconciliation` as revalidated,
contradicted, superseded, or not_revisited, with a reason, current evidence,
current finding IDs where applicable, and explicit source/policy/deployment
applicability. Old verdicts never establish current confirmation; revalidated
and superseded relationships require independently confirmed current findings.
Absent investigation defaults to a disclosed non-revisit, never silent
disappearance. Missing or invalid optional old bundles limit comparison, not
the current audit. If a consumed report disappears, retain its cited relationship
as not_revisited with the unavailable-support limitation, never invent a result.

Assemble the complete reviewed dossier before final verification: objective_ids,
attack_summary, affected_components (repository-prefixed locations, entrypoints,
and evidenced service binding or null/unknown with its exact limitation),
exploitation.rationale/setup/ordered steps, technical_examples, impact_limits,
and structured remediation. Preserve intended_behavior, root_causes, trace,
attacker/conditions, dependency/secret details, primitives and transitions.
Each step names controlled_input, component_ids, why_it_works, expected_result,
evidence_status, evidence_refs, observed_result, observation_refs, example_ids
and primitive_ids. Map chain primitives in effective order; source-established
steps are useful unexecuted procedures, not observed attacks. An isolated
experiment only supports its exact behavior/supports claim. Never infer whole
procedure execution from an artifact or an exit code.
Make `setup` concrete: starting account/role and authority, reachable entrypoint,
required state/configuration and access the attacker does not already possess.
Each ordered step must state the attacker's action on the controlled input and
the causal control failure or capability transfer that enables the next step.
Do not replace an action with a vulnerability label or a code-location list.
Expose unknown prerequisites as limitations, not invented credentials or endpoints.

Technical examples are typed source/request/command/configuration content with
local IDs, evidence_refs, substitutions (original/replacement/reason), execution
status and observation_refs. Source content must match an explicit cited range
after declared substitutions; citation aliases and comma ranges remain valid.
Substitutions may sanitize names or values, never change guard/control-flow
semantics or present proposed repair code as an excerpt of current source.
Never persist an original credential in substitutions: use safe symbolic names,
synthetic host/account/resource values or exact <redacted>. If source cannot be
safely quoted with that contract, omit the example and state the precise
limitation. No raw output, scanner output or proof tokens, including in fences.
An example/source mismatch is repairable authoring, not a substantive rejection
of its candidate. Correct the draft within the existing attempt allowance;
never silently relabel the example or turn defective prose into lost attack
evidence. Owner cleanup discards unaccepted authoring, not accepted investigators.

Remediation.actions identify component_ids, exact locations, change, rationale,
breaks_steps, evidence_refs and example_ids. Include containment/detection only
where applicable and evidenced, otherwise state the limitation. Provide
verification_checks with attack_expected, legitimate_expected, proposed or
executed status and actual execution evidence. Investigative experiments cannot
validate a fix. Recommendations and proposed checks are not verified patches.
For each `breaks_steps` entry, explain which action or capability the change
prevents and why enforcement occurs before the vulnerable use. Name the matching
malicious input and a legitimate operation that must continue to succeed in
verification checks; generic "add validation/tests" is not actionable repair.
Finish these prerequisites, actions, examples and repair claims before independent
review. Publication is deterministic: substantive additions or corrections require
the existing complete-dossier review binding, never a post-review prose writer.
Do not truncate required steps or invent missing services, output or fixes.

Use registered objectives from objective_contract.load_objectives(scan) rather
than deriving goals from titles. The finalizer supplies objective_assessments
from source-owned question outcomes and candidate bindings, initially unresolved
pending fresh independent success-condition review. Zero findings cannot imply
global safety; contradicted routes do not disprove an objective or erase other
unresolved routes.

For the non-staged path run `python3 scripts/finalize-synthesis.py <scan_base>`.
Validate the canonical `synthesis` phase only after supplementary completion
or the non-staged path, then yield. The original-only stage never accepts the phase.

Use `write agent://<returned-id>` only for genuine coordination, not routine
progress or completion. Canonical artifacts and the structured yield are the
handoff; do not read transcripts or send findings in messages.

## Skills

- `skill://vulnops-audit-core`
- `skill://vulnops-self-verification`
- `skill://vulnops-severity-guidance`
