---
name: vulnops-audit-core
description: VulnOps attacker-led hunting, impact, evidence, and adversarial-validation doctrine
---

# VulnOps Audit Core

Hunt for exploitable behavior, not checklist deviations. Every candidate must
name a real attacker, their starting access, the trust boundary crossed, exact
input or action sequence, reachable code path, mitigation review, observable
result, and material impact.

## New assessment and accepted publication

Use current source and the current attempt's assigned routing for new work.
Admission still requires the exact assigned owner, execution/attempt, source view
and model. Retained/legacy artifacts keep their original source refs, dispositions
and producing contributor routes; never re-resolve saved actors through today's
group mapping or relabel them during aggregation. Paths or matching line numbers
do not establish current applicability. New source-backed claims require actual
control-flow review and independent verification, not old acceptance alone.

Newly reviewed investigation and verification artifacts require
`assessment_context: {attempt_id: context.attempt_id}` only after actual current
source review. Use the shared assessment reference for newly produced records;
preserve its assessment scope and original producing attempt. Never backfill
accepted evidence or add assessment fields to unrelated terminal yield envelopes.
Experiments bind the current request `attempt_id`; only actual current contained
execution supports a new claim of observed behavior. Retained observations keep
their original scope; disabled execution or setup failure cannot establish one.

Report-only continuation projects this execution's accepted final-verification
set, not the publishing attempt's activity. Preserve all effective dossiers and
their dispositions, severity, reviewer, contributors and objective conclusions.
Confirmed assessed-scope totals do not disappear on restart; environment-required,
rejected and evidence-limited outcomes remain distinct, never promoted by copying.
Imported prior-run/baseline intelligence does not enter a new execution's confirmed
set without its own supported review. A publication date or route change does not
establish applicability to later source.

Keep `report.assessment` scope metadata separate from immutable dossier content;
`outcome_assessment` describes outcome status. Disclose mixed or unknown recorded
scope without filling gaps from today's checkout. Publication checks accepted
authority and complete effective-dossier/review bindings, not today's source,
historical group equality or disposed workspace availability. Missing essential
final/review authority blocks publication precisely; optional support defects stay
attributed limitations. Never rerun accepted phases merely to publish them.

Synthesis authors concrete prerequisites, controlled inputs, causal attack actions,
faithful examples and repairs linked to steps before independent verification.
Review covers those claims and both malicious and legitimate repair-check cases.
Deterministic publication may format and link accepted content but cannot add
post-review facts or silently clip it. Substantive corrections require the existing
complete-dossier review binding; completed reports and their authorship remain
immutable. Same-model fresh-context review never implies model diversity.

Accepted checkpoints and safely accepted partial owner results/accounting survive
resume; files without accepted completion are not success. Current allocations
govern future dispatch without erasing consumed work. Never restore lifecycle
hashes, directory seals, historical source/routing equality, compatibility IDs or
whole-history replay. Local packet/dossier/scanner/download/patch integrity,
current output validation, ownership, safe paths and containment remain required.

## Hunting method

When defining or challenging architecture, attacker objectives or investigation
questions, read [source-backed threat modeling](references/threat-modeling.md).
Use the assigning phase's existing model and question records.

- Follow data through entry, validation, transformation, storage, retrieval,
  and sink. Read error, fallback, retry, cleanup, timeout, and recovery paths.
- Probe empty, missing, maximum, negative, boundary-time, encoding, parser,
  serialization, and round-trip behavior.
- Compare parallel paths to the same action. Check operation reordering,
  replay, concurrent requests, check-then-act gaps, and security defaults.
- Start from privileged capabilities and work backward to who can reach them.
  Treat model, parser, cache, proxy, database, plugin, and worker outputs as
  untrusted at the next boundary.
- Record unexpected adjacent leads as bounded rabbit holes for the lead.

## Graph investigation

Codegraph is optional. Use good results to improve source review, not as a gate.
Missing tools, failed indexing/queries and unhelpful results require an honest
limitation and source-only continuation, never mandatory graph work.
Current graph preparation is disposable navigation outside the target. Use current
request/owner receipts plus inspected current source, not index/snapshot hashes
or historical cache survival as admission authority. Old graph receipts remain
historical records and cannot establish current vulnerability behavior.

- Start from a concrete entrypoint, sensitive behavior or capability consumer.
  Use `query` to discover symbols, `callers` backward from a sensitive function,
  `callees` forward from an entrypoint, and `impact` for dependent consumers.
  Reserve `affected` for explicit test-impact questions, not reachability.
- Resolve ambiguity with the full repository-prefixed file and indexed symbol.
  Keep stable IDs and qualified names distinct from short display names.
- Read normalized context and its completeness limits. Search matches are not
  call edges. Empty, heuristic, unknown-completeness and truncated results do
  not establish the absence of an attacker path.
- Inspect relevant returned source locations, arguments, guards and alternate
  entry/fallback paths. Record what source supports or contradicts the question,
  the locations inspected and what changed in the campaign conclusion.
- Explain each graph result actually relied upon as supported, contradicted or
  inconclusive. Source is required for support/contradiction. Skipped or failed
  optional queries need only a limitation; do not fabricate receipts or answers.
- For inter-service leads, match source/configuration contracts: route/method
  and endpoint, topic and broker, or storage namespace/key and deployment
  binding. Similar names alone and missing static edges prove neither a
  handoff nor its absence. A graph relationship never promotes evidence trust.

## Evidence gate

- Another layer that fully prevents exploitation converts the issue to a
  hardening note.
- Operator-equivalent behavior, test-only code, ordinary errors, unproven
  deployment assumptions, and parser/runtime guesses are not findings.
- Severity combines likelihood and concrete impact. If damage cannot be
  stated, lower the severity or reject the candidate.
- Report positive security patterns and defenses that survived review.
- Dependency enumeration belongs to SCA and secret enumeration to Secrets.
  Hunters consume those results and do not repeat their scans.
- Target source is read-only. Dynamic evidence may only use the configured
  safe-reproduction wrapper and a disposable workspace.
