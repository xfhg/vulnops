---
name: vulnops-advantage-security-scan
description: Coordinate one native baseline-informed Advantage investigation pass with bounded objective questions and canonical result accounting.
---

# Advantage Security Scan

Read the [Advantage execution context](references/advantage-context.md) first.
The native linked lifecycle is the sole execution authority.

## Invocation and ownership

For an explicit standard scan request, use **Shared top-level entry** in
`references/advantage-context.md`; inside OMP the controller selects
`python3 scripts/init-advantage.py --in-session [<completed-audit-path-or-run-id>] --mode standard`.
Preserve explicit depth; omitted depth is full. Standard must be explicit;
unqualified Advantage defaults to deep. Every request starts fresh. Terminal
startup is documented only in that shared entry contract.
Inside an initialized execution, `vulnops-advantage-investigation` consumes the
accepted plan and initial packets. It never initializes a new execution or invokes
a launcher. Standard means one informed pass, not another uninformed audit and
not fourteen mandatory skill phases. The main controller owns top-level phase
state and deadlines; assigned workers perform only their packet.

Inputs are bound context, the complete available baseline catalog/report records, canonical
plan, immutable wave/packets, current source, and explicit optional-action
selection. Workers retain full catalog access beyond their compact packets.
Baseline findings, scanner leads, deferred claims, and rejections keep their
original statuses. Read-only source inspection is authorized; target execution
requires the distinct contained experiment path in the shared reference.

## One pass, concrete questions

1. Read every planned assignment and its exact success condition. Ensure each
   has an initial attacker, controlled material, absent privileges, inherited
   evidence, closest control, expected capability gain, proof obligation, and
   stop condition. Do not silently replace a difficult seeded root with an
   easier neighboring weakness.
2. Dispatch canonical native `vulnops-advantage-investigator` owners using immutable
   waves/packets and current-invocation task coordination, never a dispatch ledger.
   Preserve current consumption and allocation deferrals. Partition questions, not arbitrary file
   counts. Choose forward input-to-sink, backward consumer-to-source,
   authorization/state-machine, or open-ended perspectives to fit real work.
   Respect `budget.max_concurrency` and global task/question allocations.
3. Workers use finding-discovery, validation, and attack-path-analysis as
   reasoning within their single assignment. No nested scan, extra phase pool,
   independent ledger, or unregistered worker is permitted. Continue source
   inspection of assigned sibling operations after one candidate is found.
4. Receive terminal structured yields and validate the corresponding packet-bound
   results before consolidation or reuse. File existence, peer messages, and
   spawn acknowledgement are not completion. Preserve precise counterevidence,
   failed paths, useful primitive-only results, and every unresolved question.
   Apply the shared attack-progress/failure-boundary rules: discard unusable
   publication as evidence and continue healthy work through reporting. Missing
   proof is `locally_unresolved`; only actual failed/cancelled native work supports
   `execution_failed`. Preserve admitted peers without mandatory retry, exhaustion
   proof or bookkeeping reconciliation; never fabricate empty success.
5. Admit a continuation only through `build-advantage-wave.py` after a validated
   predecessor: specify the evidence delta or newly actionable alternative,
   next missing fact, and remaining global reserve. Never retry an external
   blocker as more local searching or change identities to evade live controls.
6. Finish with `finalize-advantage-investigation.py --context <context>`.
   Empty valid work still receives canonical terminal accounting. Synthesis and
   fresh final verification happen once afterward; this coordinator does not
   publish a finding or author the final report.

## Evidence and coverage

Inspect actual guards, fallback/error branches, parsers, stored-state consumers,
protocol boundaries, and affected callers. A public library input can establish
a caller boundary without fabricated internet deployment. Cross-repository
chains require actual handoff evidence. Search hits and architecture mapping are
not full file review; pass agreement is not independent proof of a shared
baseline assumption. Do not repeat dependency/secret scanners: consume their
bound records and investigate only the material additional obligation.

Output remains `investigation/results.json` projected from the exact native
worker results, with source-only versus contained observations explicit. Report
budget deferral, local uncertainty, external prerequisites, and execution failure
separately. Zero new findings never means complete security assurance. Optional
patch assessments retain their separate action records; unrequested actions are
not performed. Actions-only execution does not invoke this skill.
