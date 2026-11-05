# Evidence-Backed Hardening Analysis

Use this method when the selected hardening action diagnoses accepted attack
transitions or compares defensive designs. The entry skill owns selected inputs,
phase authority and native action output. This guidance creates no portfolio,
implementation directory, new evidence registry or permission to modify source.

## Diagnose before choosing components

Read the actual accepted dossiers, their transitions and limits, available
evidence closures and decisive source consumers. A captured snippet is a lead,
not a complete architecture argument. Preserve the shared historical/current
assessment contract and exact selected inputs without adding historical
hash/equality gates. Separate observed or source-established facts, inferred
structural conditions and proposed behavior; an attractive design does not prove
that its predicted properties exist today.

Cluster evidence by violated invariant, control owner, dangerous capability,
trust boundary or repeated state transition, not simply CWE, severity, directory
or title. Qualify opportunities where evidence demonstrates dispersed or
inconsistently owned enforcement, repeated tactical controls, a convention-only
invariant, or a consequential shared capability with credible recurrence or
blast-radius risk. Overprivilege or weak isolation must relate to an accepted
transition, not generic best practice or an unrelated cleanup idea.

Develop a small number of high-leverage choices. Independent local bugs may need
local remediation rather than architecture. Explain that conclusion honestly
through the entry skill's no-opportunity disposition; missing necessary support
instead requires unresolved accounting. Do not fabricate a proposal to fill an
action record or reopen discovery to justify one.

Trace current attacker inputs, authority/data/state and lifetime flow,
enforcement owners, deployment boundaries, recovery, performance-critical or
allocation-sensitive paths, compatibility and operational dependencies. Explain
how the current structure enables the observed transition. Give execution-scoped
finding IDs a meaningful title and what each establishes wherever used; opaque
IDs alone do not teach the reader the diagnosis.

State falsifiable invariants before choosing components. For example, the final
resolved resource and acting identity must be authorized together before any
side effect. Define non-goals, compatibility and rollout obligations, constraints
and unknown performance/resource budgets. Do not invent measurements or infer
user priorities that were not supplied.

## Compare real choices

Include proportionate tactical repair as a baseline. Develop only genuinely
different alternatives justified by the failure, such as shared guards, an owned
safe API or representation, scoped handles/capabilities, process or privilege
isolation, or a state machine making invalid transitions unrepresentable. Do not
force a fixed number, rename the same design as several options, or present
rollout steps as alternative architectures.

Give every serious option its strongest case in connected prose: what remains
familiar, what changes, where control moves, why that interrupts the attack,
which capability remains, what new trusted component appears and how adoption
could be reversed. Explain useful rejected alternatives rather than hiding them.
Use comparable before/after descriptions at the same abstraction level when
helpful; preserve component names, trust boundaries and meaningful authority
edges. Never invent a current service, sandbox or process to improve a diagram,
or introduce extra diagram files outside the native action contract.

Map each option to the exact selected attack transitions it addresses, mitigates,
leaves unchanged or cannot yet resolve. Explain those effects with evidence,
residual risks, and whether tactical patches remain necessary during and after
migration. A design that blocks a trigger but preserves the dangerous capability
elsewhere may mitigate rather than eliminate the transition.

## Explain tradeoffs, not scores

For each option cover the material dimensions below, including honest neutrality
or uncertainty rather than omitting an inconvenient cost:

- **Security:** removed or narrowed attack paths, remaining authority and new
  trusted components; whether enforcement can drift again.
- **Performance/latency:** additional hops, copies, serialization, locks, cache
  misses or work on the critical path.
- **Memory/resources:** new buffers, indexes, processes, queues, caches,
  allocations or retained objects, and when their cost is incurred.
- **Reliability/availability:** failure containment, retries, backpressure,
  recovery and introduced shared failure points.
- **Operations:** deployment, observability and incident-response burden, plus
  ownership and developer ergonomics that affect future control drift.
- **Compatibility/migration:** API, protocol, data and cross-version behavior,
  staged rollout, persistent state and rollback/reversibility.

Explain the mechanism, expected direction, confidence and evidentiary basis of
each important tradeoff in the existing `tradeoffs` and proposal prose. Use
measured claims only for actual admitted measurements; distinguish source-derived,
analogous and hypothetical reasoning. Never invent composite scores, benchmark
percentages, savings or precise budgets. For unmeasured effects, propose a
workload, metric, baseline, candidate comparison and decision criterion; identify
a threshold as proposed or still to be agreed, not an observed product constraint.

Give a conditional recommendation in `rationale`, with the evidence, priority or
constraint that would make another option preferable. Explain the appealing part
and principal concern of each serious alternative without salesmanship. A new
reader must be able to challenge the inference from evidence to diagnosis to
recommendation; labels and comparison tables cannot replace that reasoning.
Use truthful statements about inspected source or unavailable measurements, not
first-person decoration or repeated stock prose.

## Preserve legitimate behavior and a reversible path

Describe staged adoption, tactical protections during migration, safety checks,
legitimate operations that must remain supported, rollback and falsifiable
acceptance/measurement work. Name the malicious behavior to reject and the
normal behavior to preserve at the same boundary and abstraction level. A plan
to deny every request does not satisfy an invariant that must support authorized
use. Performance improvements are proposals until measured; a proposed repair
is not implemented, verified or a reason to close a finding.

For example, for accepted archive destination escapes, compare local guards
with an owned extraction API that derives and checks each final destination
before materialization. The malicious control rejects escaping members before
writes; legitimate nested relative entries still extract into the caller's
output root. Consider link behavior, partial-failure cleanup and compatibility
rather than assuming a lexical guard alone suffices. Explain whether migration
leaves unconverted callers vulnerable and keeps their tactical protections.
Do not execute either control or implement either option as part of analysis.

Keep this work in the native `hardening` action record, using its proposal,
rationale, invariant, assumptions, tradeoffs and citations rather than a second
report hierarchy. Implementation requires separately authorized work and Blue
production-patch authority. Material unknowns remain explicit; independently
supported proposals may proceed without inventing a recommendation for another
unresolved opportunity.
