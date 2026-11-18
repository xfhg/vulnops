# VulnOps architecture

VulnOps traces attacker-controlled input through security decisions to a concrete
sensitive effect. Models investigate and review; deterministic tools allocate work,
admit evidence and publish accepted conclusions.

This document explains the boundaries between those responsibilities.
[README.md](README.md) covers setup and entrypoints; [WORKFLOWS.md](WORKFLOWS.md)
compares the workflows; [AGENTS.md](AGENTS.md) owns execution procedures, commands,
retry rules and phase budgets. [config.toml.example](config.toml.example) owns the
configuration reference.

## Evidence model

| Concept | Meaning |
|---|---|
| Objective | An actor's desired effect and exact success condition. |
| Question | A specific route or proof obligation needed to assess that objective. |
| Observation | A source, scanner or experiment result whose security implications still need investigation. |
| Capability | An operation the actor can perform over a defined resource scope under stated conditions. |
| Finding | A complete control failure, with source support, causal steps, impact and repair guidance, submitted for independent review. |

A finding must establish starting access, controlled material, the failed authority
decision, propagation to a sensitive consumer, the resulting effect and its
conditions. Disclosure also needs a return path to the attacker. Source citations
support this explanation; adjacency in a graph does not establish causality.

The investigator's source visibility and baseline knowledge grant no credentials
or access to the modeled attacker. Legitimate features can supply capabilities
without being vulnerabilities. Scanner matches remain leads until affected use,
reachability, attacker control and impact are established.

Questions preserve established facts, counterevidence, missing facts and next
actions. A contradicted route does not close every route to an objective. Local
uncertainty, an external prerequisite, an allocation limit and execution failure
remain distinct outcomes; none implies clean coverage.

## Three executions, different authority

| Execution | Input and purpose | Authority boundary |
|---|---|---|
| Ordinary audit | Discover and assess attack paths in the current application source namespace. | Reviewed assessment under `scans/`; accepted unfinished work can resume. |
| Advantage | Investigate from a completed ordinary audit plus authorized current source or patch views. | A separate linked assessment; every explicit investigation invocation starts fresh. |
| Remediation | Produce production patches from eligible accepted findings and supported exact-source authority. | A separate `remediations/` bundle; it does not alter the assessment or apply patches. |

Each workflow requires its own explicit request. Completing one never launches
another. Report consumption in [VulnOps @stake](stake/README.md) is read-only and
creates no new assessment or repair authority.

## Source scope and trust boundaries

One application may contain several Git repositories under `target/`. Repository
directory prefixes remain part of source references, and Recon represents every
repository. Cross-repository claims require evidenced producer/consumer,
configuration, identity and deployment relationships.

| Location or capability | Boundary |
|---|---|
| `target/` | Read-only input: no generated files, indexing state, package installation, builds, tests or direct execution. |
| `scans/` | Durable sanitized audit/Advantage evidence and reports. |
| `.harness/` | Runtime contexts, configuration, caches and temporary tool/navigation state. |
| `work/` | Disposable source, patch and experiment workspaces. |
| `remediations/` | Published patch bundles and receipts. |
| Configured LLM service | Receives required prompt/source context; local scanners do not make model analysis local. |
| Target execution | Disabled by default; available only through explicitly enabled, functional safe containment. |

Investigation stays offline except for the configured LLM endpoint. Advisory
snapshots are prepared before the audit. Egress policy and enforced OS isolation
are separate settings; policy-only mode is not a network sandbox.

Current inventory governs new work. Retained evidence keeps its producing attempt
and assessed source scope. Source changes neither erase accepted checkpoints nor
make historical conclusions apply to the new checkout.

## Ordinary audit flow

```mermaid
flowchart LR
    R[Recon] --> T[Tool Collection] --> S[ThreatHunter]
    S --> P[Campaign Planning] --> I[Intrusion] --> G[Gap Exploration]
    G --> Y[Synthesis] --> V[Final Verification] --> O[Report]
```

| Phase | Responsibility | Main artifact relative to the run |
|---|---|---|
| Recon | Map projects, inputs and trust boundaries through three parallel workers; preserve source-backed handoffs and unknowns. | `repo-context/repo-context.json`, `security-surfaces.json` in the same directory |
| Tool Collection | Run Wraith and Poltergeist through deterministic wrappers; normalize observations and receipts. | `tool-collection/collection.json` |
| ThreatHunter (`sast`) | Build contextual questions, investigate source paths, review candidates and perform bounded gapfill. | `sast/verified-findings.json` |
| Campaign Planning | Select capability-led, gap-driven and direct-validation questions from accepted evidence and source inspection. | `campaign-planning/campaign-plan.json` |
| Intrusion | Establish compatible capability transitions and investigate justified continuations in accepted waves. | `intrusion/intrusion-results.json` |
| Gap Exploration | Investigate consequential remaining source routes under a separate allocation. | `gap-exploration/results.json` |
| Synthesis | Deduplicate roots, resolve composition and author complete dossiers. | `synthesis/findings.json` |
| Final Verification | Challenge each effective dossier in fresh context; accept, correct, reject or retain precise uncertainty. | `final-verification/findings.json` |
| Report | Render accepted conclusions, accounting and limits without new model reasoning. | `report/security-report.json` and `.md` |

The lead accepts phases in order. Coordinators own their declared workers, while
deterministic scripts own normalization, allocation and publication. Accepted
Recon remains unchanged; later discoveries become attributed phase-local
amendments. Legacy ordinary runs retain their recorded phase set.

Empty campaign, synthesis and review paths use deterministic closure only when
their obligations are resolved. An empty result is valid; missing required work is
not an empty result.

### Source investigation and composition

ThreatHunter derives questions from actual actors, surfaces and boundaries rather
than a subsystem × attack-class cross-product. Objectives and questions retain
stable identities through packets, source expansion, review and gapfill. Packets
bound assignments, not access to relevant dependencies inside the authorized
source namespace. Each assigned cell receives its own disposition.

The evidence index includes findings, rejected routes, unresolved questions,
scanner observations and contextual capabilities. Campaign selection protects
source questions from scanner volume and balances consequence, actionability and
comparable-priority actor/boundary coverage. Initial and continuation allowances
are application-wide, not multiplied by repository count.

Each chain transition must establish the producer grant, attacker control,
compatible identity/resource/deployment scope, preserved influence, the consumer's
authority, ineffective intervening controls and jointly satisfiable conditions.
Rejecting a chain does not erase an independently established component weakness.

Intrusion consumes accepted prior-wave evidence. A continuation names its parent,
triggering evidence, changed hypothesis or actionable alternative, next question
and remaining allocation. It is distinct from retrying a failed operation. New
capabilities must be composed, continued or explicitly deferred.

### Scanner admission

Clean and findings-present scanner outcomes can both succeed. Duplicate
normalization is normal processing; `match_count` and unique `candidate_count`
remain separate. Invocation, parse, schema, count or integrity failure closes Tool
Collection as failed rather than producing a successful empty/degraded scan.

Dependency advisories need affected use and reachability. Secret observations need
source-backed exposure and impact; no live credential use is implied. Durable
secret values are exactly `<redacted>`; raw output, recoverable fragments and proof
tokens are excluded.

## Gap Exploration and protected cohorts

Gap Exploration is supplementary, source-only work after the main investigation.
It selects consequential new branches or unresolved local obligations; it cannot
resolve an external prerequisite by repeating local work. Its allowance is separate
from original investigation and does not multiply by repositories or passes.
Workers return at most two candidates, use optional Codegraph navigation and have
no recursive continuations or borrowed dynamic-experiment budget.

Original Synthesis closes before supplementary authoring; original Final
Verification closes before supplementary review. These are cohorts within the
existing phases, with one canonical result. Mixed-origin claims retain original
review allocation. Supplementary-only claims use the extra allowance.

Accepted originals and admitted peers survive an unusable supplement. Unaccepted
combined output can be discarded by its owner, while missing reviews leave their
dependent claims unconfirmed. A zero-time allowance is a deferral; an actually
failed task remains a failure. Unsafe access or corrupted authority cannot use
optional-failure closure.

Gap worker drafts do not own `admission` metadata. Admission and native
reconciliation exclude only that publisher-owned field and apply the same
attribution/assessment normalization. Terminal hashes still bind the complete
original draft bytes, and packet, provenance and receipt checks remain separate.
This preserves analytical equality without rewriting saved runs. See
[`gap_exploration_contract.py`](scripts/gap_exploration_contract.py) and
[`gap_dossier.py`](scripts/gap_dossier.py).

## Dossiers and independent review

Synthesis is the sole pre-verification finding authority. A dossier contains:

- actor, starting access, controlled material, prerequisites and objective;
- affected components, source locations and evidenced service bindings;
- ordered steps, mechanisms, expected results and supporting evidence;
- reviewed typed examples, impact limits and chain transitions where applicable;
- repair actions linked to the steps they interrupt, with proposed rejection and
  legitimate-behavior checks;
- producing attempts, assessed scope and evidence lineage.

Unknown service labels remain unknown; missing essential reachability remains a
proof gap. Standalone findings deduplicate by root cause, chains by ordered
primitives and terminal impact. Source examples must match their citations except
for explicit safe substitutions. Source-established expectations remain distinct
from executed observations.

Final Verification challenges the complete effective dossier, including corrections,
examples, transitions, severity and repairs. The review binding prevents an old
approval from confirming changed content. It proves which dossier was reviewed,
not that the reviewer's reasoning is correct. Unresolved/rejected claims cannot
mark objectives achieved.

Fresh context is not model diversity. The shipped routes retain OMP sign-in:
Astra for investigation/review and GPT-6.1 Sol for the lead, Recon and separate
remediation, all at High effort. Daybreak Red/Blue are account access tiers,
not model selectors; configuration cannot grant their safeguards or entitlements.
Diversity is evaluated against all relied-upon contributors, preserving historical
attribution. Effort changes or a different lead/synthesizer do not create diversity.

## Advantage

### Entry and baseline selection

Terminal launchers and the prepared OMP `--in-session` initializer converge on the
[same controller](.omp/main/vulnops-advantage-main.md). Only one workflow can be
active. Initialization requires an unambiguous completed ordinary baseline and
returns an immutable temporary `input_path` containing source/evidence roots,
routes, mode, depth and allocations. It does not replay the baseline's source
investigation or start a second OMP.

Every explicit investigation request creates a fresh destination and independent
limits, including after interruption. Earlier Advantage queues, attempts and
checkpoints are not resumed. Completed historical products remain readable under
their recorded phase set.

Retained report publication is a separate deterministic operation in
`render-advantage-report.py --retained <base> --mode standard|deep`. It accepts only
base-source evidence with unselected actions and sufficient saved review,
assignment, dossier and provenance authority. It claims exclusive ownership,
rejects live or existing report destinations, writes companions and installs
canonical JSON last. A hash-bound receipt records the retained evidence closure
and separate publication time; no native phase acceptance is reconstructed, no
source is executed, and missing historical scope remains unknown. See
[`advantage_publication.py`](scripts/advantage_publication.py).

Mode defaults to `deep`, depth to `full`; they are independent selections:

| Mode | Operation |
|---|---|
| `standard` | One fresh informed investigation pass. |
| `deep` | Independent passes sharing one initial allocation and continuation reserve. |
| `diff` | One pass over immutable patch bytes and explicitly bound base/derived source views. |
| `actions` | Selected assessments/handoffs from a completed non-actions Advantage source; no new discovery or promotion. |

### Planning, investigation and handoffs

Discovery follows Baseline → Planning → Investigation → Gap Exploration →
Synthesis → Final Verification → Handoff → Report. Actions-only runs record skips
for the five discovery/review phases between Baseline and Handoff.

Baseline intake exposes available canonical cohorts with execution-qualified
references, including counterevidence and unresolved work. Missing cohorts remain
unknown, and malformed citations limit their dependent claims. Historical
knowledge becomes a current capability only through current proof.

Planning records actor access, controlled material, unavailable privileges, desired
effect, success condition, source view, counterevidence and stop conditions. The
builder validates this authored plan and derives immutable packets. Reopening a
contradicted route requires evidence addressing its decisive control.

Initial deep passes cannot read each other's hypotheses/results. After native work
stops, semantic admission validates exact ownership and byte bindings before
publishing per-task results. Continuations explicitly consume an admitted
predecessor in the same pass and inherited question. They require new evidence or
an actionable alternative; blind retries of externally blocked work are not
continuations. Actual allocations come from
[`advantage_config.py`](scripts/advantage_config.py), shared across passes and
repositories.

Synthesis reconciles every eligible candidate with the baseline. Final Verification
reviews both the effective attack and the claimed advancement:

| Classification | Meaning after independent acceptance |
|---|---|
| `new_root` | A distinct exploitable control failure. |
| `new_chain` | Compatible transitions establish distinct exploitability, a boundary crossing or greater effect. |
| `impact_expansion` | A proven capability/effect beyond the baseline. |
| `baseline_correction` | A material correction, reported separately from added outcomes. |
| `baseline_revalidation` | Current confirmation of the prior root/impact, not an added outcome. |

Baseline reconciliation preserves reused, revalidated, contradicted and unvisited
historical findings without changing the original audit. An investigation-only
revalidation cannot supply independently confirmed authority.

Diff preparation binds the supplied patch to one selected repository/base and
creates a disposable derived view under `work/`. Base and derived citations stay
distinct, including deleted paths; the target is unchanged.

Handoff performs only selected fix verification, patch-risk assessment, hardening
or tracking. Discovery-mode patch assessments are authored during Investigation
and imported by Handoff. Actions-only reasoning uses the completed Advantage
source linked to the same ordinary baseline. It requires accepted selected IDs
and a patch where the selected assessment needs one. Tracking produces sanitized
local records without contacting a provider. Unexpected hypotheses require a
separate investigation, and no handoff applies a patch or grants merge approval.

### Failure and publication

Native hooks retain live phase ordering, task handles and outcomes in process
memory. Advantage has no persisted scheduler, manifest or recovery ledger. Phase
acceptance requires semantic validity, correct order and no live/queued work;
a successful terminal-envelope boolean is not an additional evidence gate.

Original synthesis projected after its native author stops gains canonical
authority only through the existing publication observation: the immutable input,
assigned route and all terminal draft hashes must still match, and the original
finalizer must succeed with the fixed, non-redirected canonical output. Observation
adds that output's hash to the author's existing artifacts without changing its
terminal outcome. The downstream original loader still requires the exact native
hash; file existence alone grants no authority.

| Fault | Result |
|---|---|
| Claim-level proof gap | Withhold that conclusion and preserve usable neighboring evidence. |
| Missing, malformed or unadmitted child output | Discard it as evidence; retain healthy work and precise missing-proof accounting. Retry/exhaustion is not required for closure. |
| Corrupted authoritative ownership, unsafe access, secret disclosure or forbidden execution | Stop the affected execution. |

`execution_failed` requires an actual failed/cancelled native task. Missing proof
from unadmitted output is `locally_unresolved`; never-launched work is not a failed
execution. A valid aggregate may advance with limitations, while a failed top-level
attempt without accepted closure cannot advance merely because files exist.

The report leads with new roots, chains and impact expansions. Assessed-confirmed
counts can also include independently revalidated roots and therefore differ from
added-outcome counts. Up to five consequential unfinished terminal routes are
selected for the human view; complete accounting remains in canonical evidence.
Top-level failure/cancellation ends the invocation. Later investigation starts
fresh; retained report publication follows the separate boundary above.

## Runtime and recovery

OMP provides task dispatch, worker contexts and terminal outcomes. The harness
provides canonical actors, model routes, deadlines and evidence gates. The lead
retains overall ownership; coordinators fan out only declared workers. Messages,
progress cards and spawn acknowledgements do not accept evidence.

One top-level phase runs at a time, with bounded worker concurrency. Deadlines are
armed through the launcher's private configuration overlay. Children cannot
extend them or substitute actors/routes. Twelve routing groups resolve controller
and nested-worker assignments; defaults and overrides live in configuration.

Controller instructions live in `.omp/main/`, worker responsibilities in
`.omp/agents/`, methods in `.omp/skills/`, and deterministic mechanics in `scripts/`.
Skill references stay with their owning skill. Maintainer planning tools are
separate from the production audit workflow.

Ordinary audits and remediation retain unfinished recovery. Initialization claims
the intended run before mutation, preserves accepted predecessors and consumed
allocations, and assigns current source/routes/limits only to new work. A removed
selected directory is a stale pointer; malformed state in an existing directory
is an error. Explicit fresh work creates a distinct run without deleting evidence.

Acceptance, not file existence, distinguishes durable evidence from owner drafts.
Recovery preserves accepted artifacts and required support; only their owner may
remove unaccepted/dependent output. It never resets consumed work to evade limits
or rewrites upstream evidence to pass a downstream gate.

Completed readers use publication identity and canonical evidence without today's
source, graph caches or mutable controls. Supported legacy records normalize in
memory; completed bundles are not migration targets. Canonical output remains
schema `2.0`. Local hashes bind specific scanner output, reviews, patches or
receipts; they are not a universal source-fingerprint gate on audit resume.

## Navigation and contained experiments

Codegraph indexes a disposable source copy outside the target. Preparation has one
finite budget covering copying/indexing; ordinary failure or timeout cleans owned
work and falls back to source-only investigation. Unsafe paths, cancellation or
failed shutdown/cleanup remain errors. Operational settings are in
[AGENTS.md](AGENTS.md).

Typed graph queries suggest source to inspect. Only relied-upon results need
owned receipts and source-backed answers. Empty or skipped navigation proves no
absence of attack paths.

An investigative experiment answers a named uncertainty before or after a candidate
exists. It records the question, why static reasoning is insufficient, approved
inputs, expected supporting/contradicting observations and interpretation limits.
It cannot establish deployment facts outside its setup.

Target execution requires opt-in safe mode and a successful functional Linux
Bubblewrap probe. There is no Docker, macOS or direct-shell fallback. Resource and
parallel limits apply; reservations survive ordinary resume. Disabled/unavailable
execution records the missing capability. Raw output and proof tokens are
discarded; only permitted sanitized observations/support remain.

## Remediation

The planner consumes accepted effective dossiers. Rejected findings, secrets,
environment-required cases and missing exact-source authority do not become
speculative patches. Automated publication requires a single repository; a
multi-repository finding needs explicit per-repository patch ownership elsewhere.

The current [`require_exact_source_authority`](scripts/remediation_common.py)
implementation supports legacy exact-source records and rejects attempt/assessment
provenance, historical findings and unresolved applicability before checking the
fingerprint. Completing a current assessment therefore does not automatically make
it eligible. The prerequisite is independent establishment on the intended patch
base and explicit manual remediation authorization; manufacturing a fingerprint
or altering a completed report cannot supply that authority.

New bundles bind report and final-findings digests. Eligible workers edit only
production source/configuration in disposable copies, without target execution,
builds, package managers or tests. The publisher checks permitted text paths,
secret hygiene and `git apply --check --whitespace=error-all` against authorized
source. `patch_ready` means those checks passed; semantic repair, regression
safety, applying, committing and pushing remain separate work.

## Reports and consumption

Deterministic renderers take confirmed finding authority from Final Verification.
Other phases supply accounting and limitations. Markdown provides attacker
outcomes, complete dossiers and step-linked repair guidance; JSON retains the
full evidence and attribution. Assessment scope/date stays distinct from
publication date. Republishing neither revokes the accepted verdict nor assesses
later source.

Confirmed severity totals exclude explicitly unconfirmed environment-required
dossiers even when `summary.total` includes them. Overlapping coverage categories
are not additive vulnerability counts. Canonical JSON/Markdown do not clip accepted
dossiers by byte size; bounded display cohorts retain exact totals and references.
Consumers such as @stake apply their own documented import resource limits.

Typed example content and substitution `original`/`replacement` values are literal
data, including accepted whitespace-only values. Descriptions still require
substantive prose. Size, secret-hygiene, source-match and review bindings remain
applicable; publication does not trim literals to satisfy a prose check.

Execution ownership is shared by producer-route collection and completed-bundle
reading. Local string references identify local producers; typed
`{execution_id, artifact_ref}` references and attributed contributors retain
baseline/action-source ownership. Unknown, conflicting, ambiguous or unsafe
bindings fail; inherited evidence is not reinterpreted as a local artifact.

Deliver the canonical run tree and sanitized supporting evidence with its relative
layout. Publication metadata carries original identity, scope and routes, so
current completed reports do not need runtime ledgers or a checkout. Markdown
alone is insufficient. Exclude credentials, target code, runtime contexts, raw
scanner/proof output and recovery scratch.

@stake has separate local-server and static-browser adapters. The server reads
admitted folders; the browser admits a ZIP pair and stores it in IndexedDB, with
atomic replacement and restore validation. Neither reruns an assessment. See the
[viewer guide](stake/README.md) for import limits and source/evidence navigation,
and [Sites guide](stake/SITES.md) for isolated app-only publication.

## Evaluation and assurance

| Check | What it establishes |
|---|---|
| Deterministic regression test | The asserted boundary or failure behavior for its fixtures. |
| Authored workflow scenario | Builders, lifecycle gates and renderers consume supplied evidence correctly; not autonomous model discovery. |
| Native OMP/tool probe | The installed dispatch, cancellation, parsing or tool behavior actually exercised. |
| Launcher smoke test | The selected entrypoint reaches the observed startup boundary; not a completed audit. |
| Model-led audit | One assessment completed with its recorded findings/limits; not exhaustive coverage. |
| Contained experiment | Behavior under the recorded conditions; not untested production reachability. |
| Patch apply-check | Applicability to the authorized source; not semantic repair or regression safety. |

Tests should assert consumer-visible artifacts, state transitions or refusals.
Recovery scenarios must include accepted predecessors and abandoned downstream
output, not only empty happy-path destinations. Report observed checks rather than
using test count, authored fixtures or binary presence as assurance claims.

Useful entrypoints include [investigation acceptance tests](tests/test_investigation_acceptance.py),
[workflow scenarios](tests/test_redteam_workflow.py), [native lifecycle probes](scripts/probe-omp-lifecycle.py)
and [toolchain probes](scripts/probe-toolchain.sh). Offline installation and live
provider readiness are distinct; preparation is documented in [offline.md](offline.md).

## Implementation map

| Concern | Main owners |
|---|---|
| Ordinary source selection and lifecycle | [`run-audit.sh`](scripts/run-audit.sh), [`target-inventory.py`](scripts/target-inventory.py), [`run_lifecycle.py`](scripts/run_lifecycle.py), [`recover-run.py`](scripts/recover-run.py) |
| Recon and dependency inputs | [`finalize-recon.py`](scripts/finalize-recon.py), [`dependency_contract.py`](scripts/dependency_contract.py) |
| Scanner orchestration | [`collect-tools.py`](scripts/collect-tools.py), [`normalize-wraith.py`](scripts/normalize-wraith.py), [`normalize-poltergeist.py`](scripts/normalize-poltergeist.py) |
| Source hunting and review | [`build-hunt-plan.py`](scripts/build-hunt-plan.py), [`sast_contract.py`](scripts/sast_contract.py), [`finalize-sast.py`](scripts/finalize-sast.py) |
| Campaigns and accepted waves | [`build-evidence-index.py`](scripts/build-evidence-index.py), [`build-campaign-plan.py`](scripts/build-campaign-plan.py), [`build-intrusion-wave.py`](scripts/build-intrusion-wave.py), [`finalize-intrusion.py`](scripts/finalize-intrusion.py) |
| Ordinary synthesis/review | [`finalize-synthesis.py`](scripts/finalize-synthesis.py), [`finalize-verification.py`](scripts/finalize-verification.py) |
| Advantage intake and native lifecycle | [`advantage_baseline.py`](scripts/advantage_baseline.py), [`advantage_contract.py`](scripts/advantage_contract.py), [`init-advantage.py`](scripts/init-advantage.py), [`advantage_lifecycle.py`](scripts/advantage_lifecycle.py), [native guard](.omp/guards/target-readonly.ts) |
| Advantage plans, passes and review | [`advantage_config.py`](scripts/advantage_config.py), [`build-advantage-plan.py`](scripts/build-advantage-plan.py), [`build-advantage-wave.py`](scripts/build-advantage-wave.py), [`advantage_pipeline.py`](scripts/advantage_pipeline.py) |
| Supplementary evidence/cohorts | [`gap_exploration_contract.py`](scripts/gap_exploration_contract.py), [`gap_dossier.py`](scripts/gap_dossier.py) |
| Actions, reports and retained publication | [`advantage_actions.py`](scripts/advantage_actions.py), [`advantage_reporting.py`](scripts/advantage_reporting.py), [`advantage_publication.py`](scripts/advantage_publication.py), [`report_bundle.py`](scripts/report_bundle.py) |
| References and attribution | [`evidence_refs.py`](scripts/evidence_refs.py), [`model_routing.py`](scripts/model_routing.py), [`model_identity.py`](scripts/model_identity.py) |
| Navigation and experiments | [`setup-codegraph.sh`](scripts/setup-codegraph.sh), [`codegraph_contract.py`](scripts/codegraph_contract.py), [`run-investigation-experiment.py`](scripts/run-investigation-experiment.py), [`run-safe-reproduction.sh`](scripts/run-safe-reproduction.sh) |
| Production patches | [`build-remediation-plan.py`](scripts/build-remediation-plan.py), [`publish-remediation-patch.py`](scripts/publish-remediation-patch.py), [`validate-remediation.py`](scripts/validate-remediation.py) |
| Runtime readiness and routing | [`validate-config.sh`](scripts/validate-config.sh), [`validate-omp-agents.py`](scripts/validate-omp-agents.py), [`set-omp-deadline.py`](scripts/set-omp-deadline.py) |

Extend an existing owning method or question before adding a phase. A new phase
needs a distinct responsibility, output authority, zero-item behavior and actual
consumers. Changes must preserve accepted evidence, ordinary recovery, fresh-only
Advantage and the separate exact-source remediation boundary.
