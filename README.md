# VulnOps V2

VulnOps is an evidence-driven red-team audit harness for finding exploitable
source-code weaknesses, impact expansions, and composed attack paths. It combines
real scanner output, source-first adversarial analysis, typed code navigation,
attack-primitive composition, optional contained reproduction, and independent
verification. The final report contains only findings that survive deterministic
integrity gates.

## Operating objective

The workflow turns disconnected security signals into evidence-backed answers:

- Can an attacker actually reach the affected behavior?
- What boundary is crossed and what capability is gained?
- What consumes that capability next?
- Do two individually understood weaknesses compose into a more damaging path?
- Which untested state transitions or trust assumptions deserve targeted review?
- Can another verifier reproduce the reasoning from canonical evidence?

Those questions are part of the phase contracts rather than a post-processing
step. The harness uses a structured evidence and capability system so tools,
models, and specialist doctrine can change without weakening provenance.

1. normalize heterogeneous evidence;
2. translate evidence into attacker prerequisites and gained capabilities;
3. allocate bounded investigation budget to the highest-priority transitions;
4. independently challenge every reportable conclusion; and
5. emit sanitized, machine-checkable output.

## Analysis strategy

### Known evidence is a launch point

A dependency advisory, source finding, exposed credential candidate, entrypoint,
or trust transition can become an attack primitive. Campaign Planning asks what
the primitive grants, which controls it may bypass, which downstream code consumes
it, and whether it satisfies the prerequisites of another primitive.

Novelty is an outcome, not a seed requirement. A valuable result may be:

- a previously unknown root cause;
- proof that an advisory is reachable through an affected use;
- a known weakness with newly established downstream impact;
- a chain made entirely from known primitives whose composition crosses a new
  boundary or produces materially greater impact; or
- a defensible closure showing that an attractive hypothesis is not exploitable.

That distinction keeps the harness red-team oriented without rewarding novelty
theater. It seeks attacker leverage and combined effect.

## Canonical workflow

```text
                              deterministic control plane
                  identity · budgets · schemas · hashes · validation
                                         │
                                         ▼
Repository ── Recon ── Tool Collection ── SAST ── Campaign Planning
    │            │        │                  │              │
 read-only       │    Wraith +          source-first   evidence index
 fingerprint     │    Poltergeist       validation     + primitives
                 │                                          │
                 └──────── canonical evidence ───────────────┘
                                                            ▼
                              Intrusion campaigns + typed Codegraph queries
                                                            │
                                                            ▼
                            Synthesis ── Independent Verification ── Report
```

| Stage | Purpose | Sole authoritative output |
|---|---|---|
| Recon | Model projects, inputs, entrypoints, assets, and trust boundaries | Repository context and immutable security surfaces |
| Tool Collection | Run deterministic scanners concurrently and normalize healthy output | SCA records, redacted secret records, tool receipts |
| SAST | Threat-model concrete attacker paths and hunt source-backed security questions | Validated source findings, closures, and coverage ledger |
| Campaign Planning | Convert all prior evidence into typed primitives and bounded hypotheses | Evidence index and campaign plan |
| Intrusion | Test capability transitions, impact expansion, and uncovered attack paths | Exactly one terminal result per campaign |
| Synthesis | Deduplicate root causes and establish standalone or composed findings | Sole pre-verification finding set |
| Independent Verification | Challenge each finding in a fresh verifier context | Accepted findings and explicit rejections |
| Report | Render bounded verified output | Sanitized JSON and Markdown |

### SAST hunting and Intrusion

SAST hunting asks **what security flaws exist in each part of the codebase**.
It works broadly across risk-prioritized, source-backed hunt mappings. Each
mapping contextualizes an attack-class lens to a concrete attacker, source flow,
boundary, files, and security question. The planner never expands a class across
every surface merely because it applies somewhere in the subsystem. Workers
trace attacker-controlled input through source, verify individual root causes,
and record a separate disposition for every assigned question.

Intrusion asks **what an attacker can accomplish with the evidence already
available**. Campaigns start from SAST findings and other canonical evidence, then
investigate downstream consumers, capability transitions, control bypasses,
impact expansions, and composed attack paths. This work is narrower and
hypothesis-driven rather than a second general source hunt.

For example, SAST may establish that an attacker can write outside an archive
extraction directory. Campaign Planning can turn that write primitive into a
hypothesis about a privileged configuration consumer, and Intrusion can determine
whether the primitive crosses another boundary or produces materially greater
impact. Codegraph helps Intrusion navigate those paths, but its output never
replaces source-backed proof.

SAST therefore owns systematic flaw discovery and initial source verification;
Intrusion owns adversarial follow-through. Neither publishes the final finding
set. Both feed Synthesis, the sole authority that deduplicates root causes and
decides whether the evidence supports a standalone finding, an impact expansion,
or a closed multi-step chain.

### Orchestration, subagents, and parallelism

VulnOps uses OMP subagents where work is independent and keeps evidence-dependent
phases sequential. Every model-owned top-level phase runs as a supervised OMP
job. The lead follows the exact job ID, enforces the phase deadline, and accepts
completion only after a structured yield and phase validation. IRC carries short
stage progress and peer questions; it is never the completion mechanism.

| Area | Worker strategy | Maximum concurrency |
|---|---|---:|
| Recon | Overview, trust-boundary, and input-surface workers in one batch | 3 |
| Tool Collection | Concurrent Wraith invocations and one Poltergeist scan | 4 processes |
| SAST deep dives | One worker per bounded hunt-task packet, with overflow queued | 4 quick / 8 balanced / 16 full |
| SAST verification | One adversarial verifier per deduplicated candidate | 4 quick / 8 balanced / 12 full |
| Safe reproduction | One contained worker per eligible source-verified candidate | Configured `max_parallel` |
| Intrusion | One worker per campaign, with overflow queued | Depth-bounded campaign waves |
| Final Verification | One fresh-context verifier per synthesized finding | Depth-bounded verifier waves |

Nested task batches block their coordinator until the batch returns, while the
workers inside the batch execute concurrently. Every coordinator may spawn only
its declared specialist workers. Stable task IDs prevent duplicate launches, and
overflow is queued rather than silently dropped. SAST workers receive small,
hash-bound task packets containing only their exact contextual cells instead of
the aggregate hunt plan or repository-wide boundary context.

The phase order remains sequential by design:

```text
Recon → Tool Collection → SAST → Campaign Planning
      → Intrusion → Synthesis → Final Verification → Report
```

Each downstream phase consumes validated, immutable upstream evidence, so
overlapping those phases would violate the authority and resume contracts.
Deterministic scanning, aggregation, empty paths, and reporting do not consume
model agents. Campaign Planning and Synthesis remain single-agent consolidation
phases because each owns one canonical decision artifact.

The optional OMP advisor runtime is disabled because it adds an unowned review
loop to every turn. This does not disable `task`, `job`, canonical phase agents,
or any of the worker fanout above.

## Red-team campaign model

The planner records every primitive as:

```text
prerequisites
    └─> primitive ──> capability gained
                         ├─ boundary crossed
                         ├─ reachable assets
                         └─ conditions
```

Campaigns are selected through three complementary lanes:

| Lane | Question | Analysis objective |
|---|---|---|
| `primitive_led` | What consumes this known capability, or can two capabilities compose? | Chain, bypass, new boundary crossing, expanded impact |
| `gap_driven` | Which uncovered state, order, replay, parser, fallback, race, or trust assumption merits review? | New root cause or evidence-backed closure |
| `direct_validation` | Is this candidate installed, active, reachable, and consequential? | Exploitability proof plus one-hop downstream analysis |

Budgets are deterministic and depth-bounded:

| Depth | Primitive-led | Gap-driven | Direct validation | Maximum SAST hunt tasks | Maximum hunt questions | Gapfill rounds |
|---|---:|---:|---:|---:|---:|---:|
| `quick` | 2 | 1 | 1 | 12 | 24 | 1 |
| `balanced` | 5 | 3 | 2 | 32 | 64 | 2 |
| `full` | 10 | 7 | 3 | 64 | 128 | 3 |

These are ceilings, not quotas to fabricate. Empty lanes remain empty. An audit
with no campaigns, no synthesized findings, or no verification work follows a
deterministic zero-item path and still produces a valid report.

## Evidence standard

A reportable issue requires more than a scanner match or plausible story. The
canonical finding contract requires:

- attacker perspective, starting access, and crossed boundary;
- intended behavior and concrete root-cause locations;
- an ordered source trace from entrypoint through propagation to sink;
- exploit conditions and concrete impact;
- source-validation references attributed to the primary model;
- typed source references resolving to canonical artifacts;
- remediation and a closure rationale; and
- an independent result attributed to the configured verifier model.

Additional gates apply by finding kind. Dependencies require an installed version,
affected use, and proven reachability. Secrets retain only the exact
`<redacted>` marker, location, exposure path, and bounded validity state. Chains
require at least two ordered primitives and exact closure between each output
capability and the next input capability.

Codegraph receipts may corroborate navigation only when the query parsed, the
normalized result hash matches, and the result contains a real relationship or
result node. Even then, graph output is context—not proof of attacker control,
unsafe behavior, or impact.

## Safety and trust boundary

VulnOps is intentionally fail-closed:

- The target checkout is read-only input. Its full working-tree fingerprint is
  checked during initialization, after Codegraph snapshot creation, after every
  phase, and at whole-scan validation.
- Runtime writes are constrained to `scans/` and `.harness/`.
- Audit execution is offline except for the configured LLM endpoint.
- Raw scanner output and raw proof output never enter scan artifacts or reports.
- Secret values, partial identifiers, entropy material, and proof tokens are not
  persisted.
- Target code is never executed by a model or normal shell step.
- Optional reproduction is Linux/bubblewrap-only and requires a successful real
  namespace/isolation probe. Restricted hosts return `needs_environment`; there
  is no Docker, macOS, or unsandboxed fallback.

The result is not a promise that static analysis can observe deployment-only
facts. It is a controlled way to distinguish established findings from hypotheses
that require an appropriate environment.

## Model portability and independent verification

The primary, orchestration tiers, and verifier selectors are configured
independently:

```toml
[llm]
selector = "provider/primary-model"

[llm.roles]
orchestrator = "provider/primary-model:low"
task = "provider/primary-model:medium"
slow = "provider/primary-model:high"
smol = "provider/primary-model:minimal"

[llm.verification]
selector = "provider/verifier-model" # empty inherits the primary selector
```

The audit lead uses the low-cost orchestration tier, phase coordinators use the
task tier, and evidence-heavy investigators use the slow tier. Source-validation
metadata remains attributed to the primary selector. The fresh-context
independent verifier uses an exact OMP per-agent model override generated from
`llm.verification.selector`; its agent front matter retains `pi/slow` only as a
supported fail-safe default. Readiness validation rejects a missing or
unresolvable verifier override before an audit starts. One custom
OpenAI-compatible endpoint is supported; all selectors may choose models on it,
and any selector may instead use an OMP-known built-in provider.

The configured primary, role, and verifier selectors are part of run identity.
Changing any one starts a new run, preventing incompatible reasoning state from
being resumed. Model diversity compares normalized underlying model identities;
changing only a thinking-effort suffix does not claim diversity. When the models
match, reports state the same-model limitation; fresh contexts still separate the
tasks.

## Quick start

### Prerequisites

- Linux when safe reproduction is required; the static workflow may run on a
  prepared supported platform, but it never gains an alternative reproduction
  backend;
- Python 3 and Bash;
- Git;
- bundled `omp`, `wraith`, `poltergeist`, `osv-scanner`, and `codegraph` binaries;
- a local OSV database; and
- bubblewrap only if safe reproduction is enabled.

Install or refresh the bundled toolchain and local advisory database using the
repository scripts appropriate to the deployment environment:

```bash
bash scripts/install-tools.sh
bash scripts/fetch-osv-db.sh
```

OMP is version- and checksum-pinned by the platform lock files. Readiness fails
if the installed binary differs from that lock, preventing silent regression to
an orchestration version with known task-lifecycle defects.

Copy `config.toml.example` to `config.toml`, configure the selectors and endpoint,
then place exactly one Git repository beneath `target/`.

Validate readiness before spending model budget:

```bash
bash scripts/validate-config.sh
```

Start the OMP-led audit:

```bash
./run.sh "audit the target repository at balanced depth"
```

The audit lead initializes the run with `scripts/run-audit.sh` exactly once and
then owns the canonical phase sequence. Operators preparing a run explicitly may
invoke `bash scripts/run-audit.sh balanced` before handing control to OMP.
`quick`, `balanced`, and `full` control bounded investigation depth. The main OMP
process is the single audit lead and follows [AGENTS.md](AGENTS.md). For design
rationale and exact trust contracts, see [ARCHITECTURE.md](ARCHITECTURE.md).
If the launcher exits after a run is initialized, it fail-closes active work so
the next compatible invocation can recover deterministically from the first
unfinished phase.

Status is health, not volume. Normal scanner deduplication and reaching the
configured SAST depth budget close `ok`; their occurrence/unique and
`depth_limited` counts remain visible as coverage. `degraded` is reserved for a
material capability loss such as a failed hunt cell or evidence that requires an
unavailable environment.

### Offline and controlled deployment

Installation, advisory-database refresh, and target cloning are preparation
activities. They occur before the contained audit runtime. For disconnected
environments, `scripts/offline-pack.sh` builds a version-pinned bundle with tool
hashes, a local OSV database, setup material, and chunk manifests:

```bash
bash scripts/offline-pack.sh --platform linux_amd64
```

The pack excludes live `config.toml` credentials by default and substitutes the
example configuration. Including live configuration is an explicit sensitive
operation. Transfer and endpoint policy remain deployment responsibilities; the
audit itself still permits only the configured LLM connection.

A target may be placed manually or cloned during preparation:

```bash
bash scripts/clone-target.sh <repository-url> [branch] [directory]
```

The clone helper removes write permission after cloning. Network cloning is never
part of audit execution.

## Configuration

`config.toml` is the sole configuration source. The supported surface is kept
small deliberately:

- LLM base URL, API key, primary selector, tiered role selectors, verifier
  selector, and one optional custom-provider model registry;
- default depth;
- SAST packet-size and per-depth task/question/gapfill/attempt bounds; and
- safe-reproduction resource limits.

Scanner binary choices, raw-output switches, model-authored reporting, redundant
phase toggles, and multiple custom endpoints are not configuration options. The
runtime has one canonical path and deterministic reporting is always enabled.

Example reproduction policy:

```toml
[harness.reproduction]
mode = "off"          # off | safe
sandbox = "auto"      # auto | bubblewrap
timeout_seconds = 120
cpu_seconds = 60
memory_mb = 1024
max_processes = 64
max_output_kb = 256
max_parallel = 1
```

## Run identity and resumability

Each run records repository path, commit, exact target fingerprint, depth,
reproduction mode, primary selector, every orchestration role selector, verifier
selector, workflow identity, resolved SAST budget, and a fingerprint of the
schemas, planners, validators, recovery tools, and phase-agent contracts that
govern the workflow. Only the current incomplete run
resumes when its immutable target and model/policy identity matches. Completed
runs are closed. Failed or interrupted runs recover at the first unfinished phase:
already validated upstream phase directories are sealed and retained, while the
failed phase and everything downstream are deleted and rerun with fresh attempt
counters. A harness-contract or SAST-budget change is recorded as a recovery
generation instead of discarding completed work. A source change, dirty-tree
change, depth change, reproduction-policy change, or role/model change creates an
isolated run.

This makes results attributable to a specific input and operating policy, and
prevents resumed investigations from silently mixing evidence produced under
different assumptions. Cross-contract recovery is explicit in the run manifest
and final report; retained prior-contract phases are accepted only while their
whole-directory seals remain unchanged.

## Canonical artifacts

Every run lives at `scans/<repo-id>/runs/<run-id>/`:

```text
run-manifest.json                 run identity, phase state, model metadata
task-ledger.json                  task attempts, status, artifacts, errors
repo-context/                     repository model and immutable surfaces
tool-collection/                  normalized SCA/secrets evidence and receipts
sast/                             threat model, hunts, validation, coverage
campaign-planning/                evidence index and bounded campaign plan
intrusion/                        per-campaign and aggregate terminal results
synthesis/                        sole pre-verification finding set
final-verification/               per-finding verdicts and accepted findings
report/                           sanitized JSON and Markdown reports
```

The operational context at `.harness/audit-context.json` is the only path and
selector authority for agents. Codegraph snapshots, tool work, contained homes,
and probes also live beneath `.harness/`, never in the target.

## Validation and observability

Three layers make the workflow inspectable:

```bash
bash scripts/validate-phase.sh <scan-base> <phase>
bash scripts/validate-scan.sh <scan-base>
bash scripts/audit-status.sh [<scan-base>]
```

Phase validation checks schemas, semantic references, artifact hashes, tool
counts, graph receipts, source paths, campaign completeness, and target
immutability. Whole-scan validation additionally checks run identity, task
closure, final-verifier attribution, model-diversity metadata, report counts,
redaction, artifact-size bounds, and cross-phase consistency.

Model phases run as supervised OMP jobs. The lead follows the returned job ID,
applies a depth-specific deadline, and accepts completion only when the job is
terminal, its agent yielded structured output, and the phase gate passes. IRC is
reserved for genuine stage progress and never substitutes for job lifecycle.

The report summarizes severity, verification state, and finding origin:

- `standalone_known`
- `known_impact_expansion`
- `composite_chain`
- `independent_discovery`
- `cross_evidence_discovery`

Those categories distinguish standalone risk, impact expansion, composed paths,
and independent discovery without discarding confirmed findings.

## Scope

VulnOps operates on source repositories the operator is authorized to assess. It
supports product-security review, high-risk release gates, security research, and
focused red-team campaign planning. It does not replace production-environment
validation, external attack-surface testing, or human authorization decisions.

## Lifecycle and cleanup

Scan outputs are durable deliverables; target checkouts and runtime work are
replaceable. Inspect cleanup scope before changing state:

```bash
bash scripts/cleanup.sh status
bash scripts/cleanup.sh work
bash scripts/cleanup.sh target
```

`cleanup.sh all` removes work, logs, and the target while retaining scans. The
explicit full-clean mode also removes scan deliverables and should be reserved for
intentional environment destruction.

## Project layout

```text
.omp/main/             audit-lead orchestration policy
.omp/agents/           phase and worker behavior
.omp/skills/           reusable security doctrine and specialist lenses
config/                attack taxonomy and static policy data
schemas/v2/            strict JSON contracts
scripts/               deterministic execution, adapters, finalizers, gates
tests/                 configuration, phase, lifecycle, and integration tests
target/                exactly one read-only Git repository
scans/                 isolated durable run artifacts
.harness/              contained runtime state and immutable graph snapshots
```

The governing design rule is simple: use model intelligence where interpretation
adds value, use deterministic code where integrity matters, and never promote a
security claim beyond its evidence.
