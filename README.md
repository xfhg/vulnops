# VulnOps V2

**An evidence-driven red-team audit system for finding exploitable source-code
weaknesses, impact expansions, and composed attack paths.**

VulnOps turns a repository into a bounded security investigation. It combines
real scanner output, source-first adversarial analysis, typed code navigation,
attack-primitive composition, optional contained reproduction, and independent
verification. The final report contains only findings that survive deterministic
integrity gates.

The product is designed for the gap between two familiar security activities:
high-volume scanning that reports known signals without proving exploitability,
and expert manual review that can discover deeper paths but is difficult to
standardize, reproduce, and scale. VulnOps keeps the useful breadth of automation
while enforcing the evidence discipline expected from a serious red-team review.

## The investment thesis

Security teams do not lack alerts. They lack a reliable way to turn disconnected
signals into answers to the questions that drive remediation:

- Can an attacker actually reach the affected behavior?
- What boundary is crossed and what capability is gained?
- What consumes that capability next?
- Do two individually understood weaknesses compose into a more damaging path?
- Which untested state transitions or trust assumptions deserve targeted review?
- Can another verifier reproduce the reasoning from canonical evidence?

VulnOps makes those questions the workflow, not an optional analysis layer added
after scanning. The durable product asset is therefore not a larger list of
detectors. It is a structured evidence and capability system that can absorb new
tools, models, and specialist doctrine without weakening provenance.

This creates a practical path from repository audit to security decision support:

1. normalize heterogeneous evidence;
2. translate evidence into attacker prerequisites and gained capabilities;
3. spend bounded investigation budget on the highest-value transitions;
4. independently challenge every reportable conclusion; and
5. emit sanitized, machine-checkable output suitable for engineering workflows.

No market-size or performance claim is hard-coded into the product narrative.
The harness exposes measurable operating data—coverage, campaign dispositions,
verification rejections, environment gaps, origin classes, and phase receipts—so
deployment economics can be evaluated from real audits rather than promotional
proxies.

## What makes VulnOps different

### Known evidence is a launch point, not the product

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

### Tools must prove that they worked

Wraith, Poltergeist, and Codegraph are not blind checklist steps. The runtime
executes functional fixtures during readiness, parses each tool's real output
envelope, records version and result counts, hashes normalized artifacts, and
fails unhealthy receipts. A binary merely existing on disk is insufficient.

Scanner data is then used where it adds value:

- Wraith establishes installed dependency and advisory candidates for source
  reachability and composition work.
- Poltergeist identifies secret locations and exposure hypotheses while removing
  the value before persistence.
- Codegraph indexes a run-local source snapshot and answers typed navigation
  questions about callers, callees, impact, affected symbols, and search matches.
  Its results guide source review but never substitute for vulnerability proof.

Dependency discovery is deterministic. Recon's finalizer finds every supported
lockfile or manifest in the target and owns `projects[].dependency_files`, so
model guesses such as `go.sum`, `package.json`, Dockerfiles, and workflows cannot
enter the scanner queue. Tool Collection stages normalized artifacts beneath
`.harness/` and publishes the complete canonical set only after schemas, counts,
receipts, and hashes pass.

### Models reason; deterministic code owns integrity

Models perform the work that benefits from adversarial interpretation: threat
modeling, source hunts, hypothesis refinement, campaign investigation, synthesis,
and fresh-context verification. Python and shell code own the parts that must be
stable: tool execution, normalization, IDs, budgets, manifests, hashes, schema
validation, reference resolution, fingerprint checks, empty paths, and reporting.

This boundary reduces model-authored bookkeeping, repeated summarization, and
format drift. It also makes failures diagnosable: a conclusion can be traced to a
source record, campaign, receipt, and verifier result.

### Evidence is promoted, not copied

Each evidence body has one canonical home and one stable identifier. Downstream
phases cite it instead of rewriting it. Every record and campaign receives a
terminal disposition. Upstream artifacts—especially the repository model and
security surfaces—are immutable once validated.

## Product workflow

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
| SAST | Threat-model and hunt source across risk-prioritized subsystem/attack-class cells | Validated source findings, closures, and coverage ledger |
| Campaign Planning | Convert all prior evidence into typed primitives and bounded hypotheses | Evidence index and campaign plan |
| Intrusion | Test capability transitions, impact expansion, and uncovered attack paths | Exactly one terminal result per campaign |
| Synthesis | Deduplicate root causes and establish standalone or composed findings | Sole pre-verification finding set |
| Independent Verification | Challenge each finding in a fresh verifier context | Accepted findings and explicit rejections |
| Report | Render bounded decision-ready output | Sanitized JSON and Markdown |

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

| Lane | Question | Typical added value |
|---|---|---|
| `primitive_led` | What consumes this known capability, or can two capabilities compose? | Chain, bypass, new boundary crossing, expanded impact |
| `gap_driven` | Which uncovered state, order, replay, parser, fallback, race, or trust assumption merits review? | New root cause or evidence-backed closure |
| `direct_validation` | Is this candidate installed, active, reachable, and consequential? | Exploitability proof plus one-hop downstream analysis |

Budgets are deterministic and depth-bounded:

| Depth | Primitive-led | Gap-driven | Direct validation | Maximum SAST hunt tasks | Gapfill rounds |
|---|---:|---:|---:|---:|---:|
| `quick` | 2 | 1 | 1 | 12 | 1 |
| `balanced` | 5 | 3 | 2 | 32 | 2 |
| `full` | 10 | 7 | 3 | 64 | 3 |

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

Primary and verifier selectors are configured independently:

```toml
[llm]
selector = "provider/primary-model"

[llm.verification]
selector = "provider/verifier-model" # empty inherits the primary selector
```

All discovery and source-validation roles use the primary selector. The
fresh-context independent verifier uses the generated `pi/verifier` role. One
custom OpenAI-compatible endpoint is supported; both selectors may choose
different models on it, and either selector may instead use an OMP-known built-in
provider.

The normalized selectors are part of run identity. Changing either one starts a
new run, preventing incompatible reasoning state from being resumed. Model
diversity is the deterministic boolean result of selector inequality. When the
selectors match, reports state the same-model limitation; fresh contexts still
separate the tasks.

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

- LLM base URL, API key, primary selector, verifier selector, and one optional
  custom-provider model registry;
- default depth;
- SAST context-packet size and per-depth task/gapfill/attempt bounds; and
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
reproduction mode, primary selector, verifier selector, and workflow identity.
Only the current incomplete run resumes when every field matches. Completed and
failed runs are terminal. A source change, dirty-tree change, depth change,
reproduction-policy change, or model change creates an isolated run.

This provides two business-relevant properties: results are attributable to a
specific input and operating policy, and a resumed investigation cannot silently
mix evidence produced under different assumptions.

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

The report summarizes severity, verification state, and finding origin:

- `standalone_known`
- `known_impact_expansion`
- `composite_chain`
- `independent_discovery`
- `cross_evidence_discovery`

Those categories make the system's incremental value measurable without
discarding confirmed standalone risk.

## Adoption and deployment fit

VulnOps is best suited to teams that need a repeatable deep review of source they
are authorized to assess: product-security investigations, release gates for
high-risk services, due diligence, security research, and focused red-team
campaign planning.

The architecture supports gradual adoption:

1. run with reproduction disabled and use source-backed findings only;
2. measure coverage, closures, verification rejection rate, and environment gaps;
3. enable functional bubblewrap reproduction on suitable Linux workers;
4. integrate the deterministic JSON report and final-finding artifact with issue
   management or governance systems; and
5. add specialist attack doctrine or normalized tools while preserving the same
   evidence contracts.

The system does not claim to replace a production environment, external attack
surface testing, or human authorization decisions. Its role is to make deep
repository analysis more rigorous, compositional, auditable, and economically
repeatable.

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
