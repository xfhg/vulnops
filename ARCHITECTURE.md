# VulnOps V2 Architecture

This document is the technical design record for the canonical VulnOps audit
harness. It explains the trust model, control plane, artifact contracts, phase
ownership, evidence promotion rules, red-team composition model, containment
boundary, and failure semantics.

The architecture is optimized for one outcome: produce security conclusions that
remain useful after the excitement of discovery has passed—conclusions that are
source-backed, attributable, independently challenged, safe to retain, and precise
enough for an engineer to remediate.

## 1. Goals and explicit boundaries

### 1.1 Goals

The harness is designed to:

- discover exploitable code weaknesses, not just pattern matches;
- establish or reject reachability for known dependency and secret signals;
- use known findings as capabilities in deeper impact-expansion and composition
  work;
- find attack paths across source areas, trust boundaries, and evidence types;
- preserve a canonical, typed evidence chain from tool output to final report;
- separate model judgment from deterministic integrity enforcement;
- operate offline except for one configured LLM gateway;
- keep the target immutable and all runtime state contained;
- fail closed when evidence, tools, isolation, references, or identity do not
  satisfy their contracts; and
- scale investigation through bounded parallelism rather than unbounded agent
  fanout.

### 1.2 Non-goals

The harness does not:

- equate an advisory, graph relationship, scanner match, or model assertion with
  a vulnerability;
- execute target code outside the supported containment backend;
- retain raw scanner output, raw proof output, secret values, or proof tokens;
- access the public internet during an audit, other than the configured model
  endpoint;
- fabricate campaigns, graph scope, findings, or verifier work to fill a budget;
- provide multiple workflow modes, phase implementations, schema generations, or
  report authorities;
- support multiple custom LLM endpoints in one runtime; or
- infer deployment-only facts that are not present in the repository or a safely
  reproduced environment.

## 2. Architectural principles

### 2.1 Evidence before assertion

Every reportable finding must resolve to canonical artifacts and source locations.
The minimum proof shape is attacker → boundary → entrypoint → propagation → sink
→ impact, with explicit conditions. Different finding kinds add stricter fields;
none weakens this base requirement.

### 2.2 One owner per artifact

Each phase owns a disjoint output namespace. A downstream phase consumes upstream
artifacts by stable reference and never repairs, rewrites, or regenerates them.
This prevents an investigation agent from silently changing the evidence it is
supposed to evaluate.

### 2.3 Determinism around model reasoning

Models are used for interpretation and adversarial reasoning. Deterministic code
owns paths, IDs, budgets, schema validation, normalization, aggregation, hashes,
fingerprints, run state, empty-result handling, and reporting. The deterministic
shell around model work makes results resumable and auditable.

### 2.4 Capabilities, not labels

A known issue is represented by what an attacker needs and gains, not merely by a
CVE, category, or title. This permits composition across evidence kinds and makes
impact-expansion a first-class operation.

### 2.5 Bounded work with explicit closure

Depth controls finite budgets. Fanout has a fixed concurrency ceiling and overflow
is queued. Every evidence record and campaign reaches a terminal disposition.
The system values a defensible closure because unresolved work is operationally
indistinguishable from dropped work.

### 2.6 Safe absence is valid state

Zero lockfiles, zero scanner matches, zero campaigns, zero synthesized findings,
and zero verifier tasks are valid outcomes. Deterministic finalizers produce the
required empty wrappers and manifests. No stage invents an item merely to make a
later stage run.

## 3. System boundary

```text
┌──────────────────────────── VulnOps repository ────────────────────────────┐
│                                                                            │
│  target/<repo>             Immutable audit input                           │
│  context/                  Optional untrusted operator input                │
│       │                                                                    │
│       ├──────────── read-only source reads ───────────────┐                 │
│       │                                                   │                 │
│       └── fingerprint ──> identity/integrity gates        │                 │
│                                                           ▼                 │
│  .harness/                                      scans/<repo>/runs/<run>/    │
│  ├─ audit-context.json                          ├─ canonical evidence       │
│  ├─ contained homes/caches/temp                 ├─ phase manifests          │
│  ├─ tool probes                                 ├─ task ledger              │
│  └─ codegraph/<run>/project snapshot            └─ final reports            │
│             │                                                              │
│             └── writable index and typed queries                            │
│                                                                            │
│  bins/ + scripts/             deterministic execution and validation        │
│  .omp/agents + .omp/skills    model behavior and reusable doctrine           │
│  schemas/v2                   canonical artifact contracts                  │
└────────────────────────────────────────────────────────────────────────────┘
                         │
                         └── only permitted audit network path:
                             configured LLM endpoint
```

The target is never a workspace. Agents may read it, but all writes belong under
`scans/` or `.harness/`. Containment helpers relocate homes, caches, and temporary
state so third-party tools do not leak runtime files into operator or target
directories.

`context/` is a second read-only input boundary. Its deterministic inventory is
limited to 1,024 accepted UTF-8 text files and 16 MiB; symlinks are not followed,
and unsupported or excess inputs close Recon as degraded with explicit warnings.
The run identity binds paths, sizes, hashes, and acceptance decisions. Raw bytes
are never copied into canonical artifacts or packages.

### 3.1 Offline distribution boundary

The offline release is built on the matching target platform from a clean
worktree. A strict JSON lock binds every downloaded tool and OMP native-addon
archive to an immutable URL, version, byte size, and SHA-256. The OSV snapshot
lock independently binds all lockfile-relevant ecosystems: CRAN, Go, Hackage,
Hex, Maven, NuGet, Packagist, Pub, PyPI, RubyGems, crates.io, and npm. Package
preparation is the only step allowed to download those inputs.

Normal OSV synchronization is lock-preserving. Since the canonical upstream
archive names are mutable, creating a new pin requires the explicit
`fetch-osv-db.sh --refresh-lock <snapshot-id>` maintenance path. That path stages
and validates all twelve downloads before publishing databases and atomically
replacing the lock last; interruption therefore fails closed against either lock
instead of accepting a mixed snapshot.

The builder stages an explicit Git inventory, substitutes the example
configuration by default, installs locked tools, copies the already verified
local OSV snapshot, revalidates every input, and emits a normalized tar/gzip
archive. Its manifest records every immutable regular file
and symlink with type, mode, size, and hash; configuration and runtime output
paths are explicitly mutable. A relocation smoke test extracts into a different
path, compares the complete inventory, starts every binary (including OMP with
its separately shipped native addon), validates the entire OSV snapshot, and
runs setup verification before the archive or chunks are published.

The staged runtime uses the same config-driven capability surface as a source
installation. The archive includes the optional isolation integration scripts
but does not bundle Bubblewrap itself. Its default configuration therefore uses
policy-only agent egress and disables reproduction, while operators may select
enforced egress or safe reproduction when the destination supplies a functionally
supported Bubblewrap installation. The package manifest records dependency-
complete offline installation and configured runtime policy; it does not freeze
network or reproduction capabilities.

Chunks are platform-namespaced and described by a non-executable JSON manifest.
Reconstruction validates exact ordered names, per-chunk hashes and sizes, rejects
extra parts, and verifies the rebuilt archive hash. SHA-256 provides integrity,
not publisher authenticity; no signing authority is claimed.

The distribution boundary does not install a network sandbox or inject an OMP
network-denial profile. OMP retains normal access to its configured provider,
including subscription-backed providers. Audit execution is designed not to
depend on non-LLM online resources, because they may be unavailable on the
destination, but the package format does not enforce that assumption. Any
configured operating-system egress boundary remains explicit run identity.

## 4. Control plane and data plane

VulnOps is easier to reason about as two cooperating planes.

### 4.1 Control plane

The control plane consists of:

- `config.toml` and the environment generated from it;
- `.harness/audit-context.json`, the path and selector authority;
- `run-manifest.json`, the run identity and phase state machine;
- `task-ledger.json`, task attempts and terminal outcomes;
- phase manifests, which describe inputs, outputs, coverage, warnings, errors,
  tool versions, and terminal status;
- strict JSON schemas; and
- configuration, phase, and whole-scan validators.

The control plane decides whether work is compatible, complete, and safe to
promote. It never manufactures a security conclusion.

Deterministic Tool Collection uses `ok` for every contract-valid scanner result,
including findings and normal deduplication. Match occurrences and unique
normalized records are separate coverage counts, not health warnings. There is
no successful degraded state for this phase; deterministic contract violations
fail closed.

Model-owned top-level phases are supervised OMP jobs. The lead captures one job
ID per stable phase task, observes that job through the OMP job lifecycle, and
enforces the depth-specific deadline stored in audit context. A job is not
successful merely because files appeared or an IRC message arrived: it must
terminate with a schema-valid yield and then pass the phase validator. IRC carries
only bounded stage transitions and peer questions.

### 4.2 Evidence data plane

The data plane carries:

- repository structure and security surfaces;
- operator-context metadata and concise Recon-derived observations;
- normalized tool observations and receipts;
- SAST candidates, validation results, closures, and coverage;
- canonical evidence records and attack primitives;
- campaigns, graph query receipts, and terminal results;
- synthesized findings and independent verdicts; and
- final sanitized report data.

Stable IDs and artifact references connect these structures. Evidence bodies are
not copied between phases.

## 5. Run identity, initialization, and resume

Initialization discovers exactly one Git repository below `target/`, verifies the
required binaries through a functional probe, computes repository identity, and
creates an isolated run directory.

The complete compatibility identity is:

```text
repository path
+ commit
+ exact working-tree fingerprint
+ operator-context inventory fingerprint and limits
+ depth
+ reproduction mode
+ offline-package manifest and OSV snapshot identity
+ agent-egress mode and enforcement backend
+ normalized primary selector
+ exact orchestrator, task, slow, and smol role selectors
+ normalized verifier selector
+ workflow identity
+ harness contract fingerprint
+ resolved SAST budget snapshot
```

Only the current incomplete run resumes when immutable target and model/policy
identity matches. `complete` is closed; `failed` and interrupted executions are
recoverable states. A changed role selector creates a new run even if the
underlying model happens to be similar. A harness-contract or resolved-budget
change starts a recorded recovery generation inside the same audit.

The harness contract fingerprint binds schemas, planning and aggregation code,
validators, recovery code, and phase-agent contracts. Each successful phase also
receives a deterministic whole-directory seal. Recovery preserves those bytes,
removes the failed phase and every downstream phase, resets their task entries,
and resumes from the first unfinished phase. When the harness contract changed,
whole-scan validation accepts a retained prior-contract phase only by verifying
its recorded seal and prior successful phase state; rerun phases must pass current
semantic validation.

### 5.1 Why commit alone is insufficient

A Git commit does not capture ignored files, uncommitted changes, generated source,
or modified tracked files. `target-fingerprint.py` covers the working tree used by
the audit. The fingerprint is rechecked after graph snapshot creation, after every
phase, and at whole-scan validation. Any mismatch invalidates the run.

Operator context is supporting evidence, not a vulnerability authority. It may
refine intended behavior, environmental assumptions, Campaign Planning, and
Intrusion hypotheses. A finding may cite its derived observation only alongside
source or canonical tool evidence, and target evidence prevails on conflict.

### 5.2 State machines

Run statuses are:

```text
initialized → running → complete
                    ├→ degraded
                    └→ failed
                         │
                         └→ recover → initialized
```

Phase statuses are `pending`, `running`, `ok`, `degraded`, `failed`, or `skipped`.
Task statuses are `pending`, `running`, `ok`, `degraded`, `failed`, or `shallow`.
Updates are atomic and timestamped. A phase manifest is validated before its
status is synchronized into the run manifest.

The state updater enforces phase order and mutual exclusion in code. A top-level
task has one stable ID, at most two real attempts, and may run only with its owning
phase. Successful artifacts must be existing scan-relative files and the owning
phase directory is sealed after validation; failed tasks have null artifacts and
bounded errors. Stopping closes every running phase/task. Recovery never restarts
or mutates successful upstream phases: it retains their seals and discards the
failed/downstream suffix. The two-attempt ceiling applies per recovery generation.

`degraded` is not a schema escape hatch and does not mean “less than exhaustive.”
It represents structurally valid output with a material loss of audit capability,
such as `needs_environment` or a failed SAST cell. Expected bounded behavior—tool
deduplication, findings-present scanner exits, normal negative results, and
configured depth/task/question/round/attempt ceilings—remains `ok`. Malformed or
inconsistent output fails.

The semantic phase validator derives the permitted status from canonical
coverage rather than trusting a producer-supplied label. Recon, healthy Tool
Collection, and Campaign Planning close `ok`. Intrusion, Synthesis, Final
Verification, and Report may close `degraded` only when their canonical coverage
contains `needs_environment`. SAST may close `degraded` only for a failed cell or
environment-required verification.

## 6. Canonical workflow

```text
Recon
  │
  ├──────────────┐
  ▼              ▼
repository    Tool Collection: Wraith + Poltergeist
model            │
  │              │ normalized records + healthy receipts
  └──────┬───────┘
         ▼
SAST: threat model → deterministic hunt plan → batched hunts
      → validation → alternate traces → optional reproduction → coverage
         │
         ▼
Campaign Planning: evidence records → typed primitives → bounded campaigns
         │
         ▼
Intrusion: source investigation + typed Codegraph navigation
         │            exactly one terminal result per campaign
         ▼
Synthesis: root-cause deduplication + impact expansion + chain closure
         │
         ▼
Independent Verification: fresh context, every finding, every chain step
         │
         ▼
Deterministic Report: final accepted findings only
```

### 6.1 Orchestration and concurrency model

The main OMP process owns the workflow and launches each model-owned phase as one
supervised asynchronous job. Job identity, terminal state, structured yield, and
the phase validator form the completion contract. Deadlines are stored in audit
context and a timeout closes the stable attempt rather than leaving an orphaned
phase. IRC is limited to genuine progress transitions and peer questions.

Parallelism is applied within phases where workers have disjoint ownership:

| Area | Decomposition | Bound |
|---|---|---:|
| Recon | Overview, trust-boundary, and input-surface research | 3 workers |
| Tool Collection | Wraith invocations plus Poltergeist | 4 processes |
| SAST deep dives | Hash-bound hunt-task packets | 4 quick / 8 balanced / 16 full |
| SAST verification | Deduplicated validation candidates | 4 quick / 8 balanced / 12 full |
| Safe reproduction | Eligible source-verified candidates | Configured `max_parallel` |
| Intrusion | Planned campaigns | Depth-bounded waves |
| Final Verification | Synthesized findings | Depth-bounded waves |
| Linked remediation | Eligible final accepted findings | 4 quick / 8 balanced / 12 full |

OMP nested task batches are synchronous from the coordinator's perspective, but
the workers within a batch run concurrently. Queue overflow is executed in later
waves and never silently discarded. Coordinators can spawn only their declared
specialists, leaf workers do not create unbounded descendants, and stable IDs
prevent a second task from representing already-active work.

Top-level phases do not overlap. Recon, Tool Collection, SAST, Campaign Planning,
Intrusion, Synthesis, Final Verification, and Report form a strict evidence
pipeline: downstream work requires the preceding immutable phase to validate.
Campaign Planning and Synthesis therefore remain single-agent consolidation
authorities. Deterministic scanning, bookkeeping, aggregation, empty paths, and
reporting use no model agents.

The OMP advisor is disabled independently of task execution. It would add a
background review loop without owning a VulnOps artifact or gate; disabling it
does not affect asynchronous jobs, phase coordinators, or canonical worker
fanout.

## 7. Phase ownership and contracts

| Phase | Reads | Sole writes | Key promotion gate |
|---|---|---|---|
| Recon | Target source | `repo-context/` | Complete source-backed repository and surface model |
| Tool Collection | Recon dependency files, target source | `tool-collection/` | Healthy parser receipt, exact counts/hash, sanitized normalized record |
| SAST | Recon, tool evidence, target source | `sast/` | Adversarial source validation and coverage disposition |
| Campaign Planning | All validated upstream evidence | `campaign-planning/` | Resolved evidence IDs, typed primitives, bounded nonfabricated plan |
| Intrusion | Evidence index, campaign plan, target, graph snapshot | `intrusion/` | One terminal result per planned campaign; valid graph receipts |
| Synthesis | Evidence, SAST, intrusion | `synthesis/` | Complete finding contract and closed primitive transitions |
| Final Verification | Synthesized findings and cited source | `final-verification/` | Correct verifier identity and fresh independent verdict |
| Report | Final verified findings | `report/` | Deterministic sanitized projection and matching counts |

Linked remediation is intentionally not a ninth row. It begins only from a
completed, whole-scan-valid audit and writes to a separate `remediations/` root.
The report remains the final audit authority; remediation is an optional
developer artifact linked by run ID, report/finding hashes, and target
fingerprint.

The phase directory itself is part of the authority model. A worker artifact
written outside its assigned directory is invalid even if its JSON is otherwise
well formed.

### 7.1 Why SAST and Intrusion are separate phases

SAST and Intrusion both inspect source, but they answer different questions and
own different evidence transitions.

| Dimension | SAST hunting | Intrusion |
|---|---|---|
| Primary question | Which individual security flaws exist across the modeled attack surface? | What can an attacker accomplish from the accumulated evidence? |
| Planning unit | Source-backed security question mapping an attack-class lens to one concrete flow | Falsifiable campaign built from evidence records and typed primitives |
| Search shape | Broad and coverage-driven | Narrow and hypothesis-driven |
| Starting inputs | Recon, tool evidence, threat model, and target source | Evidence index, campaign plan, SAST findings, target source, and graph snapshot |
| Main evidence transition | Candidate source trace → adversarially verified root cause or terminal disposition | Starting capability → validated downstream consumer, boundary transition, expanded impact, new root cause, or closure |
| Composition | Establishes individual vulnerability primitives | Tests whether primitives compose and whether output capabilities satisfy later prerequisites |
| Terminal authority | Verified findings, rejected/deferred candidates, and coverage dispositions under `sast/` | One `candidate`, `closed`, `rejected`, or `needs_environment` result per campaign under `intrusion/` |

This separation prevents campaign work from becoming an unbounded second SAST
pass. SAST spends its bounded budget establishing broad source coverage and
validating individual root causes. Campaign Planning then converts all validated
evidence—not only SAST findings—into prerequisites, gained capabilities,
boundaries, and concrete hypotheses. Intrusion follows only those bounded
hypotheses to test downstream consumption, control bypass, capability closure,
and materially greater impact.

Codegraph has a deliberately stronger procedural role in Intrusion: every planned
typed question must be executed and receipted. Its evidentiary role remains weak,
however. Graph output is navigation context in both phases and cannot establish
attacker control, unsafe behavior, satisfied exploit conditions, or impact without
independent source evidence.

The output boundary is equally important. A source-verified SAST result may become
a confirmed primitive, while an Intrusion worker may only return a terminal
campaign result and bounded candidates or new primitives. Intrusion does not
rewrite SAST evidence or publish findings. Synthesis alone decides whether the
combined evidence supports an independently exploitable known finding, a new root
cause, an impact expansion, or a capability-closed multi-step chain.

## 8. Recon architecture

Recon creates the common repository model used to prevent every later worker from
rediscovering project structure independently. It decomposes work into focused
overview, trust-boundary, and input-surface investigations and consolidates them
into:

- `repo.md`, a bounded human-readable repository brief;
- `repo-context.json`, projects, languages, dependency files, build/test hints,
  source areas, and architectural metadata;
- `security-surfaces.json`, stable entrypoints, trust boundaries, inputs, assets,
  and cross-references; and
- research records beneath `repo-context/research/`.

Security surfaces become immutable after Recon validation. Campaign Planning may
reference them; Intrusion may query and reason from them; no downstream phase may
rebuild them in a reduced shape.

This ownership rule matters because a changed surface model changes the scope of
everything downstream. Allowing a planner to regenerate it would make campaign
results impossible to attribute to the originally validated reconnaissance.

`finalize-recon.py` owns the machine handoff to Tool Collection. It ignores draft
dependency arrays, walks the target without following symlinks or generated/vendor
trees, discovers every input supported by the bundled offline scanner, assigns
each input to the most specific compatible project, atomically rewrites those
arrays, and writes the Recon phase manifest. Semantic validation independently
repeats discovery and requires exact inventory equality. Models describe
architecture; they do not decide which files a binary receives.

## 9. Tool Collection architecture

Tool Collection is deterministic and uses no model workers. `collect-tools.py`
revalidates immutable Recon, extracts its deterministically finalized inventory,
starts Wraith invocations and the Poltergeist scan concurrently, validates their
individual receipts, merges normalized SCA records, finalizes the phase, and
removes temporary tool work after success.

All scanner output first lands under `.harness/tool-work/<run-id>`. Schemas,
parse states, counts, and normalized hashes must pass in staging before the
complete set is atomically published into `tool-collection/`. Raw scanner files
never cross this boundary. Infrastructure failure remains fail-closed, but a
malformed model handoff is prevented upstream rather than accepted as normal.

Concurrency is capped at four invocations. This eliminates sequential scanner
latency without introducing model scheduling overhead.

### 9.1 Functional readiness

`probe-toolchain.sh` establishes behavior, not presence:

| Component | Fixture | Required observation |
|---|---|---|
| OMP | Contained help invocation | Process is runnable inside the harness home |
| Wraith | Known affected Go dependency | At least one normalized offline advisory |
| Poltergeist | Synthetic token assembled by the probe | At least one candidate with exact `<redacted>` persistence |
| Codegraph | Small caller/callee Go program | A real meaningful relationship and matching normalized hash |

An installed binary that emits a changed, empty, or malformed envelope fails
readiness before model budget is spent.

### 9.2 Wraith contract

Wraith is invoked for each validated lockfile/dependency file. Exit statuses that
represent a clean or findings-present scan are accepted by the wrapper; execution
and parse failures are not. The adapter consumes the actual package, result, and
vulnerability envelope and produces bounded records containing package, installed
version, advisory identifiers, affected ranges, and source lockfile references.

The normalized count must agree with the parsed envelope. A `null` result body is
acceptable only when the associated counts are zero. Before each invocation the
wrapper verifies the exact ecosystem database size, hash, ZIP integrity, and
snapshot identity. Each receipt includes tool version, package count, database
identity, parse status, normalized result count, warnings, and SHA-256 of the
persisted artifact.

Conan inputs are not passed to Wraith because OSV has no corresponding offline
ecosystem archive. Maven manifests are scanned with their offline database, while
the inability to perform remote transitive resolution is explicit. Both become
structured coverage-gap records, evidence-index gaps, and report limitations
rather than silent clean results.

Advisories enter the evidence index as candidate vulnerability primitives. They
do not become final dependency findings until source review proves an affected use
is reachable.

### 9.3 Poltergeist contract

Poltergeist accepts both clean and matches-found outcomes as successful scanner
execution. The adapter strips permitted log prelude, parses the real structured
body, converts paths to target-relative locations, assigns stable IDs, and replaces
every detected value with exactly `<redacted>` before persistence.

No partial value, prefix, entropy sample, or raw value hash is retained. Multiple
match events may normalize to fewer unique records; occurrence and unique
candidate counts preserve both facts without turning deterministic deduplication
into a warning or degraded state.

Secret records are credential candidates. Promotion requires an exposure path and
a supported validity state; the scanner match alone is context.

### 9.4 Why raw output is excluded

Raw scanner output is high-volume, unstable, and may contain sensitive material.
Persisting it would expand the breach surface and allow final reports to depend on
tool-specific formats. Normalized bounded records retain what later reasoning can
use, while receipts retain enough metadata to prove that normalization came from a
healthy execution.

## 10. SAST architecture

SAST combines repository-specific threat modeling with deterministic coverage
planning and model-based source investigation.

### 10.1 Threat model

The threat model identifies subsystems, entrypoints, boundaries, risk, applicable
attack classes, and repository-specific classes. Applicability is expressed only
through source-backed hunt mappings. Each mapping binds a class to concrete
surfaces, threats, assets, attacker, entrypoints, boundaries, source files, a
security question, stop conditions, priority, rationale, and evidence. Attack
doctrine lives in reusable skills; the phase agent coordinates work but does not
duplicate specialist methodology in its prompt.

### 10.2 Contextual hunt cells

`build-hunt-plan.py` creates exactly one cell per declared hunt mapping. It does
not construct a subsystem × surface × attack-class cross-product. A selected
class with no contextual mapping fails threat-model validation rather than
creating generic research work.

Every cell retains the complete mapping context, stable ID, owner, methodology,
specialist lenses, priority, evidence, status, and disposition rationale. Multiple
surfaces may belong to one cell only when they form one concrete ordered source
flow.

Dependency enumeration and secret enumeration remain owned by Tool Collection.
When those tools produced validated output, their cells are marked
`tool_satisfied`; SAST does not pay model cost to repeat scanner work.

### 10.3 Batching without losing coverage

Up to four cells are placed in one hunt task only when they share a subsystem,
domain, overlapping source files, and an entrypoint, boundary, or surface. The
same attack class is not repeated within a batch. This lets compatible questions
share source review without treating arbitrary cells as related.

Packets are bounded in bytes and contain the authoritative task plus its exact
cell definitions. Repository-wide trust boundaries, entrypoints, and unrelated
scanner references are not copied into every packet. Essential context is never
silently truncated; an oversized packet fails planning and must be split.

Each worker receives a task-specific file beneath `sast/hunt-tasks/`, not the
aggregate hunt plan. The packet embeds the exact task, exact cells, and SHA-256 of
the plan that produced it. SAST validation requires an exact packet set and
rejects stale, orphaned, oversized, or hash-mismatched work before promotion.

### 10.4 Depth and fanout

| Depth | Hunt concurrency | Maximum tasks | Maximum questions | Gapfill rounds | Verification concurrency |
|---|---:|---:|---:|---:|---:|
| quick | 4 | 12 | 24 | 1 | 4 |
| balanced | 8 | 32 | 64 | 2 | 8 |
| full | 16 | 64 | 128 | 3 | 12 |

Initial work is scheduled risk-first and round-robin across subsystems so one
large critical subsystem cannot consume the whole budget. One quarter of the task
budget is reserved for gapfill when gapfill is enabled. Gapfill schedules
evidence-backed rabbit holes first, cell-specific shallow/failed retries second,
and initially deferred contextual cells last. Overflow remains explicitly
deferred. Separate task and question ceilings prevent batching from hiding
unbounded analysis scope. Task attempts are bounded.

After the last gapfill round, the finalizer converts remaining `deferred` and
`shallow` cells to `depth_limited`. This is a terminal coverage disposition for
the selected audit depth, remains visible to downstream gap planning and the
report, and does not degrade the phase. Only failed cells or environment-required
verification degrade SAST.

### 10.5 Aggregation, deduplication, and alternate traces

Each worker returns exactly one `cell_results` row per assigned cell. Finding,
clean, not-applicable, shallow, and failed states carry cell-specific review
evidence. Candidate IDs must match the cell rows, and candidates may reference
only cells with the same attack class. Reviewing an unassigned file or entrypoint
fails the worker contract; adjacent work must be returned as a contextual rabbit
hole.

`finalize-sast.py` validates raw hunt results, derives outcomes from the per-cell
rows, aggregates candidates, clusters by root cause, creates the validation queue,
and builds the coverage ledger. One candidate in a batched task cannot mark its
unrelated sibling cells as findings. A
preferred trace is not allowed to suppress a valid alternate: when verification
rejects the preferred member of a cluster, `--advance-alternates` promotes the
next bounded alternate for verification.

Gapfill is a real feedback loop:

```text
coverage ledger / rabbit holes
          │
          ▼
build new bounded tasks → execute tasks → aggregate outcomes
          │
          └──────── repeat until no work or budget exhausted
```

Calling the planner repeatedly without executing and aggregating new tasks is not
gapfill and is forbidden by the phase contract.

### 10.6 Promotion states

Source verification may establish a finding, reject it, defer it, or identify that
environment evidence is required. Only established source findings become
confirmed vulnerability primitives. Environment-required candidates remain
candidates and cannot be silently upgraded.

## 11. Canonical evidence index

Campaign Planning begins by constructing `evidence-index.json`. It is the bridge
between heterogeneous observations and attacker-oriented reasoning.

### 11.1 Evidence records

Records may originate from:

- `recon`
- `sca`
- `secret`
- `sast`
- `coverage`
- `hardening`
- `positive_pattern`
- `reproduction`
- `tool_warning`

Every record has a stable `E-` ID, source kind and source ID, canonical artifact
reference, bounded summary, files, and disposition. Dispositions are `promoted`,
`closed`, `rejected`, `needs_environment`, or `unresolved`.

The index intentionally retains closures, warnings, positive controls, coverage
gaps, and environment limits. Red-team planning benefits from knowing where
controls held and where evidence is incomplete; dropping negative evidence would
cause repeated work and biased campaign selection.

### 11.2 Attack primitives

Primitive types are:

- `vulnerability`
- `credential`
- `access`
- `control_gap`
- `state_transition`
- `environment_constraint`

Trust levels are:

- `confirmed`: the capability is established by acceptable evidence;
- `candidate`: useful hypothesis that must be validated before reliance; and
- `context_only`: navigation or planning context that cannot serve as an
  established exploit step.

Each primitive contains source-record IDs, prerequisites, capability gained,
boundary, reachable assets, conditions, and evidence references.

The capability representation is the core red-team abstraction. It permits a
source flaw, dependency issue, credential, access path, and state transition to be
compared through what they enable rather than through incompatible scanner labels.

## 12. Campaign Planning architecture

`build-campaign-plan.py` deterministically selects bounded initial campaigns. The
campaign-planning model reviews actual source and may improve hypotheses, typed
graph questions, validation method, stop conditions, and expected added value. It
may not change stable IDs, canonical references, or lane budgets.

### 12.1 Lane strategy

`primitive_led` campaigns pair actionable primitives where possible, then examine
individual primitives for downstream consumers. This is where known findings
become red-team leverage.

`gap_driven` campaigns examine uncovered boundaries, state transitions, coverage
holes, and repository-specific risks for order, replay, race, parser differential,
fallback, and implicit-trust failures.

`direct_validation` campaigns establish whether candidate dependency, credential,
or source primitives are active and reachable and then inspect at least one
downstream consumer.

The deterministic lane ceilings are 2/1/1 for quick, 5/3/2 for balanced, and
10/7/3 for full. Fewer eligible inputs yield fewer campaigns.

### 12.2 Campaign contract

Every `CAM-###` contains:

- starting evidence IDs;
- primitive IDs;
- attacker capability and target boundary;
- a falsifiable hypothesis;
- target-relative source files;
- zero or more typed graph questions using `query`, `callers`, `callees`, `impact`,
  or `affected`;
- validation method;
- explicit stop conditions;
- expected added value; and
- initial `unresolved` disposition.

Files and IDs must resolve before Intrusion begins. Questions are never generic
instructions to “use the graph”; they name an operation, subject, and reason.

## 13. Codegraph architecture

Codegraph's first job is to index the target's source. It does so through a
run-local copy because the upstream tool stores `.codegraph` state inside the
indexed project. Pointing it directly at the target would violate immutability.

### 13.1 Snapshot creation

`setup-codegraph.sh` copies the target to
`.harness/codegraph/<run-id>/project`, excluding `.git`, `.codegraph`, and
`.harness`, and then runs `codegraph init` on that snapshot.

Target-internal symlinks are resolved and remapped to equivalent paths inside the
snapshot. Broken symlinks and symlinks escaping the repository are rejected. The
target fingerprint is checked immediately afterward to prove snapshot preparation
did not mutate the source checkout.

The snapshot is immutable audit input from the perspective of later phases; only
Codegraph's own index lives there. It is not a second source of truth for files.

### 13.2 Typed query adapter

`codegraph-adapter.py` supports five operations:

| Operation | Intended use |
|---|---|
| `query` | Bounded symbol/text-like structural search |
| `callers` | Identify inbound call relationships |
| `callees` | Identify outbound call relationships |
| `impact` | Explore downstream impact from a subject |
| `affected` | Explore affected symbols or paths |

Every query includes `-p <snapshot-project>`, parses the real JSON envelope, and
emits a bounded `context.json` plus sibling `receipt.json`. Nodes are capped at 500
and edges at 1,000. The receipt records operation, subject, tool version, status,
parse status, result count, normalized hash, meaningful flag, and warnings.

### 13.3 Meaningful result rule

A context is meaningful when it contains a real relationship edge or a result
node—not merely the subject echoed back by the tool. Every executed campaign query
must appear in `graph_query_receipts`. Only meaningful receipts may also appear in
the `graph_evidence_refs` subset or a synthesized finding.

This rule does not prevent indexing or querying. It prevents an empty or
self-referential response from being cited as corroboration.

Graph context can answer “where should source review continue?” It cannot by itself
answer “is attacker input controlled?”, “is the behavior unsafe?”, “are conditions
met?”, or “what impact follows?” Those claims require source and, where necessary,
contained reproduction evidence.

## 14. Intrusion architecture

Intrusion creates one bounded worker per planned campaign. Workers receive stable
campaign IDs, canonical evidence, source scope, and typed graph questions. They
read source first, use Codegraph for navigation, and do not alter planning or Recon
artifacts.

### 14.1 Terminal result invariant

Every campaign produces exactly one result with status:

- `candidate`: at least one complete source-backed candidate exists;
- `closed`: the hypothesis was investigated and disproved or bounded;
- `rejected`: the campaign premise or evidence is invalid;
- `needs_environment`: indispensable deployment or runtime evidence is absent.

Candidate status requires candidates; other statuses forbid them. Aggregate result
order must exactly match plan order. Missing, duplicate, orphan, or malformed
results fail finalization.

### 14.2 New primitives and candidates

An investigation may add `NP-` primitives with the same typed prerequisite,
capability, boundary, asset, condition, trust, and evidence structure used by the
canonical index. A candidate must include:

- stable `IC-` ID and finding kind;
- attacker model;
- concrete root-cause locations;
- ordered entrypoint-to-sink trace;
- conditions and impact;
- evidence references and primitive IDs; and
- source, dynamic, or environment-required validation level.

Environment-required hypotheses cannot masquerade as candidates with established
source proof. Graph-only candidates fail.

### 14.3 Empty campaign plan

When the campaign plan contains no campaigns, no intrusion worker is spawned.
`finalize-intrusion.py` emits an empty `results` wrapper, empty bounded summary,
and `ok` phase manifest. It does not fabricate graph questions or rebuild security
surfaces to create work.

## 15. Synthesis architecture

Synthesis is the sole pre-verification finding authority. It reads the evidence
index, SAST verified findings, and terminal intrusion results. It does not simply
concatenate them.

The synthesis agent:

- deduplicates standalone issues by root cause;
- preserves independently exploitable known findings;
- separates newly proven impact expansions;
- promotes complete new root causes and cross-evidence discoveries;
- constructs chains only when capability transitions close; and
- records closure rationale and canonical source references.

### 15.1 Finding origins

Findings are classified as:

- `standalone_known`
- `known_impact_expansion`
- `composite_chain`
- `independent_discovery`
- `cross_evidence_discovery`

Origin is an analytical property, not a severity modifier. A standalone known
issue may be critical; a novel observation may be informational.

### 15.2 Chain proof

A chain must contain at least two ordered primitive steps. For every adjacent pair:

```text
left.output_capability == right.input_capability
```

Each step identifies its crossed boundary and evidence. The composition must
establish distinct exploitability, a new boundary crossing, or materially greater
combined impact. Merely listing vulnerabilities in sequence is not a chain.

A valid chain may consist entirely of known primitives. The added value is the
newly established transition and combined effect.

### 15.3 Finding-kind gates

All findings require the common attacker, behavior, root cause, trace, condition,
impact, remediation, validation, provenance, and closure fields.

Dependency findings additionally require advisory ID, package, installed version,
affected use, and `reachable` status. Secret findings require exact `<redacted>`,
location, exposure path, and validity of `confirmed_format` or `likely` for
promotion. Chain findings require the primitive-step proof above. Non-chain
findings may not carry chain steps.

When no candidate source exists, `empty-synthesis.py` produces the canonical empty
wrapper and phase manifest without invoking a synthesis model.

## 16. Independent verification architecture

Final Verification fans out one fresh-context verifier task per synthesized
finding. OMP resolves the worker through a generated per-agent override bound to
the configured verifier selector. Its `pi/slow` front-matter role is only a
runtime-supported fallback; configuration validation requires the override to
match exactly and verifies the selected model and thinking effort against OMP's
catalog before an audit can start. The worker assumes the claim is wrong until
cited source proves every material field.

Possible verdicts are `verified`, `corrected`, `rejected`, and
`needs_environment`. A correction must contain a complete corrected finding plus
field-level before/after reasons. A rejection remains visible in the final wrapper
with its verification reference; it is not rendered as an accepted finding.

For a chain, the verifier records one ordered primitive result per step and checks
every transition. A chain cannot be accepted because its terminal impact seems
plausible while one intermediate capability is unsupported.

### 16.1 Model attribution and diversity

The primary selector owns source-validation attribution. The configured verifier
selector must appear in every independent result. `model_diversity` compares the
normalized underlying model identities and is stored as a JSON boolean in the
run, context, verifier results, final wrapper, and every accepted finding. Known
thinking-effort suffixes are removed for this comparison, so high versus xhigh on
the same model is not misrepresented as independent model diversity.

The validator rejects wrong-model results or inconsistent diversity metadata.
When normalized model identities match, the report records the limitation; it
does not misrepresent fresh context as model diversity.

When synthesis is empty, deterministic finalization emits empty accepted and
rejected arrays with the correct diversity value. No verifier tasks are fabricated.

## 17. Safe reproduction

Safe reproduction is optional and configuration-controlled. `off` means no target
code is run. `safe` permits execution only through
`scripts/run-safe-reproduction.sh` after a successful functional Bubblewrap
probe. Offline packages include the integration scripts but do not bundle or
require Bubblewrap; selecting `safe` therefore requires a supported Bubblewrap
installation on the destination.

### 17.1 Support boundary

The supported backend is Linux Bubblewrap. Readiness is based on a real namespace
and isolation probe, not the presence of the executable. Kernel policy, container
restrictions, or missing user namespaces may make bubblewrap unavailable even when
installed.

An unavailable backend yields environment-required evidence. There is no Docker,
macOS, or direct-shell fallback.

### 17.2 Resource and output controls

The wrapper enforces configured wall time, CPU time, memory, process count, output
size, and parallelism. Sanitized tests and draft patches may be retained in the
designated reproduction/fix directories. Exact proof tokens and raw command output
are not report inputs.

Integration tests run only when the same functional probe succeeds. Unit tests
always retain fail-closed refusal coverage.

## 18. Reporting and information minimization

`render-report.py` is deterministic and reads only
`final-verification/findings.json`. No reporting agent can reinterpret rejected or
intermediate evidence at the final stage.

The JSON and Markdown reports include bounded titles, finding kind, origin,
severity, risk score, confidence, verdict, impact, remediation, and canonical
evidence references. Summary counts are recomputed from accepted findings and
validated against the final artifact.

Sanitization removes sensitive or proof-like tokens from presentation fields.
Whole-scan validation also enforces artifact-size limits and scans persisted
artifacts for forbidden secret patterns. Information minimization is an
architectural property, not a user-selectable report option.

### 18.1 Linked production remediation

The post-audit remediation launcher revalidates the completed scan and requires
the current target to match its exact fingerprint. A deterministic planner then
copies each accepted final finding into a bounded, hash-bound packet with its
canonical artifact and source references. Obvious non-code actions, secrets, and
environment-required claims close as manual work without invoking a patch agent.

One worker handles each eligible finding in a disposable original/working pair
under `work/`. The worker cannot write the target or scan and cannot execute
code. A deterministic publisher computes the Git diff, rejects binary, symlink,
test/fixture/example/documentation, secret-bearing, escaping, oversized, or
incomplete changes, and runs read-only `git apply --check` against the exact
audited tree. Only then is a `.patch` atomically published.

There is no independent patch reviewer in this mode. `patch_ready` therefore
means structurally safe and applicable, not semantically proven or regression
tested. The aggregate and summary always expose that limitation. The harness
never applies a patch or performs repository delivery actions.

## 19. Validation architecture

Validation is layered because JSON-schema correctness alone cannot establish
workflow integrity.

### 19.1 Readiness validation

`validate-config.sh` verifies:

- the exact supported configuration keys and value bounds;
- primary, tiered role, and verifier selector syntax;
- custom-provider endpoint/auth requirements;
- generated role mapping and canonical agent/spawn graph;
- every strict platform asset, the OMP native runtime, and full package inventory;
- registration of every selected custom model;
- required binaries, scripts, schemas, agents, and every locked OSV database;
- absence of forbidden workflow/report/config surfaces;
- disabled URL/update/discovery surfaces and the configured agent-egress backend;
- deterministic reporting ownership; and
- real functional tool output.

Unknown configuration options fail. This prevents misspellings and dead knobs from
creating the appearance of policy without runtime effect.

### 19.2 Phase validation

`validate-phase.sh` applies schema and semantic checks for one phase, validates its
manifest, and rechecks the target fingerprint. Semantic checks include:

- target-relative files exist and remain inside the repository;
- source IDs and artifact references resolve canonically;
- tool receipt counts and hashes match normalized output;
- hunt, validation, campaign, and result IDs are unique;
- campaign budgets and coverage counts agree;
- campaign results match the plan exactly;
- graph receipts are executed, hashed, and meaningful when cited;
- traces run from entrypoint through propagation to sink;
- dependency, secret, and chain kind-specific rules hold; and
- source validation names the primary selector.

### 19.3 Whole-scan validation

`validate-scan.sh` validates every phase and adds global invariants:

- workflow and run identity consistency;
- all required phases and tasks terminal;
- exact primary/verifier/diversity attribution;
- final verifier result completeness;
- final report counts and origin breakdown;
- reproduction references and hashes;
- redaction and forbidden sensitive-output patterns;
- bounded artifact sizes;
- absence of noncanonical phase directories; and
- exact phase-directory seals for retained recovery inputs;
- contiguous recovery history and recovery counts; and
- unchanged target fingerprint.

Only after this gate passes may the run be marked `complete`.

## 20. Failure semantics

| Condition | Required behavior |
|---|---|
| Target fingerprint changes | Fail the phase/run; never reconcile against changed source |
| Binary missing or functional probe fails | Fail readiness before audit work |
| Safe sandbox unavailable | Continue static work; classify required reproduction as `needs_environment` |
| Scanner clean result | Persist valid empty normalized artifact and healthy receipt |
| Scanner parse/count/hash mismatch | Fail Tool Collection |
| Model emits malformed or out-of-scope artifact | Repair/rerun within bounded attempts or fail task |
| Candidate evidence disproved | Record rejected/closed disposition |
| Deployment fact unavailable | Record `needs_environment`; do not promote to confirmed |
| Campaign worker missing/duplicate/orphan | Fail Intrusion finalization |
| Planned graph query unexecuted | Fail campaign finalization |
| Graph result empty or self-only | May be recorded as executed; may not be cited as meaningful evidence |
| No campaigns/findings | Use deterministic empty path and valid manifests |
| Verifier selector/model mismatch | Fail Final Verification/whole scan |
| Final counts or references disagree | Fail whole-scan validation |
| Failed or interrupted phase | Close the current execution; next initialization seals validated upstream phases, clears the failed/downstream suffix, and resumes there |
| Retained phase seal mismatch | Refuse recovery or whole-scan completion; never repair the retained bytes |

## 21. Efficiency and DRY design

The harness minimizes cost and duplicated reasoning through structural choices:

- Recon creates one shared repository model.
- Tool Collection runs scanners concurrently without model agents.
- Tool-owned attack cells are not repeated by SAST.
- Compatible contextual source hunts share one bounded packet while retaining
  validator-enforced per-cell coverage.
- Evidence bodies are stored once and referenced.
- Planning scripts create IDs, budgets, and initial hypotheses mechanically;
  models refine only the reasoning fields.
- One evidence index replaces phase-specific handoff summaries.
- One campaign result and one finding synthesis stage prevent repeated merges.
- Empty work is finalized deterministically.
- Independent verification is per finding, so parallelism scales with actual
  reportable work.
- Reporting performs no model call.

Depth budgets make marginal cost legible. Phase manifests expose actual work and
coverage, enabling empirical tuning without changing evidence rules.

## 22. Extensibility rules

### 22.1 Adding an attack doctrine

Add reusable methodology beneath `.omp/skills/`, reference it from the attack
taxonomy or repository-specific threat model, and keep phase scheduling behavior
in `.omp/agents/`. Do not copy doctrine into multiple agent prompts.

### 22.2 Adding a scanner

A scanner integration must provide:

1. a deterministic wrapper with contained runtime paths;
2. a functional fixture proving expected real output;
3. a bounded sanitizer/normalizer;
4. a strict normalized schema;
5. a receipt containing version, parse status, count, warnings, and normalized
   hash;
6. evidence-index mapping with explicit trust and disposition; and
7. phase and whole-scan semantic validation.

Binary presence or a model-authored summary is not an integration.

### 22.3 Adding a phase

A phase requires one clear output authority, schema, manifest, task ownership,
validator dispatch, run-state entry, zero-item behavior, and report/evidence
consumer. If its outputs duplicate an existing authority, extend that authority
instead of adding a phase.

### 22.4 Adding a model provider

Built-in OMP providers are selected directly. A custom provider must fit the one
configured OpenAI-compatible endpoint and register every selected custom model.
Introducing multiple endpoint/auth blocks requires an explicit architecture change
because endpoint identity, offline policy, bootstrap generation, and resume
identity would all need to expand together.

## 23. Canonical invariants

These invariants are non-negotiable:

1. The target is read-only and fingerprint-stable.
2. Runtime writes stay under `scans/` or `.harness/`.
3. Audit network access is limited to the configured model endpoint.
4. Every security claim resolves to source-backed canonical evidence.
5. Scanner, advisory, graph, or model output alone is insufficient proof.
6. Target execution occurs only through opt-in functional bubblewrap containment.
7. Raw output and sensitive values never enter durable scan artifacts or reports.
8. Every evidence record and campaign receives a disposition.
9. Fanout is bounded and overflow is queued.
10. Downstream phases never mutate upstream artifacts.
11. Synthesis is the sole pre-verification finding authority.
12. Final reporting reads independently verified findings only.
13. Primary and verifier identity are explicit, validated, and resume-critical.
14. Schema version `2.0` is the only artifact contract.
15. There is one workflow, one phase dispatch path, and one report authority.

Together, these choices make VulnOps more than a collection of security tools or
prompts. It is a controlled evidence system for adversarial software analysis.
