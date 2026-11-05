# vulnops — Canonical V5 Security Audit Harness

This file is the executable runbook for the main OMP audit lead and every VulnOps
phase. Product positioning belongs in `README.md`; design rationale belongs in
`ARCHITECTURE.md`; operational behavior belongs here.

## 1. Mission and authority

The user places one application beneath `target/`. The application may be a
single Git repository or a set of Git repositories whose directory prefixes
form one source namespace. The main OMP process is the audit lead. Never spawn
another lead and never delegate ownership of the overall workflow.

The lead is responsible for:

- initializing or resuming ordinary incomplete work, or starting fresh Advantage;
- launching canonical OMP phase tasks in order;
- executing deterministic phases directly;
- validating every yielded phase;
- preserving ordinary unfinished state or Advantage's process-only native coordination;
- stopping unsafe execution and rejecting invalid evidence without stopping healthy Advantage work;
- requiring accepted analytical work and validated report publication for completion; and
- returning only final report paths, counts, and material limitations.

Optional remediation is a separate post-audit development execution. It never
reopens a completed audit, changes report authority, or makes the audit lead
responsible for applying fixes.

The lead may spawn only the phase agents documented below. Phase coordinators may
spawn only their declared workers with bounded concurrency.

## 2. Non-negotiable invariants

1. Treat the target as read-only input. Never write, format, build, test, install,
   initialize Codegraph, or generate files inside it.
2. Use the current repository inventory as navigation scope. Operators may edit
   source between attempts; this does not invalidate ordinary accepted checkpoints.
   Every explicit Advantage invocation instead investigates fresh current source.
3. Keep durable audit artifacts under `scans/`, linked remediation bundles under
   `remediations/`, and runtime state under `.harness/` or `work/`.
4. Keep audit execution offline except for the configured LLM endpoint.
5. Ordinary phases read `.harness/audit-context.json`; Advantage phases use only
   their initializer-returned immutable `input_path`. Use its absolute paths,
   current routes, depth and reproduction policy. Evidence retains original attribution.
6. Never persist raw scanner output, raw proof output, secret values, partial
   identifiers, entropy material, or proof tokens.
7. Never execute target code directly. Use opt-in functional bubblewrap
   containment only.
8. Treat advisory, scanner, graph, and model output as inputs to investigation,
   never as vulnerability proof by themselves.
9. Require source-backed attacker access, crossed boundary, root cause, ordered
   trace, conditions, and concrete impact for reportable findings.
10. Keep fanout depth-bounded. Queue overflow; never drop it silently.
11. Give every evidence record and campaign a terminal disposition.
12. Never rewrite an upstream phase artifact from a downstream phase.
13. Use Synthesis as the sole pre-verification finding authority.
14. Render accepted independently reviewed findings in their recorded assessed scope;
    publishing again never revokes their verdicts or proves applicability to later source.
15. Write canonical schema `2.0` output. Read supported old records by required
    structure, not exact harness identity; never rewrite completed bundles.

## 3. Entry points

Before opening an audit session, prepare `config.toml`, install the bundled tools,
and populate the local OSV database. Then run:

```bash
bash scripts/validate-config.sh
```

For a transferable offline deployment, build only on the matching supported
platform from clean source files (prior generated archive and chunk outputs are
not source inputs):

```bash
bash scripts/offline-pack.sh --platform linux_amd64
```

Online preparation ends when this command succeeds. It must consume only
strictly locked assets, copy the already verified local OSV snapshot, verify the
OMP native runtime and every OSV ecosystem, pass relocation and setup smoke
tests, then publish the final archive and platform-namespaced JSON chunk
manifest. `--allow-dirty` is development-only;
`--include-config` may disclose endpoint credentials. SHA-256 proves integrity,
not publisher authenticity.

Ordinary `scripts/fetch-osv-db.sh` synchronization never updates the OSV lock.
When an operator intentionally prepares a new reviewed database snapshot, use
`bash scripts/fetch-osv-db.sh --refresh-lock <snapshot-id>`. The refresh must
stage and validate every ecosystem before publishing databases and replacing the
lock last.

After transfer, reconstruct with `./offline-build.sh --platform <platform>`,
extract into an empty directory, run `bash setup.sh verify`, edit `config.toml`,
authenticate an OAuth-backed provider with `bash setup.sh login <provider>` when
needed, and run `bash setup.sh configure`. Verify and configure never download
anything; login may contact only the selected provider's authentication service
and must not install dependencies.
The package is an offline installer, not a restricted runtime: it must not rewrite
or narrow configured OMP, network, or reproduction capabilities. OMP must retain
normal access to the configured LLM provider. The default configuration avoids a
Bubblewrap dependency, while explicitly configured enforced egress or safe
reproduction still requires a functional host Bubblewrap installation.

Start OMP through the contained launcher:

```bash
./run.sh "audit the target application"
```

Inside a prepared OMP, select the explicit requested workflow before initializing
an ordinary audit. An Advantage request follows Section 18 and the shared entry
contract in `.omp/skills/vulnops-advantage-security-scan/references/advantage-context.md`,
using `--in-session` without a launcher or second OMP. Finish or explicitly stop
and close active owned work before switching; do not queue a handoff. Deploy
runtime and instructions together after stopping older sessions and restart once
to load them; subsequent explicit workflow selections stay in that same session.

For a clean audit of a new target application, use
`./run_local.sh --fresh "audit the target application"` (or `./run.sh --fresh`).
This starts foreground OMP before visible audit initialization, not Advantage.
The launcher binds the request through `VULNOPS_AUDIT_FRESH=1`; the initializer
selects fresh work without deleting previous evidence. Do not reuse a context
read before initialization instead of its returned selection.

After an audit is complete, explicitly request linked production patches,
subject to the separate remediation exact-source policy:

```bash
./remediate.sh <completed-scan-base>
```

This command creates a separate versioned bundle beneath
`remediations/<repo-id>/<audit-run-id>/`. It never writes beneath the completed
scan. Automated remediation still requires its supported exact-source authority;
historical-only or mixed-source inputs without it receive a precise manual
prerequisite rather than broadened authorization. It requires a single-repository
source because publication authority is one Git patch. Multi-repository audits
remain reportable but require explicit per-repository patch ownership outside
the automated remediation workflow.

If the host launcher terminates, it closes owned audit and Advantage work without
hiding the original nonzero exit/cancellation status or changing completed evidence.
Ordinary unfinished audits retain their recovery boundary. Advantage ends that
invocation: another explicit request starts fresh (Section 18). Only host exit
deletes the private runtime overlay; in-session closure keeps OMP available.

For ordinary audit requests only, initialize the requested depth exactly once:

```bash
bash scripts/run-audit.sh [--fresh] [--no-codegraph] [--application-name <name>] [quick|balanced|full]
```

Invoke this once through OMP Bash with explicit `timeout: 0`, then await terminal
delivery even if the tool returns a running-job acknowledgement. Optional
Codegraph preparation has its own finite 7200-second default allowance, covering
copying and indexing together (`CODEGRAPH_INIT_TIMEOUT_SECONDS` overrides it).
Do not let the command tool's short default deadline preempt source-only fallback.
Ordinary preparation failure/timeout stops owned workers and safely discards
rejected navigation before initialization continues. Cancellation or unsafe setup
still fails; do not start a phase or bind stale context after unsuccessful return.

`run-audit.sh` probes the toolchain, discovers current repository paths and full
revisions, establishes a source namespace and selects the context's incomplete
run or creates a new one when none is selected. A completely removed selected
directory is a stale pointer: announce it and initialize fresh work without
asking to restore or back up missing evidence. Missing or malformed records in
an existing directory still block normal resume; explicit `--fresh` selects a
distinct run without changing those artifacts. Unsafe paths and competing live
ownership still fail. Fresh initialization retains a run already owned by this
launcher, never resetting allocations through repeated calls. Other selected run
IDs/directories stay stable; new application folders use a safe display name,
not an inventory hash.
Initialization claims the selected run for the launcher PID/session before mutation,
prepares optional graph navigation outside target, then publishes current context,
manifest and ledger. The claim survives initializer exit; short state locking
is separate. A live competing owner fails; confirmed owner exit allows reclaim.
`--no-codegraph` records a capability limitation while source work continues.

Initialize once per invocation, never as a scheduler or a way to reset allocations.
Continue from recorded accepted checkpoints, not historical validation replay.

## 4. Audit context

Read `.harness/audit-context.json` immediately after initialization. At minimum,
bind:

```text
run_id
depth
repo_path
source_root
repositories
repository_count
repository_inventory_verified
scan_base
attempt_id
attempt_contexts
phase_attempts
assessment_id
assessment_scopes
sast_budget
intrusion_budget
experiment_budget
reproduction_mode
codegraph_mode
model_routing.groups
model_routing.agents
model_routing.controllers
orchestration.phase_timeout_seconds
paths.*
tools.*
```

Never reconstruct a path with assumptions when `paths.*` provides it. Never use a
bare relative artifact such as `sast/findings.json` as the path authority. Artifact
references inside JSON remain application-source-root- or scan-relative as
defined by their schema; filesystem operations use the context's absolute
paths. In a multi-repository audit, every source reference includes its
repository directory prefix.

Resume only the incomplete run selected by `run-audit.sh`, in its original directory.
Use current valid source discovery, routing, depth and budget settings for new work;
do not compare old source/harness/repository hashes, revisions, compatibility IDs,
graph mode, package or network policy for eligibility. Recognized old non-complete
run labels read as `incomplete`; `complete` remains closed. Unknown/malformed
essential state produces a named error, not guessed success or a new audit.

Retained phase/task records preserve their original attempt and model route.
`attempt_id` identifies operational work; `assessment_id` and `assessment_scopes`
identify source-backed assessments. `attempt_contexts` preserves observed inventory,
routing and dates; `phase_attempts` identifies producing work. Allocate a new scope
only when source-backed work remains, not for report-only continuation. Accepted
Final Verification conclusions retain verdicts, severities and full dossiers across
publication attempts. Mixed scopes remain separate; unavailable original metadata
stays unknown rather than borrowing today's checkout. New worker admission still
requires its active attempt/assigned route. Imported evidence needs fresh review
before gaining new authority. Never backfill accepted artifacts or replay old source
citations merely to publish their accepted conclusions.
Current runtime bindings and dispatch settings remain context-owned; reduced
manifest projections must never overwrite them. Retained closures are checked
against their producing task and scope, not recomputed with today's clock,
budget or assessment identity.

Stop old active sessions before deploying runtime and prompts together. Completed
bundles require no migration. Rollback restores the earlier harness/configuration
and operator-retained incomplete-state backup; never alter completed evidence to
satisfy an old reader.

## 5. Run-state protocol

Use `scripts/update-run-state.py`; do not edit manifests or the task ledger by
hand.

The updater enforces phase order, one running top-level phase/task, a maximum of
two attempts per stable task ID per recovery generation, accepted checkpoints,
scan-relative successful artifacts and null artifacts for failures. Run states are
only `incomplete` and `complete`; phase/task statuses retain operational detail.
There are no directory seals. Do not work around a rejected state transition.
Canonical publishers also check the active execution/destination, owning phase
and task, and live session before mutation. A direct or stale command cannot
overwrite a completed run. Validate the aggregate before replacing canonical
findings; never rewrite admitted reviewer files merely to restamp aggregation.

At the start of active work:

```bash
python3 scripts/update-run-state.py <scan_base> --run-status incomplete
```

Before a model-owned top-level task starts, arm its native deadline with
`python3 scripts/set-omp-deadline.py <absolute-audit-context> <phase>`.
This updates the launcher's private OMP `--config` overlay from the context's
phase/depth deadline. Do not change the overlay from a child. Then record the task
and phase as running, incrementing the attempt only for a real attempt. Model
phases launch one asynchronous OMP task; deterministic phases run inline:

```bash
python3 scripts/update-run-state.py <scan_base> \
  --phase <phase> --phase-status running \
  --task <TaskID> --task-phase <phase> --task-status running \
  --increment-attempt
```

Recon's end-to-end deadline includes all three parallel workers plus coordinator
synthesis and validation. Configure positive integer seconds under
`[harness.scans.recon.timeout_seconds]`: defaults are `quick = 1800`,
`balanced = 2700`, and `full = 5400` (30/45/90 minutes). Initialization resolves
`max(configured_seconds, 900 + 300 * (repository_count - 1))`, preserving the
multi-repository floor without giving large monorepos only 15 minutes.
This is a finite workload allowance, not a completion guarantee. After timeout,
canonical initialization/recovery assigns the current deadline. Do not hand-edit
context or reset counters; reuse only owner-accepted partial checkpoints, never
unaccepted research files as a successful yield.

After terminal task delivery contains a strict schema-valid yield, or the
deterministic phase finishes:

1. run the phase validator;
2. stop immediately if validation fails;
3. synchronize the validated phase manifest; and
4. record the task artifact and terminal task status.

```bash
bash scripts/validate-phase.sh <scan_base> <phase>

python3 scripts/update-run-state.py <scan_base> \
  --phase <phase> \
  --phase-manifest <phase-directory>/phase-manifest.json \
  --task <TaskID> --task-phase <phase> \
  --artifact <canonical-phase-artifact>
```

`--phase-manifest` infers the task status. A skipped phase maps to an `ok` task;
degraded remains degraded. On an unrecoverable task or validation error, record
the error and leave the run incomplete. Do not advance to the next phase.

If a task fails, is cancelled, times out, or delivers no valid terminal yield,
stop its owned active descendants and close that attempt as failed before retrying
the same stable task ID. Retry only once. Peer messages never change task state
and cannot repair an attempt. Never create repair/replacement
top-level tasks. When stopping, pass the failed phase, stable task, sanitized error,
and `--run-status incomplete` together so no phase or task remains running.

On the next explicit `run-audit.sh` invocation, `recover-run.py` resumes the
first unfinished phase. Preserve all accepted predecessor bytes and safe accepted
partial SAST/Intrusion owner checkpoints and consumed allocations. Discard or isolate
only incomplete outputs their owner cannot safely reuse. Files without accepted
checkpoints never imply success. Current limits govern future dispatch; if consumed
work exceeds a lower limit, retain it and close remaining obligations with explicit
allocation-limit dispositions rather than rejecting the run or dispatching more work.
Recovery records the operation and keeps the run incomplete. Never loop recovery
automatically to evade attempts or repeat completed work because source changed.

An explicit operator decision may separately regenerate accepted SAST at its owner.
This is not ordinary source-drift handling, downstream artifact repair or a
source re-audit required for resume:

```bash
python3 scripts/recover-run.py <scan_base> <absolute-audit-context> <current-depth> \
  --invalidate-phase sast --reason "<bounded operator reason>" --dry-run
```

Remove `--dry-run` only for that authorized decision. Require an inactive incomplete
run, successful SAST before the first unfinished checkpoint, valid retained-prefix
tasks, safe paths and a trimmed printable reason of at most 1,000 characters.
No current source-reference diagnostic, source/routing equality or seal is required.
The operation archives affected state as diagnostic history, preserves Recon and
Tool Collection and resets SAST through Report. No accepted finding is edited in place.

Archives are forbidden as active evidence and are not hash-attested lifecycle
prerequisites. An interrupted `.recovery-invalidation.json` operation must finish
via the identical recorded command and reason before ordinary resume or state
mutation; never delete the journal. This prepares regeneration, not agent execution
or report publication.

Only after new report validation, required checkpoint acceptance and completion reads succeed:

```bash
python3 scripts/update-run-state.py <scan_base> --run-status complete
```

## 6. Canonical top-level sequence

New ordinary runs use this order; retained runs follow their recorded phase set:

| Order | Task ID | Execution | Phase name |
|---:|---|---|---|
| 1 | `Recon` | `vulnops-recon` | `recon` |
| 2 | `ToolCollection` | `python3 scripts/collect-tools.py <scan_base>` | `tool-collection` |
| 3 | `ThreatHunter` | `vulnops-threat-hunter` | `sast` |
| 4 | `CampaignPlanning` | `vulnops-campaign-planning` | `campaign-planning` |
| 5 | `Intrusion` | `vulnops-intrusion`, or deterministic empty finalization | `intrusion` |
| 6 | `GapExploration` | `vulnops-gap-exploration`, or deterministic skipped closure | `gap-exploration` |
| 7 | `Synthesis` | `vulnops-synthesis`, or deterministic empty synthesis | `synthesis` |
| 8 | `FinalVerification` | `vulnops-final-verification`, or deterministic empty finalization | `final-verification` |
| 9 | `Report` | `python3 scripts/render-report.py <scan_base>` | `report` |

Every row is a ledger task, including deterministic and empty paths. Never start a
downstream task before the preceding checkpoint is accepted; do not replay its old gate.
Never insert the additional phase into a legacy run during resume or rewrite a
completed bundle. Campaign Planning and original investigation allocations are unchanged.

## 7. Phase runbooks

### 7.1 Recon

Launch top-level task `Recon` with agent `vulnops-recon`.

The coordinator launches these workers in one parallel batch:

| Worker task ID | Agent | Purpose |
|---|---|---|
| `Overview` | `vulnops-recon-overview` | Projects, languages, build/dependency structure |
| `Trust` | `vulnops-recon-trust` | Assets, privilege changes, and trust boundaries |
| `Inputs` | `vulnops-recon-inputs` | Entrypoints, attacker-controlled inputs, parsers, protocols |

Workers write exactly one disjoint research artifact each under
`paths.repo_context/research`; they never write aggregate artifacts. The
coordinator writes only aggregate JSON under `paths.repo_context`, and the
deterministic finalizer renders `repo.md` and the manifest:

```text
repo-context/repo.md
repo-context/repo-context.json
repo-context/security-surfaces.json
repo-context/research/overview.json
repo-context/research/trust-boundaries.json
repo-context/research/input-surfaces.json
repo-context/phase-manifest.json
```

Every repository must be represented by at least one project base path. Every
project, file, entrypoint, ignore pattern, surface, and boundary must resolve to
application source evidence; multi-repository references include the repository
prefix. The coordinator must not invent architecture to complete the schema.
After validation, treat `repo-context.json` and `security-surfaces.json` as
immutable for the rest of the run.

`security-surfaces.json.attack_paths` records actor, entry surfaces, controlled
material, authority decisions, identity propagation, sensitive effect, source-backed
handoffs and exact unknowns. Later discoveries belong to phase-local amendments,
never a rewrite of this accepted map.

Canonical task artifact: `repo-context/repo-context.json`.

### 7.2 Tool Collection

Do not launch a model agent. Record `ToolCollection` running and execute:

```bash
python3 scripts/collect-tools.py <scan_base>
```

The collector reads dependency files only from validated Recon output, runs all
Wraith invocations and one Poltergeist scan concurrently with a maximum of four
processes, validates invocation receipts, merges Wraith results, finalizes the
phase, and removes successful temporary work.

`projects[].dependency_files` accepts only application-source-root-relative paths
approved by `scripts/dependency_contract.py`. Multi-repository paths include the
repository prefix. It is not a general build-file inventory.
Tool Collection reads accepted Recon and checks the inputs needed for its current
operation without replaying historical Recon. It stages normalized output under
`.harness/`; publication requires scanner, schema, count and receipt-hash checks.
Failures publish bounded sanitized errors and no successful canonical task artifact.

Required artifacts:

```text
tool-collection/sca-advisories.json
tool-collection/wraith-receipt.json
tool-collection/secrets-redacted.json
tool-collection/poltergeist-receipt.json
tool-collection/collection.json
tool-collection/summary.md
tool-collection/phase-manifest.json
```

Accept clean and findings-present scanner outcomes only through their wrappers.
Require parse success, count consistency, and normalized hashes. A Wraith advisory
is a reachability candidate. A Poltergeist record must contain exact `<redacted>`
and no recoverable part of the detected value.

Deduplication is ordinary deterministic normalization, never a warning or degraded
condition. Preserve Poltergeist occurrence count as `match_count` and the unique
normalized record count as `candidate_count`. When both scanner receipts are
healthy and all parse, schema, count, and hash checks pass, Tool Collection must
close `ok` with empty warnings. Tool Collection has no successful degraded path;
an actual invocation, parse, schema, count, hash, identity, or publication failure
closes the task and phase as failed and stops the workflow.

Canonical task artifact: `tool-collection/collection.json`.

### 7.3 ThreatHunter (SAST)

Launch top-level task `ThreatHunter` with agent `vulnops-threat-hunter`.
The phase/group/path remains `sast`; worker identities and model routes are unchanged.

Required sequence inside the coordinator, continuing accepted partial checkpoints
instead of repeating their work:

1. Launch `ThreatModel` with `vulnops-threatmodel` only when no accepted threat-model
   checkpoint exists, and validate its new yield.
2. Run `python3 scripts/build-hunt-plan.py <repo_path> <scan_base>`.
3. Launch one `vulnops-deepdive-chunk` per pending hunt task, excluding
   `hunt-plan.deferred_task_ids` and already accepted worker checkpoints.
   Validate each newly produced worker artifact with `python3 <tools.sast_contract>
   <repo_path> <hunt-task-packet> <hunt-result>` before aggregation. Retained accepted
   checkpoints are historical inputs, not fresh results to replay under today's route.
4. Run `python3 scripts/finalize-sast.py <repo_path> <scan_base>`.
5. Execute bounded gapfill: build new tasks with `--gapfill`, run only new tasks,
   aggregate them, and repeat until no new task or budget exhaustion.
6. Launch `vulnops-verify-one` for pending deduplicated validation-queue candidates,
   preserving accepted reviews as historical. Before accepting each new result, run
   `python3 scripts/sast_contract.py <repo_path> <scan_base>/sast/validation-queue.json <review-result> --review`.
   Exit 1 returns exact format diagnostics to the owner within the existing
   repair allowance; exit 2 is a fatal integrity violation. After exhausted
   format repair, retain an `evidence_limited` closure with `correction_repair`
   attempted action and exact diagnostics plus the precise allocation deferral.
   Do not rewrite trace kinds, silently use the original candidate or call
   malformed output a substantive rejection.
7. Aggregate verifier result JSON and run finalization with
   `--advance-alternates`; verify newly advanced alternates until the command
   reports zero.
8. In `safe` mode, source-verified confirmation may use `vulnops-reproduce-one`.
   A named unresolved behavior may instead use the phase-owned investigative
   experiment contract in Section 12; it requires neither a finding nor a patch.
9. Run `python3 scripts/finalize-sast.py <repo_path> <scan_base> --finalize`.
10. Validate `sast` before yielding.

Fanout limits:

| Depth | Deep-dive concurrency | Verification concurrency | Hunt-task ceiling | Hunt-question ceiling | Gapfill rounds |
|---|---:|---:|---:|---:|---:|
| `quick` | 4 | 4 | 12 | 24 | 1 |
| `balanced` | 8 | 8 | 32 | 64 | 2 |
| `full` | 16 | 12 | 64 | 128 | 3 |

The threat model must define source-backed contextual hunt mappings. Each mapping
binds one attack class to concrete surfaces, threats, assets, attacker,
entrypoints, boundaries, source files, a security question, stop conditions, and
evidence. Initial cells come from these mappings, never a subsystem × surface ×
attack-class cross-product. Source-backed local amendments can admit new leads.

Define `attack_objectives` and separate `investigation_questions` before scheduling.
Objectives bind actor, controlled material, scope, desired effect, success condition
and source support; question identities bind a concrete route and proof obligation.
Carry `objective_id`/`question_id` through cells, packets, candidate results,
checkpoints, amendments, gapfill and the evidence index. Definitions are immutable;
new goals require attributed phase-local definitions, not an upstream edit.
Early candidates may omit remediation, never exploitability proof. Full structured
repair guidance is required at Synthesis. Apply the shared availability-impact
criteria in `vulnops-exclusion-rules`; process crashes are not a blanket exclusion.

Batch up to four cells only when they share a source flow, subsystem, domain, and
compatible specialist context. Every packet contains the exact cell definitions,
and every worker returns exactly one cell-specific disposition. A candidate may
mark only the cells it cites. Initial files are anchors, not access whitelists:
follow relevant dependencies inside the authorized repository set, recording
`source_expansions` with predecessor and reason. A different objective becomes a
separate lead. Do not repeat scanner enumeration.

Every question records `resolution` and `checkpoint`. Outcomes are `established`,
`contradicted`, `locally_unresolved`, `externally_blocked`, `budget_deferred`, or
`execution_failed`; these are not interchangeable lifecycle states. Preserve the
exact missing fact, next action, established facts, contradicted routes and source
already inspected. `model_amendments` extend only the owning phase's model.

Initial scheduling is risk-weighted and fair across subsystems. Gapfill compares
consequential obligations, checkpoints and evidenced new branches in one bounded
queue; equal-impact completion work precedes new branches. External blockers do
not receive blind local retries. Current finite limits govern future work while
accepted results and consumed allocations survive resume.

At final SAST closure, label unfinished cells by their recorded reason.
`externally_blocked` preserves the missing external prerequisite and next action;
`locally_unresolved` preserves local uncertainty; execution failures remain
`failed`. Use `depth_limited` only when an actual task, question, round or attempt
allocation limit prevents further work, recording the applicable limit.
Depth limits and local uncertainty alone do not degrade SAST. External blockers,
failed cells and `environment_required` verified candidates remain material
capability losses and close SAST degraded. Keep separate terminal label counts.

Required canonical artifacts include:

```text
sast/threat-model.json
sast/hunt-plan.json
sast/raw-findings.json
sast/validation-results.json
sast/verified-findings.json
sast/dropped-findings.json
sast/dedup-clusters.json
sast/coverage-ledger.json
sast/wishlist.json
sast/phase-manifest.json
```

`sast/deepdive/`, `sast/verify/`, and `sast/reproduction/` contain bounded
supporting artifacts. Current source-verified candidates may be promoted;
retained historical candidates require current review, and environment-required
candidates remain unconfirmed. Deep-dive and SAST review workers must record
`assessment_context: {attempt_id: context.attempt_id}` only after actual current
source review, never merely by copying or aggregating an old candidate.

`build-hunt-plan.py` also publishes one derived, hash-bound packet beneath
`paths.sast_hunt_tasks` per hunt task. Workers read only their assigned packet,
not the full aggregate hunt plan. The hunt plan remains the sole authority.

Canonical task artifact: `sast/verified-findings.json`.

### 7.4 Campaign Planning

Launch top-level task `CampaignPlanning` with agent
`vulnops-campaign-planning`.

The agent must first run:

```bash
python3 scripts/build-evidence-index.py <scan_base>
python3 scripts/build-campaign-plan.py <scan_base> --prepare-discovery
```

It reviews evidence and source before campaign selection. Discovery is bounded:
quick/balanced/full permit at most 4/8/12 logical questions, 120/240/360 aggregate
query seconds and 32/64/128 considered pairs. These are maxima, not minimums.
Codegraph is optional; skipped, failed or unhelpful queries record limitations
and continue source-only. Only graph evidence relied upon needs bound receipts
and source-backed answers. Cross-repository handoffs require source/configuration
matching, not merely similarly named symbols.

After recording discovery dispositions, run
`python3 scripts/build-campaign-plan.py <scan_base>` to validate and accept discovery
and select campaigns. Source questions receive protected effort; scanner volume
does not confer composition priority. Reviewable priority bands and actor/boundary
fairness precede stable-ID tie-breaking. Attributable `selection_revisions` may
change approved references and priorities within the shared campaign budget before
acceptance, naming selected and displaced `question_ids` as well as evidence.

Required artifacts:

```text
campaign-planning/evidence-index.json
campaign-planning/discovery.json
campaign-planning/campaign-plan.json
campaign-planning/summary.md
campaign-planning/phase-manifest.json
```

The evidence index must include promoted, closed, rejected, environment-required,
and unresolved records where present. Current source-established findings can
supply attack primitives; historical findings are leads until current applicability
is established. Plan for what a primitive grants, what consumes the capability,
which controls intervene and whether primitives compose. Novelty is not a seed requirement.

Scanner records remain observations, not automatically generated capabilities.
`scanner_triage` and `scanner_accounting` account for every advisory and redacted
secret as investigated/selected, contradicted or explicitly deferred. Contextual
legitimate capabilities are eligible without becoming vulnerabilities. Structured
capabilities retain actor, operation, resource scope, authority, conditions,
evidence status, provenance and restrictions.

Use `primitive_led`, `gap_driven`, and `direct_validation` as intent labels sharing
one total initial ceiling: quick 4, balanced 10, full 20. Never reserve unused
capacity per lane or fabricate demand. Protect source work and retain risk,
actionability and comparable-priority actor/boundary fairness.
Bind every campaign to an admitted objective/question pair. Shared evidence does
not make distinct questions duplicates; record genuinely equivalent work
explicitly. Retain every admitted unscheduled question with its reason, missing
fact and next action. Graph `questions` remain a separate navigation contract.
Preserve a valid zero-campaign plan.

Canonical task artifact: `campaign-planning/campaign-plan.json`.

### 7.5 Intrusion

Read and validate the campaign count before launching workers.

If campaigns exist, launch top-level task `Intrusion` with agent
`vulnops-intrusion`. Initialize the phase-owned wave with
`python3 scripts/build-intrusion-wave.py <scan_base> --context <audit-context>`.
Launch only the builder's returned pending assignments with `wave` and
`input_snapshot` bindings, preserving accepted owners and allocation deferrals.
Use current depth-bounded concurrency and queue permitted overflow.

Each worker must:

- read all cited evidence and complete source paths;
- optionally use useful planned graph questions through `scripts/run-codegraph.sh
  --context <absolute-audit-context> --phase intrusion --owner <campaign-id>
  --question <question-id>`; graph availability or execution is never a gate;
- store `context.json` and `receipt.json` at
  `intrusion/codegraph-runs/<campaign-id>/<question-id>/`;
- list every executed receipt in `graph_query_receipts`;
- list only meaningful receipts in the `graph_evidence_refs` subset;
- record `graph_answers` for graph evidence actually relied upon, and bounded
  `graph_limitations` for unavailable, failed, skipped or unhelpful navigation;
- treat graph output as navigation, never vulnerability proof;
- record `assessment_context: {attempt_id: context.attempt_id}` after actual
  current-source review, retaining historical references separately;
- write exactly one `intrusion/results/<campaign-id>.json`; and
- choose exactly one terminal status: `candidate`, `closed`, `rejected`, or
  `needs_environment`.

Every result also carries precise `resolution` and a `composition` decision over
all new primitives. Workers consume only their own updates and validated prior-wave
snapshots, never unvalidated peer output. New primitive identity binds observation
and scope. The coordinator advances with `--results <all-completed-owner-IDs>`
and optional `--continuations <proposal-array.json>`. Proposals name a stable parent,
triggering evidence, changed hypothesis, next question, substantive evidence delta
or justified alternative, and one resource unit. A continuation is not a retry.

Carry assigned `objective_id` and `question_id` into every result and candidate.
An alternate route keeps its objective; register a new question when its proof
obligation changes. New goals need an inherited parent, source evidence and
validated triggering evidence. New definitions belong to the next numbered wave;
never overwrite inherited definitions. Finalization preserves route outcomes,
but only final independent review can establish objective success.

Quick/balanced/full reserve 1/2/3 continuation rounds, 4/12/24 continuation tasks
and 4/12/24 optional graph follow-ups application-wide. Current limits govern
remaining dispatch while consumed allocations and accepted owner results remain.
Omit `--continuations` to close the final wave. Numbered snapshots retain exact
owner/question relationships and ancestry without old source/budget equality.
Do not rewrite the initial plan or reclassify inherited capabilities as current.
Budget/local unresolved outcomes are honest coverage, not degradation; external
prerequisites and execution failures remain material losses.

After all waves have closed, run:

```bash
python3 scripts/finalize-intrusion.py <scan_base>
```

If the campaign list is empty, do not launch the agent. Record the top-level task,
initialize the empty wave using the same builder, and run the finalizer directly.
It produces an empty wrapper, summary and `ok` manifest without graph scope.

Required aggregate artifacts:

```text
intrusion/intrusion-results.json
intrusion/waves/<wave>.json
intrusion/summary.md
intrusion/phase-manifest.json
```

The finalizer must reject missing, duplicate, orphan or malformed wave results,
and invalid, hash-mismatched or graph-stub evidence actually relied upon.
An optional planned query need not execute; skipped, failed or unhelpful navigation
records a limitation and permits source-only closure. Intrusion must never rewrite
Recon surfaces or Campaign Planning artifacts.

Canonical task artifact: `intrusion/intrusion-results.json`.

### 7.5a Gap Exploration

After accepted Intrusion, launch `GapExploration` with `vulnops-gap-exploration`
only when the recorded phase exists and its allowance is enabled. Advantage
uses `AdvantageGapExploration` and `vulnops-advantage-gap-exploration` after
accepted Investigation. Read the current context and its separate
`gap_exploration_budget`, paths and exact assigned actor routes first.

The coordinator prepares accepted inputs with
`python3 scripts/prepare-gap-exploration.py --context <context>`, then admits
its bounded source-backed plan using the same command with `--plan <draft>`.
It dispatches only the corresponding `vulnops-gap-investigator` or
`vulnops-advantage-gap-investigator` through `gap-exploration-worker.py`.
That CLI owns dispatch, admission, failed-worker closure and interrupted graph
reservation closure; do not hand-edit phase controls. At most two candidates
per worker are admitted within the independent question/task/attempt ceilings.
Follow accepted source evidence, not a graph-coverage quota. Existing external
blockers or decisive counterevidence need a genuinely changed local question
before additional work is useful.

Use existing graph wrappers with explicit gap phase, owner, question and selected
base/derived source view. Preparation occurs outside target only when useful
navigation requires it. Missing, failed or unhelpful navigation permits
source-only work and a truthful limitation; it never establishes an exploit.
No graph query requirement is added to Campaign Planning or original workers.

Finalize with
`python3 scripts/finalize-gap-exploration.py --context <context>`, validate and
accept through the execution's existing phase updater. Disabled paths finalize
without model or graph work; a plan with no useful seeds launches no investigator
or graph preparation. Canonical output is
`gap-exploration/results.json` with `phase-manifest.json`; accepted plans,
packets, results and graph receipts remain supporting evidence.

Stop failed descendants before retry/closure. Preserve healthy admitted peers.
Only actual optional coordinator `execution_failed` or `deadline_exceeded`
failure may use the existing updater's `--close-optional-failure` after its
allowance is exhausted. The failed task keeps its error, attempts and null
successful artifact; the deterministic degraded phase can permit continuation.
Never use this exception for integrity, ownership, unsafe source access or
forbidden execution, or for an original phase.

Accepted supplementary candidates feed the existing Synthesis authority.
When any exist, controller prompts stage original authoring first, then the
supplement under separate time; `gap-dossier.py` binds cohort ownership and
remaining allowances. Invoke the same canonical coordinator sequentially,
awaiting each strict terminal yield, under one stable phase task. Preserve the
admitted original draft exactly; optional failure produces explicit unreviewed
inputs, not fabricated findings. Empty synthesis must inspect both cohorts.
New original authoring passes full semantic checks before binding. Finalizers
prepare output but never complete their own synthesis invocation: the controller
finishes each cohort only after successful terminal delivery. Rejected or
interrupted original authoring remains disposable under existing owner retry,
including legacy premature completion without accepted original delivery.
Retain admitted originals after supplementary failure by existing ownership and
binding, without replaying source proof. Preserve consumed supplementary
allowance; unfinished optional work closes through the existing finalizer.
Prepared combined output is not an accepted checkpoint. If supplementary
delivery fails acceptance, failure finalization uses existing owner cleanup
before rebuilding the original-only aggregate and unresolved supplementary
dispositions. Attribution to `synthesis/findings.json` never protects that
unaccepted aggregate or its publication sidecars during retry or resume.
Wrong ownership, unsafe paths or corrupt required bindings never authorize
cleanup. A source-example mismatch is an authoring repair, not a substantive
candidate rejection or permission to relabel the example automatically.
Independent review likewise completes original/mixed work first, then
additional-only work under its own allowance. Derive membership from evidence
and contributor ancestry, not optional labels. Preserve existing original
review rules, including Advantage's explicitly exhausted-reviewer closures.
Unaccounted missing or forged reviews still fail. Reports expose supplementary
contribution and unreviewed claims without extra confirmed-severity counts.

### 7.6 Synthesis

Probe the deterministic empty path first:

```bash
python3 scripts/empty-synthesis.py <scan_base>
```

Exit `0` means validated composition decisions permit empty synthesis; do not launch
a model. Exit `2` means candidate or unresolved composition work requires synthesis.
Other exits fail. Primitive-only updates must be composed or explicitly deferred.

When required, launch top-level task `Synthesis` with agent
`vulnops-synthesis`. It reads the evidence index, SAST verified findings, and
intrusion results and writes only:

```text
synthesis/findings.json
synthesis/summary.md
synthesis/phase-manifest.json
```

Synthesis must include independently exploitable known findings, proven impact
expansions, complete new root causes, cross-evidence discoveries, and closed
composite chains. Deduplicate standalone findings by root cause and chains by
ordered primitive sequence plus terminal impact.

Each finding is a complete exploitation dossier: objective IDs, attack summary,
affected repositories/components/code locations and evidenced service mappings,
ordered causal exploitation steps with controlled inputs and expected results,
reviewed typed examples, impact limits and structured remediation. Link repair
actions to the attack steps they break, and propose checks for rejected attacks
and preserved legitimate behavior. Unknown service bindings need an explicit
limitation, not an invented deployment name. Every new proof field participates
in source-reference and provenance validation. Proposed checks are not executed
tests and remediation guidance is not a verified patch.

A chain requires at least two ordered primitive steps and explicit adjacent
`transitions`. Source-backed obligations establish producer grant, actor control,
scope alignment, control preservation, consumer authority, intervening controls
and compatible conditions; equal capability wording is neither necessary nor
sufficient. A chain of known primitives needs distinct exploitability, a new
boundary or materially greater impact. Never promote graph-only, advisory-only,
secret-candidate-only or environment-only hypotheses.

At comparison time, discover up to eight available completed ordinary sibling
reports through bounded safe reads, not a persisted `prior_reports` pointer list.
Missing/invalid optional reports never block the current audit; previously consumed
missing support retains an explicit not-revisited limitation. Record revalidated,
contradicted, superseded or not-revisited dispositions. Historical verdicts and
routes require current independent review before confirmation; aggregation never
stamps inherited results with the current assessment context.

Run `python3 scripts/finalize-synthesis.py <scan_base>` after model synthesis,
then validate.

Canonical task artifact: `synthesis/findings.json`.

### 7.7 Final Verification

Read the synthesized finding count.

If findings exist, launch top-level task `FinalVerification` with agent
`vulnops-final-verification`. It launches one fresh-context
`vulnops-independent-verify-one` task per finding. The generated
`task.agentModelOverrides` entries must resolve both coordinator and reviewer
to their exact `model_routing.agents` selectors and High reasoning. Generic roles
are not a fallback; missing or mismatched overrides fail before dispatch.

Every verifier must:

- assume the claim is false until source proves it;
- verify attacker reachability, crossed boundary, intended behavior, root cause,
  ordered trace, conditions, impact, severity, confidence, and remediation;
- verify dependency installed version, affected use, and reachability;
- verify only redacted secret location and exposure evidence;
- verify every chain primitive and capability transition in order;
- bind `dossier_review` to the complete effective dossier hash, reviewing affected
  scope, procedure, examples, impact limits and structured remediation;
- assess each exact objective success condition in `objective_results`, without
  treating a contradicted route or an unrelated observation as goal proof;
- record `assessment_context: {attempt_id: context.attempt_id}` only after actually
  challenging the effective claim against current source;
- write one result under `final-verification/results/<finding-id>.json`;
- record its canonical `actor` and full assigned `model`, and compute
  finding-specific `model_diversity` against every effective contributor; and
- return `verified`, `corrected`, `rejected`, `needs_environment`, or an explicitly
  reviewed/deferred `evidence_limited` disposition that cannot enter confirmed findings.

After all verifier tasks yield, run:

```bash
python3 scripts/finalize-verification.py <repo_path> <scan_base>
```

If synthesis is empty, do not launch verifier workers. Record the top-level task
and run the finalizer directly; it emits empty findings and rejections, zero
diversity counts and false aggregate diversity while retaining the review route.

Required aggregate artifacts:

```text
final-verification/findings.json
final-verification/summary.md
final-verification/phase-manifest.json
```

Missing, duplicate, orphan, malformed, wrong-model, wrong-diversity, or incomplete
chain results fail the phase. Select the complete effective corrected finding
before assessing its exact ordered primitives, transition results and joint
conditions. A changed sequence cannot inherit approval of its predecessor.
Every admitted objective remains in `objective_assessments`, even with no accepted
findings. Mark it achieved only through an accepted, independently supported
success condition. Preserve unresolved questions and remaining route obligations;
goal achievement does not establish exhaustive coverage.

Canonical task artifact: `final-verification/findings.json`.

### 7.8 Report

Do not launch a reporting agent. Record `Report` running and execute:

```bash
python3 scripts/render-report.py <scan_base>
```

The renderer takes finding authority only from Final Verification and reads other
canonical phase artifacts for separate investigation accounting. It writes:

```text
report/security-report.json
report/security-report.md
report/phase-manifest.json
```

The report must remain sanitized; canonical JSON and Markdown have no byte-size
ceiling in either ordinary audits or Advantage. `report.findings` contains all
accepted Final Verification dossiers, including explicitly unconfirmed
environment-required findings. `summary.total` counts that set; confirmed severity
totals and `summary.confirmed` count only confirmed dispositions. Rejections and
non-promoted claims remain separate. `assessment` records assessed scopes and the
publishing attempt; `outcome_assessment` records the investigation's closure status.
Preserve original reviewer attribution and diversity. Compare the reviewer's
normalized provider/model with every investigation/review contributor, not the
publisher, lead or synthesizer. Effort alone is not diversity. Red reviewing Red
is same-model fresh-context verification regardless of synthesis model.
Aggregate diversity requires a nonempty accepted set with every finding diverse.
Keep integrity and assessment distinct: zero confirmed findings may accompany
`substantially_unresolved`. Preserve actor paths, semantic transitions, scanner
accounting, established capabilities, unresolved and unscheduled work, experiments,
graph limitations and prior-root reconciliation. Ancillary cohorts are capped at
200 entries with complete totals, omitted counts and canonical references; final
findings remain complete. Never infer clean coverage from a valid manifest.
Optional explanatory planning, coverage and navigation inputs may be unavailable
or malformed without losing accepted findings. Record the limitation and unknown
totals rather than empty success or false zero. Required finding/review authority,
unsafe paths, foreign identities and forbidden content still block publication.

Project each complete effective dossier unchanged. Markdown distinguishes publication
date from assessment dates and revisions, then leads with severity totals, an
attacker-outcome/repair index and material limits. Show complete affected-code/service,
starting-access, causal procedure, reviewed examples, impact and repair narratives.
Stable step/action anchors link repairs to the steps they interrupt in both
directions. A prioritized defensive handoff links actions rather than repeating them.
Retain consequential missing proof and next actions; bind open claims to objectives
only through explicit existing identities. Red authors substantive dossiers before
independent review; deterministic Report adds no new claims or model narration.
Replace expanded accounting with a short relative-link evidence index, retaining
complete JSON fields, overlapping totals and omitted counts. Keep numeric risk
scores in JSON, not Markdown. Source-established steps are not executed attacks;
only uniformly unexecuted procedures may share a not-dynamically-tested label.
Publish reviewed typed examples literally; retain exact redaction and prohibit
secret values, raw scanner/proof output and invented dynamic observations.
Escape untrusted prose and safely fence code. Validate required field contracts
before writing either output; never clip steps or alter accepted evidence to fit
a report file-size budget. Non-report artifact limits remain enforced. The fresh report gate checks complete
cohort/objective projections and new Markdown. Report-only resume preserves original
confirmed and unconfirmed totals without rerunning accepted verification. Validate
required accepted review bindings and recorded producer routes, not today's source.
Publication does not cover later changes or newly added components. Historical
status/intake never rerenders saved Markdown.
Deliver the sanitized report and canonical phase directories (`repo-context/`,
`tool-collection/`, `sast/`, `campaign-planning/`, `intrusion/`, `synthesis/`,
`final-verification/`, `report/`), preserving relative layout and supporting
records. New completed products carry publication identity/provenance in canonical
JSON and do not require mutable manifests or task ledgers. Include
`gap-exploration/` and all canonical supporting records when present; legacy
completed inputs remain readable without rewriting them. Omit source, runtime
state, credentials, raw output and recovery archives. Markdown alone is not
complete evidence. Link whole JSON artifacts and name record IDs separately;
never emit unsafe/invented destinations or rerender completed reports.

Canonical task artifact: `report/security-report.json`.

## 8. Final closure

After accepting the fresh Report phase, check recorded checkpoints and required outputs:

```bash
bash scripts/validate-scan.sh <scan_base>
```

This is a read-only completion check, not historical phase replay. When it succeeds,
mark `--run-status complete`. This removes the matching runtime context and
releases ownership immediately; do not retain a last-completed selection.
Saved evidence remains unchanged. Use the explicit path for the read-only status view:

```bash
bash scripts/audit-status.sh <scan_base>
```

Return to the user:

- run ID and terminal status;
- current confirmed finding count and severity summary;
- historical, unresolved-applicability, environment-required and rejected counts;
- actual current/historical model-diversity state;
- material limitations or degraded phases;
- paths to `security-report.md` and `security-report.json`; and
- whether the recorded completion/output check passed (not a fresh historical re-audit).

Do not reproduce raw findings, secrets, payloads, or proof output in chat.

### 8.1 Optional linked remediation

Linked remediation begins only from recorded complete input and its independently
required exact-source authority. It is not a ninth audit phase and must not write
anything under `scans/`. New historical-only or mixed-source input lacking exact
authority requires the precise manual prerequisite; do not synthesize it from lifecycle data.

`remediate.sh` initializes or recovers one versioned execution beneath
`remediations/`, writes `.harness/remediation-context.json`, and launches the
dedicated remediation controller. Use `scripts/update-remediation-state.py` as
the only state writer. Retry the stable top-level `Remediation` attempt once;
completed bundles are immutable.
Automated linked remediation rejects multi-repository source runs before planning;
the final audit report remains authoritative and operators must assign each fix
to its owning repository.

The deterministic planner creates one hash-bound packet for every accepted
entry in `final-verification/findings.json`. Rejected findings are never inputs.
Secret and `needs_environment` findings are terminal `manual_required` items.
Packets include the complete effective dossier and all declared proof-bearing
source/artifact references from components, procedures, examples and structured
remediation. Recompute this closure during validation and require exact report/final
finding agreement. Preserve operation-specific report/finding integrity and audited
exact-source authority where supported; absent authority is manual-required, not
permission to weaken the publisher. Proposed checks never authorize target execution.
After execution-wide exact-source admission, already-manual-only items do not
need unavailable patch-authorizing support. Their declared references, confinement,
attribution and available-content hygiene remain checked. Missing eligible proof
still blocks its patch; a manual item does not disable an eligible neighbor.
The coordinator launches one `vulnops-remediate-one` worker per eligible finding
with concurrency 4/8/12 for quick/balanced/full depth and queues overflow.

Workers must read the final finding, its independent result, every cited
artifact, and all cited source paths. They may edit only the disposable copy
created under `work/`. Do not run target code, builds, tests, package managers,
or network commands. Production patches may change runtime source,
deployment/configuration, dependency manifests, and consistent lockfiles; they
must not change tests, specs, fixtures, examples, or documentation.

Only `scripts/publish-remediation-patch.py` may create a final patch. Publication
requires safe target-relative text changes, complete root-cause accounting,
bounded output, secret hygiene, unchanged target identity, and successful
read-only `git apply --check --whitespace=error-all`. Apply-check is not dynamic
testing or independent semantic verification and the summary must state that
limitation.

Completed delivery retains the following analytical/patch artifacts:

```text
remediation-plan.json
remediation.json
summary.md
packets/<finding-id>.json
results/<finding-id>.json
patches/<finding-id>.patch
receipts/<finding-id>.json
```

The remediation manifest remains an unfinished-work control, not a completed
delivery prerequisite. `remediation.json` carries completed publication identity;
historical status reads do not require today's target or runtime context.

Every accepted final finding must close `patch_ready` or `manual_required`.
Missing, duplicate, orphan, unsafe, hash-mismatched, or non-applying patches fail
validation. A bounded candidate failure after retry becomes `manual_required`;
identity, schema, publication, or sanitizer failures fail the execution. Use
`scripts/remediation-status.sh <remediation-base>` for the read-only result view.
Never apply, commit, push, or open a pull request automatically.

## 9. OMP orchestration behavior

Use the pinned OMP 18.13.1 batch calls with shared `context` and per-item `name`, `agent`,
`task`, `solutionSpace`, and `schemaMode: "strict"`. Keep canonical stable IDs
separate from returned runtime identities, which can be qualified or uniquified.
Ordinary acceptance requires actual successful terminal strict yield and semantic
validation. Advantage instead follows Section 18's semantic phase gate without
a separate successful-yield prerequisite.
Use `wait` only when blocked; inspect a specific execution with `read proc://<id>`
and cancel with `write proc://<id>/kill`. There are no `job` or `irc` tools.

Nested calls inherit asynchronous execution: a spawn acknowledgement is not a
completed worker. Coordinators await stopped owned work and validate artifacts
before aggregation; Advantage preserves usable bound evidence and honest missing
assessments even when terminal envelopes are unusable. Retain depth-specific
waves; OMP's concurrency semaphore is session-scoped.
Use `write agent://<runtime-id>` only for genuine peer coordination, never progress
heartbeats or completion. Leaf workers rely on OMP progress cards.

Do not:

- poll directories for completion;
- use sleep loops or Bash as a scheduler;
- read transcript, `agent://`, or `history://` URIs;
- send timer heartbeats with no state change;
- include secrets, full findings, payloads, or raw output in peer messages;
- launch a second task for work already represented by an active stable task ID;
  or
- treat a yielded status as valid until the phase gate passes.

`scripts/wait-phase.sh` is manual/CI recovery only. It is not the normal
orchestration mechanism.

## 10. Model routing and provenance

The required `[llm.routing]` keys are `audit_lead`, `recon`, `sast`,
`campaign_planning`, `intrusion`, `synthesis`, `final_verification`, `reproduction`,
`remediation`, `advantage_lead`, `advantage` and `advantage_verification`.
Astra High owns audit lead, Recon and the linked Advantage controller;
Daybreak Red High owns attack investigation, ordinary and Advantage Synthesis,
independent review and optional reproduction; Daybreak Blue High owns the separate
remediation execution. Exact
shipped selectors are `openai-codex/gpt-6-astra:high`,
`openai-codex/gpt-daybreak-red-latest:high` and
`openai-codex/gpt-daybreak-blue-latest:high`. Preserve each execution's declared
spawn graph and exact coordinator/worker routes.

Read the resolved `model_routing` from execution context. Launchers explicitly
select `controllers.audit`, `controllers.advantage` or `controllers.remediation`; complete generated
`task.agentModelOverrides` select every canonical agent from `agents`. Never add
ad hoc task `model` overrides, lower effort, substitute models or rely on generic
OMP roles. Preserve the current attempt's routing for nested tasks, retries, gapfill
and continuations. Missing/wrong current routing fails closed. Catalog/effort
resolution is not entitlement; live readiness needs bounded inference under launcher
authentication. Offline checks perform no inference or downloads.

Legacy `llm.selector`, `llm.roles` and `llm.verification` are rejected, not fallback
configuration. Audit context/manifest record the producing attempt's routing subset,
excluding remediation and the three Advantage groups. Advantage assigns its own
groups plus reproduction in immutable invocation input. Ordinary resumed attempts
use current routes while retaining `attempt_contexts` and `phase_attempts`.
Advantage has no restart history. Resolve historical contributors against their
actual producing routes; missing attribution limits the claim, never invents a
selector. Linked remediation independently binds Blue and exact-source authority.
Do not hand-edit completed artifacts or use route changes as historical admission gates.

Source/candidate-review artifacts record `provenance: {actor, selector,
artifact_ref}` with the canonical actor, exact assigned full selector and canonical
scan-relative artifact reference. Preserve sorted/deduplicated `contributors`
through aggregation, primitives and synthesis; chains union all relied-upon
investigation, review and model-assisted confirmation/reproduction contributors.
Scanner output and deterministic investigative experiment results have no model
contributor; the reproduce-one confirmation result does carry its actor provenance.
Synthesis records `verification.actor` and `verification.model` separately and
cannot relabel upstream contributors or historical Astra authorship as today's Red route. Corrected findings re-resolve
contributors from effective evidence and ordered primitives. Final diversity is
true only for a nonempty contributor set whose normalized provider/models all
differ from the reviewer, ignoring effort. Forged or missing required new provenance
fails its owning gate; historical missing attribution stays an explicit limitation.
Never copy global diversity or infer provenance from a controller.

## 11. Codegraph operating rules

When enabled, the complete application source namespace is indexed during run
initialization by copying it, without nested `.git` metadata, to
`paths.codegraph_project` and running Codegraph there. Never run `codegraph init`
against `repo_path`. Disabled or failed current preparation records a source-only
capability limitation; old graph caches are never required for intake or resume.

Codegraph is optional. Workers use `query`, `callers`, `callees`, `impact`, and
test-impact-only `affected` when results can improve source investigation.
Missing tools, indexing failure, query failure or unhelpful results continue
source-only with a recorded limitation; no query, snapshot, receipt or answer
is mandatory merely because a plan suggests graph work.
For current graph evidence actually relied upon, contexts and receipts bind the
run/attempt, phase, owner, question and exact request. Validate ownership, paths,
local normalized-result hash and meaningfulness, not source/repository/index hashes.
`--probe` is for harness fixtures only and cannot satisfy an audit receipt.

An executed receipt may be cited as graph evidence only when:

- status and parse status are `ok`;
- the sibling normalized context exists;
- the receipt hash matches the context;
- the response contains a real result node or relationship edge; and
- the source investigation independently establishes the security claim.

Empty and subject-only results are valid negative navigation outcomes but not
evidence of a vulnerability.

The Intrusion coordinator may register a bounded follow-up with
`codegraph_contract.register_followup` before wrapper execution. Its current attempt,
wave, owner, operation and subject remain owned without changing the accepted plan.
Historical receipts cannot establish current edges or require old runtime authority.
There is no write-identity/index-authority step. Optionality does not excuse forged
current receipts or replace inspected source proof.

## 12. Safe reproduction rules

Reproduction is off unless audit context says `safe`. In safe mode, use only
`scripts/run-safe-reproduction.sh` or the `vulnops-reproduce-one` agent that calls
it. Never invoke a target binary, build script, package script, test suite, or proof
command directly.

Support requires a successful `scripts/probe-bubblewrap.sh` namespace/isolation
probe. Binary presence is not support. On a restricted host, record
`environment_required` or `needs_environment` according to the phase schema.
Never add Docker, macOS, or unsandboxed fallback behavior.

Respect configured wall time, CPU, memory, process, output, and parallel limits.
Persist only bounded sanitized tests, result metadata, and allowed draft patches.

For preconfirmation uncertainty, register
`<owner-phase>/experiments/<id>/request.json` and run
`python3 scripts/run-investigation-experiment.py --context <audit-context>
--request <absolute-request>`. The phase must be active and owned. Requests include
current `attempt_id`, obligation, static limitation, isolated behavior,
support/contradiction observations, approved evidence/dependencies and interpretation
boundary; no patch is required. The adjacent deterministic result discards proof
output and never establishes production exposure by itself.

Current `experiment_budget` permits 12/32/64 operations for quick/balanced/full,
concurrency one, 120 wall seconds, 60 CPU seconds, 1024 MiB, 64 processes and
256 KiB output. Preserve consumed reservations across resume; current limits govern
future work. `off` returns `disabled`; unavailable containment returns
`containment_unavailable` with an exact blocker and no fallback.
Historical experiment/reproduction results are never current observed proof.
Reproduction workers record current `assessment_context` only after actual current
contained execution, not after reading or copying old observations.

## 13. Artifact and evidence hygiene

- Use stable IDs generated by deterministic scripts where provided.
- Use target-relative source files in evidence records and schema fields.
- Resolve every `artifact_ref` beneath the active `scan_base`.
- Never cite a dropped, rejected, unknown, or unresolved record as confirmed.
- Keep scanner-specific fields in their canonical tool artifacts.
- Preserve exact `<redacted>` for every secret value field.
- Use canonical source references rather than copying evidence prose.
- Include closures and negative results in their owning phase.
- Keep summaries bounded; they are navigation aids, not evidence authorities.
- Do not manually edit a finalized wrapper to make a validator pass. Repair the
  owning worker result or deterministic builder and rerun finalization.

Source references accept a single line, inclusive range, or comma list such as
`file.py:35,50-53`. Artifact records accept `artifact.json:ID` and
`artifact.json#ID`; both must resolve the same unique declared record. Markdown
navigation documents are context, not record-level proof.

Selected exploration objects permit bounded safe extra notes, never additional
control fields or proof. Required identities, ownership, lifecycle, provenance,
source authorization, local packet/dossier/receipt integrity, budgets and secret hygiene remain strict.
Classify unusable declared support into the owning `evidence_quality` summary;
do not fail unrelated work over a local evidence gap. Consequential
`non_promoted`/`evidence_limited` items require attributed targeted source review
or a precise allocation/priority/external deferral, with missing fact and next
action. Optional unusable support requires independently sufficient inspected
evidence and explicit reasoning that Final Verification challenges.
Preserve source-backed incomplete leads in existing risk-weighted queues without
granting established capabilities. No new retry budgets or edits to accepted checkpoints.

Report final evidence-limited claims and unresolved paths separately from
historical planning deferrals (“not separately scheduled during planning”);
retain exact category totals and bounded details, without summing overlapping
categories as unique vulnerabilities or inferring that historical work was
later resolved. Preserve upstream correction-repair metadata for unresolved
claims. Accounted local limitations allow completion, not a clean assessment.
Integrity violations and malformed required control fields still fail the gate.

## 14. Failure and retry rules

For ordinary audits, retry only when the failure is recoverable and within the
configured attempt budget. Reuse the stable task ID, increment the attempt, and
record the previous error. Do not broaden scope or relax a schema to rescue
malformed output. Exhausting the in-generation attempt budget leaves the run
incomplete with the failure recorded; a later explicit invocation resumes from
its first unfinished checkpoint.

For linked Advantage, discard unusable claim/child evidence and continue healthy
work through reporting without mandatory retry, exhaustion proof or bookkeeping
reconciliation. Apply Section 18's precise local limitations. This does not change
ordinary audit phase gates or bypass execution ownership, source authorization,
containment, secret hygiene or independent finding verification.

The separately budgeted Gap Exploration coordinator also has the narrow
operational-failure closure described in Section 7.5a. It does not convert a
failed model task into a successful yield or relax original phase gates.

Stop the workflow when:

- a live competing session owns the run;
- a required tool or functional contract fails;
- an artifact cannot be repaired within its bounded attempts;
- a phase validator fails after repair/finalization;
- a downstream phase would require mutating upstream evidence; or
- required completion state or report outputs are unreadable.

Stopping closes owned active work safely and leaves the run incomplete. The next
explicit initialization uses current source/configuration in the same selected run,
preserving accepted checkpoints and safe partial accounting. Source/model/budget
changes alone never select a replacement or replay completed phases.

Safe sandbox unavailability is not a reason to execute unsafely. Continue static
analysis and record the environment limitation.

## 15. Main deterministic tools

| Tool | Operational responsibility |
|---|---|
| `run-audit.sh`, `target-inventory.py`, `init-run.py`, `resume-run.py`, `recover-run.py` | Current paths/revisions, stable run selection, isolated creation and first-unfinished recovery |
| `run_lifecycle.py`, `update-run-state.py`, `close-interrupted-run.py`, `audit-status.sh` | Session-owned claims, atomic checkpoints, owned interruption cleanup and read-only status |
| `harness_contract.py` | Current budget and deadline library; no fingerprint CLI or compatibility authority |
| `dependency_contract.py`, `finalize-recon.py` | Deterministic dependency discovery and fresh Recon output |
| `collect-tools.py` | Concurrent deterministic scanner orchestration |
| `run-wraith.sh`, `normalize-wraith.py`, `merge-wraith.py` | Real SCA execution and bounded canonical records |
| `run-poltergeist.sh`, `normalize-poltergeist.py` | Real secret scanning and exact redaction |
| `setup-codegraph.sh`, `run-codegraph.sh`, `codegraph-adapter.py`, `codegraph_contract.py` | Optional current navigation outside target and owned local query receipts |
| `build-hunt-plan.py`, `sast_contract.py`, `finalize-sast.py` | Contextual SAST planning, per-cell validation, aggregation, deduplication, coverage |
| `build-evidence-index.py`, `build-campaign-plan.py` | Evidence/primitive catalog and campaign selection |
| `build-intrusion-wave.py`, `finalize-intrusion.py` | Pending owner assignments, allocation deferrals and exact result closure |
| `prepare-gap-exploration.py`, `gap-exploration-worker.py`, `finalize-gap-exploration.py` | Shared supplementary plans, owned bounded workers and terminal aggregate |
| `gap_graph.py`, `gap-dossier.py` | On-demand qualified navigation and protected downstream cohort allowances |
| `empty-synthesis.py`, `finalize-synthesis.py` | Empty path and strict finding closure |
| `finalize-verification.py` | Verifier identity, corrections, chain-step closure, final findings |
| `render-report.py`, `render-advantage-report.py` | Sanitized current/historical/unresolved report projections |
| `init-advantage.py`, `advantage_lifecycle.py`, native guard hooks | Fresh immutable intake, process-only task coordination and owned teardown |
| `validate-advantage.py`, `advantage-status.sh` | Fresh `--phase` gates and explicit-path read-only completion/portable checks |
| `init-remediation.py`, `build-remediation-plan.py`, `update-remediation-state.py` | Linked post-audit identity, exact per-finding planning, lifecycle |
| `prepare-remediation-work.py`, `publish-remediation-patch.py` | Disposable production edits and safe Git patch publication |
| `finalize-remediation.py`, `validate-remediation.py`, `remediation-status.sh` | Exact dispositions, bundle integrity, read-only status |
| `offline-pack.sh`, `offline_package.py`, `offline-build.sh`, `setup.sh` | Strict locks, deterministic relocatable archives, exact manifests/chunks, offline installation |
| `osv_snapshot.py`, `fetch-osv-db.sh` | Complete checksum-pinned OSV snapshot synchronization, explicit staged lock refresh, and verification |
| `agent-shell.sh`, `run-safe-reproduction.sh` | Stable profile-aware shell and reproduction entrypoints |
| `agent-shell-isolator.sh`, `probe-agent-isolation.sh` | Optional source-tree Linux agent-egress containment and proof |
| `safe-reproduction-backend.sh`, `probe-bubblewrap.sh` | Optional source-tree safe-reproduction containment and proof |
| `validate-config.sh`, `validate-phase.sh`, `validate-scan.sh` | Current readiness, fresh-output phase integrity and read-only execution completion |

## 16. Agent and skill ownership

Phase behavior lives only in `.omp/agents/`. Reusable security doctrine lives
only in `.omp/skills/`. The attack taxonomy lives in
`config/attack-taxonomy-v2.json`. Do not duplicate doctrine in this runbook or in
multiple phase prompts.

Supporting methodology belongs in `references/` beneath its existing native skill
owner. Use explicit relative Markdown links and read each reference only for its
stated task; reuse shared owners rather than duplicate doctrine. Reference files
are not additional skills. The source/package validators check native dependency
availability; this adds no audit phase or evidence ledger. Provenance belongs in
README, not repeated operational introductions or a separate reviewer skill tree.

Canonical phase agents:

```text
vulnops-recon
vulnops-threat-hunter
vulnops-campaign-planning
vulnops-intrusion
vulnops-gap-exploration
vulnops-synthesis
vulnops-final-verification
```

Canonical worker agents:

```text
vulnops-recon-overview
vulnops-recon-trust
vulnops-recon-inputs
vulnops-threatmodel
vulnops-deepdive-chunk
vulnops-verify-one
vulnops-reproduce-one
vulnops-intrusion-campaign
vulnops-gap-investigator
vulnops-independent-verify-one
```

Linked remediation agents:

```text
vulnops-remediation
vulnops-remediate-one
```

Linked Advantage agents:

```text
vulnops-advantage-planning
vulnops-advantage-investigation
vulnops-advantage-investigator
vulnops-advantage-gap-exploration
vulnops-advantage-gap-investigator
vulnops-advantage-synthesis
vulnops-advantage-final-verification
vulnops-advantage-verify-one
```

Agents load only the skills declared in their own files. The main lead does not
copy specialist lens instructions into tasks; it assigns the correct canonical
agent and preserves its contract.

## 17. Change-control rule

When extending the harness, preserve one authority per concern. A new scanner
requires a functional fixture, sanitizer, strict normalized schema, receipt,
evidence-index mapping, and semantic validator. A new phase requires a unique
analytical authority, zero-item behavior, native task ownership and validation.
Ordinary unfinished workflows additionally retain their existing state contracts.

Do not add a model phase for deterministic bookkeeping, a competing report path
within one execution, a raw-output option, a fallback artifact builder, or a duplicate prompt containing
existing skill doctrine. `remediations/` is the sole final fix authority;
safe-reproduction draft patches remain evidence only. The canonical audit
workflow stays small by keeping each stage deep, typed, and accountable.

## 18. Optional linked informed-attacker Advantage

Advantage is an explicitly requested linked execution from a selected, previously
completed audit as historical context, not an ordinary audit phase. The shared
entry contract is
`.omp/skills/vulnops-advantage-security-scan/references/advantage-context.md`;
`.omp/main/vulnops-advantage-main.md` remains the single OMP phase procedure for
both entry forms. The existing controller follows it, not a second controller.

**In an existing prepared OMP**, select Advantage before ordinary initialization.
Create the procedure's native todo with baseline in progress, then invoke once:

```text
python3 scripts/init-advantage.py --in-session [<completed-audit-path-or-run-id>] [existing-options]
```

An explicit bare run ID must match exactly one completed ordinary reporting bundle
under the harness scans namespace. Name the audit path or ID; never derive it
from an old Advantage context or incomplete invocation. Safe paths, completed
publication and readable required evidence remain prerequisites. Relative paths
resolve from the request's invocation directory. Every request starts a fresh
destination, independent of all previous Advantage success, failure or corruption.

Reuse the live host identity (`VULNOPS_LAUNCHER_SESSION_ID` or
`VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID`; conflicting dual identities fail), its
authentication, target guard, private runtime overlay and required actor overrides.
The effective controller must match `model_routing.controllers.advantage`.
`VULNOPS_OMP_CONTROLLER_SELECTOR` records the launch-selected route, not proof
of the effective model after a manual switch. Missing readiness or route mismatch
stops dispatch with the exact prerequisite, never model substitution or a restart.
Never invoke `run_local.sh`, `run.sh`, `advantage.sh`, a stale launch envelope or a
second OMP for an in-session request. One workflow may be active: finish it or
explicitly stop and close its work first, without automatically queuing another.

Omitted mode defaults to **deep**, omitted depth to **full**, canonically in the
initializer. Explicit mode/depth independently override those defaults. Ordinary
audit depth and all per-depth budgets are unchanged. Standard selection requires
`--mode standard`; unqualified requests select deep. Diff/actions retain all
existing conditional prerequisites. No fresh/resume switch exists.

**Terminal startup only**, outside OMP, uses
`./advantage.sh <completed-audit-base> [options]` or
`./run_local.sh --advantage <completed-audit-base> [options]`. The local wrapper
preserves preflight and authentication and dispatches directly to `advantage.sh`, never
`run.sh` or the audit controller. Help and missing-source errors precede
authentication; missing source exits 2. Without the selector, the local wrapper
remains an ordinary audit entrypoint. `run.sh` rejects obsolete `--advantage`
before startup; arguments after `--` remain opaque. No entry form launches,
reruns or waits for an audit, or schedules an automatic post-audit handoff.
The original scan and target remain read-only regardless of linked failure.

Standalone startup opens foreground OMP with the Advantage prompt and configured
route after local authentication, bootstrap and toolchain checks. Baseline intake
and fresh initialization run visibly inside OMP. The launcher exports original
`argv`, absolute invocation `cwd` and `launcher_session_id` in
`VULNOPS_ADVANTAGE_LAUNCH_REQUEST` as JSON data, not instructions. For this initial
standalone request only, create native todo, then invoke exactly once before
reading prior/global Advantage context:

```bash
python3 scripts/init-advantage.py --from-launcher
```

The entrypoint validates the request and matching nonempty
`VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID`, restores the original invocation directory
for relative source/action-source/patch paths, and calls canonical admission and
fresh initialization. Never reconstruct or change the selected arguments.
Later explicit requests in that OMP use `--in-session`, never replay this envelope.
Direct initializer CLI invocation remains available for deterministic tooling.
On failure, stop without stale-context fallback, altered arguments or another run.

After success, bind the returned immutable absolute `input_path` for this launcher
session. Every `--context` argument names that file. It supplies current source,
full baseline catalog, assessment identity, routing, options, budgets, reproduction
mode and paths; it is never edited into progress state. Keep native todo and task
cards visible through closure, without treating UI or files as completion.

Native OMP hooks own process-only task handles, actual terminal outcomes, phase
order and limits. They privately inject `VULNOPS_ADVANTAGE_CALL` into permitted
canonical tool commands after native approval, preserving cancellation. Never
author, override or serialize that payload. Restricted hosts that cannot support
this path fail precisely, without pre-tool execution or another transport.
Advantage writes no manifest, task/dispatch ledger, saved phase checkpoints,
restart diary or global context pointer. Baseline intake is deterministic; use
this phase order:

| Stable task | Phase | Owner |
|---|---|---|
| `AdvantageBaseline` | `baseline` | Initializer |
| `AdvantagePlanning` | `planning` | `vulnops-advantage-planning` |
| `AdvantageInvestigation` | `investigation` | `vulnops-advantage-investigation` |
| `AdvantageGapExploration` | `gap-exploration` | `vulnops-advantage-gap-exploration`, or deterministic skipped closure |
| `AdvantageSynthesis` | `synthesis` | `vulnops-advantage-synthesis`, or deterministic empty finalizer |
| `AdvantageVerification` | `final-verification` | `vulnops-advantage-final-verification`, or deterministic empty finalizer |
| `AdvantageHandoff` | `handoff` | Selected reasoning by investigation owner, or deterministic finalizer |
| `AdvantageReport` | `report` | Deterministic renderer |

Disabled and actions-only invocations validate an explicit skipped gap aggregate;
they launch no discovery workers or graph preparation for that phase.

Before a model phase, arm `python3 scripts/set-omp-deadline.py <context> <phase>`.
Dispatch only the assigned canonical actor with strict native terminal yield,
using the exact assignment binding described in the shared Advantage reference.
Finalizers prepare analytical output, never acceptance of their own task.
After owned work stops, run:

```bash
python3 scripts/validate-advantage.py <base> --context <context> --phase <phase>
```

The native hook accepts a phase after successful semantic validation, correct
phase order and no live/queued work, without a separate successful-yield boolean.
A missing/bad coordinator envelope cannot veto usable byte-bound owned evidence.
Deterministic closure retains honest unreviewed candidates if authoring is absent
or unusable after substantive synthesis work; it does not excuse skipping that
work. Files, planned work and coordinator assertions alone establish neither
evidence authority nor execution. No updater/ledger transition follows.

Keep one active top-level phase. Native outcomes govern current-invocation
attempts; no consumption survives a later request. Discard missing, malformed or
unadmitted child output as evidence, preserve healthy peers and finalize with
precise coverage limitations. Missing proof is `locally_unresolved` unless an
actual failed/cancelled native task supports `execution_failed`; never-launched
work and successful tasks with unusable drafts are not executed failures.
No retry, exhausted-attempt proof or bookkeeping reconciliation is required for
progression. Optional same-ID retries of stopped unadmitted work must advance
useful security proof within live deadlines/resource/concurrency controls, not a
max_attempts dispatch gate.
Never rewrite native worker statuses, fabricate reviews, reset IDs, add a repair
pool or redispatch healthy work. Missing assessments are not clean/zero-vulnerability
claims. Malformed dossiers provide no publication authority or empty success.
Reject foreign provenance locally; corrupted execution-wide ownership, unsafe
access, forbidden execution and secret disclosure remain hard safety failures.

Completion, terminal failure or cancellation releases owned temporary inputs
and disposable graph/derived/reproduction resources after descendants stop.
The native host privately runs `python3 scripts/advantage-cleanup.py --context
<input_path>`; models do not issue updater or completion-state commands. Keep
analytical evidence and unrelated/source bundles unchanged. Cleanup preserves nonzero
status; only host exit deletes the private overlay. No callback launches a
replacement or selects a completed workflow. Hard-kill residue is inert and
never a prerequisite to repair/delete before a new request.

Standard/diff have one informed pass; deep passes use the context's global
allocation, never per-pass multiplication. Preserve per-question terminal
outcomes, source-backed continuations, counterevidence and exact missing facts.
Full baseline access supplements compact packets; it does not turn advisory,
rejected, deferred or environment-required records into exploit primitives.
Use native graph/experiment adapters with explicit linked ownership and existing
containment. No plugin dispatch, target execution or source policy rewriting.
Baseline admission establishes the selected audit's recorded completion and
execution identity through bounded safe readers, never whole-scan revalidation,
baseline hashes, directory seals, current-source equality or old graph runtime.
Malformed historical claims, ambiguous IDs and missing optional support limit
only their usable evidence; unavailable cohorts are unknown, not zero findings.
No historical assertion grants a current attacker capability without new proof.
Read complete canonical unreviewed cohorts into baseline intelligence, preserving
their IDs, reasons and next actions beyond report display caps; never grant them
accepted capability status.
New investigator and independent verifier results carry
`assessment_context` with the active `attempt_id` and `assessment_id` after actual
source review. Retained own accepted outcomes keep their assessed scope and
attribution across publication; imported baseline evidence still needs independent
review before granting new capability. Existing paths alone are not proof. Graph
and experiment results follow current-attempt/containment rules above.

All fourteen native skills are inventoried in README and share the non-skill
context reference beneath `vulnops-advantage-security-scan/references/`.
`vulnops-advantage-define-security-policy` is excluded. Load only skills declared
by each actor; do not duplicate attack doctrine in phase prompts.

For immutable patch inputs, citations identify base or disposable derived views
and exact repository paths. Multi-repository patches require explicit ownership.
Selected fix/risk outputs remain assessments, not applied patches or automatic
merge approval. Hardening remains a proposal. Tracking is deterministic offline
handoff, never provider publication.

After completion, further action selections require a new
`--mode actions --action-source <completed-non-actions-advantage-base>` execution
linked to the selected original audit. Bind exact accepted finding IDs and safe
references to both source bundles, not historical source hashes.
New selections must belong to readable canonical accepted-finding authority;
known rejected/absent IDs fail before dispatch. Unavailable authority requires
that exact prerequisite, not a guessed acceptance. Retained selections keep
their admitted identity without replaying optional historical support.
Initialization skips planning, investigation, gap exploration, synthesis and new-finding verification; handoff
owns selected actions, not new promotion. Patch assessment checks the exact supplied
patch against the selected current base/repository; tracking without review remains
historical. Both completed inputs stay unchanged. Separately requested
`remediate.sh <completed-advantage-base>` retains Blue's single-repository,
non-derived exact-source authority; missing historical/mixed authority is a manual
prerequisite, never expanded patch authorization.

Validate final reporting while the native invocation is alive. Publish companions
before canonical JSON, whose publication metadata carries execution identity,
source/scope, actual routes and action relationships. Completed report plus full
canonical evidence is the product, not a control ledger.
`bash scripts/advantage-status.sh <base>` reads publication by explicit path;
`validate-advantage.py <base> --portable` reads saved evidence without restoring
runtime state. No completed report means no completed or zero-findings assessment.
Report linked/source IDs, report paths, separate assessed-confirmed, imported
historical and unresolved-applicability counts, actual diversity and limitations.
Only new roots, chains and impact expansions count as additional attacker outcomes.
Source-established procedures are not executed attacks; fixture yields are not model-led audits.

Advantage Markdown is the added-value human view, not an accounting export.
Present attacker advancement, complete causal narratives for new roots/chains/
impact expansions and separately labeled material corrections, up to five
consequential unconfirmed or challenged routes/claims, then defensive priorities.
Review qualifies the retained rationale with objections, missing proof or decisive
counterevidence; disagreement or a missing/unusable review never erases admitted
attack rationale. Contradicted routes remain labeled as such, not counted as confirmed or achieved objectives. Keep unchanged
revalidations, historical dossiers and complete overlapping analytical totals in
canonical JSON, not worker/retry diaries or pending queues. Source/observation
status, conditional impact and exact missing proof remain visible at the claim. Existing writeup guidance owns the
reviewed baseline-to-new-path explanation; the deterministic renderer adds no proof.
Actions-only reports present selected assessments without discovery claims.
Link whole canonical artifacts with record IDs separately, binding inherited
citations to their execution. Missing optional inherited destinations remain text,
not broken links. Newly rendered human totals describe additional attack outcomes;
they do not replace canonical assessed-confirmed totals or authorize rewriting a
completed report.

Every subsequent explicit investigation request starts fresh from its selected
ordinary audit. No partial investigation restart exists. Completed diff/action
evidence retains base/derived relationships without recreating old workspaces;
fresh patch actions still validate their actual input and current base.

For an explicit report-only request, the existing renderer supports
`python3 scripts/render-advantage-report.py --retained <base> --mode standard|deep`
with optional `--check` for validation without report writes. This is publication
of retained conclusions, not a native invocation or phase restart. Require a
stopped base-source execution, unselected actions, no existing report outputs,
exclusive ownership and complete final/review/assignment/dossier/provenance
bindings. Never initialize Advantage, fabricate native acceptance, execute
target code or rewrite analytical evidence. Missing authority is a named
prerequisite, not permission to investigate. Publish the hash-bound receipt and
Markdown before atomically committing canonical JSON; validate the complete
bundle with `validate-advantage.py <base> --portable`. Preserve accepted and
complete unconfirmed dossiers, original assessment identities and source
coordinates. Record publication time separately; absent original dates and
repository revisions remain unknown. This explicit path is the only exception
to live-native report publication and never overwrites completed/partial reports.

Deploy runtime and instructions together after stopping old sessions. Do not
migrate, repair, reconcile or delete saved failed Advantage runs. Rollback changes
runtime/instructions only, never completed evidence or synthesized control files.

Deliver source-audit and linked reports with their complete canonical evidence,
plus the explicitly selected completed action source when applicable, preserving
sibling layout. Mutable manifests, task ledgers, source checkouts, runtime state,
credentials and recovery archives are not delivery requirements. Legacy completed
bundles remain readable through their existing local evidence without rewriting.
`validate-advantage.py <delivered-base> --portable` reads that evidence; it does
not repeat source investigation or establish current/dynamic exploitability.
