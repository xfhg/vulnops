# vulnops — Canonical V2 Security Audit Harness

This file is the executable runbook for the main OMP audit lead and every VulnOps
phase. Product positioning belongs in `README.md`; design rationale belongs in
`ARCHITECTURE.md`; operational behavior belongs here.

## 1. Mission and authority

The user places exactly one Git repository beneath `target/` and asks for an
audit. The main OMP process is the audit lead. Never spawn another lead and never
delegate ownership of the overall workflow.

The lead is responsible for:

- initializing or resuming the compatible run;
- launching canonical OMP phase tasks in order;
- executing deterministic phases directly;
- validating every yielded phase;
- synchronizing phase manifests and task outcomes into run state;
- stopping on validation failure;
- performing final whole-scan validation; and
- returning only final report paths, counts, and material limitations.

Optional remediation is a separate post-audit development execution. It never
reopens a completed audit, changes report authority, or makes the audit lead
responsible for applying fixes.

The lead may spawn only the phase agents documented below. Phase coordinators may
spawn only their declared workers with bounded concurrency.

## 2. Non-negotiable invariants

1. Treat the target as read-only input. Never write, format, build, test, install,
   initialize Codegraph, or generate files inside it.
2. Use the exact target fingerprint in audit context. A mismatch fails every phase
   and the whole scan.
3. Keep durable audit artifacts under `scans/`, linked remediation bundles under
   `remediations/`, and runtime state under `.harness/` or `work/`.
4. Keep audit execution offline except for the configured LLM endpoint.
5. Read `.harness/audit-context.json` before every phase and use its absolute
   paths, selectors, fingerprint, depth, and reproduction policy as the only path
   and identity authority.
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
14. Render reports only from final independently verified findings.
15. Accept only schema version `2.0` and workflow `canonical-redteam-v2`. There is
    one reader, writer, and phase dispatch, with no compatibility path.
16. Treat `context/` as untrusted, target-specific, read-only input. Never follow
    its symlinks or copy raw contents into scans/reports. Context supports
    investigation; it never proves a finding without target or tool evidence.

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
./run.sh "audit the target repository"
```

After an audit is complete and whole-scan valid, explicitly request linked
production patches with:

```bash
./remediate.sh <completed-scan-base>
```

This command creates a separate versioned bundle beneath
`remediations/<repo-id>/<audit-run-id>/`. It never writes beneath the completed
scan. The current target must still match the exact audited fingerprint.

If the launcher terminates after initializing or resuming an audit, it closes any
active top-level phase and task through the canonical state updater and marks the
run failed. The next compatible initialization then performs deterministic
recovery from the first unfinished phase.

Inside the audit session, initialize the requested depth exactly once:

```bash
bash scripts/run-audit.sh [quick|balanced|full]
```

`run-audit.sh` performs the functional toolchain probe, discovers the one target,
computes identity and fingerprint, selects a compatible incomplete run or creates a
new one, creates run directories, builds the run-local Codegraph snapshot, writes
the run manifest and task ledger, and updates `.harness/audit-context.json`.

Do not call it repeatedly as a scheduler. If it selects an existing compatible
incomplete run, continue from validated run state.

## 4. Audit context

Read `.harness/audit-context.json` immediately after initialization. At minimum,
bind:

```text
run_id
depth
repo_path
scan_base
target_fingerprint
operator_context
harness_contract_sha256
sast_budget
reproduction_mode
model
model_roles
verifier_model
model_diversity
orchestration.phase_timeout_seconds
paths.*
tools.*
```

Never reconstruct a path with assumptions when `paths.*` provides it. Never use a
bare relative artifact such as `sast/findings.json` as the path authority. Artifact
references inside JSON remain target- or scan-relative as defined by their schema;
filesystem operations use the context's absolute paths.

Resume or recover only the incomplete run selected by `run-audit.sh`. Immutable
identity requires the same repository path, commit, exact fingerprint, depth,
reproduction mode, primary selector, all tiered role selectors, verifier selector,
operator-context identity, and workflow. A harness-contract or resolved-budget change triggers deterministic
recovery rather than discarding the run. Completed runs are closed; failed and
interrupted runs are recoverable.

## 5. Run-state protocol

Use `scripts/update-run-state.py`; do not edit manifests or the task ledger by
hand.

The state updater enforces canonical phase order, exactly one running top-level
phase/task, a maximum of two attempts per stable task ID in one recovery
generation, immutable and hash-sealed successful phases, scan-relative successful
artifacts, and null artifacts for failures. Do not work around a rejected state
transition.

At the start of active work:

```bash
python3 scripts/update-run-state.py <scan_base> --run-status running
```

Before a top-level task starts, record the task and phase as running. Increment the
attempt only when a real attempt begins. Model phases then launch one asynchronous
OMP task job and supervise that exact job with `job`; deterministic phases run
inline:

```bash
python3 scripts/update-run-state.py <scan_base> \
  --phase <phase> --phase-status running \
  --task <TaskID> --task-phase <phase> --task-status running \
  --increment-attempt
```

After the task job reaches `completed` with a schema-valid yield, or the
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
degraded remains degraded. On an unrecoverable task or validation error, record the
error and mark the run failed. Do not advance to the next phase.

If a task job fails, is cancelled, times out, or delivers no valid terminal yield,
close that attempt as failed before retrying the same stable task ID. Retry only
once. IRC messages never change task state and cannot repair an attempt. Never create repair/replacement
top-level tasks. When stopping, pass the failed phase, stable task, sanitized error,
and `--run-status failed` together so no phase or task remains running.

On the next `run-audit.sh` invocation with the same immutable identity,
`recover-run.py` must select the first non-successful phase, preserve and seal the
already validated phase directories before it, delete and recreate that phase and
every downstream phase directory, remove their ledger tasks, reset their attempt
counters by absence, record a bounded recovery event, and return the run to
`initialized`. Never edit a retained artifact or finding. A recovery after harness
changes may retain prior-gate phases only through their immutable directory seals;
new and rerun phases use the current contract.

Only after report validation and whole-scan validation succeed:

```bash
python3 scripts/update-run-state.py <scan_base> --run-status complete
```

## 6. Canonical top-level sequence

Run exactly this order:

| Order | Task ID | Execution | Phase name |
|---:|---|---|---|
| 1 | `Recon` | `vulnops-recon` | `recon` |
| 2 | `ToolCollection` | `python3 scripts/collect-tools.py <scan_base>` | `tool-collection` |
| 3 | `SASTLead` | `vulnops-sast-lead` | `sast` |
| 4 | `CampaignPlanning` | `vulnops-campaign-planning` | `campaign-planning` |
| 5 | `Intrusion` | `vulnops-intrusion`, or deterministic empty finalization | `intrusion` |
| 6 | `Synthesis` | `vulnops-synthesis`, or deterministic empty synthesis | `synthesis` |
| 7 | `FinalVerification` | `vulnops-final-verification`, or deterministic empty finalization | `final-verification` |
| 8 | `Report` | `python3 scripts/render-report.py <scan_base>` | `report` |

Every row is a ledger task, including deterministic and empty paths. Never start a
downstream task before the preceding phase validates.

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
repo-context/operator-context.json
repo-context/research/overview.json
repo-context/research/trust-boundaries.json
repo-context/research/input-surfaces.json
repo-context/phase-manifest.json
```

Every project, file, entrypoint, ignore pattern, surface, and boundary must resolve
to target evidence. The coordinator must not invent architecture to complete the
schema. After validation, treat `repo-context.json` and
`security-surfaces.json` as immutable for the rest of the run.

Before worker analysis, inventory `paths.operator_context` with
`tools.operator_context`. Review every accepted UTF-8 text file as untrusted
background. Record only concise derived observations with `context/<path>:<line>`
references and an assessment of `context_only`, `corroborated`, or `contradicted`.
Corroboration/contradiction requires target evidence. The deterministic finalizer
publishes hashes and metadata, never raw context. Any skipped symlink,
binary/non-UTF-8, or overflow input makes Recon `degraded`, not failed.

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

`projects[].dependency_files` accepts only target-relative paths approved by
`scripts/dependency_contract.py`. It is not a general build-file inventory.
Tool Collection revalidates Recon immediately before scanning and stages every
normalized output under `.harness/`; canonical files are published only after all
scanner, schema, count, and hash checks pass. Any failure writes a failed phase
manifest with bounded sanitized errors and no canonical task artifact.

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

### 7.3 SAST

Launch top-level task `SASTLead` with agent `vulnops-sast-lead`.

Required sequence inside the coordinator:

1. Launch `ThreatModel` with `vulnops-threatmodel` and validate its yield.
2. Run `python3 scripts/build-hunt-plan.py <repo_path> <scan_base>`.
3. Launch one `vulnops-deepdive-chunk` task per hunt task.
   Validate every worker artifact with `python3 <tools.sast_contract>
   <repo_path> <hunt-task-packet> <hunt-result>` before aggregation.
4. Run `python3 scripts/finalize-sast.py <repo_path> <scan_base>`.
5. Execute bounded gapfill: build new tasks with `--gapfill`, run only new tasks,
   aggregate them, and repeat until no new task or budget exhaustion.
6. Launch `vulnops-verify-one` per deduplicated validation-queue candidate.
7. Aggregate verifier result JSON and run finalization with
   `--advance-alternates`; verify newly advanced alternates until the command
   reports zero.
8. When reproduction mode is `safe`, launch `vulnops-reproduce-one` only for
   eligible source-verified candidates and only through the safe wrapper.
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
evidence. The planner creates cells only from these mappings; it never constructs
a subsystem × surface × attack-class cross-product.

Batch up to four cells only when they share a source flow, subsystem, domain, and
compatible specialist context. Every packet contains the exact cell definitions,
and every worker returns exactly one cell-specific disposition. A candidate may
mark only the cells it cites. Review outside the assigned files or entrypoints is
returned as a contextual rabbit hole rather than silently widening the task. Do
not repeat dependency or secret enumeration owned by Tool Collection.

Initial scheduling is risk-weighted and round-robin across subsystems. Gapfill
spends its reserve on evidence-backed rabbit holes first, then bounded
shallow/failed retries, then initially deferred contextual mappings. Queue
overflow and all gapfill work remain within the same total budget.

At final SAST closure, any remaining `shallow` or `deferred` cell becomes the
terminal coverage disposition `depth_limited`. Reaching a configured depth,
task, question, round, or attempt ceiling is normal bounded-audit behavior and
must not mark SAST degraded. SAST is degraded only for a material capability
loss represented by a `failed` cell or an `environment_required` verified
candidate. Preserve the depth-limited count in coverage so the report remains
honest about scope without mislabelling expected budget enforcement as failure.

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
supporting artifacts. Source-verified candidates may be promoted;
environment-required candidates remain unconfirmed.

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
python3 scripts/build-campaign-plan.py <scan_base>
```

It then reads every evidence disposition and relevant source location and may
refine hypothesis text, typed graph questions, validation methods, stop conditions,
and expected added value. It may not change stable IDs, canonical references, or
lane budgets.

Required artifacts:

```text
campaign-planning/evidence-index.json
campaign-planning/campaign-plan.json
campaign-planning/summary.md
campaign-planning/phase-manifest.json
```

The evidence index must include promoted, closed, rejected, environment-required,
and unresolved records where present. Known findings are first-class attack
primitives. Explicitly plan for what a primitive grants, what consumes the gained
capability, whether a control is bypassed, and whether multiple primitives compose.
Novelty is not a seed requirement.

Use the bounded lanes `primitive_led`, `gap_driven`, and `direct_validation`.
Never fabricate work to fill a ceiling. Preserve a valid zero-campaign plan.

Canonical task artifact: `campaign-planning/campaign-plan.json`.

### 7.5 Intrusion

Read and validate the campaign count before launching workers.

If campaigns exist, launch top-level task `Intrusion` with agent
`vulnops-intrusion`. It launches exactly one `vulnops-intrusion-campaign` per
campaign using stable campaign IDs and depth-bounded concurrency. Queue overflow.

Each worker must:

- read all cited evidence and complete source paths;
- execute every planned graph question through `scripts/run-codegraph.sh` against
  `paths.codegraph_project`;
- store `context.json` and `receipt.json` at
  `intrusion/codegraph-runs/<campaign-id>/<question-id>/`;
- list every executed receipt in `graph_query_receipts`;
- list only meaningful receipts in the `graph_evidence_refs` subset;
- treat graph output as navigation, never vulnerability proof;
- write exactly one `intrusion/results/<campaign-id>.json`; and
- choose exactly one terminal status: `candidate`, `closed`, `rejected`, or
  `needs_environment`.

After all workers yield, run:

```bash
python3 scripts/finalize-intrusion.py <scan_base>
```

If the campaign list is empty, do not launch the agent. Record the top-level task
and run the same finalizer directly. It must produce an empty wrapper, summary,
and `ok` manifest without creating graph scope.

Required aggregate artifacts:

```text
intrusion/intrusion-results.json
intrusion/summary.md
intrusion/phase-manifest.json
```

The finalizer must reject missing, duplicate, orphan, malformed, unexecuted-query,
hash-mismatched, or graph-stub results. Intrusion must never rewrite Recon surfaces
or Campaign Planning artifacts.

Canonical task artifact: `intrusion/intrusion-results.json`.

### 7.6 Synthesis

Probe the deterministic empty path first:

```bash
python3 scripts/empty-synthesis.py <scan_base>
```

Exit `0` means it produced the valid empty synthesis; do not launch a model. Exit
`2` means candidate sources exist and model synthesis is required. Any other exit
is failure.

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

A chain requires at least two ordered primitive steps. Every output capability
must exactly satisfy the next input capability. A chain may use only known
primitives when their composition proves distinct exploitability, a new boundary,
or materially greater impact. Never promote graph-only, advisory-only,
secret-candidate-only, or environment-only hypotheses.

Run `python3 scripts/finalize-synthesis.py <scan_base>` after model synthesis,
then validate.

Canonical task artifact: `synthesis/findings.json`.

### 7.7 Final Verification

Read the synthesized finding count.

If findings exist, launch top-level task `FinalVerification` with agent
`vulnops-final-verification`. It launches one fresh-context
`vulnops-independent-verify-one` task per finding. The generated
`task.agentModelOverrides` entry must resolve that agent to the exact configured
verifier selector; `pi/slow` in the agent front matter is only a supported
fallback and is not authoritative in a valid audit.

Every verifier must:

- assume the claim is false until source proves it;
- verify attacker reachability, crossed boundary, intended behavior, root cause,
  ordered trace, conditions, impact, severity, confidence, and remediation;
- verify dependency installed version, affected use, and reachability;
- verify only redacted secret location and exposure evidence;
- verify every chain primitive and capability transition in order;
- write one result under `final-verification/results/<finding-id>.json`;
- record exactly `verifier_model` and `model_diversity` from audit context; and
- return `verified`, `corrected`, `rejected`, or `needs_environment`.

After all verifier tasks yield, run:

```bash
python3 scripts/finalize-verification.py <repo_path> <scan_base>
```

If synthesis is empty, do not launch verifier workers. Record the top-level task
and run the finalizer directly; it emits empty findings and rejections with the
correct diversity boolean.

Required aggregate artifacts:

```text
final-verification/findings.json
final-verification/summary.md
final-verification/phase-manifest.json
```

Missing, duplicate, orphan, malformed, wrong-model, wrong-diversity, or incomplete
chain results fail the phase. Corrected results must contain a complete corrected
finding.

Canonical task artifact: `final-verification/findings.json`.

### 7.8 Report

Do not launch a reporting agent. Record `Report` running and execute:

```bash
python3 scripts/render-report.py <scan_base>
```

The renderer reads final verified findings only and writes:

```text
report/security-report.json
report/security-report.md
report/phase-manifest.json
```

The report must remain bounded and sanitized. It includes origin and severity
counts and reports the same-model limitation when the normalized underlying
primary and verifier model identities match. Thinking effort alone is not model
diversity.

Canonical task artifact: `report/security-report.json`.

## 8. Final closure

After Report phase validation, run:

```bash
bash scripts/validate-scan.sh <scan_base>
```

Mark the run complete only when this succeeds. Then use the read-only status view:

```bash
bash scripts/audit-status.sh <scan_base>
```

Return to the user:

- run ID and terminal status;
- final finding count and severity summary;
- confirmed, environment-required, and rejected counts;
- model-diversity state;
- material limitations or degraded phases;
- paths to `security-report.md` and `security-report.json`; and
- whether whole-scan validation passed.

Do not reproduce raw findings, secrets, payloads, or proof output in chat.

### 8.1 Optional linked remediation

Linked remediation begins only after the source run is `complete` and
`validate-scan.sh` succeeds. It is not a ninth audit phase and must not add,
rewrite, or reseal anything under `scans/`.

`remediate.sh` initializes or recovers one versioned execution beneath
`remediations/`, writes `.harness/remediation-context.json`, and launches the
dedicated remediation controller. Use `scripts/update-remediation-state.py` as
the only state writer. Retry the stable top-level `Remediation` attempt once;
completed bundles are immutable.

The deterministic planner creates one hash-bound packet for every accepted
entry in `final-verification/findings.json`. Rejected findings are never inputs.
Secret and `needs_environment` findings are terminal `manual_required` items.
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

Required artifacts are:

```text
remediation-manifest.json
remediation-plan.json
remediation.json
summary.md
packets/<finding-id>.json
results/<finding-id>.json
patches/<finding-id>.patch
receipts/<finding-id>.json
```

Every accepted final finding must close `patch_ready` or `manual_required`.
Missing, duplicate, orphan, unsafe, hash-mismatched, or non-applying patches fail
validation. A bounded candidate failure after retry becomes `manual_required`;
identity, schema, publication, or sanitizer failures fail the execution. Use
`scripts/remediation-status.sh <remediation-base>` for the read-only result view.
Never apply, commit, push, or open a pull request automatically.

## 9. OMP orchestration behavior

Use the terminal OMP job delivery plus schema-valid yield as the completion
signal for top-level model phases. Use `job` to poll/cancel the exact task job.
Use IRC only for genuine peer questions and short top-level stage transitions;
it is never a scheduler or completion signal. Nested task batches are
synchronous, so coordinators wait for the task result rather than IRC-polling.
Leaf workers rely on OMP task progress cards and do not send routine progress
directly to `Main`.

Do not:

- poll directories for completion;
- use sleep loops or Bash as a scheduler;
- read transcript, `agent://`, or `history://` URIs;
- send timer heartbeats with no state change;
- include secrets, full findings, payloads, or raw output in IRC;
- launch a second task for work already represented by an active stable task ID;
  or
- treat a yielded status as valid until the phase gate passes.

`scripts/wait-phase.sh` is manual/CI recovery only. It is not the normal
orchestration mechanism.

## 10. Model roles

Generated OMP roles use the same underlying primary model with tiered reasoning:
`pi/default` for low-effort orchestration, `pi/task` for medium-effort
coordination and Recon, `pi/slow` for high-effort security investigation, and
`pi/smol`/`pi/tiny` for minimal-effort mechanical work. Independent verification
uses the exact configured verifier selector through OMP's per-agent model
override; readiness validation must prove that the override, model, and effort
resolve before an audit begins.

The exact role-selector map is part of run and resume identity. The primary
high-effort selector must be recorded in source-validation metadata. The
verifier selector must be recorded in every independent result. Diversity
compares normalized provider/model identity; a thinking-effort difference alone
is not model diversity. Do not substitute selectors, infer model names, or
rewrite diversity metadata in an agent artifact.

## 11. Codegraph operating rules

The target source is indexed during run initialization by copying it to
`paths.codegraph_project` and running Codegraph there. Never run `codegraph init`
against `repo_path`.

Campaign workers issue typed operations only: `query`, `callers`, `callees`,
`impact`, and `affected`. Use the planned question ID as the receipt directory.
Every planned question requires one executed receipt, even when no meaningful
result is found.

An executed receipt may be cited as graph evidence only when:

- status and parse status are `ok`;
- the sibling normalized context exists;
- the receipt hash matches the context;
- the response contains a real result node or relationship edge; and
- the source investigation independently establishes the security claim.

Empty and subject-only results are valid negative navigation outcomes but not
evidence of a vulnerability.

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
- Never use operator context as the sole source of a finding. When it conflicts
  with target source or canonical tool output, the target/tool evidence wins.
- Do not manually edit a finalized wrapper to make a validator pass. Repair the
  owning worker result or deterministic builder and rerun finalization.

## 14. Failure and retry rules

Retry only when the failure is recoverable and within the configured attempt
budget. Reuse the stable task ID, increment the attempt, and record the previous
error. Do not broaden scope or relax a schema to rescue malformed output. Exhausting
the in-generation attempt budget fails the current execution, not the audit
forever; deterministic recovery starts a new generation at the failed phase.

Stop the workflow when:

- target identity changes;
- a required tool or functional contract fails;
- an artifact cannot be repaired within its bounded attempts;
- a phase validator fails after repair/finalization;
- a downstream phase would require mutating upstream evidence; or
- whole-scan validation fails.

Stopping closes the current execution safely. If target and model/policy identity
remain unchanged, the next initialization recovers from the first unfinished
phase. A target fingerprint or model/policy identity change starts a distinct run
instead of reusing evidence.

Safe sandbox unavailability is not a reason to execute unsafely. Continue static
analysis and record the environment limitation.

## 15. Main deterministic tools

| Tool | Operational responsibility |
|---|---|
| `run-audit.sh`, `init-run.py`, `resume-run.py`, `recover-run.py`, `harness_contract.py` | Target discovery, identity, isolated run creation/resume, failed-phase recovery |
| `update-run-state.py`, `close-interrupted-run.py`, `phase_seal.py`, `audit-status.sh` | Atomic lifecycle updates, fail-closed launcher cleanup, immutable successful-phase seals, read-only status |
| `operator_context.py`, `dependency_contract.py`, `finalize-recon.py` | Bounded context inventory, complete dependency discovery, and Recon sealing |
| `collect-tools.py` | Concurrent deterministic scanner orchestration |
| `run-wraith.sh`, `normalize-wraith.py`, `merge-wraith.py` | Real SCA execution and bounded canonical records |
| `run-poltergeist.sh`, `normalize-poltergeist.py` | Real secret scanning and exact redaction |
| `setup-codegraph.sh`, `run-codegraph.sh`, `codegraph-adapter.py` | Snapshot indexing and typed query receipts |
| `build-hunt-plan.py`, `sast_contract.py`, `finalize-sast.py` | Contextual SAST planning, per-cell validation, aggregation, deduplication, coverage |
| `build-evidence-index.py`, `build-campaign-plan.py` | Evidence/primitive catalog and campaign selection |
| `finalize-intrusion.py` | Exact campaign-result closure |
| `empty-synthesis.py`, `finalize-synthesis.py` | Empty path and strict finding closure |
| `finalize-verification.py` | Verifier identity, corrections, chain-step closure, final findings |
| `render-report.py` | Deterministic sanitized reporting |
| `init-remediation.py`, `build-remediation-plan.py`, `update-remediation-state.py` | Linked post-audit identity, exact per-finding planning, lifecycle |
| `prepare-remediation-work.py`, `publish-remediation-patch.py` | Disposable production edits and safe Git patch publication |
| `finalize-remediation.py`, `validate-remediation.py`, `remediation-status.sh` | Exact dispositions, bundle integrity, read-only status |
| `offline-pack.sh`, `offline_package.py`, `offline-build.sh`, `setup.sh` | Strict locks, deterministic relocatable archives, exact manifests/chunks, offline installation |
| `osv_snapshot.py`, `fetch-osv-db.sh` | Complete checksum-pinned OSV snapshot synchronization, explicit staged lock refresh, and verification |
| `agent-shell.sh`, `run-safe-reproduction.sh` | Stable profile-aware shell and reproduction entrypoints |
| `agent-shell-isolator.sh`, `probe-agent-isolation.sh` | Optional source-tree Linux agent-egress containment and proof |
| `safe-reproduction-backend.sh`, `probe-bubblewrap.sh` | Optional source-tree safe-reproduction containment and proof |
| `validate-config.sh`, `validate-phase.sh`, `validate-scan.sh` | Readiness, phase integrity, and whole-scan gates |

## 16. Agent and skill ownership

Phase behavior lives only in `.omp/agents/`. Reusable security doctrine lives
only in `.omp/skills/`. The attack taxonomy lives in
`config/attack-taxonomy-v2.json`. Do not duplicate doctrine in this runbook or in
multiple phase prompts.

Canonical phase agents:

```text
vulnops-recon
vulnops-sast-lead
vulnops-campaign-planning
vulnops-intrusion
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
vulnops-independent-verify-one
```

Linked remediation agents:

```text
vulnops-remediation
vulnops-remediate-one
```

Agents load only the skills declared in their own files. The main lead does not
copy specialist lens instructions into tasks; it assigns the correct canonical
agent and preserves its contract.

## 17. Change-control rule

When extending the harness, preserve one authority per concern. A new scanner
requires a functional fixture, sanitizer, strict normalized schema, receipt,
evidence-index mapping, and semantic validator. A new phase requires a unique
artifact authority, zero-item behavior, manifest, task ownership, validation
dispatch, and run-state entry.

Do not add a model phase for deterministic bookkeeping, a second report path, a
raw-output option, a fallback artifact builder, or a duplicate prompt containing
existing skill doctrine. `remediations/` is the sole final fix authority;
safe-reproduction draft patches remain evidence only. The canonical audit
workflow stays small by keeping each stage deep, typed, and accountable.
