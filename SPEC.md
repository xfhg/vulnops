# VulnOps V2 Offline Audit Harness Reconstruction Specification

## Purpose and reconstruction target

This document is the normative reconstruction specification for the complete current VulnOps V2 offline audit harness rooted at `/app/latestvops/vulnops-offline`. A developer on another machine can use it to rebuild the same source/control surface, packaged assets, configuration behavior, audit state machine, artifact contracts, and validation behavior without this conversation.

The reconstruction target is schema version `2.0` and workflow `canonical-redteam-v2`. It is a canonical, attacker-led, offline security-audit harness with deterministic lifecycle enforcement around bounded OMP model phases. Exactly one repository is placed beneath `target/`; that repository is immutable audit input.

This specification describes current observable behavior, not a historical patch series. Where prose and executable behavior differ, authority descends in this order: executable validators and scripts; `AGENTS.md`; `ARCHITECTURE.md`; `README.md`, `offline.md`, and `WATCHDOG.md`.

## Provenance and evidence limits

The installed root has no Git metadata at or above it. Consequently, no commit-by-commit diff, original branch, tag, author history, or clean-tree claim is available. Do not infer one.

`offline-pack-manifest.json` records:

| Fact | Value |
|---|---|
| Manifest schema | `vulnops.offline-pack-manifest.v6` |
| Platform | `linux_amd64` |
| Minimum Python | `3.11` |
| Source commit assertion | `4c6adeba003ebefebf89431658fe3bff8f880f66` |
| Source state | `development` |
| OSV snapshot | `2026-07-29` |
| Workflow | `canonical-redteam-v2` |
| Audit schema | `2.0` |

The adjacent archive `vulnops-offline-linux-amd64-4c6adeba003e.tar.gz` is only a provisional transport baseline: its filename agrees with the platform and commit prefix, but no authenticated `.sha256` sidecar exists and an internal manifest cannot authenticate its enclosing archive. If an authenticated build-host checksum becomes available, verify it before extraction. Otherwise, use the archive only as a transport candidate and rely on post-extraction `setup.sh verify` for internal inventory integrity. SHA-256 establishes integrity relative to a trusted digest; it does not establish publisher authenticity.

A release-quality source rebuild requires a clean Git checkout matching the asserted commit. The extracted development package can reconstruct and operate the installed runtime, but cannot recover missing source history or prove release provenance. Never copy credentials from live `config.toml`, target source, scans, remediations, caches, raw scanner/proof output, or binary contents into a reconstruction.

## System invariants and authority map

### Mandatory invariants

1. The harness MUST discover exactly one repository beneath `target/`, MUST treat it as read-only, and MUST NOT write, format, build, test, install into, initialize Codegraph in, or directly execute that target.
2. Every phase MUST bind the exact target fingerprint and absolute paths from `.harness/audit-context.json`. A fingerprint mismatch MUST fail the phase and whole scan.
3. Audit execution MUST remain offline except for the configured LLM endpoint. Provider login MAY contact only the selected authentication service.
4. Durable audit artifacts MUST live under `scans/`; linked fixes under `remediations/`; transient state under `.harness/` or `work/`. These authorities MUST NOT overlap.
5. Raw scanner output, raw proof output, secret values, recoverable secret fragments, entropy material, proof tokens, and partial identifiers MUST NOT be persisted.
6. Target code MUST NOT execute directly. Safe reproduction is opt-in and MUST pass through the functional Bubblewrap-backed wrapper; there is no unsafe fallback.
7. A reportable finding MUST have source-backed attacker access, a crossed trust boundary, root cause, ordered trace, necessary conditions, and concrete impact. Scanner, advisory, Codegraph, and model output are investigation inputs, never proof alone.
8. Fanout MUST be depth-bounded. Overflow MUST queue rather than disappear.
9. Every evidence record, hunt cell, campaign, verifier result, and remediation item MUST receive a terminal disposition.
10. Downstream phases MUST NOT rewrite upstream artifacts. Successful phase directories are hash-sealed and immutable.
11. Synthesis is the sole pre-verification finding authority. Independent final verification is the sole report authority. Reports MUST consume only final verified findings.
12. Only schema `2.0` and workflow `canonical-redteam-v2` are accepted. No compatibility reader, writer, alias, or alternate dispatch exists.
13. Exactly one top-level phase and one ledger task MAY be running. Canonical order MUST be preserved. A phase MUST validate before its successor starts.
14. Raw paths MUST never be reconstructed from convention when the context supplies `paths.*`. Artifact references are scan-relative or target-relative as their schema specifies; filesystem operations use context absolute paths.
15. The configured primary/verifier selectors, normalized model identity, depth, reproduction policy, repository identity, workflow, and role-selector map participate in immutable run compatibility.
16. `context/` is optional untrusted, target-specific input. The harness MUST hash and inventory it, MUST NOT follow symlinks or persist raw contents, and MUST NOT allow it to establish a finding without target or canonical tool evidence.

### One-authority map

| Concern | Sole authority |
|---|---|
| Operator configuration | `config.toml`, parsed by `scripts/parse-config.py` and loaded by `scripts/load-config.sh` |
| Generated OMP runtime configuration | `scripts/bootstrap-omp.sh` output in `.omp/config.yml` and `.harness/home/.omp/agent/` |
| Active paths, identity, policy, budgets, deadlines | `.harness/audit-context.json` |
| Operator-context inventory and identity | `scripts/operator_context.py` |
| Workflow, phases, canonical artifacts | `scripts/harness_contract.py` |
| Run lifecycle and task ledger mutation | `scripts/update-run-state.py` |
| Remediation lifecycle mutation | `scripts/update-remediation-state.py` |
| Artifact shapes | `schemas/v2/*.json` |
| Phase integrity | `scripts/validate-phase.sh` / `validate-phase-v2.py` |
| Whole-scan integrity | `scripts/validate-scan.sh` / `validate-scan-v2.py` |
| Agent operational behavior | `.omp/agents/*.md`, with controller behavior in `.omp/main/` |
| Reusable security doctrine | `.omp/skills/*/SKILL.md` |
| Attack-class allocation | `config/attack-taxonomy-v2.json` |
| Package inventory and immutable hashes | `offline-pack-manifest.json` plus platform lock |
| OSV content | `config/osv-snapshot.lock.json` |
| Final audit report | `report/security-report.{json,md}` rendered from final verification |
| Final remediation patch | `scripts/publish-remediation-patch.py` output under `remediations/` |

## Repository reconstruction inventory

### Source and control inputs

Reconstruct these root controls: `.gitattributes`, `.gitignore`, `AGENTS.md`, `ARCHITECTURE.md`, `README.md`, `offline.md`, `WATCHDOG.md`, `config.toml.example`, `run.sh`, `remediate.sh`, `setup.sh`, and `offline-build.sh`.

Reconstruct `.omp/main/` with the audit and remediation controllers, `.omp/guards/target-readonly.ts`, all 17 agent definitions, and all 16 skills listed below. Reconstruct every checked-in file under `scripts/`, all configuration locks, and the taxonomy. `scripts/` includes shell entrypoints plus Python authorities for initialization, recovery, state, seals, scanners, normalization, schemas, SAST, campaigns, Codegraph, synthesis, verification, reporting, remediation, sanitization, packaging, and validation.

The 33 schema files are:

- `campaign-plan.schema.json`, `candidate-finding.schema.json`, `coverage-ledger.schema.json`, `dependency-limitations.schema.json`
- `evidence-index.schema.json`, `final-findings.schema.json`, `hunt-plan.schema.json`, `hunt-result.schema.json`
- `independent-verification-result.schema.json`, `intrusion-results.schema.json`, `operator-context.schema.json`, `phase-manifest.schema.json`, `recon-research.schema.json`
- `remediation-manifest.schema.json`, `remediation-packet.schema.json`, `remediation-patch-receipt.schema.json`, `remediation-plan.schema.json`, `remediation-worker-result.schema.json`, `remediation.schema.json`
- `repo-context.schema.json`, `report.schema.json`, `reproduction-result.schema.json`, `run-manifest.schema.json`
- `sca-advisories.schema.json`, `secrets-redacted.schema.json`, `security-surfaces.schema.json`, `synthesis-findings.schema.json`
- `task-ledger.schema.json`, `threat-model.schema.json`, `tool-collection.schema.json`, `tool-receipt.schema.json`
- `validation-result.schema.json`, `wishlist.schema.json`

All reside under `schemas/v2/`; filenames and schema IDs are not extension points.

The seven test modules are `test_greenfield_v2.py`, `test_offline_package.py`, `test_launcher_cleanup.py`, `test_model_configuration.py`, `test_recovery.py`, `test_remediation.py`, and `test_sast_contextual_planning.py`.

### Bundled platform assets

`bins/` contains the platform-locked OMP executable and native module, Wraith, Poltergeist, `osv-scanner`, the Codegraph launcher/shim and bundle, plus `.version` markers. `config/offline-pack.linux_amd64.lock.json` and `config/offline-pack.darwin_arm64.lock.json` are distinct platform authorities. `.harness/osv-db/osv-scanner/` contains immutable ZIP snapshots for exactly: CRAN, Go, Hackage, Hex, Maven, NuGet, Packagist, Pub, PyPI, RubyGems, crates.io, and npm.

### Generated configuration

The mutable generated set is `.omp/config.yml`, installed agent-home configuration under `.harness/home/.omp/agent/`, and `config.toml`. The example is source; live `config.toml` is local secret-bearing state and MUST NOT be copied into a distributable package unless `--include-config` is explicitly selected with its disclosure risk understood.

### Runtime outputs and ignored caches

Runtime-mutated prefixes are `.harness/` (except its packaged OSV snapshot), `target/`, `context/`, `scans/`, `remediations/`, and `work/`. `context/` is optional per-target operator input and MUST be excluded from source/package inventory. Ignore and never reconstruct `__pycache__/` or `*.pyc`. Audit sessions, tool work, probes, logs, caches, Codegraph snapshots, prepared remediation copies, reports, and target repositories are outputs, not source inputs.

## Configuration and model identity

`config.toml.example` defines the complete accepted key surface. Unknown tables/keys, wrong types, invalid enums, nonpositive limits, inconsistent model metadata, or missing required values MUST fail parsing/readiness.

| Table | Keys and contract |
|---|---|
| `[llm]` | `base_url`, `api_key`, `selector`, `model`; selector is canonical primary source-validation identity; model is custom-provider metadata consistency only |
| `[llm.roles]` | `orchestrator`, `task`, `slow`, `smol`; all four selectors are required and immutable run identity |
| `[llm.verification]` | `selector`; empty inherits `[llm].selector` |
| `[llm.provider]` | `name`, `api`, `auth`, `discovery`; `api` supports the validated OpenAI-compatible protocol, `auth` the validated credential method, and discovery is `proxy` or `explicit` |
| `[[llm.provider.models]]` | `id`, `name`, optional `context_window`, optional `max_tokens`; used for explicit discovery |
| `[harness]` | `default_depth`: `quick`, `balanced`, or `full` |
| `[harness.network]` | `linux_agent_egress`: `policy_only` or `enforced` |
| `[harness.scans.sast]` | `context_packet_bytes`, a positive bounded UTF-8 packet ceiling |
| `[harness.scans.sast.budget.<depth>]` | `max_hunt_tasks`, `max_hunt_questions`, `max_gapfill_rounds`, `max_attempts`; three explicit depth tables |
| `[harness.reproduction]` | `mode` (`off` or `safe`), `sandbox` (`auto` or `bubblewrap`), `timeout_seconds`, `cpu_seconds`, `memory_mb`, `max_processes`, `max_output_kb`, `max_parallel` |

Default ceilings are quick `12/24/1/2`, balanced `32/64/2/2`, and full `64/128/3/2` for tasks/questions/gapfill/attempts. The top-level task attempt ceiling remains two.

`bootstrap-omp.sh` generates selectors `pi/default`, `pi/task`, `pi/slow`, `pi/smol`, and `pi/tiny` from configured roles; tiered reasoning does not imply different underlying models. The generated `task.agentModelOverrides` MUST map `vulnops-independent-verify-one` to the exact configured verification selector. The worker front-matter `pi/slow` is fallback only and is not authoritative for a valid run.

Model diversity compares normalized provider/model identity via `scripts/model_identity.py`; effort suffixes alone do not create diversity. Primary and verifier selectors and resolved identities are recorded, validated, and immutable across resume. `probe-verifier-model.py` proves selector resolution and readiness.

Credentials remain only in local configuration/provider auth storage, are exported transiently by `load-config.sh`, and MUST NOT enter manifests, reports, artifacts, generated prompts, or package output by default. `setup.sh login <provider>` performs provider authentication only; `verify` and `configure` MUST remain offline.

## Canonical audit lifecycle and state machine

Run `bash scripts/run-audit.sh [quick|balanced|full]` exactly once per initialization/resume operation. It probes the toolchain, discovers the sole target, computes target and operator-context identity, selects a compatible incomplete run or creates one, creates run directories, builds the run-local Codegraph snapshot when enabled, writes manifest/ledger, and publishes `.harness/audit-context.json`. Then use `python3 scripts/update-run-state.py <scan_base> --run-status running`.

| Order | Stable task | Phase | Execution | Canonical task artifact | Empty path / terminal meaning |
|---:|---|---|---|---|---|
| 1 | `Recon` | `recon` | `vulnops-recon` | `repo-context/repo-context.json` | no empty shortcut; `ok/degraded/failed` |
| 2 | `ToolCollection` | `tool-collection` | deterministic `collect-tools.py` | `tool-collection/collection.json` | healthy clean/findings both `ok`; no successful degraded path |
| 3 | `SASTLead` | `sast` | `vulnops-sast-lead` | `sast/verified-findings.json` | budget exhaustion is bounded coverage, not degradation |
| 4 | `CampaignPlanning` | `campaign-planning` | `vulnops-campaign-planning` | `campaign-planning/campaign-plan.json` | valid zero-campaign plan |
| 5 | `Intrusion` | `intrusion` | agent or deterministic finalizer | `intrusion/intrusion-results.json` | zero campaigns finalize `ok` without graph scope |
| 6 | `Synthesis` | `synthesis` | empty probe or `vulnops-synthesis` | `synthesis/findings.json` | probe exit 0 creates empty result; exit 2 requires model |
| 7 | `FinalVerification` | `final-verification` | agent or deterministic finalizer | `final-verification/findings.json` | zero findings finalize with correct diversity |
| 8 | `Report` | `report` | deterministic `render-report.py` | `report/security-report.json` | report final verified findings only |

Every phase MUST produce `phase-manifest.json`; `scripts/validate-phase.sh <scan_base> <phase>` gates advancement. Model-owned tasks are started atomically with the phase, increment the attempt, launch exactly one asynchronous canonical OMP task, and are supervised by exact job ID until a structured terminal yield. Deadline comes from `orchestration.phase_timeout_seconds` and depth. Failure, cancellation, timeout, malformed/missing yield, failed status, or invalid phase closes the attempt before one retry of the same stable ID. IRC is never completion authority.

`update-run-state.py` is the only writer. It enforces canonical order, one running phase/task, maximum two attempts per stable task per recovery generation, scan-relative successful artifacts, null failure artifacts, and hash-sealed successful phases. Synchronizing a validated manifest infers terminal task status (`skipped` maps to task `ok`; `degraded` stays degraded).

Compatible resume requires the same repository path/commit/fingerprint, operator-context fingerprint/limits/counts, depth, reproduction mode, primary and tiered selectors, verifier selector, and workflow. A contract or resolved-budget change triggers deterministic recovery. `recover-run.py` preserves and verifies sealed successful directories before the first unsuccessful phase, recreates that and all downstream directories, removes their ledger tasks, resets attempts by absence, records a bounded recovery event, and returns the run to initialized. Completed runs are closed; interrupted/failed runs are recoverable, but the launcher MUST fail-close active state through `close-interrupted-run.py`. After report validation, `validate-scan.sh` must pass before `--run-status complete`; `audit-status.sh` is read-only.

## Phase implementation contracts

### 1. Recon

`vulnops-recon` launches `Overview`, `Trust`, and `Inputs` in one parallel batch. Workers write only `research/overview.json`, `research/trust-boundaries.json`, and `research/input-surfaces.json`; they do not aggregate. Each reviews every accepted operator-context file as untrusted data and records only concise derived observations. `operator_context.py` accepts at most 1,024 UTF-8 text files and 16 MiB, does not follow symlinks, and skips binary/non-UTF-8 or overflow inputs with warnings. `finalize-recon.py` validates target/context references and emits `repo.md`, `repo-context.json`, `security-surfaces.json`, `operator-context.json`, and the phase manifest. Context-only observations remain hypotheses; corroborated or contradicted observations require target evidence. Any skipped context makes Recon `degraded`. Raw context is never copied. Aggregates become immutable after validation.

### 2. Tool Collection

`collect-tools.py` revalidates Recon, accepts only dependency paths approved by `dependency_contract.py`, runs Wraith invocations plus one Poltergeist scan concurrently with at most four processes, validates receipts, normalizes, merges, stages under `.harness/`, and atomically publishes only after schema/count/hash checks. Required files are `sca-advisories.json`, `wraith-receipt.json`, `secrets-redacted.json`, `poltergeist-receipt.json`, `collection.json`, `summary.md`, and `phase-manifest.json`. Wraith advisories are reachability candidates. Secret values are exactly `<redacted>`; `match_count` preserves occurrences and `candidate_count` counts unique normalized records. Healthy scanners and valid normalization close `ok` with no warnings. Invocation, parse, schema, count, hash, identity, or publication failure closes failed.

### 3. SAST

Order is mandatory: ThreatModel; `build-hunt-plan.py`; contextual deep-dive packets; `sast_contract.py` validation; `finalize-sast.py`; bounded gapfill; candidate verification; alternate advancement until zero; optional safe reproduction; finalization. Packets batch at most four cells sharing source flow, subsystem, domain, and compatible specialist context. Adjacent work becomes a bounded rabbit hole, not widened scope. Tool Collection owns dependency and secret enumeration.

| Depth | Deep dive | Verify | Tasks | Questions | Gapfill rounds |
|---|---:|---:|---:|---:|---:|
| quick | 4 | 4 | 12 | 24 | 1 |
| balanced | 8 | 8 | 32 | 64 | 2 |
| full | 16 | 12 | 64 | 128 | 3 |

Risk-weighted round-robin scheduling precedes gapfill. Gapfill prioritizes evidence-backed rabbit holes, bounded shallow/failed retries, then deferred contextual mappings. Remaining shallow/deferred cells become `depth_limited`, which is honest bounded coverage, not degradation. Only failed capability cells or `environment_required` verified candidates degrade SAST. Required aggregates: `threat-model.json`, `hunt-plan.json`, `raw-findings.json`, `validation-results.json`, `verified-findings.json`, `dropped-findings.json`, `dedup-clusters.json`, `coverage-ledger.json`, `wishlist.json`, `phase-manifest.json`; bounded support lives in `deepdive/`, `verify/`, and `reproduction/`.

### 4. Campaign Planning

Run `build-evidence-index.py` then `build-campaign-plan.py`. The evidence index preserves promoted, closed, rejected, environment-required, and unresolved records. Known findings are first-class primitives. Campaigns explicitly state granted and consumed capabilities, control bypass, composition, typed graph questions, validation, stop conditions, and added value. Lanes are exactly `primitive_led`, `gap_driven`, and `direct_validation`; budgets are deterministic and need not be filled. Required output: `evidence-index.json`, `campaign-plan.json`, `summary.md`, and manifest. Agents may refine prose/questions but not stable IDs, references, or lane budgets.

Derived operator-context observations enter the index as supporting records and may prioritize gap-driven work or annotate campaigns that touch the same target files. They never create attack primitives by themselves.

### 5. Intrusion

Validate campaign count first. For nonzero campaigns, launch one `vulnops-intrusion-campaign` per stable campaign ID with bounded concurrency and queued overflow. Each reads all cited evidence/source, executes every planned typed graph question, stores `context.json` and `receipt.json` at `codegraph-runs/<campaign>/<question>/`, lists every receipt as executed and only meaningful ones as evidence, and writes one `results/<campaign>.json` with `candidate`, `closed`, `rejected`, or `needs_environment`. `finalize-intrusion.py` rejects missing, duplicate, orphaned, malformed, unexecuted, hash-mismatched, or graph-stub results. Zero campaigns run only the same finalizer. Aggregate files: `intrusion-results.json`, `summary.md`, manifest.

### 6. Synthesis

First run `empty-synthesis.py`: exit 0 means it emitted valid empty synthesis; exit 2 means candidate sources require `vulnops-synthesis`; every other exit fails. The model may write only `findings.json`, `summary.md`, and manifest, followed by `finalize-synthesis.py`. Standalone findings deduplicate by root cause; chains by ordered primitive sequence plus terminal impact. A chain has at least two steps and each output capability exactly satisfies the next input. Known primitives may compose only to prove distinct exploitability, a new boundary, or materially greater impact. Graph-only, advisory-only, secret-candidate-only, and environment-only hypotheses cannot promote.

An operator-context observation may support intended behavior or conditions but MUST NOT be the sole source of a finding, trace, root cause, or impact. Independent verification rechecks every such citation and target/tool evidence wins on conflict.

### 7. Final Verification

For nonempty synthesis, the coordinator launches one fresh-context `vulnops-independent-verify-one` per finding using the exact verifier selector override. Each assumes false and verifies reachability, boundary, intended behavior, root cause, trace, conditions, impact, severity, confidence, remediation, dependency version/use/reachability, redacted secret exposure, and every chain transition. Results are `verified`, `corrected`, `rejected`, or `needs_environment` and record exact verifier/diversity metadata. `finalize-verification.py` rejects missing, duplicate, orphaned, malformed, wrong-model/diversity, or incomplete-chain records; corrected records contain a complete finding. Empty synthesis runs only the finalizer. Output: `findings.json`, `summary.md`, manifest.

### 8. Report

`render-report.py` consumes final-verification findings only and emits bounded sanitized `security-report.json`, `security-report.md`, and manifest. It includes origin/severity counts and flags same-model limitation when normalized identities match. Validate phase, then whole scan, then mark complete.

## OMP agents, skills, and security taxonomy

The two controllers are `.omp/main/vulnops-main.md` (audit) and `.omp/main/vulnops-remediation-main.md` (linked remediation). Top-level orchestration remains with the main controller; it MUST NOT spawn a second lead.

All agents have `blocking: false`. Authorized spawn edges are:

- `vulnops-recon` → `vulnops-recon-overview`, `vulnops-recon-trust`, `vulnops-recon-inputs`.
- `vulnops-sast-lead` → `vulnops-threatmodel`, `vulnops-deepdive-chunk`, `vulnops-verify-one`, `vulnops-reproduce-one`.
- `vulnops-intrusion` → `vulnops-intrusion-campaign`.
- `vulnops-final-verification` → `vulnops-independent-verify-one`.
- `vulnops-remediation` → `vulnops-remediate-one`.
- `vulnops-campaign-planning` and `vulnops-synthesis` are leaf coordinators; all named workers are leaves.

The complete 17-agent inventory is: `vulnops-campaign-planning`, `vulnops-deepdive-chunk`, `vulnops-final-verification`, `vulnops-independent-verify-one`, `vulnops-intrusion-campaign`, `vulnops-intrusion`, `vulnops-recon-inputs`, `vulnops-recon-overview`, `vulnops-recon-trust`, `vulnops-recon`, `vulnops-remediate-one`, `vulnops-remediation`, `vulnops-reproduce-one`, `vulnops-sast-lead`, `vulnops-synthesis`, `vulnops-threatmodel`, and `vulnops-verify-one`.

The complete 16-skill inventory is: `vulnops-access-control`, `vulnops-attack-ai-llm`, `vulnops-attack-client`, `vulnops-attack-general`, `vulnops-attack-http-auth`, `vulnops-attack-mobile`, `vulnops-attack-native`, `vulnops-audit-core`, `vulnops-batch-etl`, `vulnops-crypto`, `vulnops-deserialization`, `vulnops-exclusion-rules`, `vulnops-iac`, `vulnops-logic-bug`, `vulnops-self-verification`, and `vulnops-severity-guidance`.

`config/attack-taxonomy-v2.json` defines exactly 28 classes: `injection`, `access_control`, `resource_file`, `cryptography`, `business_logic`, `feature_abuse`, `chained_trust`, `wildcard`, `obvious_code`, `known_dependencies`, `secret_enumeration`, `ai_indirect_injection`, `ai_tool_arguments`, `ai_agency`, `ai_context_output`, `http_framing`, `http_cache`, `auth_tokens`, `auth_federation`, `client_dom`, `client_messaging`, `client_ui`, `client_prototype`, `native_memory`, `native_privileged`, `iac_supply_chain`, `etl_data_movement`, and `mobile_platform`.

Recursion is forbidden beyond declared edges. Coordinator concurrency follows depth tables; overflow queues. Terminal OMP job delivery plus schema-valid yield is completion; files and IRC are not. Workers own one disjoint result; deterministic finalizers own aggregates. `validate-omp-agents.py` validates definitions, allowed tools, edges, selectors, and generated overrides. `target-readonly.ts` guards target writes. Doctrine appears once in skills; operational behavior appears once in agents/runbooks.

## Deterministic tools, schemas, and artifact hygiene

| Family | Inputs and outputs | Fail-closed contracts |
|---|---|---|
| Initialization/state/seals | `run-audit.sh`, `init-run.py`, `resume-run.py`, `recover-run.py`, `target-fingerprint.py`, `harness_contract.py`, `update-run-state.py`, `close-interrupted-run.py`, `phase_seal.py`, `audit-status.sh` produce context, manifest, ledger, seals, status | exact identity; canonical order; atomic writes; two attempts; immutable successful directories |
| Dependency/scanners | `dependency_contract.py`, `collect-tools.py`, Wraith/Poltergeist wrappers and normalizers, `merge-wraith.py`, `finalize-tool-collection.py` produce receipt-, count-, hash-bound SCA/secret wrappers | approved files only; bounded output; exact redaction; temporary raw deletion; atomic publish |
| SAST | `build-hunt-plan.py`, `sast_contract.py`, `finalize-sast.py` produce stable contextual cells/tasks/results, dedup clusters, verification queues, coverage | packet hash binding; exact cell closure; budgets; no unassigned scope; no manual aggregate edits |
| Evidence/campaigns | `build-evidence-index.py`, `build-campaign-plan.py` produce stable evidence/primitive records and bounded lane campaigns | canonical refs only; terminal dispositions; deterministic IDs/budgets |
| Codegraph/intrusion | `setup-codegraph.sh`, `run-codegraph.sh`, `codegraph-adapter.py`, `finalize-intrusion.py` produce run-local snapshot and receipt/context pairs | typed operations; receipt/context hashes; every question executed; meaningful subset only |
| Synthesis/verification/report | `empty-synthesis.py`, `finalize-synthesis.py`, `finalize-verification.py`, `render-report.py` produce sole finding authorities and sanitized report | exact source authority; root-cause/chain closure; verifier identity; no environment-only promotion |
| Sanitization/policy | `artifact_policy.py`, `redact-output.py`, JSON validators | bounded fields; no secrets/raw output/traversal/unknown refs; target-/scan-relative path rules |
| Remediation | init/plan/state/work/publish/finalize/validate/status tools | exact source finding set; disposable work; safe text paths; applying patch; immutable source scan |
| Packaging/config | `parse-config.py`, `load-config.sh`, `bootstrap-omp.sh`, `offline_package.py`, `offline-pack.sh`, `osv_snapshot.py`, install/setup/probes | strict keys/locks/hashes; relocation; no downloads during verify/configure |
| Gates | `validate-config.sh`, `validate-phase.sh`, `validate-scan.sh`, `validate-remediation.py` | any identity, schema, count, hash, path, model, containment, or inventory mismatch fails |

Stable IDs are deterministic wherever builders provide them. Bounded strings, arrays, evidence, errors, and summaries are enforced by schemas/validators. Hashes bind phase seals, source packets, normalized contexts, scanner receipts, package files, OSV archives, and remediation publications. Manual editing of finalized wrappers is prohibited: repair the owning worker result or deterministic input and rerun its finalizer. Path traversal, absolute artifact references, unknown/dropped/rejected references presented as confirmed, downstream mutation, raw outputs, secret values, and recoverable fragments MUST fail validation.

## Offline toolchain, packaging, and installation

Build on a clean matching-platform source checkout. Linux and Darwin locks are separate and authoritative; every asset is verified by exact size and SHA-256. The package includes OMP plus matching native runtime, Wraith, Poltergeist, OSV Scanner, Codegraph bundle/shim, and all 12 locked OSV ecosystems. Binary presence alone is insufficient; setup runs functional native, scanner, Codegraph, OSV, relocation, and path-leak probes.

Normal `fetch-osv-db.sh` synchronization MUST NOT change the lock. An intentional reviewed refresh uses `bash scripts/fetch-osv-db.sh --refresh-lock <snapshot-id>`, stages every ecosystem, validates completeness/hashes, publishes databases, and replaces the lock last.

`bash scripts/offline-pack.sh --platform <linux_amd64|darwin_arm64>` defaults to clean source, rejects dirty/untracked build inputs, and always excludes `context/`. `--allow-dirty` is development-only; `--include-config` intentionally includes credential-bearing configuration; `--force` permits replacing outputs; `--output` selects destination. The packer consumes strict locks and the verified local OSV snapshot, creates a deterministic manifest/archive, and publishes platform-namespaced `offline-pack-chunks.json`. Prior generated archives/chunks are not source inputs.

`./offline-build.sh --platform <platform>` reconstructs chunks safely into an empty directory, rejects traversal/collision/mismatch, and verifies inventory. `bash setup.sh verify` is offline and checks exact immutable inventory, platform locks, OSV, native runtime, relocation, and tools. `bash setup.sh login <provider>` may contact only that provider’s authentication service and installs nothing. Edit `config.toml`, then `bash setup.sh configure`; configure generates OMP state and remains offline. The package is an offline installer, not a restricted runtime: it MUST NOT rewrite configured OMP, LLM, network, or reproduction policy. A development extraction is operationally reproducible but not release provenance.

## Scanners, Codegraph, isolation, and reproduction

Wraith runs only approved dependency inputs, uses accepted clean/findings exit outcomes through `run-wraith.sh`, normalizes into `sca-advisories.schema.json`, and merges deterministically. Poltergeist runs through `run-poltergeist.sh`, accepts only wrapper-defined outcomes, normalizes into `secrets-redacted.schema.json`, and writes literal `<redacted>` for every value. Both produce `tool-receipt.schema.json` receipts whose invocation status, parse status, normalized hashes, and counts must agree with canonical artifacts. Raw temporary output is removed after successful publication and never copied into scans.

Codegraph is enabled by default unless the explicit supported `--no-codegraph` initialization path is selected. Initialization copies the target into a run-local immutable `paths.codegraph_project`; it MUST NOT initialize the target. Operations are exactly `query`, `callers`, `callees`, `impact`, and `affected`. Every planned question has an executed receipt and normalized sibling context, even for no result. A receipt is meaningful evidence only when status/parse are `ok`, context exists and hash matches, and a real result node or edge exists. Empty/subject-only output is valid negative navigation, never vulnerability proof. Source independently establishes security claims.

`policy_only` agent egress applies policy without a harness network namespace and requires no Bubblewrap. `enforced` requires `agent-shell-isolator.sh` plus a successful `probe-agent-isolation.sh`; binary presence is not enough. Safe reproduction requires mode `safe`, a successful functional `probe-bubblewrap.sh`, and execution only via `run-safe-reproduction.sh`/`safe-reproduction-backend.sh`. Enforce configured wall time, CPU, memory, process, output, and parallel limits. Persist only bounded sanitized test/result metadata and allowed draft patches. On unsupported hosts, record `environment_required`/`needs_environment`; never execute unsandboxed or add Docker/macOS fallback.

## Linked remediation

Remediation is not a ninth audit phase. It starts only from a `complete`, whole-scan-valid source run and writes only `remediations/<repo-id>/<audit-run-id>/`; nothing under `scans/` is changed or resealed.

`./remediate.sh <completed-scan-base>` verifies current target fingerprint/identity, initializes or recovers a versioned bundle, writes `.harness/remediation-context.json`, and starts `vulnops-remediation`. Only `update-remediation-state.py` mutates its state. The stable top-level `Remediation` attempt may retry once; recovery resets from the unsuccessful execution while completed bundles remain immutable.

`build-remediation-plan.py` creates exactly one hash-bound packet for each accepted entry in `final-verification/findings.json`; rejected findings are not inputs. Secret and `needs_environment` findings are terminal `manual_required`. Eligible workers run with concurrency quick 4, balanced 8, full 12, queue overflow, and edit only a disposable `work/` copy prepared by `prepare-remediation-work.py`. Allowed production changes are runtime source, deployment/configuration, dependency manifests, and consistent lockfiles. Tests, specs, fixtures, examples, and documentation MUST NOT change.

Only `publish-remediation-patch.py` creates final patches. It enforces target-relative safe text changes, complete root-cause accounting, bounded output, sanitizer/secret hygiene, source identity, and read-only `git apply --check --whitespace=error-all`. Apply-check proves textual applicability only, not compilation, tests, runtime behavior, exploit closure, or independent semantics.

Required bundle artifacts are `remediation-manifest.json`, `remediation-plan.json`, `remediation.json`, `summary.md`, `packets/<finding-id>.json`, `results/<finding-id>.json`, `patches/<finding-id>.patch`, and `receipts/<finding-id>.json`. Every accepted final finding closes `patch_ready` or `manual_required`. Candidate failure after bounded retry may become manual; identity, schema, sanitizer, publication, missing/duplicate/orphan, hash, or non-applying patch failure fails the execution. `remediation-status.sh` is read-only. Never auto-apply, commit, push, or open a pull request.

## Dev-box reconstruction procedure and acceptance matrix

### Clean-source path

1. Obtain a clean Git checkout of asserted commit `4c6adeba003ebefebf89431658fe3bff8f880f66` on the matching supported platform; verify its authenticated repository provenance separately.
2. Restore the inventory above, exact platform lock, schemas, controllers, agents, skills, scripts, tests, and documentation. Use Python 3.11 or newer.
3. Install only locked assets with the bundled installation tooling. Populate/verify the 12-ecosystem OSV snapshot against `config/osv-snapshot.lock.json`; do not refresh the lock unless intentionally reviewing a new snapshot.
4. Copy `config.toml.example` to local `config.toml`, enter local provider settings, and run `bash scripts/validate-config.sh`.
5. Run `python3 scripts/validate-omp-agents.py .`.
6. Run `python3 -m unittest discover -s tests -p 'test_*.py'`; all seven modules must pass. Asset-dependent tests may skip only before assets are intentionally packaged; the final packaged run must not skip them.
7. Build with `bash scripts/offline-pack.sh --platform linux_amd64` (or the exact matching platform). Expect the deterministic archive and `offline/linux_amd64/offline-pack-chunks.json`.
8. In a new empty directory, copy transport outputs, run `./offline-build.sh --platform linux_amd64`, then `bash setup.sh verify`.
9. Edit extracted `config.toml`; optionally run `bash setup.sh login openai-codex`; run `bash setup.sh configure` and `bash scripts/validate-config.sh`.
10. Use a disposable fixture repository only: launch `./run.sh "audit the target repository"`, initialize one quick audit with `bash scripts/run-audit.sh quick`, execute canonical phases, validate each, run `validate-scan.sh`, and confirm context-directed report paths.

### Extracted-package path

1. If and only if an authenticated outer checksum is supplied, verify the archive before extraction. Without one, retain the provisional transport warning.
2. Reconstruct into an empty directory using `./offline-build.sh --platform linux_amd64`.
3. Run `bash setup.sh verify`; it is the post-extraction immutable inventory authority.
4. Edit `config.toml` locally. Optionally authenticate with `bash setup.sh login openai-codex`.
5. Run `bash setup.sh configure`, then `bash scripts/validate-config.sh`.
6. This yields an operational runtime matching the manifest. It does not recover Git history or convert development provenance into release provenance.

### Acceptance matrix

| Area | Command/scenario | Required result |
|---|---|---|
| Configuration/model roles | `bash scripts/validate-config.sh` and `test_model_configuration.py` | strict keys; all role selectors resolve; exact verifier override; correct normalized diversity |
| Agent graph | `python3 scripts/validate-omp-agents.py .` | 17 definitions, declared edges only, valid tools/models, `blocking: false` |
| Greenfield contracts | `test_greenfield_v2.py` | schema/workflow, artifacts, phases, scanners, validators, hygiene all pass |
| Operator context | `test_greenfield_v2.py`, `test_model_configuration.py` | absent/empty stability, bounds/skips, immutable resume identity, and context-only finding rejection pass |
| Contextual SAST | `test_sast_contextual_planning.py` | mapped cells, packet/hash/budget/gapfill and coverage semantics pass |
| Recovery/launcher | `test_recovery.py`, `test_launcher_cleanup.py` | sealed-prefix recovery and fail-closed interruption pass |
| Remediation | `test_remediation.py` | exact finding plan, safe publication, applicability, terminal closure pass |
| Offline package | `test_offline_package.py` | deterministic inventory, locks, chunks, traversal rejection, relocation pass |
| Complete tests | `python3 -m unittest discover -s tests -p 'test_*.py'` | all seven modules pass; final packaged run has no asset skips |
| Package build | `offline-pack.sh --platform linux_amd64` | deterministic archive and platform chunk manifest |
| Installed verification | `offline-build.sh`; `setup.sh verify` | exact immutable inventory, locks, OSV, OMP natives, tools, relocation, no path leaks |
| Disposable quick audit | run launcher and canonical quick lifecycle | context schema `2.0`, workflow `canonical-redteam-v2`, read-only target, eight terminal phases, valid scan/report |
| Final report | context `paths.report` | JSON/Markdown counts agree with independently verified findings only |

## Reconstruction completeness checklist

A reconstruction is complete only when:

- all eight canonical task/phase pairs and empty paths behave exactly as specified;
- every listed schema, agent, skill, test, lock, controller, guard, top-level entrypoint, and deterministic tool is present;
- configuration accepts the complete example surface and rejects unknown/invalid input without consuming live credentials;
- source target remains read-only and all artifact/path/hash/model invariants validate;
- offline package reconstruction and `setup.sh verify` pass on the matching platform;
- the seven-module test suite, agent validator, and configured readiness validator pass;
- a disposable quick audit reaches a whole-scan-valid report under context-provided paths; and
- source changes match this specification; no package, target, scan, remediation, cache, runtime configuration, or generated manifest is required merely to validate the implementation.
