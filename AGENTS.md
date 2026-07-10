# vulnops — Security Audit Harness

## How to Run

The user clones a repo into `target/` manually, then says:
> "audit the target repo"

The main OMP process is the audit lead. Do not spawn a lead subagent. Phase subagents are workers only.

### Step 0: Detect Target

```bash
bash scripts/run-audit.sh [depth]
```

This finds the repo inside `target/`, computes an exact working-tree
fingerprint, creates an isolated `scans/<repo-id>/runs/<run-id>/` directory,
and writes `.harness/audit-context.json`. Read that file for every path you
need. Only the current incomplete run may resume, and only when repository,
commit, depth, fingerprint, and reproduction mode all match. Completed and
failed runs are never audit input.

Depth is `quick`, `balanced`, or `full`; omission uses
`harness.default_depth` (`balanced` in the example config).

### Configuration

All settings live in `config.toml` at the harness root:
- **[llm]** — gateway URL, API key, model name
- **[harness]** — scan settings, tool paths (codegraph index, scan fanout)
- **[output]** / **[logging]** — output format and log retention

Run `bash scripts/load-config.sh` to see exported env vars.
Run `bash scripts/validate-config.sh` before audit runtime.
Run `bash scripts/audit-status.sh` for read-only status checks. If it reports the scan complete, answer once and stop; do not re-run phases or keep re-stating the same status after compaction.

Audit runtime is offline except for the configured LLM endpoint. Bootstrap commands such as dependency setup, tool install, OSV DB fetch, and target cloning are outside audit runtime.

codegraph is the sole graph backend and a required binary (`bins/codegraph`, validated by `validate-config.sh`). Audit runtime needs no Python virtual environment — the deterministic builders (`build-intelligence.py`, `build-intrusion-plan.py`, `finalize-intrusion.py`) run on system `python3` with stdlib only. Graph evidence is AST-only, offline, and scoped per planned intelligence/intrusion scope (`codegraph-runs/<sid>/codegraph-out/context.json`).

### Main Process Controller

`run.sh` injects `.omp/main/vulnops-main.md` into the main OMP process with `--append-system-prompt`. Main is responsible for orchestration:

1. Run `bash scripts/run-audit.sh [depth]`.
2. Read `.harness/audit-context.json`.
3. Mark the run, phase, and top-level task lifecycle through
   `scripts/update-run-state.py`; synchronize terminal state from the validated
   phase manifest.
4. Spawn phase subagents directly.
5. Use OMP task completion/yield as the terminal phase signal.
6. Run final validation, then mark the run complete or failed.

Live feedback comes from OMP's native task/subagent cards and IRC. Main uses `irc op=list`, `irc op=wait`, and `irc op=inbox` for live phase presence and progress; `validate-phase.sh` validates after yield; `wait-phase.sh` is only for manual recovery, CI, or non-OMP automation.

Do not use Bash progress probes while a phase subagent is still running. Bash is for setup, short validation gates, and controlled wrapper tools, not for pretending to be OMP's scheduler.

Do not inspect subagent transcripts with `agent://...` or `history://...` URIs. They can be mis-emitted as malformed tool calls (`function.name = ""`) against OpenAI-compatible gateways. Use OMP task yield, IRC progress, and filesystem validation artifacts.

### OMP Project Agents

Project-local OMP agents live in `.omp/agents/`. Use named phase agents, not generic `task` roles:

#### Main-spawned phase tasks

- `vulnops-recon`
- `vulnops-sca`
- `vulnops-secrets`
- `vulnops-sast-lead`
- `vulnops-intelligence`
- `vulnops-triage`
- `vulnops-intrusion`
- `vulnops-reconcile`
- `vulnops-final-verification`

#### Recon sub-pipeline

- `vulnops-recon-overview`
- `vulnops-recon-trust`
- `vulnops-recon-inputs`

#### SAST sub-pipeline (spawned by `vulnops-sast-lead` via `task`)

- `vulnops-threatmodel`
- `vulnops-decompose`
- `vulnops-deepdive-chunk`
- `vulnops-verify-one`
- `vulnops-reproduce-one`

#### Final verification sub-pipeline

- `vulnops-independent-verify-one`

OMP skills live in `.omp/skills/`. Audit agents should use the shared exclusion, self-verification, severity, and specialist lens skills through `skill://...` when relevant.

### Step 1: Reconnaissance

Main runs `vulnops-recon` as task ID `Recon`.

Required outputs:
- `<paths.repo_md>`
- `<paths.repo_context_json>`
- `<paths.security_surfaces_json>`
- `<paths.repo_context>/research/overview.json`
- `<paths.repo_context>/research/trust-boundaries.json`
- `<paths.repo_context>/research/input-surfaces.json`
- `<paths.repo_context>/phase-manifest.json`

After the recon task yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> recon
```

If recon fails, stop.

### Step 2: Parallel Security Scans

Main spawns these agents in one OMP task batch with stable IDs:

- `SCA` -> `vulnops-sca`
- `Secrets` -> `vulnops-secrets`

SCA required outputs:
- `<paths.sca>/summary.md`
- `<paths.sca_raw_advisories>`
- `<paths.sca>/phase-manifest.json`

Secrets required outputs:
- `<paths.secrets>/summary.md`
- `<paths.secrets_redacted_candidates>`
- `<paths.secrets>/phase-manifest.json`

After SCA and Secrets both yield and validate, Main runs `SASTLead` ->
`vulnops-sast-lead`. SAST consumes their evidence so code hunters never repeat
dependency or secret enumeration. SAST is internally sequential with bounded
fanout:

1. `vulnops-threatmodel` writes:
   - `<paths.sast_threat_model>`
   - `<paths.sast_threat_model_md>`
2. `vulnops-decompose` writes:
   - `<paths.sast_task_manifest>`
   - `<paths.sast_hunt_plan>`
   - `<paths.sast_decompose_md>`
3. `vulnops-sast-lead` fans out one subsystem/attack-class hunt task:
   - `quick`: max 4 concurrent chunks
   - `balanced`: max 8 concurrent chunks
   - `full`: max 16 concurrent chunks
   - overflow chunks are queued, not dropped
4. Deterministic aggregation validates source traces, deduplicates by root
   cause location, merges provenance, builds the coverage ledger, and loops
   through capped high-risk gapfill until no new work or a cap is reached.
5. `vulnops-sast-lead` fans out `vulnops-verify-one` by deduplicated candidate:
   - `quick`: max 4 concurrent findings
   - `balanced`: max 8 concurrent findings
   - `full`: max 12 concurrent findings
   - overflow findings are queued, not dropped
   - if a preferred dedup trace is rejected, the next distinct trace in that
     root-cause cluster is verified; a surviving root cause is not rechecked
6. When config enables safe reproduction, source-verified candidates may run
   only through `scripts/run-safe-reproduction.sh`; test and draft patch
   artifacts stay under the scan.
7. Verify/finalize writes:
   - `<paths.sast_verified_findings>`
   - `<paths.sast_dropped_findings>`
8. SAST final outputs also include:
   - `<paths.sast_coverage_ledger>`
   - `<paths.sast_validation_results>`
   - `<paths.sast_dedup_clusters>`
   - `<paths.sast_wishlist>`
   - `<paths.sast>/summary.md`
   - `<paths.sast>/phase-manifest.json`

Main lets OMP's subagent UI and IRC messages show live progress. Validate SCA
and Secrets after their parallel batch, then validate SAST after its separate
task yields:

```bash
bash scripts/validate-phase.sh <scan_base> sca
bash scripts/validate-phase.sh <scan_base> secrets
bash scripts/validate-phase.sh <scan_base> sast
```

Raw SAST findings are not final candidates until verified. Source-verified,
dynamically verified, and environment-required candidates retain distinct
tiers; environment-required is never treated as confirmed.

### Step 3: Intelligence Fusion

Main runs `vulnops-intelligence` as task ID `Intelligence` after SCA, Secrets,
and SAST have all yielded and validated.

Required outputs:
- `<paths.intelligence_evidence_corpus>`
- `<paths.intelligence_attack_surface_map>`
- `<paths.intelligence_intel_plan>`
- `<paths.intelligence_cards>`
- `<paths.intelligence_coverage_gaps>`
- `<paths.intelligence_rule_gaps>`
- `<paths.intelligence>/summary.md`
- `<paths.intelligence>/phase-manifest.json`

After intelligence yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> intelligence
```

Intelligence Fusion preserves evidence across phase boundaries. It may create new hypotheses from tool evidence, graph inference, agent exploration, or coverage gaps, but those hypotheses cannot become final findings without triage or intrusion evidence-gate promotion. codegraph is the sole graph backend (AST-only, offline); it runs scoped per planned intelligence scope.

### Step 4: Triage

Main runs `vulnops-triage` as task ID `Triage`.

Triage reads Intelligence Fusion outputs, SCA, secrets, and only `<paths.sast_verified_findings>` for SAST.

Required outputs:
- `<paths.triage>/consolidated.md`
- `<paths.triage>/findings.json`
- `<paths.intrusion_seeds>`
- `<paths.triage>/phase-manifest.json`

After triage yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> triage
```

Triage must not promote rejected, dropped, or deferred SAST findings. It may
carry an explicitly environment-required item forward only with that tier and
its missing-evidence reason intact.

### Step 5: Intrusion Analysis

Main runs `vulnops-intrusion` as task ID `Intrusion` after triage.

Required outputs:
- `<paths.intrusion>/summary.md`
- `<paths.intrusion_enrichment>`
- `<paths.intrusion_plan>`
- `<paths.intrusion>/phase-manifest.json`

After intrusion yields terminal status, run:

```bash
bash scripts/validate-phase.sh <scan_base> intrusion
```

Intrusion is terminal only when `intrusion/phase-manifest.json` status is `ok`, `intrusion/enrichment.json` exists, `intrusion/intrusion-plan.json` exists, and required `intrusion/codegraph-runs/<sid>/codegraph-out/context.json` are non-empty (nodes + edges > 0). Reconciliation must not start before terminal intrusion state. codegraph is AST-only by design.

### Step 6: Final Reconciliation

Main runs `vulnops-reconcile` as task ID `Reconcile` only after intrusion is terminal.

Required outputs:
- `<paths.final_reconciliation_candidates>`
- `<paths.final_reconciliation>/summary.md`
- `<paths.final_reconciliation>/phase-manifest.json`

After final reconciliation yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> final-reconciliation
```

Final reconciliation applies intrusion upgrades/downgrades only when enrichment has evidence references. It must not promote unverified findings.

### Step 7: Independent Final Verification

Main runs `vulnops-final-verification` as task ID `FinalVerification`.

Required outputs:
- `<paths.final_verified_findings>`
- `<paths.final_verification>/summary.md`
- `<paths.final_verification>/phase-manifest.json`

After it yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> final-verification
```

Every reconciled candidate must have exactly one fresh-context verifier result.
Corrections must provide a complete strict finding; missing, duplicate, orphan,
or malformed results fail the phase.

### Step 8: Deterministic Report

Run `python3 scripts/render-report.py <scan_base>`. It reads
`<paths.final_verified_findings>` as the only finding source of truth.
The renderer redacts secrets and technical proof tokens; exact proof inputs
remain only in access-controlled local artifacts, while the report retains
safe evidence, test, and draft-patch references.

Required outputs:
- `<paths.final_report_md>`
- `<paths.final_report_json>`
- `<paths.report>/phase-manifest.json`

After rendering, run:

```bash
bash scripts/validate-phase.sh <scan_base> report
```

Markdown is presentation only. JSON controls metrics and finding status.

### Step 9: Validate

Run:

```bash
bash scripts/validate-scan.sh <scan_base>
```

If validation fails, present the validation errors instead of pretending the scan is complete.
If validation succeeds, mark the run `complete`. The audit request is terminal.
Report the final paths/counts once, then stop issuing tool calls for that request.

For phase-level checkpoints, use:

```bash
bash scripts/validate-phase.sh <scan_base> <phase>
```

Supported phases include `recon`, `sca`, `secrets`, `sast-threatmodel`,
`sast-decompose`, `sast-deepdive`, `sast-verify`, `sast`, `intelligence`,
`triage`, `intrusion`, `final-reconciliation`, `final-verification`, and
`report`.

---

## Constraints

1. **READ-ONLY on target.** Never modify files in `target/`.
2. **Harness-local writes only.** Scan artifacts go under `scans/`; runtime homes, temp files, caches, and logs stay under `.harness/`.
3. **Offline by default.** No internet during audit runtime except the configured LLM endpoint.
4. **Evidence-based.** No speculation. Every finding needs source evidence.
5. **No weaponized payloads.** Safe local proof is permitted only when config
   enables it and only through `scripts/run-safe-reproduction.sh`; never run
   target code unsandboxed.
6. **No secret exfiltration.** Redact all values before writing artifacts.
7. **Bounded fanout.** Use OMP subagents aggressively but within depth limits.
8. **No passive sleep polling.** Use OMP task/yield and IRC progress, then `scripts/validate-phase.sh`.

## Skills

Phase agents declare their own `skill://` lists in their `.omp/agents/*.md`. The shared skill registry lives under `.omp/skills/`:

### Phase agents load

- `skill://vulnops-exclusion-rules` — false-positive exclusion patterns for SAST evidence
- `skill://vulnops-self-verification` — required evidence gate before promoting a finding
- `skill://vulnops-severity-guidance` — severity rating rubric for confirmed findings
- `skill://vulnops-access-control` — authz, IDOR, privilege escalation specialist lens
- `skill://vulnops-iac` — IaC and CI/CD specialist lens
- `skill://vulnops-batch-etl` — batch job and ETL pipeline specialist lens
- `skill://vulnops-logic-bug` — business-logic and race condition specialist lens
- `skill://vulnops-deserialization` — deserialization and gadget specialist lens
- `skill://vulnops-crypto` — cryptography and randomness specialist lens
- `skill://vulnops-audit-core` — shared attacker, evidence, verification-tier, and reporting gate
- `skill://vulnops-attack-general` — general vulnerability hunt doctrine
- `skill://vulnops-attack-ai-llm` — AI/LLM trust and tool-use doctrine
- `skill://vulnops-attack-http-auth` — HTTP, cache, token, and federation doctrine
- `skill://vulnops-attack-client` — browser and client-side doctrine
- `skill://vulnops-attack-native` — native memory and privileged-interface doctrine
- `skill://vulnops-attack-mobile` — mobile OS, app-link, IPC, storage, and WebView doctrine

## Tools

- `bins/omp` — OMP orchestrator
- `irc` — OMP live subagent presence/progress channel available to Main and phase agents
- `scripts/run-wraith.sh` — SCA scan wrapper
- `scripts/run-poltergeist.sh` — secrets scan wrapper
- `scripts/build-intelligence.py` — deterministic OODA intelligence artifact builder/finalizer
- `scripts/build-hunt-plan.py` — bounded area × attack-class planner and gapfill scheduler
- `scripts/finalize-sast.py` — strict aggregation, correction, dedup fallback, and evidence-tier finalizer
- `scripts/run-safe-reproduction.sh` — opt-in fail-closed offline reproduction sandbox
- `scripts/finalize-verification.py` — canonical independent-verification finalizer
- `scripts/render-report.py` — deterministic sanitized report renderer
- `scripts/update-run-state.py` — atomic run/phase/task lifecycle updater
- `scripts/run-codegraph.sh` — codegraph CLI wrapper (required, sole graph backend)
- `scripts/codegraph-context.sh` — codegraph blast-radius context helper (emits per-scope `context.json`)
- `scripts/validate-config.sh` — audit runtime readiness gate
- `scripts/bootstrap-omp.sh` — harness-local OMP onboarding/model bootstrap
- `scripts/validate-phase.sh` — phase artifact checkpoint gate
- `scripts/wait-phase.sh` — manual recovery/CI wait gate, not Main's live orchestration mechanism
- `scripts/validate-scan.sh` — artifact integrity gate

## Cleanup

```bash
bash scripts/cleanup.sh all
```

## Adding Scans

1. Create or update a phase agent under `.omp/agents/`.
2. Add reusable doctrine as a skill under `.omp/skills/<name>/SKILL.md`.
3. Add schemas for new structured outputs.
4. Add paths in `scripts/run-audit.sh`.
5. Add phase checks in `scripts/validate-phase.sh`.
6. Add final validation in `scripts/validate-scan.sh`.
