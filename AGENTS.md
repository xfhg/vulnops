# vulnops — Security Audit Harness

## How to Run

The user clones a repo into `target/` manually, then says:
> "audit the target repo"

The main OMP process is the audit lead. Do not spawn a lead subagent. Phase subagents are workers only.

### Step 0: Detect Target

```bash
bash scripts/run-audit.sh [depth]
```

This finds the repo inside `target/`, computes all paths, creates scan directories, and writes `.harness/audit-context.json`. Read that file for every path you need.

Depth is `quick` (default), `balanced`, or `full`.

### Configuration

All settings live in `config.toml` at the harness root:
- **[llm]** — gateway URL, API key, model name
- **[graphify]** — backend and model for intrusion analysis
- **[harness]** — scan settings, tool paths
- **[output]** / **[logging]** — output format and log retention

Run `bash scripts/load-config.sh` to see exported env vars.
Run `bash scripts/validate-config.sh` before audit runtime.

Audit runtime is offline except for the configured LLM endpoint. Bootstrap commands such as dependency setup, tool install, OSV DB fetch, and target cloning are outside audit runtime.

### Main Process Controller

`run.sh` injects `.omp/main/vulnops-main.md` into the main OMP process with `--append-system-prompt`. Main is responsible for orchestration:

1. Run `bash scripts/run-audit.sh [depth]`.
2. Read `.harness/audit-context.json`.
3. Spawn phase subagents directly.
4. Use OMP task completion/yield as the terminal phase signal.
5. Run final validation.

Live feedback comes from OMP's native task/subagent cards and IRC. Main uses `irc op=list`, `irc op=wait`, and `irc op=inbox` for live phase presence and progress; `validate-phase.sh` validates after yield; `wait-phase.sh` is only for manual recovery, CI, or non-OMP automation.

Do not use Bash progress probes while a phase subagent is still running. Bash is for setup, short validation gates, and controlled wrapper tools, not for pretending to be OMP's scheduler.

### OMP Project Agents

Project-local OMP agents live in `.omp/agents/`. Use named phase agents, not generic `task` roles:

- `vulnops-recon`
- `vulnops-sca`
- `vulnops-secrets`
- `vulnops-sast-lead`
- `vulnops-threatmodel`
- `vulnops-decompose`
- `vulnops-deepdive-chunk`
- `vulnops-verify-one`
- `vulnops-triage`
- `vulnops-intrusion`
- `vulnops-reconcile`
- `vulnops-reporter`

OMP skills live in `.omp/skills/`. Audit agents should use the shared exclusion, self-verification, severity, and specialist lens skills through `skill://...` when relevant.

### Step 1: Reconnaissance

Main runs `vulnops-recon` as task ID `Recon`.

Required outputs:
- `<paths.repo_md>`
- `<paths.repo_context_json>`
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
- `SASTLead` -> `vulnops-sast-lead`

SCA required outputs:
- `<paths.sca>/summary.md`
- `<paths.sca_raw_advisories>`
- `<paths.sca>/phase-manifest.json`

Secrets required outputs:
- `<paths.secrets>/summary.md`
- `<paths.secrets_redacted_candidates>`
- `<paths.secrets>/phase-manifest.json`

SAST is internally sequential with bounded fanout:

1. `vulnops-threatmodel` writes:
   - `<paths.sast_threat_model>`
   - `<paths.sast_threat_model_md>`
2. `vulnops-decompose` writes:
   - `<paths.sast_task_manifest>`
   - `<paths.sast_decompose_md>`
3. `vulnops-sast-lead` fans out `vulnops-deepdive-chunk` by task-manifest chunk:
   - `quick`: max 4 concurrent chunks
   - `balanced`: max 8 concurrent chunks
   - `full`: max 16 concurrent chunks
   - overflow chunks are queued, not dropped
4. Deepdive writes per-chunk JSON under `<paths.sast_deepdive>` and aggregate raw findings to `<paths.sast_raw_findings>`.
5. `vulnops-sast-lead` fans out `vulnops-verify-one` by raw finding:
   - `quick`: max 4 concurrent findings
   - `balanced`: max 8 concurrent findings
   - `full`: max 12 concurrent findings
   - overflow findings are queued, not dropped
6. Verify writes:
   - `<paths.sast_verified_findings>`
   - `<paths.sast_dropped_findings>`
7. SAST final outputs:
   - `<paths.sast_coverage_ledger>`
   - `<paths.sast>/summary.md`
   - `<paths.sast>/phase-manifest.json`

Main lets OMP's subagent UI and IRC messages show live progress for all three parallel phases. As each phase task yields, Main summarizes its status and validates that phase:

```bash
bash scripts/validate-phase.sh <scan_base> sca
bash scripts/validate-phase.sh <scan_base> secrets
bash scripts/validate-phase.sh <scan_base> sast
```

Raw SAST findings are not final candidates until verified.

### Step 3: Triage

Main runs `vulnops-triage` as task ID `Triage`.

Triage reads SCA, secrets, and only `<paths.sast_verified_findings>` for SAST.

Required outputs:
- `<paths.triage>/consolidated.md`
- `<paths.triage>/findings.json`
- `<paths.triage>/phase-manifest.json`

After triage yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> triage
```

Triage must not promote unverified, dropped, or deferred SAST findings.

### Step 4: Intrusion Analysis

Main runs `vulnops-intrusion` as task ID `Intrusion` after triage.

Required outputs:
- `<paths.intrusion>/summary.md`
- `<paths.intrusion_enrichment>`
- `<paths.intrusion>/phase-manifest.json`

After intrusion yields terminal status, run:

```bash
bash scripts/validate-phase.sh <scan_base> intrusion
```

Intrusion is terminal only when `intrusion/phase-manifest.json` status is `ok`, `degraded`, `skipped`, or `failed`, and `intrusion/enrichment.json` exists. Reconciliation must not start before terminal intrusion state.

### Step 5: Final Reconciliation

Main runs `vulnops-reconcile` as task ID `Reconcile` only after intrusion is terminal.

Required outputs:
- `<paths.final_reconciliation_findings>`
- `<paths.final_reconciliation>/summary.md`
- `<paths.final_reconciliation>/phase-manifest.json`

After final reconciliation yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> final-reconciliation
```

Final reconciliation applies intrusion upgrades/downgrades only when enrichment has evidence references. It must not promote unverified findings.

### Step 6: Report

Main runs `vulnops-reporter` as task ID `Reporter`.

Reporter reads `<paths.final_reconciliation_findings>` as the source of truth.

Required outputs:
- `<paths.final_report_md>`
- `<paths.final_report_json>`
- `<paths.report>/phase-manifest.json`

After reporter yields, run:

```bash
bash scripts/validate-phase.sh <scan_base> report
```

Markdown is presentation only. JSON controls metrics and finding status.

### Step 7: Validate

Run:

```bash
bash scripts/validate-scan.sh <scan_base>
```

If validation fails, present the validation errors instead of pretending the scan is complete.

For phase-level checkpoints, use:

```bash
bash scripts/validate-phase.sh <scan_base> <phase>
```

Supported phases include `recon`, `sca`, `secrets`, `sast-threatmodel`, `sast-decompose`, `sast-deepdive`, `sast-verify`, `sast`, `triage`, `intrusion`, `final-reconciliation`, and `report`.

---

## Constraints

1. **READ-ONLY on target.** Never modify files in `target/`.
2. **Harness-local writes only.** Scan artifacts go under `scans/`; runtime homes, temp files, caches, and logs stay under `.harness/`.
3. **Offline by default.** No internet during audit runtime except the configured LLM endpoint.
4. **Evidence-based.** No speculation. Every finding needs source evidence.
5. **No exploit payloads.** Use safe proof and code reasoning.
6. **No secret exfiltration.** Redact all values before writing artifacts.
7. **Bounded fanout.** Use OMP subagents aggressively but within depth limits.
8. **No passive sleep polling.** Use OMP task/yield and IRC progress, then `scripts/validate-phase.sh`.

## Tools

- `bins/omp` — OMP orchestrator
- `irc` — OMP live subagent presence/progress channel available to Main and phase agents
- `scripts/run-wraith.sh` — SCA scan wrapper
- `scripts/run-poltergeist.sh` — secrets scan wrapper
- `scripts/run-graphify.sh` — intrusion analysis wrapper
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
