# vulnops

`vulnops` is a self-contained security audit harness for automated repository review in restricted and air-gapped environments.

The harness treats `target/` as read-only during audit runtime, writes each
audit to `scans/<repo-id>/runs/<run-id>/`, and keeps tool homes, caches,
temporary files, and agent state under `.harness/`. Audit runtime is offline
except for the configured OpenAI-compatible LLM endpoint.

## Requirements

| Requirement | Purpose |
|---|---|
| Bash-compatible shell environment | Runs harness scripts and OMP orchestration |
| Python 3.11+ | Configuration parsing (tomllib), validators, and deterministic builders |
| Git | Target repository access and source metadata |
| OpenAI-compatible LLM endpoint | Main audit orchestration (OMP) and agent reasoning |

Harness-managed tools are installed into `bins/` with `scripts/install-tools.sh`; do not install or rely on global copies for audit runtime.

## Quick Start

Prepare the harness:

```bash
cp config.toml.example config.toml
vi config.toml

bash scripts/install-tools.sh
bash scripts/fetch-osv-db.sh
bash scripts/bootstrap-omp.sh
bash scripts/validate-config.sh
```

Prepare one target repository:

```bash
mkdir -p target
git clone https://github.com/org/repo.git target/repo
```

Run the audit:

```bash
bash run.sh "audit the target repo"
```

Check status without restarting phases:

```bash
bash scripts/audit-status.sh
```

Use `bash scripts/clone-target.sh <repo_url> [branch] [clone_dir]` only as a bootstrap convenience. Target cloning and dependency setup happen before audit runtime.

## Configuration

`config.toml` is the single source of truth. The required runtime settings are:

```toml
[llm]
base_url = "https://llm.example.local/v1"
api_key = "..."
model = "provider/model"

[harness]
default_depth = "quick" # quick | balanced | full

[harness.reproduction]
mode = "off" # off | safe; safe is explicit opt-in
```

Run `bash scripts/load-config.sh` to inspect the exported environment. Run `bash scripts/validate-config.sh` before audit runtime to verify tool installation (including the required codegraph binary), containment, OMP bootstrap state, and OSV database availability.

codegraph is the harness's sole graph backend: AST-only, fully offline, and scoped per planned intelligence/intrusion scope. Audit runtime needs no Python virtual environment — the deterministic builders run on system `python3` with stdlib only.

## Audit Workflow

The operator request is:

```text
audit the target repo
```

`run.sh` validates the prepared runtime, starts OMP with the project main prompt, and lets the main OMP process coordinate phase agents. The high-level pipeline is:

1. Detect the target repository and create `.harness/audit-context.json`.
2. Build strict repository context from three parallel recon perspectives.
3. Run SCA and secrets in parallel.
4. Build a dynamic threat model, then hunt a bounded subsystem × attack-class
   matrix without repeating dependency or secret enumeration.
5. Mechanically validate, root-cause deduplicate, fill high-risk coverage gaps,
   and adversarially verify candidates. When explicitly enabled, run narrow
   fail-closed reproduction in an offline disposable sandbox and retain local
   regression-test/draft-patch artifacts.
6. Fuse evidence into intelligence artifacts and graph-guided hypotheses.
7. Triage, run scoped intrusion analysis, and reconcile candidates.
8. Independently verify every reconciled candidate in a fresh context.
9. Render sanitized reports deterministically and validate cross-phase state,
   provenance, counts, artifacts, and the unchanged target fingerprint.

Depth controls SAST fanout and analysis breadth:

| Depth | Hunt concurrency | Verification concurrency | Total hunt cap | Gapfill rounds |
|---|---:|---:|---:|---:|
| `quick` | 4 | 4 | 12 | 1 |
| `balanced` | 8 | 8 | 32 | 2 |
| `full` | 16 | 12 | 64 | 3 |

Operational doctrine, phase contracts, and worker-agent responsibilities are defined in `AGENTS.md`.

## Outputs

Each audit writes to:

```text
scans/<repo-id>/runs/<run-id>/
```

Primary deliverables:

| Path | Purpose |
|---|---|
| `report/security-report.md` | Human-readable final report |
| `report/security-report.json` | Machine-readable final report and metrics |
| `final-verification/findings.json` | Canonical source of truth after independent verification |
| `final-reconciliation/candidates.json` | Strict candidates awaiting independent verification |
| `triage/findings.json` | Deduplicated candidates before final reconciliation |
| `intelligence/` | Evidence corpus, attack-surface map, hypotheses, coverage gaps |
| `sast/reproduction/` | Optional local sanitized tests, draft patches, and fail→pass results |
| `sast/`, `sca/`, `secrets/`, `intrusion/` | Phase artifacts, provenance, coverage, and manifests |
| `run-manifest.json`, `task-ledger.json` | Current-run lifecycle and resumability state |

Every completed scan should pass:

```bash
bash scripts/validate-scan.sh scans/<repo-id>/runs/<run-id>
```

## Offline / Airgapped Deployment

Build the offline pack on the same platform as the offline desktop:

```bash
# Linux AMD64
bash scripts/offline-pack.sh --platform linux_amd64

# Apple Silicon macOS
bash scripts/offline-pack.sh --platform darwin_arm64
```

The build produces:

| Artifact | Git policy |
|---|---|
| `vulnops-offline-<platform>-<timestamp>.tar.gz` | Ignored; do not commit |
| `offline/vulnops-offline-<platform>-<timestamp>.tar.gz.part-*` | Commit for Git transport |
| `offline/offline-pack-chunks.json` | Commit with the chunks for auditability |
| `offline/offline-pack-chunks.sh` | Commit with the chunks; `offline-build.sh` uses this without Python |

Commit the chunk set:

```bash
git add offline/ offline-build.sh
git commit -m "Update offline pack chunks"
```

On the target side, rebuild and extract the tarball:

```bash
bash offline-build.sh

mkdir -p /opt/vulnops
tar -xzf vulnops-offline-*.tar.gz -C /opt/vulnops
cd /opt/vulnops
vi config.toml
bash setup.sh
```

`offline-build.sh` verifies every chunk and the reconstructed tarball SHA256 before writing the final archive. It does not require Python for current chunk sets. `scripts/offline-pack.sh` excludes live `config.toml` by default and packages `config.toml.example` as `config.toml`; use `--include-config` only when intentionally packaging live credentials.

The pack contains only binaries, the OSV database, and harness source — no Python wheels and no bundled CPython. It does not bundle a local model runtime; `config.toml` must point to a local or LAN OpenAI-compatible LLM endpoint before `bash setup.sh` succeeds.

Each offline pack build replaces the previous `offline/` chunk set.

## Script Reference

| Script | Operator use |
|---|---|
| `run.sh [prompt]` | Validate runtime and start OMP |
| `scripts/install-tools.sh` | Install harness tools into `bins/` |
| `scripts/fetch-osv-db.sh` | Fetch the OSV database for offline SCA |
| `scripts/clone-target.sh <url> [branch] [dir]` | Optional pre-runtime target clone helper |
| `scripts/bootstrap-omp.sh` | Generate harness-local OMP config/models from `config.toml` (run automatically by `run.sh`/`setup.sh`) |
| `scripts/run-audit.sh [depth]` | Detect target and create audit context |
| `scripts/update-run-state.py` | Atomically record run, phase, and top-level task state |
| `scripts/build-hunt-plan.py` | Build and gap-fill the bounded hunt plan |
| `scripts/finalize-sast.py` | Validate, deduplicate, advance alternates, and finalize SAST |
| `scripts/run-safe-reproduction.sh` | Execute opt-in narrow proof in an offline sandbox |
| `scripts/finalize-verification.py` | Produce canonical independently verified findings |
| `scripts/render-report.py` | Render sanitized JSON and Markdown deterministically |
| `scripts/audit-status.sh [scan_base]` | Read-only scan status |
| `scripts/setup-codegraph.sh` | Initialize the codegraph index for the target (runs automatically during audit via `run-audit.sh`) |
| `scripts/validate-config.sh` | Validate prepared runtime |
| `scripts/validate-phase.sh <scan_base> <phase>` | Validate a phase checkpoint |
| `scripts/validate-scan.sh <scan_base>` | Validate final scan artifacts |
| `scripts/offline-pack.sh [options]` | Build tarball and Git-friendly chunks |
| `offline-build.sh [--force]` | Rebuild tarball from `offline/` chunks |
| `scripts/cleanup.sh [all|target|work|logs]` | Remove selected ephemeral state |

## Repository Layout

```text
vulnops/
├── AGENTS.md              # Audit orchestration doctrine
├── config.toml.example    # Configuration template
├── config/                # Agent prompts, lock files, and scan criteria
├── .omp/                  # Main prompt, phase agents, and audit skills
├── scripts/               # Harness operations and validation scripts
├── schemas/               # Structured artifact schemas
├── target/                # One target repository, prepared before audit runtime
├── scans/                 # Immutable per-run audit deliverables
├── offline/               # Committable offline pack chunks
├── bins/                  # Harness-managed tool binaries
└── .harness/              # Runtime home, cache, temp, logs, and generated OMP config
```

## Cleanup

```bash
bash scripts/cleanup.sh all
bash scripts/cleanup.sh target
bash scripts/cleanup.sh work
bash scripts/cleanup.sh logs
bash scripts/cleanup.sh --full
```

`all` preserves scan deliverables. Use `--full` only when intentionally removing `scans/`.
