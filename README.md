# vulnops

`vulnops` is a self-contained security audit harness for automated repository review in restricted and air-gapped environments.

The harness treats `target/` as read-only during audit runtime, writes deliverables under `scans/<repo-id>/`, and keeps tool homes, caches, temporary files, and agent state under `.harness/`. Audit runtime is offline except for the configured OpenAI-compatible LLM endpoint.

## Requirements

| Requirement | Purpose |
|---|---|
| Bash-compatible shell environment | Runs harness scripts and OMP orchestration |
| Python 3.12+ | Configuration parsing, validators, Graphify environment, and offline setup |
| Git | Target repository access and source metadata |
| OpenAI-compatible LLM endpoint | Main audit orchestration and graph-guided analysis |

Harness-managed tools are installed into `bins/` with `scripts/install-tools.sh`; do not install or rely on global copies for audit runtime.

## Quick Start

Prepare the harness:

```bash
cp config.toml.example config.toml
vi config.toml

bash scripts/install-tools.sh
bash scripts/fetch-osv-db.sh
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

[graphify]
backend = ""
base_url = ""
api_key = ""
model = ""
full_repo = false
cluster_when = "cross_module_only"

[harness]
default_depth = "quick" # quick | balanced | full
```

Empty `[graphify]` connection values inherit `[llm]`, which is the preferred default.

Run `bash scripts/load-config.sh` to inspect the exported environment. Run `bash scripts/validate-config.sh` before audit runtime to verify tool installation, containment, OMP bootstrap state, OSV database availability, and Graphify LLM access.

Graphify defaults to scoped extraction derived from repository context, deterministic tool evidence, intelligence cards, and triage. Full-repository extraction is opt-in.

## Audit Workflow

The operator request is:

```text
audit the target repo
```

`run.sh` validates the prepared runtime, starts OMP with the project main prompt, and lets the main OMP process coordinate phase agents. The high-level pipeline is:

1. Detect the target repository and create `.harness/audit-context.json`.
2. Build repository context and security-surface inventory.
3. Run SCA, secrets, and SAST in parallel.
4. Fuse evidence into intelligence artifacts and graph-guided hypotheses.
5. Triage verified candidates into normalized findings.
6. Run targeted intrusion analysis with scoped Graphify output.
7. Reconcile final findings and generate reports.
8. Validate scan integrity.

Depth controls SAST fanout and analysis breadth:

| Depth | Deepdive concurrency | Verify concurrency | Intended use |
|---|---:|---:|---|
| `quick` | 4 chunks | 4 findings | Fast, high-confidence review |
| `balanced` | 8 chunks | 8 findings | Broader default review |
| `full` | 16 chunks | 12 findings | Maximum coverage |

Operational doctrine, phase contracts, and worker-agent responsibilities are defined in `AGENTS.md`.

## Outputs

Each audit writes to:

```text
scans/<repo-id>/
```

Primary deliverables:

| Path | Purpose |
|---|---|
| `report/security-report.md` | Human-readable final report |
| `report/security-report.json` | Machine-readable final report and metrics |
| `final-reconciliation/findings.json` | Source of truth for final normalized findings |
| `triage/findings.json` | Deduplicated candidates before final reconciliation |
| `intelligence/` | Evidence corpus, attack-surface map, hypotheses, coverage gaps |
| `sast/`, `sca/`, `secrets/`, `intrusion/` | Phase artifacts and manifests |

Every completed scan should pass:

```bash
bash scripts/validate-scan.sh scans/<repo-id>
```

## Offline / Airgapped Deployment

Build the offline pack on a Linux AMD64 machine with network access:

```bash
bash scripts/offline-pack.sh
```

The build produces:

| Artifact | Git policy |
|---|---|
| `vulnops-offline-<timestamp>.tar.gz` | Ignored; do not commit |
| `offline/vulnops-offline-<timestamp>.tar.gz.part-*` | Commit for Git transport |
| `offline/offline-pack-chunks.json` | Commit with the chunks |

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

`offline-build.sh` verifies every chunk and the reconstructed tarball SHA256 before writing the final archive. `scripts/offline-pack.sh` excludes live `config.toml` by default and packages `config.toml.example` as `config.toml`; use `--include-config` only when intentionally packaging live credentials.

Each offline pack build replaces the previous `offline/` chunk set.

## Script Reference

| Script | Operator use |
|---|---|
| `run.sh [prompt]` | Validate runtime and start OMP |
| `scripts/install-tools.sh` | Install harness tools into `bins/` |
| `scripts/fetch-osv-db.sh` | Fetch the OSV database for offline SCA |
| `scripts/clone-target.sh <url> [branch] [dir]` | Optional pre-runtime target clone helper |
| `scripts/run-audit.sh [depth]` | Detect target and create audit context |
| `scripts/audit-status.sh [scan_base]` | Read-only scan status |
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
├── scans/                 # Audit deliverables
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
