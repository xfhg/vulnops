# vulnops

A self-contained, air-gapped security orchestration harness designed to execute automated repository audits without external network dependencies. 

## Prerequisites

| Requirement | Purpose | Install |
|---|---|---|
| **OMP** v15+ | Orchestrator | Auto-installed by `install-tools.sh` |
| **LLM endpoint** | OpenAI-compatible (LMStudio, vLLM, Ollama, etc.) | Set `base_url` in `config.toml` |
| **Python 3.11+** | Config parsing (`tomllib`) | Pre-installed on macOS |
| **git** | Clone target repos | Xcode CLT or `brew install git` |

## Setup

```bash
# 1. Install tools (wraith, poltergeist, OMP) to bins/
bash scripts/install-tools.sh

# 2. Download OSV vulnerability database (one-time)
bash scripts/fetch-osv-db.sh
```

## Usage

```bash
# Clone a repo to audit
bash scripts/clone-target.sh https://github.com/org/repo.git

# Run the full pipeline
bash run.sh "audit the target repo"

# Or open OMP interactively
bash run.sh
```

OMP starts with `.omp/main/vulnops-main.md` appended to the main process system prompt. Main is the audit controller and spawns phase workers directly. The pipeline is: detect -> recon -> SCA + secrets + SAST lead (parallel) -> SAST threatmodel/decompose/deepdive/verify -> intelligence fusion -> triage -> LLM-backed targeted intrusion analysis -> final reconciliation -> report -> validation.

### Depth

Pass to `run-audit.sh` or `run.sh`:

| Level | Time | Description |
|---|---|---|
| `quick` | ~5 min | High-confidence vectors only (default) |
| `balanced` | ~15 min | Broader coverage |
| `full` | ~30 min+ | Comprehensive scan |

## Configuration

`config.toml` is the single source of truth. Key sections:

```toml
[llm]
base_url = "http://localhost:1234/v1"  # OpenAI-compatible endpoint
api_key = "..."
model = "google/gemma-4-e4b"

[graphify]
# Empty values inherit [llm]. This is the default and preferred path.
backend = ""
base_url = ""
api_key = ""
model = ""
full_repo = false
cluster_when = "cross_module_only"

[graphify.max_scope_files]
quick = 40
balanced = 100
full = 200

[graphify.max_scopes]
quick = 4
balanced = 8
full = 16

[harness]
default_depth = "quick"   # "quick" | "balanced" | "full"

[output]
format = "both"           # "markdown" | "json" | "both"
```

Run `bash scripts/load-config.sh` to see exported env vars. Full options with descriptions are in `config.toml`.

Run `bash scripts/validate-config.sh` before audits to confirm the runtime is fully prepared, contained inside the harness repo, and able to reach the configured Graphify LLM. Graphify defaults to targeted scoped extraction derived from recon, deterministic tool evidence, intelligence cards, and triage; full-repo extraction is opt-in.

Run `bash scripts/audit-status.sh` for a read-only audit status check. If it reports the scan complete, answer once and stop; do not re-run phases or keep restating the same result.

## Pipeline

```
User: "audit the target repo"
       │
       ▼
  ┌──────────┐
  │  Recon    │  Architecture, trust boundaries, security surfaces
  └────┬─────┘
       │
  ┌────▼────────────────────────┐
  │  Parallel Scans             │
  │  ├── SCA (wraith + OSV db) │
  │  ├── SAST lead            │
  │  │   ├── threatmodel      │
  │  │   ├── decompose        │
  │  │   ├── deepdive chunks  │
  │  │   └── verify findings  │
  │  └── Secrets (poltergeist)  │
  └────┬────────────────────────┘
       │
  ┌────▼────────────┐
  │ Intelligence    │  Evidence corpus, attack map, graph hypotheses
  └────┬────────────┘
       │
  ┌────▼────┐
  │ Triage  │  Consolidated findings with risk scores
  └────┬────┘
       │
  ┌────▼──────────┐
  │ Intrusion     │  LLM-backed graph-guided deep discovery
  └────┬──────────┘
       │
  ┌────▼──────────┐
  │ Reconcile     │  Final normalized findings
  └────┬──────────┘
       │
  ┌────▼────┐
  │ Report  │  security-report.md + security-report.json
  └─────────┘
       │
       ▼
  validate-scan.sh
```

SAST subagent fanout is bounded by depth:

| Depth | Deepdive concurrency | Verify concurrency |
|---|---:|---:|
| `quick` | 4 chunks | 4 findings |
| `balanced` | 8 chunks | 8 findings |
| `full` | 16 chunks | 12 findings |

Overflow work is queued in batches, not dropped.

## Scripts

| Script | Purpose |
|---|---|
| `run.sh [prompt]` | Entry point — loads config, runs OMP |
| `install-tools.sh` | Download wraith, poltergeist, OMP to `bins/` |
| `fetch-osv-db.sh` | Download OSV database for offline SCA |
| `clone-target.sh <url> [branch]` | Clone a repo to `target/` for auditing |
| `run-audit.sh [depth]` | Detect repo in `target/`, write audit context |
| `jail.sh <command>` | Run a command with harness-local home/cache/temp paths |
| `load-config.sh` | Export `config.toml` env vars |
| `bootstrap-omp.sh` | Generate harness-local OMP config/model registry from `config.toml` |
| `build-intelligence.py <repo> <scan>` | Build/finalize OODA intelligence artifacts after deterministic phases |
| `validate-config.sh` | Confirm prepared audit runtime, containment, and Graphify LLM access |
| `audit-status.sh [scan_base]` | Read-only audit status without restarting phases |
| `validate-phase.sh <scan_base> <phase>` | Validate one phase or SAST subphase checkpoint |
| `wait-phase.sh <scan_base> <phase> [seconds]` | Wait deterministically for a phase, then validate it |
| `validate-scan.sh <scan_base>` | Validate manifests, findings, report counts, and redaction |
| `cleanup.sh [all\|target\|work\|logs]` | Clean ephemeral state |
| `offline-pack.sh [options]` | Build self-contained offline tar.gz for airgapped Linux AMD64 deployment |

## Offline / Airgapped Deployment

For datacenter nodes with no internet, build a single tar.gz on a Linux AMD64 machine that has connectivity, then transfer it to the airgapped target.

**Build machine** (Linux x86_64 with internet):

```bash
bash scripts/offline-pack.sh
# Produces: vulnops-offline-<timestamp>.tar.gz (~500 MB)
```

The default pack contains harness source, locked Linux AMD64 binaries (omp, wraith, poltergeist, osv-scanner), the full OSV database, Python wheels for graphifyy + tree-sitter parsers, an audit manifest, and a `setup.sh` that the target runs once. It does not include live credentials by default: `config.toml.example` is packaged as `config.toml`.

Useful options:

```bash
bash scripts/offline-pack.sh --output /tmp/vulnops-pack.tar.gz
bash scripts/offline-pack.sh --force --output /tmp/vulnops-pack.tar.gz
bash scripts/offline-pack.sh --include-config        # explicitly include local config.toml
bash scripts/offline-pack.sh --refresh-lock          # intentionally refresh locked versions
```

**Airgapped target** (Linux x86_64, Python 3.12, bash 4+, git):

```bash
mkdir -p /opt/vulnops
tar -xzf vulnops-offline-*.tar.gz -C /opt/vulnops
cd /opt/vulnops
# Edit config.toml with your on-prem LLM endpoint and API key
bash setup.sh        # creates venv, seeds OMP config, validates readiness
bash run.sh "audit the target repo"
```

`setup.sh` refuses to continue while the packaged redacted config still has empty `[llm]` fields. After setup, the pipeline runs identically to online — zero network access required except the configured LLM endpoint. The bundled Python wheels are cp312-specific, so the target must have Python 3.12. The `wheels/` directory can be deleted after setup if disk space is tight.

## Directory Structure

```
vulnops/
├── config.toml              # Single source of truth
├── AGENTS.md                # OMP pipeline instructions
├── .omp/
│   ├── main/                # Main-process OMP controller prompt
│   ├── agents/              # Project-local OMP audit agents
│   ├── skills/              # Reusable audit skills and security lenses
│   └── config.yml           # Project OMP provider/tool policy
├── .harness/home/.omp/agent/
│   ├── config.yml           # Generated OMP onboarding/model role config
│   └── models.yml           # Generated on-prem provider model mapping
├── run.sh                   # Entry point
├── config/
│   ├── scan-criteria.yaml   # SAST severity thresholds
│   └── agents/              # Compatibility prompt files used by OMP agents
├── scripts/                 # Harness scripts
├── bins/                    # Installed tool binaries (wraith, poltergeist, omp)
├── target/                  # Cloned repos (gitignored; read-only by policy)
├── schemas/                 # Scan artifact schemas
├── scans/                   # Audit deliverables
└── work/                    # Ephemeral workspace (gitignored)
```

## Cleanup

```bash
bash scripts/cleanup.sh all       # Clean everything except scans/
bash scripts/cleanup.sh target    # Just the cloned repo
bash scripts/cleanup.sh work      # Just the ephemeral workspace
```

Scan results in `scans/` are preserved — they are the deliverables.
