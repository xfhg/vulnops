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

OMP starts with `.omp/main/vulnops-main.md` appended to the main process system prompt. Main is the audit controller and spawns phase workers directly. The pipeline is: detect -> recon -> SCA + secrets + SAST lead (parallel) -> SAST threatmodel/decompose/deepdive/verify -> triage -> intrusion analysis (optional) -> final reconciliation -> report -> validation.

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
model = "google/gemma-4-e4b"

[harness]
default_depth = "quick"   # "quick" | "balanced" | "full"

[output]
format = "both"           # "markdown" | "json" | "both"
```

Run `bash scripts/load-config.sh` to see exported env vars. Full options with descriptions are in `config.toml`.

Run `bash scripts/validate-config.sh` before audits to confirm the runtime is fully prepared and contained inside the harness repo.

## Pipeline

```
User: "audit the target repo"
       │
       ▼
  ┌──────────┐
  │  Recon    │  Architecture, trust boundaries → repo.md
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
  ┌────▼────┐
  │ Triage  │  Consolidated findings with risk scores
  └────┬────┘
       │
  ┌────▼──────────┐
  │ Intrusion     │  Graph-guided deep discovery (optional)
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
| `validate-config.sh` | Confirm prepared audit runtime and containment |
| `validate-phase.sh <scan_base> <phase>` | Validate one phase or SAST subphase checkpoint |
| `wait-phase.sh <scan_base> <phase> [seconds]` | Wait deterministically for a phase, then validate it |
| `validate-scan.sh <scan_base>` | Validate manifests, findings, report counts, and redaction |
| `cleanup.sh [all\|target\|work\|logs]` | Clean ephemeral state |

## Directory Structure

```
vulnops/
├── config.toml              # Single source of truth
├── AGENTS.md                # OMP pipeline instructions
├── .omp/
│   ├── main/                # Main-process OMP controller prompt
│   ├── agents/              # Project-local OMP audit agents
│   ├── skills/              # Reusable audit skills and security lenses
│   ├── config.yml           # Project OMP provider policy
│   └── models.yml           # On-prem provider model mapping
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
