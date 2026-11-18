# Security audit workflows

Use this guide to choose the work. [README.md](README.md) provides launch commands;
[AGENTS.md](AGENTS.md) defines execution procedures and budgets;
[ARCHITECTURE.md](ARCHITECTURE.md) explains evidence and recovery boundaries.

| Workflow | Starting point | Result |
|---|---|---|
| Ordinary audit | Authorized application source under `target/`. | A reviewed assessment of attacker paths and unresolved obligations. Valid unfinished work can resume. |
| Advantage | A completed ordinary audit plus authorized current source or patch views. | A separate assessment of new roots, chains, impact expansions and baseline corrections/revalidations. Each invocation starts fresh. |
| Production remediation | Eligible accepted findings with supported exact-source patch authority. | A separate production patch bundle; no automatic apply, commit or push. |
| VulnOps @stake | Completed ordinary/Advantage reports. | Read-only exploration of findings, evidence and repairs. See the [viewer guide](stake/README.md). |

Only one assessment workflow may be active in an OMP session. Completing one does
not launch another. An incomplete audit is not an Advantage baseline.

## Ordinary audit

| Phase | Purpose |
|---|---|
| Recon | Map projects, entrypoints, identities, assets and trust boundaries. |
| Tool Collection | Normalize dependency and redacted-secret observations as investigation leads. |
| ThreatHunter (`sast`) | Trace controlled input through security decisions; challenge candidate root causes. |
| Campaign Planning | Prioritize concrete objectives and the missing proof for capability transitions. |
| Intrusion | Establish whether capabilities compose under compatible conditions; follow supported alternatives. |
| Gap Exploration | Pursue consequential remaining source routes under a separate allocation. |
| Synthesis | Deduplicate roots and write complete attack dossiers with repair guidance. |
| Final Verification | Independently challenge access, steps, controls, conditions, impact and the effective dossier. |
| Report | Publish accepted outcomes, evidence and material limits. |

## Advantage

Advantage uses the baseline as intelligence. Historical findings, rejected routes
and unresolved questions guide selection; current applicability still needs proof.
Default mode is `deep` and default depth is `full`, independently overridable.

| Mode | Work |
|---|---|
| `standard` | One informed investigation pass. |
| `deep` | Independent passes sharing one finite allocation and continuation reserve. |
| `diff` | One pass over a supplied immutable patch and bound base/derived source views. |
| `actions` | Selected fix/risk/hardening assessments or offline tracking from a completed non-actions Advantage source. No discovery or finding promotion. |

Discovery proceeds through Baseline → Planning → Investigation → Gap Exploration →
Synthesis → Final Verification → Handoff → Report. Handoff performs only selected
actions; unselected work closes deterministically. Actions-only mode skips the
five discovery/review phases between Baseline and Handoff.

A new root, chain or impact expansion must establish what the baseline did not.
Revalidation is a current assessed conclusion, not an additional attacker outcome.
Corrections remain separate and never edit the original audit. A failed or
interrupted invocation has no resumable investigation checkpoint; see
[retained publication](ARCHITECTURE.md#entry-and-baseline-selection) for the
separate, constrained report-only operation.

## Shared evidence rules

Prove attacker access, control, boundary crossing and concrete impact. Chains need
every transition and compatible prerequisites. Preserve counterevidence and exact
unknowns; zero confirmed findings does not establish clean coverage. Distinguish
source-established behavior from contained observations, and proposed repair
checks from executed tests.
