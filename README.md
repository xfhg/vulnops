<p align="center">
  <img src="assets/logo.svg" alt="VulnOps logo" width="240">
</p>

# VulnOps V5.X



VulnOps is a **Red.Team audit platform** that turns application security assessments into defensible remediation priorities. It conducts coordinated intrusion campaigns across application codebases, establishes viable attack paths and their impact, and delivers independently reviewed findings with precise recommendations for code and control changes // **the actions that break the attack path**

**Advantage** extends this work through informed-attacker investigation, using prior assessment intelligence to identify additional routes to compromise. **VulnOps @stake** brings the evidence and repair guidance into a single workspace, connecting security decisions with the files, controls and implementation steps engineering needs to address them.

```mermaid
---
config:
  htmlLabels: false
  flowchart:
    htmlLabels: false
    wrappingWidth: 320
    padding: 20
---
flowchart LR
    subgraph AUDIT["Red Team audit"]
        direction TB
        A1["01 · Recon<br/>Projects, entrypoints<br/>and trust boundaries"]
        A2["02 · Tool Collection<br/>Dependency and<br/>redacted-secret leads"]
        A3["03 · ThreatHunter<br/>Source investigation<br/>and candidate review"]
        A4["04 · Campaign Planning<br/>Attacker objectives<br/>and capability transitions"]
        A5["05 · Intrusion<br/>Pursue campaigns, chains<br/>and alternate routes"]
        A6["06 · Gap Exploration<br/>Investigate consequential<br/>remaining paths"]
        A7["07 · Synthesis<br/>Deduplicate roots and<br/>assemble attack dossiers"]
        A8["08 · Final Verification<br/>Challenge access, controls,<br/>conditions and impact"]
        A9["09 · Report<br/>Findings, evidence, repair<br/>actions and open questions"]
        A1 --> A2 --> A3 --> A4 --> A5 --> A6 --> A7 --> A8 --> A9
    end

    subgraph ADVANTAGE["Advantage · informed attacker"]
        direction TB
        B1["01 · Baseline Intelligence<br/>Prior findings, defeated<br/>routes and unknowns"]
        B2["02 · Planning<br/>Fresh objectives<br/>against current source"]
        B3["03 · Investigation<br/>Alternate entrypoints,<br/>chains and greater impact"]
        B4["04 · Gap Exploration<br/>Pursue overlooked consumers<br/>and missing transitions"]
        B5["05 · Synthesis<br/>Separate new outcomes,<br/>corrections and revalidations"]
        B6["06 · Final Verification<br/>Validate the attack<br/>and claimed advancement"]
        B7["07 · Handoff<br/>Selected fix, risk, hardening<br/>and tracking assessments"]
        B8["08 · Report<br/>Linked outcomes, remediation<br/>priorities and limits"]
        B1 --> B2 --> B3 --> B4 --> B5 --> B6 --> B7 --> B8
    end

    subgraph REMEDIATION["Separate production remediation"]
        direction TB
        R1["Admission and planning<br/>Eligible findings<br/>and exact-source authority"]
        R2["Production patch work<br/>Changes in disposable<br/>source copies"]
        R3["Safety and applicability checks<br/>Patch hygiene and<br/>git apply --check"]
        R4["Remediation outcome<br/>Patch bundle or<br/>explicit manual prerequisites"]
        R1 -->|Eligible| R2 --> R3 --> R4
        R1 -->|Manual prerequisite| R4
    end

    W["VulnOps @stake<br/>Findings and evidence<br/>Attack · code · repair maps"]

    AUDIT -. "Optional · completed audit<br/>+ current source" .-> ADVANTAGE
    AUDIT -. "Explicit remediation<br/>request" .-> REMEDIATION
    ADVANTAGE -. "Explicit remediation<br/>request" .-> REMEDIATION
    AUDIT -->|Reports| W
    ADVANTAGE -->|Reports| W

    classDef stage fill:#18181b,stroke:#71717a,color:#fff
    classDef campaign fill:#830000,stroke:#bc0202,color:#fff
    classDef output fill:#18181b,stroke:#ff1d58,color:#fff
    class A1,A2,A3,A7,A8,B1,B2,B5,B6,B7,R1,R2,R3 stage
    class A4,A5,A6,B3,B4 campaign
    class A9,B8,R4,W output
```

Dashed links require a separate request. The Advantage lane shows investigation modes; actions-only proceeds from Baseline to Handoff and Report. 

Remediation boxes show the steps within its separate workflow; patches are not automatically applied or tested.

| Workflow | Use it for | Entry point |
|---|---|---|
| Ordinary audit | Assess an application or resume unfinished work | `./run.sh` |
| Advantage | Investigate further using a completed audit as intelligence | `./advantage.sh` |
| Remediation | Generate production patches in a separate execution | `./remediate.sh` |
| VulnOps @stake | Explore completed reports, code references and repair instructions | [Viewer guide](stake/README.md) |

V5 is the product version; artifacts use schema `2.0` under `schemas/v2/`.

V5 is an AI-driven security audit platform that investigates application code from an attacker’s perspective. It traces how weaknesses combine into paths to compromise, challenges those paths through independent review, and connects supported findings to the code and controls that need to change. Each finding explains the attacker’s starting access, the conditions required, the potential impact, and **the actions that break the attack path** // giving engineering teams evidence to prioritize and implement repairs, not just a list of findings.

License: [FSL-1.1-ALv2](LICENSE). Copyright 2026 xfhg. 

Each version receives an
additional Apache 2.0 license two years after it is made available.
