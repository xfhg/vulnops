# SAST Coordinator Compatibility Prompt

This file is retained for compatibility. The canonical SAST orchestration is now handled by project-local OMP agents:

- `.omp/agents/vulnops-sast-lead.md`
- `.omp/agents/vulnops-threatmodel.md`
- `.omp/agents/vulnops-decompose.md`
- `.omp/agents/vulnops-deepdive-chunk.md`
- `.omp/agents/vulnops-verify-one.md`

## Inputs

These are provided in your assignment:

- **repo_path**: path to the target repository root (read-only)
- **scan_dir**: directory for SAST outputs
- **harness_root**: path to the harness root directory
- **repo_context**: path to repo.md
- **criteria_path**: path to config/scan-criteria.yaml
- **depth**: quick | balanced | full

## Constraints

- READ-ONLY on repo_path. Never modify the target.
- All outputs go to scan_dir.
- No network.
- Do not emit unverified SAST findings into triage.
- Use shared skills:
  - `skill://vulnops-exclusion-rules`
  - `skill://vulnops-self-verification`
  - `skill://vulnops-severity-guidance`

## Required SAST Subpipeline

### 1. Threat Model

Write:

- `<scan_dir>/threat-model.md`
- `<scan_dir>/threat-model.json`

Threat model JSON must include assets, trust boundaries, entrypoints, threats, assumptions, evidence_refs, warnings, and errors.

### 2. Decompose

Write:

- `<scan_dir>/decompose.md`
- `<scan_dir>/task-manifest.json`

Task manifest chunks must include id, risk_rank, size, files, focus_entry_points, hypothesis, threat_id, lenses, related_advisories, and evidence_refs.

Use specialist lenses where appropriate:

- `skill://vulnops-access-control`
- `skill://vulnops-iac`
- `skill://vulnops-batch-etl`
- `skill://vulnops-logic-bug`
- `skill://vulnops-deserialization`
- `skill://vulnops-crypto`

### 3. Deep Dive

Analyze each task-manifest chunk. Write per-chunk outputs under:

- `<scan_dir>/deepdive/<chunk_id>.json`

Aggregate all candidate findings into:

- `<scan_dir>/raw-findings.json`

Raw findings must include id, chunk_id, title, severity, confidence, source_ref, sink_ref, entrypoint_ref, evidence_refs, lenses, description, impact, remediation, and false_positive_notes.

### 4. Adversarial Verify

Verify every raw finding. Assume every finding is wrong until source review proves otherwise.

For each raw finding:

1. Re-read the cited source and sink.
2. Walk callers backward to an external or lower-privileged entrypoint.
3. Hunt for validation, encoding, allow-lists, framework protections, auth/authz gates, feature flags, generated/test-only scope, and dead code.
4. Emit `verified`, `false-positive`, or `deferred`.

Write:

- `<scan_dir>/verified-findings.json`
- `<scan_dir>/dropped-findings.json`

Every raw finding must have exactly one verifier outcome.

### 5. Coverage And Manifest

Write:

- `<scan_dir>/coverage-ledger.json`
- `<scan_dir>/summary.md`
- `<scan_dir>/phase-manifest.json`

Coverage ledger rows close each nominated file/vector as `finding`, `clean`, `not_applicable`, or `deferred`.

## Depth Fanout

- **quick**: max 4 deepdive chunks, max 4 verify tasks
- **balanced**: max 8 deepdive chunks, max 8 verify tasks
- **full**: max 16 deepdive chunks, max 12 verify tasks

Overflow work is queued in batches, not dropped.
