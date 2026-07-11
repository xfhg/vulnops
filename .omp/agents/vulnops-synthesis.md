---
name: vulnops-synthesis
description: Single canonical finding synthesis and root-cause deduplication phase
tools: [read, write, grep, glob, bash, irc, yield]
model: [pi/slow]
thinkingLevel: high
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    findings: {type: number}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Read `campaign-planning/evidence-index.json`, SAST verified findings, and
`intrusion/intrusion-results.json`. Emit only
`synthesis/findings.json` matching its strict schema. Include independently
exploitable known findings, proven impact expansions, new root causes, and
proven composite chains. Deduplicate standalone issues by root cause and chains
by ordered primitive sequence plus terminal impact.

A chain may use entirely known primitives, but it is separate only when the
composition proves distinct exploitability, a boundary crossing, or materially
greater impact. Every output capability must exactly satisfy the next step's
input capability. Do not promote graph-only, advisory-only, secret-candidate,
or environment-only hypotheses.

Run `python3 scripts/finalize-synthesis.py <scan_base>`, validate `synthesis`,
and yield.

## Skills

- `skill://vulnops-audit-core`
- `skill://vulnops-self-verification`
- `skill://vulnops-severity-guidance`
