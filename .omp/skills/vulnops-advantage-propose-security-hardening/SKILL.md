---
name: vulnops-advantage-propose-security-hardening
description: Produce explicitly requested bounded Advantage hardening proposals tied to accepted attack transitions and falsifiable invariants, without implementing fixes.
---

# Advantage Propose Security Hardening

Read the [native Advantage context](../vulnops-advantage-security-scan/references/advantage-context.md)
first. When diagnosing an accepted attack transition or comparing hardening
options, read [hardening analysis](references/hardening-analysis.md).

## Explicit request and immutable inputs

Dispatch only for selected `--hardening`. The native investigation actor owns
bounded handoff analysis after final verification. For post-completion work,
use **Shared top-level entry** in the shared context reference with
`--mode actions --action-source <completed-non-actions-advantage-base>` bound to
the same original audit. Inside OMP only the controller invokes
`init-advantage.py --in-session` with those options and `--hardening`; assigned
workers never initialize top-level work or invoke a launcher. Preserve explicit
depth (otherwise full). Use the exact admitted finding source, accepted dossiers,
full baseline and available evidence closures, and current source under the shared
assessment contract; never mutate either bundle or target.
A hardening request authorizes analysis only, not implementation, new discovery,
publication, or a mandatory architectural rewrite.

## Evidence to design choice

Tie the structural diagnosis to accepted dossiers and decisive source consumers.
State falsifiable invariants, compare proportionate local repair with genuinely
different alternatives, and explain security and engineering tradeoffs, residual
risk, legitimate behavior and rollout/rollback. Separate observed facts,
source-established behavior, inference and proposals. Recommend conditionally;
missing support is not evidence that no opportunity exists.

## Native handoff output

For a proposal, author a native `hardening` record in `handoff/action-draft.json`
with `outcome: proposal`, `finding_execution_id`, `finding_ids`, nonempty
`attack_transitions`, `falsifiable_invariant`, `assumptions`, nonempty `tradeoffs`,
and `citations`; explain alternatives in `proposal` and the conditional
recommendation in `rationale`. With no structural opportunity, use only
`outcome: no_opportunity`, `finding_execution_id`, `reviewed_finding_ids`
covering the exact accepted set (including an empty set), and an honest
`rationale`; do not fabricate a proposal or source citation.
Missing necessary support is not evidence of no opportunity: use the shared
action-quality contract's `outcome: unresolved` and
`assessment_status: locally_unresolved`, preserving missing facts and provenance.
Continue independently supported selected proposals/actions; do not invent a
recommendation or start discovery merely to fill the handoff.

The action finalizer produces canonical `handoff/actions.json`. Proposals never
change severity, accepted-finding status, or verification; a proposed design is
not an implemented or verified repair. Unexpected new hypotheses in actions mode
remain unconfirmed follow-ups with an explicit original-baseline investigation
recommendation. Source implementation requires separately authorized work;
production security patches use the Blue remediation authority.
