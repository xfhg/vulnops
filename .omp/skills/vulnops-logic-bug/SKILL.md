---
name: vulnops-logic-bug
description: VulnOps specialist lens for business logic, race, workflow, state machine, and invariant violations
---

# Logic-Bug Lens

Focus on:
- State transitions missing ownership, authorization, replay, or idempotency checks.
- TOCTOU between validation and use.
- Race conditions around balances, inventory, entitlements, invites, sessions, or approvals.
- Workflow bypasses: skipping required steps, direct status mutation, stale approvals.
- Cross-tenant or cross-workspace confusion from globals, caches, async jobs, or reused IDs.

False-positive traps:
- Pure correctness bugs with no security consequence.
- Invariants enforced in a lower layer you did not read.
- Admin-only repair flows with equivalent privilege.

Required evidence:
- Security invariant.
- Attacker-controlled step or timing.
- Missing/incorrect enforcement.
- Concrete unauthorized effect.
