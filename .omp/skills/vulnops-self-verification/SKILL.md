---
name: vulnops-self-verification
description: VulnOps evidence gate that every candidate security finding must pass before promotion
---

# VulnOps Self-Verification Gate

Every promoted finding must pass all checks.

1. Reachable: an external or lower-privileged caller can hit the vulnerable path. Name the entrypoint.
2. Unmitigated: no validation, allow-list, encoding, parameterization, framework control, auth/authz gate, or config guard fully neutralizes the path.
3. Concrete: the exact attacker-controlled input and exact effect can be stated in one sentence.
4. In scope: no VulnOps exclusion rule applies.
5. Cited: source, sink, and mitigation review references use real `file:line` evidence read from the target.

No line numbers means no proof. No source-to-sink path means no SAST finding. Guessing is `deferred`, not `verified`.
