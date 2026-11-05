---
name: vulnops-severity-guidance
description: VulnOps severity guidance for rating exploitability, exposure, preconditions, and blast radius
---

# VulnOps Severity Guidance

Rate the exploit path, not the vulnerability class name.

Before assigning severity, record:
- Access level: anonymous, any authenticated user, privileged user, local user, or operator.
- Preconditions: every required condition the attacker must already have.
- Blast radius: one record, one tenant, many tenants, service integrity, host execution, or secrets exposure.

Severity:
- Critical: unauthenticated or low-privileged path to RCE, auth bypass, broad tenant escape, private key exposure, or bulk sensitive data compromise.
- High: reachable attack with low preconditions and material confidentiality, integrity, or availability impact.
- Medium: authenticated or condition-dependent path with scoped impact.
- Low: local, adjacent, test-only-adjacent, heavily preconditioned, or limited operational impact.
- Info: useful security context without a directly exploitable path.

Downgrade when impact depends on a second independent vulnerability, non-production code, privileged-only operation, or ambiguous reachability.
