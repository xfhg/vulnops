---
name: vulnops-audit-core
description: VulnOps attacker-led hunting, impact, evidence, and adversarial-validation doctrine
---

# VulnOps Audit Core

Hunt for exploitable behavior, not checklist deviations. Every candidate must
name a real attacker, their starting access, the trust boundary crossed, exact
input or action sequence, reachable code path, mitigation review, observable
result, and material impact.

## Hunting method

- Follow data through entry, validation, transformation, storage, retrieval,
  and sink. Read error, fallback, retry, cleanup, timeout, and recovery paths.
- Probe empty, missing, maximum, negative, boundary-time, encoding, parser,
  serialization, and round-trip behavior.
- Compare parallel paths to the same action. Check operation reordering,
  replay, concurrent requests, check-then-act gaps, and security defaults.
- Start from privileged capabilities and work backward to who can reach them.
  Treat model, parser, cache, proxy, database, plugin, and worker outputs as
  untrusted at the next boundary.
- Record unexpected adjacent leads as bounded rabbit holes for the lead.

## Evidence gate

- Another layer that fully prevents exploitation converts the issue to a
  hardening note.
- Operator-equivalent behavior, test-only code, ordinary errors, unproven
  deployment assumptions, and parser/runtime guesses are not findings.
- Severity combines likelihood and concrete impact. If damage cannot be
  stated, lower the severity or reject the candidate.
- Report positive security patterns and defenses that survived review.
- Dependency enumeration belongs to SCA and secret enumeration to Secrets.
  Hunters consume those results and do not repeat their scans.
- Target source is read-only. Dynamic evidence may only use the configured
  safe-reproduction wrapper and a disposable workspace.
