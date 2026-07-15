---
name: vulnops-attack-general
description: VulnOps general injection, authorization, resource, logic, abuse, chain, wildcard, and obvious-code attack classes
---

# VulnOps General Attack Classes

Use only the hunt-plan class assigned to the task.

- Injection: trace values, keys, metadata, stored data, and secondary-system
  data into SQL, shell, template, HTML, file, redirect, deserialization, and
  dynamic execution sinks.
- Access control: compare every path to the same state change; verify the right
  principal, permission, tenant, resource, bulk item, and ownership check.
- Resource/file: traversal, symlink, archive, temporary-file, SSRF, redirect,
  parser differential, and check/use races.
- Cryptography: randomness, nonce/key lifecycle, authentication, verification,
  comparison timing, failure fallback, and trust-domain separation.
- Business logic: skipped/replayed/out-of-order states, partial failure,
  numeric manipulation, concurrency, expiry, rollback, and unsafe defaults.
- Feature abuse: export/import, search oracles, enumeration, preview leakage,
  callbacks, notification URLs, and legitimate capabilities with unintended
  cross-user effects.
- Chained trust: second-order use, component assumption gaps, token/capability
  escalation, recovery paths, and combinations of individually weak primitives.
- Wildcard: inspect undocumented, legacy, experimental, strange, irreversible,
  and environment-dependent code not covered by standard categories.
- Obvious code: debug/test endpoints, unsafe dynamic execution, permissive
  origin/cookie/redirect behavior, and explicit security TODOs. Do not repeat
  dependency or secret enumeration.
