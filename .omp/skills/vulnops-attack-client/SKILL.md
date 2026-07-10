---
name: vulnops-attack-client
description: VulnOps browser DOM, messaging, WebSocket, CORS, navigation, UI-redress, and prototype attack classes
---

# VulnOps Client-Side Attack Classes

- DOM injection requires a controllable browser-only source and an executing
  sink. Credit framework escaping and inspect only explicit escape hatches.
- DOM clobbering requires attacker-controlled markup attributes that shadow a
  security-relevant global or object property.
- Messaging, WebSocket, and CORS issues require a missing or weak origin check
  plus a privileged action or credentialed cross-origin read.
- Clickjacking requires a frameable sensitive action. Navigation issues require
  attacker influence over the final destination or executable scheme.
- Prototype pollution requires a nested/recursive attacker-key write and a
  reachable gadget with security impact.

State whose browser session executes the attack and what crosses an origin or
victim boundary.
