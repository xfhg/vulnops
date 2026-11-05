---
name: vulnops-attack-mobile
description: Evidence-driven mobile application security review for Android, iOS, cross-platform clients, embedded web content, deep links, IPC, local storage, platform permissions, and backend trust assumptions. Use when a VulnOps hunt task has the mobile domain or examines code crossing a mobile OS or app boundary.
---

# Mobile Attack Review

Apply the shared audit evidence gate. Treat a mobile client as attacker-controlled
unless a claim is enforced again by a trusted service or operating-system
boundary.

## Map boundaries

Identify exported components, URL/deep-link handlers, intents or IPC, app
extensions, WebViews, JavaScript bridges, universal/app links, push handlers,
clipboard and share flows, local files and databases, secure-storage wrappers,
backup behavior, logs, notifications, biometric gates, permissions, and
backend APIs.

Record the caller, required device state, authentication level, user
interaction, platform version, and the more-trusted capability reached.

## Hunt

- Trace untrusted URI, intent, IPC, file, pasteboard, notification, and web
  content into privileged actions or sensitive data.
- Verify component export rules, link ownership checks, origin validation,
  WebView navigation policy, bridge exposure, and file/content URL handling.
- Check whether local authorization, feature flags, certificate pinning,
  obfuscation, or client-side entitlement checks are incorrectly treated as a
  server-side security boundary.
- Review token/key storage, device backups, screenshots, logs, notifications,
  pasteboards, and inter-app sharing without copying secret values.
- Review cryptographic API parameters, nonce/key lifecycles, randomness, and
  platform keystore access with the cryptography lens when assigned.
- Check update/install trust, dependency loading, native bridges, unsafe
  deserialization, and memory-unsafe code with the matching specialist lens.
- Distinguish a malicious app, compromised browser/content origin, stolen
  unlocked device, rooted device, and remote backend caller; do not merge
  these attacker models.

## Reject weak claims

Reject findings that require an already equivalent device privilege, assume a
rooted device defeats an explicit threat model without crossing another
boundary, or report missing hardening as direct compromise. Keep worthwhile
defense-in-depth observations as hardening notes.

Promote only an ordered, cited path from a real mobile entrypoint to an
unmitigated sink with concrete impact and explicit prerequisites.
