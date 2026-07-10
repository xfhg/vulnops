---
name: vulnops-attack-http-auth
description: VulnOps HTTP framing, cache, forwarded-header, session, token, OAuth, OIDC, and SAML attack classes
---

# VulnOps HTTP and Authentication Attack Classes

- Framing claims require two components and the exact bytes they parse
  differently: content length, transfer encoding, HTTP/2 downgrade, duplicate
  fields, whitespace, or header delimiters.
- Cache claims require response influence absent from the cache key, or a
  cache/application path-classification disagreement with cross-user impact.
- Trace Host and forwarding headers into routing, reset links, redirects,
  access decisions, absolute URLs, response headers, and cache keys.
- For JWT or session tokens, verify the signature operation, server-pinned
  algorithm, key selection, issuer, audience, expiry, nonce, rotation,
  revocation, and privilege-change lifecycle.
- Establish whether the target is the authorization server, identity provider,
  or relying party before assigning OAuth/OIDC/SAML duties. Check callback
  binding, state, PKCE, nonce, assertion selection, replay, audience, recipient,
  and validity windows.

Framework defaults count as mitigations. Claims depending on unseen proxy,
cache, identity-provider, or deployment configuration are
`environment_required`, not confirmed.
