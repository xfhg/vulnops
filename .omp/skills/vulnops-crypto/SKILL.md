---
name: vulnops-crypto
description: VulnOps specialist lens for cryptographic misuse, token handling, key management, and transport protection
---

# Crypto Lens

Focus on:
- Hardcoded keys, static IVs/nonces, reused nonces, predictable tokens, weak randomness.
- Deprecated or unsafe primitives: ECB mode, MD5/SHA1 for security, DES/3DES, raw RSA, custom crypto.
- Missing authentication on encrypted data.
- JWT/session mistakes: `none`, weak secret, missing issuer/audience/expiry checks, algorithm confusion.
- TLS bypass: disabled certificate validation, permissive hostname verification, cleartext transport for secrets.

False-positive traps:
- Hashes used only for non-security checksums.
- Test keys in test-only code.
- Legacy decrypt-only migration code not reachable for attacker-controlled data.

Required evidence:
- Secret/key/token/crypto operation.
- Attacker influence or exposure path.
- Concrete confidentiality, integrity, authentication, or replay impact.
