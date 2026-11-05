---
name: vulnops-exclusion-rules
description: VulnOps security audit exclusion rules for reducing false positives in source validation, synthesis, and verification
---

# VulnOps Exclusion Rules

Do not report a finding when any exclusion applies.

## No Real Attacker

- Code reachable only from tests, fixtures, local developer tooling, examples, or generated samples.
- Inputs controlled only by an operator who already has equivalent shell, deploy, or admin access.
- Dead branches, disabled feature paths, unreachable handlers, or code behind impossible build flags.

Exception: CI/CD parameters, scheduled job inputs, shared mounted config, and cross-team writable config are attacker-controlled when a lower-privileged party can influence them.

## No Security Impact

- Isolated request errors or crashes with no consequential loss of service to others, disproportionate resource exhaustion, data exposure, authorization bypass, code execution, integrity loss, or tenant-boundary crossing.
- Style, hygiene, or best-practice issues without a concrete exploitation path.
- Placeholder secrets, obvious test tokens, and migration-only legacy crypto when production values come from a secure runtime source.

Attacker-triggered material availability loss is eligible even without a confidentiality
or integrity effect. Establish the reachable input, disruption mechanism, affected
shared process/service or persistent resource, scope of affected users, and recovery
conditions from source. A request that terminates a shared service is not equivalent
to one handler rejecting malformed input. Keep deployment, supervision, restart,
and amplification assumptions explicit; ordinary traffic volume alone is not proof.

## Wrong Layer

- Backend-only bug classes reported against pure client/browser enforcement.
- SCA dependency version findings reported as SAST findings.
- Memory-safety findings in managed code unless native/unsafe/FFI/JNI/cgo boundaries are involved.
- Filesystem traversal claims against flat object-store keys unless the key is later materialized onto a filesystem.

## Noise Floor

- Log injection with no downstream parser or trust decision.
- Pure volumetric rate-limit concerns unless one request can trigger algorithmic complexity, recursive expansion, or unbounded allocation.
- Prompt text passed to an LLM unless the target repo itself implements an LLM security boundary.
