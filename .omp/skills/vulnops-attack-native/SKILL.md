---
name: vulnops-attack-native
description: VulnOps memory-safety, binary, parser, runtime, kernel, and privileged-interface attack classes
---

# VulnOps Native and Binary Attack Classes

Review attacker-controlled lengths, offsets, counts, pointer lifetimes, type
tags, initialization, user copies, double fetches, dispatch selectors,
privileged interfaces, and duplicated fast/compatibility paths.

- Re-derive worst-case allocation and copy geometry rather than trusting the
  common path.
- Verify subtraction, conversion, multiplication, pointer-depth, fixed-buffer,
  leaf/interior-node, and owner/view invalidation assumptions.
- Distinguish an ordinary crash from an out-of-bounds primitive, disclosure,
  control-flow effect, privilege crossing, or persistent integrity impact.
- Use crash/debugger/sanitizer or reclaim-and-compare evidence only through the
  safe reproduction sandbox.

If build inputs, debugger support, sanitizers, or isolation are unavailable,
return an environment requirement instead of asserting exploitability.
