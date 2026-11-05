# Static assessment

Use when source review must establish or defeat a concrete security claim. The
calling phase owns scope, permissions, dispositions and output schema. This is
an evidence method, not another workflow or authorization to execute target code.

## Establish the smallest complete tuple

- **Source:** the input, trigger or state the actual attacker controls; distinguish
  remote/user/tenant control from trusted operator configuration.
- **Control:** the nearest authorization, validation, encoding, configuration or
  state check, including relevant missing checks and compensating controls.
- **Sink:** the sensitive operation, dependency use, authority grant or impact.
- **Path:** the calls and configuration connecting source, control and sink under
  compatible prerequisites, including transformations and failure/fallback paths.
- **Boundary:** the asset and authority separation violated, not merely a dangerous
  API or an action the caller is already authorized to perform.
- **Counterevidence:** inspected facts that defeat, constrain or contradict this
  particular route and impact.
- **Gaps:** exact missing facts, what is already established, and the smallest next
  observation that would distinguish the competing explanations.

A dependency name, string match, partial call chain or safe sibling is not a
complete assessment. Preserve each independently reachable operation's controls.

## Search outward from the claim

1. Inspect assigned source locations and normalized scanner/advisory references.
2. Resolve dependency versions and affected use through manifests, lockfiles,
   exports, binary entrypoints, build metadata and generated-artifact boundaries.
3. Follow actual callers: routes, RPC handlers, parser interfaces, CLI commands,
   package APIs, message consumers and plugin hooks.
4. Inspect nearby guards, supported configurations and downstream interpretation.
5. Read product documentation, deployment files, comments and existing tests to
   distinguish intended behavior from assumptions. Inspection is not execution.

Expand only to relevant authorized source. Missing implementation or deployment
context is a specific proof gap, not evidence that the system is safe or exposed.

## Challenge exposure and confidence

Identify whether the affected surface is a hosted service, public library API,
local CLI, developer tool, extension point, generated/vendor implementation,
example or fixture. Establish how untrusted material crosses the claimed boundary;
file location alone establishes neither exposure nor a harmless dummy value.

An exposed credential claim has a disclosure path: a source reader obtains
credential authority beyond reading source. It need not execute the containing
code. Use only redacted records and context; never print or use credential values.
Do not invent public repository access, live validity or credential privileges.

Exact inspected control flow and a supported boundary strengthen confidence.
Unresolved caller, version, configuration, identity or deployment facts limit it;
confidence cannot substitute for missing exploitability proof. A library input
may be a real boundary without an observed deployment, while a deployment-specific
claim must state its exposure prerequisites. Apply the existing native
[severity guidance](../../vulnops-severity-guidance/SKILL.md) when rating impact
and [exclusion rules](../../vulnops-exclusion-rules/SKILL.md) when deciding scope.

Return rationale, source/control/sink evidence, precise source references,
counterevidence, limits and next action in the caller's existing fields. Separate
established behavior, contradicted routes and unresolved facts. Predictions and
unexecuted examples are not observations; only authorized contained execution can
supply new dynamic evidence. No extra verdict schema or ledger is required.
