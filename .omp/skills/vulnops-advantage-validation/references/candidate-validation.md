# Candidate and Sibling Validation

Use this method for the assigned candidate set, not to expand a standalone
question into a repository scan. The entry skill owns permissions and native
resolution fields. For the source/control/sink/boundary and counterevidence
method, read the shared
[static assessment](../../vulnops-self-verification/references/static-assessment.md)
when establishing source proof; do not create a second assessment ledger.

## Set the proof obligation

Write up to five concrete criteria for the claim: reachable attacker input,
exact failed control, actual sensitive effect, compatible prerequisites and
boundary, and decisive counterevidence. Include the real HTTP, CLI, message,
file, library or other supported interface; a contrived internal-helper call
cannot substitute for reachability. A seed or advisory location is an obligation
to inspect, not a finding or proof of the current code's behavior.

Inspect transformations, failure and fallback paths, downstream interpretation,
object identity and state lifecycle. Check supported alternate configurations;
a safe default does not establish safety on every path.

Preserve the exact seeded/root-control location even if a wrapper or neighboring
route makes the story easier to tell. Keep the source view, candidate, seed,
baseline, objective/question and concrete operation identities. Historical
rejections remain applicable unless new source evidence defeats their decisive
reason; merely rephrasing the claim does not reopen it.

Choose source reasoning or an authorized contained experiment according to the
material missing fact, not a hierarchy of tools. Inspected tests can clarify a
contract but are not executed tests. Missing libraries, a compile failure,
unavailable infrastructure or absent deployment configuration limit proof;
they do not prove safety. A complete static tuple can establish behavior while
deployment applicability remains conditional. Confidence follows actual evidence
and contrary facts, never a numeric reward for a crash, sanitizer or debugger.

When a contained experiment would materially settle the question, propose the
smallest realistic trigger plus a negative/legitimate control to the owning
coordinator. Explain what each possible result would establish. The entry skill
and shared native context exclusively govern requests, reservation, execution
and sanitized observations. This method authorizes no setup, dependency install,
direct execution or raw-log retention. Record failed or unperformed validation
honestly, without turning an expected result into an observation.

## Preserve every concrete sibling

After one representative has a strong proof tuple, spend effort on assigned
siblings rather than repeatedly deepening that demonstration. For each instance,
identify its actual source, closest control, branch-local transformation, sink
or protected action, impact, counterevidence and disposition in native fields.
One PoC cannot settle every sibling, and a safe sibling cannot suppress another
operation. Group prose only after each independently triggerable instance has
its own evidence-backed accounting.

A broad assigned family may contain multiple operations in the same file:
`execute` versus `executemany`, a loader's single-document versus multi-document
mode, or create/delete/reset actions. Check each supplied concrete operation.
Shared wrappers establish reachability but do not replace the underlying
root-control, parser, resolver or protected-action locations. Exported runtime
implementations and duplicated controls remain separately assessable. Preserve
distinct proof tuples in one flow: a command-injection finding does not settle
an SSRF, path-write or authorization claim beside it.

For example, if one query operation binds attacker values while a sibling
concatenates them into syntax, the binding control contradicts only the first
instance's claimed injection path. The second still needs its own caller,
syntax-control, sink and impact proof. Record both dispositions; do not generalize
either safety or vulnerability from the representative.

## Challenge the exact operation

Load only the applicable existing vulnerability-family skill for its class
method and exclusions. The following are instance-specific checks when those
structures occur, not another taxonomy, severity policy or mandatory hunt list:

- **Parser/loader implementations:** inspect the concrete registered codec,
  converter, resolver or container handler that parses, resolves types, filters
  classes or constructs objects. A safe loader elsewhere cannot settle a
  different default factory, fallback or exported resolver. Check priority,
  caller-supplied factories and fail-open configuration on the actual instance;
  an XML secure-processing flag alone or swallowed feature-setup error is not
  proof that entity/DTD processing is disabled. Use `skill://vulnops-deserialization`
  for loader/control doctrine.
- **Structured-input helpers:** connect adversarial input to the exact type,
  size, shape, recursion, conversion or allocation guard and resulting effect.
  A parser-edge finding does not close an independently unsafe object-model
  helper. For protocol/version parsers, inspect full-format validation before
  splitting, conversion, comparison or feature selection. Distinguish a local
  exception from shared-service loss, recovery failure or a security-gate bypass
  using `skill://vulnops-attack-native` and `skill://vulnops-attack-general` when
  applicable; deterministic exceptions are not automatically security findings.
- **Injection modes and later interpretation:** check every assigned argument
  type, API mode and fallback branch through its typecheck, escape, canonicalize
  or bind operation to the actual consumer. Frontend widgets do not constrain
  API/webhook input. Recursive placeholder/template expansion may re-interpret
  a previously resolved value; later business checks must constrain the same
  object and defeat that exact syntax-control path. Use
  `skill://vulnops-attack-general` for injection and resource reasoning.
- **Destinations and filesystem operations:** follow the actual parser, decoder,
  matcher, canonicalizer, filter and redirect into the final network or file
  operation. Optional filters, feature documentation or a safe new handler do
  not settle a legacy/exported path. For archive/restore operations, require
  containment before each member is materialized, not only later manifest gates,
  scanning, promotion or top-level filtering. Consider links, metadata and
  copied subtrees when relevant; writes into trusted configuration or peer-object
  directories can cross a boundary without escaping the application's overall
  root. Missing optional parser dependencies alone do not defeat a static
  decode/filter/join/write proof.
- **Authentication and authorization state:** under
  `skill://vulnops-access-control` and `skill://vulnops-attack-http-auth`, inspect
  the actual middleware/decorator and configuration, not an admin-looking name.
  Follow principal/token installation, rebind or reauthentication, issuer and
  callback state after upgrades or redirects. For assertion sets, selection,
  clones and serialization, prove that the consumed object is the one validated;
  a loop finding one valid element does not authorize another selected element.
  For self-service updates compare request and persisted identity, tenant, role,
  MFA, recovery and trust-state fields, including scalar and collection aliases.

Deprecation, opt-in registration and warnings that an unrestricted mode is unsafe
are prerequisites, not proof that a plausible restricted-mode bypass is safe.
A caught exception, named guard or authentication check must actually defeat the
claimed instance and impact. Use class-specific legitimate controls; do not
suppress merely because the feature is intended or because another class in the
same flow was already reported. Existing family skills own browser, AI/tool,
crypto and other applicable proof requirements; no general example replaces them.

## Bound adjacency and preserve uncertainty

For a consequential missing caller, configuration, consumer or provenance fact,
make one targeted adjacency pass within the assignment. Relevant sources may be
generated clients/specifications, workflow callers, deployment or policy
configuration, storage/ACL definitions or package importers. If the fact remains
unavailable, state exactly what would settle it and why the current evidence
does not. Do not convert external unknowns into blind local retries, expand the
assignment or authorize another environment.

Apply the shared optional-support contract to defective citations. Independently
inspected evidence must establish every necessary obligation, with the owning
analyst explaining sufficiency; citation counts or repaired ranges are not proof.
An established entrypoint without the sensitive effect remains unconfirmed.
Keep eligible neighbors and exact missing facts, then use the entry skill's
native question resolutions and candidate reasons. Prioritize consequential
assigned uncertainty without silently dropping lower-impact concrete instances.
