# Causal Attack-Path Analysis

Use this method when reconstructing or challenging an assigned capability path.
The entry skill and shared native context retain scope, permissions, transition
obligations and output ownership; this is reasoning guidance, not another phase.

## Establish the starting facts

State the attacker action and narrow terminal effect in ordinary language. Name
the credential or input actually controlled, the protected owner or resource,
and the privilege the attacker does not already have. Distinguish baseline
information, inherited primitive proof, newly inspected source, contained
observations, assumptions and absent access.

Map the component to its product surface or production workflow and the assigned
threat-model boundary. Establish the real entrypoint, service identity and
effective privileges, dataflow and sensitive consumer. Preserve repository
prefixes and the assessed source view. When source/configuration supports them,
inspect listeners, routes, ports, ingress, load balancers and network policy;
otherwise retain the exact exposure uncertainty. Separate public, internal,
admin-only, local-network and localhost requirements rather than inferring
public ingress. Missing ingress evidence alone does not defeat a source-proven
library interface or internal lower-trust boundary.

Identify whether the effect is self-only or crosses a meaningful owner, tenant,
process, identity or privilege boundary. Explain required configuration and
whether prerequisites are supported, implausible, contradicted or unknown.
Trace sensitive data and secret references without using credentials or copying
secret values. Identify the impact surface (such as runtime, build, data,
identity or network) and evidenced reach (one object, service or broader shared
consumer); do not turn a shared dependency into assumed fleet-wide impact.
These are factual distinctions for native fields, not new enums or a separate
attack-facts report.

## Carry the capability to its consumer

Follow the same value, object, identity or state through every meaningful
transformation and sensitive consumer. Apply the shared context's edge proof
obligations to each ordered producer-to-consumer handoff, not just to its two
endpoints. Cite the actual grant, mapping, delegation and consuming authority.

Reopen every primitive's material conditions even when the baseline accepted it.
A read primitive does not prove that a useful credential exists; a credential
format proves neither possession nor validity, scope or consumer acceptance.
Same-named services, tenants or resources are not evidence of a binding between
repositories. Show the source/configuration handoff and canonical resource
identity rather than filling a gap with naming similarity.

Search for the strongest contrary fact at each edge: denial paths,
reauthentication, tenant remapping, token audience, resource ownership, cleanup,
retries, expiration and state/lifetime restrictions. Explain why each material
control does or does not defeat this exact transfer. Treat existing policy as
contextual evidence, never as permission to suppress a claim mechanically.

Test joint feasibility. Different identities, tenants, deployments, mutually
exclusive settings or incompatible timing can defeat a composition even when
both primitives work independently. If a consumer rejects the gained capability,
record that contradicted edge and withhold the dependent chain. Retain the
independently established primitive. If acceptance is unknown instead, preserve
the unresolved transfer and its smallest discriminating next proof; lack of
proof is not evidence of rejection.

For example, a source-established token disclosure does not establish access to
a second service when that service enforces an incompatible audience. The
second-service transition is contradicted on that path, while the disclosure
may remain independently eligible. An alternate accepting consumer is a new
question only within the coordinator's existing continuation allocation;
renaming the failed edge does not earn another attempt.

## Explain the added outcome

Compare the resulting capability and narrow impact with inherited intelligence.
A reportable composition needs distinct exploitability, another boundary or
materially greater impact, not two finding titles joined together or the same
failed control retold as a chain. Preserve original counterevidence and exact
baseline identities. Explain what source establishes and what remains conditional.

Only after these facts apply native exclusion/self-verification and severity
skills as directed by the entry skill. Calibrate actual access requirements,
likelihood, blast radius and effective mitigations. Evidence confidence is not
consequence severity. Do not invent production reliability, affected releases,
public exposure, remote execution or tenant-wide impact. The exact objective's
success condition, not an intermediate capability, determines whether it was
achieved; fresh final verification remains required.
