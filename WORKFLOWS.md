# Security Audit Workflows

## Original Audit: Discover What an Attacker Can Do

Start without assuming vulnerabilities exist. Map the application, identify attacker-controlled inputs, trace security decisions and prove concrete impact.

| Step | Phase | Attacker-focused purpose |
|---|---|---|
| 1 | Reconnaissance | Identify exposed entry points, attacker identities, valuable assets and trust boundaries. Understand where untrusted input can acquire authority. |
| 2 | Tool Collection | Collect dependency and exposed-secret leads. Treat scanner matches as questions to investigate, not proof of exploitation. |
| 3 | Source Investigation | Trace attacker-controlled inputs through security controls to sensitive operations. Establish exploitable root causes and challenge each candidate with counterevidence. |
| 4 | Campaign Planning | Prioritize meaningful attacker objectives. Connect established capabilities to potential consumers and identify the missing proof for promising attack paths. |
| 5 | Intrusion | Pursue the selected paths, test whether capabilities actually compose and follow evidence-backed alternatives. Establish the conditions required to cross each boundary. |
| 6 | Gap Exploration | Take an additional pass over consequential blind spots, alternate callers and overlooked capability consumers. Use Codegraph when useful, then challenge each promising route against the actual source and controls. |
| 7 | Synthesis | Assemble complete exploitation narratives. Separate standalone vulnerabilities from chains and demonstrate any additional impact without double-counting the same root cause. |
| 8 | Independent Verification | Assume each claim is false. Challenge attacker access, causal steps, intervening controls, required conditions and impact against the source. |
| 9 | Security Report | Explain what an attacker can achieve, what remains unproven and which defensive changes break the demonstrated attack paths. |

## Advantage: Find What an Informed Attacker Can Do Next

Start with a previous audit as intelligence—not as unquestioned proof. Look for additional attacker capabilities, alternate routes, overlooked boundaries and greater impact.

Explicitly request Advantage in an existing prepared harness OMP session; its
controller uses `python3 scripts/init-advantage.py --in-session [<completed-audit-path-or-run-id>] [options]`
before ordinary audit initialization, without a launcher or second OMP. Name the
completed audit path or exact unique run ID; never restore selection from an old
Advantage invocation. Terminal startup remains `./advantage.sh <completed-audit-base> [options]`
or `./run_local.sh --advantage <completed-audit-base> [options]`, outside OMP only.

Advantage defaults to deep/full; explicit mode/depth overrides remain independent.
Use `--mode standard` explicitly for standard work. Every explicit request starts
fresh; previous success, failure or interruption never supplies checkpoints or
consumes this invocation's limits. Ordinary audit depth and unfinished recovery
are unchanged; deep passes retain one shared current-invocation allocation.
Only one workflow may be active: finish or explicitly stop and close its owned
work first. Native tasks and semantic validation own live progress; completed
reports plus canonical evidence need no execution ledger. No callback starts
another workflow. Deploy runtime/instructions together after stopping old
sessions, without migrating, deleting or repairing saved Advantage runs.
The shared entry guide and Advantage controller remain the authorities; all
investigation, safe experiment, gap exploration and independent-review capabilities remain.

| Step | Phase | Attacker-focused purpose |
|---|---|---|
| 1 | Baseline Intelligence | Understand previously established weaknesses, rejected hypotheses and unresolved questions. Distinguish historical claims from capabilities that still require current proof. |
| 2 | Attack Planning | Define concrete attacker objectives and the questions needed to prove them. Prioritize routes that could reveal new weaknesses or materially extend known impact. |
| 3 | Investigation | Follow alternate entry points, sibling operations and capability chains. Use counterevidence to redirect effort; preserve useful independent discoveries when another path fails. |
| 4 | Gap Exploration | Pursue consequential routes the main investigation left open. Look for alternate callers, missing transitions and source-backed opportunities beyond the baseline; graph navigation suggests where to look, never what is exploitable. |
| 5 | Synthesis | Explain exactly what advances beyond the baseline: a new root cause, a viable chain or an impact expansion. Keep corrections and unchanged revalidations distinct from new attacker outcomes. |
| 6 | Independent Verification | Challenge every claimed advancement, including each capability transition and its conditions. Confirm that the evidence proves the stated attacker objective. |
| 7 | Defensive Handoff | When requested, assess whether proposed fixes interrupt the attack, identify targeted hardening and turn accepted findings into actionable defensive work. |
| 8 | Advantage Report | Lead with additional attacker outcomes, complete causal narratives, consequential unknowns and the defensive priorities that follow. |

## Shared Attacker Mindset

- Prove access, control, boundary crossing and concrete impact—not merely suspicious code.
- A chain must work end to end; a missing prerequisite leaves that chain unproven.
- Negative results and counterevidence guide the next useful question.
- One failed path does not invalidate an independently proven path.
- Additional exploration supplements the main attack plan; it does not displace it. A promising lead becomes a finding only after complete proof and independent challenge.
- Source-established exploitability is not an executed attack. State dynamic evidence and environmental uncertainty explicitly.
- Recommend fixes that break the demonstrated attack while preserving legitimate behavior.
