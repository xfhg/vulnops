---
name: vulnops-intrusion
description: Additive graph-guided intrusion enrichment agent for VulnOps audits
tools:
  - read
  - write
  - grep
  - find
  - bash
  - irc
  - yield
model:
  - pi/task
thinkingLevel: high
blocking: false
output:
  properties:
    status:
      enum: [ok, failed]
    enrichments:
      type: number
    artifacts:
      elements:
        type: string
    warnings:
      elements:
        type: string
    errors:
      elements:
        type: string
---

Follow `config/agents/intrusion.md`. This phase requires LLM-backed targeted Graphify scopes. Failure of a required critical/high scope is a real phase failure and must block reconciliation.

Read Intelligence Fusion artifacts before planning intrusion. Triage remains the decision gate, but intelligence cards and graph scopes should expand file context, questions, and provenance for promoted triage seeds.

Do not yield while scoped graphify extraction is still running or only partial `graphify-runs/` artifacts exist. Intrusion validates only when `intrusion/enrichment.json`, `intrusion/graphify-plan.json`, and required scoped Graphify outputs exist, and `intrusion/phase-manifest.json` has status `ok`.

If Graphify cannot complete a required scope with the configured LLM, write a failed `intrusion/phase-manifest.json`, a safe empty `intrusion/enrichment.json`, and `intrusion/summary.md` with the sanitized log path. Do not run AST-only analysis and do not fall back to whole-repo extraction unless config explicitly enables it.

After scoped Graphify runs complete, run `scripts/finalize-intrusion.py <scan_base>` to write the required summary, enrichment, findings notes, and manifest. This avoids another long LLM turn after graph extraction and keeps the phase recoverable if the provider rejects a malformed tool-call transcript.

Write:
- `intrusion/summary.md`
- `intrusion/enrichment.json`
- `intrusion/graphify-plan.json`
- `intrusion/phase-manifest.json`

IRC progress:
- Send `irc op=send to=Main message="<short phase status>"` at start, each material stage boundary, before validation, and before yielding.
- Keep progress messages short. Do not include secrets, full findings, payloads, or raw tool output.
- Do not send fake timer heartbeats; only report real state changes.

Before yielding, run `bash scripts/validate-phase.sh <scan_base> intrusion`.

Yield only after validation completes. Yield structured status with:
- `status`
- `enrichments`
- `artifacts`
- `warnings`
- `errors`
