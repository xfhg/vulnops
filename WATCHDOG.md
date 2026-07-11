# Canonical V2 Watchdog

The advisor passively reviews Main and cannot approve actions or mutate state.
Watch for:

- Drift between `.omp/agents/`, `.omp/main/vulnops-main.md`, `AGENTS.md`, and
  the eight canonical phase manifests.
- More than one running top-level phase/task, repeated attempt increments without
  a stable-task retry, post-yield IRC treated as completion, absolute task
  artifacts, or a successful phase restarted downstream.
- Recon dependency inputs not produced by `finalize-recon.py`, an inventory that
  differs from deterministic target discovery, or unsupported files such as
  `go.sum`, `package.json`, Dockerfiles, build scripts, or workflows queued to
  Wraith.
- Tool Collection invoking model workers, persisting raw output, or accepting
  unhealthy Wraith, Poltergeist, OMP, or Codegraph receipts.
- Tool Collection publishing canonical files before its complete staged set passes
  schemas, counts, receipt health, and normalized hashes.
- Any direct `codegraph init` against `target/`, escaping symlink, unexecuted
  graph question, receipt/hash mismatch, or graph stub cited as evidence.
- Evidence records, primitives, campaigns, or verifier results without exactly
  one terminal disposition.
- Candidate/context-only primitives silently treated as confirmed capabilities.
- Chains with missing primitives, open capability transitions, unrelated issue
  aggregation, or combined severity unsupported by end-to-end impact.
- Dependency advisories promoted without installed affected use and
  reachability, or secret candidates promoted without exact redaction and
  exposure validation.
- SAST gapfill that queues work without executing it, loses per-cell coverage,
  or treats malformed worker output as clean.
- Reproduction outside a successful bubblewrap probe, or dynamic verification
  without fail/pass evidence and matching artifact hashes.
- Target fingerprint drift, output outside `scans/` or `.harness/`, network use
  beyond the configured LLM endpoint, or reporting from anything other than
  final verified findings.
- Any compatibility reader, alternate schema generation, deprecated phase,
  fallback scanner, duplicated prompt/config, or model-authored report.
