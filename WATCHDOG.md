# Watchdog notes

These are the vulnops harness advisor's review priorities. The advisor is a passive
reviewer of the Main controller; it cannot approve actions or change session state.

Especially watch for:

- Phase-contract drift between `.omp/agents/vulnops-*.md` frontmatter/output lists and
  the behavior prompts under `config/agents/*.md`, or between either and `AGENTS.md`.
- A phase agent that yields `status: "ok"` with empty or missing `artifacts`, or whose
  `phase-manifest.json` status disagrees with `validate-phase.sh` output.
- Missing or empty required codegraph evidence: `codegraph-runs/<sid>/codegraph-out/context.json`
  must be non-empty (nodes + edges > 0) for every required intelligence/intrusion scope.
  codegraph is the sole graph backend; there is no whole-repo fallback.
- Any residual reference to `graphify`, `.venv`, `codegraphy`, or `find` as a tool name
  (post-migration failure modes — `find` is not an OMP tool; the real name is `glob`).
- Required artifacts that `validate-phase.sh` checks but that the corresponding agent
  prompt omits from its Write/Required-outputs list (e.g. `security-surfaces.json` for
  recon, `intrusion-seeds.json` for triage).
- Per-finding markdown files treated as part of the validated contract — they are not;
  `validate-phase.sh` / `validate-scan.sh` are the only contract. Behavior prompts are advisory.
- `intrusion` declared terminal before `intrusion/phase-manifest.json` is `ok` AND the
  required-scope codegraph contexts exist — reconciliation must not start early.
- Subagents prompted via `ask` in a non-interactive audit run (the harness runs
  `--approval-mode yolo`; an `ask` call would stall).
- A v2 phase manifest whose terminal status is not synchronized into
  `run-manifest.json` and the corresponding top-level task in
  `task-ledger.json`.
- SAST starting before validated SCA and Secrets evidence, which would duplicate
  dependency or secret enumeration instead of marking those cells tool-owned.
- A hunt result that emitted malformed candidates but is counted as clean, or a
  later successful gapfill attempt that is still dominated by an older shallow
  attempt.
- Verifier corrections without a complete corrected candidate/finding, unsafe
  IDs interpolated into artifact paths, or duplicate/orphan verifier results.
- `dynamic_verified` without an offline sandbox, expected unpatched failure,
  patched pass, non-null test and patch references, and matching hashes.
- Reporting driven from reconciliation instead of
  `final-verification/findings.json`, or any model-authored reporting task where
  the deterministic renderer is required.
