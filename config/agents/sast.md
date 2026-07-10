# SAST Coordinator Compatibility Prompt

The project-local OMP SAST agents are canonical. This file documents their v2
artifact contract for recovery and non-OMP automation.

## Inputs and constraints

- Read paths only from `.harness/audit-context.json`.
- Target source is read-only and audit runtime has no network access.
- Consume validated SCA and Secrets outputs; never repeat their enumeration.
- Target code may run only through `scripts/run-safe-reproduction.sh` when
  context `reproduction_mode` is `safe`.

## Pipeline

1. Write `threat-model.json` matching `schemas/v2/threat-model.schema.json`.
   Select applicable general, AI/LLM, HTTP/auth, browser, native, mobile, IaC,
   and ETL classes, plus evidence-backed repository-specific classes.
2. Run `scripts/build-hunt-plan.py`. It writes strict `hunt-plan.json`, the
   compatibility `task-manifest.json`, and `decompose.md`. One task owns one
   subsystem and attack class; dependency and secret cells are tool-owned.
3. Hunters write `deepdive/<task_id>.json` matching the v2 hunt-result schema.
   Candidates require attacker, crossed boundary, intended behavior, root
   cause, typed preconditions, ordered trace, mitigation review, and impact.
4. Run `scripts/finalize-sast.py` to mechanically validate, aggregate, create
   the coverage ledger, deduplicate by root cause, and create the validation
   queue. Malformed candidates are rejected before model validation.
5. Requeue reserved high-risk cells, shallow/failed high-risk cells, and
   distinct bounded rabbit-hole leads through `build-hunt-plan.py --gapfill`.
   Execute and aggregate each new batch, then repeat until no work is added or
   the per-depth task, round, or attempt cap is reached.
6. Adversarial verifiers emit strict `source_verified`, `rejected`, `deferred`,
   or `environment_required` results. Apply complete corrected candidates;
   after a preferred dedup trace is rejected, use `--advance-alternates` to
   verify the next member without rechecking a surviving root cause.
7. In safe mode, reproduction workers create sanitized local regression-test
   and draft-patch artifacts in a disposable offline sandbox.
8. Run `finalize-sast.py --finalize` to write verified, dropped, coverage,
   wishlist, summary, and phase-manifest artifacts.

## Default budgets

- quick: 4 concurrent, 12 total tasks, 1 gapfill round, 2 attempts per cell.
- balanced: 8 concurrent, 32 tasks, 2 rounds, 2 attempts.
- full: 16 concurrent, 64 tasks, 3 rounds, 2 attempts.

Overflow work is queued rather than dropped. A clean task without reviewed
files, entrypoints, sinks, and mitigations is shallow, not successful.
