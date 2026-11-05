"""Accepted supplementary inputs and protected downstream cohort accounting."""
from __future__ import annotations

import copy
import json
import importlib.util
import os
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from advantage_contract import inside, load
import advantage_contract as core

GAP_ACTORS = {"vulnops-gap-investigator", "vulnops-advantage-gap-investigator"}
PUBLISHERS = {"vulnops-synthesis", "vulnops-advantage-synthesis"}


def accepted(base: Path, *, context: dict | None = None) -> dict | None:
    from gap_exploration_contract import load_accepted
    return load_accepted(Path(base), context=context)


def accepted_candidates(base: Path, *, context: dict | None = None) -> list[dict]:
    document = accepted(base, context=context)
    return document.get("candidates", []) if document else []


def candidate_references(candidate: dict) -> set[str]:
    identifier = candidate["id"]
    owner = candidate["artifact_ref"].split(":", 1)[0]
    return {f"gap-exploration/results.json:{identifier}", f"{owner}:{identifier}"}


def source_reference(source: dict) -> str:
    if "#/" in source["artifact_ref"]:
        # Linked source resolution validates the exact JSON pointer before attribution.
        return source["artifact_ref"].split("#", 1)[0] + ":" + source["source_id"]
    ref = source["artifact_ref"].replace("#", ":", 1)
    if ":" not in ref:
        ref += ":" + source["source_id"]
    elif ref.split(":", 1)[1] != source["source_id"]:
        raise ValueError("source identity differs from its artifact reference")
    return ref


def supplementary_only(finding: dict, candidates: list[dict]) -> bool:
    """A worker label cannot turn an original or mixed claim into optional work."""
    references = {ref for row in candidates for ref in candidate_references(row)}
    sources = finding.get("source_refs", [])
    if not sources or any(not isinstance(row.get("artifact_ref"), str) or
                          source_reference(row) not in references for row in sources):
        return False
    owners = {tuple(row["provenance"][key] for key in ("actor", "selector", "artifact_ref"))
              for row in candidates}
    contributors = [row for row in finding.get("contributors", [])
                    if not (row.get("actor") in PUBLISHERS and
                            row.get("artifact_ref") == "synthesis/findings.json")]
    return bool(contributors) and all(
        row.get("actor") in GAP_ACTORS and
        tuple(row.get(key) for key in ("actor", "selector", "artifact_ref")) in owners
        for row in contributors)


def review_cohorts(findings: list[dict], candidates: list[dict]) -> dict[str, list[str]]:
    result = {"original": [], "supplementary": []}
    for finding in findings:
        result["supplementary" if supplementary_only(finding, candidates) else "original"].append(finding["id"])
    return result


def preserve_original(original: dict, combined: dict) -> None:
    """Add evidence/claims, never replace or silently weaken a validated original."""
    def contains(before, after):
        if isinstance(before, dict):
            return isinstance(after, dict) and all(key in after and contains(value, after[key])
                                                   for key, value in before.items())
        if isinstance(before, list):
            if not isinstance(after, list):
                return False
            remaining = iter(after)
            return all(any(contains(value, item) for item in remaining) for value in before)
        return before == after
    for key in ("findings", "non_promoted", "input_claims"):
        for row in original.get(key, []):
            identity = "input_ref" if key == "input_claims" else "id"
            matches = [item for item in combined.get(key, []) if item.get(identity) == row[identity]]
            if len(matches) != 1 or not contains(row, matches[0]):
                raise ValueError("supplementary synthesis changed a protected original " + key + " claim")


def _base(context: dict) -> Path:
    paths = context.get("paths", {})
    value = paths.get("advantage_base") or paths.get("scan_base") or context.get("scan_base")
    if not value:
        raise ValueError("downstream cohort requires its execution base")
    return Path(value)


def _dispatch(base: Path, context: dict, phase: str, *, active=False) -> tuple[Path, dict]:
    if phase not in {"synthesis", "final-verification"}:
        raise ValueError("only downstream phases own supplementary cohorts")
    if context.get("execution_kind") == "advantage":
        raise ValueError("Advantage downstream work has no dispatch or cohort state")
    manifest_name = "run-manifest.json"
    manifest_path = inside(base, manifest_name)
    manifest = load(manifest_path)
    if manifest.get("run_id") != context.get("run_id"):
        raise ValueError("downstream cohort belongs to another execution")
    state = manifest.get("phases", {}).get(phase)
    state = state.get("status") if isinstance(state, dict) else state
    if active and (state != "running" or manifest.get("attempt_id") != context.get("attempt_id")):
        raise ValueError("cohort mutation requires the active current phase")
    if active and (manifest.get("status") == "complete" or any(
            name != phase and (value.get("status") if isinstance(value, dict) else value) == "running"
            for name, value in manifest["phases"].items())):
        raise ValueError("competing or completed downstream phase owner")
    if active:
        ledger = load(inside(base, "task-ledger.json"))
        owners = [row for row in ledger["tasks"] if row.get("phase")==phase]
        if (ledger.get("run_id")!=context["run_id"] or len(owners)!=1 or
                owners[0].get("status")!="running" or owners[0].get("attempt_id")!=context["attempt_id"]):
            raise ValueError("downstream mutation lacks its active canonical task")
    path = inside(base, f"{phase}/dispatch.json")
    document = load(path) if path.exists() else {
        "schema_version": "2.0", "run_id": context["run_id"], "phase": phase, "workers": []}
    if document.get("run_id") != context["run_id"] or document.get("phase") != phase:
        raise ValueError("downstream dispatch ownership differs")
    return path, document


def _write_dispatch(path: Path, document: dict) -> None:
    from artifact_policy import publication_content_error
    error = publication_content_error(document)
    if error:
        raise ValueError(error)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def begin_cohort(context: dict, phase: str, cohort: str) -> dict:
    if context.get("execution_kind") == "advantage":
        raise ValueError("native tasks own Advantage cohorts; begin registration is unsupported")
    if cohort not in {"original", "supplementary"}:
        raise ValueError("unknown downstream cohort")
    base = _base(context)
    path, document = _dispatch(base, context, phase, active=True)
    cohorts = document.setdefault("cohorts", {})
    ledger_path = inside(base, "task-ledger.json")
    ledger = load(ledger_path)
    if ledger.get("run_id") != context["run_id"]:
        raise ValueError("cohort retry authority belongs to another execution")
    owners = [row for row in ledger["tasks"] if row["phase"] == phase]
    if ledger_path.exists() and (len(owners)!=1 or owners[0].get("status")!="running"
                                 or type(owners[0].get("attempts")) is not int):
        raise ValueError("cohort retry requires its one active canonical phase task")
    phase_attempt = max((row["attempts"] for row in owners), default=0)
    existing = cohorts.get(cohort)
    retry = existing and (context["attempt_id"] != existing.get("attempt_id")
                          or phase_attempt > existing.get("phase_attempt", 0))
    if retry and phase == "synthesis" and cohort == "original":
        # Use the same bounded cleanup as explicit recovery, after canonical retry admission.
        spec = importlib.util.spec_from_file_location("synthesis_retry_recovery",
                                                    Path(__file__).with_name("recover-run.py"))
        recovery = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recovery)
        operation = recovery.unfinished_work(base, phase, context)
        retained = operation["replace"].get("synthesis/dispatch.json", {})
        if "original" not in retained.get("cohorts", {}):
            recovery.reconcile_work(base, phase, operation)
            path, document = _dispatch(base, context, phase, active=True)
            cohorts = document.setdefault("cohorts", {})
            existing = None
    if (existing and cohort=="supplementary" and phase=="final-verification"
            and existing.get("status")=="completed" and existing.get("attempt_id")!=context["attempt_id"]):
        # A fresh review may use only remaining time/attempts, never a fresh allowance.
        existing.update(status="running", completed_at=None, reason="", attempt_id=context["attempt_id"])
        if datetime.now(timezone.utc)>=_cohort_deadline(context,phase,cohort,existing):
            existing.update(status="failed", completed_at=datetime.now(timezone.utc).isoformat(),
                            failure_kind="budget_deferred",
                            reason="The retained supplementary review allowance is exhausted; no current review was launched.")
        _write_dispatch(path,document)
    if existing and not (cohort == "original"
                         and (existing.get("status") == "failed" or phase=="final-verification")
                         and retry):
        # Only the ordinary phase retry authority can replenish original work.
        # Supplementary continuation never resets its consumed allowance.
        return existing
    if cohort == "supplementary":
        if cohorts.get("original", {}).get("status") != "completed":
            raise ValueError("original cohort must complete before supplementary work")
        if not accepted_candidates(base, context=context):
            raise ValueError("no accepted supplementary inputs")
    spec = importlib.util.spec_from_file_location("gap_deadline", Path(__file__).with_name("set-omp-deadline.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stamp = datetime.now(timezone.utc)
    key = "synthesis_timeout_seconds" if phase == "synthesis" else "verification_timeout_seconds"
    zero = cohort == "supplementary" and (not context["gap_exploration_budget"]["enabled"] or context["gap_exploration_budget"][key] == 0)
    seconds = 0 if zero else module.deadline_ms(context, phase, cohort=cohort) / 1000
    row = {"attempt_id": context["attempt_id"], "phase_attempt": phase_attempt,
           "status": "running", "started_at": stamp.isoformat(),
           "deadline_at": (stamp + timedelta(seconds=seconds)).isoformat(), "completed_at": None, "reason": ""}
    if existing and existing.get("output_ref"):
        row.update({key: existing[key] for key in ("output_ref", "output_sha256", "attempt_id")})
    if zero:
        limitation="disabled" if not context["gap_exploration_budget"]["enabled"] else "configured with zero additional seconds"
        row.update(status="failed", completed_at=stamp.isoformat(), failure_kind="budget_deferred",
                   reason=f"Supplementary {phase} is {limitation}; no native execution was launched.")
    cohorts[cohort] = row
    _write_dispatch(path, document)
    return row


def _cohort_deadline(context: dict, phase: str, cohort: str, row: dict) -> datetime:
    deadline = datetime.fromisoformat(row["deadline_at"])
    if cohort == "supplementary":
        key = "synthesis_timeout_seconds" if phase == "synthesis" else "verification_timeout_seconds"
        seconds = context["gap_exploration_budget"][key] if context["gap_exploration_budget"]["enabled"] else 0
        current = datetime.fromisoformat(row["started_at"]) + timedelta(seconds=seconds)
        deadline = min(deadline, current)
    return deadline


def remaining_ms(context: dict, phase: str, cohort: str) -> int | None:
    if context.get("execution_kind") == "advantage":
        call = core.live_call(context, phase)
        operation = call.get("operation", {})
        seconds = operation.get("timeout_seconds")
        return int(seconds * 1000) if type(seconds) in (int, float) and seconds >= 0 else None
    if not (context.get("scan_base") or context.get("paths", {}).get("scan_base")
            or context.get("paths", {}).get("advantage_base")):
        return None
    base = _base(context)
    if not inside(base, f"{phase}/dispatch.json").exists():
        return None
    _, document = _dispatch(base, context, phase)
    row = document.get("cohorts", {}).get(cohort)
    if not row:
        return None
    if row["status"] != "running":
        return 0
    return max(0, int((_cohort_deadline(context, phase, cohort, row)-datetime.now(timezone.utc)).total_seconds()*1000))


def require_cohort(context: dict, phase: str, cohort: str) -> dict:
    if context.get("execution_kind") == "advantage":
        return native_cohort(context, phase, cohort)
    _, document = _dispatch(_base(context), context, phase, active=True)
    row = document.get("cohorts", {}).get(cohort)
    if (not row or row.get("status") != "running" or
            datetime.now(timezone.utc) >= datetime.fromisoformat(row["deadline_at"])):
        raise ValueError("downstream cohort is not running within its separate allowance")
    if cohort == "supplementary":
        if datetime.now(timezone.utc) >= _cohort_deadline(context,phase,cohort,row):
            raise ValueError("supplementary cohort exhausted the lowered current allocation")
    return row


def require_synthesis_publication(context: dict, cohort: str) -> dict:
    """Validate new work strictly; permit an already completed historical union."""
    if context.get("execution_kind") == "advantage":
        return native_cohort(context, "synthesis", cohort)
    _, document = _dispatch(_base(context), context, "synthesis", active=True)
    row = document.get("cohorts", {}).get(cohort, {})
    if cohort == "supplementary" and row.get("status") == "completed":
        if document.get("cohorts", {}).get("original", {}).get("status") != "completed":
            raise ValueError("completed supplementary work lacks its admitted original")
        return row
    return require_cohort(context, "synthesis", cohort)


def _close_cohort(context: dict, phase: str, cohort: str, *, reason: str = "") -> dict:
    if context.get("execution_kind") == "advantage":
        raise ValueError("native terminal outcomes own Advantage cohort closure")
    path, document = _dispatch(_base(context), context, phase, active=True)
    row = document.get("cohorts", {}).get(cohort)
    legacy_supplement = phase == "synthesis" and cohort == "supplementary"
    if not row or row["status"] not in ({"running", "completed"} if not reason or legacy_supplement else {"running"}):
        raise ValueError("cohort closure requires its running assignment")
    if any(worker.get("status") == "running" and worker.get("cohort", cohort) == cohort
           for worker in document.get("workers", [])):
        raise ValueError("stop and record active reviewers before cohort closure")
    if row["status"] == "completed" and not reason:
        return row
    if not reason and datetime.now(timezone.utc) > datetime.fromisoformat(row["deadline_at"]):
        raise ValueError("cohort exhausted its separate deadline")
    row.update(status="failed" if reason else "completed", reason=reason,
               completed_at=datetime.now(timezone.utc).isoformat())
    _write_dispatch(path, document)
    return row


def finish_cohort(context: dict, phase: str, cohort: str) -> dict:
    if phase == "synthesis":
        base = _base(context)
        if cohort == "original":
            load_original_draft(base, context, "synthesis/original-findings.json")
        else:
            # The controller calls this only after successful terminal delivery.
            # Require the aggregate to have been prepared before accepting it.
            original = load_original_draft(base, context, "synthesis/original-findings.json")
            combined = load(inside(base, "synthesis/findings.json"))
            if combined.get("run_id") != context["run_id"]:
                raise ValueError("synthesis publication belongs to another execution")
            preserve_original(original, combined)
    return _close_cohort(context, phase, cohort)


def fail_cohort(context: dict, phase: str, cohort: str, reason: str) -> dict:
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("failed cohort requires the actual terminal failure")
    return _close_cohort(context, phase, cohort, reason=reason)


def cohort_failure(base: Path, context: dict, phase: str, cohort: str = "supplementary") -> dict:
    if context.get("execution_kind") == "advantage":
        return native_cohort_failure(context, phase, cohort)
    _, document = _dispatch(base, context, phase)
    row = document.get("cohorts", {}).get(cohort)
    if (cohort != "supplementary" or not row or row.get("status") != "failed" or
            document.get("cohorts", {}).get("original", {}).get("status") != "completed" or
            not row.get("reason") or not row.get("completed_at") or
            any(worker.get("status") == "running" for worker in document.get("workers", []))):
        raise ValueError("unreviewed closure requires a stopped failed supplementary cohort")
    return row


def bind_original_draft(context: dict, relative: str) -> None:
    base = _base(context)
    if context.get("execution_kind") == "advantage":
        if relative != "synthesis/original-findings.json":
            raise ValueError("original synthesis requires its canonical analytical artifact")
        document = load(inside(base, relative))
        if document.get("run_id") != context["run_id"]:
            raise ValueError("original analytical output belongs to another execution")
        call = core.live_call(context, "synthesis")
        if any(row["phase"] == "synthesis" and row["id"] == "AdvantageSynthesisOriginal" for row in call["workers"]):
            native_cohort(context, "synthesis", "original")
        else:
            validate_empty_original(context, document)
        return
    path, document = _dispatch(base, context, "synthesis", active=True)
    row = document.get("cohorts", {}).get("original")
    if not row or row["status"] != "running":
        raise ValueError("original draft requires its running synthesis cohort")
    draft = base / relative
    if draft.is_symlink() or not draft.resolve().is_relative_to((base / "synthesis").resolve()):
        raise ValueError("unsafe original draft")
    digest = hashlib.sha256(draft.read_bytes()).hexdigest()
    row.update(output_ref=relative, output_sha256=digest)
    _write_dispatch(path, document)


def load_original_draft(base: Path, context: dict, relative: str) -> dict | None:
    if context.get("execution_kind") == "advantage":
        return native_original(base, context, relative)
    _, document = _dispatch(base, context, "synthesis")
    row = document.get("cohorts", {}).get("original", {})
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("unsafe original draft path")
    draft = inside(base, relative)
    if (draft.is_symlink() or not draft.resolve().is_relative_to(inside(base, "synthesis")) or
            row.get("output_ref") != relative or not row.get("output_sha256")):
        raise ValueError("original draft lacks its protected publication binding")
    data = draft.read_bytes()
    if hashlib.sha256(data).hexdigest() != row["output_sha256"]:
        raise ValueError("protected original draft changed")
    return json.loads(data)


def synthesis_selector(base: Path, context: dict, finding: dict) -> str:
    """Retained original authorship is not the current aggregate publisher's route."""
    actor = "vulnops-advantage-synthesis" if context.get("execution_kind") == "advantage" else "vulnops-synthesis"
    if context.get("execution_kind") == "advantage":
        original = load_original_draft(base, context, "synthesis/original-findings.json") if inside(base, "synthesis/original-findings.json").is_file() else None
        if original:
            rows = [row for row in [*original.get("findings", []), *original.get("non_promoted", [])] if row["id"] == finding["id"]]
            if rows:
                routes = [row["selector"] for row in rows[0].get("contributors", []) if row["actor"] == actor]
                if len(set(routes)) == 1:
                    return routes[0]
        return context["model_routing"]["agents"][actor]
    path = base / "synthesis/dispatch.json"
    if path.is_file():
        _, dispatch = _dispatch(base, context, "synthesis")
        cohort = dispatch.get("cohorts", {}).get("original", {})
        if cohort.get("output_ref"):
            original = load_original_draft(base, context, cohort["output_ref"])
            if any(row["id"] == finding["id"] for row in [*original.get("findings", []), *original.get("non_promoted", [])]):
                manifest_name = "run-manifest.json"
                manifest = json.loads((base / manifest_name).read_text())
                assignment = manifest.get("attempt_contexts", {}).get(cohort["attempt_id"])
                if not assignment:
                    if cohort["attempt_id"] != context.get("attempt_id"):
                        raise ValueError("protected original publisher route is unavailable")
                    return context["model_routing"]["agents"][actor]
                return assignment["model_routing"]["agents"][actor]
    return context["model_routing"]["agents"][actor]


def _digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _validate_review(context: dict, candidate: dict, result: dict) -> None:
    from run_lifecycle import current_assessment
    from intrusion_contract import primitive_updates_view
    if not current_assessment(result, context):
        raise ValueError("review admission requires actual current independent review")
    base = _base(context)
    spec = importlib.util.spec_from_file_location("ordinary_gap_review", Path(__file__).with_name("finalize-verification.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    index = json.loads((base / "campaign-planning/evidence-index.json").read_text())
    intrusion = json.loads((base / "intrusion/intrusion-results.json").read_text())
    primitives = {row["id"]: row for row in index.get("primitives", [])}
    primitives.update({row["id"]: row for result in intrusion.get("results", [])
                       for row in primitive_updates_view(base, context, result)})
    module.validate_assessment(Path(__file__).resolve().parent.parent, base,
        Path(context.get("source_root") or context["repo_path"]), candidate, result,
        context["model_routing"]["agents"]["vulnops-synthesis"], primitives,
        context["model_routing"], repositories=context["repositories"])


def review_worker(context: dict, finding_id: str, action: str, reason: str = "") -> dict:
    """Record native ordinary reviewer execution, not its substantive verdict."""
    if context.get("execution_kind") == "advantage" or not re.fullmatch(r"F-[0-9]{3}", finding_id):
        raise ValueError("ordinary review dispatch requires its canonical finding identity")
    base = _base(context)
    path, document = _dispatch(base, context, "final-verification", active=True)
    source = load(inside(base, "synthesis/findings.json"))
    matches = [row for row in source["findings"] if row["id"] == finding_id]
    if len(matches) != 1:
        raise ValueError("review dispatch requires an exact synthesized finding")
    cohort = "supplementary" if supplementary_only(matches[0], accepted_candidates(base, context=context)) else "original"
    workers = document["workers"]
    phase_attempt = document.get("cohorts", {}).get(cohort, {}).get("phase_attempt", 0)
    attempts = [row for row in workers if row["id"] == finding_id and
                (cohort=="supplementary" or row.get("phase_attempt",0)==phase_attempt)]
    if action == "begin":
        require_cohort(context, "final-verification", cohort)
        if cohort=="supplementary" and sum(row.get("status")=="running" for row in workers)>=context["gap_exploration_budget"]["max_concurrency"]:
            raise ValueError("supplementary reviewer concurrency exhausted")
        limit = context["gap_exploration_budget"]["max_attempts"] if cohort == "supplementary" else 2
        stale = bool(attempts and attempts[-1]["status"]=="completed" and attempts[-1].get("attempt_id")!=context["attempt_id"])
        if (attempts and attempts[-1]["status"] != "failed" and not stale) or len(attempts) >= limit:
            raise ValueError("review assignment is active, completed or exhausted")
        row = {"id": finding_id, "cohort": cohort, "attempt": len(attempts) + 1, "status": "running",
               "attempt_id": context["attempt_id"], "phase_attempt": phase_attempt, "error": "", "input_sha256": _digest(matches[0]),
               "result_ref": f"final-verification/results/{finding_id}.json", "result_sha256": None}
        workers.append(row)
    else:
        if not attempts or attempts[-1]["status"] != "running":
            raise ValueError("review terminal record requires a running assignment")
        row = attempts[-1]
        if action == "fail":
            if not reason.strip():
                raise ValueError("review failure requires its actual terminal error")
            row.update(status="failed", error=reason)
        elif action == "finish":
            require_cohort(context, "final-verification", cohort)
            result_path = base / row["result_ref"]
            if result_path.is_symlink() or not result_path.resolve().is_relative_to(base.resolve()):
                raise ValueError("unsafe reviewer publication")
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if row["input_sha256"] != _digest(matches[0]):
                raise ValueError("reviewed candidate changed after dispatch")
            _validate_review(context, matches[0], result)
            require_cohort(context, "final-verification", cohort)
            completed_at=datetime.now(timezone.utc).isoformat()
            from run_lifecycle import assessment_ref
            result["assessment_context"] = assessment_ref(context)
            if result.get("non_promoted"):
                result["non_promoted"]["assessment_context"] = assessment_ref(context)
            _write_dispatch(result_path, result)
            row.update(status="completed", result_sha256=_digest(result),
                       completed_at=completed_at)
        else:
            raise ValueError("unknown reviewer execution action")
    _write_dispatch(path, document)
    if action == "fail":
        rejected = base / row["result_ref"]
        if rejected.is_symlink() or not rejected.resolve().is_relative_to(base.resolve()):
            raise ValueError("unsafe rejected reviewer output")
        rejected.unlink(missing_ok=True)
    return row


def validate_review_admission(base: Path, context: dict, candidate: dict, result: dict) -> None:
    """Optional review cannot borrow an original slot or bypass its admission."""
    if not supplementary_only(candidate, accepted_candidates(base, context=context)):
        return
    if context.get("execution_kind") == "advantage":
        from advantage_pipeline import worker_input, terminal_worker, native_draft, project_worker_result
        packet, _, digest, _ = worker_input(context, "final-verification", candidate["id"])
        native = terminal_worker(context, "final-verification", candidate["id"], digest, result["attempt"])
        expected = project_worker_result(context, "final-verification", packet, native_draft(context, native))
        if result != expected:
            raise ValueError("supplementary review differs from native terminal analytical evidence")
        return
    _, dispatch = _dispatch(base, context, "final-verification")
    workers = [row for row in dispatch["workers"] if row["id"] == candidate["id"]]
    cohort = dispatch.get("cohorts", {}).get("supplementary", {})
    if not workers or not cohort:
        raise ValueError("supplementary review lacks its separate assignment")
    row = workers[-1]
    if (row.get("status") != "completed" or row.get("cohort") != "supplementary" or
            row.get("input_sha256") != _digest(candidate) or row.get("result_sha256") != _digest(result) or
            not row.get("completed_at") or
            datetime.fromisoformat(row["completed_at"]) > datetime.fromisoformat(cohort["deadline_at"])):
        raise ValueError("supplementary review lacks an unchanged timely admitted result")


def review_failure(base: Path, context: dict, candidate: dict) -> tuple[str, str, str]:
    if context.get("execution_kind") == "advantage":
        if not supplementary_only(candidate, accepted_candidates(base, context=context)):
            raise ValueError("original or mixed review cannot close as optional")
        call = core.live_call(context, "final-verification")
        rows = [row for row in call["workers"] if row["phase"] == "final-verification" and row["id"] == candidate["id"]]
        if rows:
            row = rows[-1]
            if row["status"] in {"failed", "cancelled"}:
                return (row.get("error") or "Native independent reviewer failed or was cancelled.",
                        f"synthesis/findings.json:{candidate['id']}", "execution_failed")
            if row["status"] == "completed":
                return ("Native reviewer delivered no admitted independent review; the candidate remains unreviewed.",
                        f"synthesis/findings.json:{candidate['id']}", "locally_unresolved")
            raise ValueError("stop native supplementary reviewer before unreviewed closure")
        failure = native_cohort_failure(context, "final-verification", "supplementary")
        return ("Independent review was not launched. " + failure["reason"],
                f"synthesis/findings.json:{candidate['id']}", "locally_unresolved")
    _, dispatch = _dispatch(base, context, "final-verification")
    workers = [row for row in dispatch["workers"] if row["id"] == candidate["id"]]
    if workers and workers[-1].get("status") == "failed":
        row = workers[-1]
        if (row.get("cohort") == "supplementary" and row.get("error") and
                row.get("attempt", 0) >= context["gap_exploration_budget"]["max_attempts"]):
            return row["error"], f"final-verification/dispatch.json:{candidate['id']}", "execution_failed"
    if workers and workers[-1].get("status") == "completed" and workers[-1].get("attempt_id") != context.get("attempt_id"):
        row = workers[-1]
        cohort = dispatch.get("cohorts", {}).get("supplementary")
        if cohort and (row["attempt"] >= context["gap_exploration_budget"]["max_attempts"] or
                       datetime.now(timezone.utc) >= _cohort_deadline(context,"final-verification","supplementary",cohort)):
            retained = load(inside(base,row["result_ref"]))
            if row.get("result_sha256") != _digest(retained) or row.get("input_sha256") != _digest(candidate):
                raise ValueError("historical supplementary reviewer admission changed")
            return ("The admitted review belongs to an earlier source assessment and the separate current-review allowance is exhausted.",
                    f"final-verification/dispatch.json:{candidate['id']}", "budget_deferred")
    failure = cohort_failure(base, context, "final-verification")
    return failure["reason"], "final-verification/dispatch.json:supplementary", failure.get("failure_kind", "execution_failed")


def unreviewed_row(base: Path, context: dict, candidate: dict, *, phase: str,
                   input_refs: list[str]) -> dict:
    if phase == "final-verification":
        reason, reference, status = review_failure(base, context, candidate)
    else:
        failure = cohort_failure(base, context, phase)
        reason = failure["reason"]
        reference = (f"gap-exploration/results.json:{candidate['id']}" if context.get("execution_kind") == "advantage"
                     else f"{phase}/dispatch.json:supplementary")
        status = failure.get("failure_kind", "execution_failed")
    return _unreviewed_record(context, candidate["id"], input_refs, reason, reference, status)


def _unreviewed_record(context: dict, identifier: str, input_refs: list[str],
                       reason: str, reference: str, status: str) -> dict:
    row = {"id": identifier, "input_refs": input_refs, "status": status,
           "reason": reason, "missing_fact": "Complete independent dossier review has not been established.",
           "next_action": "Complete the bounded supplementary authoring and independent source review before promotion.",
           "task_ref": reference}
    if context.get("attempt_id"):
        from run_lifecycle import assessment_ref
        row["assessment_context"] = assessment_ref(context)
    return row


def _historical_unreviewed(base: Path, context: dict, row: dict, candidate: dict,
                           phase: str, refs: list[str]) -> dict:
    """Check recorded failure and producing scope, not a consumer's live allowance."""
    reference = row["assessment_context"]
    manifest_name = "advantage-manifest.json" if context.get("execution_kind") == "advantage" else "run-manifest.json"
    manifest = load(inside(base, manifest_name))
    attempt = reference.get("attempt_id")
    if not attempt or set(reference) - {"attempt_id", "assessment_id"}:
        raise ValueError("unreviewed closure lacks its producing attempt")
    scope_id = reference.get("assessment_id")
    if not scope_id and any(scope.get("attempt_id") == attempt
                            for scope in manifest.get("assessment_scopes", {}).values()):
        raise ValueError("unreviewed closure omitted its producing scope")
    if scope_id:
        scope = manifest.get("assessment_scopes", {}).get(scope_id, {})
        if scope.get("run_id") != context["run_id"] or scope.get("attempt_id") != attempt:
            raise ValueError("unreviewed closure has foreign producing scope")
    if context.get("execution_kind") == "advantage":
        from report_bundle import read_publication
        bundle = read_publication(base, expected_kind="advantage")
        if bundle["report"].get("publication"):
            raise ValueError("new Advantage evidence cannot use legacy cohort control records")
        dispatch = load(inside(base, f"{phase}/dispatch.json"))
        if dispatch.get("run_id") != context["run_id"]:
            raise ValueError("legacy supplementary evidence belongs to another execution")
    else:
        _, dispatch = _dispatch(base, context, phase)
    if row["task_ref"] == f"{phase}/dispatch.json:supplementary":
        if context.get("execution_kind") == "advantage":
            failure = dispatch.get("cohorts", {}).get("supplementary", {})
            if (failure.get("status") != "failed" or not failure.get("reason")
                    or dispatch.get("cohorts", {}).get("original", {}).get("status") != "completed"):
                raise ValueError("legacy optional closure lacks its producing evidence")
        else:
            failure = cohort_failure(base, context, phase)
        if (failure.get("attempt_id") != attempt
                and manifest.get("phase_attempts", {}).get(phase) != attempt):
            raise ValueError("unreviewed closure has foreign failure authority")
        reason, status = failure["reason"], failure.get("failure_kind", "execution_failed")
    elif phase == "final-verification" and row["task_ref"] == f"{phase}/dispatch.json:{candidate['id']}":
        workers = [worker for worker in dispatch["workers"] if worker["id"] == candidate["id"]]
        if not workers or workers[-1].get("cohort") != "supplementary":
            raise ValueError("unreviewed closure lacks its assigned failure")
        worker = workers[-1]
        details = manifest.get("attempt_contexts", {}).get(attempt, {})
        budget = details.get("gap_exploration_budget", {})
        if worker.get("status") == "failed":
            if (worker.get("attempt_id") != attempt or not worker.get("error")
                    or worker.get("attempt", 0) < budget.get("max_attempts", float("inf"))):
                raise ValueError("unreviewed closure lacks exhausted producing review authority")
            reason, status = worker["error"], "execution_failed"
        elif (worker.get("status") == "completed" and worker.get("attempt_id") != attempt
              and manifest.get("phase_attempts", {}).get(phase) == attempt):
            result = load(inside(base, worker["result_ref"]))
            if worker.get("result_sha256") != _digest(result) or worker.get("input_sha256") != _digest(candidate):
                raise ValueError("historical supplementary reviewer admission changed")
            reason = "The admitted review belongs to an earlier source assessment and the separate current-review allowance is exhausted."
            status = "budget_deferred"
        else:
            raise ValueError("unreviewed closure lacks recorded producing review authority")
    else:
        raise ValueError("unreviewed closure has foreign task authority")
    return _unreviewed_record(reference, candidate["id"], refs, reason, row["task_ref"], status)


def validate_unreviewed(base: Path, context: dict, rows: list[dict], candidates: list[dict], phase: str) -> None:
    """Validate fresh closure strictly and inherited closure against its producer."""
    known = {row["id"]: row for row in candidates}
    seen = set()
    supplements = accepted_candidates(base, context=context)
    for row in rows:
        identifier = row["id"]
        if identifier in seen or identifier not in known:
            raise ValueError("unreviewed closure has duplicate or unknown candidate")
        seen.add(identifier)
        candidate = known[identifier]
        if phase == "final-verification":
            if not supplementary_only(candidate, supplements):
                raise ValueError("original or mixed finding cannot close as unreviewed")
            refs = [f"synthesis/findings.json:{identifier}"]
        elif phase == "synthesis":
            if identifier not in {item["id"] for item in supplements}:
                raise ValueError("only accepted supplementary input can close unreviewed")
            refs = [f"gap-exploration/results.json:{identifier}"]
        else:
            raise ValueError("unreviewed closure is limited to supplementary downstream work")
        from run_lifecycle import current_assessment
        if context.get("execution_kind") == "advantage" and inside(base, "report/security-report.json").is_file():
            from report_bundle import read_publication
            bundle = read_publication(base, expected_kind="advantage")
            if not bundle["report"].get("publication"):
                expected = _historical_unreviewed(base, context, row, candidate, phase, refs)
                if row != expected:
                    raise ValueError("legacy unreviewed evidence changed its producing limitation")
                continue
            if (row.get("input_refs") != refs or row.get("task_ref") != refs[0]
                    or row.get("status") not in {"execution_failed", "budget_deferred", "locally_unresolved"}
                    or not all(isinstance(row.get(key), str) and row[key].strip()
                               for key in ("reason", "missing_fact", "next_action"))):
                raise ValueError("completed unreviewed limitation changed candidate evidence scope")
            continue
        if row.get("assessment_context") and not current_assessment(row, context):
            expected = _historical_unreviewed(base, context, row, candidate, phase, refs)
        else:
            expected = unreviewed_row(base, context, candidate, phase=phase, input_refs=refs)
        if row != expected:
            raise ValueError("unreviewed closure differs from authoritative lifecycle failure")


def close_supplementary_draft(base: Path, context: dict, original: dict) -> dict:
    result = copy.deepcopy(original)
    rows = [unreviewed_row(base, context, candidate, phase="synthesis",
                           input_refs=[f"gap-exploration/results.json:{candidate['id']}"])
            for candidate in accepted_candidates(base, context=context)]
    result["unreviewed"] = rows
    return result


def retained_original(base: Path, context: dict, dispatch: dict) -> str | None:
    """Retain admitted bindings, never replay fresh source proof during cleanup."""
    from run_lifecycle import assert_owner
    if context.get("execution_kind") == "advantage":
        raise ValueError("Advantage original evidence is not recoverable work")
    from synthesis_contract import InvalidSynthesisStructure, validate_synthesis_structure
    assert_owner(base, context.get("launcher_session_id"))
    manifest = load(inside(base, "run-manifest.json"))
    ledger = load(inside(base, "task-ledger.json"))
    owners = [row for row in ledger.get("tasks", []) if row.get("phase") == "synthesis"]
    def status(value):
        return value.get("status") if isinstance(value, dict) else value
    disposable = {"running", "failed"}
    if (manifest.get("run_id") != context["run_id"] or manifest.get("status") == "complete"
            or status(manifest.get("phases", {}).get("synthesis")) not in disposable
            or any(name != "synthesis" and status(state) == "running"
                   for name, state in manifest.get("phases", {}).items())
            or ledger.get("run_id") != context["run_id"] or len(owners) != 1
            or owners[0].get("status") not in disposable
            or any(row.get("phase") != "synthesis" and row.get("status") == "running"
                   for row in ledger.get("tasks", []))):
        raise ValueError("original draft cleanup lacks its disposable canonical phase owner")
    cohorts = dispatch.get("cohorts", {})
    original = cohorts.get("original", {})
    relative = original.get("output_ref")
    # Old finalizers completed themselves before terminal delivery. Without a
    # subsequent cohort, a recorded failed owner cannot establish admission.
    failed_owner = owners[0].get("status") == "failed" or bool(owners[0].get("failure_history"))
    admitted = (original.get("status") == "completed" and relative
                and original.get("output_sha256")
                and not (failed_owner and "supplementary" not in cohorts))
    if admitted:
        draft = load_original_draft(base, context, relative)
        if draft.get("run_id") != context["run_id"]:
            raise ValueError("original draft belongs to another execution")
        try:
            validate_synthesis_structure(draft, linked=False)
        except InvalidSynthesisStructure:
            admitted = False
    if admitted:
        return relative
    cohorts.pop("original", None)
    supplementary = cohorts.get("supplementary")
    if supplementary:
        supplementary.update(
            status="failed", completed_at=datetime.now(timezone.utc).isoformat(),
            failure_kind="execution_failed",
            reason="Supplementary synthesis depended on unaccepted original authoring; its union was discarded.")
    return None


def recovery_checkpoint(base: Path, phase: str, context: dict) -> dict:
    """Retain only bound phase-local work; rejected drafts are never recovered."""
    if context.get("execution_kind") == "advantage":
        raise ValueError("Advantage supplementary work has no recovery checkpoint")
    # Match the canonical paths returned by _dispatch without accepting a symlink root.
    base = inside(base, ".")
    if not (base / phase / "dispatch.json").exists():
        return {"files": [], "documents": {}}
    path, dispatch = _dispatch(base, context, phase)
    files = {str(path.relative_to(base))}
    cohorts = dispatch.get("cohorts", {})
    if phase == "synthesis":
        relative = retained_original(base, context, dispatch)
        if relative:
            files.add(relative)
    else:
        source = load(inside(base, "synthesis/findings.json"))
        candidates = {row["id"]: row for row in source["findings"]}
        from dossier_contract import validate_publication_schema
        for worker in {row["id"]:row for row in dispatch["workers"]}.values():
            if worker["status"] != "completed":
                continue
            candidate = candidates.get(worker["id"])
            relative = f"final-verification/results/{worker['id']}.json"
            result_path = base / relative
            if worker.get("result_ref") != relative or result_path.is_symlink() or not result_path.resolve().is_relative_to(base.resolve()):
                raise ValueError("retained review output ownership differs")
            result = json.loads(result_path.read_text())
            if (not candidate or worker.get("input_sha256") != _digest(candidate) or
                    worker.get("result_sha256") != _digest(result)):
                raise ValueError("retained reviewer admission changed")
            validate_publication_schema(result, "independent-verification-result.schema.json")
            files.add(relative)
    stamp = datetime.now(timezone.utc).isoformat()
    for worker in dispatch.get("workers", []):
        if worker.get("status") == "running":
            worker.update(status="failed", error="Native reviewer interrupted before terminal admission.")
    for row in cohorts.values():
        if row.get("status") == "running":
            row.update(status="failed", completed_at=stamp,
                       reason="Native downstream cohort interrupted before terminal completion.")
    return {"files": sorted(files), "documents": {str(path.relative_to(base)): dispatch}}


def native_cohort(context: dict, phase: str, cohort: str) -> dict:
    if phase not in {"synthesis", "final-verification"} or cohort not in {"original", "supplementary"}:
        raise ValueError("unknown native downstream cohort")
    call = core.live_call(context, phase)
    if cohort == "supplementary":
        if not accepted_candidates(_base(context), context=context):
            raise ValueError("supplementary authoring requires accepted supplementary evidence")
        key = "synthesis_timeout_seconds" if phase == "synthesis" else "verification_timeout_seconds"
        if not context["gap_exploration_budget"]["enabled"] or context["gap_exploration_budget"][key] <= 0:
            raise ValueError("supplementary work has no current invocation allowance")
        if phase == "synthesis":
            native_original(_base(context), context, "synthesis/original-findings.json")
        else:
            require_original_reviews_closed(context, call)
    if phase == "synthesis":
        identifier = "AdvantageSynthesis" + cohort.title()
        rows = [row for row in call["workers"] if row["phase"] == phase and row["id"] == identifier]
        if not rows or rows[-1]["status"] not in {"running", "completed", "failed", "cancelled"}:
            raise ValueError("synthesis cohort lacks actual native author execution")
        validate_synthesis_author(context, rows[-1])
        return rows[-1]
    return {"cohort": cohort, "phase": phase}


def native_cohort_failure(context: dict, phase: str, cohort: str) -> dict:
    if cohort != "supplementary":
        raise ValueError("original authoring or review cannot close as optional")
    call = core.live_call(context)
    rows = [row for row in call["workers"] if row["phase"] == phase]
    if any(row["status"] == "running" for row in rows):
        # A live finalizer is allowed; an unfinished author/reviewer is not.
        caller = call["caller"]["id"]
        if any(row["status"] == "running" and row["runtime_id"] != caller for row in rows):
            raise ValueError("stop native supplementary descendants before optional closure")
    if phase == "synthesis":
        native_original(_base(context), context, "synthesis/original-findings.json")
        selected = [row for row in rows if row["id"] == "AdvantageSynthesisSupplementary"]
    else:
        require_original_reviews_closed(context, call)
        selected = [row for row in rows if row["id"] == "AdvantageReviewSupplementary"]
    key = "synthesis_timeout_seconds" if phase == "synthesis" else "verification_timeout_seconds"
    if not selected and (not context["gap_exploration_budget"]["enabled"] or context["gap_exploration_budget"][key] == 0):
        return {"reason": "Supplementary work is disabled; no native execution was launched.",
                "failure_kind": "budget_deferred"}
    if not selected:
        return {"reason": "Supplementary work was not launched; independent dossier review remains unestablished.",
                "failure_kind": "locally_unresolved"}
    latest = selected[-1]
    if latest["status"] in {"failed", "cancelled"}:
        return {"reason": latest.get("error") or "Native supplementary coordinator failed or was cancelled.",
                "failure_kind": "execution_failed"}
    if latest["status"] == "completed":
        return {"reason": "Native supplementary output has no admitted independent dossier review.",
                "failure_kind": "locally_unresolved"}
    raise ValueError("stop native supplementary coordinator before unreviewed closure")


def native_original(base: Path, context: dict, relative: str) -> dict | None:
    """Retain bound original evidence; an absent publication is not an original."""
    if relative != "synthesis/original-findings.json":
        raise ValueError("original synthesis requires its canonical analytical artifact")
    target = inside(base, relative)
    if inside(base, "report/security-report.json").is_file():
        from report_bundle import read_publication
        bundle = read_publication(base, expected_kind="advantage")
        binding = load(inside(base, "synthesis/findings.json")).get("original_evidence", {})
        if not bundle["report"].get("publication"):
            cohort = load(inside(base, "synthesis/dispatch.json")).get("cohorts", {}).get("original", {})
            binding = {"ref": cohort.get("output_ref"), "sha256": cohort.get("output_sha256")}
        elif not binding:
            return None
        if binding != {"ref": relative, "sha256": core.sha256_file(target)}:
            raise ValueError("original draft changed its completed analytical binding")
    else:
        call = core.live_call(context)
        rows = [row for row in call["workers"] if row["phase"] == "synthesis" and row["id"] == "AdvantageSynthesisOriginal"]
        if any(row["status"] == "running" for row in rows):
            raise ValueError("stop native original author before supplementary work")
        bound = [(row, checksum) for row in rows
                 for ref, checksum in row.get("artifact_sha256", {}).items()
                 if inside(base, ref) == target]
        if bound:
            digest = core.sha256_file(target)
            for row, checksum in bound:
                validate_synthesis_author(context, row)
                if checksum != digest:
                    raise ValueError("original draft differs from exact native terminal evidence")
        elif rows or not target.is_file():
            return None
        else:
            try:
                result = load(target)
                validate_empty_original(context, result)
            except ValueError:
                return None
            return result
    result = load(target)
    if result.get("run_id") != context["run_id"]:
        raise ValueError("original draft belongs to another invocation")
    return result


def require_original_reviews_closed(context: dict, call: dict) -> None:
    """Only active original reviewers gate supplementary scheduling, never retry capacity."""
    from advantage_pipeline import verification_cohorts
    for identifier, cohort in verification_cohorts(context).items():
        if cohort != "original":
            continue
        rows = [row for row in call["workers"] if row["phase"] == "final-verification" and row["id"] == identifier]
        if rows and rows[-1]["status"] == "running":
            raise ValueError("stop native original reviewer before supplementary work")


def validate_empty_original(context: dict, document: dict) -> None:
    from advantage_pipeline import admitted_synthesis, empty_synthesis
    original_context = {**context, "_original_synthesis": True}
    expected = admitted_synthesis(original_context, empty_synthesis(original_context))
    if document != expected:
        raise ValueError("original draft lacks exact deterministic empty analytical closure")


def validate_synthesis_author(context: dict, worker: dict) -> None:
    actor = "vulnops-advantage-synthesis"
    if worker.get("actor") != actor or worker.get("selector") != context["model_routing"]["agents"][actor]:
        raise ValueError("native synthesis author differs from immutable exact route")
