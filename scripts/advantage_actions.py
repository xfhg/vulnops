"""Selected patch assessments and historical finding actions; never a patch publisher."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from artifact_policy import publication_content_error
from evidence_accounting import EvidenceIssue, diagnostic, summarize

ROOT = Path(__file__).resolve().parents[1]
ACTION_NAMES = ("verify_fix", "patch_risk", "hardening", "tracking", "diff_review")


def core():
    import advantage_contract
    return advantage_contract


def safe_relative(value: str) -> Path:
    path = Path(value)
    if (not value or path.is_absolute() or any(p in {"", ".", "..", ".git"} for p in value.split("/"))
            or "\\" in value or any(ord(c) < 32 for c in value) or path.as_posix() != value):
        raise ValueError("unsafe patch/source path")
    return path




def repository_root(context: dict, selected: str | None) -> tuple[str, Path]:
    repositories = context["repositories"]
    if selected is None and len(repositories) == 1:
        selected = repositories[0]["path"]
    matches = [item for item in repositories if item["path"] == selected]
    if len(matches) != 1:
        raise ValueError("patch requires one exact repository inventory path (mandatory for multiple repositories)")
    source = Path(context.get("source_root") or context["repo_path"])
    relative = matches[0]["path"]
    repo = source if relative == "." else core().inside(source, source / safe_relative(relative))
    return relative, repo


def patch_paths(data: bytes) -> list[tuple[str, str]]:
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("patch exceeds 4 MiB bound")
    text = data.decode("utf-8")
    if "\x00" in text or publication_content_error(text):
        raise ValueError("patch is not publishable sanitized UTF-8 text")
    # Git's parser applies hunks, but this independent admission excludes mode,
    # rename, binary, symlink and path ambiguities before any disposable copy.
    if re.search(r"^(?:GIT binary patch|Binary files |rename |copy |old mode |new mode |similarity index )", text, re.M):
        raise ValueError("only ordinary text additions, modifications and deletions are accepted")
    for mode in re.findall(r"^(?:new file mode|deleted file mode) (\d+)$", text, re.M):
        if mode not in {"100644", "100755"}:
            raise ValueError("patch cannot create or delete special files")
    paths = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("diff --git "):
            match = re.fullmatch(r"diff --git a/([^\t ]+) b/([^\t ]+)", line)
            if not match or match[1] != match[2]:
                raise ValueError("ambiguous or renamed patch path")
            safe_relative(match[1])
        if not line.startswith("--- "):
            continue
        if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
            raise ValueError("patch missing paired source headers")
        old, new = line[4:], lines[index + 1][4:]
        if old != "/dev/null" and not old.startswith("a/"):
            raise ValueError("patch old path requires a/ prefix")
        if new != "/dev/null" and not new.startswith("b/"):
            raise ValueError("patch new path requires b/ prefix")
        if old == new == "/dev/null":
            raise ValueError("patch has no source path")
        path = new[2:] if new != "/dev/null" else old[2:]
        safe_relative(path)
        if old != "/dev/null" and new != "/dev/null" and old[2:] != new[2:]:
            raise ValueError("renamed patch paths are unsupported")
        paths.append((path, "added" if old == "/dev/null" else "deleted" if new == "/dev/null" else "modified"))
    if not paths or len(paths) > 512 or len({p for p, _ in paths}) != len(paths):
        raise ValueError("patch must contain 1..512 unique changed text paths")
    return paths


def derived_root(context: dict) -> Path:
    run_id = context["run_id"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id) or ".." in run_id:
        raise ValueError("unsafe linked run identity")
    return core().inside(ROOT, ROOT / "work/advantage" / run_id / "derived")


def prepare_patch(context: dict) -> dict | None:
    options = context["options"]
    requested = context["mode"] == "diff" or bool(options.get("verify_fix")) or options.get("assess_patch_risk", False)
    patch = options.get("patch")
    if not requested:
        if patch or options.get("repository"):
            raise ValueError("unused patch/repository input")
        return None
    if not patch:
        raise ValueError("selected assessment requires an immutable patch")
    patch_path = Path(patch)
    if patch_path.is_symlink() or not patch_path.is_file():
        raise ValueError("patch must be a regular local file, not a symlink")
    data = patch_path.read_bytes()
    paths = patch_paths(data)
    key, repo = repository_root(context, options.get("repository"))
    before = {name: core().sha256_file(repo / name) if (repo / name).is_file() else None for name, _ in paths}
    for name, status in paths:
        path = core().inside(repo, repo / name)
        if status != "added" and (not path.is_file() or path.is_symlink()):
            raise ValueError("patch base file missing or unsafe")
        if status == "added" and path.exists():
            raise ValueError("patch addition already exists in selected current base")
    destination = derived_root(context)
    digest = hashlib.sha256(data).hexdigest()
    bound_path = core().inside(Path(context["scan_base"]), Path(context["scan_base"]) / "baseline/assessment.patch")
    if bound_path.exists() and bound_path.read_bytes() != data:
        raise ValueError("bound patch bytes changed")
    if destination.exists():
        binding = context.get("patch_binding")
        if binding is None:
            raise ValueError("derived workspace already exists without an owned patch binding")
        # This disposable view belongs to this action, never to the source audit.
        # Rebuild against the explicitly selected current base on a new attempt.
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_root = Path(context.get("source_root") or context["repo_path"])
    shutil.copytree(source_root, destination, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    derived_repo = destination if key == "." else destination / key
    try:
        for file in destination.rglob("*"):
            if file.is_symlink() and not file.resolve().is_relative_to(destination.resolve()):
                raise ValueError("derived source contains an escaping symlink")
        for args in (["--check"], []):
            result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "apply", "--no-index", "--whitespace=nowarn", *args, "-"],
                                    cwd=derived_repo, input=data, capture_output=True,
                                    env={"PATH": os.environ.get("PATH", os.defpath), "GIT_CONFIG_NOSYSTEM": "1",
                                         "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CEILING_DIRECTORIES": str(destination.parent)})
            if result.returncode:
                raise ValueError("patch does not apply exactly to the selected current repository base")
        if any((core().sha256_file(repo / name) if (repo / name).is_file() else None) != digest for name, digest in before.items()):
            raise ValueError("selected patch base changed while preparing patch view")
        changed = []
        for name, status in paths:
            old, new = repo / name, derived_repo / name
            if status == "deleted" and new.exists() or status != "deleted" and not new.is_file():
                raise ValueError("patch result differs from declared file operation")
            if old.is_file() and new.is_file() and old.read_bytes() == new.read_bytes():
                raise ValueError("patch claims a changed file without a content delta")
            changed.append({"path": name, "status": status,
                            "old_sha256": core().sha256_file(old) if old.is_file() else None,
                            "new_sha256": core().sha256_file(new) if new.is_file() else None})
        binding = {"sha256": digest, "repository": key,
                   "patch_ref": "baseline/assessment.patch", "changed_files": changed}
        bound_path.parent.mkdir(parents=True, exist_ok=True)
        bound_path.write_bytes(data)
        return binding
    except BaseException:
        shutil.rmtree(destination)
        raise


def source_view_context(context: dict, view: str) -> dict:
    if view == "base":
        return context
    if view != "derived" or not context.get("patch_binding"):
        raise ValueError("source view requires an immutable derived patch binding")
    portable = not context.get("source_root")
    validate_patch(context, portable=portable)
    return {**context, "source_root": None if portable else str(derived_root(context)),
            "repo_path": None if portable else str(derived_root(context)),
            "source_view": "derived"}


def validate_patch(context: dict, *, portable: bool = False) -> None:
    binding = context.get("patch_binding")
    if not binding:
        return
    base = Path(context["scan_base"])
    patch = core().inside(base, base / safe_relative(binding["patch_ref"]))
    if core().sha256_file(patch) != binding["sha256"]:
        raise ValueError("bound assessment patch bytes changed")
    parsed = patch_paths(patch.read_bytes())
    if parsed != [(item["path"], item["status"]) for item in binding["changed_files"]]:
        raise ValueError("patch changed-file accounting differs from exact bytes")
    if portable:
        return
    original = context["options"].get("patch")
    if original and Path(original).is_absolute() and core().sha256_file(Path(original)) != binding["sha256"]:
        raise ValueError("original supplied patch changed")
    _, repo = repository_root(context, binding["repository"])
    derived = derived_root(context) if binding["repository"] == "." else derived_root(context) / binding["repository"]
    for item in binding["changed_files"]:
        for root, field in ((repo, "old_sha256"), (derived, "new_sha256")):
            path = core().inside(root, root / safe_relative(item["path"]))
            actual = core().sha256_file(path) if path.is_file() else None
            if actual != item[field]:
                raise ValueError("selected patch base or derived changed-file content no longer matches the assessment")


def selected_findings(context: dict, *, tracking: bool = False,
                      unavailable_cohorts: set | None = None) -> tuple[dict, Path, str]:
    from advantage_baseline import accepted_findings
    if context["mode"] == "actions":
        source = context.get("action_source")
        if not isinstance(source, dict) or not source.get("execution_id"):
            raise ValueError("selected findings require an authoritative action source binding")
        requested = sorted(set(context["options"].get("verify_fix", [])
                               + context["options"].get("track_findings", [])))
        if source.get("selected_findings") != [{"id": identifier} for identifier in requested]:
            raise ValueError("selected action findings differ from their admitted execution binding")
        root, execution_id = Path(source["root"]), source["execution_id"]
    elif tracking:
        root, execution_id = Path(context["scan_base"]), context["run_id"]
    else:
        root, execution_id = Path(context["source_scan"]), context["source_run_id"]
    if root.resolve() != Path(context["scan_base"]).resolve():
        from report_bundle import read_publication
        publication = read_publication(root)
        if publication["run_id"] != execution_id:
            raise ValueError("selected finding source must be its bound completed execution")
    accepted = accepted_findings(root, unavailable_cohorts=unavailable_cohorts,
                                 expected_execution_id=execution_id)
    return accepted, root, execution_id


def validate_citations(context: dict, citations: list[dict], *, portable: bool = False) -> None:
    if not citations:
        raise EvidenceIssue("missing_record", "assessment requires source-backed citations")
    binding = context.get("patch_binding")
    for citation in citations:
        view = citation["view"]
        path = safe_relative(citation["path"])
        if view == "derived" and not binding:
            raise ValueError("derived citation requires a bound patch")
        if citation["repository"] not in {item["path"] for item in context["repositories"]}:
            raise ValueError("citation repository is not in the admitted inventory")
        from advantage_pipeline import refs, source_context
        if not portable:
            key, source = repository_root(context, citation["repository"])
            if view == "derived":
                source = derived_root(context) if key == "." else derived_root(context) / key
            file = core().inside(source, source / path)
            if file.is_file() and core().sha256_file(file) != citation["sha256"]:
                raise ValueError("assessment citation source hash mismatch")
        qualified = citation["path"] if citation["repository"] == "." else citation["repository"] + "/" + citation["path"]
        reference = f"{qualified}:{citation['start_line']}-{citation['end_line']}"
        view_context = source_context(context, view)
        refs(view_context, [reference], source=True, kind="source")
        if portable:
            # Historical reads check safe coordinates, not obsolete runtime receipts.
            continue
        try:
            lines = file.read_text(encoding="utf-8").splitlines()
        except UnicodeError:
            raise EvidenceIssue("unreadable_content", "assessment source is not readable UTF-8") from None
        if not 1 <= citation["start_line"] <= citation["end_line"] <= len(lines):
            raise EvidenceIssue("invalid_range", "assessment citation exceeds source lines")


def empty_actions(context: dict) -> dict:
    return core().envelope(context, **{name: {"status": "not_selected", "records": []} for name in ACTION_NAMES}, unconfirmed_followups=[])


def retained_patch_actions(context: dict) -> dict | None:
    """Only accepted investigation owns patch assessments copied into a handoff."""
    if context["mode"] == "actions" or not context.get("patch_binding"):
        return None
    if context.get("portable") or not context.get("source_root"):
        from report_bundle import read_publication
        publication = read_publication(Path(context["scan_base"]), expected_kind="advantage")
        if publication["run_id"] != context["run_id"]:
            raise ValueError("accepted patch assessment belongs to another publication")
    elif "investigation" not in core().live_call(context)["accepted_phases"]:
        return None
    document = core().load(Path(context["scan_base"]) / "investigation/actions.json")
    core().validate_schema(document, "advantage-action.schema.json")
    if document["run_id"] != context["run_id"]:
        raise ValueError("accepted patch assessment belongs to another execution")
    return document


def assess_actions(context: dict, document: dict, *, investigation: bool = False) -> dict:
    """Project local uncertainty without editing authored or accepted action bytes."""
    core().validate_schema(document, "advantage-action.schema.json")
    if document["run_id"] != context["run_id"]:
        raise ValueError("action owner run differs from context")
    if error := publication_content_error(document):
        raise ValueError("action output is not sanitized: " + error)
    result = copy.deepcopy(document)
    options = context["options"]
    portable = not context.get("source_root") or bool(context.get("portable", False))
    retained = None if investigation else retained_patch_actions(context)
    validate_patch(context, portable=portable or retained is not None)
    expected = {"verify_fix": bool(options.get("verify_fix")), "patch_risk": bool(options.get("assess_patch_risk")),
                "hardening": bool(options.get("hardening")) and not investigation,
                "tracking": bool(options.get("track_findings")) and not investigation,
                "diff_review": context["mode"] == "diff"}
    for name, requested in expected.items():
        action = result[name]
        if action["status"] != ("completed" if requested else "not_selected"):
            raise ValueError("action disposition differs from explicit selection: " + name)
        if bool(action["records"]) != requested:
            raise ValueError("selected action missing results or unselected action claims results: " + name)
    fix = result["verify_fix"]["records"]
    if sorted(item["finding_id"] for item in fix) != sorted(options.get("verify_fix", [])):
        raise ValueError("fix verification must exactly cover selected finding IDs")
    if len(result["patch_risk"]["records"]) > 1:
        raise ValueError("patch risk requires exactly one assessment of the supplied patch")
    diff = result["diff_review"]["records"]
    if expected["diff_review"]:
        actual = [(item["path"], item["change"]) for item in diff]
        wanted = [(item["path"], item["status"]) for item in context["patch_binding"]["changed_files"]]
        if sorted(actual) != sorted(wanted):
            raise ValueError("diff review must account for every exact changed and deleted path once")
    for item in [*fix, *result["patch_risk"]["records"], *diff]:
        if item["patch_sha256"] != context["patch_binding"]["sha256"]:
            raise ValueError("assessment is bound to another patch")
    closures = []
    for name in ("verify_fix", "patch_risk", "hardening", "diff_review"):
        if retained is not None and name in {"verify_fix", "patch_risk", "diff_review"}:
            if result[name] != retained[name]:
                raise ValueError("handoff differs from accepted investigation patch assessment")
            closures.extend(row for row in retained.get("non_promoted", [])
                            if row["id"].startswith(name + "/"))
            continue
        for index, item in enumerate(result[name]["records"]):
            owner = f"{name}/records/{index}"
            for row in item.get("evidence_quality", {}).get("diagnostics", []):
                if row["owner"] != owner or row["affected_item_ids"] != [owner]:
                    raise ValueError("action evidence diagnostic belongs to another assessment")
            issues = list(item.get("evidence_quality", {}).get("diagnostics", []))

            def limited(code, field, disposition="evidence_limited"):
                row = diagnostic(code, owner, field, [owner], disposition)
                if row not in issues:
                    issues.append(row)

            unavailable = set()
            if name in {"verify_fix", "hardening"}:
                accepted, _, source_id = selected_findings(
                    context, tracking=name == "hardening", unavailable_cohorts=unavailable)
                if item["finding_execution_id"] != source_id:
                    raise ValueError("assessment does not select an accepted finding in its bound source")
                selected = [item["finding_id"]] if name == "verify_fix" else item.get("finding_ids", item.get("reviewed_finding_ids", []))
                if not set(selected) <= accepted.keys():
                    if name != "verify_fix" and not unavailable:
                        raise ValueError("assessment must link exact accepted finding transitions")
                    limited("missing_record", "finding_id" if name == "verify_fix" else "finding_ids")
                if name == "hardening" and "reviewed_finding_ids" in item:
                    if len(result[name]["records"]) != 1 or set(accepted) - set(selected) or (not unavailable and sorted(selected) != sorted(accepted)):
                        raise ValueError("no-opportunity hardening must account for the exact complete accepted set")
                    if unavailable:
                        limited("missing_record", "reviewed_finding_ids")
                elif name == "hardening" and (not selected or not item["attack_transitions"] or not item["tradeoffs"]):
                    raise ValueError("hardening proposal requires concrete attack transitions and engineering tradeoffs")

            # Every citation is inspected, including siblings of a bad citation:
            # an unsafe path or changed source hash is never hidden by a local issue.
            citations, valid, failures = {}, {}, {}
            for field in ("citations", "affected_consumers"):
                for number, citation in enumerate(item.get(field, [])):
                    key = f"{field}[{number}]"
                    citations[key] = citation
                    try:
                        validate_citations(context, [citation], portable=portable)
                        valid[key] = citation
                    except EvidenceIssue as exc:
                        failures[key] = exc.code
            optional = {}
            for support in item.get("optional_support", []):
                key = support["reference"]
                if (key in optional or key not in citations or key in support["independent_support"]
                        or not support["obligation"].strip() or not support["rationale"].strip()
                        or any(ref not in citations for ref in support["independent_support"])):
                    raise ValueError("optional action support requires a unique owned citation and independent proof rationale")
                optional[key] = support
            for field, code in failures.items():
                support = optional.get(field)
                sufficient = support is not None and all(ref in valid for ref in support["independent_support"])
                limited(code, field, "optional" if sufficient else "evidence_limited")
            proof = [citation for field, citation in valid.items() if field.startswith("citations[")]
            consumers = [citation for field, citation in valid.items() if field.startswith("affected_consumers[")]
            if not proof and not (name == "hardening" and "reviewed_finding_ids" in item):
                limited("missing_record", "citations")
            if name == "verify_fix" and {c["view"] for c in proof} != {"base", "derived"}:
                limited("missing_record", "citations.source_views")
            if name == "patch_risk" and not any(c["view"] == "derived" for c in proof):
                limited("missing_record", "citations.derived")
            if name == "diff_review":
                needed = "base" if item["change"] == "deleted" else "derived"
                if not any(c["path"] == item["path"] and c["view"] == needed for c in proof):
                    limited("missing_record", "citations.changed_path")
                if item["assessment"] == "deleted_control" and not any(c["view"] == "derived" for c in consumers):
                    limited("missing_record", "affected_consumers")
            for check in item.get("checks", []):
                if check["status"] == "executed":
                    validate_executed_check(context, check)
                elif check["experiment_ref"] is not None:
                    raise ValueError("unrun check cannot claim an experiment receipt")
            unresolved = any(row["disposition"] == "evidence_limited" for row in issues)
            # Retained canonical unresolved outcomes cannot become positive merely
            # because their source happens to be readable on a later attempt.
            unresolved = unresolved or item.get("assessment_status") == "locally_unresolved"
            if unresolved:
                if name == "verify_fix":
                    item["outcome"] = "inconclusive"
                    for field in ("original_path", "alternate_routes", "legitimate_behavior"):
                        item[field] = "unresolved"
                elif name == "patch_risk":
                    item.update(likelihood="unknown", confidence="low")
                elif name == "hardening":
                    item["outcome"] = "unresolved"
                else:
                    item["assessment"] = "unresolved"
                closures.append({
                    "id": owner,
                    "input_refs": [("investigation/actions.json#/" if investigation else "handoff/actions.json#/") + owner],
                    "disposition": "evidence_limited",
                    "reason": "Selected assessment lacks independently usable essential evidence.",
                    "risk_context": "This selected action is unresolved, not fix or merge approval.",
                    "missing_fact": "The source or selected finding obligation identified by evidence_quality is unavailable.",
                    "next_action": "The owning analyst may inspect the missing fact if valuable within existing authority; unrelated selected actions continue.",
                    "review": None, "deferral": None})
            elif name == "verify_fix":
                if item["outcome"] == "fixed" and any(item[field] != "established" for field in ("original_path", "alternate_routes", "legitimate_behavior")):
                    raise ValueError("fixed requires original, alternate-route and legitimate-behavior proof")
                if item["outcome"] == "still_vulnerable" and item["original_path"] != "contradicted" and item["alternate_routes"] != "contradicted":
                    raise ValueError("still vulnerable requires a source-established remaining exploit route")
            item["assessment_status"] = "locally_unresolved" if unresolved else "supported"
            item["evidence_quality"] = summarize(issues)
    if result["tracking"]["records"] != (tracking_records(context) if expected["tracking"] else []):
        raise ValueError("offline tracking differs from deterministic selected finding projection")
    for item in result["unconfirmed_followups"]:
        validate_citations(context, item["citations"], portable=portable)
    result["non_promoted"] = closures
    core().validate_schema(result, "advantage-action.schema.json")
    return result


def validate_actions(context: dict, document: dict, *, investigation: bool = False) -> None:
    assessed = assess_actions(context, document, investigation=investigation)
    # Historical documents without quality metadata remain untouched. New
    # canonical handoffs must expose the exact locally unresolved partition.
    if "non_promoted" in document and assessed != document:
        raise ValueError("action evidence accounting differs from canonical assessment")


def validate_executed_check(context: dict, check: dict) -> None:
    from investigation_experiments import load, validate_result
    if not isinstance(check["experiment_ref"], str):
        raise ValueError("executed check requires an actual experiment result reference")
    base = Path(context["scan_base"])
    path = core().inside(base, base / safe_relative(check["experiment_ref"]))
    result = load(path)
    request_path = core().inside(base, base / safe_relative(result["request_ref"]))
    request = load(request_path)
    scope = validate_result(context, request, result, request_path)
    if scope != "current" or result["status"] not in {"supported", "contradicted"} or request["source_view"] != "derived":
        raise ValueError("executed patch check lacks a current contained derived-source observation")


def tracking_records(context: dict) -> list[dict]:
    ids = context["options"].get("track_findings", [])
    if not ids:
        return []
    accepted, source, execution_id = selected_findings(context, tracking=True)
    if len(ids) != len(set(ids)):
        raise ValueError("tracking requires unique selected finding IDs")
    links = {}
    if accepted:
        rows = core().load(source / "final-verification/findings.json").get("links", [])
        if isinstance(rows, list):
            for item in rows:
                if isinstance(item, dict) and isinstance(item.get("finding_id"), str):
                    identifier = item["finding_id"]
                    links[identifier] = item if identifier not in links else {}
    records = []
    for finding_id in sorted(ids):
        record = {
            "finding_id": finding_id, "finding_execution_id": execution_id,
            "finding_ref": {"execution_id": execution_id, "artifact_ref": f"final-verification/findings.json#{finding_id}"},
            "baseline_ids": [], "assessment_scope": "historical", "publication": "offline_only",
            "disclosure_limitations": "Sanitized local handoff only; no provider contacted or ticket created."}
        finding = accepted.get(finding_id)
        if (finding is None or not isinstance(finding.get("title"), str)
                or not 1 <= len(finding["title"]) <= 1024
                or finding.get("severity") not in {"critical", "high", "medium", "low", "info", "informational",
                                                  "Critical", "High", "Medium", "Low", "Info"}):
            record.update(assessment_status="locally_unresolved",
                          limitation="The exact selected finding is unavailable as a usable accepted record; no tracking claim was published.")
        else:
            baseline_ids = links.get(finding_id, {}).get("baseline_ids", [])
            record.update(title=finding["title"], severity=finding["severity"],
                          baseline_ids=baseline_ids if isinstance(baseline_ids, list) and all(isinstance(value, str) for value in baseline_ids) else [],
                          assessment_scope="assessed" if execution_id == context["run_id"] else "historical")
        records.append(record)
    return records


def validate_investigation(context: dict) -> None:
    if context["mode"] == "actions":
        return
    if context.get("patch_binding"):
        validate_actions(context, core().load(Path(context["scan_base"]) / "investigation/actions.json"), investigation=True)


def finalize_handoff(base: Path, context: dict) -> dict:
    base = Path(base)
    core().require_active(context, "handoff")
    context["_source_receipts"] = {}
    context["_source_examples"] = {}
    document = empty_actions(context)
    draft_path = base / "handoff/action-draft.json"
    if draft_path.exists():
        document = core().load(draft_path)
    if context["mode"] != "actions" and context.get("patch_binding"):
        investigation = retained_patch_actions(context)
        if investigation is None:
            raise ValueError("handoff requires accepted investigation patch assessments")
        for name in ("verify_fix", "patch_risk", "diff_review"):
            document[name] = investigation[name]
    records = tracking_records(context)
    if records:
        document["tracking"] = {"status": "completed", "records": records}
    document = assess_actions(context, document)
    core().atomic_json(base / "handoff/actions.json", document)
    from advantage_pipeline import record_source_receipts
    record_source_receipts(context, "handoff")
    return document


def validate_phase(base: Path, phase: str, context: dict) -> None:
    if phase != "handoff":
        raise ValueError("actions validator owns handoff only")
    validate_actions(context, core().load(Path(base) / "handoff/actions.json"))


def cli(operation: str) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("--context", type=Path)
    args = parser.parse_args()
    try:
        context = core().load_context(args.context)
        if Path(context["scan_base"]).resolve() != args.base.resolve():
            raise ValueError("action CLI base differs from linked context")
        if operation == "prepare":
            binding = prepare_patch(context)
            if binding != context.get("patch_binding"):
                raise ValueError("patch preparation must match initialization binding")
            print(json.dumps(binding, sort_keys=True))
        else:
            finalize_handoff(args.base, context)
            core().finalize_phase(args.base, "handoff", context=context)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    return 2
