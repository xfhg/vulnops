#!/usr/bin/env python3
"""Read-only available canonical baseline admission and typed record cataloguing."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from artifact_policy import artifact_size_limit, contains_raw_secret
from evidence_refs import EvidenceIssue, RECORD_COLLECTIONS
from evidence_accounting import diagnostic, summarize
from run_lifecycle import AUDIT_PHASE_DIRS as PHASE_DIRS
from advantage_contract import (ROOT, PHASES, component, envelope, inside, load, load_value,
                                validate_schema)

# Canonical collections include records not exposed by the capped report projection.
COLLECTIONS = frozenset({key for values in RECORD_COLLECTIONS.values() for key in values} | {
    "findings", "rejections", "deferred", "deferred_findings", "unresolved", "unresolved_candidates",
    "candidates", "cell_results", "rabbit_holes", "model_amendments", "observations", "primitive_updates",
    "objective_assessments", "question_resolutions", "objective_outcomes", "question_outcomes",
    "capabilities", "experiments", "requests", "limitations", "records", "relations", "relationships",
    "positive_patterns", "hardening_notes", "accepted", "rejected", "outcomes", "conclusions",
    "results", "tasks", "questions", "objectives", "evidence", "evidence_records", "accounting",
    "non_promoted", "input_claims", "diagnostics", "scanner_accounting", "question_dispositions",
    "evidence_dispositions", "wishlist_items", "reproduction_results", "graph_receipts",
})
IDENTIFIERS = ("id", "finding_id", "candidate_id", "campaign_id", "cell_id", "evidence_id", "experiment_id", "task_id", "code", "question_id", "objective_id")

# These collections define records. Other cohorts (for example question outcomes
# and input claims) refer to records and may legitimately repeat an upstream ID.
# Their catalog identity is the exact file/pointer, not the referenced ID.
OWNED_ID_COLLECTIONS = frozenset({
    "projects", "actors", "entry_points", "trust_boundaries", "attack_paths", "assets",
    "entrypoints", "subsystems", "threats", "hunt_mappings", "attack_classes",
    "attack_objectives", "investigation_questions", "cells", "tasks", "items",
    "records", "primitives", "campaigns", "advisories", "candidates", "findings",
    "rejections", "non_promoted", "unreviewed", "objectives", "questions",
})


def current_inventory(source: Path, application: str) -> dict:
    """Discover today's navigation inventory without fingerprinting source bytes."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/target-inventory.py"), str(source),
         "--application-name", application], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ValueError("cannot discover current repository inventory: " + result.stderr.strip())
    inventory = json.loads(result.stdout)
    inventory.pop("repository_set_sha256", None)
    return inventory


def validate_source_audit(scan: Path, run: dict, source: Path | None = None) -> None:
    """Read essential historical inputs; completion is not a snapshot attestation."""
    from run_lifecycle import run_status
    if "report" not in run and run_status(run.get("status")) != "complete":
        raise ValueError("source must be a completed audit")
    if run.get("execution_kind", "audit") != "audit":
        raise ValueError("Advantage cannot be an investigation baseline")
    if not isinstance(run.get("run_id"), str):
        raise ValueError("source publication: missing run_id")
    component(run["run_id"])
    if not isinstance(run.get("repository"), str) or not run["repository"]:
        raise ValueError("source publication: missing repository")


def _limitation(diagnostics, unavailable_cohorts, relative, code, pointer=""):
    """Retain locations, never parser input or invented historical identities."""
    cohort = relative + ("#" + pointer if pointer else "")
    if diagnostics is not None:
        diagnostics.append(diagnostic(code, relative, pointer or "artifact", []))
    if unavailable_cohorts is not None:
        unavailable_cohorts.add(cohort)


def _historical_value(scan, relative, diagnostics=None, unavailable_cohorts=None):
    path = inside(scan, relative)
    try:
        if not path.exists():
            raise EvidenceIssue("missing_file", "optional historical artifact unavailable")
        value = load_value(path)
        if not isinstance(value, (dict, list)):
            raise EvidenceIssue("unreadable_content", "historical artifact has no record envelope")
        return value
    except EvidenceIssue as exc:
        _limitation(diagnostics, unavailable_cohorts, relative, exc.code)
        return None


def _usable_identifier(value):
    if not isinstance(value, str):
        return False
    try:
        component(value)
    except ValueError:
        return False
    return True


def _usable_finding(row):
    """Require readable historical identity/attribution, not current proof replay."""
    def text(value):
        return isinstance(value, str) and bool(value.strip())

    if (row.get("finding_kind") not in ("code", "dependency", "secret", "chain")
            or row.get("severity") not in ("critical", "high", "medium", "low", "informational", "info")
            or not all(text(row.get(key)) for key in ("title", "impact"))):
        return False
    contributors = row.get("contributors")
    if (not isinstance(contributors, list) or not contributors
            or not all(isinstance(author, dict) and
                       all(text(author.get(key)) for key in ("actor", "selector", "artifact_ref"))
                       and ("execution_id" not in author or text(author["execution_id"]))
                       for author in contributors)):
        return False
    if row["finding_kind"] == "chain":
        steps = row.get("primitive_steps")
        return (isinstance(steps, list) and bool(steps)
                and all(isinstance(step, dict) and text(step.get("primitive_id")) for step in steps)
                and len({step["primitive_id"] for step in steps}) == len(steps))
    roots = row.get("root_causes")
    return (isinstance(roots, list) and bool(roots)
            and all(isinstance(root, dict) and text(root.get("file")) and text(root.get("scope"))
                    and type(root.get("line")) is int and root["line"] > 0 for root in roots))


def _unique_rows(rows, relative, pointer, diagnostics=None, unavailable_cohorts=None,
                 *, keys=IDENTIFIERS):
    """Exclude every member of an ambiguous group without choosing a winner."""
    groups = {}
    for index, row in enumerate(rows):
        location = pointer + "/" + str(index)
        identifier = next((row[key] for key in keys if key in row), None) if isinstance(row, dict) else None
        if (not _usable_identifier(identifier) or
                relative == "final-verification/findings.json" and pointer == "/findings"
                and not re.fullmatch(r"F-[0-9]{3}", identifier)):
            code = "missing_record" if identifier is None else "unreadable_content"
            _limitation(diagnostics, unavailable_cohorts, relative, code, location)
            continue
        groups.setdefault(identifier, []).append((location, row))
    usable = {}
    for identifier, matches in groups.items():
        if len(matches) != 1:
            for location, _ in matches:
                _limitation(diagnostics, unavailable_cohorts, relative, "ambiguous_record", location)
        else:
            location, row = matches[0]
            if (relative == "final-verification/findings.json" and pointer == "/findings"
                    and (row.get("verdict"), row.get("status")) in {
                        ("confirmed", "verified"), ("needs_environment", "needs_environment")}
                    and not _usable_finding(row)):
                _limitation(diagnostics, unavailable_cohorts, relative, "unreadable_content", location)
            else:
                usable[location] = (identifier, row)
    return usable


def canonical_inventory(scan: Path, *, advantage: bool = False, diagnostics=None,
                        unavailable_cohorts=None) -> list[dict]:
    """Catalog available canonical evidence, never old caches or directory seals."""
    scan = inside(scan.parent, scan)
    dirs = {phase: phase for phase in PHASES} if advantage else PHASE_DIRS
    paths = []
    for directory in dirs.values():
        root = inside(scan, directory)
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            path = inside(scan, path)
            if path.is_dir():
                continue
            if not path.is_file() or any(part.startswith(".") for part in path.relative_to(scan).parts):
                raise ValueError("noncanonical entry in source phase bundle: " + str(path))
            paths.append(path)
    rows = []
    for path in sorted(paths):
        path = inside(scan, path)
        relative = path.relative_to(scan).as_posix()
        limit = artifact_size_limit(Path(relative))
        if limit is not None and path.stat().st_size > limit:
            raise ValueError("source artifact exceeds publication bound: " + relative)
        if path.suffix == ".json":
            if _historical_value(scan, relative, diagnostics, unavailable_cohorts) is None:
                continue
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeError:
                if contains_raw_secret(path.read_bytes().decode("utf-8", errors="replace")):
                    raise ValueError("source artifact contains possible raw secret")
                _limitation(diagnostics, unavailable_cohorts, relative, "unreadable_content")
                continue
            if contains_raw_secret(text):
                raise ValueError("source artifact contains possible raw secret: " + relative)
        rows.append({"artifact_ref": relative})
    return rows


def catalog_records(scan: Path, execution_id: str, files: list[dict], *,
                    diagnostics=None, unavailable_cohorts=None) -> tuple[list[dict], dict]:
    component(execution_id)
    records, counts = [], {}
    for file in files:
        relative = file["artifact_ref"]
        if not relative.endswith(".json") or relative.startswith("report/") or relative in {"run-manifest.json", "task-ledger.json"} or relative.endswith("phase-manifest.json"):
            continue
        document = _historical_value(scan, relative, diagnostics, unavailable_cohorts)
        if document is None:
            continue
        if isinstance(document, dict) and "run_id" in document and document["run_id"] != execution_id:
            raise ValueError("historical artifact declares another execution")
        if relative == "final-verification/findings.json" and (
                not isinstance(document, dict) or not isinstance(document.get("findings"), list)):
            _limitation(diagnostics, unavailable_cohorts, relative, "unreadable_content", "/findings")
            if not isinstance(document, dict):
                continue
        if relative == "final-verification/findings.json" and isinstance(document, dict):
            if not isinstance(document.get("unreviewed"), list):
                _limitation(diagnostics, unavailable_cohorts, relative,
                            "unreadable_content" if "unreviewed" in document else "missing_record",
                            "/unreviewed")
        file_records = []

        def collection_rows(rows, pointer, collection):
            counts.setdefault(collection, 0)
            if collection in OWNED_ID_COLLECTIONS:
                keys = ("id",) if collection == "findings" else IDENTIFIERS
                usable = _unique_rows(rows, relative, pointer, diagnostics, unavailable_cohorts, keys=keys)
                for index, row in enumerate(rows):
                    location = pointer + "/" + str(index)
                    if location in usable:
                        visit(row, location, collection, usable[location][0])
            else:
                for index, row in enumerate(rows):
                    visit(row, pointer + "/" + str(index), collection)

        def visit(value, pointer="", collection=None, identifier=None):
            if not isinstance(value, dict):
                if collection:
                    _limitation(diagnostics, unavailable_cohorts, relative, "unreadable_content", pointer)
                return
            if collection:
                keys = ("id",) if collection == "diagnostics" else (*IDENTIFIERS, "input_ref")
                identifier = identifier or next((str(value[key]) for key in keys if isinstance(value.get(key), (str, int)) and str(value[key])), pointer or relative)
                disposition_fields = (("disposition", "status", "verdict", "outcome")
                                      if collection == "unreviewed" else
                                      ("verdict", "status", "outcome", "disposition", "evidence_status", "trust")
                                      if collection == "findings" else
                                      ("status", "verdict", "outcome", "disposition", "evidence_status", "trust"))
                status = next((value[key] for key in disposition_fields if isinstance(value.get(key), str)), "unspecified")
                if not status or len(status) > 4096 or len(identifier) > 4096:
                    _limitation(diagnostics, unavailable_cohorts, relative, "unreadable_content", pointer)
                else:
                    ref = relative + "#" + pointer if pointer else relative
                    file_records.append({"id": identifier, "record_type": collection, "status": status,
                                         "reference": {"execution_id": execution_id, "artifact_ref": ref},
                                         "pointer": pointer})
            for key, child in value.items():
                child_pointer = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
                if key in COLLECTIONS and isinstance(child, list):
                    # These names denote prose/references inside records, not
                    # another collection of owned definitions.
                    if pointer and key in {"entrypoints", "subsystems", "limitations"}:
                        continue
                    if key == "limitations" and relative.startswith("gap-exploration/"):
                        continue
                    collection_rows(child, child_pointer, key)
                elif isinstance(child, dict):
                    visit(child, child_pointer, key if key == "non_promoted" else None)
            # Unregistered extension arrays are inert, not additional authority.

        if isinstance(document, list):
            collection = {"verified-findings.json": "findings", "rejected-findings.json": "rejections"}.get(
                Path(relative).name, Path(relative).stem.replace("-", "_"))
            collection_rows(document, "", collection)
        else:
            root_collection = ("experiments" if "/experiments/" in relative else
                               "reproduction_results" if "/reproduction/" in relative else
                               "campaign_results" if relative.startswith("intrusion/results/") else
                               "hunt_results" if relative.startswith("sast/deepdive/") else None)
            visit(document, collection=root_collection)
        for row in file_records:
            records.append(row)
            counts[row["record_type"]] = counts.get(row["record_type"], 0) + 1
    return records, dict(sorted(counts.items()))


def build_catalog(context: dict, scan: Path) -> dict:
    from report_bundle import read_publication
    report = _historical_value(scan, "report/security-report.json")
    run = (read_publication(scan, expected_kind="audit") if isinstance(report, dict) and report.get("publication")
           else load(scan / "run-manifest.json"))
    validate_source_audit(scan, run)
    if context.get("source_run_id", run["run_id"]) != run["run_id"]:
        raise ValueError("baseline source belongs to another execution")
    diagnostics, unavailable = [], set()
    files = canonical_inventory(scan, diagnostics=diagnostics, unavailable_cohorts=unavailable)
    records, counts = catalog_records(scan, run["run_id"], files,
                                     diagnostics=diagnostics, unavailable_cohorts=unavailable)
    available = {row["artifact_ref"] for row in files}
    for ref in ("report/security-report.json", "final-verification/findings.json"):
        if ref not in available and ref not in unavailable:
            _limitation(diagnostics, unavailable, ref, "missing_file")
    report = (_historical_value(scan, "report/security-report.json")
              if "report/security-report.json" in available else None)
    if isinstance(report, dict) and report.get("run_id", run["run_id"]) != run["run_id"]:
        raise ValueError("historical report declares another execution")
    assessment = report.get("assessment") if isinstance(report, dict) else None
    if not isinstance(assessment, dict) or not isinstance(assessment.get("scopes"), list):
        from run_lifecycle import report_assessment
        assessment = report_assessment(run, list(effective_findings(
            scan, expected_execution_id=run["run_id"]).values()))
    repositories = {}
    for scope in assessment["scopes"]:
        if scope.get("run_id") not in {None, run["run_id"]}:
            raise ValueError("baseline assessment scope belongs to another execution")
        for repository in scope.get("repositories") or []:
            repositories[json.dumps(repository, sort_keys=True)] = repository
    # Only an original legacy report can supply missing legacy metadata; an
    # operational resume's inventory is never substituted for assessed scope.
    if not repositories and not run.get("attempt_contexts") and not run.get("attempt_id"):
        for repository in (report.get("repositories", []) if isinstance(report, dict) else []):
            repositories[json.dumps(repository, sort_keys=True)] = repository
    quality = summarize(diagnostics)
    limitations = [{"artifact_ref": row["owner"], "reason": row["explanation"],
                    "code": row["code"], "field": row["field"], "count": row["count"]}
                   for row in quality["diagnostics"]]
    catalog = envelope(context, source_run_id=run["run_id"], repositories=list(repositories.values()),
                       files=files, records=records, counts=counts, limitations=limitations,
                       counts_complete=not unavailable, unavailable_cohorts=sorted(unavailable),
                       evidence_quality=quality, file_count=len(files), record_count=len(records))
    validate_schema(catalog, "advantage-baseline")
    return catalog


def validate_baseline(base: Path, context: dict) -> None:
    binding = context["baseline"]
    if binding["catalog_ref"] != "baseline/catalog.json":
        raise ValueError("baseline catalog location differs from canonical path")
    catalog = load(inside(base, binding["catalog_ref"]))
    validate_schema(catalog, "advantage-baseline")
    if (catalog["run_id"] != context["run_id"] or
            catalog["source_run_id"] != context["source_run_id"] or
            binding["execution_id"] != context["source_run_id"]):
        raise ValueError("baseline catalog belongs to another execution")


def effective_findings(scan: Path, *, expected_execution_id=None, diagnostics=None,
                       unavailable_cohorts=None) -> dict[str, dict]:
    """Read all original final dispositions, never a report's historical display filter."""
    relative = "final-verification/findings.json"
    document = _historical_value(scan, relative, diagnostics, unavailable_cohorts)
    if document is None:
        return {}
    if (expected_execution_id is not None and isinstance(document, dict)
            and "run_id" in document and document["run_id"] != expected_execution_id):
        raise ValueError("historical findings declare another execution")
    rows = document.get("findings") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        _limitation(diagnostics, unavailable_cohorts, relative, "unreadable_content", "/findings")
        return {}
    usable = _unique_rows(rows, relative, "/findings", diagnostics, unavailable_cohorts, keys=("id",))
    return {identifier: row for identifier, row in usable.values()}


def accepted_findings(scan: Path, *, expected_execution_id=None, diagnostics=None,
                      unavailable_cohorts=None) -> dict[str, dict]:
    """Select confirmed intelligence without granting later-source applicability."""
    return {identifier: row for identifier, row in effective_findings(
        scan, expected_execution_id=expected_execution_id, diagnostics=diagnostics,
        unavailable_cohorts=unavailable_cohorts).items()
        if row.get("verdict") == "confirmed" and row.get("status") == "verified"}


def admit_action_source(scan: Path, context: dict) -> dict:
    from report_bundle import read_publication
    manifest = read_publication(scan, expected_kind="advantage")
    if manifest["mode"] == "actions":
        raise ValueError("action source must be a completed non-actions Advantage execution")
    if manifest.get("source", {}).get("source_run_id") != context["source_run_id"]:
        raise ValueError("action source belongs to a different audit baseline")
    selected = sorted(set(context["options"]["verify_fix"] + context["options"]["track_findings"]))
    for identifier in selected:
        component(identifier)
    if selected:
        unavailable = set()
        accepted = accepted_findings(scan, expected_execution_id=manifest["run_id"],
                                     unavailable_cohorts=unavailable)
        missing = set(selected) - accepted.keys()
        if missing:
            known = effective_findings(scan, expected_execution_id=manifest["run_id"])
            rejected = missing & known.keys()
            if rejected:
                raise ValueError("action selection is not accepted in final-verification/findings.json: "
                                 + ", ".join(sorted(rejected)))
        if missing and unavailable:
            raise ValueError("action selection prerequisite: readable canonical accepted-finding authority "
                             "required at final-verification/findings.json for " + ", ".join(sorted(missing)))
        if missing:
            raise ValueError("action selection is not accepted in final-verification/findings.json: "
                             + ", ".join(sorted(missing)))
    return {"execution_id": manifest["run_id"], "root": str(scan),
            "files": canonical_inventory(scan, advantage=True),
            "selected_findings": [{"id": identifier} for identifier in selected]}


def validate_action_source_binding(base: Path, context: dict, *, portable: bool = False) -> None:
    from report_bundle import publication_identity
    binding = context["action_source"]
    if context["mode"] != "actions" or not binding:
        raise ValueError("action source may only be bound by actions mode")
    scan = inside(Path(binding["root"]).parent, Path(binding["root"]))
    source = publication_identity(scan, expected_kind="advantage")
    if (source["run_id"] != binding["execution_id"]
            or source["mode"] == "actions" or source.get("source", {}).get("source_run_id") != context["source_run_id"]):
        raise ValueError("invalid or recursive action finding source")
    selected = sorted(set(context["options"]["verify_fix"] + context["options"]["track_findings"]))
    for identifier in selected:
        component(identifier)
    if binding["selected_findings"] != [{"id": identifier} for identifier in selected]:
        raise ValueError("selected action findings differ from their execution binding")
