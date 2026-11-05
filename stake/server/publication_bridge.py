#!/usr/bin/env python3
"""Read-only protocol for Stake. Never initialize or publish audit artifacts."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

sys.dont_write_bytecode = True
HARNESS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HARNESS / "scripts"))


class ReadFailure(Exception):
    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(message)


def safe_text(base: Path, relative: str):
    from artifact_policy import artifact_size_limit, publication_content_error
    from evidence_refs import _parts
    name, _ = _parts(relative)
    limit = artifact_size_limit(Path(relative))
    # Walk using directory descriptors rather than check-then-open paths. This
    # prevents an intermediate directory being swapped for an escaping symlink.
    directories = [*base.parts[1:], *PurePosixPath(name).parts[:-1]]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(base.anchor, flags)
    try:
        for part in directories:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(PurePosixPath(name).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        raise ReadFailure("unavailable", "Referenced artifact was not delivered.") from None
    except OSError:
        raise ReadFailure("denied", "Artifact path is not an admitted regular file.") from None
    finally:
        os.close(directory)
    with os.fdopen(descriptor, encoding="utf-8") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ReadFailure("denied", "Artifact is not a regular file.")
        if limit is not None and info.st_size > limit:
            raise ReadFailure("denied", "Artifact exceeds its publication size limit.")
        text = handle.read()
    if publication_content_error(text, size_limit=limit):
        raise ReadFailure("denied", "Artifact fails publication hygiene.")
    return text


def json_value(base: Path, relative: str):
    from artifact_policy import artifact_size_limit, publication_content_error
    value = json.loads(safe_text(base, relative))
    if publication_content_error(value, size_limit=artifact_size_limit(Path(relative))):
        raise ReadFailure("denied", "Artifact fails publication hygiene.")
    return value


def admit(root: str):
    from report_bundle import read_publication
    from artifact_policy import publication_content_error
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ReadFailure("invalid_input", "The supplied input is not a run directory.")
    def required(relative, reader):
        try:
            return reader(base, relative)
        except ReadFailure as exc:
            raise ReadFailure(exc.code, relative + ": " + exc.message) from None
        except (UnicodeError, json.JSONDecodeError):
            raise ReadFailure("invalid_content", relative + ": invalid UTF-8 JSON/text.") from None

    report = required("report/security-report.json", json_value)
    if not isinstance(report, dict) or report.get("schema_version") != "2.0":
        raise ReadFailure("unsupported", "Expected a supported schema 2.0 publication.")
    if report.get("mode", report.get("publication", {}).get("mode")) == "actions":
        raise ReadFailure("unsupported", "Actions-only Advantage reports are not supported in this release.")
    markdown = required("report/security-report.md", safe_text)
    final = required("final-verification/findings.json", json_value)
    if not isinstance(final, dict) or not isinstance(final.get("findings"), list):
        raise ReadFailure("invalid_authority", "final-verification/findings.json lacks canonical findings.")
    if final["findings"] != report.get("findings"):
        raise ReadFailure("invalid_authority", "report/security-report.json findings differ from final-verification/findings.json.")
    # This is structural consumption of an existing publication, not replay of
    # independent reviews or validation against the current source checkout.
    try:
        bundle = read_publication(base, validate_evidence=False)
    except (ValueError, OSError, KeyError, TypeError):
        raise ReadFailure("invalid_publication", "Publication identity, companion ownership, or structure is invalid.") from None
    # The files are checked again against the captured values to avoid accepting
    # mixed versions if an operator changes a bundle while it is being loaded.
    if bundle["report"] != report or bundle["final"] != final:
        raise ReadFailure("changed_input", "Publication changed during import; load it again after writes have finished.")
    if publication_content_error(bundle, size_limit=None):
        raise ReadFailure("denied", "Publication metadata fails publication hygiene.")
    return {**bundle, "markdown": markdown}


def select_value(value, reference: str):
    """Resolve a selector against captured bytes using declared harness collections."""
    import re
    from evidence_refs import _parts, RECORD_COLLECTIONS, EvidenceIssue
    from advantage_contract import resolve_pointer
    relative, identifier = _parts(reference)
    if identifier.startswith("/") and "#" in reference:
        return resolve_pointer(value, identifier)
    if not identifier:
        if ":" in reference or "#" in reference:
            raise EvidenceIssue("unsupported_selector", "empty selector")
        return value
    if ":" in identifier or "#" in identifier:
        raise EvidenceIssue("unsupported_selector", "noncanonical selector")
    collections = RECORD_COLLECTIONS.get(PurePosixPath(relative).name, ())
    if relative.startswith("sast/deepdive/"):
        collections = ("candidates", "cell_results", "rabbit_holes", "attack_objectives", "investigation_questions", "model_amendments")
    elif relative.startswith("repo-context/research/"):
        collections = ("observations", "attack_paths")
    elif relative.startswith("intrusion/results/") or re.fullmatch(r"investigation/passes/[^/]+/results/[^/]+\.json", relative):
        collections = ("candidates", "primitive_updates")
    elif relative.startswith("gap-exploration/"):
        collections = ("candidates", "objectives", "questions")
    elif relative.startswith("intrusion/waves/"):
        collections = ("primitives", "attack_objectives", "investigation_questions")
    matches = []

    def visit(node, children=(), owner_keys=("id", "finding_id", "candidate_id")):
        if isinstance(node, list):
            for child in node:
                visit(child, children, owner_keys)
        elif isinstance(node, dict):
            if identifier == next((node[key] for key in owner_keys if node.get(key)), None):
                matches.append(node)
                return
            for key in children:
                nested = ("candidates", "primitive_updates") if key == "results" and relative.startswith("intrusion/") else ("entry_points",) if key == "projects" else ("entity",) if key == "model_amendments" else ()
                keys = ("campaign_id",) if key == "results" and relative.startswith("intrusion/") else ("cell_id",) if key == "cell_results" else ("evidence_id",) if key == "scanner_triage" else ("code",) if key == "limitations" else ("id",)
                visit(node.get(key), nested, keys)

    root_keys = ("campaign_id",) if relative.startswith("intrusion/results/") else () if collections else ("id", "finding_id", "candidate_id")
    if PurePosixPath(relative).name in {"hardening-notes.json", "positive-patterns.json"}:
        root_keys = ()
    visit(value, collections, root_keys)
    if len(matches) != 1:
        raise EvidenceIssue("missing_record" if not matches else "ambiguous_record", "selector is not unique")
    return matches[0]


def evidence(root: str, reference: str, execution_id: str):
    from evidence_refs import _parts
    base = Path(root)
    if base.resolve(strict=True) != base:
        raise ReadFailure("denied", "The admitted root was replaced with a symlink.")
    relative, selector = _parts(reference)
    allowed = {"repo-context", "tool-collection", "sast", "campaign-planning", "intrusion", "gap-exploration", "synthesis", "final-verification", "report", "baseline", "planning", "investigation", "handoff"}
    parts = PurePosixPath(relative).parts
    forbidden = {"drafts", "recovery-archives", "work", "runtime", ".harness", "raw", "raw-output", "__pycache__"}
    if parts[0] not in allowed or forbidden.intersection(parts) or parts[-1] in {"context.json", "input.json", "dispatch.json"}:
        raise ReadFailure("denied", "Reference is outside delivered canonical evidence.")
    suffix = PurePosixPath(relative).suffix
    if suffix not in {".json", ".md", ".txt"}:
        raise ReadFailure("denied", "This artifact format is not supported for evidence navigation.")
    if suffix != ".json":
        if selector or ":" in reference or "#" in reference:
            raise ReadFailure("unavailable", "Text artifacts cannot carry record selectors.")
        return {"content": safe_text(base, relative), "format": "text"}
    value = json_value(base, relative)
    if isinstance(value, dict) and "run_id" in value and value["run_id"] != execution_id:
        raise ReadFailure("denied", "Artifact belongs to a different execution.")
    return {"content": select_value(value, reference), "format": "json"}


def main():
    try:
        from report_bundle import read_publication  # noqa: F401
        from dossier_contract import validate_publication_schema  # noqa: F401
        from artifact_policy import publication_content_error  # noqa: F401
        request = json.load(sys.stdin)
        operation = request.get("operation")
        if operation == "probe":
            if not (HARNESS / "schemas/v2/publication-metadata.schema.json").is_file():
                raise ReadFailure("prerequisite", "Harness schemas are missing; run Stake alongside a complete VulnOps checkout.")
            value = {"python": list(sys.version_info[:3]), "harness": True}
        elif operation == "admit":
            value = admit(request["root"])
        elif operation == "evidence":
            value = evidence(request["root"], request["reference"], request["executionId"])
        elif operation == "select":
            value = {"content": select_value(request["value"], request["reference"]), "format": "json"}
        else:
            raise ReadFailure("invalid_request", "Unknown read operation.")
        print(json.dumps({"ok": True, "value": value}, ensure_ascii=False, allow_nan=False))
    except ReadFailure as exc:
        print(json.dumps({"ok": False, "code": exc.code, "message": exc.message}))
    except (ImportError, ModuleNotFoundError):
        print(json.dumps({"ok": False, "code": "prerequisite", "message": "Harness Python modules are unavailable; use Python 3.10+ alongside the complete VulnOps checkout."}))
    except Exception as exc:
        # Never echo exception strings: schema/path/decoder diagnostics can
        # contain the rejected report's secrets or attacker-provided material.
        code = getattr(exc, "code", "invalid_input")
        if code in {"missing_file", "missing_record", "ambiguous_record", "unsupported_selector"}:
            message = "Evidence selector is missing, ambiguous, or unsupported."
        elif isinstance(exc, FileNotFoundError):
            code, message = "unavailable", "Required input directory or artifact is unavailable."
        elif isinstance(exc, (UnicodeError, json.JSONDecodeError)):
            code, message = "invalid_content", "Artifact is not valid UTF-8 JSON/text."
        else:
            code, message = "denied", "Artifact could not be admitted safely."
        print(json.dumps({"ok": False, "code": code, "message": message}))


if __name__ == "__main__":
    main()
