"""Resolve evidence namespaces without interpreting source data as provenance."""
from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath


SCAN_NAMESPACES = frozenset({
    "repo-context", "tool-collection", "sast", "campaign-planning", "intrusion", "gap-exploration",
    "synthesis", "final-verification", "report", "run-manifest.json", "task-ledger.json",
})

# Only declared record collections are searchable; descriptive extensions are inert.
RECORD_COLLECTIONS = {
    "repo-context.json": ("projects", "actors"),
    "security-surfaces.json": ("entry_points", "trust_boundaries", "attack_paths"),
    "threat-model.json": ("assets", "trust_boundaries", "entrypoints", "subsystems", "threats", "hunt_mappings", "attack_paths", "attack_classes", "attack_objectives", "investigation_questions"),
    "hunt-plan.json": ("cells", "tasks", "attack_objectives", "investigation_questions"),
    "coverage-ledger.json": ("cells", "tasks", "attack_objectives", "investigation_questions"),
    "wishlist.json": ("items",),
    "evidence-index.json": ("records", "primitives", "attack_objectives", "investigation_questions"),
    "campaign-plan.json": ("campaigns", "attack_objectives", "investigation_questions"),
    "discovery.json": ("questions", "relationships", "scanner_triage", "attack_objectives", "investigation_questions"),
    "sca-advisories.json": ("advisories",),
    "secrets-redacted.json": ("candidates",),
    "dependency-limitations.json": ("limitations",),
    "intrusion-results.json": ("results",),
    "findings.json": ("findings", "unreviewed"),
}


def navigation_file(scan: Path, ref: str) -> Path:
    """Navigation documents are readable context, never record-level proof."""
    relative, selector = _parts(ref)
    path = (scan / relative).resolve()
    if not path.is_relative_to(scan.resolve()) or PurePosixPath(relative).parts[0] not in SCAN_NAMESPACES:
        raise ValueError("unauthorized navigation artifact")
    if path.is_relative_to((scan / "recovery-archives").resolve()):
        raise ValueError("recovery diagnostics cannot be cited as active evidence")
    if selector or ":" in ref or "#" in ref or path.suffix.lower() not in {".md", ".txt"}:
        raise EvidenceIssue("unsupported_selector", "navigation references require a whole text document")
    if not path.is_file():
        raise EvidenceIssue("missing_file", "missing navigation artifact")
    return path


class EvidenceIssue(ValueError):
    """A local evidence-quality problem, never an authorization failure."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _parts(ref: str) -> tuple[str, str]:
    if not isinstance(ref, str) or not ref or len(ref) > 4096 or any(ord(char) < 32 for char in ref):
        raise ValueError("reference must be a nonempty canonical string")
    relative, separator, selector = re.split(r"([:#])", ref, maxsplit=1) if re.search(r"[:#]", ref) else (ref, "", "")
    path = PurePosixPath(relative)
    if (not relative or relative == "." or path.is_absolute() or ".." in path.parts
            or str(path) != relative or "\\" in ref):
        raise ValueError("noncanonical evidence reference")
    return relative, selector


def artifact_value(scan: Path, ref: str):
    relative, identifier = _parts(ref)
    path = (scan / relative).resolve()
    if not path.is_relative_to(scan.resolve()):
        raise ValueError("unauthorized scan artifact")
    if (path.is_relative_to((scan / "recovery-archives").resolve())
            or path == (scan / ".recovery-invalidation.json").resolve()):
        raise ValueError("recovery diagnostics cannot be cited as active evidence")
    if not path.is_file():
        raise EvidenceIssue("missing_file", "unresolved scan artifact")
    if ((":" in ref or "#" in ref) and not identifier) or ":" in identifier or "#" in identifier:
        raise EvidenceIssue("unsupported_selector", "noncanonical evidence selector")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError):
        raise EvidenceIssue("unreadable_content", "scan artifact is not readable JSON") from None
    if not identifier:
        return value
    matches = []

    def visit(node, collections=(), owner_keys=("id", "finding_id", "candidate_id")):
        if isinstance(node, dict):
            owner_id = next((node[key] for key in owner_keys if node.get(key)), None)
            if identifier == owner_id:
                matches.append(node)
                return
            for key in collections:
                child = node.get(key)
                nested = ("candidates", "primitive_updates") if key == "results" and relative.startswith("intrusion/") else ("entry_points",) if key == "projects" else ("entity",) if key == "model_amendments" else ()
                keys = ("campaign_id",) if key == "results" and relative.startswith("intrusion/") else ("cell_id",) if key == "cell_results" else ("evidence_id",) if key == "scanner_triage" else ("code",) if key == "limitations" else ("id",)
                visit(child, nested, keys)
        elif isinstance(node, list):
            for child in node:
                visit(child, collections, owner_keys)

    collections = RECORD_COLLECTIONS.get(path.name, ())
    if relative.startswith("sast/deepdive/"):
        collections = ("candidates", "cell_results", "rabbit_holes", "attack_objectives", "investigation_questions", "model_amendments")
    elif relative.startswith("repo-context/research/"):
        collections = ("observations", "attack_paths")
    elif relative.startswith("intrusion/results/"):
        collections = ("candidates", "primitive_updates")
    elif re.fullmatch(r"investigation/passes/[^/]+/results/[^/]+\.json", relative):
        collections = ("candidates",)
    elif relative.startswith("gap-exploration/"):
        collections = ("candidates", "objectives", "questions")
    elif relative.startswith("intrusion/waves/"):
        collections = ("primitives", "attack_objectives", "investigation_questions")
    root_keys = ("campaign_id",) if relative.startswith("intrusion/results/") else () if collections else ("id", "finding_id", "candidate_id")
    if path.name in {"hardening-notes.json", "positive-patterns.json"}:
        root_keys = ()
    visit(value, collections, root_keys)
    if len(matches) != 1:
        raise EvidenceIssue("missing_record" if not matches else "ambiguous_record",
                            "artifact reference must resolve one canonical record")
    return matches[0]


def source_file(source_root: Path, repositories: list[dict], ref: str,
                line_counts: dict | None = None) -> Path:
    relative, selector = _parts(ref)
    root = source_root.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("unauthorized source file")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("authorized repository inventory is required")
    authorized = False
    for repository in repositories:
        prefix = repository.get("path") if isinstance(repository, dict) else None
        if not isinstance(prefix, str) or not prefix:
            raise ValueError("invalid authorized repository prefix")
        if prefix != ".":
            canonical, suffix = _parts(prefix)
            if suffix or canonical != prefix:
                raise ValueError("invalid authorized repository prefix")
        boundary = (root / prefix).resolve()
        if (boundary.is_relative_to(root) and path.is_relative_to(boundary)
                and (prefix == "." or PurePosixPath(relative).is_relative_to(prefix))):
            authorized = True
    if not authorized:
        raise ValueError("source file is outside the authorized repository set")
    if not path.is_file():
        raise EvidenceIssue("missing_file", "missing source file")
    if (":" in ref or "#" in ref) and not selector:
        raise EvidenceIssue("unsupported_selector", "empty source line selector")
    if selector:
        if "#" in ref:
            raise EvidenceIssue("unsupported_selector", "source selectors require a colon")
        ranges = []
        for component in selector.split(","):
            match = re.fullmatch(r"([1-9][0-9]*)(?:-([1-9][0-9]*))?", component.strip())
            if match is None or len(match[1]) > 12 or len(match[2] or "") > 12:
                raise EvidenceIssue("unsupported_selector", "invalid source line selector")
            ranges.append((int(match[1]), int(match[2] or match[1])))
        counts = line_counts if line_counts is not None else {}
        if path not in counts:
            with path.open(encoding="utf-8", errors="replace") as handle:
                counts[path] = sum(1 for _ in handle)
        if any(not 1 <= start <= end <= counts[path] for start, end in ranges):
            raise EvidenceIssue("invalid_range", "source line range is outside the file")
    return path


def validate_evidence_refs(scan: Path | None, source_root: Path, repositories: list[dict],
                           refs: list[str], *, owner: str, kind: str = "mixed",
                           line_counts: dict | None = None, historical: bool = False) -> list[str]:
    """Resolve current proof, or read historical citations without asserting applicability."""
    label = re.sub(r"[^A-Za-z0-9_./\[\]-]", "?", str(owner))[:160]
    if kind not in {"mixed", "source", "artifact"}:
        raise ValueError("unknown evidence reference contract")
    if not isinstance(refs, list):
        raise ValueError(f"{label}: evidence references must be an array")
    if not historical and (not isinstance(source_root, Path) or not source_root.is_dir() or not repositories):
        raise ValueError(f"{label}: authorized source root and repository inventory are required")
    counts = line_counts if line_counts is not None else {}
    artifacts = []
    for offset, ref in enumerate(refs):
        try:
            relative, _ = _parts(ref)
            artifact = kind == "artifact" or kind == "mixed" and PurePosixPath(relative).parts[0] in SCAN_NAMESPACES
            if kind == "mixed" and not historical:
                source_exists = (source_root / relative).is_file()
                scan_exists = scan is not None and (scan / relative).is_file()
                if not (source_root / relative).resolve().is_relative_to(source_root.resolve()):
                    raise ValueError("unauthorized source file")
                if scan is not None and not (scan / relative).resolve().is_relative_to(scan.resolve()):
                    raise ValueError("unauthorized scan artifact")
                if source_exists and (artifact or scan_exists):
                    raise EvidenceIssue("ambiguous_namespace", "ambiguous source and scan artifact reference")
                if scan_exists:
                    artifact = True
            if artifact:
                if scan is None:
                    raise ValueError("scan authority is required for artifact evidence")
                artifact_value(scan, ref)
                artifacts.append(ref)
            elif not historical:
                # Historical coordinates are preserved, never resolved through
                # today's repository membership, line ranges, or symlinks.
                source_file(source_root, repositories, ref, counts)
        except EvidenceIssue as exc:
            raise EvidenceIssue(exc.code, f"{label}[{offset}]: {exc}") from None
        except ValueError as exc:
            raise ValueError(f"{label}[{offset}]: {exc}") from None
        except (OSError, RuntimeError):
            # Filesystem errors can contain untrusted paths; report only the owner.
            raise ValueError(f"{label}[{offset}]: unreadable evidence reference") from None
    return artifacts
