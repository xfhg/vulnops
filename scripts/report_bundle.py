"""Portable completed reporting products; never reconstruct runnable workflow state."""
from __future__ import annotations

import hashlib
import json
import stat
from copy import deepcopy
from pathlib import Path

from artifact_policy import artifact_size_limit, publication_content_error
from evidence_refs import _parts


def _value(scan: Path, relative: str):
    base = Path(scan).resolve()
    path = base / relative
    if path.resolve() != path or not path.is_relative_to(base):
        raise ValueError(f"unsafe artifact path: {relative}")
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"publication artifact is not a regular file: {relative}")
        limit = artifact_size_limit(Path(relative))
        if limit is not None and path.stat().st_size > limit:
            raise ValueError(f"publication artifact exceeds size bound: {relative}")
        text = path.read_text(encoding="utf-8")
        error = publication_content_error(text, size_limit=limit)
        if error:
            raise ValueError(f"{relative}: {error}")
        value = json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {relative}: {exc}") from exc
    return value


def document(scan: Path, relative: str) -> dict:
    value = _value(scan, relative)
    if not isinstance(value, dict):
        raise ValueError(f"{relative}: expected object")
    return value


def _local_reference(record: dict, run_id: str, bindings: dict) -> str | None:
    """Classify evidence ownership without rebinding inherited paths locally."""
    reference = record["artifact_ref"]
    owner = record.get("execution_id", run_id)
    if isinstance(reference, dict):
        from advantage_contract import validate_schema
        validate_schema(reference, "advantage-reference")
        if "execution_id" in record and owner != reference["execution_id"]:
            raise ValueError("publication reference has conflicting execution owners")
        owner = reference["execution_id"]
        if owner == run_id:
            raise ValueError("typed publication reference must name an inherited execution")
        reference = reference["artifact_ref"]
    relative, _ = _parts(reference)
    if owner == run_id:
        return relative
    owners = [binding for binding in (bindings.get("baseline"), bindings.get("action_source"))
              if binding and binding["execution_id"] == owner]
    if len(owners) != 1:
        raise ValueError("publication reference has unadmitted or ambiguous execution owner")
    return None


def publication_metadata(context: dict, *, execution_kind: str, producer_routes: dict | None = None) -> dict:
    """Keep selected evidence bindings, not context, phase state or retry history."""
    metadata = {
        "execution_kind": execution_kind,
        "repository": context.get("repo_name") or context.get("repository"),
        "repositories": deepcopy(context.get("repositories", [])),
        "model_routing": deepcopy(context.get("model_routing", {})),
        "producer_routes": deepcopy(producer_routes or {}),
    }
    if execution_kind == "advantage":
        for key in ("mode", "patch_binding"):
            if key in context:
                metadata[key] = deepcopy(context[key])
        metadata["options"] = {key: deepcopy(context.get("options", {}).get(key)) for key in
                               ("repository", "verify_fix", "assess_patch_risk", "hardening", "track_findings")}
        metadata["options"]["patch"] = context.get("patch_binding", {}).get("patch_ref") if context.get("patch_binding") else None
        metadata["source"] = {"source_run_id": context["source_run_id"]}
        for key in ("baseline", "action_source"):
            if context.get(key):
                metadata[key] = {name: deepcopy(value) for name, value in context[key].items() if name != "root"}
    # Exact-source authority is preserved only when it already exists. Never
    # fingerprint today's checkout to retroactively authorize an old finding.
    if context.get("target_fingerprint"):
        metadata["target_fingerprint"] = context["target_fingerprint"]
    base = Path(context["scan_base"])
    gap = base / "gap-exploration/results.json"
    if gap.is_file():
        document(base, "gap-exploration/results.json")
        metadata["gap_exploration"] = {"ref": "gap-exploration/results.json",
                                       "sha256": hashlib.sha256(gap.read_bytes()).hexdigest()}
    if producer_routes is None:
        from run_lifecycle import routing_for_artifact
        refs = set()
        if gap.is_file():
            refs.update(row["ref"] for row in document(base, "gap-exploration/results.json").get("results", []))
        final_path = base / "final-verification/findings.json"
        if final_path.is_file():
            final = document(base, "final-verification/findings.json")
            for finding in final.get("findings", []) + final.get("rejections", []):
                for row in finding.get("contributors", []) + finding.get("source_refs", []):
                    relative = _local_reference(row, context["run_id"], context)
                    if relative is not None:
                        refs.add(relative)
                if finding.get("independent_verification_ref"):
                    refs.add(finding["independent_verification_ref"])
        for relative in sorted(refs):
            _value(base, relative)
            route = (context["model_routing"] if execution_kind == "advantage" else
                     routing_for_artifact(base, relative, context.get("model_routing", {})))
            metadata["producer_routes"][relative] = deepcopy(route)
    return metadata


def publication_identity(scan: Path, *, expected_kind: str | None = None) -> dict:
    """Read recorded completion identity even when a required companion is lost."""
    base = Path(scan).resolve()
    report = document(base, "report/security-report.json")
    run_id = report.get("run_id")
    if not isinstance(report.get("summary", report.get("counts")), dict) or not isinstance(report.get("findings"), list):
        raise ValueError("report/security-report.json: missing findings or outcome counts")
    metadata = report.get("publication")
    if metadata is None:
        names = [name for name in ("run-manifest.json", "advantage-manifest.json") if (base / name).is_file()]
        if len(names) != 1:
            raise ValueError("legacy publication requires its original completed metadata")
        old = document(base, names[0])
        run_id = old.get("run_id") if "run_id" not in report else run_id
        if old.get("status") != "complete" or old.get("run_id") != run_id:
            raise ValueError("legacy publication is not its completed execution")
        metadata = {key: deepcopy(old[key]) for key in
                    ("repository", "repositories", "model_routing", "mode", "options", "patch_binding", "target_fingerprint", "baseline", "action_source")
                    if key in old}
        metadata["execution_kind"] = "advantage" if names[0] == "advantage-manifest.json" else "audit"
        metadata["producer_routes"] = {}
        metadata["source"] = {key: deepcopy(old[key]) for key in
                              ("source_run_id", "source_scan", "source_repository", "finding_source") if key in old}
    else:
        from dossier_contract import validate_publication_schema
        validate_publication_schema(metadata, "publication-metadata.schema.json")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("report/security-report.json: missing execution identity")
    if not isinstance(metadata, dict) or metadata.get("execution_kind") not in {"audit", "advantage"}:
        raise ValueError("report publication has invalid execution kind")
    if expected_kind and metadata["execution_kind"] != expected_kind:
        raise ValueError(f"completed {expected_kind} publication required")
    if not isinstance(metadata.get("repository"), str) or not metadata["repository"]:
        raise ValueError("report publication has no repository identity")
    for key, kind in (("repositories", list), ("model_routing", dict), ("producer_routes", dict)):
        if key in metadata and not isinstance(metadata[key], kind):
            raise ValueError(f"report publication has invalid {key}")
    if report.get("execution_kind", metadata["execution_kind"]) != metadata["execution_kind"]:
        raise ValueError("report and publication execution kinds differ")
    return {**deepcopy(metadata), "report": report, "run_id": run_id, "scan_base": str(base)}


def read_publication(scan: Path, *, expected_kind: str | None = None, validate_evidence: bool = False) -> dict:
    identity = publication_identity(scan, expected_kind=expected_kind)
    base, report = Path(identity["scan_base"]), identity["report"]
    run_id = identity["run_id"]
    metadata = {key: value for key, value in identity.items() if key not in {"report", "run_id", "scan_base"}}
    markdown = base / "report/security-report.md"
    if markdown.resolve() != markdown or not stat.S_ISREG(markdown.stat().st_mode):
        raise ValueError("unsafe Markdown publication")
    try:
        error = publication_content_error(markdown.read_text(encoding="utf-8"), size_limit=None)
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read report/security-report.md: {exc}") from exc
    if error:
        raise ValueError(error)
    if validate_evidence and report.get("publication"):
        expected = metadata.get("markdown_sha256")
        if not expected or hashlib.sha256(markdown.read_bytes()).hexdigest() != expected:
            raise ValueError("Markdown differs from its committed publication")
    final = None
    if metadata.get("mode") != "actions":
        final = document(base, "final-verification/findings.json")
        if final.get("run_id", run_id) != run_id or not isinstance(final.get("findings"), list):
            raise ValueError("canonical final authority has invalid execution or findings")
        if report.get("publication") and final.get("findings") != report["findings"]:
            raise ValueError("report findings differ from canonical final authority")
        strict = validate_evidence and bool(report.get("publication"))
        if strict and metadata["execution_kind"] == "advantage":
            from advantage_pipeline import validate_accepted_findings
            validate_accepted_findings({"run_id": run_id, "execution_kind": "advantage",
                                        "scan_base": str(base)}, final)
        # Dossier identity and typed contributor/reviewer fields remain unchanged.
        from dossier_contract import dossier_hash, validate_publication_schema
        for finding in final["findings"] if strict else []:
            if not isinstance(finding, dict) or not isinstance(finding.get("id"), str):
                raise ValueError("canonical finding lacks identity")
            ref = finding.get("independent_verification_ref")
            if ref != f"final-verification/results/{finding['id']}.json":
                raise ValueError("finding lacks its canonical independent review")
            review = document(base, ref)
            if metadata["execution_kind"] == "audit":
                validate_publication_schema(finding, "final-findings.schema.json", "finding")
                validate_publication_schema(review, "independent-verification-result.schema.json")
            expected_status = "needs_environment" if finding.get("verdict") == "needs_environment" else "confirmed"
            reviewed_status = "confirmed" if review.get("status") in {"verified", "corrected"} else review.get("status")
            if reviewed_status != expected_status:
                raise ValueError("independent review disposition differs from accepted finding")
            if report.get("publication"):
                route = metadata.get("producer_routes", {}).get(ref, {})
                if route.get("agents", {}).get(review.get("actor")) != review.get("model") or not review.get("model"):
                    raise ValueError("independent review differs from published producing route")
                for contributor in finding.get("contributors", []):
                    source_ref = _local_reference(contributor, run_id, metadata)
                    if source_ref is None:
                        continue
                    route = metadata.get("producer_routes", {}).get(source_ref, {})
                    if route.get("agents", {}).get(contributor["actor"]) != contributor["selector"]:
                        raise ValueError("contributor differs from published producing route")
            if review.get("finding_id") != finding["id"] or review.get("dossier_review", {}).get("dossier_sha256") != dossier_hash(finding):
                raise ValueError("independent review differs from accepted dossier")
            for source in finding.get("source_refs", []):
                reference = _local_reference(source, run_id, metadata)
                if reference is not None:
                    _value(base, reference)
    if validate_evidence and metadata.get("publication_method") == "retained_evidence":
        from advantage_publication import validate_published
        validate_published(base, report)
    return {**deepcopy(metadata), "report": report, "final": final,
            "run_id": run_id, "scan_base": str(base),
            "assessment": deepcopy(report.get("assessment", {}))}


def retire_controls(base: Path, run_id: str) -> None:
    """Retire completed ordinary controls only after validating portable authority."""
    bundle = read_publication(base, expected_kind="audit", validate_evidence=True)
    if bundle["run_id"] != run_id or "publication" not in bundle["report"]:
        raise ValueError("control retirement requires the new owning publication")
    for relative in ("run-manifest.json", "task-ledger.json"):
        path = Path(base) / relative
        if path.is_symlink():
            raise ValueError("unsafe completed execution control")
        path.unlink(missing_ok=True)
