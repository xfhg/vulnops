#!/usr/bin/env python3
"""Shared fail-closed helpers for linked remediation artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from model_routing import validate_routing
from artifact_policy import DEFAULT_ARTIFACT_LIMIT, artifact_size_limit, publication_content_error
from evidence_accounting import claim_reference_groups, effective_support
from evidence_refs import EvidenceIssue, SCAN_NAMESPACES, _parts, validate_evidence_refs


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_object(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} must contain an object")
    return document


def atomic_json(path: Path, document: object) -> bytes:
    limit = None if artifact_size_limit(path) is None else DEFAULT_ARTIFACT_LIMIT
    error = publication_content_error(document, size_limit=limit)
    if error:
        raise ValueError(error)
    data = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)
    return data


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def atomic_text(path: Path, text: str) -> None:
    atomic_bytes(path, text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_json(document: object) -> str:
    data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def classification(finding: dict[str, Any]) -> tuple[str, str]:
    if finding.get("verdict") != "confirmed" or finding.get("status") != "verified":
        return "manual_only", "finding requires environment confirmation before a source patch is appropriate"
    if finding.get("finding_kind") == "secret":
        return "manual_only", "secret remediation requires removal and external rotation without persisting a deletion hunk"
    return "eligible", "confirmed source-backed finding is eligible for production patch authoring"


def manual_finding_evidence(scan: Path, source: Path, finding: dict,
                            limitations: list[str] | None = None) -> tuple[list, list[str]]:
    """Check manual dossier safety without treating absent patch proof as authority."""
    from advantage_contract import PHASES, context_for_base, load_value, resolve_reference
    if error := publication_content_error(finding):
        raise ValueError("manual finding is not sanitized: " + error)
    manifest = source_publication(scan)
    advantage = manifest["execution_kind"] == "advantage"
    context = context_for_base(scan, source) if advantage else None
    groups = claim_reference_groups(finding)
    for row in finding.get("optional_support", []):
        groups.append(("optional_support", [row["reference"], *row["independent_support"]], "mixed"))
    groups.append(("capability.provenance", finding.get("capability", {}).get("provenance", []), "mixed"))
    extra = [finding["independent_verification_ref"], *finding["graph_receipt_refs"]]
    for row in finding.get("contributors", []):
        reference = row["artifact_ref"]
        if row.get("execution_id", manifest["run_id"]) != manifest["run_id"]:
            if not advantage:
                raise ValueError("manual contributor declares another execution")
            reference = {"execution_id": row["execution_id"], "artifact_ref": reference}
        extra.append(reference)
    if finding["verification"].get("reproduction_ref"):
        extra.append(finding["verification"]["reproduction_ref"])
    groups.append(("verification artifacts", extra, "artifact"))
    if finding.get("secret"):
        groups.append(("secret location", [f"{finding['secret']['file']}:{finding['secret']['line']}"], "source"))
    artifacts, files, missing = {}, set(), set()
    for field, refs, kind in groups:
        for ref in refs:
            if isinstance(ref, dict):
                if not advantage:
                    raise ValueError("ordinary remediation requires local evidence references")
                value = ref.get("artifact_ref")
            else:
                value = ref
            relative, selector = _parts(value)
            artifact = (isinstance(ref, dict) or kind == "artifact"
                        or kind == "mixed" and Path(relative).parts[0] in
                        (PHASES if advantage else SCAN_NAMESPACES))
            if ((":" in value or "#" in value) and not selector
                    or ":" in selector or "#" in selector):
                raise ValueError("noncanonical manual evidence selector")
            if not artifact and selector and (
                    "#" in value or not re.fullmatch(r"[1-9][0-9]*(?:-[1-9][0-9]*)?(?:,[1-9][0-9]*(?:-[1-9][0-9]*)?)*", selector)):
                raise ValueError("noncanonical manual source selector")
            if artifact:
                artifacts[json.dumps(ref, sort_keys=True)] = ref
            else:
                files.add(relative)
            try:
                if advantage:
                    resolve_reference(context, ref, kind)
                else:
                    path = resolve_beneath(scan if artifact else source, relative)
                    if artifact and path.is_file():
                        value = load_value(path)
                        if isinstance(value, dict) and value.get("run_id", manifest["run_id"]) != manifest["run_id"]:
                            raise ValueError("manual evidence declares another execution")
                    validate_evidence_refs(scan, source, [{"path": "."}], [ref], owner=field, kind=kind)
            except EvidenceIssue as exc:
                if exc.code not in {"missing_file", "missing_record", "unreadable_content"}:
                    raise
                missing.add(field)
    if missing and limitations is not None:
        limitations.append("Safe supporting evidence is unavailable for this manual-only finding: "
                           + ", ".join(sorted(missing)) + "; no patch is authorized.")
    return [artifacts[key] for key in sorted(artifacts)], sorted(files)


def finding_evidence(scan: Path, source: Path, finding: dict[str, Any], *,
                     limitations: list[str] | None = None) -> tuple[list, list[str]]:
    """Preserve manual evidence identity; require full closure for eligible patches."""
    if classification(finding)[0] == "manual_only":
        return manual_finding_evidence(scan, source, finding, limitations)
    if source_publication(scan)["execution_kind"] == "advantage":
        return advantage_finding_evidence(scan, source, finding)
    repositories = [{"path": "."}]
    effective = effective_support(scan, source, repositories, finding, used_optional=set())
    groups = claim_reference_groups(effective)
    extra = [finding["independent_verification_ref"], *finding["graph_receipt_refs"]]
    if finding["verification"].get("reproduction_ref"):
        extra.append(finding["verification"]["reproduction_ref"])
    groups.append(("verification artifacts", extra, "artifact"))
    if finding.get("secret"):
        groups.append(("secret location", [f"{finding['secret']['file']}:{finding['secret']['line']}"], "source"))
    files, artifacts = set(), set()
    for field, refs, kind in groups:
        bound = set(validate_evidence_refs(scan, source, repositories, refs, owner=field, kind=kind))
        artifacts.update(bound)
        files.update(_parts(ref)[0] for ref in refs if ref not in bound)
    return sorted(artifacts), sorted(files)


def resolve_beneath(base: Path, relative: str, *, require_file: bool = False) -> Path:
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError(f"unsafe relative artifact path: {relative!r}")
    candidate = (base / relative).resolve()
    candidate.relative_to(base.resolve())
    if require_file and not candidate.is_file():
        raise ValueError(f"artifact does not resolve: {relative}")
    return candidate


def relative_to_root(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def require_remediation_base(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    resolved.relative_to((root / "remediations").resolve())
    if resolved.is_symlink():
        raise ValueError("remediation base must not be a symlink")
    return resolved


def require_work_base(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    resolved.relative_to((root / "work/remediation").resolve())
    if resolved.is_symlink():
        raise ValueError("remediation work base must not be a symlink")
    return resolved


def context_path(root: Path) -> Path:
    return Path(
        os.environ.get(
            "VULNOPS_REMEDIATION_CONTEXT",
            root / ".harness/remediation-context.json",
        )
    )


def load_context(root: Path) -> dict[str, Any]:
    context = load_object(context_path(root))
    if context.get("schema_version") != "2.0" or context.get("artifact_kind") != "linked-remediation":
        raise ValueError("invalid linked-remediation context")
    validate_routing(context.get("model_routing"), scope="remediation")
    if context.get("model") != context["model_routing"]["controllers"]["remediation"]:
        raise ValueError("remediation model summary differs from its routing")
    manifest = load_object(Path(context["remediation_base"]) / "remediation-manifest.json")
    for key in ("model_routing", "report_sha256", "remediation_contract_sha256"):
        if manifest.get(key) != context.get(key) or not context.get(key):
            raise ValueError(f"remediation context {key} identity mismatch")
    scan = Path(context["source_scan"])
    if context.get("source_manifest_sha256"):
        # Existing unfinished remediation retains its original source binding.
        if sha256_file(legacy_source_manifest(scan)) != context["source_manifest_sha256"]:
            raise ValueError("immutable legacy source manifest changed")
    if sha256_file(scan / "report/security-report.json") != context["report_sha256"]:
        raise ValueError("immutable source publication changed")
    if source_publication(scan)["execution_kind"] == "advantage":
        validate_advantage_source(scan, Path(context["repo_path"]))
    return context


def target_fingerprint(root: Path, target: Path) -> str:
    result = subprocess.run(
        [sys.executable, str(root / "scripts/target-fingerprint.py"), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("target fingerprint command failed")
    value = result.stdout.strip()
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("target fingerprint command returned an invalid digest")
    return value


def validate_schema(root: Path, schema_name: str, document: Path) -> list[str]:
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/validate-json.py"),
            str(root / f"schemas/v2/{schema_name}"),
            str(document),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return [result.stderr.strip() or f"schema validation failed: {document}"]
    return []


def sanitized_error(value: object) -> str:
    return " ".join(str(value).split())[:1000] or "linked remediation failed"


def legacy_source_manifest(scan: Path) -> Path:
    paths = [scan / name for name in ("run-manifest.json", "advantage-manifest.json") if (scan / name).is_file()]
    if len(paths) != 1:
        raise ValueError("remediation source requires exactly one explicit audit or Advantage manifest")
    return paths[0]


def source_publication(scan: Path) -> dict:
    from report_bundle import document, read_publication
    report = document(scan, "report/security-report.json")
    if "publication" not in report:
        # Preserve exact-source refusal and unfinished legacy patch prerequisites.
        path = legacy_source_manifest(scan)
        old = document(scan, path.name)
        if old.get("status") != "complete" or not old.get("run_id"):
            raise ValueError("source audit must be complete before remediation")
        if report.get("run_id", old["run_id"]) != old["run_id"]:
            raise ValueError("legacy source report differs from its execution")
        return {**old, "execution_kind": "advantage" if path.name == "advantage-manifest.json" else "audit",
                "report": report, "final": document(scan, "final-verification/findings.json")}
    return read_publication(scan)


def packet_schema(scan: Path) -> str:
    return "advantage-remediation-packet.schema.json" if source_publication(scan)["execution_kind"] == "advantage" else "remediation-packet.schema.json"


def require_exact_source_authority(run: dict, final: dict, report: dict | None = None) -> str:
    """Require the existing exact-source policy only for production remediation.

    Attempt provenance identifies reviews, not frozen source bytes. It cannot
    replace the exact-source authority of supported legacy remediation inputs.
    """
    if not isinstance(final.get("findings"), list):
        raise ValueError("final-verification/findings.json requires a findings array")
    assessment_records = [run, final, report or {}, *final["findings"]]
    if any(
        isinstance(record, dict) and (
            record.get("attempt_id") or record.get("attempt_contexts") or record.get("assessment_context")
            or record.get("assessment_id") or record.get("assessment_scopes")
            or (isinstance(record.get("assessment"), dict)
                and ("scopes" in record["assessment"] or "publication_attempt_id" in record["assessment"]))
            or record.get("historical_findings") or record.get("unresolved_applicability")
        )
        for record in assessment_records
    ):
        raise ValueError(
            "manual-required: historical or mixed-attempt findings lack exact-source authority "
            "for automated production remediation; independently establish each claim on the "
            "intended patch base and obtain explicit manual remediation authorization"
        )
    digest = run.get("target_fingerprint")
    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(
            "manual-required: source manifest lacks exact-source authority (target_fingerprint) "
            "required by automated production remediation; independently establish the findings "
            "on the intended patch base and obtain explicit manual remediation authorization; "
            "do not generate a fingerprint to retroactively authorize historical findings"
        )
    return digest


def validate_advantage_source(scan: Path, source: Path) -> dict:
    from advantage_contract import context_for_base
    manifest = source_publication(scan)
    if manifest["execution_kind"] != "advantage" or manifest.get("mode") == "actions":
        raise ValueError("remediation requires a completed non-actions Advantage finding source")
    if not isinstance(manifest.get("repositories"), list) or len(manifest["repositories"]) != 1:
        raise ValueError("automated remediation supports single-repository findings only; per-repository patch ownership is not authorized")
    final = load_object(scan / "final-verification/findings.json")
    findings, source_links = final.get("findings"), final.get("links")
    if not isinstance(findings, list):
        raise ValueError("final-verification/findings.json requires a findings array")
    if not isinstance(source_links, list) or any(
        not isinstance(item, dict) or not item.get("finding_id") or not item.get("source_view")
        for item in source_links
    ):
        raise ValueError(
            "manual-required: final-verification/findings.json lacks exact source-view ownership links; "
            "establish each finding's base repository before authorizing production remediation"
        )
    links = {item["finding_id"]: item for item in source_links}
    if len(links) != len(source_links) or any(
        not isinstance(item, dict) or not item.get("id") for item in findings
    ) or set(links) != {item["id"] for item in findings}:
        raise ValueError("manual-required: Advantage remediation source lacks exact source-view ownership")
    if any(item["source_view"] != "base" for item in links.values()):
        raise ValueError("manual-required: derived-patch findings cannot be remediated against the unchanged audited target; establish the findings on the intended patch base before manual remediation")
    require_exact_source_authority(manifest, final, load_object(scan / "report/security-report.json"))
    return context_for_base(scan, source)


def advantage_finding_evidence(scan: Path, source: Path, finding: dict) -> tuple[list, list[str]]:
    from advantage_contract import context_for_base, resolve_reference, PHASES
    from advantage_pipeline import validate_finding
    context = context_for_base(scan, source)
    final = load_object(scan / "final-verification/findings.json")
    matches = [item for item in final["findings"] if item["id"] == finding["id"]]
    links = [item for item in final["links"] if item["finding_id"] == finding["id"]]
    if matches != [finding] or len(links) != 1 or links[0]["source_view"] != "base":
        raise ValueError("remediation evidence must be an exact accepted base-source dossier")
    validate_finding(context, finding, links[0])
    groups = claim_reference_groups(finding)
    extra = [finding["independent_verification_ref"], *finding["graph_receipt_refs"]]
    if finding["verification"].get("reproduction_ref"):
        extra.append(finding["verification"]["reproduction_ref"])
    groups.append(("verification artifacts", extra, "artifact"))
    artifacts, files = {}, set()
    for _, refs, kind in groups:
        for ref in refs:
            resolve_reference(context, ref, kind)
            if isinstance(ref, dict) or kind == "artifact" or (kind == "mixed" and Path(_parts(ref)[0]).parts[0] in PHASES):
                artifacts[json.dumps(ref, sort_keys=True)] = ref
            else:
                files.add(_parts(ref)[0])
    return [artifacts[key] for key in sorted(artifacts)], sorted(files)


def resolve_remediation_artifact(scan: Path, source: Path, reference) -> None:
    if source_publication(scan)["execution_kind"] == "advantage":
        from advantage_contract import context_for_base, resolve_reference
        resolve_reference(context_for_base(scan, source), reference, "artifact")
    else:
        relative, _ = _parts(reference)
        resolve_beneath(scan, relative, require_file=True)


def read_remediation(base: Path, *, validate_evidence: bool = False) -> dict:
    """Read completed patch outcomes without reopening their source or workspace."""
    from report_bundle import document
    from dossier_contract import validate_publication_schema
    base = Path(base).resolve()
    bundle = document(base, "remediation.json")
    validate_publication_schema(bundle, "remediation.schema.json")
    summary = resolve_beneath(base, "summary.md", require_file=True)
    if summary.is_symlink() or summary.resolve() != base / "summary.md":
        raise ValueError("unsafe remediation summary")
    if error := publication_content_error(summary.read_text(encoding="utf-8"), size_limit=None):
        raise ValueError(error)
    if validate_evidence and bundle.get("summary_sha256") and sha256_file(summary) != bundle["summary_sha256"]:
        raise ValueError("remediation summary differs from its committed publication")
    seen = set()
    for item in bundle["items"]:
        identifier = item["finding_id"]
        if identifier in seen:
            raise ValueError("duplicate remediation finding")
        seen.add(identifier)
        if item["disposition"] == "patch_ready":
            expected = {"patch_ref": f"patches/{identifier}.patch", "receipt_ref": f"receipts/{identifier}.json",
                        "result_ref": f"results/{identifier}.json"}
            if any(item[field] != reference for field, reference in expected.items()) or not item["patch_sha256"]:
                raise ValueError("patch-ready remediation lacks its canonical outputs")
        elif any(item[field] is not None for field in ("patch_ref", "patch_sha256", "receipt_ref")):
            raise ValueError("manual remediation cannot publish a patch")
        for field in ("patch_ref", "receipt_ref", "result_ref"):
            if item[field]:
                path = resolve_beneath(base, item[field], require_file=True)
                if path != base / item[field] or path.is_symlink():
                    raise ValueError("unsafe remediation evidence")
        if not validate_evidence:
            continue
        if item["result_ref"]:
            result = document(base, item["result_ref"])
            validate_publication_schema(result, "remediation-worker-result.schema.json")
            if (result["remediation_id"] != bundle["remediation_id"]
                    or result["finding_id"] != identifier or result["model"] != bundle["model"]):
                raise ValueError("remediation worker attribution differs from publication")
        if item["patch_ref"]:
            receipt = document(base, item["receipt_ref"])
            validate_publication_schema(receipt, "remediation-patch-receipt.schema.json")
            if (receipt["finding_id"] != identifier or receipt["patch_ref"] != item["patch_ref"]
                    or receipt["patch_sha256"] != item["patch_sha256"]
                    or sha256_file(base / item["patch_ref"]) != item["patch_sha256"]):
                raise ValueError("remediation patch receipt differs from publication")
    ready = sum(item["disposition"] == "patch_ready" for item in bundle["items"])
    if bundle["counts"] != {"total": len(seen), "patch_ready": ready, "manual_required": len(seen) - ready}:
        raise ValueError("remediation outcome counts differ from dispositions")
    if bundle["status"] != ("degraded" if ready < len(seen) else "ok"):
        raise ValueError("remediation status differs from recorded dispositions")
    return bundle
