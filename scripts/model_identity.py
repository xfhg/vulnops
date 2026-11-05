#!/usr/bin/env python3
"""Canonical OMP selector identity helpers.

Thinking effort changes execution cost, not model diversity. Only a recognized
trailing OMP effort suffix is removed; colons that are part of a model ID stay
intact.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from evidence_refs import EvidenceIssue, artifact_value, validate_evidence_refs
from evidence_accounting import effective_support
from dossier_contract import dossier_evidence_groups
from run_lifecycle import routing_for_artifact


THINKING_EFFORTS = {
    "off",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
    "auto",
}


def model_identity(selector: str) -> str:
    value = str(selector or "").strip()
    head, separator, suffix = value.rpartition(":")
    if separator and suffix.lower() in THINKING_EFFORTS:
        return head
    return value


def model_diversity(primary: str, verifier: str) -> bool:
    return model_identity(primary) != model_identity(verifier)


def validate_provenance(value: dict, routing: dict, expected_actor: str | None = None,
                        expected_ref: str | None = None) -> dict:
    if not isinstance(value, dict) or set(value) != {"actor", "selector", "artifact_ref"}:
        raise ValueError("required actor/selector/artifact_ref provenance is missing")
    actor, selector, ref = (value[key] for key in ("actor", "selector", "artifact_ref"))
    if not all(isinstance(item, str) and item for item in (actor, selector, ref)):
        raise ValueError("provenance fields must be nonempty strings")
    if expected_actor is not None and actor != expected_actor:
        raise ValueError("provenance actor differs from assigned owner")
    if routing.get("agents", {}).get(actor) != selector:
        raise ValueError(f"provenance selector differs from assigned route for {actor}")
    relative = ref.partition(":")[0]
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or str(path) != relative or "\\" in ref or "#" in ref:
        raise ValueError("provenance requires a canonical scan-relative artifact reference")
    if expected_ref is not None and ref != expected_ref:
        raise ValueError("provenance artifact reference differs from canonical owner")
    owners = {
        "vulnops-deepdive-chunk": r"sast/deepdive/[^/:]+\.json",
        "vulnops-verify-one": r"sast/verify/[^/:]+\.json",
        "vulnops-intrusion-campaign": r"intrusion/results/[^/:]+\.json",
        "vulnops-gap-investigator": r"gap-exploration/results/[^/:]+\.json",
        "vulnops-recon-overview": r"repo-context/research/overview\.json",
        "vulnops-recon-trust": r"repo-context/research/trust-boundaries\.json",
        "vulnops-recon-inputs": r"repo-context/research/input-surfaces\.json",
        "vulnops-reproduce-one": r"sast/reproduction/[^/:]+/result\.json",
    }
    if actor not in owners or re.fullmatch(owners[actor], ref) is None:
        raise ValueError("provenance does not name its canonical actor-owned artifact")
    return dict(value)


def contributor_union(*groups: list[dict]) -> list[dict]:
    values = {}
    for group in groups:
        for item in group:
            key = tuple(item[name] for name in ("actor", "selector", "artifact_ref"))
            values[key] = dict(item)
    return [values[key] for key in sorted(values)]




def finding_contributors(scan: Path, finding: dict, routing: dict, primitives: dict | None = None,
                         *, source_root: Path, repositories: list[dict], diagnostics: list | None = None) -> list[dict]:
    """Attribute explicit relied-upon records, never incidental sibling citations."""
    optional_seen = set()
    finding = effective_support(scan, source_root, repositories, finding, diagnostics, used_optional=optional_seen)
    groups = []
    visiting = set()
    line_counts = {}
    manifest = {}
    for name in ("advantage-manifest.json", "run-manifest.json"):
        if (scan / name).exists():
            manifest = artifact_value(scan, name)
            break
    def historical_record(ref, value):
        if not manifest:
            # Standalone current-output consumers provide their assigned route.
            return False
        current = manifest.get("attempt_id")
        if not current:
            return True
        assessment = value.get("assessment_context") if isinstance(value, dict) else None
        if isinstance(assessment, dict) and assessment.get("attempt_id"):
            return assessment["attempt_id"] != current
        phase = ref.split("/", 1)[0]
        if phase == "repo-context":
            phase = "recon"
        attempt = manifest.get("phase_attempts", {}).get(phase)
        if ref.startswith(("sast/deepdive/", "sast/verify/", "sast/reproduction/")):
            from sast_contract import producing_attempt
            attempt = producing_attempt(scan, ref) or attempt
        return attempt != current
    def collect_evidence(value, owner, *, historical=False):
        if finding.get("optional_support") and not historical:
            value = effective_support(scan, source_root, repositories,
                                      {**value, "optional_support": finding["optional_support"]},
                                      diagnostics, used_optional=optional_seen)
        for ref in validate_evidence_refs(scan, source_root, repositories, value.get("evidence_refs", []),
                                          owner=f"{owner}.evidence_refs", line_counts=line_counts,
                                          historical=historical):
            collect_ref(ref)
    def collect_ref(ref, identifier=None):
        value = artifact_value(scan, ref)
        path = re.split(r"[:#]", ref, maxsplit=1)[0]
        if path.startswith("gap-exploration/"):
            from gap_dossier import accepted_candidates, candidate_references
            candidates = accepted_candidates(scan)
            normalized = ref.replace("#", ":", 1)
            if identifier is not None and ":" not in normalized:
                normalized += ":" + identifier
            if ":" in normalized:
                if normalized not in {item for row in candidates for item in candidate_references(row)}:
                    raise ValueError("supplementary provenance must resolve an accepted candidate")
            elif path not in {row["provenance"]["artifact_ref"] for row in candidates}:
                raise ValueError("supplementary provenance must resolve an accepted worker")
            if identifier is not None and path.startswith("gap-exploration/results/") and ":" not in ref and "#" not in ref:
                ref=f"{path}:{identifier}"
                value=artifact_value(scan,ref)
        owner_file = path.startswith(("sast/deepdive/", "sast/verify/", "repo-context/research/",
                                      "intrusion/results/", "sast/reproduction/", "gap-exploration/results/"))
        if identifier is not None and not owner_file and ":" not in ref and "#" not in ref and (
            isinstance(value, list) or isinstance(value, dict) and
            any(key in value for key in ("results", "findings", "advisories", "candidates", "entry_points", "trust_boundaries", "campaigns"))
        ):
            ref = f"{ref}:{identifier}"
            value = artifact_value(scan, ref)
        if ref in visiting:
            return
        visiting.add(ref)
        before = len(groups)
        if owner_file:
            root = artifact_value(scan, path)
            collect(root, attribution="provenance")
            if ":" in ref or "#" in ref:
                collect_evidence(value, ref, historical=historical_record(ref, value))
        else:
            attribution = "provenance" if path == "sast/validation-results.json" or path == "intrusion/intrusion-results.json" and isinstance(value, dict) and "campaign_id" in value else "contributors"
            admitted = path in {"sast/raw-findings.json", "sast/validation-queue.json", "sast/verified-findings.json",
                                "sast/validation-results.json", "campaign-planning/evidence-index.json",
                                "intrusion/intrusion-results.json"}
            if not path.startswith(("repo-context/", "sast/", "intrusion/", "campaign-planning/", "tool-collection/")):
                admitted = True
            if path == "repo-context/security-surfaces.json":
                root = artifact_value(scan, path)
                admitted = value in root.get("entry_points", []) + root.get("trust_boundaries", [])
            if admitted:
                collect(value, proof=":" in ref or "#" in ref, attribution=attribution,
                        historical=historical_record(ref, value))
        if len(groups) == before and ref.startswith(("sast/deepdive/", "sast/verify/", "sast/raw-findings.json",
                                                     "sast/verified-findings.json", "sast/validation-results.json",
                                                     "intrusion/results/", "intrusion/intrusion-results.json", "gap-exploration/")):
            raise EvidenceIssue("unreadable_content", f"source investigation lacks historical attribution: {ref}")
    def collect(value, proof=False, attribution="contributors", historical=False):
        if isinstance(value, list):
            for item in value:
                collect(item, proof=proof, attribution=attribution, historical=historical)
        elif isinstance(value, dict):
            provenance = value.get("provenance") if attribution == "provenance" else None
            items = ([provenance] if isinstance(provenance, dict) else []) if attribution == "provenance" else value.get("contributors", [])
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("artifact_ref"), str):
                    raise EvidenceIssue("unreadable_content", "historical contributor attribution is unavailable")
                try:
                    assigned = routing_for_artifact(scan, item["artifact_ref"], routing)
                except ValueError as exc:
                    if "missing producing model assignment" not in str(exc):
                        raise
                    raise EvidenceIssue("unreadable_content", "historical model assignment is unavailable") from None
                if not assigned.get("agents", {}).get(item.get("actor")):
                    raise EvidenceIssue("unreadable_content", "historical actor assignment is unavailable")
                item = validate_provenance(item, assigned)
                owner = artifact_value(scan, item["artifact_ref"])
                if not isinstance(owner, dict) or owner.get("provenance") != item:
                    raise EvidenceIssue("unreadable_content", "contributor does not resolve its source-owned attribution")
                groups.append([item])
            if proof and "evidence_refs" in value:
                collect_evidence(value, value.get("id") or value.get("candidate_id") or "evidence", historical=historical)
            if not items and attribution != "provenance":
                for key in ("results", "findings", "entry_points", "trust_boundaries"):
                    for item in value.get(key, []):
                        collect(item, proof=proof, attribution=attribution, historical=historical)
    collect_evidence(finding, finding.get("id", "finding"))
    for field, refs, kind in dossier_evidence_groups(finding):
        for ref in validate_evidence_refs(scan, source_root, repositories, refs, owner=field, kind=kind):
            collect_ref(ref)
    for source in finding.get("source_refs", []):
        ref = source["artifact_ref"]
        if re.search(r"[:#]", ref) and re.split(r"[:#]", ref, maxsplit=1)[1] != source["source_id"]:
            raise ValueError("source ID differs from canonical artifact reference")
        collect_ref(ref, source["source_id"])
    for ref in finding.get("verification", {}).get("source_validation_refs", []):
        for artifact_ref in validate_evidence_refs(scan, source_root, repositories, [ref], owner="verification.source_validation_refs"):
            collect_ref(artifact_ref)
    if primitives is None and finding.get("primitive_steps"):
        primitives = {}
        required_ids = {step["primitive_id"] for step in finding["primitive_steps"]}
        for relative, key in (("campaign-planning/evidence-index.json", "primitives"),
                              ("intrusion/intrusion-results.json", "results")):
            path = scan / relative
            if path.is_file():
                rows = json.loads(path.read_text()).get(key, [])
                if key == "results":
                    from intrusion_contract import primitive_updates_view
                    context = {"source_root": str(source_root), "repositories": repositories, "model_routing": routing}
                    selected = [{**row, "primitive_updates": [item for item in row.get("primitive_updates", []) if item["id"] in required_ids],
                                 "non_promoted": [item for item in row.get("non_promoted", []) if item["id"] in required_ids]}
                                for row in rows if any(item["id"] in required_ids for item in row.get("primitive_updates", []))]
                    rows = [item for row in selected for item in primitive_updates_view(scan, context, row)]
                primitives.update({item["id"]: item for item in rows})
    primitives = primitives or {}
    for step in finding.get("primitive_steps", []):
        primitive = primitives.get(step["primitive_id"])
        if primitive is None:
            raise ValueError("effective finding references unknown primitive")
        for policy in primitive.get("optional_support", []):
            if policy not in finding.get("optional_support", []):
                raise ValueError("relied-upon primitive optional-support rationale must reach independent verification")
            optional_seen.add(policy["reference"])
        collect(primitive, proof=True)
        if primitive.get("capability", {}).get("evidence_status") in {"source_established", "experimentally_observed"} and not primitive.get("contributors"):
            raise EvidenceIssue("unreadable_content", "source-established primitive lacks investigation contributors")
        collect_evidence(step, f"{finding.get('id', 'finding')}.{step['primitive_id']}")
    for transition in finding.get("transitions", []):
        for proof in [transition.get("resolution", {}), *transition.get("obligations", {}).values()]:
            collect_evidence(proof, f"{finding.get('id', 'finding')}.transition")
    if {row["reference"] for row in finding.get("optional_support", [])} != optional_seen:
        raise ValueError("optional-support declaration must name an unusable relied-upon citation")
    contributors = contributor_union(*groups)
    if not contributors:
        raise EvidenceIssue("unreadable_content", "effective finding lacks attributable investigation provenance")
    return contributors


def finding_diversity(contributors: list[dict], verifier: str) -> bool:
    if not contributors or not model_identity(verifier):
        raise ValueError("finding diversity requires contributors and a verifier selector")
    if any(not isinstance(item.get("selector"), str) or not item["selector"] for item in contributors):
        raise ValueError("finding contributor selector is missing")
    return all(model_diversity(item["selector"], verifier) for item in contributors)


def diversity_summary(findings: list[dict]) -> dict:
    if any(type(item.get("model_diversity")) is not bool for item in findings):
        raise ValueError("finding diversity is missing")
    diverse = sum(item["model_diversity"] for item in findings)
    total = len(findings)
    return {"model_diversity": bool(total) and diverse == total,
            "diversity_counts": {"diverse": diverse, "same_model": total - diverse, "total": total}}
