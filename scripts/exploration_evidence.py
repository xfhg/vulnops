"""Declared Recon/threat-model support fields; extra descriptive data is inert."""
from pathlib import Path, PurePosixPath

from evidence_accounting import classify_refs, diagnostic, summarize
from evidence_refs import EvidenceIssue, SCAN_NAMESPACES, navigation_file


def model_evidence_quality(scan, source, repositories, document, *, owner, kind, diagnostics=None, historical=False):
    fields = [(document, "evidence_refs", "evidence_refs", kind == "threat-model")]
    collections = {
        "repo-context": ("projects", "actors"),
        "security-surfaces": ("entry_points", "trust_boundaries", "security_relevant_files"),
        "research": ("observations",),
        "threat-model": ("assets", "trust_boundaries", "entrypoints", "subsystems", "threats", "hunt_mappings", "attack_classes"),
    }[kind]
    for collection in collections:
        for index, item in enumerate(document.get(collection, [])):
            fields.append((item, "evidence_refs", f"{collection}[{index}].evidence_refs", kind == "threat-model"))
            if collection == "projects":
                fields.extend((entry, "evidence_refs", f"projects[{index}].entry_points[{j}].evidence_refs", False)
                              for j, entry in enumerate(item.get("entry_points", [])))
    for index, item in enumerate(document.get("attack_paths", [])):
        fields.append((item, "source_refs", f"attack_paths[{index}].source_refs", False))
        for j, handoff in enumerate(item.get("handoff_evidence", [])):
            prefix = f"attack_paths[{index}].handoff_evidence[{j}]"
            fields.append((handoff, "source_refs", prefix + ".source_refs", False))
            for key in ("producer", "consumer"):
                if key in handoff:
                    fields.append(({key: [handoff[key]]}, key, prefix + "." + key, False))
    issues = []
    for item, key, field, mixed in fields:
        refs = item.get(key, [])
        if not isinstance(refs, list):
            raise ValueError("declared model evidence field must be an array")
        for offset, ref in enumerate(refs):
            if not isinstance(ref, str):
                raise ValueError("declared model evidence reference must be a string")
            relative = ref.partition(":")[0].partition("#")[0]
            path = PurePosixPath(relative)
            label = f"{field}[{offset}]"
            ids = [f"{owner}:{field}"]
            if mixed and path.suffix.lower() in {".md", ".txt"} and path.parts and path.parts[0] in SCAN_NAMESPACES:
                try:
                    navigation_file(Path(scan), ref)
                except EvidenceIssue as exc:
                    issues.append(diagnostic(exc.code, owner, label, ids))
            else:
                _, local = classify_refs(Path(scan), Path(source), repositories, [ref], owner=owner,
                                         field=label, affected_item_ids=ids, kind="mixed" if mixed else "source",
                                         historical=historical)
                issues.extend(local)
    if diagnostics is not None:
        diagnostics.extend(issues)
    return summarize(issues)


def recon_evidence_quality(scan, source, repositories, *, historical=False):
    import json
    documents = [("repo-context/repo-context.json", "repo-context"),
                 ("repo-context/security-surfaces.json", "security-surfaces"),
                 *((f"repo-context/research/{name}.json", "research")
                   for name in ("overview", "trust-boundaries", "input-surfaces"))]
    diagnostics = []
    for relative, kind in documents:
        model_evidence_quality(scan, source, repositories, json.loads((Path(scan) / relative).read_text()),
                               owner=relative, kind=kind, diagnostics=diagnostics, historical=historical)
    return summarize(diagnostics)
