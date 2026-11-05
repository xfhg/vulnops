"""Publication-only authority for stopped Advantage executions, never native recovery.

Retained final/review/assignment bindings authorize projection, not new findings.
No target reads, model dispatch, lifecycle acceptance or assessment restamping.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

import advantage_contract as core
import advantage_pipeline as pipeline
from artifact_policy import publication_content_error
from dossier_contract import dossier_hash, validate_dossier_review
from evidence_refs import _parts
from model_routing import split_selector
from report_bundle import document, read_publication, _local_reference
from run_lifecycle import claim_run, release_run, state_lock, report_assessment

RECEIPT = "report/publication-receipt.json"


class RetainedEvidence:
    def __init__(self, base: Path, mode: str):
        self.base = core.require_base(base)
        self.run_id = core.component(self.base.name)
        self.inputs = {}
        self.roots = {self.run_id: self.base}
        self.context = {"run_id": self.run_id, "scan_base": str(self.base),
                        "execution_kind": "advantage", "mode": mode,
                        "_retained_publication": True, "repositories": [],
                        "model_routing": {"agents": {}}, "options": {},
                        "patch_binding": None, "action_source": None}

    def read(self, ref, *, owner=None):
        owner = owner or self.run_id
        relative, _ = _parts(ref)
        root = self.roots[owner]
        value = document(root, relative)
        if value.get("run_id", owner) != owner:
            raise ValueError("retained evidence has foreign execution: " + relative)
        path = core.inside(root, relative)
        digest = core.sha256_file(path)
        key = (owner, relative)
        if key in self.inputs and self.inputs[key] != digest:
            raise ValueError("retained evidence changed during publication: " + relative)
        self.inputs[key] = digest
        return value

    def bound(self, ref, digest):
        value = self.read(ref)
        if self.inputs[(self.run_id, _parts(ref)[0])] != digest:
            raise ValueError("retained hash binding differs: " + ref)
        return value

    def route(self, ref, provenance):
        if provenance.get("execution_id") != self.run_id or provenance.get("artifact_ref") != ref:
            raise ValueError("retained author changed execution or artifact: " + ref)
        actor, selector = provenance["actor"], provenance["selector"]
        split_selector(selector)
        routes = self.context["model_routing"]["agents"]
        if actor in routes and routes[actor] != selector:
            raise ValueError("ambiguous retained producing route: " + actor)
        routes[actor] = selector
        self.context.setdefault("_publication_producer_routes", {})[ref] = {"agents": {actor: selector}}

    def references(self, value):
        for ref in pipeline.walk_refs(value):
            raw = ref["artifact_ref"] if isinstance(ref, dict) else ref
            relative, _ = _parts(raw)
            if isinstance(ref, dict):
                owner = ref["execution_id"]
                if owner not in self.roots or owner == self.run_id:
                    raise ValueError("unadmitted retained reference owner")
                self.read(relative, owner=owner)
                core.resolve_reference(self.context, ref, kind="artifact")
            elif relative.split("/", 1)[0] in core.PHASES:
                self.read(relative)
                core.resolve_reference(self.context, ref, kind="artifact")
            else:
                if relative.startswith(("/", ".")) or ".." in Path(relative).parts:
                    raise ValueError("unsafe retained source coordinate")
            # Source references are preserved coordinates, not reads of today's target.

    def review_references(self, scan, target, repositories, values, **kwargs):
        self.references({"evidence_refs": values})
        return [ref for ref in values if isinstance(ref, dict) or
                _parts(ref)[0].split("/", 1)[0] in core.PHASES]

    def validate(self):
        c = self.context
        catalog = self.read("baseline/catalog.json")
        core.validate_schema(catalog, "advantage-baseline")
        baseline_id = core.component(catalog["source_run_id"])
        if baseline_id == self.run_id:
            raise ValueError("retained baseline cannot be the publication destination")
        baseline = core.require_base(self.base.parent / baseline_id)
        baseline_publication = read_publication(baseline, expected_kind="audit", validate_evidence=True)
        if baseline_publication["run_id"] != baseline_id:
            raise ValueError("retained baseline identity differs")
        self.roots[baseline_id] = baseline
        c.update(source_run_id=baseline_id, repository=baseline_publication["repository"],
                 baseline={"execution_id": baseline_id, "root": str(baseline), "catalog_ref": "baseline/catalog.json"})
        self.read("report/security-report.json", owner=baseline_id)
        self.read("final-verification/findings.json", owner=baseline_id)
        plan = self.read("planning/plan.json")
        pipeline.schema(plan, "plan", c)
        self.route("planning/plan.json", plan["provenance"])
        if (c["mode"] == "deep") != (len(plan["passes"]) > 1):
            raise ValueError("declared publication mode differs from retained pass structure")
        actions = self.read("handoff/actions.json")
        core.validate_schema(actions, "advantage-action")
        for key in ("diff_review", "verify_fix", "patch_risk", "hardening", "tracking"):
            if actions[key]["status"] != "not_selected" or actions[key]["records"]:
                raise ValueError("retained selected actions require their original action/source binding; publication-only supports unselected actions")
        investigation = self.read("investigation/results.json")
        pipeline.schema(investigation, "investigation", c)
        for row in investigation["results"]:
            ref = row["artifact_ref"]
            result = self.bound(ref, row["sha256"])
            pipeline.schema(result, "result", c)
            self.route(ref, result["provenance"])
            packet_ref = "investigation/packets/" + core.component(row["task_id"]) + ".json"
            packet = self.bound(packet_ref, result["packet_sha256"])
            pipeline.schema(packet, "packet", c)
            if (pipeline.result_path(packet) != ref or result["task_id"] != packet["assignment"]["task_id"]
                    or result["pass_id"] != packet["assignment"]["pass_id"]):
                raise ValueError("retained investigation ownership changed: " + row["task_id"])
        gap_path = self.base / "gap-exploration/results.json"
        if gap_path.exists():
            gap = self.read("gap-exploration/results.json")
            from gap_exploration_contract import validate_analytical_phase, accepted_support_refs
            validate_analytical_phase(c, native=False)
            for ref in accepted_support_refs(self.base, context=c):
                self.read(ref)
            for row in gap["results"]:
                result = self.bound(row["ref"], row["sha256"])
                self.route(row["ref"], result["provenance"])
        synthesis = self.read("synthesis/findings.json")
        pipeline.schema(synthesis, "synthesis", c)
        self.route("synthesis/findings.json", synthesis["provenance"])
        if synthesis.get("original_evidence"):
            self.bound(synthesis["original_evidence"]["ref"], synthesis["original_evidence"]["sha256"])
        final = self.read("final-verification/findings.json")
        pipeline.schema(final, "verification", c)
        assignments_doc = self.read("final-verification/assignments.json")
        pipeline.schema(assignments_doc, "assignments", c)
        assignments = pipeline.unique(assignments_doc["assignments"], "finding_id")
        candidates = pipeline.unique(synthesis["findings"])
        links = pipeline.unique(synthesis["links"], "finding_id")
        accepted = pipeline.unique(final["findings"])
        reviews = pipeline.unique(final["reviews"], "finding_id")
        unconfirmed = pipeline.unique(final["unconfirmed"], "finding_id")
        if set(assignments) != set(candidates) or set(accepted) & set(unconfirmed) or set(accepted) | set(unconfirmed) != set(candidates):
            raise ValueError("retained review authority omits or duplicates a dossier")
        if set(reviews) - set(candidates) or set(accepted) - set(reviews):
            raise ValueError("accepted dossier lacks its retained review receipt")
        for fid, assignment in assignments.items():
            packet = self.read(f"final-verification/packets/{core.component(fid)}.json")
            if packet != assignment or assignment["candidate_sha256"] != dossier_hash(candidates[fid]):
                raise ValueError("retained review packet differs from assigned dossier: " + fid)
            expected_ref = f"final-verification/results/{fid}.json"
            if assignment["result_ref"] != expected_ref or assignment["actor"] != "vulnops-advantage-verify-one" or not assignment["fresh_context"]:
                raise ValueError("retained reviewer ownership differs: " + fid)
            if fid not in reviews:
                if unconfirmed[fid]["assignment_ref"] != "final-verification/assignments.json":
                    raise ValueError("unconfirmed dossier lost its assignment: " + fid)
                continue
            receipt = reviews[fid]
            if receipt["artifact_ref"] != expected_ref:
                raise ValueError("retained review receipt has foreign path: " + fid)
            review = self.bound(expected_ref, receipt["sha256"])
            pipeline.schema(review, "verification-result", c)
            if (review["finding_id"] != fid or review["assignment_sha256"] != core.digest(assignment)
                    or review["actor"] != assignment["actor"] or review["model"] != assignment["selector"]
                    or review["status"] != receipt["status"] or not review["fresh_context"]):
                raise ValueError("retained review changed assignment or disposition: " + fid)
            self.route(expected_ref, {"execution_id": self.run_id, "artifact_ref": expected_ref,
                                     "actor": review["actor"], "selector": review["model"]})
            if fid not in accepted:
                if review["status"] in {"verified", "corrected"}:
                    raise ValueError("accepted review was omitted from final authority: " + fid)
                continue
            effective = review["corrected_finding"] if review["status"] == "corrected" else candidates[fid]
            expected = {**effective, "verdict": "confirmed", "model_diversity": review["model_diversity"],
                        "independent_verification_ref": expected_ref}
            expected.pop("assessment_context", None)
            if review.get("assessment_context"):
                expected["assessment_context"] = review["assessment_context"]
            if accepted[fid] != expected:
                raise ValueError("final dossier differs from retained effective review: " + fid)
            contributors = pipeline.contributor_union(c, accepted[fid], links[fid])
            if contributors != accepted[fid]["contributors"]:
                raise ValueError("retained contributor closure differs: " + fid)
            diverse = bool(contributors) and all(split_selector(p["selector"])[:2] != split_selector(review["model"])[:2] for p in contributors)
            if diverse != review["model_diversity"]:
                raise ValueError("retained model diversity differs: " + fid)
            validate_dossier_review(self.base, None, [], accepted[fid], review,
                                    objective_registry=pipeline.synthesis_objectives(c),
                                    evidence_validator=self.review_references)
            primitives = [row["primitive_id"] for row in accepted[fid]["primitive_steps"]]
            if ([row["primitive_id"] for row in review["primitive_results"]] != primitives
                    or any(row["status"] != "verified" for row in review["primitive_results"])
                    or review["joint_conditions"]["outcome"] != "established"):
                raise ValueError("retained independent review lacks complete ordered proof: " + fid)
            pipeline.validate_transitions(c, accepted[fid], review["transition_results"],
                reference_validator=lambda values, **kwargs: self.references({"evidence_refs": values}))
            self.references(accepted[fid])
            self.references(review)
            for contributor in contributors:
                relative = _local_reference(contributor, self.run_id, c)
                owner = contributor.get("execution_id", self.run_id)
                if relative is not None:
                    source = self.read(relative)
                    if source.get("provenance") != contributor:
                        raise ValueError("local contributor differs from retained author: " + relative)
                else:
                    self.read(contributor["artifact_ref"], owner=owner)
        pipeline.validate_accepted_findings(c, final)
        if final["links"] != [links[f["id"]] for f in final["findings"]]:
            raise ValueError("retained finding classification differs from synthesis")
        for phase in ("synthesis", "final-verification"):
            pipeline.schema(self.read(phase + "/source-receipts.json"), "source-receipts", c)
        # Preserve identifiers; no date/revision is borrowed from today's source or baseline.
        scopes = {}
        for finding in [*final["findings"], *synthesis["findings"]]:
            assessment = finding.get("assessment_context") or final.get("assessment_context")
            if not assessment or not assessment.get("assessment_id"):
                raise ValueError("retained dossier lacks its assessment identity: " + finding["id"])
            sid = assessment["assessment_id"]
            scope = {"assessment_id": sid, "run_id": self.run_id, "attempt_id": assessment["attempt_id"],
                     "repositories": [], "source_root": None, "started_at": None,
                     "source_view": links[finding["id"]]["source_view"], "patch_ref": None,
                     "limitations": ["Original assessment date and repository revisions are unavailable in retained analytical evidence."]}
            if scope["source_view"] != "base":
                raise ValueError("derived-view publication requires the retained original patch binding")
            if sid in scopes and scopes[sid] != scope:
                raise ValueError("conflicting retained assessment identities")
            scopes[sid] = scope
        c["assessment_scopes"] = scopes
        c["attempt_contexts"] = {scope["attempt_id"]: {} for scope in scopes.values()}
        c["phase_attempts"] = {"final-verification": final["assessment_context"]["attempt_id"]}
        self.final, self.synthesis = final, synthesis
        return self

    def receipt(self, published_at, publication_id):
        return {"schema_version": "2.0", "execution_kind": "advantage", "run_id": self.run_id,
                "publication_id": publication_id, "published_at": published_at,
                "authority": "retained_independent_review_bindings", "native_acceptance_reconstructed": False,
                "mode": self.context["mode"], "baseline_id": self.context["source_run_id"],
                "inputs": [{"execution_id": owner, "artifact_ref": ref, "sha256": digest}
                           for (owner, ref), digest in sorted(self.inputs.items())]}

    def unchanged(self):
        for (owner, ref), digest in self.inputs.items():
            if core.sha256_file(core.inside(self.roots[owner], ref)) != digest:
                raise ValueError("retained publication input changed: " + ref)


def prepare(base, mode):
    if mode not in {"standard", "deep"}:
        raise ValueError("retained publication supports standard/deep base-source reports; other modes require original patch/action bindings")
    evidence = RetainedEvidence(base, mode).validate()
    c = evidence.context
    value = pipeline.report_projection(c)
    value["unconfirmed_dossiers"] = [copy.deepcopy(f) for f in evidence.synthesis["findings"]
                                       if f["id"] in {row["finding_id"] for row in evidence.final["unconfirmed"]}]
    publication_id = "publication-" + uuid.uuid4().hex
    value["assessment"] = report_assessment(c, [*value["findings"], *value["unconfirmed_dossiers"]])
    value["assessment"].update(publication_attempt_id=publication_id, retained=True)
    published_at = core.now()
    receipt = evidence.receipt(published_at, publication_id)
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    value["publication"].update(publication_method="retained_evidence", published_at=published_at,
        retained_evidence={"ref": RECEIPT, "sha256": hashlib.sha256(receipt_bytes).hexdigest()})
    markdown = pipeline.report_markdown(value, c)
    value["publication"]["markdown_sha256"] = hashlib.sha256(markdown.encode()).hexdigest()
    pipeline.schema(value, "report", c)
    if error := publication_content_error(markdown, size_limit=None):
        raise ValueError(error)
    evidence.unchanged()
    return evidence, value, markdown, receipt_bytes


def publish(base, mode, *, check=False):
    base = core.require_base(base)
    runtime = Path(os.environ.get("VULNOPS_RUNTIME_ROOT", core.ROOT / ".harness"))
    # A native invocation owns its immutable input until teardown. Never compete.
    if os.path.lexists(runtime / "tmp" / (base.name + "-input.json")):
        raise ValueError("stop and close the selected native invocation before retained publication")
    if os.environ.get("VULNOPS_ADVANTAGE_CALL"):
        raise ValueError("retained publication cannot execute inside a native Advantage invocation")
    with state_lock(base):
        for name in ("security-report.json", "security-report.md", "publication-receipt.json"):
            if os.path.lexists(core.inside(base, "report/" + name)):
                raise ValueError("report destination already exists; completed or partial publications are not overwritten: " + name)
        session = "retained-publication-" + uuid.uuid4().hex
        claim_run(base, session)
        try:
            evidence, value, markdown, receipt = prepare(base, mode)
            if not check:
                output = core.inside(base, "report")
                output.mkdir(exist_ok=True)
                created = []
                try:
                    for name, payload in (("publication-receipt.json", receipt),
                                          ("security-report.md", markdown.encode()),
                                          ("security-report.json", (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())):
                        evidence.unchanged()
                        target = core.inside(output, name)
                        # Stage complete bytes, then install exclusively and atomically.
                        # JSON is the commit marker and is always installed last.
                        with tempfile.NamedTemporaryFile(dir=output, prefix=".publication-", delete=False) as handle:
                            staged = Path(handle.name)
                            try:
                                handle.write(payload)
                                handle.flush()
                                os.fsync(handle.fileno())
                                if name == "security-report.json":
                                    validate_published(base, value)
                                    evidence.unchanged()
                                os.link(staged, target)
                                created.append(target)
                            finally:
                                staged.unlink()
                    read_publication(base, expected_kind="advantage", validate_evidence=True)
                except BaseException:
                    if not (output / "security-report.json").exists():
                        for path in reversed(created):
                            path.unlink()
                    raise
            return {"run_id": value["run_id"], "status": "validated" if check else "complete",
                    "counts": value["counts"], "unconfirmed": len(value["unconfirmed"]),
                    "report": None if check else str(base / "report/security-report.json"),
                    "limitations": value["assessment"]["limitations"]}
        finally:
            release_run(base, session)


def validate_published(base, report):
    binding = report["publication"]["retained_evidence"]
    if binding["ref"] != RECEIPT or core.sha256_file(core.inside(base, RECEIPT)) != binding["sha256"]:
        raise ValueError("retained publication receipt changed")
    receipt = document(base, RECEIPT)
    if (receipt["run_id"] != report["run_id"] or receipt["authority"] != "retained_independent_review_bindings"
            or receipt["native_acceptance_reconstructed"] is not False
            or receipt["published_at"] != report["publication"]["published_at"]
            or receipt["publication_id"] != report["assessment"]["publication_attempt_id"]):
        raise ValueError("retained publication identity differs")
    evidence = RetainedEvidence(base, receipt["mode"]).validate()
    for row in receipt["inputs"]:
        if row["execution_id"] not in evidence.roots:
            raise ValueError("retained receipt names unadmitted execution")
        if core.sha256_file(core.inside(evidence.roots[row["execution_id"]], _parts(row["artifact_ref"])[0])) != row["sha256"]:
            raise ValueError("retained publication evidence changed: " + row["artifact_ref"])
    expected = evidence.receipt(receipt["published_at"], receipt["publication_id"])
    if expected != receipt:
        raise ValueError("retained publication receipt omitted or changed its evidence closure")
    unconfirmed = [f for f in evidence.synthesis["findings"] if f["id"] in {row["finding_id"] for row in evidence.final["unconfirmed"]}]
    if report.get("unconfirmed_dossiers") != unconfirmed or report["unconfirmed"] != evidence.final["unconfirmed"]:
        raise ValueError("publication changed unconfirmed dossiers")
    projected = pipeline.report_projection(evidence.context)
    for key in ("findings", "links", "counts", "cohort_counts", "baseline_reconciliation", "objective_assessments", "historical_findings", "unresolved_applicability"):
        if report[key] != projected[key]:
            raise ValueError("retained report projection differs: " + key)
    assessment = report_assessment(evidence.context, [*report["findings"], *unconfirmed])
    assessment.update(publication_attempt_id=receipt["publication_id"], retained=True)
    if report["assessment"] != assessment:
        raise ValueError("publication changed retained assessment scope")
    pipeline.schema(report, "report", evidence.context)
