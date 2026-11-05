"""Phase-owned, immutable Intrusion waves and source-backed transition obligations."""
from __future__ import annotations
import hashlib
import json
import os
import tempfile
from pathlib import Path
from model_identity import validate_provenance, contributor_union
from evidence_refs import EvidenceIssue, artifact_value
from evidence_accounting import classify_refs, summarize, validate_non_promoted, effective_support
from objective_contract import validate_binding, validate_registry
from run_lifecycle import assessment_ref, current_assessment, run_status

OBLIGATIONS = ("producer_grant", "actor_control", "scope_alignment", "control_preservation", "consumer_authority", "intervening_controls", "conditions_compatible")
OUTCOMES = {"established", "contradicted", "locally_unresolved", "externally_blocked", "budget_deferred", "execution_failed"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def artifact(scan, ref):
    relative = ref
    path = Path(relative)
    if not relative or path.is_absolute() or ".." in path.parts or "\\" in relative or ":" in relative or "#" in relative:
        raise ValueError("unsafe intrusion artifact reference")
    result = Path(scan).resolve() / path
    if result.resolve() != result or not result.is_file():
        raise ValueError("missing or redirected intrusion artifact: " + ref)
    return result


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def require_active(scan, context):
    run = load(artifact(scan, "run-manifest.json"))
    if run.get("run_id") != context.get("run_id") or run_status(run.get("status")) != "incomplete" or run.get("phases", {}).get("intrusion") != "running":
        raise ValueError("Intrusion publications require the active owning phase")


def publish(path, document):
    """Publish once, atomically; an identical retry is safe, a conflict never is."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.resolve() != path.parent.absolute():
        raise ValueError("snapshot directory may not redirect")
    raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".wave-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != raw:
                raise ValueError("immutable intrusion publication conflicts: " + str(path)) from None
    finally:
        os.unlink(temporary)


def refs_exist(scan, refs, *, allow_local=False):
    if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs):
        raise ValueError("source-established evidence requires artifact references")
    for ref in refs:
        try:
            artifact_value(Path(scan), ref)
        except EvidenceIssue:
            if not allow_local:
                raise


def resolution(scan, value, *, allow_local=False):
    if not isinstance(value, dict) or value.get("outcome") not in OUTCOMES:
        raise ValueError("missing exact investigation resolution")
    if not all(isinstance(value.get(key), str) for key in ("reason", "next_action", "missing_fact")) or not value["reason"].strip():
        raise ValueError("resolution requires reason, next action and missing fact")
    if value["outcome"] in {"established", "contradicted"}:
        refs_exist(scan, value.get("evidence_refs"), allow_local=allow_local)
    elif value["outcome"] == "externally_blocked" and not value["missing_fact"].strip():
        raise ValueError("external blocker requires exact missing fact")
    elif value["outcome"] in {"locally_unresolved", "budget_deferred", "execution_failed"} and not value["next_action"].strip():
        raise ValueError("unresolved work requires an actionable checkpoint")
    for ref in value.get("evidence_refs", []):
        refs_exist(scan, [ref], allow_local=allow_local)


def validate_transitions(scan, target, primitive_ids, transitions, primitives, require_established=True):
    """Validate explicit proof, not prose equality; source claims remain investigator judgments."""
    expected = list(zip(primitive_ids, primitive_ids[1:]))
    if [(t.get("producer_id"), t.get("consumer_id")) for t in transitions] != expected:
        raise ValueError("transitions must cover the effective sequence exactly in order")
    for transition in transitions:
        resolution(scan, transition.get("resolution"))
        established = transition["resolution"]["outcome"] == "established"
        if require_established and not established:
            raise ValueError("confirmed chain has an unresolved transition")
        for pid in (transition["producer_id"], transition["consumer_id"]):
            capability = primitives.get(pid, {}).get("capability", {})
            if established and capability.get("evidence_status") not in {"source_established", "experimentally_observed"}:
                raise ValueError("transition relies on an unestablished capability: " + pid)
        obligations = transition.get("obligations", {})
        if set(obligations) != set(OBLIGATIONS):
            raise ValueError("transition lacks semantic proof obligations")
        for proof in obligations.values():
            if proof.get("outcome") not in {"established", "contradicted", "locally_unresolved", "externally_blocked"} or not str(proof.get("reason", "")).strip():
                raise ValueError("invalid transition obligation disposition")
            if established and proof["outcome"] != "established":
                raise ValueError("established transition contains an incompatible or unresolved obligation")
            if proof["outcome"] in {"established", "contradicted"}:
                refs_exist(scan, proof.get("evidence_refs"))
                if not proof.get("source_locations"):
                    raise ValueError("semantic transition proof requires inspected source")
            for location in proof.get("source_locations", []):
                relative = Path(location["file"])
                path = Path(target).resolve() / relative
                if relative.is_absolute() or ".." in relative.parts or not path.is_file() or not path.resolve().is_relative_to(Path(target).resolve()):
                    raise ValueError("transition source escapes authorized namespace")
                start, end = location["start_line"], location["end_line"]
                if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(path.read_text(encoding="utf-8").splitlines()):
                    raise ValueError("invalid transition source range")


def primitive_id(primitive):
    # Identity follows the observation and scope, never its discovering worker.
    capability = {key: value for key, value in primitive.get("capability", {}).items() if key not in {"provenance", "evidence_status"}}
    return "NP-" + digest({"type": primitive.get("type"), "capability": capability, "boundary": primitive.get("boundary")})[:12].upper()


def binding(scan, context):
    return {"run_id": context["run_id"],
            "plan_sha256": hashlib.sha256(artifact(scan, "campaign-planning/campaign-plan.json").read_bytes()).hexdigest(),
            "evidence_index_sha256": hashlib.sha256(artifact(scan, "campaign-planning/evidence-index.json").read_bytes()).hexdigest()}


def snapshot_ref(wave):
    return f"intrusion/waves/{wave:03d}.json"


def reference_keys(refs):
    """Compare already validated artifact references independently of delimiter."""
    return {ref.replace("#", ":", 1) for ref in refs}


def objective_registry(scan, context, document):
    return validate_registry(
        document["attack_objectives"], document["investigation_questions"])


def assignment_bindings(assignments, objectives, questions):
    owners = set()
    for assignment in assignments.values():
        pair = assignment["objective_id"], assignment["question_id"]
        validate_binding(assignment, objectives, questions)
        if pair in owners or questions[pair[1]].get("equivalent_to"):
            raise ValueError("objective/question has duplicate active ownership")
        owners.add(pair)


def prior_result_refs(refs, published, owner=None):
    for ref in refs:
        path = ref.split("#", 1)[0].split(":", 1)[0]
        if path.startswith("intrusion/results/") and path not in published and path != owner:
            raise ValueError("evidence uses an unvalidated peer result")


def continuation_record(scan, context, initial, results, prior, proposal, wave, objectives, questions, *, historical=False):
    from codegraph_contract import _schema
    _schema(proposal, "intrusion-results.schema.json", "continuationProposal")
    required = {"parent_campaign", "objective_id", "question_id", "attack_objectives", "investigation_questions",
                "triggering_evidence", "changed_hypothesis", "next_question", "evidence_delta",
                "alternative_path", "resource_allocation"}
    if set(proposal) != required or proposal["parent_campaign"] not in initial:
        raise ValueError("continuation lacks an attributable stable objective checkpoint")
    refs_exist(scan, proposal["triggering_evidence"])
    published = {record["ref"] for record in results.values()}
    prior_result_refs(proposal["triggering_evidence"] + proposal["evidence_delta"], published)
    supported = set(published)
    for record in results.values():
        result = load(artifact(scan, record["ref"]))
        supported.update(result["evidence_refs"])
        for primitive in result["primitive_updates"]:
            supported.update(primitive["evidence_refs"])
    if not reference_keys(proposal["triggering_evidence"]).issubset(reference_keys(supported)) or not reference_keys(proposal["evidence_delta"]).issubset(reference_keys(supported)):
        raise ValueError("continuation delta is not attributable to validated prior results")
    if not proposal["changed_hypothesis"].strip() or not proposal["next_question"].strip() or proposal["resource_allocation"] != 1:
        raise ValueError("continuation requires hypothesis, next obligation and one budget unit")
    previous = [c for c in prior if c["parent_campaign"] == proposal["parent_campaign"]]
    old_refs = reference_keys(ref for c in previous for ref in c["evidence_delta"])
    new_evidence = reference_keys(proposal["evidence_delta"]) - old_refs
    new_question = proposal["next_question"].strip().casefold() not in {c["next_question"].strip().casefold() for c in previous}
    if not new_evidence and not (new_question and proposal["alternative_path"].strip()):
        raise ValueError("continuation has no evidence delta or justified newly actionable alternative")
    inherited_objectives, inherited_questions = objectives, questions
    objectives, questions = validate_registry(
        proposal["attack_objectives"], proposal["investigation_questions"],
        inherited_objectives=inherited_objectives, inherited_questions=inherited_questions,
        scan=Path(scan), target=None if historical else Path(context.get("source_root") or context["repo_path"]),
        repositories=context["repositories"])
    parent_objectives = {initial[proposal["parent_campaign"]]["objective_id"],
                         *(c["objective_id"] for c in previous)}
    parent_objectives = {identity for identity in parent_objectives
                         if objectives[identity]["owner"] != snapshot_ref(wave)}
    for definition in [*proposal["attack_objectives"], *proposal["investigation_questions"]]:
        prior_result_refs(definition["evidence_refs"], published)
        if definition["id"] in inherited_objectives or definition["id"] in inherited_questions:
            raise ValueError("continuation registrations must be new, not inherited definitions")
        if definition["owner"] != snapshot_ref(wave):
            raise ValueError("new objective/question must belong to its dispatch snapshot")
        if not reference_keys(definition["evidence_refs"]).intersection(reference_keys(proposal["triggering_evidence"])):
            raise ValueError("new objective/question lacks its validated triggering evidence")
    for objective in proposal["attack_objectives"]:
        if objective.get("parent_objective_id") not in parent_objectives:
            raise ValueError("changed goal requires an inherited parent objective")
    if proposal["objective_id"] not in parent_objectives and proposal["objective_id"] not in {o["id"] for o in proposal["attack_objectives"]}:
        raise ValueError("changed goal requires a newly registered objective")
    if {o["id"] for o in proposal["attack_objectives"]} - {proposal["objective_id"]} or {q["id"] for q in proposal["investigation_questions"]} - {proposal["question_id"]}:
        raise ValueError("new registrations must bind the continuation assignment")
    assignment_bindings({"proposal": proposal}, objectives, questions)
    cid = proposal["parent_campaign"] + "-C" + digest(proposal)[:12].upper()
    if any(c["id"] == cid for c in prior):
        raise ValueError("continuation already has an owner")
    return {**proposal, "id": cid, "graph_questions": []}, objectives, questions


def allocation_deferral(assignment):
    return {"objective_id": assignment["objective_id"], "question_id": assignment["question_id"],
            "parent_campaign": assignment["id"], "outcome": "budget_deferred",
            "reason": "Current allocation exhausted after retained consumed work.",
            "next_action": assignment.get("next_question") or assignment.get("hypothesis") or
                           "Review this retained question in a future authorized allocation."}


def read_snapshot(scan, context, reference, *, _snapshots=None):
    # Only this traversal populates the map; never reuse it across validation calls.
    path = artifact(scan, reference["ref"])
    if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
        raise ValueError("worker snapshot hash mismatch")
    snapshot = load(path)
    expected_binding = binding(scan, context)
    if reference["ref"] != snapshot_ref(snapshot["wave"]) or any(
            snapshot["binding"].get(key) != value for key, value in expected_binding.items()):
        raise ValueError("worker snapshot run/plan identity mismatch")
    wave = snapshot["wave"]
    if type(wave) is not int or wave < 0:
        raise ValueError("invalid wave ordinal")
    plan = load(artifact(scan, "campaign-planning/campaign-plan.json"))
    initial = {c["id"]: c for c in plan["campaigns"]}
    objectives, questions = objective_registry(scan, context, plan)
    if wave == 0:
        deferred = {row["parent_campaign"] for row in snapshot.get("allocation_deferrals", [])}
        if snapshot["previous"] is not None or snapshot["assignments"] != {key: value for key, value in initial.items() if key not in deferred} or not deferred.issubset(initial) or snapshot["results"] or snapshot["primitives"] or snapshot["continuations"]:
            raise ValueError("initial wave differs from immutable campaign plan")
        if any(snapshot[key] != plan[key] for key in ("attack_objectives", "investigation_questions")):
            raise ValueError("initial wave changes inherited objective definitions")
        assignment_bindings(snapshot["assignments"], objectives, questions)
        if _snapshots is not None:
            _snapshots[wave] = snapshot
        return snapshot
    if snapshot["previous"]["ref"] != snapshot_ref(wave - 1):
        raise ValueError("wave ancestry must be contiguous")
    previous = read_snapshot(scan, context, snapshot["previous"], _snapshots=_snapshots)
    objectives, questions = objective_registry(scan, context, previous)
    prior_deferrals = previous.get("allocation_deferrals", [])
    if snapshot.get("allocation_deferrals", [])[:len(prior_deferrals)] != prior_deferrals:
        raise ValueError("wave mutates prior allocation deferrals")
    newly_deferred = {row["parent_campaign"] for row in snapshot.get("allocation_deferrals", [])[len(prior_deferrals):]}
    carried = {key: value for key, value in snapshot["assignments"].items() if key in previous["assignments"]}
    closed = set(previous["assignments"]) - set(carried) - newly_deferred
    if not previous["assignments"] or set(snapshot["results"]) != set(previous["results"]) | closed:
        raise ValueError("wave must account for exactly its preceding assignments")
    if any(value != previous["assignments"][key] for key, value in carried.items()):
        raise ValueError("wave changes carried assignment ownership")
    if any(snapshot["results"].get(owner) != record for owner, record in previous["results"].items()):
        raise ValueError("wave mutates prior result ownership")
    primitives = {p["id"]: p for p in previous["primitives"]}
    for owner in closed:
        record = snapshot["results"][owner]
        result_path = artifact(scan, record["ref"])
        if record["ref"] != f"intrusion/results/{owner}.json" or hashlib.sha256(result_path.read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError("validated result changed after wave publication")
        result = load(result_path)
        if result["campaign_id"] != owner or result["input_snapshot"] != snapshot["previous"]:
            raise ValueError("result is not bound to its preceding assignment")
        assignment = previous["assignments"][owner]
        if any(result.get(key) != assignment[key] for key in ("objective_id", "question_id")):
            raise ValueError("retained result changes its assigned objective/question binding")
        for primitive in result["primitive_updates"]:
            if primitive["id"] != primitive_id(primitive):
                raise ValueError("retained primitive changes its observation identity")
            primitives[primitive["id"]] = primitive
    if {p["id"] for p in snapshot["primitives"]} != set(primitives):
        raise ValueError("wave primitives are not the validated result union")
    for primitive in snapshot["primitives"]:
        observed = primitives[primitive["id"]]
        comparable = {key: value for key, value in primitive.items() if key != "assessment_context"}
        original = {key: value for key, value in observed.items() if key != "assessment_context"}
        limited = {**original, "trust": "candidate", "capability": {
            **original["capability"], "evidence_status": "hypothesized"}}
        if comparable not in (original, limited):
            raise ValueError("wave mutates a validated primitive observation")
    prior = previous["continuations"]
    if snapshot["continuations"][:len(prior)] != prior:
        raise ValueError("continuation ancestry mismatch")
    added = snapshot["continuations"][len(prior):]
    reconstructed = list(prior)
    for continuation in added:
        proposal = {k: v for k, v in continuation.items() if k not in {"id", "graph_questions"}}
        expected, objectives, questions = continuation_record(
            scan, context, initial, snapshot["results"], reconstructed, proposal, wave, objectives, questions,
            historical=True)
        if continuation != expected:
            raise ValueError("continuation identity differs from attributable proposal")
        reconstructed.append(expected)
    if snapshot["attack_objectives"] != list(objectives.values()) or snapshot["investigation_questions"] != list(questions.values()):
        raise ValueError("snapshot changes inherited objective/question definitions")
    assignment_bindings(snapshot["assignments"], objectives, questions)
    if snapshot["assignments"] != {**carried, **{c["id"]: c for c in added}}:
        raise ValueError("continuation has missing or duplicate active ownership")
    if _snapshots is not None:
        _snapshots[wave] = snapshot
    return snapshot


def reference(scan, snapshot):
    ref = snapshot_ref(snapshot["wave"])
    return {"ref": ref, "sha256": hashlib.sha256(artifact(scan, ref).read_bytes()).hexdigest()}


def evidence_limited_ids(scan, context, result):
    rows = result.get("non_promoted", [])
    ids = [row["id"] for row in rows]
    allowed = {result["campaign_id"], *(p["id"] for p in result.get("primitive_updates", [])),
               *(c["id"] for c in result.get("candidates", []))}
    if len(ids) != len(set(ids)) or not set(ids).issubset(allowed):
        raise ValueError("non-promoted Intrusion items must have unique local ownership")
    for row in rows:
        expected_ref = f"intrusion/results/{result['campaign_id']}.json:{row['id']}"
        if row.get("input_refs") != [expected_ref]:
            raise ValueError("non-promoted Intrusion item must cite its exact owned record")
        validate_non_promoted(row, context["model_routing"], Path(scan),
                              Path(context.get("source_root") or context["repo_path"]),
                              context["repositories"], actor="vulnops-intrusion-campaign")
    return set(ids)


def result_support_view(scan, context, result, diagnostics=None):
    limited = evidence_limited_ids(scan, context, result)
    source = Path(context.get("source_root") or context["repo_path"])
    def project(node, identifier):
        if identifier in limited:
            return dict(node)
        return effective_support(Path(scan), source, context["repositories"], node, diagnostics)
    view = project(result, result["campaign_id"])
    view["candidates"] = [project(item, item["id"]) for item in result["candidates"]]
    view["primitive_updates"] = [project(item, item["id"]) for item in result["primitive_updates"]]
    return view


def primitive_updates_view(scan, context, result):
    limited = evidence_limited_ids(scan, context, result)
    source = Path(context.get("source_root") or context["repo_path"])
    return [({**item, "trust": "candidate", "capability": {
        **item["capability"], "evidence_status": "hypothesized"}} if item["id"] in limited else
        effective_support(Path(scan), source, context["repositories"], item))
        for item in result["primitive_updates"]]


def result_evidence_diagnostics(scan, target, context, result, *, _snapshot=None, historical=False):
    """Declared proof fields only; descriptive extension strings are inert."""
    if historical:
        return []
    diagnostics = []
    result = result_support_view(scan, context, result, diagnostics)
    groups = [(result["campaign_id"], result, "result"),
              (result["campaign_id"], result["resolution"], "resolution"),
              (result["campaign_id"], result["composition"], "composition")]
    for candidate in result.get("candidates", []):
        groups.append((candidate["id"], candidate, "candidates." + candidate["id"]))
        for index, transition in enumerate(candidate.get("transitions", [])):
            prefix = f"candidates.{candidate['id']}.transitions[{index}]"
            groups.append((candidate["id"], transition.get("resolution", {}), prefix + ".resolution"))
            groups.extend((candidate["id"], proof, prefix + "." + name)
                          for name, proof in transition.get("obligations", {}).items())
    for primitive in result.get("primitive_updates", []):
        groups.append((primitive["id"], primitive, "primitive_updates." + primitive["id"]))
        groups.append((primitive["id"], {"evidence_refs": primitive.get("capability", {}).get("provenance", [])},
                       "primitive_updates." + primitive["id"] + ".capability.provenance"))
    snapshot = _snapshot if _snapshot is not None else read_snapshot(scan, context, result["input_snapshot"])
    published = {record["ref"] for record in snapshot["results"].values()}
    for identifier, node, field in groups:
        prior_result_refs(node.get("evidence_refs", []), published, f"intrusion/results/{result['campaign_id']}.json")
        _, issues = classify_refs(Path(scan), Path(target), context["repositories"], node.get("evidence_refs", []),
                                  owner=f"intrusion/results/{result['campaign_id']}.json", field=field,
                                  affected_item_ids=[identifier], kind="artifact")
        diagnostics.extend(issues)
        for index, location in enumerate(node.get("source_locations", [])):
            ref = f"{location['file']}:{location['start_line']}-{location['end_line']}"
            _, issues = classify_refs(Path(scan), Path(target), context["repositories"], [ref],
                                      owner=f"intrusion/results/{result['campaign_id']}.json",
                                      field=f"{field}.source_locations[{index}]",
                                      affected_item_ids=[identifier], kind="source")
            diagnostics.extend(issues)
    return diagnostics


def available_primitives(scan, context, index, result, *, _snapshot=None):
    snapshot = _snapshot if _snapshot is not None else read_snapshot(scan, context, result["input_snapshot"])
    owner = result["campaign_id"]
    if owner not in snapshot["assignments"] or result.get("wave") != snapshot["wave"]:
        raise ValueError("result is not owned by its assigned input wave")
    known = {p["id"]: p for p in index.get("primitives", [])}
    known.update({p["id"]: p for p in snapshot["primitives"]})
    # Prior observations are questions, not grants of current attacker authority.
    for identity, primitive in list(known.items()):
        if not current_assessment(primitive, context):
            known[identity] = {**primitive, "trust": "candidate", "capability": {
                **primitive["capability"], "evidence_status": "hypothesized"}}
    provenance = validate_provenance(result.get("provenance"), context.get("model_routing") or {},
                                     "vulnops-intrusion-campaign", f"intrusion/results/{owner}.json")
    limited = evidence_limited_ids(scan, context, result)
    for update in primitive_updates_view(scan, context, result):
        if update["id"] != primitive_id(update):
            raise ValueError("new primitive identity must bind observation and scope")
        refs_exist(scan, update.get("evidence_refs"), allow_local=update["id"] in limited)
        refs_exist(scan, update.get("capability", {}).get("provenance"), allow_local=update["id"] in limited)
        references = reference_keys([*update["evidence_refs"], *update["capability"]["provenance"]])
        inherited = [item.get("contributors", []) for item in [*known.values(), *index.get("records", [])]
                     if references.intersection(reference_keys([
                         item.get("id", ""), item.get("artifact_ref", ""), *item.get("evidence_refs", []),
                         *(value["artifact_ref"] for value in item.get("contributors", []))]))]
        expected = contributor_union([provenance], *inherited)
        if update.get("contributors") != expected:
            raise ValueError("primitive contributors must preserve owner and relied-upon investigation provenance")
        if update["id"] in known and current_assessment(known[update["id"]], context) and known[update["id"]] != update:
            raise ValueError("conflicting primitive identity")
        known[update["id"]] = update
    return known


def validate_result(scan, target, context, index, result, *, _snapshot=None):
    # Internal callers may supply only an input wave already checked by read_snapshot.
    from codegraph_contract import _schema, validate_campaign_graph
    _schema(result, "intrusion-results.schema.json", "result")
    if context.get("attempt_id") and not current_assessment(result, context):
        raise ValueError("current worker result requires its assigned assessment attempt")
    snapshot = _snapshot if _snapshot is not None else read_snapshot(scan, context, result["input_snapshot"])
    known = available_primitives(scan, context, index, result, _snapshot=snapshot)
    assignment = snapshot["assignments"][result["campaign_id"]]
    if any(result[key] != assignment[key] for key in ("objective_id", "question_id")):
        raise ValueError("result changes its assigned objective/question binding")
    limited = evidence_limited_ids(scan, context, result)
    diagnostics = result_evidence_diagnostics(scan, target, context, result, _snapshot=snapshot)
    if any(row["disposition"] != "optional" and not set(row["affected_item_ids"]).issubset(limited) for row in diagnostics):
        raise ValueError("unusable Intrusion support requires targeted review or explicit local deferral")
    result = result_support_view(scan, context, result)
    resolution(scan, result["resolution"], allow_local=result["campaign_id"] in limited)
    outcome, status = result["resolution"]["outcome"], result["status"]
    if (status == "candidate") != bool(result["candidates"]):
        raise ValueError("candidate lifecycle disagrees with candidates")
    if status == "candidate" and outcome != "established" or status == "rejected" and outcome != "contradicted" or (status == "needs_environment") != (outcome == "externally_blocked"):
        raise ValueError("lifecycle disagrees with investigation resolution")
    for ref in result["evidence_refs"]:
        refs_exist(scan, [ref], allow_local=result["campaign_id"] in limited)
    validate_campaign_graph(Path(scan), Path(target), context, assignment, result)
    for candidate in result["candidates"]:
        if any(candidate[key] != assignment[key] for key in ("objective_id", "question_id")):
            raise ValueError("candidate changes its assigned objective/question binding")
        if any(pid not in known for pid in candidate["primitive_ids"]):
            raise ValueError("candidate uses an unvalidated peer primitive")
        refs_exist(scan, candidate["evidence_refs"], allow_local=candidate["id"] in limited)
        original = {p["id"] for p in index.get("primitives", [])}
        own = {p["id"] for p in result["primitive_updates"]}
        for pid in set(candidate["primitive_ids"]) - original - own:
            owners = [record["ref"] for record in snapshot["results"].values()
                      if any(p["id"] == pid for p in load(artifact(scan, record["ref"]))["primitive_updates"])]
            if not reference_keys([*owners, *(f"{owner}:{pid}" for owner in owners)]).intersection(reference_keys(candidate["evidence_refs"])):
                raise ValueError("cross-campaign capability requires its owning result reference")
        trace = candidate["trace"]
        if not trace or trace[0]["kind"] != "entrypoint" or trace[-1]["kind"] != "sink" or any(t["kind"] != "propagation" for t in trace[1:-1]):
            raise ValueError("candidate trace must be ordered entrypoint to sink")
        for location in [*candidate["root_causes"], *trace]:
            path = Path(target).resolve() / location["file"]
            if not path.is_file() or not path.resolve().is_relative_to(Path(target).resolve()):
                raise ValueError("candidate source is outside authorized source")
        inherited = [item.get("contributors", []) for item in index.get("records", [])
                     if item.get("artifact_ref") in candidate["evidence_refs"] or item["id"] in candidate["evidence_refs"]]
        expected = contributor_union([result["provenance"]], *(known[pid].get("contributors", []) for pid in candidate["primitive_ids"]), *inherited)
        if candidate.get("contributors") != expected:
            raise ValueError("candidate contributors must preserve owner and primitive investigation provenance")
        if candidate["id"] in limited:
            continue
        if candidate["validation_level"] == "environment_required":
            raise ValueError("unresolved environment is not a candidate")
        if candidate["finding_kind"] == "chain":
            if len(candidate["primitive_ids"]) < 2:
                raise ValueError("chain requires at least two primitives")
            validate_transitions(scan, target, candidate["primitive_ids"], candidate["transitions"], known)
        elif candidate["transitions"]:
            raise ValueError("non-chain candidate may not claim transitions")
    decision = result["composition"]
    if not decision["reason"].strip() or any(pid not in known for pid in decision["primitive_ids"]):
        raise ValueError("composition decision lacks accountable primitive scope")
    for ref in decision["evidence_refs"]:
        refs_exist(scan, [ref], allow_local=result["campaign_id"] in limited)
    if result["primitive_updates"] and not set(p["id"] for p in result["primitive_updates"]).issubset(decision["primitive_ids"]):
        raise ValueError("composition decision must account for every new observation")
    return known


def build_wave(scan, target, context, completed=(), proposals=()):
    """One coordinator publishes a complete prior-wave view before dispatching work."""
    scan = Path(scan)
    require_active(scan, context)
    index = load(artifact(scan, "campaign-planning/evidence-index.json"))
    paths = sorted((scan / "intrusion/waves").glob("[0-9][0-9][0-9].json"))
    if not paths:
        if completed or proposals:
            raise ValueError("initialize the immutable wave before consuming results")
        plan = load(artifact(scan, "campaign-planning/campaign-plan.json"))
        snapshot = {"schema_version": "2.0", "wave": 0, "binding": binding(scan, context), "previous": None, "assignments": {c["id"]: c for c in plan["campaigns"]}, "results": {}, "primitives": [], "continuations": []}
        snapshot["continuation_rounds_used"] = 0
        from campaign_contract import BUDGETS
        limit = BUDGETS.get(context.get("depth"), plan["budget"])["max_campaigns"]
        deferred = plan["campaigns"][limit:]
        snapshot["assignments"] = {c["id"]: c for c in plan["campaigns"][:limit]}
        if deferred:
            snapshot["allocation_deferrals"] = [allocation_deferral(c) for c in deferred]
        if assessment_ref(context):
            snapshot["assessment_context"] = assessment_ref(context)
        objectives, questions = objective_registry(scan, context, plan)
        assignment_bindings(snapshot["assignments"], objectives, questions)
        snapshot.update(attack_objectives=plan["attack_objectives"], investigation_questions=plan["investigation_questions"])
    else:
        previous = load(paths[-1])
        previous = read_snapshot(scan, context, reference(scan, previous))
        if not completed and not proposals:
            from campaign_contract import BUDGETS
            plan = load(artifact(scan, "campaign-planning/campaign-plan.json"))
            limit = BUDGETS.get(context.get("depth"), plan["budget"])["max_campaigns"]
            initial = {c["id"] for c in plan["campaigns"]}
            remaining = max(0, limit - len(set(previous["results"]) & initial))
            continuation_remaining = max(0, context["intrusion_budget"]["continuation_tasks"] -
                                         len(set(previous["results"]) - initial))
            kept, deferred = {}, []
            for owner, assignment in previous["assignments"].items():
                capacity = remaining if owner in initial else continuation_remaining
                if capacity > 0:
                    kept[owner] = assignment
                    if owner in initial:
                        remaining -= 1
                    else:
                        continuation_remaining -= 1
                else:
                    deferred.append(allocation_deferral(assignment))
            if not deferred:
                return previous
            snapshot = {**previous, "wave": previous["wave"] + 1,
                        "previous": reference(scan, previous), "assignments": kept,
                        "allocation_deferrals": [*previous.get("allocation_deferrals", []), *deferred]}
            if assessment_ref(context):
                snapshot["assessment_context"] = assessment_ref(context)
            publish(scan / snapshot_ref(snapshot["wave"]), snapshot)
            return snapshot
        if completed and previous["previous"]:
            prior_wave = read_snapshot(scan, context, previous["previous"])
            registered = [{k: v for k, v in c.items() if k not in {"id", "graph_questions"}}
                          for c in previous["continuations"][len(prior_wave["continuations"]):]]
            if sorted(completed) == sorted(prior_wave["assignments"]) and list(proposals) == registered:
                return previous
        if not previous["assignments"]:
            if completed or proposals:
                raise ValueError("closed Intrusion wave cannot schedule new work")
            return previous
        if set(completed) != set(previous["assignments"]) or len(completed) != len(set(completed)):
            raise ValueError("wave publication requires every assigned terminal owner exactly once")
        snapshot = {**previous, "wave": previous["wave"] + 1, "previous": reference(scan, previous), "assignments": {}, "results": dict(previous["results"]), "primitives": list(previous["primitives"]), "continuations": list(previous["continuations"])}
        if assessment_ref(context):
            snapshot["assessment_context"] = assessment_ref(context)
        primitives = {p["id"]: p for p in snapshot["primitives"]}
        for owner in sorted(completed):
            ref = f"intrusion/results/{owner}.json"
            result = load(artifact(scan, ref))
            if result.get("campaign_id") != owner or result.get("input_snapshot") != reference(scan, previous):
                raise ValueError("worker result does not bind the completed wave")
            validate_result(scan, target, context, index, result, _snapshot=previous)
            snapshot["results"][owner] = {"ref": ref, "sha256": hashlib.sha256(artifact(scan, ref).read_bytes()).hexdigest()}
            if assessment_ref(context):
                snapshot["results"][owner]["assessment_context"] = assessment_ref(context)
            for primitive in primitive_updates_view(scan, context, result):
                if assessment_ref(context):
                    primitive = {**primitive, "assessment_context": assessment_ref(context)}
                if primitive["id"] in primitives and current_assessment(primitives[primitive["id"]], context) and primitives[primitive["id"]] != primitive:
                    raise ValueError("conflicting duplicate primitive observations")
                primitives[primitive["id"]] = primitive
        snapshot["primitives"] = [primitives[key] for key in sorted(primitives)]
        budget = context["intrusion_budget"]
        available = max(0, budget["continuation_tasks"] - len(snapshot["continuations"]))
        rounds_used = previous.get("continuation_rounds_used", previous["wave"])
        if rounds_used >= budget["continuation_rounds"]:
            available = 0
        initial = {c["id"]: c for c in load(artifact(scan, "campaign-planning/campaign-plan.json"))["campaigns"]}
        objectives, questions = objective_registry(scan, context, previous)
        for proposal in proposals:
            if len(snapshot["assignments"]) >= available:
                snapshot.setdefault("allocation_deferrals", []).append({
                    "objective_id": proposal["objective_id"], "question_id": proposal["question_id"],
                    "parent_campaign": proposal["parent_campaign"], "outcome": "budget_deferred",
                    "reason": "Current continuation allocation is exhausted; retained work consumes the allowance.",
                    "next_action": proposal["next_question"]})
                continue
            continuation, objectives, questions = continuation_record(
                scan, context, initial, snapshot["results"], snapshot["continuations"], proposal,
                snapshot["wave"], objectives, questions)
            snapshot["continuations"].append(continuation)
            snapshot["assignments"][continuation["id"]] = continuation
        snapshot["continuation_rounds_used"] = rounds_used + int(bool(snapshot["assignments"]))
        assignment_bindings(snapshot["assignments"], objectives, questions)
        snapshot.update(attack_objectives=list(objectives.values()), investigation_questions=list(questions.values()))
    publish(scan / snapshot_ref(snapshot["wave"]), snapshot)
    return snapshot


def validate_intrusion(scan, target, context, index, wrapper):
    paths = sorted((Path(scan) / "intrusion/waves").glob("[0-9][0-9][0-9].json"))
    if not paths:
        raise ValueError("Intrusion requires its immutable wave authority")
    if index != load(artifact(scan, "campaign-planning/evidence-index.json")):
        raise ValueError("Intrusion evidence index differs from canonical authority")
    latest = load(paths[-1])
    snapshots = {}
    latest = read_snapshot(scan, context, reference(scan, latest), _snapshots=snapshots)
    if [path.name for path in paths] != [f"{wave:03d}.json" for wave in range(latest["wave"] + 1)]:
        raise ValueError("Intrusion wave files must be exactly contiguous")
    if {p.stem for p in (Path(scan) / "intrusion/results").glob("*.json")} != set(latest["results"]):
        raise ValueError("Intrusion contains missing or orphan result ownership")
    if latest["assignments"]:
        raise ValueError("Intrusion has undisposed active assignments")
    if any(wrapper.get(key) != latest[key] for key in ("attack_objectives", "investigation_questions")):
        raise ValueError("Intrusion aggregate differs from immutable objective/question registry")
    if wrapper.get("allocation_deferrals", []) != latest.get("allocation_deferrals", []):
        raise ValueError("aggregate changes allocation deferrals")
    results = wrapper.get("results", [])
    if len(results) != len(latest["results"]) or {r["campaign_id"] for r in results} != set(latest["results"]):
        raise ValueError("Intrusion aggregate does not cover all immutable result owners")
    for result in results:
        record = latest["results"][result["campaign_id"]]
        published = artifact(scan, record["ref"]).read_bytes()
        expected = json.loads(published)
        if record.get("assessment_context"):
            expected = {**expected, "assessment_context": record["assessment_context"]}
            expected["candidates"] = [{**candidate, "assessment_context": record["assessment_context"]}
                                      for candidate in expected["candidates"]]
        if hashlib.sha256(published).hexdigest() != record["sha256"] or result != expected:
            raise ValueError("aggregate differs from validated worker publication")
        # Ancestry traversal already validated this exact hash-bound publication.
    if not composition_resolved(wrapper):
        raise ValueError("actionable composition lacks a goal-bound continuation or explicit deferral")
    expected_quality = summarize([issue for result in results
                                  for issue in result_evidence_diagnostics(
                                      scan, target, context, result, _snapshot=snapshots[result["wave"]],
                                      historical=not current_assessment(result, context))])
    if wrapper.get("evidence_quality", summarize([])) != expected_quality:
        raise ValueError("Intrusion evidence-quality accounting differs from worker publications")
    return latest


def composition_resolved(wrapper):
    results = wrapper.get("results", [])
    objectives = {objective["id"]: objective for objective in wrapper.get("attack_objectives", [])}
    deferred = {(row["parent_campaign"], row["objective_id"]) for row in wrapper.get("allocation_deferrals", [])}
    return all(r.get("composition", {}).get("outcome") in {"none_actionable", "resolved", "deferred"} or
               r.get("composition", {}).get("outcome") == "continuation" and (
               (r["campaign_id"], r["objective_id"]) in deferred or
               any(other["wave"] > r["wave"] and
                   other["campaign_id"].split("-C", 1)[0] == r["campaign_id"].split("-C", 1)[0] and
                   (other["objective_id"] == r["objective_id"] or
                    objectives.get(other["objective_id"], {}).get("parent_objective_id") == r["objective_id"])
                   for other in results))
               for r in results)
