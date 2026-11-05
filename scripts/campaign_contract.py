"""Deterministic, source-first campaign discovery and selection authority."""
from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
import hashlib
from itertools import combinations
from pathlib import Path

from codegraph_contract import (_load, _schema, resolve_subject,
                               validate_graph_answers, validate_query_receipt)
from evidence_accounting import classify_refs, summarize
from objective_contract import load_registry, validate_registry
from run_lifecycle import assessment_ref, current_assessment

BUDGETS = {depth: {"max_campaigns": count} for depth, count in
           (("quick", 4), ("balanced", 10), ("full", 20))}
DISCOVERY_BUDGETS = {depth: {"questions": q, "query_seconds": seconds, "pairs": pairs}
                     for depth, q, seconds, pairs in (("quick", 4, 120, 32), ("balanced", 8, 240, 64), ("full", 12, 360, 128))}


def priority(record):
    return record.get("risk_context", {}).get("priority", 3)


def fair_questions(records):
    """Risk precedes actor/subsystem fairness; citation quality is not a rank."""
    bands = defaultdict(lambda: defaultdict(list))
    for rec in sorted(records, key=lambda row: row["id"]):
        actor = rec.get("risk_context", {}).get("actor", "")
        scope = tuple(rec.get("subsystems", [])) or tuple(str(Path(f).parent) for f in rec["files"][:1])
        bands[priority(rec)][(actor, scope)].append(rec)
    return [rec for band in sorted(bands) for rec in round_robin(bands[band])]


def stable(prefix: str, *parts: str) -> str:
    return prefix + hashlib.sha256("\0".join(parts).encode()).hexdigest()[:12].upper()


def round_robin(groups):
    pending = deque(iter(groups[key]) for key in sorted(groups))
    while pending:
        items = pending.popleft()
        try:
            yield next(items)
            pending.append(items)
        except StopIteration:
            pass


def repository_for(file: str, context: dict) -> str:
    prefixes = sorted((r["path"] for r in context.get("repositories", []) if r.get("path") != "."), key=len, reverse=True)
    return next((prefix for prefix in prefixes if file.startswith(prefix + "/")), ".")


def graph_question(record: dict, project: Path, intent: str | None = None) -> dict | None:
    operation = intent or ("callees" if record.get("source_kind") == "recon" or any(a.get("entrypoint_id") for a in record.get("source_anchors", [])) else "callers")
    reasons = {"callers": "Inspect inbound callers, attacker access and alternate guards.",
               "callees": "Inspect outbound input propagation and alternate controls.",
               "impact": "Inspect dependent consumers of the cited capability.",
               "query": "Resolve a concrete source symbol before following its flow.",
               "affected": "Identify tests exercising the explicitly selected changed component."}
    for file in record.get("files", []):
        symbol = record.get("symbol") or next((a["symbol"] for a in record.get("source_anchors", []) if a.get("file") == file and a.get("symbol")), None)
        subject = symbol if operation == "query" else file
        if not subject:
            continue
        try:
            resolve_subject(operation, subject, project)
        except (ValueError, OSError):
            continue
        return {"type": operation, "subject": subject, "reason": reasons[operation]}
    return None


def actionable(index):
    records = {rec["id"]: rec for rec in index["records"]}
    return sorted((p for p in index["primitives"]
                   if p.get("capability", {}).get("evidence_status") != "contradicted"
                   and any(records[rid]["files"] for rid in p["source_record_ids"])),
                  key=lambda p: (min(priority(records[rid]) for rid in p["source_record_ids"]), p["id"]))


def prepare_discovery(scan: Path, context: dict, index: dict) -> dict:
    depth = context["depth"]
    budget = DISCOVERY_BUDGETS[depth]
    records = {r["id"]: r for r in index["records"]}
    seeds = defaultdict(list)
    for rec in fair_questions(records.values()):
        if rec["files"] and rec["disposition"] not in {"closed", "rejected"}:
            key = (rec["source_kind"] in {"sca", "secret"}, repository_for(rec["files"][0], context), next(iter(rec.get("subsystems", [])), str(Path(rec["files"][0]).parent)))
            seeds[key].append(rec)
    questions = []
    enabled = context.get("codegraph_mode") == "enabled"
    project = Path(context.get("paths", {}).get("codegraph_project", "/nonexistent"))
    eligible = sum(len(items) for items in seeds.values()) if enabled else 0
    for rec in [*round_robin({k: v for k, v in seeds.items() if not k[0]}), *round_robin({k: v for k, v in seeds.items() if k[0]})]:
        if len(questions) >= budget["questions"]:
            break
        question = graph_question(rec, project) if enabled else None
        if question is not None:
            questions.append({"id": stable("DQ-", rec["id"], question["type"], question["subject"]), **question,
                              "evidence_ids": [rec["id"]], "disposition": "pending", "reason_closed": ""})
    primitives = actionable(index)
    groups = defaultdict(list)
    flow_hints = {p["capability_gained"] for p in primitives}.intersection(value for p in primitives for value in p["prerequisites"])
    for primitive in primitives:
        keys = set()
        # Exact source-authored capability/prerequisite matches are hints, never proof.
        keys.update(("flow", value) for value in [primitive["capability_gained"], *primitive["prerequisites"]] if value in flow_hints)
        for rid in primitive["source_record_ids"]:
            rec = records[rid]
            keys.update(("source", f) for f in rec["files"])
            keys.update(("entrypoint", a["entrypoint_id"]) for a in rec.get("source_anchors", []) if a.get("entrypoint_id"))
        keys.update(("asset", asset) for asset in primitive["reachable_assets"])
        for key in sorted(keys):
            groups[key].append(primitive)
    # Stream hinted pairs first, then the stable fallback; never materialize n-choose-2.
    hints = {key: combinations(items, 2) for key, items in groups.items() if len(items) > 1}
    def pairs():
        yield from round_robin(hints)
        yield from combinations(primitives, 2)
    relationships, seen = [], set()
    for left, right in pairs():
        ids = tuple(sorted((left["id"], right["id"])))
        evidence = sorted(set(left["source_record_ids"] + right["source_record_ids"]))
        if ids in seen:
            continue
        seen.add(ids)
        relationships.append({"id": stable("REL-", *ids), "primitive_ids": list(ids), "evidence_ids": evidence,
                              "kind": "alternate_path", "producer_id": None, "consumer_id": None,
                              "disposition": "inconclusive", "source_locations": [], "question_ids": [],
                              "handoff": None, "reason": "Unreviewed evidence pairing; no capability transition established."})
        if len(relationships) >= budget["pairs"]:
            break
    total = len(primitives) * (len(primitives) - 1) // 2
    limitations = ["Codegraph disabled; source-only discovery."] if not enabled else ["Graph navigation is optional; uncited results do not establish a relationship."]
    if enabled and not questions:
        limitations.append("No resolved indexed source anchor is available; graph discovery is unavailable or unhelpful and selection continues source-only.")
    missing = sum(not rec["files"] for rec in records.values())
    if missing:
        limitations.append(f"{missing} evidence records have no canonical source anchor.")
    inputs = []
    for rec in records.values():
        if not rec.get("objective_id") or not rec.get("question_id"):
            continue
        owned = [p for p in primitives if rec["id"] in p["source_record_ids"]]
        inputs.append({"objective_id": rec["objective_id"], "question_id": rec["question_id"],
                       "evidence_ids": sorted({rec["id"], *(rid for p in owned for rid in p["source_record_ids"])}),
                       "primitive_ids": [p["id"] for p in owned], "relationship_ids": [],
                       "lane": "direct_validation" if rec["source_kind"] in {"sca", "secret"} else "primitive_led" if owned else "gap_driven",
                       "priority_band": "scanner_triage" if rec["source_kind"] in {"sca", "secret"} else "source_hypothesis",
                       "reason": "Investigate the registered source obligation without assuming attacker capability."})
    # Several observations can belong to one obligation without gaining extra slots.
    merged = {}
    for item in inputs:
        key = (item["objective_id"], item["question_id"])
        if key not in merged:
            merged[key] = item
        else:
            for field in ("evidence_ids", "primitive_ids"):
                merged[key][field] = sorted(set(merged[key][field] + item[field]))
    return {"schema_version": "2.0", "run_id": context["run_id"], "depth": depth, "status": "prepared",
            **({"assessment_context": assessment_ref(context)} if assessment_ref(context) else {}),
            "budget": dict(budget),
            "attack_objectives": deepcopy(index["attack_objectives"]), "investigation_questions": deepcopy(index["investigation_questions"]),
            "question_inputs": list(merged.values()),
            "questions": questions, "relationships": relationships, "graph_answers": [], "graph_evidence_refs": [],
            "scanner_triage": [{"evidence_id": r["id"], "status": "uninvestigated",
                                "reason": "Scanner observation only; applicability and attacker relationship are not established.",
                                "evidence_refs": [], "missing_fact": "Exposure, material role and authority without live authentication." if r["source_kind"] == "secret" else "Affected feature use, installed version, reachability, controls and environmental prerequisites."}
                               for r in records.values() if r["source_kind"] in {"sca", "secret"}],
            "graph_limitations": limitations,
            "counters": {"questions_used": 0, "questions_deferred": max(0, eligible - len(questions)),
                         "pairs_considered": len(relationships), "pairs_deferred": max(0, total - len(relationships)),
                         "query_seconds_used": 0, "questions_exhausted": int(eligible > budget["questions"]),
                         "pairs_exhausted": int(total > len(relationships)), "time_exhausted": 0}}


def validate_discovery(scan: Path, target: Path, context: dict, *, require_sealed: bool = True) -> dict:
    scan, target = Path(scan).resolve(), Path(target).resolve()
    path = scan / "campaign-planning/discovery.json"
    configured = context.get("paths", {}).get("campaign_discovery")
    if path.resolve() != path or (configured is not None and Path(configured) != path):
        raise ValueError("discovery path differs from canonical authority")
    doc = _load(path)
    _schema(doc, "campaign-discovery.schema.json")
    historical = bool(context.get("attempt_id")) and not current_assessment(doc, context)
    if doc["run_id"] != context["run_id"]:
        raise ValueError("discovery belongs to another run")
    if require_sealed and doc["status"] != "sealed":
        raise ValueError("discovery is not sealed")
    index = _load(scan / "campaign-planning/evidence-index.json")
    _schema(index, "evidence-index.schema.json")
    if index["run_id"] != context["run_id"]:
        raise ValueError("discovery evidence belongs to another run")
    inherited = load_registry(scan, through="sast")
    for field, expected in zip(("attack_objectives", "investigation_questions"), inherited):
        if {row["id"]: row for row in index[field]} != expected:
            raise ValueError("evidence index objective registry differs from its source authority")
    records = {r["id"]: r for r in index["records"]}
    validate_investigation_inputs(index, doc, scan=scan, target=None if historical else target, repositories=context["repositories"])
    primitives = {p["id"]: p for p in actionable(index)}
    budget, counters = doc["budget"], doc["counters"]
    questions, relationships = doc["questions"], doc["relationships"]
    if len(questions) > budget["questions"] or len(relationships) > budget["pairs"]:
        raise ValueError("discovery exceeds its allocated budget")
    if counters["query_seconds_used"] > budget["query_seconds"] or counters["questions_used"] > len(questions) or counters["pairs_considered"] != len(relationships):
        raise ValueError("discovery accounting exceeds budget")
    canonical_count = len(primitives)
    total_pairs = canonical_count * (canonical_count - 1) // 2
    eligible = counters["questions_deferred"] + len(questions)
    expected_counters = {"pairs_deferred": max(0, total_pairs - len(relationships)),
                         "pairs_exhausted": int(total_pairs > len(relationships)),
                         "questions_deferred": max(0, eligible - len(questions)),
                         "questions_exhausted": int(eligible > budget["questions"]),
                         "time_exhausted": int(counters["query_seconds_used"] >= budget["query_seconds"])}
    if any(counters[key] != value for key, value in expected_counters.items()):
        raise ValueError("discovery deferral counters differ from canonical evidence")
    qids = {q["id"]: q for q in questions}
    if len(qids) != len(questions) or len({r["id"] for r in relationships}) != len(relationships):
        raise ValueError("duplicate discovery identity")
    for question in questions:
        if not set(question["evidence_ids"]).issubset(records):
            raise ValueError("discovery question cites unknown evidence")
        if question["id"] != stable("DQ-", *question["evidence_ids"], question["type"], question["subject"]):
            raise ValueError("discovery question identity differs from evidence")
        if require_sealed and question["disposition"] == "pending":
            raise ValueError("discovery question lacks terminal disposition")
        if question["disposition"] != "pending" and not question["reason_closed"].strip():
            raise ValueError("closed discovery question requires a reason")
        if question["disposition"] == "graph-lead-only" and not any(a["question_id"] == question["id"] for a in doc["graph_answers"]):
            raise ValueError("graph-only question disposition requires relied-on evidence")
    refs = doc["graph_evidence_refs"]
    expected = {f"campaign-planning/codegraph-runs/{q['id']}/receipt.json": q for q in questions}
    if not set(refs).issubset(expected):
        raise ValueError("orphan discovery graph receipt")
    for ref in refs:
        result = validate_query_receipt(scan, target, context, "campaign-planning", "discovery", expected[ref], ref)
        if not result["meaningful"]:
            raise ValueError("discovery cites non-meaningful graph evidence")
    diagnostics, answers = [], []
    for answer in doc["graph_answers"]:
        question = qids.get(answer["question_id"])
        if question is None:
            raise ValueError("graph answer cites unknown discovery question")
        if historical:
            continue
        source_refs = [f"{loc['file']}:{loc['start_line']}-{loc['end_line']}" for loc in answer["source_locations"]]
        valid, issues = classify_refs(scan, target, context["repositories"], source_refs,
                                     owner=f"campaign-planning/discovery.json:{question['id']}",
                                     field="source_locations", affected_item_ids=question["evidence_ids"], kind="source")
        diagnostics.extend(issues)
        question["evidence_quality"] = "evidence_limited" if issues else "resolved"
        if issues:
            answer["disposition"] = question["disposition"] = "inconclusive"
            answer["conclusion_effect"] = question["reason_closed"] = "Source proof remains unresolved; inspect the cited source within the existing allocation."
            answer["limitations"] = list(dict.fromkeys(["Unusable source support cannot establish the graph answer.", *answer["limitations"]]))[:16]
        projected = {key: answer[key] for key in ("question_id", "receipt_ref", "observation", "disposition", "source_locations", "limitations", "conclusion_effect")}
        projected["source_locations"] = [loc for ref, loc in zip(source_refs, answer["source_locations"]) if ref in valid]
        answers.append(projected)
    if not historical:
        validate_graph_answers(target, [expected[ref] for ref in refs], answers, refs)
    answered = {a["question_id"] for a in doc["graph_answers"]}
    leads = {a["question_id"] for a in doc["graph_answers"] if a["disposition"] != "contradicted"}
    if len(answered) < len(questions) and not doc["graph_limitations"]:
        raise ValueError("unused discovery questions need a limitation")
    for rel in relationships:
        ids = rel["primitive_ids"]
        if len(set(ids)) != 2 or not set(ids).issubset(primitives) or rel["id"] != stable("REL-", *sorted(ids)):
            raise ValueError("invalid relationship primitive identity")
        evidence = sorted({rid for pid in ids for rid in primitives[pid]["source_record_ids"]})
        if rel["evidence_ids"] != evidence or not set(rel["question_ids"]).issubset(qids):
            raise ValueError("relationship references differ from canonical evidence")
        if not {rid for qid in rel["question_ids"] for rid in qids[qid]["evidence_ids"]}.issubset(evidence):
            raise ValueError("relationship graph questions cite unrelated evidence")
        if rel["kind"] in {"producer_consumer", "handoff"}:
            if {rel["producer_id"], rel["consumer_id"]} != set(ids):
                raise ValueError("directional relationship requires distinct producer and consumer")
        elif rel["producer_id"] is not None or rel["consumer_id"] is not None:
            raise ValueError("shared sinks and alternate paths are not capability transitions")
        if historical:
            continue
        locations = list(rel["source_locations"])
        handoff = rel.get("handoff") or {}
        locations.extend(handoff[key] for key in ("producer_location", "consumer_location") if handoff.get(key))
        locations.extend((handoff.get("mapping_evidence") or {}).get("source_locations", []))
        _, issues = classify_refs(scan, target, context["repositories"],
                                  [f"{loc['file']}:{loc['start_line']}-{loc['end_line']}" for loc in locations],
                                  owner=f"campaign-planning/discovery.json:{rel['id']}",
                                  field="source_locations", affected_item_ids=rel["evidence_ids"], kind="source")
        diagnostics.extend(issues)
        rel["evidence_quality"] = "evidence_limited" if issues else "resolved"
        if issues and rel["disposition"] == "source-supported":
            rel["disposition"] = "inconclusive"
            rel["reason"] = "Source relationship proof is unresolved; inspect the owning locations within the existing campaign allocation."
        if rel["disposition"] == "graph-lead-only" and (not rel["question_ids"] or not set(rel["question_ids"]).issubset(leads)):
            raise ValueError("graph lead requires relied-on graph answers")
        if rel["disposition"] == "source-supported":
            if not rel["source_locations"]:
                raise ValueError("source-reviewed relationship requires source locations")
            reviewed = {loc["file"] for loc in rel["source_locations"]}
            sides = [{f for rid in primitives[pid]["source_record_ids"] for f in records[rid]["files"]} for pid in ids]
            if any(not reviewed.intersection(files) for files in sides):
                raise ValueError("source review must cover both primitive anchors")
            repositories = [{repository_for(f, context) for f in files} for files in sides]
            cross_repo = not repositories[0].intersection(repositories[1])
            if cross_repo or rel["kind"] == "handoff":
                handoff = rel["handoff"]
                if not handoff or not handoff.get("mapping_evidence"):
                    raise ValueError("source-supported handoff requires explicit mapping evidence")
                required = {"route", "method", "endpoint"} if handoff["type"] == "http" else {"topic", "broker"} if handoff["type"] == "queue" else {"namespace", "key"} if handoff["type"] == "storage" else {"path", "format"}
                for side in ("producer", "consumer"):
                    if set(handoff[side + "_contract"]) != required or not all(handoff[side + "_contract"].values()):
                        raise ValueError("handoff contract is incomplete")
                mapping = handoff["mapping_evidence"]
                for field in ("binding", "actor_control", "resource_scope", "authority", "transformations", "guards", "compatible_conditions"):
                    if not mapping.get(field, "").strip():
                        raise ValueError("handoff mapping omits a semantic proof obligation")
                if not mapping.get("source_locations"):
                    raise ValueError("handoff mapping requires source/configuration evidence")
                for loc in mapping["source_locations"]:
                    if loc not in rel["source_locations"]:
                        raise ValueError("mapping evidence must be reviewed")
                for side in ("producer", "consumer"):
                    loc = handoff[side + "_location"]
                    if loc not in rel["source_locations"]:
                        raise ValueError("handoff configuration must be included in reviewed locations")
    triage = doc.get("scanner_triage", [])
    scanner_ids = {rid for rid, record in records.items() if record["source_kind"] in {"sca", "secret"}}
    if {item["evidence_id"] for item in triage} != scanner_ids or len(triage) != len(scanner_ids):
        raise ValueError("scanner observations require complete triage accounting")
    approved_refs = set(records) | {record["artifact_ref"] for record in records.values()}
    for item in triage:
        if item["status"] in {"applicable", "contradicted"} and not item["evidence_refs"]:
            raise ValueError("interpreted scanner triage requires evidence")
        if not set(item["evidence_refs"]).issubset(approved_refs):
            raise ValueError("scanner triage cites evidence outside the approved index")
    if not historical:
        doc["evidence_quality"] = summarize(diagnostics)
    return doc


def validate_investigation_inputs(index, discovery, *, scan=None, target=None, repositories=None):
    objectives, questions = validate_registry(
        discovery["attack_objectives"], discovery["investigation_questions"],
        inherited_objectives={o["id"]: o for o in index["attack_objectives"]},
        inherited_questions={q["id"]: q for q in index["investigation_questions"]},
        scan=scan, target=target, repositories=repositories)
    for field, inherited in (("attack_objectives", index["attack_objectives"]),
                             ("investigation_questions", index["investigation_questions"])):
        current = {row["id"]: row for row in discovery[field]}
        if any(current.get(row["id"]) != row for row in inherited):
            raise ValueError("discovery must preserve all inherited objective definitions")
        inherited_ids = {row["id"] for row in inherited}
        if any(row["owner"] != "campaign-planning/discovery.json" for row in current.values() if row["id"] not in inherited_ids):
            raise ValueError("new discovery definitions require discovery ownership")
    records = {r["id"]: r for r in index["records"]}
    primitives = {p["id"]: p for p in actionable(index)}
    relationships = {r["id"]: r for r in discovery["relationships"]}
    seen = set()
    for item in discovery["question_inputs"]:
        key = (item["objective_id"], item["question_id"])
        question = questions.get(item["question_id"])
        evidence = set(item["evidence_ids"])
        if key in seen or question is None or question["objective_id"] != item["objective_id"]:
            raise ValueError("invalid or duplicate investigation question ownership")
        seen.add(key)
        if not evidence or not evidence.issubset(records):
            raise ValueError("investigation question requires approved evidence")
        if not set(item["primitive_ids"]).issubset(primitives) or not set(item["relationship_ids"]).issubset(relationships):
            raise ValueError("investigation question cites unknown or contradicted capability")
        if any(not set(primitives[pid]["source_record_ids"]).issubset(evidence) for pid in item["primitive_ids"]):
            raise ValueError("investigation question primitive lacks owning evidence")
        if any(not set(relationships[rid]["evidence_ids"]).issubset(evidence) for rid in item["relationship_ids"]):
            raise ValueError("investigation question relationship lacks owning evidence")
        if not item["reason"].strip():
            raise ValueError("investigation question requires a reviewable reason")
    return objectives, questions


def candidate_demand(index: dict, discovery: dict) -> list[dict]:
    """Only explicit, source-backed registered obligations receive capacity."""
    records = {r["id"]: r for r in index["records"]}
    questions = {q["id"]: q for q in discovery["investigation_questions"]}
    relationships = {r["id"]: r for r in discovery["relationships"]}
    triage = {row["evidence_id"]: row for row in discovery["scanner_triage"]}
    demand = []
    for item in discovery["question_inputs"]:
        question = questions[item["question_id"]]
        if question.get("equivalent_to"):
            continue
        evidence = [records[rid] for rid in item["evidence_ids"]]
        if not any(r["files"] and r["disposition"] not in {"closed", "rejected"}
                   and triage.get(r["id"], {}).get("status") not in {"contradicted", "deferred"} for r in evidence):
            continue
        if any(relationships[rid]["disposition"] == "contradicted" for rid in item["relationship_ids"]):
            continue
        supported = bool(item["relationship_ids"]) and all(
            relationships[rid]["disposition"] == "source-supported" for rid in item["relationship_ids"])
        demand.append({"objective_id": item["objective_id"], "question_id": item["question_id"],
                       "lane": item["lane"], "primitive_ids": item["primitive_ids"],
                       "starting_evidence": sorted(item["evidence_ids"]), "relationship_ids": item["relationship_ids"],
                       "selection_reason": item["reason"],
                       "priority_band": "proof_obligation" if supported else item["priority_band"]})
    return demand


def selected_candidates(index: dict, discovery: dict, *, limit: int | None = None) -> list[dict]:
    """Risk, then actionable proof, then comparable actor/flow fairness."""
    records = {r["id"]: r for r in index["records"]}
    objectives = {o["id"]: o for o in discovery["attack_objectives"]}
    questions = {q["id"]: q for q in discovery["investigation_questions"]}
    bands = defaultdict(lambda: defaultdict(list))
    actionability = {name: rank for rank, name in enumerate(
        ("proof_obligation", "continuation", "source_hypothesis", "scanner_triage", "exploratory"))}
    for item in sorted(candidate_demand(index, discovery), key=lambda c: (c["objective_id"], c["question_id"])):
        objective = objectives[item["objective_id"]]
        rank = min(priority(records[rid]) for rid in item["starting_evidence"])
        group = (objective["starting_actor"], questions[item["question_id"]]["route"])
        bands[(rank, actionability[item["priority_band"]])][group].append(item)
    ranked = [item for band in sorted(bands) for item in round_robin(bands[band])]
    source = next((item for item in ranked if any(
        records[rid]["source_kind"] not in {"sca", "secret", "tool_warning"} and records[rid]["files"]
        and records[rid]["disposition"] not in {"closed", "rejected"}
        for rid in item["starting_evidence"])), None)
    if limit is None:
        limit = BUDGETS[discovery["depth"]]["max_campaigns"]
    chosen = ranked[:limit]
    if chosen and source is not None and source not in chosen:
        chosen[-1] = source
    return chosen


def question_dispositions(index, discovery, campaigns):
    demand = {c["question_id"]: c for c in candidate_demand(index, discovery)}
    inputs = {item["question_id"]: item for item in discovery["question_inputs"]}
    rows = []
    for question in discovery["investigation_questions"]:
        owners = [c["id"] for c in campaigns if c["question_id"] == question["id"]]
        equivalent = question.get("equivalent_to")
        status = "selected" if owners else "equivalent" if equivalent else "deferred" if question["id"] in demand else "evidence_limited"
        reason = ("Assigned within the total campaign allocation." if owners else
                  "Equivalent work reuses the referenced question; no additional capacity granted." if equivalent else
                  "Finite total allocation prioritized other distinct obligations by risk, actionable proof and actor/flow fairness." if status == "deferred" else
                  "No eligible source-backed evidence assignment; establish the missing source context or resolve the closed/contradicted route.")
        rows.append({"objective_id": question["objective_id"], "question_id": question["id"],
                     "campaign_ids": owners, "evidence_ids": inputs.get(question["id"], {}).get("evidence_ids", []),
                     "status": status, "equivalent_to": equivalent, "reason": reason,
                     "missing_fact": question["proof_obligation"],
                     "next_action": "Inspect the assigned source obligation." if owners else "Resolve the referenced obligation without claiming objective closure."})
    return rows


def validate_selection(scan: Path, target: Path, context: dict, plan: dict) -> None:
    discovery = validate_discovery(scan, target, context)
    _schema(plan, "campaign-plan.schema.json")
    validate_registry(plan["attack_objectives"], plan["investigation_questions"],
                      inherited_objectives={o["id"]: o for o in discovery["attack_objectives"]},
                      inherited_questions={q["id"]: q for q in discovery["investigation_questions"]})
    if plan.get("discovery_ref") != "campaign-planning/discovery.json":
        raise ValueError("campaign plan discovery reference differs")
    index = _load(Path(scan) / "campaign-planning/evidence-index.json")
    if plan.get("run_id") != context["run_id"]:
        raise ValueError("campaign plan belongs to another run")
    validate_selection_decisions(index, discovery, plan)


def validate_selection_decisions(index: dict, discovery: dict, plan: dict) -> None:
    """Validate attribution and resource authority, not exact heuristic ranking."""
    validate_investigation_inputs(index, discovery)
    for field in ("attack_objectives", "investigation_questions"):
        if plan[field] != discovery[field]:
            raise ValueError("campaign plan must retain all admitted objective and question definitions")
    records = {r["id"]: r for r in index["records"]}
    expected = selected_candidates(index, discovery, limit=plan["budget"]["max_campaigns"])
    eligible = {(c["objective_id"], c["question_id"]): c for c in candidate_demand(index, discovery)}
    campaigns = plan.get("campaigns", [])
    if len(campaigns) > plan["budget"]["max_campaigns"]:
        raise ValueError("campaign selection exceeds its allocated total budget")
    seen = set()
    for offset, campaign in enumerate(campaigns, 1):
        key = (campaign["objective_id"], campaign["question_id"])
        if campaign["id"] != f"CAM-{offset:03d}" or key in seen or key not in eligible or not campaign["starting_evidence"]:
            raise ValueError("invalid or duplicate campaign selection identity")
        seen.add(key)
        for field in ("starting_evidence", "primitive_ids", "relationship_ids"):
            if campaign[field] != eligible[key][field]:
                raise ValueError("selection ownership differs from registered question")
        if not campaign["selection_reason"].strip():
            raise ValueError("selection requires a reviewable reason")
    changed = len(campaigns) != len(expected) or any(any(c.get(k) != v for k, v in e.items()) for c, e in zip(campaigns, expected))
    revisions = plan.get("selection_revisions", [])
    if changed and not revisions:
        raise ValueError("selection departure requires an attributable revision")
    baseline = {c["question_id"]: c for c in expected}
    revised = {c["question_id"]: c for c in campaigns}
    affected = baseline.keys() ^ revised.keys()
    affected |= {qid for qid in baseline.keys() & revised.keys()
                 if any(revised[qid].get(k) != v for k, v in baseline[qid].items())}
    if [c["question_id"] for c in campaigns] != [c["question_id"] for c in expected] and not affected:
        affected = set(baseline)
    attributed = set()
    for revision in revisions:
        cited = set(revision["question_ids"])
        if not revision["author"].strip() or not revision["reason"].strip() or not revision["evidence_ids"] or not set(revision["evidence_ids"]).issubset(records):
            raise ValueError("selection revision lacks attribution or approved evidence")
        if not cited or not cited.issubset(baseline.keys() | revised.keys()):
            raise ValueError("selection revision cites unknown selected or displaced questions")
        required = {rid for qid in cited for row in (baseline.get(qid), revised.get(qid)) if row for rid in row["starting_evidence"]}
        if not required.issubset(revision["evidence_ids"]):
            raise ValueError("selection revision must cite displaced and selected evidence")
        attributed.update(cited)
    if not affected.issubset(attributed):
        raise ValueError("selection revision must attribute displaced and selected questions")
    source_ids = {r["id"] for r in records.values() if r["source_kind"] not in {"sca", "secret", "tool_warning"} and r["files"] and r["disposition"] not in {"closed", "rejected"}}
    source_demand = any(source_ids.intersection(c["starting_evidence"]) for c in eligible.values())
    if source_demand and campaigns and not any(source_ids.intersection(c["starting_evidence"]) for c in campaigns):
        raise ValueError("scanner volume cannot displace all meaningful source work")
    if plan["question_dispositions"] != question_dispositions(index, discovery, campaigns):
        raise ValueError("selection must account for every admitted question and equivalent obligation")
    accounting = plan.get("scanner_accounting", [])
    scanner_ids = {r["id"] for r in records.values() if r["source_kind"] in {"sca", "secret"}}
    if {item["evidence_id"] for item in accounting} != scanner_ids or len(accounting) != len(scanner_ids):
        raise ValueError("selection must account for every scanner observation")
    for item in accounting:
        owners = [c["id"] for c in campaigns if item["evidence_id"] in c["starting_evidence"]]
        if item["campaign_ids"] != owners or (item["status"] == "selected") != bool(owners):
            raise ValueError("scanner accounting differs from selected work")
        if item["status"] == "contradicted" and not any(t["evidence_id"] == item["evidence_id"] and t["status"] == "contradicted" for t in discovery.get("scanner_triage", [])):
            raise ValueError("scanner rejection requires evidenced triage")
    unresolved = {r["id"] for r in records.values()
                  if r["source_kind"] not in {"sca", "secret", "tool_warning"}
                  and (r["disposition"] in {"unresolved", "evidence_limited", "needs_environment"}
                       or not r.get("objective_id") or not r.get("question_id"))}
    unresolved.update(rid for rel in discovery["relationships"] if rel.get("evidence_quality") == "evidence_limited" for rid in rel["evidence_ids"])
    unresolved.update(rid for question in discovery["questions"] if question.get("evidence_quality") == "evidence_limited" for rid in question["evidence_ids"])
    dispositions = plan.get("evidence_dispositions", [])
    if {row["evidence_id"] for row in dispositions} != unresolved or len(dispositions) != len(unresolved):
        raise ValueError("selection must account for every unresolved source question")
    for row in dispositions:
        owners = [c["id"] for c in campaigns if row["evidence_id"] in c["starting_evidence"]]
        if row["campaign_ids"] != owners or (row["status"] == "selected") != bool(owners):
            raise ValueError("evidence disposition differs from selected work")
        if not all(row.get(key, "").strip() for key in ("missing_fact", "next_action", "priority_reason", "attempted_resolution")):
            raise ValueError("unresolved question requires missing proof and accountable next action")
        if not owners and not row.get("deferral_reason", "").strip():
            raise ValueError("unselected question requires a precise budget or priority deferral")
