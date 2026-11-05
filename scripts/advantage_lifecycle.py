#!/usr/bin/env python3
"""Fresh Advantage intake and read-only evidence validation; no recovery state."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tomllib
import uuid

from advantage_contract import (ROOT, PHASES, atomic_json, component, inside, load,
    load_context, now, phase_paths, require_base, skip_disposition, validate_phase,
    validate_schema, native_call_payload)
from advantage_baseline import admit_action_source, build_catalog, current_inventory, validate_source_audit
from run_lifecycle import _session


def context_document(context: dict) -> dict:
    """The immutable invocation input contains configuration and source bindings only."""
    document = {key: value for key, value in context.items() if not key.startswith("_")}
    validate_schema(document, "advantage-context")
    return document


def prepare_in_session(args) -> str:
    """Validate the prepared host, without reading any previous Advantage execution."""
    from model_routing import advantage_routing, load_routing, read_agent_overrides
    identities = {value for name in ("VULNOPS_LAUNCHER_SESSION_ID", "VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID")
                  if (value := os.environ.get(name))}
    if len(identities) != 1 or not os.environ.get("VULNOPS_LAUNCHER_PID"):
        raise ValueError("in-session Advantage requires one live harness launcher identity")
    session_id, _, _ = _session(identities.pop())
    routing = advantage_routing(load_routing(ROOT))
    if os.environ.get("VULNOPS_OMP_CONTROLLER_SELECTOR") != routing["controllers"]["advantage"]:
        raise ValueError("in-session Advantage controller route differs from the prepared OMP session")
    exported = json.loads(os.environ.get("VULNOPS_MODEL_ROUTING", "{}"))
    if not isinstance(exported, dict) or not isinstance(exported.get("agents"), dict):
        raise ValueError("in-session Advantage requires prepared agent routes")
    if any(exported["agents"].get(actor) != selector for actor, selector in routing["agents"].items()):
        raise ValueError("in-session Advantage agent routes differ from the prepared session")
    configs = {Path(os.environ.get("VULNOPS_PROJECT_OMP_CONFIG", ROOT / ".omp/config.yml"))}
    if agent_home := os.environ.get("PI_CODING_AGENT_DIR"):
        configs.add(Path(agent_home) / "config.yml")
    for config in configs:
        overrides = read_agent_overrides(config)
        if any(overrides.get(actor) != selector for actor, selector in routing["agents"].items()):
            raise ValueError("in-session Advantage requires matching generated agent model overrides")
    overlay = Path(os.environ.get("VULNOPS_OMP_RUNTIME_CONFIG", ""))
    runtime_dir = ROOT / ".harness/tmp"
    if (not overlay.is_file() or overlay.is_symlink()
            or overlay.resolve().parent != runtime_dir.resolve()
            or not overlay.name.startswith("omp-runtime-")):
        raise ValueError("in-session Advantage requires the host's launcher-owned runtime overlay")
    task_config = load(overlay).get("task")
    overlay_overrides = task_config.get("agentModelOverrides", {}) if isinstance(task_config, dict) else None
    if (not isinstance(task_config, dict) or type(task_config.get("maxRuntimeMs")) is not int
            or task_config["maxRuntimeMs"] <= 0 or not isinstance(overlay_overrides, dict)
            or any(overlay_overrides.get(actor, selector) != selector
                   for actor, selector in routing["agents"].items())):
        raise ValueError("in-session Advantage runtime overlay is not prepared for canonical dispatch")
    return session_id


def resolve_source(selector: Path | None) -> Path:
    from report_bundle import read_publication
    if selector is None:
        # Session-associated selection is supplied by the live host, never a saved pointer.
        call = native_call_payload()
        selected = call.get("baseline")
        if not isinstance(selected, str) or not selected:
            raise ValueError("select a completed audit path or exact run ID; live baseline is absent")
        selector = Path(selected)
    if len(selector.parts) == 1 and not selector.exists():
        run_id = component(str(selector))
        matches = []
        scans = ROOT / "scans"
        for path in scans.glob(f"*/runs/{run_id}/report/security-report.json"):
            path = inside(scans, path)
            try:
                publication = read_publication(path.parent.parent, expected_kind="audit")
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if publication["run_id"] == run_id:
                matches.append(path.parent.parent)
        if len(matches) != 1:
            raise ValueError("select a completed audit path; exact run ID is absent or ambiguous")
        return matches[0]
    absolute = selector.absolute()
    return inside(absolute.parent, absolute)


def initialize(args) -> dict:
    from advantage_config import resolve_budget
    from harness_contract import resolved_experiment_budget, resolved_gap_exploration_budget
    from model_routing import advantage_routing, load_routing
    from offline_package import network_identity, package_identity
    from report_bundle import read_publication
    if getattr(args, "in_session", False):
        session_id = prepare_in_session(args)
    else:
        if args.source_scan is None:
            raise ValueError("source_scan is required outside --in-session entry")
        session_id, _, _ = _session(os.environ.get("VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID")
                                     or os.environ.get("VULNOPS_LAUNCHER_SESSION_ID"))
    call = native_call_payload()
    if (call.get("launcher_session_id") != session_id
            or call.get("caller", {}).get("kind") != "main"):
        raise ValueError("Advantage initialization requires the live native controller")
    scan = resolve_source(args.source_scan)
    run = read_publication(scan, expected_kind="audit")
    source = Path(args.source_root or ROOT / "target").resolve()
    validate_source_audit(scan, run, source)
    inventory = current_inventory(source, run["repository"])
    source = Path(inventory["source_root"])
    with (ROOT / "config.toml").open("rb") as handle:
        config = tomllib.load(handle)
    mode, depth = args.mode, args.depth
    patch_needed = mode == "diff" or bool(args.verify_fix) or args.assess_patch_risk
    if bool(args.patch) != bool(patch_needed):
        raise ValueError("an immutable patch is required exactly for diff/fix-verification/patch-risk requests")
    if args.repository and not args.patch:
        raise ValueError("--repository requires a selected patch")
    repository = args.repository
    if args.patch and not repository:
        if len(inventory["repositories"]) != 1:
            raise ValueError("multi-repository patches require explicit --repository inventory path")
        repository = inventory["repositories"][0]["path"]
    if (mode == "actions") != bool(args.action_source):
        raise ValueError("--action-source is required only for actions mode")
    if mode == "actions" and not (args.verify_fix or args.assess_patch_risk or args.hardening or args.track_finding):
        raise ValueError("actions mode requires at least one selected action")
    if len(args.verify_fix) != len(set(args.verify_fix)) or len(args.track_finding) != len(set(args.track_finding)):
        raise ValueError("selected finding IDs must be unique")
    for identifier in args.verify_fix + args.track_finding:
        component(identifier)
    options = {"patch": str(Path(args.patch).resolve()) if args.patch else None, "repository": repository,
               "verify_fix": sorted(args.verify_fix), "assess_patch_risk": args.assess_patch_risk,
               "hardening": args.hardening, "track_findings": sorted(args.track_finding),
               "action_source": str(Path(args.action_source).resolve()) if args.action_source else None}
    run_id = component("advantage-" + now().replace("-", "").replace(":", "") + "-" + uuid.uuid4().hex[:12])
    base = inside(scan.parent, run_id)
    runtime = (Path(os.environ.get("VULNOPS_RUNTIME_ROOT", ROOT / ".harness")) / "tmp").absolute()
    protected = [source, scan, base]
    if options["action_source"]:
        protected.append(Path(options["action_source"]))
    if base.is_relative_to(source) or any(runtime.resolve().is_relative_to(root) for root in protected):
        raise ValueError("Advantage outputs must not overwrite source or completed evidence")
    runtime.mkdir(parents=True, exist_ok=True)
    input_path = inside(runtime, run_id + "-input.json")
    attempt_id, assessment_id = uuid.uuid4().hex, "scope-" + uuid.uuid4().hex
    context = {"schema_version": "2.0", "workflow": "canonical-redteam-v2", "execution_kind": "advantage",
               "run_id": run_id, "source_run_id": component(run["run_id"]), "scan_base": str(base),
               "repo_id": run["run_id"], "repository": run["repository"], "commit": inventory["revision"],
               "repositories": inventory["repositories"], "repository_count": len(inventory["repositories"]),
               "mode": mode, "depth": depth, "options": options, "model_routing": advantage_routing(load_routing(ROOT)),
               "budget": resolve_budget(depth, config), "experiment_budget": resolved_experiment_budget(depth),
               "gap_exploration_budget": resolved_gap_exploration_budget(ROOT, depth),
               "reproduction_mode": config["harness"]["reproduction"]["mode"],
               "network": network_identity(config["harness"]["network"]["linux_agent_egress"]),
               "offline_package": package_identity(ROOT),
               "codegraph_mode": "enabled" if os.access(ROOT / "bins/codegraph", os.X_OK) else "disabled",
               "source_scan": str(scan), "source_root": str(source), "repo_path": str(source), "action_source": None,
               "launcher_session_id": session_id, "input_path": str(input_path),
               "attempt_id": attempt_id, "assessment_id": assessment_id, "paths": phase_paths(base, PHASES),
               "baseline": {"execution_id": run["run_id"], "root": str(scan), "catalog_ref": "baseline/catalog.json"}}
    context["paths"].update(graph_paths(run_id))
    if options["action_source"]:
        context["action_source"] = admit_action_source(Path(options["action_source"]), context)
    work = inside(ROOT / "work/advantage", run_id)
    if work.exists() or input_path.exists():
        raise ValueError("new Advantage invocation destination already exists")
    input_created = False
    base.mkdir()
    try:
        for phase in PHASES:
            (base / phase).mkdir()
        from advantage_actions import prepare_patch
        context["patch_binding"] = prepare_patch(context)
        context["assessment_scopes"] = {assessment_id: {
            "assessment_id": assessment_id, "run_id": run_id, "attempt_id": attempt_id,
            "repositories": inventory["repositories"], "source_root": str(source), "started_at": now(),
            "source_view": "base/derived" if mode == "diff" else "derived" if context["patch_binding"] else "base",
            "patch_ref": (context["patch_binding"] or {}).get("patch_ref"), "limitations": []}}
        catalog = build_catalog(context, scan)
        atomic_json(base / "baseline/catalog.json", catalog)
        document = context_document(context)
        # Exclusive immutable input publication; no mutable context or last-run pointer.
        with input_path.open("x", encoding="utf-8") as handle:
            input_created = True
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return document
    except BaseException:
        if input_created:
            input_path.unlink(missing_ok=True)
        shutil.rmtree(base)
        if work.exists():
            shutil.rmtree(work)
        raise


def graph_paths(run_id: str) -> dict:
    runtime = ROOT / ".harness/codegraph" / run_id
    return {"codegraph_runtime": str(runtime), "codegraph_project": str(runtime / "project"),
            "codegraph_identity": str(runtime / "index-identity.json")}


def cleanup(context: dict) -> None:
    """Discard this invocation's disposable inputs only; never scan prior runs."""
    from advantage_contract import live_call
    live_call(context)
    run_id = component(context["run_id"])
    runtime = Path(os.environ.get("VULNOPS_RUNTIME_ROOT", ROOT / ".harness")) / "tmp"
    expected = inside(runtime, run_id + "-input.json")
    if Path(context["input_path"]) != expected:
        raise ValueError("cleanup input does not belong to this invocation")
    for root in (ROOT / "work/advantage", ROOT / ".harness/codegraph"):
        path = inside(root, run_id)
        if path.exists():
            shutil.rmtree(path)
    expected.unlink(missing_ok=True)


def parser_for(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    if command == "init":
        parser.add_argument("source_scan", type=Path, nargs="?", help="completed audit path or exact run ID")
        parser.add_argument("--in-session", action="store_true")
        parser.add_argument("--source-root", type=Path)
        parser.add_argument("--mode", choices=("standard", "deep", "diff", "actions"), default="deep")
        parser.add_argument("--depth", choices=("quick", "balanced", "full"), default="full")
        parser.add_argument("--patch", type=Path)
        parser.add_argument("--repository")
        parser.add_argument("--verify-fix", action="append", default=[])
        parser.add_argument("--assess-patch-risk", action="store_true")
        parser.add_argument("--hardening", action="store_true")
        parser.add_argument("--track-finding", action="append", default=[])
        parser.add_argument("--action-source", type=Path)
    elif command == "cleanup":
        parser.add_argument("--context", type=Path, required=True)
    elif command in {"status", "validate"}:
        parser.add_argument("base", type=Path)
        if command == "validate":
            parser.add_argument("--context", type=Path)
            parser.add_argument("--phase", choices=PHASES)
            parser.add_argument("--portable", action="store_true")
    else:
        raise ValueError("unknown Advantage operation")
    return parser


def deterministic_phase(context: dict, phase: str) -> bool:
    """Decide empty execution from validated analytical inputs, not a model claim."""
    if phase in {"baseline", "report"} or skip_disposition(context, phase):
        return True
    base = Path(context["scan_base"])
    if phase == "investigation":
        return not load(base / "planning/plan.json")["assignments"]
    if phase == "final-verification":
        return not load(base / "synthesis/findings.json")["findings"]
    if phase == "synthesis":
        from advantage_pipeline import synthesis_inputs
        results, _ = synthesis_inputs(context)
        return not any(result["candidates"] for result in results.values())
    if phase == "handoff":
        options = context["options"]
        return not (options["verify_fix"] or options["assess_patch_risk"] or options["hardening"])
    return False


def main(command: str) -> int:
    parser = parser_for(command)
    args = parser.parse_args()
    try:
        if command == "init":
            output = initialize(args)
        elif command == "cleanup":
            path = args.context.absolute()
            context = load(inside(path.parent, path))
            validate_schema(context, "advantage-context")
            if Path(context["input_path"]) != path:
                raise ValueError("cleanup input belongs to another invocation")
            cleanup(context)
            output = {"run_id": context["run_id"], "temporary_resources_removed": True}
        elif command == "validate" and args.phase:
            if args.portable:
                raise ValueError("portable reads validate the completed publication, not historical phases")
            context = load_context(args.context)
            base = require_base(args.base)
            from advantage_contract import require_active
            require_active(context, args.phase)
            validate_phase(base, args.phase, context)
            disposition = skip_disposition(context, args.phase)
            status = "skipped" if disposition else "ok"
            if not disposition and args.phase in {"planning", "investigation", "synthesis", "final-verification", "report"}:
                from advantage_pipeline import phase_status
                status = phase_status(context, args.phase)
            elif args.phase == "gap-exploration":
                from gap_exploration_contract import phase_status
                status = phase_status(context)
            output = {"run_id": context["run_id"], "phase": args.phase, "valid": True,
                      "status": status,
                      "deterministic": deterministic_phase(context, args.phase)}
        elif command == "status" and not inside(require_base(args.base), "report/security-report.json").exists():
            output = {"run_id": args.base.name, "status": "incomplete", "counts": None,
                      "report": None, "reason": "No final Advantage publication; not a zero-findings assessment."}
        else:
            from report_bundle import read_publication
            publication = read_publication(args.base, expected_kind="advantage",
                                           validate_evidence=command == "validate")
            report = publication["report"]
            output = {"run_id": publication["run_id"], "status": "complete", "mode": publication["mode"],
                      "source_run_id": publication["source"]["source_run_id"], "counts": report["counts"],
                      "report": str(Path(publication["scan_base"]) / "report/security-report.json"), "valid": True}
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        if command == "status":
            try:
                from report_bundle import publication_identity
                identity = publication_identity(args.base, expected_kind="advantage")
            except (OSError, ValueError, KeyError, TypeError):
                pass
            else:
                print(json.dumps({"run_id": identity["run_id"], "status": "complete",
                                  "outputs_available": False, "counts": identity["report"].get("counts"),
                                  "error": " ".join(str(exc).split())[:2000]}, sort_keys=True))
        parser.error(" ".join(str(exc).split())[:2000])
    return 2
