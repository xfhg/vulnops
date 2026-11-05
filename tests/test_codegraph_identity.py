"""Current and historical graph provenance using isolated synthetic SQLite data."""
from __future__ import annotations

from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from codegraph_contract import (audit_request, current_navigation,
                               validate_campaign_graph, validate_graph_answers,
                               validate_query_receipt)


class GraphIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        environment = patch.dict(os.environ, {"VULNOPS_RUNTIME_ROOT": str(self.root / "owners")})
        environment.start()
        self.addCleanup(environment.stop)
        self.target = self.root / "source"
        self.target.mkdir()
        (self.target / "service.py").write_text("def entry():\n    return 1\n")
        self.runtime = self.root / "runtime"
        self.project = self.runtime / "project"
        (self.project / ".codegraph").mkdir(parents=True)
        (self.project / "service.py").write_text((self.target / "service.py").read_text())
        self.database = self.project / ".codegraph/codegraph.db"
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("CREATE TABLE nodes (id TEXT, name TEXT, qualified_name TEXT, file_path TEXT, start_line INTEGER, kind TEXT)")
            db.execute("CREATE TABLE edges (source TEXT, target TEXT, kind TEXT)")
            db.execute("INSERT INTO nodes VALUES ('n1', 'entry', 'service.entry', 'service.py', 1, 'function')")
        self.scan = self.root / "run"
        (self.scan / "campaign-planning").mkdir(parents=True)
        self.context = {"run_id": "run-1", "attempt_id": "attempt-1", "depth": "quick",
                        "codegraph_mode": "enabled",
                        "scan_base": str(self.scan), "source_root": str(self.target),
                        "paths": {"codegraph_runtime": str(self.runtime),
                                  "codegraph_project": str(self.project),
                                  "campaign_plan": str(self.scan / "campaign-planning/campaign-plan.json")}}
        self.context_path = self.root / "context.json"
        self.context_path.write_text(json.dumps(self.context))
        (self.scan / "run-manifest.json").write_text(json.dumps({
            "run_id": self.context["run_id"], "attempt_id": self.context["attempt_id"],
            "phases": {"intrusion": "running", "campaign-planning": "running"}}))
        self.question = {"id": "Q-1", "type": "callers", "subject": "entry", "file": "service.py", "reason": "Inspect inbound navigation"}
        self.campaign = {"id": "CAM-001", "graph_questions": [self.question]}
        (self.scan / "campaign-planning/campaign-plan.json").write_text(json.dumps({"campaigns": [self.campaign]}))

    def artifacts(self):
        request = audit_request(self.context_path, "intrusion", "CAM-001", "Q-1")
        completeness = {"local_truncated": False, "dropped_nodes": 0, "dropped_edges": 0,
                        "upstream_truncated": False, "upstream_complete": None, "heuristic": False}
        document = {"schema_version": "2.0", "tool": "codegraph", "operation": "callers", "subject": "entry",
                    "binding": request["binding"], "completeness": completeness,
                    "nodes": [{"id": "n1", "role": "source", "synthetic": False,
                               "name": "entry", "file": "service.py", "line": 1}],
                    "edges": [], "meaningful": False}
        receipt = {"schema_version": "2.0", "tool": "codegraph", "operation": "callers", "status": "ok",
                   "version": "fixture", "started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z",
                   "parse_status": "ok", "result_count": 0, "meaningful": False,
                   "binding": request["binding"], "completeness": completeness, "elapsed_seconds": 1, "warnings": []}
        request["output"].parent.mkdir(parents=True)
        ref = request["receipt"].relative_to(self.scan).as_posix()
        self.persist(request, document, receipt)
        return request, document, receipt, ref

    def persist(self, request, document, receipt):
        request["output"].write_text(json.dumps(document))
        receipt["normalized_sha256"] = hashlib.sha256(request["output"].read_bytes()).hexdigest()
        request["receipt"].write_text(json.dumps(receipt))

    def validate(self, ref):
        return validate_query_receipt(Path(os.path.relpath(self.scan)), self.target, self.context, "intrusion", "CAM-001", self.question, ref)

    def test_wrapper_receipt_uses_planned_authority_and_survives_index_removal(self):
        """Controlled graph output exercises transport, not installed-tool accuracy."""
        root = Path(__file__).resolve().parents[1]
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("run-codegraph.sh", "codegraph-adapter.py"):
            shutil.copyfile(root / "scripts" / name, scripts / name)
        binary = self.root / "bins/codegraph"
        binary.parent.mkdir()
        raw = {"targets": [{"id": "n1", "filePath": "service.py"}], "callers": [
            {"id": "n2", "name": "caller", "filePath": "service.py", "startLine": 2}]}
        binary.write_text(f"#!{sys.executable}\nimport sys\n"
                          f"print('fixture' if sys.argv[1] == '--version' else {json.dumps(raw)!r})\n")
        binary.chmod(0o755)
        environment = {**os.environ, "PYTHONPATH": str(root / "scripts")}
        command = ["bash", str(scripts / "run-codegraph.sh")]
        result = subprocess.run(command + ["--context", str(self.context_path), "--phase", "intrusion",
                                "--owner", "CAM-001", "--question", "Q-1"],
                                env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        ref = "intrusion/codegraph-runs/CAM-001/Q-1/receipt.json"
        document = self.validate(ref)
        self.assertTrue(document["meaningful"])
        self.assertEqual([(edge["source"], edge["target"]) for edge in document["edges"]], [("n2", "n1")])
        self.assertEqual(document["binding"]["file"], "service.py")
        self.assertEqual((self.target / "service.py").read_text(), "def entry():\n    return 1\n")
        self.assertFalse((self.target / ".codegraph").exists())
        receipt_path = self.scan / ref
        output = receipt_path.with_name("context.json")
        original_document = json.loads(output.read_text())
        original_receipt = json.loads(receipt_path.read_text())
        for artifact in ("context", "receipt"):
            for field in ("binding", "completeness", "unexpected"):
                with self.subTest(artifact=artifact, field=field):
                    changed_document, changed_receipt = copy.deepcopy(original_document), copy.deepcopy(original_receipt)
                    changed = changed_document if artifact == "context" else changed_receipt
                    if field == "unexpected":
                        changed[field] = True
                    else:
                        del changed[field]
                    self.persist({"output": output, "receipt": receipt_path}, changed_document, changed_receipt)
                    with self.assertRaisesRegex(ValueError, "invalid graph artifact"):
                        self.validate(ref)
        self.persist({"output": output, "receipt": receipt_path}, original_document, original_receipt)
        before = (output.read_bytes(), receipt_path.read_bytes())
        for arguments in (
                ["query", "entry", "--project", str(self.project), "--output", str(output), "--receipt", str(receipt_path)],
                ["--context", str(self.context_path), "--phase", "intrusion", "--owner", "CAM-001", "--question", "Q-1", "--file", "service.py"],
                ["--probe", "query", "entry", "--project", str(self.project), "--output", str(output), "--receipt", str(receipt_path), "--owner", "CAM-001"]):
            with self.subTest(arguments=arguments):
                rejected = subprocess.run(command + arguments, env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(rejected.returncode, 2, rejected.stderr)
                self.assertEqual((output.read_bytes(), receipt_path.read_bytes()), before)
        shutil.rmtree(self.runtime)
        self.assertTrue(self.validate(ref)["meaningful"])

    def test_receipts_survive_missing_navigation_and_changed_source(self):
        request, document, receipt, ref = self.artifacts()
        self.database.unlink()
        self.context["attempt_id"] = "attempt-2"
        (self.target / "service.py").unlink()
        before = (self.scan / ref).read_bytes()
        self.assertEqual(self.validate(ref)["assessment_scope"], "historical")
        self.assertEqual((self.scan / ref).read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "source-only"):
            current_navigation(self.context)

        for artifact in (document, receipt):
            artifact["binding"] = dict(artifact["binding"])
            artifact["binding"].pop("attempt_id")
            artifact["binding"].update(target_fingerprint="old", repository_set_sha256="old",
                                       snapshot_sha256="old")
        self.persist(request, document, receipt)
        self.assertEqual(self.validate(ref)["assessment_scope"], "historical")

    def test_foreign_run_and_target_project_are_rejected(self):
        _, _, _, ref = self.artifacts()
        self.context["run_id"] = "foreign"
        with self.assertRaisesRegex(ValueError, "binding differs"):
            self.validate(ref)
        context = copy.deepcopy(self.context)
        for runtime, project in (
                (self.target / "navigation", self.target / "navigation/project"),
                (self.target.parent, self.target.parent / "project")):
            with self.subTest(runtime=runtime):
                context["paths"]["codegraph_runtime"] = str(runtime)
                context["paths"]["codegraph_project"] = str(project)
                if runtime == self.target.parent:
                    context["source_root"] = str(project / "nested-source")
                with self.assertRaisesRegex(ValueError, "separate from target source"):
                    current_navigation(context)

    def test_request_uses_plan_and_rejects_traversal_disabled_and_missing_questions(self):
        request = audit_request(self.context_path, "intrusion", "CAM-001", "Q-1")
        self.assertEqual(request["binding"]["file"], "service.py")
        for owner, question in (("../CAM-001", "Q-1"), ("CAM-001", "../Q-1"), ("CAM-001", "absent")):
            with self.assertRaises(ValueError):
                audit_request(self.context_path, "intrusion", owner, question)
        (self.scan / "campaign-planning/discovery.json").write_text(json.dumps({"status": "prepared", "questions": [self.question]}))
        request = audit_request(self.context_path, "campaign-planning", "discovery", "Q-1")
        self.assertEqual(request["output"], self.scan / "campaign-planning/codegraph-runs/Q-1/context.json")
        with self.assertRaises(ValueError):
            audit_request(self.context_path, "campaign-planning", "CAM-001", "Q-1")
        self.context["codegraph_mode"] = "disabled"
        self.context_path.write_text(json.dumps(self.context))
        with self.assertRaises(ValueError):
            audit_request(self.context_path, "intrusion", "CAM-001", "Q-1")

    def test_receipts_reject_binding_hash_counts_health_and_forged_meaningful(self):
        request, document, receipt, ref = self.artifacts()
        self.assertFalse(self.validate(ref)["meaningful"])
        for field, value in (("owner_id", "CAM-002"), ("file", None), ("attempt_id", "attempt-other"), ("phase", "probe")):
            changed = copy.deepcopy(receipt)
            changed["binding"][field] = value
            self.persist(request, document, changed)
            with self.assertRaises(ValueError):
                self.validate(ref)
        for field, value in (("result_count", 1), ("status", "failed"), ("meaningful", True)):
            changed = copy.deepcopy(receipt)
            changed[field] = value
            self.persist(request, document, changed)
            with self.assertRaises(ValueError):
                self.validate(ref)
        self.persist(request, document, receipt)
        request["output"].write_text(json.dumps(document) + " ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.validate(ref)
        with self.assertRaises(ValueError):
            self.validate(ref.replace("CAM-001", "CAM-002"))

    def test_context_schema_endpoints_and_source_metadata_are_enforced(self):
        request, document, receipt, ref = self.artifacts()
        for change in ("missing", "endpoint", "source", "line"):
            changed = copy.deepcopy(document)
            if change == "missing":
                del changed["completeness"]
            elif change == "endpoint":
                changed["edges"] = [{"source": "n1", "target": "absent", "kind": "callers"}]
            elif change == "source":
                changed["nodes"][0]["file"] = "../source/service.py"
            else:
                changed["nodes"][0]["line"] = 99
            self.persist(request, changed, receipt)
            with self.assertRaises(ValueError):
                self.validate(ref)

    def test_answers_require_sources_and_exact_relied_on_questions(self):
        _, _, _, ref = self.artifacts()
        answer = {"question_id": "Q-1", "receipt_ref": ref, "observation": "Only the resolved subject was returned.",
                  "disposition": "inconclusive", "source_locations": [], "limitations": ["Static callers may be incomplete."],
                  "conclusion_effect": "No absence-of-reachability conclusion."}
        result = {"graph_query_receipts": [ref], "graph_evidence_refs": [], "graph_answers": [],
                  "graph_limitations": ["Only the subject was returned; source inspection used instead."]}
        validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        validate_graph_answers(self.target, [], [], [])
        for changes in ({"disposition": "supported"}, {"disposition": "contradicted"}, {"limitations": []}, {"question_id": "Q-2"},
                        {"source_locations": [{"file": "service.py", "start_line": 1, "end_line": 50}]}):
            with self.assertRaises(ValueError):
                validate_graph_answers(self.target, [self.question], [{**answer, **changes}], [ref])
        supported = {**answer, "disposition": "supported", "source_locations": [{"file": "service.py", "start_line": 1, "end_line": 2}]}
        validate_graph_answers(self.target, [self.question], [supported], [ref])
        with self.assertRaises(ValueError):
            validate_graph_answers(self.target, [self.question], [answer, answer], [ref])
        with self.assertRaises(ValueError):
            validate_graph_answers(self.target, [self.question], [], [ref])

    def test_optional_unexecuted_unavailable_and_failed_queries(self):
        request, document, receipt, ref = self.artifacts()
        receipt["status"] = "failed"
        self.persist(request, document, receipt)
        result = {"graph_query_receipts": [ref], "graph_evidence_refs": [], "graph_answers": [],
                  "graph_limitations": ["Query failed; reviewed the source directly."]}
        validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        unresolved = {**self.question, "id": "Q-2", "subject": "not_indexed"}
        self.campaign["graph_questions"].append(unresolved)
        (self.scan / "campaign-planning/campaign-plan.json").write_text(json.dumps({"campaigns": [self.campaign]}))
        with self.assertRaisesRegex(ValueError, "unresolved graph subject"):
            audit_request(self.context_path, "intrusion", "CAM-001", "Q-2")
        result["graph_limitations"].append("Q-2 was unresolved; no graph evidence was used.")
        validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        request["receipt"].unlink()
        request["output"].unlink()
        self.database.unlink()
        for mode in ("enabled", "disabled"):
            self.context["codegraph_mode"] = mode
            for refs in ([ref], []):
                result["graph_query_receipts"] = refs
                validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        result["graph_limitations"] = []
        with self.assertRaisesRegex(ValueError, "explicit graph limitations"):
            validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        validate_campaign_graph(self.scan, self.target, self.context, {"id": "CAM-001", "graph_questions": []}, result)
        result["graph_limitations"] = ["Graph unavailable; inspected source."]

        for wrong in (ref.replace("CAM-001", "CAM-002"), ref.replace("Q-1", "Q-orphan"), "../" + ref):
            result["graph_query_receipts"] = [wrong]
            with self.assertRaises(ValueError):
                validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)

    def test_relied_evidence_is_validated_even_when_graph_disabled(self):
        request, document, receipt, ref = self.artifacts()
        document["nodes"][0]["role"] = "result"
        document["meaningful"] = receipt["meaningful"] = True
        receipt["result_count"] = 1
        self.persist(request, document, receipt)
        answer = {"question_id": "Q-1", "receipt_ref": ref, "observation": "Entry is present.",
                  "disposition": "supported",
                  "source_locations": [{"file": "service.py", "start_line": 1, "end_line": 2}],
                  "limitations": [], "conclusion_effect": "Source confirms the entry definition."}
        result = {"graph_query_receipts": [ref], "graph_evidence_refs": [ref], "graph_answers": [answer],
                  "graph_limitations": []}
        validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        extra = {**self.question, "id": "Q-2", "subject": "unresolved_optional_subject"}
        self.campaign["graph_questions"].append(extra)
        (self.scan / "campaign-planning/campaign-plan.json").write_text(json.dumps({"campaigns": [self.campaign]}))
        result["graph_limitations"] = ["Q-2 was skipped because the optional subject was unresolved."]
        validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        result["graph_answers"] = []
        with self.assertRaises(ValueError):
            validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        result["graph_answers"] = [answer]
        self.context["codegraph_mode"] = "disabled"
        self.database.unlink()
        validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        self.context["attempt_id"] = "attempt-2"
        with self.assertRaisesRegex(ValueError, "historical graph"):
            validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)
        self.context["attempt_id"] = "attempt-1"
        request["output"].write_text(json.dumps(document) + " ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            validate_campaign_graph(self.scan, self.target, self.context, self.campaign, result)


if __name__ == "__main__":
    unittest.main()
