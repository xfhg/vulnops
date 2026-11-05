from __future__ import annotations

from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from codegraph_contract import resolve_subject

spec = importlib.util.spec_from_file_location("codegraph_adapter", ROOT / "scripts/codegraph-adapter.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class GraphSubjectTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        (self.project / ".codegraph").mkdir()
        for file in ("a.py", "b.py"):
            (self.project / file).write_text("def helper(): pass\n")
        with closing(sqlite3.connect(self.project / ".codegraph/codegraph.db")) as db, db:
            db.execute("CREATE TABLE nodes (id TEXT, name TEXT, qualified_name TEXT, file_path TEXT, start_line INTEGER, kind TEXT)")
            db.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?)", [
                ("a", "helper", "helper", "a.py", 1, "function"),
                ("b", "helper", "helper", "b.py", 1, "function"),
                ("c", "entry", "entry", "a.py", 2, "function"),
            ])

    def test_file_scope_resolves_only_its_definitions(self):
        self.assertEqual([row["id"] for row in resolve_subject("callers", "a.py", self.project)], ["a", "c"])
        self.assertEqual([row["id"] for row in resolve_subject("callees", "helper", self.project, "b.py")], ["b"])
        for subject, message in (("missing", "unresolved graph subject"), ("helper", "ambiguous graph symbol")):
            with self.subTest(subject=subject), self.assertRaisesRegex(ValueError, message):
                resolve_subject("callers", subject, self.project)
        for operation, subject, file in (("affected", "helper", None), ("query", "helper", "a.py"), ("callers", "helper", "../outside.py")):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                resolve_subject(operation, subject, self.project, file)

    def test_file_scope_includes_javascript_arrow_constants(self):
        (self.project / "entry.js").write_text("const entry = () => helper();\n")
        with closing(sqlite3.connect(self.project / ".codegraph/codegraph.db")) as db, db:
            db.execute("INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?)", ("js", "entry", "entry", "entry.js", 1, "constant"))
        self.assertEqual([row["id"] for row in resolve_subject("callees", "entry.js", self.project)], ["js"])

    def test_malformed_and_wrong_shape_outputs_fail_closed(self):
        for stdout, message in (("not JSON", "malformed JSON"), ("{}", "incompatible JSON shape"), ('{"callers":[null]}', "incompatible JSON shape")):
            result = subprocess.CompletedProcess([], 0, stdout, "")
            with self.subTest(stdout=stdout), mock.patch.object(adapter.subprocess, "run", return_value=result), self.assertRaisesRegex(ValueError, message):
                adapter.execute(Path("codegraph"), self.project, "callers", "entry")

    def test_resolved_symbol_without_edges_is_negative_navigation(self):
        raw = {"callers": [], "targets": [{"filePath": "a.py", "id": "c"}]}
        with mock.patch.object(adapter.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(raw), "")):
            nodes, edges, warnings, completeness = adapter.execute(Path("codegraph"), self.project, "callers", "entry")
        self.assertEqual(edges, [])
        self.assertEqual([node["role"] for node in nodes], ["source"])
        self.assertEqual(warnings, [])
        self.assertIsNone(completeness["upstream_complete"])
        self.assertEqual(nodes[0]["id"], "c")
        self.assertFalse(nodes[0]["synthetic"])

    def test_same_named_results_keep_distinct_file_identity(self):
        nodes, edges, _, _ = adapter.normalize("callers", "entry", {"callers": [
            {"id": "repo-a:invoke", "name": "invoke", "qualifiedName": "Service.invoke", "filePath": "repo-a/a.py", "startLine": 3},
            {"id": "repo-b:invoke", "name": "invoke", "qualifiedName": "Service.invoke", "filePath": "repo-b/a.py", "startLine": 3},
        ]})
        self.assertEqual({edge["source"] for edge in edges}, {"repo-a:invoke", "repo-b:invoke"})
        results = [node for node in nodes if node["role"] == "result"]
        self.assertEqual({node["file"] for node in results}, {"repo-a/a.py", "repo-b/a.py"})
        self.assertEqual({node["qualified_name"] for node in results}, {"Service.invoke"})

        first = {"name": "invoke", "qualifiedName": "A.invoke", "filePath": "a.py", "startLine": 3}
        second = dict(first, qualifiedName="B.invoke")
        nodes, edges, _, _ = adapter.normalize("callers", "entry", {"callers": [first, second, dict(first)]})
        results = [node for node in nodes if node["role"] == "result"]
        self.assertEqual(len(results), 2)
        self.assertEqual({node["qualified_name"] for node in results}, {"A.invoke", "B.invoke"})
        self.assertEqual(len({edge["source"] for edge in edges}), 2)

    def test_oversized_identity_and_subject_are_rejected_not_clipped(self):
        with self.assertRaisesRegex(ValueError, "identifier"):
            adapter.normalize("query", "entry", [{"id": "x" * 513}])
        with self.assertRaisesRegex(ValueError, "subject"), mock.patch.object(adapter.subprocess, "run") as run:
            adapter.execute(Path("codegraph"), self.project, "query", "x" * 513)
        run.assert_not_called()

    def test_local_omissions_are_counted_before_discarding(self):
        raw = [{"id": f"n-{index}"} for index in range(502)]
        nodes, edges, warnings, completeness = adapter.normalize("query", "entry", raw)
        self.assertEqual(len(nodes), 500)
        self.assertEqual(len(edges), 499)
        self.assertEqual(completeness["dropped_nodes"], 3)
        self.assertEqual(completeness["dropped_edges"], 3)
        self.assertTrue(completeness["local_truncated"])
        self.assertTrue(completeness["heuristic"])
        self.assertIsNone(completeness["upstream_complete"])
        self.assertTrue(warnings)
        identifiers = {node["id"] for node in nodes}
        self.assertTrue(all(edge["source"] in identifiers and edge["target"] in identifiers for edge in edges))
        graph = adapter.Accumulator("callers")
        for index in range(40):
            graph.add_node(f"n{index}", "source")
        for source in range(30):
            for target in range(40):
                graph.add_edge(f"n{source}", f"n{target}", "callers")
        _, edges, _, completeness = graph.result()
        self.assertEqual(len(edges), 1000)
        self.assertEqual(completeness["dropped_edges"], 200)
        for metadata, expected in (({}, None), ({"complete": True}, True), ({"truncated": True}, False)):
            _, _, _, completeness = adapter.normalize("callers", "entry", {"callers": [], **metadata})
            self.assertIs(completeness["upstream_complete"], expected)


    def test_expanded_requests_share_one_budget(self):
        def response(command, **kwargs):
            target = "a" if command[4] == "helper" else "c"
            offset = 0 if target == "a" else 300
            raw = {"targets": [{"id": target, "filePath": "a.py"}], "callers": [
                {"id": f"n-{index}", "name": f"fn{index}", "filePath": "a.py", "startLine": 1}
                for index in range(offset, offset + 300)]}
            return subprocess.CompletedProcess(command, 0, json.dumps(raw), "")
        with mock.patch.object(adapter.subprocess, "run", side_effect=response):
            nodes, edges, _, completeness = adapter.execute(Path("codegraph"), self.project, "callers", "a.py")
        self.assertEqual(len(nodes), 500)
        self.assertEqual(len(edges), 498)
        self.assertEqual(completeness["dropped_nodes"], 102)
        self.assertEqual(completeness["dropped_edges"], 102)

    def test_target_id_substitution_and_deadline_fail_closed(self):
        for target, message in (
                ({"filePath": "a.py", "id": "wrong"}, "different or ambiguous"),
                ({"filePath": "b.py"}, "did not honor")):
            with self.subTest(target=target):
                raw = {"callers": [], "targets": [target]}
                with mock.patch.object(adapter.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(raw), "")):
                    with self.assertRaisesRegex(ValueError, message):
                        adapter.execute(Path("codegraph"), self.project, "callers", "entry")
        for timeout in (0, -1, 121, float("nan")):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "timeout"):
                adapter.execute(Path("codegraph"), self.project, "callers", "entry", timeout_seconds=timeout)
        with mock.patch.object(adapter.subprocess, "run", side_effect=subprocess.TimeoutExpired("codegraph", 1)):
            with self.assertRaisesRegex(ValueError, "time bound"):
                adapter.execute(Path("codegraph"), self.project, "callers", "entry", timeout_seconds=1)

    def test_missing_current_binary_emits_source_only_failure_receipt(self):
        binding = {"run_id": "run", "attempt_id": "attempt-1", "phase": "intrusion",
                   "owner_id": "CAM-1", "question_id": "Q-1", "operation": "query",
                   "subject": "entry", "file": None}
        request = {"project": self.project, "output": self.project / "context.json",
                   "receipt": self.project / "receipt.json", "binding": binding}
        argv = ["adapter", "--context", "audit.json", "--phase", "intrusion",
                "--owner", "CAM-1", "--question", "Q-1"]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(adapter, "audit_request", return_value=request), \
                mock.patch.object(adapter.os, "access", return_value=False), \
                mock.patch.object(adapter.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(adapter.main(), 1)
        receipt = json.loads(request["receipt"].read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertFalse(receipt["meaningful"])
        self.assertIn("source-only", receipt["warnings"][0])



if __name__ == "__main__":
    unittest.main()
