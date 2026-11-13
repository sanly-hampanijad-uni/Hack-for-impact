"""Cross-stack coverage, prerequisite logic and investigation controls."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spark_cve.agents import (create_plan, derive_verdict, investigate, parse_json_response,
                              uncertain, validate_assessment, assessment_schema, evidence_text, run_agent, call_model)
from spark_cve.clients import ServiceError
from spark_cve.tools import Repository
from spark_cve.ecosystems import parse_manifest


def plan(logic="any"):
    return {"component": "fixture", "component_kind": "application", "version_condition": "before 2.0.0",
            "trigger_logic": logic, "conditions": [
                {"name": name, "condition": name, "proof": "matching observation", "disproof": "contradicting observation"}
                for name in ("component", "affected_version", "trigger_1", "trigger_2")]}


def findings(*values):
    return [{"name": name, "finding": value} for name, value in zip(
        ("component", "affected_version", "trigger_1", "trigger_2"), values)]


class VerdictTests(unittest.TestCase):
    def test_failed_tool_is_coverage_evidence_only(self):
        evidence = [{"id": "E8", "tool": "read_dependency_file", "result": {"error": "missing package"}}]
        data = uncertain("Dependency source unavailable")
        data["conditions"] = [{"name": "component", "finding": "disproven", "explanation": "Not established", "evidence_ids": ["E8"]}]
        with self.assertRaisesRegex(ValueError, "component: failed-tool evidence.*E8"):
            validate_assessment(data, evidence)
        data["conditions"][0]["finding"] = "unknown"
        self.assertEqual(validate_assessment(data, evidence)["status"], "UNCERTAIN")

    def test_unknown_reference_reports_specific_id_and_condition(self):
        data = uncertain("Missing evidence")
        data["conditions"] = [{"name": "component", "finding": "unknown", "explanation": "Unknown", "evidence_ids": ["E999"]}]
        with self.assertRaisesRegex(ValueError, "component: unknown evidence IDs.*E999"):
            validate_assessment(data, [])

    def test_alternative_paths_do_not_all_need_to_be_present(self):
        self.assertEqual(derive_verdict(findings("proven", "proven", "proven", "unknown"), plan()), "AFFECTED")
        self.assertEqual(derive_verdict(findings("proven", "proven", "disproven", "unknown"), plan()), "UNCERTAIN")
        self.assertEqual(derive_verdict(findings("proven", "proven", "disproven", "disproven"), plan()), "NOT AFFECTED")

    def test_necessary_conditions_require_all(self):
        self.assertEqual(derive_verdict(findings("proven", "proven", "proven", "unknown"), plan("all")), "UNCERTAIN")
        self.assertEqual(derive_verdict(findings("proven", "proven", "proven", "disproven"), plan("all")), "NOT AFFECTED")

    def test_fixed_version_and_unrelated_component(self):
        for values in (("proven", "disproven", "unknown", "unknown"), ("disproven", "unknown", "unknown", "unknown")):
            self.assertEqual(derive_verdict(findings(*values), plan()), "NOT AFFECTED")

    def test_model_does_not_select_verdict_or_execution_status(self):
        schema = assessment_schema([c["name"] for c in plan()["conditions"]])
        self.assertNotIn("status", schema["properties"])
        self.assertNotIn("reproduction_status", schema["properties"])
        self.assertIn("holds", schema["properties"]["conditions"]["properties"]["component"]["properties"])

    def test_planner_retains_boolean_relationship(self):
        raw = {"component": "fixture", "component_kind": "dependency", "version_condition": "< 2.0.0",
               "trigger_logic": "any", "triggers": [{"condition": "one complete path", "proof": "matching trace", "disproof": "path guarded"}],
               "symbols": ["parse"], "queries": ["parse"]}
        class Model:
            def chat(self, *a, **k):
                return {"role": "assistant", "content": json.dumps(raw)}
        result = create_plan({"id": "SYNTHETIC"}, {}, Model(), lambda *a, **k: None)
        self.assertEqual(result["trigger_logic"], "any")
        self.assertEqual([c["name"] for c in result["conditions"]], ["component", "affected_version", "trigger_1"])

    def test_commit_hash_is_not_treated_as_ordered_version(self):
        raw = {"component": "example", "component_kind": "application", "version_condition": ">= 731ca82",
               "trigger_logic": "any", "triggers": [{"condition": "race", "proof": "matching trace", "disproof": "guarded"}],
               "symbols": [], "queries": []}
        class Model:
            def chat(self, *a, **k):
                return {"content": json.dumps(raw)}
        result = create_plan({"id": "SYNTHETIC", "description": "Affected through commit 731ca82"}, {}, Model(), lambda *a, **k: None)
        self.assertIn("source/ancestry", result["version_condition"])
        self.assertNotIn(">=", result["version_condition"])


class CrossStackTests(unittest.TestCase):
    def test_language_neutral_reader_and_missing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("app.py", "app.js", "app.ts", "app.rs", "App.java", "App.cs", "main.cpp", "app.php", "app.rb", "Dockerfile"):
                (root / name).write_text("entrypoint data\n")
            (root / "image.bin").write_bytes(b"\x00\xff")
            (root / "private.key").write_text("excluded")
            repo = Repository(root)
            self.assertEqual(len(repo.list_files()["files"]), 10)
            self.assertEqual(repo.read_file("app.py")["lines"], ["1: entrypoint data"])
            with self.assertRaisesRegex(ValueError, "does not exist"):
                repo.search_code("parse", "github.com/missing/library")

    def test_manifests_for_multiple_ecosystems(self):
        cases = [
            ("package.json", '{"dependencies":{"example":"^1.2.0"}}', "node", "declared"),
            ("package-lock.json", '{"packages":{"node_modules/example":{"version":"1.2.3"}}}', "node", "locked"),
            ("requirements.txt", 'example==1.2.3\n', "python", "declared"),
            ("pyproject.toml", '[project]\ndependencies=["example>=1.0"]', "python", "declared"),
            ("Cargo.lock", '[[package]]\nname="example"\nversion="1.2.3"', "rust", "locked"),
            ("pom.xml", '<project><dependencies><dependency><groupId>org.demo</groupId><artifactId>example</artifactId><version>1.2.3</version></dependency></dependencies></project>', "java", "declared"),
            ("app.csproj", '<Project><ItemGroup><PackageReference Include="Example" Version="1.2.3" /></ItemGroup></Project>', "dotnet", "declared"),
            ("composer.lock", '{"packages":[{"name":"demo/example","version":"1.2.3"}]}', "php", "locked"),
            ("Gemfile.lock", '    example (1.2.3)\n', "ruby", "locked"),
        ]
        for filename, raw, stack, kind in cases:
            with self.subTest(filename=filename):
                result = parse_manifest(Path(filename), raw)
                self.assertEqual(result["ecosystem"], stack)
                self.assertEqual(result["dependencies"][0]["kind"], kind)

    def test_unknown_language_can_use_operator_configured_check(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.custom").write_text("custom application")
            repo = Repository(root, allow_execution=True, custom_checks={"custom_test_1": [sys.executable, "-c", "print('custom check completed')"]})
            try:
                result = repo.run_check("custom_test_1")
                self.assertEqual(result["exit_code"], 0)
                self.assertIn("custom check completed", result["output"])
            finally:
                repo.close()

    def test_real_python_tests_and_reused_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text('[project]\nname="fixture"\nversion="1.0"\n')
            (root / "test_app.py").write_text('import unittest\nclass TestApp(unittest.TestCase):\n def test_value(self): self.assertEqual(2+2,4)\n')
            repo = Repository(root, allow_execution=True)
            try:
                self.assertEqual(repo.run_check("python_test")["exit_code"], 0)
                first = repo.workspace().base
                self.assertEqual(repo.run_check("python_test")["exit_code"], 0)
                self.assertEqual(first, repo.workspace().base)
                self.assertFalse((root / "__pycache__").exists())
            finally:
                repo.close()

    @unittest.skipUnless(shutil.which("node"), "Node is not installed")
    def test_real_node_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text('{"name":"fixture","version":"1.0.0","private":true}')
            (root / "app.test.js").write_text("const test=require('node:test'); const assert=require('node:assert/strict'); test('works',()=>assert.equal(2+2,4));")
            repo = Repository(root, allow_execution=True)
            try:
                result = repo.run_check("node_test")
                self.assertEqual(result.get("exit_code"), 0, result)
            finally:
                repo.close()

    def test_dependency_source_cannot_escape_registered_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = Repository(root, allow_execution=True)
            try:
                workspace = repo.workspace()
                dependency = workspace.base / "modules" / "example"
                dependency.mkdir(parents=True)
                (dependency / "parser.py").write_text("def parse(value): return value\n")
                workspace.dependency_roots[("python", "example")] = dependency
                self.assertIn("1: def parse", repo.read_dependency_file("example", "parser.py", ecosystem="python")["lines"][0])
                with self.assertRaises(ValueError):
                    repo.read_dependency_file("example", "../../home", ecosystem="python")
                matches = repo.search_dependency("example", "parser.parse", ecosystem="python")
                self.assertEqual(matches["matches"][0]["path"], "parser.py")
                self.assertEqual(matches["searched_symbol"], "parse")
            finally:
                repo.close()

    def test_nonexistent_test_does_not_run_a_zero_case_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/demo\ngo 1.21\n")
            (root / "main_test.go").write_text("package main\nfunc TestExisting(t *testing.T) {}\n")
            repo = Repository(root, allow_execution=True)
            try:
                result = repo.run_targeted_test("go", "TestImagined")
                self.assertIn("No existing tests", result["error"])
                self.assertEqual(result["available_selectors"], ["TestExisting"])
                self.assertNotIn("execution_started", result)
            finally:
                repo.close()


class FollowUpTests(unittest.TestCase):
    def test_transient_model_error_gets_one_retry(self):
        class Model:
            calls = 0
            def chat(self, *a, **k):
                self.calls += 1
                if self.calls == 1:
                    raise ServiceError("local inference failure", status=500)
                return {"role": "assistant", "content": "ready"}
        model, events = Model(), []
        result = call_model(model, [], lambda kind, **kw: events.append(kind), "reviewer", "SYNTHETIC", "investigation")
        self.assertEqual(result["content"], "ready")
        self.assertEqual(model.calls, 2)
        self.assertIn("model_retry", events)

    def test_reviewer_can_read_dependency_before_application_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("def parse(value): return value[0]\n")
            repo = Repository(root, allow_execution=True)
            try:
                workspace = repo.workspace()
                dependency = workspace.base / "modules/example"
                dependency.mkdir(parents=True)
                (dependency / "parser.py").write_text("def parse(value): return value[0]\n")
                workspace.dependency_roots[("python", "example")] = dependency
                data = uncertain("Need deployment configuration")
                data["conditions"] = {c["name"]: {"holds": "unknown", "explanation": "Not established", "evidence_ids": []} for c in plan()["conditions"]}
                data["follow_up_requests"] = []
                messages = [
                    {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "read_dependency_file", "arguments": {"package": "example", "ecosystem": "python", "path": "parser.py"}}}]},
                    {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "app.py"}}}]},
                    {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "finish_investigation", "arguments": {}}}]},
                    {"role": "assistant", "content": json.dumps(data)},
                ]
                class Model:
                    def chat(self, *a, **k):
                        return messages.pop(0)
                result = run_agent("reviewer", {"id": "SYNTHETIC"}, repo, Model(), lambda *a, **k: None, plan=plan())
                self.assertEqual(result["status"], "UNCERTAIN")
                self.assertEqual([e["tool"] for e in repo.evidence], ["read_dependency_file", "read_file"])
                self.assertEqual(messages, [])
            finally:
                repo.close()

    def test_reviewer_can_request_one_additional_investigation_round(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("def parse(value): return value[0]\n")
            repo = Repository(root)
            names = [c["name"] for c in plan()["conditions"]]
            def assessment(requests=None):
                data = uncertain("Need caller evidence")
                data["conditions"] = {name: {"holds": "unknown", "explanation": "Missing caller", "evidence_ids": []} for name in names}
                if requests is not None:
                    data["follow_up_requests"] = requests
                return {"role": "assistant", "content": json.dumps(data)}
            read = {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "app.py"}}}]}
            finish = {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "finish_investigation", "arguments": {}}}]}
            messages = [read, finish, assessment(), read, finish, assessment(["Read callers of parse"]),
                        read, finish, assessment(), read, finish, assessment([])]
            class Model:
                model = "synthetic-transport"
                def chat(self, *a, **k):
                    return messages.pop(0)
            with patch("spark_cve.agents.create_plan", return_value=plan()):
                result = investigate({"id": "SYNTHETIC"}, repo, Model(), lambda *a, **k: None)
            self.assertIsNone(result["analysis_error"])
            self.assertIsNotNone(result["follow_up"])
            self.assertEqual(result["review_state"], "completed")
            self.assertEqual(messages, [])
