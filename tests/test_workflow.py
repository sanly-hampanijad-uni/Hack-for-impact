"""Cross-stack coverage, prerequisite logic and investigation controls."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spark_cve.agents import (create_plan, derive_verdict, investigate, parse_json_response,
                              uncertain, validate_assessment, assessment_schema, evidence_text, run_agent, call_model,
                              simple_version_matches, downgrade_uncited_findings, component_names_match)
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
    def test_one_or_path_cannot_disprove_others_with_the_same_evidence(self):
        data = {"review_notes": "Other triggers are disproven.", "conditions": [
            {"name": "trigger_1", "finding": "proven", "explanation": "observed", "evidence_ids": ["E1"]},
            {"name": "trigger_2", "finding": "disproven", "explanation": "not seen", "evidence_ids": ["E1"]},
            {"name": "trigger_3", "finding": "disproven", "explanation": "separately tested", "evidence_ids": ["E2"]},
        ]}
        from spark_cve.agents import normalize_untested_alternatives
        self.assertEqual(normalize_untested_alternatives(data, {"trigger_logic": "any"}), ["trigger_2"])
        self.assertEqual(data["conditions"][1]["finding"], "unknown")
        self.assertEqual(data["conditions"][2]["finding"], "disproven")
        self.assertIn("requires only one proven path", data["review_notes"])

    def test_component_identity_supports_ecosystem_names_and_subpackages(self):
        self.assertTrue(component_names_match("kin-openapi", "github.com/getkin/kin-openapi"))
        self.assertTrue(component_names_match("github.com/getkin/kin-openapi/openapi3filter",
                                              "github.com/getkin/kin-openapi"))
        self.assertTrue(component_names_match("@scope/widget", "@scope/widget"))
        self.assertFalse(component_names_match("attested-tls-poc", "github.com/getkin/kin-openapi"))

    def test_application_cve_does_not_require_dependency_resolution(self):
        application_plan = {
            "component": "local parser", "component_kind": "application", "version_condition": "affected revision",
            "trigger_logic": "all", "conditions": [{"name": name} for name in
                                                      ("component", "affected_version", "trigger_1")],
        }
        evidence = [{"id": "E1", "agent": "investigator", "tool": "read_file",
                     "arguments": {"path": "app.py"},
                     "result": {"path": "app.py", "lines": ["1: def parse(value): return value[0]"]}}]
        data = uncertain("none")
        data.update({"status": "AFFECTED", "missing_information": [],
                     "conditions": [{"name": name, "finding": "proven", "explanation": "verified",
                                      "evidence_ids": ["E1"]}
                                    for name in ("component", "affected_version", "trigger_1")]})
        names = ["component", "affected_version", "trigger_1"]
        self.assertEqual(validate_assessment(data, evidence, names, application_plan)["status"], "AFFECTED")

    def test_dependency_cve_can_use_manifest_evidence_when_resolver_is_unavailable(self):
        dependency_plan = {
            "component": "org.example:widget", "component_kind": "dependency", "version_condition": "< 2.0.0",
            "trigger_logic": "all", "conditions": [{"name": name} for name in
                                                      ("component", "affected_version", "trigger_1")],
        }
        evidence = [
            {"id": "E1", "agent": "application", "tool": "inspect_dependencies", "arguments": {},
             "result": {"resolution": "unresolved", "manifests": [{"declared_requirements": [
                 {"package": "org.example:widget", "version": "1.5.0"}]}]}},
            {"id": "E2", "agent": "investigator", "tool": "read_file", "arguments": {"path": "App.java"},
             "result": {"path": "App.java", "lines": ["1: import org.example.widget.Parser;"]}},
        ]
        data = uncertain("none")
        data.update({"status": "AFFECTED", "missing_information": [],
                     "conditions": [
                         {"name": "component", "finding": "proven", "explanation": "present", "evidence_ids": ["E1"]},
                         {"name": "affected_version", "finding": "proven", "explanation": "declared", "evidence_ids": ["E1"]},
                         {"name": "trigger_1", "finding": "proven", "explanation": "reachable", "evidence_ids": ["E2"]},
                     ]})
        names = ["component", "affected_version", "trigger_1"]
        self.assertEqual(validate_assessment(data, evidence, names, dependency_plan)["status"], "AFFECTED")

    def test_uncited_definite_findings_are_conservatively_unknown(self):
        data = {"conditions": [
            {"name": "trigger_1", "finding": "proven", "explanation": "observed", "evidence_ids": ["E1"]},
            {"name": "trigger_2", "finding": "disproven", "explanation": "not tested", "evidence_ids": []},
        ]}
        self.assertEqual(downgrade_uncited_findings(data), ["trigger_2"])
        self.assertEqual(data["conditions"][1]["finding"], "unknown")
        self.assertIn("No direct evidence", data["conditions"][1]["explanation"])

    def test_simple_version_range(self):
        self.assertTrue(simple_version_matches("v0.144.0", ">= 0.136.0 && < 0.149.0"))
        self.assertFalse(simple_version_matches("v0.149.0", ">= 0.136.0 && < 0.149.0"))
        self.assertIsNone(simple_version_matches("main", ">= 0.136.0 && < 0.149.0"))

    def test_affected_dependency_must_match_plan_identity_and_version(self):
        dependency_plan = {
            "component": "kin-openapi", "component_kind": "dependency",
            "version_condition": ">= 0.136.0 && < 0.149.0", "trigger_logic": "any",
            "conditions": [{"name": name} for name in ("component", "affected_version", "trigger_1")],
        }
        evidence = [
            {"id": "E1", "agent": "application", "tool": "resolve_dependencies", "arguments": {},
             "result": {"resolution": "resolved", "packages": [{"package": "github.com/getkin/kin-openapi",
                                                                    "version": "v0.144.0", "effective_version": "v0.144.0"}]}},
            {"id": "E2", "agent": "investigator", "tool": "read_file", "arguments": {"path": "main.go"},
             "result": {"path": "main.go", "lines": ["1: package main"]}},
        ]
        data = uncertain("none")
        data.update({"status": "AFFECTED", "missing_information": [],
                     "conditions": [{"name": name, "finding": "proven", "explanation": "verified",
                                      "evidence_ids": ["E1", "E2"]}
                                    for name in ("component", "affected_version", "trigger_1")]})
        condition_names = ["component", "affected_version", "trigger_1"]
        self.assertEqual(validate_assessment(data, evidence, condition_names, dependency_plan)["status"], "AFFECTED")
        contradictory = json.loads(json.dumps(data))
        contradictory["summary"] = "The status remains UNCERTAIN despite the proven path."
        with self.assertRaisesRegex(ValueError, "Narrative contradicts derived AFFECTED"):
            validate_assessment(contradictory, evidence, condition_names, dependency_plan)
        bad_component_citation = json.loads(json.dumps(data))
        bad_component_citation["conditions"][0]["evidence_ids"] = ["E2"]
        with self.assertRaisesRegex(ValueError, "component finding must cite"):
            validate_assessment(bad_component_citation, evidence, condition_names, dependency_plan)
        bad_version_citation = json.loads(json.dumps(data))
        bad_version_citation["conditions"][1]["evidence_ids"] = ["E2"]
        with self.assertRaisesRegex(ValueError, "affected_version finding must cite"):
            validate_assessment(bad_version_citation, evidence, condition_names, dependency_plan)
        unrelated = {**dependency_plan, "component": "attested-tls-poc"}
        with self.assertRaisesRegex(ValueError, "planned dependency"):
            validate_assessment(data, evidence, condition_names, unrelated)
        fixed = json.loads(json.dumps(evidence))
        fixed[0]["result"]["packages"][0].update({"version": "v0.149.0", "effective_version": "v0.149.0"})
        with self.assertRaisesRegex(ValueError, "outside.*affected range"):
            validate_assessment(data, fixed, condition_names, dependency_plan)

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
    def test_source_is_required_before_tests_or_finish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/app\ngo 1.23\n")
            (root / "main.go").write_text("package main\nfunc main() {}\n")
            (root / "main_test.go").write_text("package main\nfunc TestExample(t *testing.T) {}\n")
            repo = Repository(root, allow_execution=True)
            names = [condition["name"] for condition in plan()["conditions"]]
            assessment = uncertain("No definite conclusion")
            assessment["conditions"] = {name: {"holds": "unknown", "explanation": "not assessed", "evidence_ids": []}
                                         for name in names}
            class Model:
                calls = 0
                def chat(self, *args, **kwargs):
                    available = {tool["function"]["name"] for tool in kwargs.get("tools", [])}
                    if self.calls == 0:
                        self.calls += 1
                        self.assert_gated(available)
                        return {"role": "assistant", "content": "", "tool_calls": [
                            {"function": {"name": "discover_tests", "arguments": {}}}]}
                    if self.calls == 1:
                        self.calls += 1
                        self.assert_gated(available)
                        return {"role": "assistant", "content": "", "tool_calls": [
                            {"function": {"name": "read_file", "arguments": {"path": "main.go"}}}]}
                    if self.calls == 2:
                        self.calls += 1
                        if "finish_investigation" not in available or "run_targeted_test" not in available:
                            raise AssertionError("finish and execution should be available after production source")
                        return {"role": "assistant", "content": "", "tool_calls": [
                            {"function": {"name": "finish_investigation", "arguments": {}}}]}
                    self.calls += 1
                    return {"role": "assistant", "content": json.dumps(assessment)}

                @staticmethod
                def assert_gated(available):
                    if "finish_investigation" in available or "run_targeted_test" in available:
                        raise AssertionError("finish and execution must be gated until production source is read")
            try:
                result = run_agent("investigator", {"id": "CVE-2026-100353"}, repo, Model(),
                                   lambda *args, **kwargs: None, plan=plan())
                self.assertEqual(result["status"], "UNCERTAIN")
                self.assertEqual([item["tool"] for item in repo.evidence], ["discover_tests", "read_file"])
            finally:
                repo.close()

    def test_targeted_test_named_for_another_cve_is_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/app\ngo 1.23\n")
            (root / "main.go").write_text("package main\nfunc main() {}\n")
            (root / "main_test.go").write_text("package main\nfunc TestCVE2026100353Reproduces(t *testing.T) {}\n")
            repo = Repository(root, allow_execution=True)
            names = [condition["name"] for condition in plan()["conditions"]]
            assessment = uncertain("Wrong-CVE test rejected")
            assessment["conditions"] = {name: {"holds": "unknown", "explanation": "not assessed", "evidence_ids": []}
                                         for name in names}
            responses = [
                {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "read_file", "arguments": {"path": "main.go"}}}]},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "run_targeted_test", "arguments": {
                        "ecosystem": "go", "selector": "TestCVE2026100353Reproduces", "path": "."}}}]},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "finish_investigation", "arguments": {}}}]},
                {"role": "assistant", "content": json.dumps(assessment)},
            ]
            class Model:
                def chat(self, *args, **kwargs):
                    return responses.pop(0)
            try:
                result = run_agent("investigator", {"id": "CVE-2026-129092"}, repo, Model(),
                                   lambda *args, **kwargs: None, plan=plan())
                self.assertEqual(result["status"], "UNCERTAIN")
                self.assertFalse(any(item["tool"] == "run_targeted_test" for item in repo.evidence))
            finally:
                repo.close()

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
