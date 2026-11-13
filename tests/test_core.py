import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from spark_cve.agents import (CONDITIONS, MODEL_ASSESSMENT_SCHEMA, investigate, uncertain,
                              validate_assessment, parse_json_response, set_execution_facts, execution_summary)
from spark_cve.cli import parser
from spark_cve.clients import NVD, Ollama, ServiceError, normalize_cve
from spark_cve.reporting import write_reports
from spark_cve.tools import Repository


def record(identifier="CVE-2026-12345", published="2026-11-12T12:00:00.000", severity="HIGH"):
    return {"id": identifier, "published": published, "lastModified": published,
            "descriptions": [{"lang": "en", "value": "Mock component condition for transport tests, not a real CVE."}],
            "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                        "cvssData": {"version": "3.1", "baseSeverity": severity, "baseScore": 8.1}}]}}


def answer(ids, status="UNCERTAIN"):
    result = uncertain("Need deployed toolchain and reachability evidence")
    result["status"] = status
    result["conditions"] = [{"name": name, "finding": "unknown", "explanation": "Not established", "evidence_ids": ids}
                            for name in CONDITIONS]
    return result


class RepositoryTests(unittest.TestCase):
    def test_execution_preflight_validates_local_image_without_pull(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Repository(root, allow_execution=True, runner="docker")
            with patch("spark_cve.tools.subprocess.run") as run:
                run.return_value.returncode = 1
                with self.assertRaisesRegex(ValueError, "preload"):
                    repo.execution_preflight()
                self.assertEqual(run.call_args.args[0], ["docker", "image", "inspect", "--", "golang:1.24"])
                run.return_value.returncode = 0
                self.assertTrue(repo.execution_preflight()["enabled"])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "go.mod").write_text("module example.test/app\n\ngo 1.23.0\nrequire (\n golang.org/x/net v0.1.0 // indirect\n)\nreplace golang.org/x/net => ../net\n")
        (self.root / "main.go").write_text('package main\nfunc main() { println("hello") }\n')
        (self.root / ".env").write_text("DO_NOT_READ=private")
        self.repo = Repository(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_boundaries_and_secrets(self):
        for name in ("../outside.go", ".env"):
            with self.assertRaises(ValueError):
                self.repo.read_file(name)
        (self.root / "linked.go").symlink_to(self.root / "main.go")
        with self.assertRaises(ValueError):
            self.repo.read_file("linked.go")
        self.assertEqual(set(self.repo.list_files()["files"]), {"go.mod", "main.go"})

    def test_dependency_declarations_and_replacements(self):
        dependencies = self.repo.inspect_dependencies()
        manifest = dependencies["manifests"][0]
        self.assertEqual(manifest["declared_requirements"][0]["version"], "v0.1.0")
        self.assertIn("replace", manifest["manifest"])
        self.assertEqual(dependencies["resolution"], "unresolved")

    def test_read_search_and_comparison(self):
        self.assertEqual(self.repo.read_file("main.go", 2, 2)["lines"], ['2: func main() { println("hello") }'])
        self.assertEqual(self.repo.search_code("PRINTLN")["matches"][0]["line"], 2)
        self.assertEqual(self.repo.compare_versions("v1.9.0", "v1.10.0")["comparison"], "less")
        self.assertEqual(self.repo.compare_versions("v0.0.0-20200101000000-abcdef", "v1.0.0")["comparison"], "unknown")

    def test_execution_disabled_and_errors_recorded(self):
        item = self.repo.invoke("reviewer", "run_check", {"check_id": "go_test"})
        self.assertIn("error", item["result"])
        self.assertEqual(item["id"], "E1")
        self.assertIn("error", self.repo.invoke("a", "read_file", {"path": "../oops.go"})["result"])

    def test_snapshot_detects_changes(self):
        old = self.repo.snapshot
        (self.root / "main.go").write_text("package changed")
        self.assertNotEqual(old, self.repo.fingerprint())

    def test_docker_runner_is_fixed_isolated_and_stages_filtered_source(self):
        self.repo.allow_execution = True
        self.repo.runner = "docker"
        with patch("spark_cve.tools.subprocess.Popen") as popen, patch("spark_cve.tools.subprocess.run"):
            popen.return_value.wait.return_value = 0
            def inspect_command(command, **kwargs):
                source = command[command.index("--mount") + 1].split("src=")[1].split(",dst=")[0]
                self.assertFalse((Path(source) / ".env").exists())
                self.assertTrue((Path(source) / "go.mod").exists())
                self.assertIn("--network=none", command)
                self.assertIn("--read-only", command)
                self.assertIn("--cap-drop=ALL", command)
                return popen.return_value
            popen.side_effect = inspect_command
            self.assertEqual(self.repo.run_check("go_test")["exit_code"], 0)

    def test_local_preflight_requires_go_without_calling_docker(self):
        self.repo.allow_execution = True
        with patch("spark_cve.tools.shutil.which", return_value=None), patch("spark_cve.tools.subprocess.run") as run:
            self.assertIn("go", self.repo.execution_preflight()["missing_runtimes"])
            run.assert_not_called()

    def test_local_runner_uses_copy_fixed_arguments_and_filtered_environment(self):
        self.repo.allow_execution = True
        (self.root / "page.html").write_text("<h1>Go embed fixture</h1>")
        with patch("spark_cve.tools.shutil.which", return_value="/toolchain/go"), patch("spark_cve.tools.subprocess.Popen") as popen:
            popen.return_value.wait.return_value = 0
            def inspect(command, **kwargs):
                self.assertEqual(command, ["/toolchain/go", "test", "-count=1", "-timeout=45s", "-v", "./..."])
                work = Path(kwargs["cwd"])
                self.assertNotEqual(work, self.root)
                self.assertTrue((work / "go.mod").exists())
                self.assertTrue((work / "page.html").exists())
                self.assertFalse((work / ".env").exists())
                self.assertNotIn("NVD_API_KEY", kwargs["env"])
                self.assertEqual(kwargs["env"]["GOPROXY"], "off")
                self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
                (work / "go.mod").write_text("changed by test")
                return popen.return_value
            popen.side_effect = inspect
            self.assertEqual(self.repo.run_check("go_test")["runner"], "local")
            self.assertTrue((self.root / "go.mod").read_text().startswith("module example.test"))

    def test_local_timeout_terminates_process_group(self):
        self.repo.allow_execution = True
        with patch("spark_cve.tools.shutil.which", return_value="/go"), patch("spark_cve.tools.subprocess.Popen") as popen, patch("spark_cve.tools.os.killpg") as killpg:
            popen.return_value.wait.side_effect = [subprocess.TimeoutExpired("go", 90), 0]
            result = self.repo.run_check("go_test")
            self.assertEqual(result["error"], "Check timed out")
            if os.name == "posix":
                killpg.assert_called_once()
            else:
                popen.return_value.kill.assert_called_once()

    @unittest.skipUnless(shutil.which("go"), "Go is not installed on this machine")
    def test_real_local_go_on_dependency_free_fixture(self):
        (self.root / "go.mod").write_text("module example.test/fixture\ngo 1.18\n")
        repo = Repository(self.root, allow_execution=True)
        result = repo.run_check("go_test")
        self.assertEqual(result.get("exit_code"), 0, result)


class NVDTests(unittest.TestCase):
    def test_network_timeout_retried_with_progress_and_configured_timeout(self):
        calls, events = [], []
        def transport(url, **kwargs):
            calls.append(kwargs)
            if len(calls) < 3:
                raise ServiceError("timed out", retryable=True)
            return {"vulnerabilities": [{"cve": record()}]}
        nvd = NVD("test-key", transport=transport, sleep=lambda _: None, timeout=90,
                  progress=lambda kind, **data: events.append((kind, data)))
        self.assertEqual(nvd.get("CVE-2026-12345")["id"], "CVE-2026-12345")
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(c["timeout"] == 90 for c in calls))
        self.assertEqual(sum(kind == "nvd_retry" for kind, _ in events), 2)
        self.assertNotIn("test-key", json.dumps(events))

    def test_timeouts_eventually_fail_without_fallback(self):
        calls = []
        def transport(*args, **kwargs):
            calls.append(1)
            raise ServiceError("timed out", retryable=True)
        with self.assertRaisesRegex(ServiceError, "timed out"):
            NVD(transport=transport, sleep=lambda _: None).recent(2)
        self.assertEqual(len(calls), 3)

    def test_unauthorized_not_retried(self):
        calls = []
        def transport(*args, **kwargs):
            calls.append(1)
            raise ServiceError("HTTP 403", status=403)
        with self.assertRaises(ServiceError):
            NVD(transport=transport, sleep=lambda _: None).recent(2)
        self.assertEqual(len(calls), 1)

    def test_transient_errors_retry_but_permanent_errors_do_not(self):
        attempts = []
        def flaky(url, **kwargs):
            attempts.append(url)
            if len(attempts) < 3:
                raise ServiceError("busy", status=503)
            return {"vulnerabilities": [{"cve": record()}]}
        self.assertEqual(NVD(transport=flaky, sleep=lambda _: None).get("CVE-2026-12345")["id"], "CVE-2026-12345")
        self.assertEqual(len(attempts), 3)

    def test_pagination_sorting_and_severity(self):
        calls = []
        def transport(url, **kwargs):
            params = parse_qs(urlparse(url).query)
            self.assertEqual(params["resultsPerPage"], ["2000"])
            index = int(params["startIndex"][0])
            calls.append(index)
            rows = [record("CVE-2026-10001", "2026-11-12T01:00:00.000"),
                    record("CVE-2026-10002", "2026-11-12T02:00:00.000", "LOW"),
                    record("CVE-2026-10003", "2026-11-12T03:00:00.000", "CRITICAL")]
            return {"totalResults": 3, "resultsPerPage": 2000, "startIndex": index,
                    "vulnerabilities": [{"cve": row} for row in rows[index:index + 2000]]}
        rows = NVD(transport=transport, sleep=lambda _: None).recent(2)
        self.assertEqual(calls, [0])
        self.assertEqual([r["id"] for r in rows], ["CVE-2026-10003", "CVE-2026-10001"])

    def test_configurable_page_size_still_fully_paginates(self):
        calls = []
        rows = [record(f"CVE-2026-{10001 + i}", f"2026-11-12T0{i + 1}:00:00.000") for i in range(3)]
        def transport(url, **kwargs):
            params = parse_qs(urlparse(url).query)
            size = int(params["resultsPerPage"][0])
            index = int(params["startIndex"][0])
            calls.append(index)
            return {"totalResults": len(rows), "resultsPerPage": size, "startIndex": index,
                    "vulnerabilities": [{"cve": row} for row in rows[index:index + size]]}
        result = NVD(transport=transport, sleep=lambda _: None, page_size=2).recent(3)
        self.assertEqual(calls, [0, 2])
        self.assertEqual(len(result), 3)

    def test_page_size_is_bounded_by_nvd_limit(self):
        with self.assertRaisesRegex(ValueError, "1–2000"):
            NVD(page_size=2001)

    def test_failure_is_not_fallback(self):
        def fail(*args, **kwargs):
            raise ServiceError("offline")
        with self.assertRaises(ServiceError):
            NVD(transport=fail).recent()

    def test_unknown_score_and_invalid_cve(self):
        row = record()
        row["metrics"] = {}
        self.assertEqual(normalize_cve(row)["severity"], "UNSCORED")
        with self.assertRaises(ValueError):
            NVD().get("bad-id")

    def test_key_only_sent_in_header(self):
        def transport(url, **kwargs):
            self.assertNotIn("test-key", url)
            self.assertEqual(kwargs["headers"], {"apiKey": "test-key"})
            return {"vulnerabilities": [{"cve": record()}]}
        self.assertEqual(NVD("test-key", transport=transport).get("CVE-2026-12345")["id"], "CVE-2026-12345")


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.plan_patch = patch("spark_cve.agents.create_plan", return_value={
            "component": "fixture", "component_kind": "unknown", "version_condition": "unknown",
            "conditions": [{"name": name, "condition": name, "proof": "source", "disproof": "source"} for name in CONDITIONS],
            "trigger_logic": "all"})
        self.plan_patch.start()
        self.addCleanup(self.plan_patch.stop)

    def test_reproduction_status_owned_by_application(self):
        self.assertNotIn("reproduction_status", MODEL_ASSESSMENT_SCHEMA["properties"])
        self.assertNotIn("reproduction_status", MODEL_ASSESSMENT_SCHEMA["required"])
        data = answer([])
        data["reproduction_status"] = "succeeded"
        data["reproduction_steps"] = ["Inspect the supplied local fixture."]
        fixed = set_execution_facts(data)
        self.assertEqual(fixed["reproduction_status"], "instructions_only")
        validate_assessment(fixed, [])
        data.pop("reproduction_status")
        data["reproduction_steps"] = []
        self.assertEqual(set_execution_facts(data)["reproduction_status"], "not_run")

    def test_generic_check_results_do_not_become_cve_reproduction(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Repository(root, allow_execution=True)
            repo.evidence = [{"id": "E1", "agent": "investigator", "tool": "run_check",
                              "arguments": {"check_id": "go_test"}, "result": {"exit_code": 0}}]
            summary = execution_summary(repo)
            self.assertEqual(summary["checks"][0]["outcome"], "passed")
            self.assertFalse(summary["cve_reproduction_executed"])
            repo.evidence[0]["result"] = {"error": "Check timed out"}
            self.assertEqual(execution_summary(repo)["checks"][0]["outcome"], "timed_out")

    def test_keyed_conditions_normalize_without_duplicates(self):
        data = answer([])
        data["conditions"] = {c["name"]: {k: v for k, v in c.items() if k != "name"} for c in data["conditions"]}
        result = parse_json_response(json.dumps(data))
        self.assertEqual([c["name"] for c in result["conditions"]], CONDITIONS)
        validate_assessment(result, [])
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            parse_json_response('{"status":"UNCERTAIN", "status":"AFFECTED"}')

    def test_testing_defaults(self):
        args = parser().parse_args(["scan", "."])
        self.assertEqual(args.limit, 2)
        self.assertEqual(args.max_turns, 8)
        self.assertEqual(args.runner, "local")

    def test_no_tool_calls_stop_after_two_attempts_and_skip_review(self):
        with tempfile.TemporaryDirectory() as root:
            class NonAgentModel:
                model = "test"
                count = 0
                def chat(self, *args, **kwargs):
                    self.count += 1
                    return {"role": "assistant", "content": "I cannot access source"}
            model = NonAgentModel()
            events = []
            result = investigate(normalize_cve(record()), Repository(root), model, lambda kind, **kw: events.append(kind))
            self.assertEqual(model.count, 2)
            self.assertEqual(result["review_state"], "skipped")
            self.assertIn("source inspection", result["analysis_error"])
            self.assertEqual(events.count("validation_error"), 2)
            self.assertIn("review_skipped", events)

    def test_failed_tool_calls_stop_without_review(self):
        with tempfile.TemporaryDirectory() as root:
            class BadToolModel:
                model = "test"
                count = 0
                def chat(self, *args, **kwargs):
                    self.count += 1
                    return {"role": "assistant", "content": "", "tool_calls": [
                        {"function": {"name": "read_file", "arguments": {"path": "missing.go"}}}]}
            model = BadToolModel()
            result = investigate(normalize_cve(record()), Repository(root), model, lambda *a, **k: None)
            self.assertEqual(model.count, 2)
            self.assertEqual(result["review_state"], "skipped")
            self.assertEqual(sum(e["tool"] == "read_file" for e in result["evidence"]), 2)

    def test_repeated_identical_successful_tool_calls_are_not_progress(self):
        with tempfile.TemporaryDirectory() as root:
            class RepeatingModel:
                model = "test"
                count = 0
                def chat(self, *args, **kwargs):
                    self.count += 1
                    return {"role": "assistant", "content": "", "tool_calls": [
                        {"function": {"name": "inspect_dependencies", "arguments": {}}}]}
            model = RepeatingModel()
            result = investigate(normalize_cve(record()), Repository(root), model, lambda *a, **k: None)
            self.assertEqual(model.count, 3)
            self.assertEqual(result["review_state"], "skipped")

    def test_preflight_requires_parsed_tool_calls_and_preserves_metrics(self):
        def good(url, **kw):
            return {"message": {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "inspect_dependencies", "arguments": {}}}]},
                "done_reason": "stop", "eval_count": 17}
        model = Ollama(transport=good)
        self.assertEqual(model.probe_tools()["metrics"]["eval_count"], 17)
        def bad(url, **kw):
            return {"message": {"role": "assistant", "content": "inspect_dependencies()"}, "done_reason": "length"}
        with self.assertRaisesRegex(ServiceError, "preflight failed"):
            Ollama(transport=bad).probe_tools()

    def test_evidence_gates(self):
        evidence = [{"id": "E1", "tool": "read_file", "result": {"lines": ["1: example"]}}]
        data = answer(["E1"], "AFFECTED")
        with self.assertRaises(ValueError):
            validate_assessment(data, evidence)
        for c in data["conditions"]:
            c["finding"] = "proven"
        self.assertEqual(validate_assessment(data, evidence)["status"], "AFFECTED")
        data["conditions"][0]["evidence_ids"] = ["E999"]
        with self.assertRaises(ValueError):
            validate_assessment(data, evidence)

    def test_cannot_claim_reproduction_from_generic_tests(self):
        data = answer([])
        data["reproduction_status"] = "succeeded"
        with self.assertRaises(ValueError):
            validate_assessment(data, [])

    def test_ollama_local_only_and_no_hidden_thinking(self):
        with self.assertRaises(ValueError):
            Ollama("https://hosted.example")
        def transport(url, **kwargs):
            self.assertEqual(kwargs["payload"]["keep_alive"], "30m")
            return {"message": {"role": "assistant", "content": "test", "thinking": "private"}}
        self.assertNotIn("thinking", Ollama(transport=transport).chat([]))

    def test_two_agents_real_tool_dispatch_report_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/app\ngo 1.23.0\n")
            (root / "main.go").write_text("package main\nfunc main() {}\n")
            repo = Repository(root)
            messages = [
                {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "main.go"}}}]},
                {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "finish_investigation", "arguments": {}}}]},
                # Regression: the model's unsupported execution claim must not
                # discard gathered evidence, skip review, or stop the batch.
                {"role": "assistant", "content": json.dumps({**answer(["E3"]), "reproduction_status": "failed"})},
                {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "main.go"}}}]},
                {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "finish_investigation", "arguments": {}}}]},
                {"role": "assistant", "content": json.dumps({**answer(["E4"]), "reproduction_status": "succeeded"})},
            ]
            class ScriptedModel:
                model = "test-transport-not-real-inference"
                def chat(self, *args, **kwargs):
                    return messages.pop(0)
            events = []
            result = investigate(normalize_cve(record()), repo, ScriptedModel(), lambda *a, **kw: events.append((a, kw)))
            self.assertEqual(result["assessment"]["status"], "UNCERTAIN")
            self.assertIsNone(result["analysis_error"])
            self.assertEqual(result["review_state"], "completed")
            self.assertEqual(result["assessment"]["reproduction_status"], "not_run")
            readers = [e["agent"] for e in result["evidence"] if e["tool"] == "read_file"]
            self.assertEqual(readers[0], "investigator")
            self.assertTrue(all(role == "reviewer" for role in readers[1:]))
            write_reports(root, [result])
            self.assertIn("E2", (root / "report.md").read_text())
            self.assertIn("No project checks were requested or executed", (root / "report.md").read_text())
            self.assertEqual(len(json.loads((root / "report.json").read_text())), 1)
            self.assertEqual(messages, [])

    def test_model_failure_yields_uncertain(self):
        with tempfile.TemporaryDirectory() as root:
            class FailingModel:
                model = "test"
                def chat(self, *args, **kwargs):
                    raise ServiceError("unavailable")
            result = investigate(normalize_cve(record()), Repository(root), FailingModel(), lambda *a, **k: None)
            self.assertEqual(result["assessment"]["status"], "UNCERTAIN")


if __name__ == "__main__":
    unittest.main()
