import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import shlex

from .agents import investigate
from .clients import NVD, Ollama, ServiceError
from .config import load_nvd_key
from .reporting import Events, write_reports
from .tools import Repository


def parser():
    root = argparse.ArgumentParser(description="Investigate repository CVE exposure across stacks with local Nemotron on DGX Spark")
    root.add_argument("--ollama-url", default=os.getenv("OLLAMA_URL", "http://127.0.0.1:11435"))
    root.add_argument("--model", default=os.getenv("NEMOTRON_MODEL", "nemotron-3-nano:30b"))
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check Ollama connectivity and installed model (no source is sent)")
    recent = sub.add_parser("recent", help="Retrieve latest scored HIGH/CRITICAL CVEs live from NVD")
    scan = sub.add_parser("scan", help="Investigate latest CVEs or one manual CVE against a local repository")
    for command in (recent, scan):
        command.add_argument("--prompt-key", action="store_true", help="Prompt for key instead of loading NVD_API_KEY from environment or .env")
        command.add_argument("--env-file", type=Path, help="Key file (default: .env in the Spark CVE project directory)")
        command.add_argument("--limit", type=int, default=2, help="Number of recent CVEs (default: 2; maximum: 10)")
        command.add_argument("--lookback-days", type=int, default=30)
        command.add_argument("--nvd-timeout", type=int, default=45, help="Seconds per live NVD request attempt (default: 45; up to 3 attempts)")
    scan.add_argument("repository", type=Path)
    scan.add_argument("--cve", help="Investigate this CVE instead of the recent batch; still fetched live")
    scan.add_argument("--output", type=Path, help="New output directory (defaults to artifacts/<timestamp>)")
    scan.add_argument("--max-turns", type=int, default=8, help="Tool turns per agent, plus assessment and at most one reviewer follow-up round")
    scan.add_argument("--allow-execution", action="store_true", help="Allow project checks in a temporary copy on the laptop")
    scan.add_argument("--allow-downloads", action="store_true", help="Allow supported package managers to retrieve dependencies")
    scan.add_argument("--runner", choices=["local", "docker"], default="local", help="Local supports multiple stacks; optional Docker runner currently supports fixed Go checks")
    scan.add_argument("--test-command", action="append", default=[], help="Operator-approved test argv, quoted as one argument; no outer shell (repeatable)")
    scan.add_argument("--reproduce-command", action="append", default=[], help="Operator-approved local reproduction argv; output requires independent review (repeatable)")
    scan.add_argument("--check-timeout", type=int, default=90, help="Seconds per check/dependency operation (default: 90)")
    scan.add_argument("--go-image", default="golang:1.24", help="Preloaded Docker image appropriate to repository Go version")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    repo = None
    try:
        if args.command == "doctor":
            model = Ollama(args.ollama_url, args.model)
            models = model.models().get("models", [])
            names = [m["name"] for m in models]
            print(json.dumps({"endpoint": args.ollama_url, "requested_model": args.model, "installed_models": names}, indent=2))
            if args.model not in names:
                print("Requested model is not installed. Have the Spark operator load it locally.", file=sys.stderr)
                return 1
            print("Checking real model tool selection…", flush=True)
            print(json.dumps(model.probe_tools(), indent=2))
            print("Ollama tool-call preflight passed (no source read or sent).")
            return 0
        if not 1 <= args.limit <= 10 or not 1 <= args.lookback_days <= 120:
            raise ValueError("limit must be 1–10 and lookback-days 1–120")
        if not 1 <= args.nvd_timeout <= 180:
            raise ValueError("nvd-timeout must be 1–180 seconds")
        key = load_nvd_key(env_file=args.env_file, prompt=args.prompt_key)
        if args.command == "scan":
            if not 1 <= args.max_turns <= 30:
                raise ValueError("max-turns must be 1–30")
            if args.allow_downloads and not args.allow_execution:
                raise ValueError("--allow-downloads requires --allow-execution")
            if not 1 <= args.check_timeout <= 600:
                raise ValueError("check-timeout must be 1–600 seconds")
            custom = {}
            for kind, commands in (("custom_test", args.test_command), ("custom_reproduction", args.reproduce_command)):
                for index, command in enumerate(commands, 1):
                    argv = shlex.split(command)
                    if not argv:
                        raise ValueError("Configured commands must not be empty")
                    custom[f"{kind}_{index}"] = argv
            repo = Repository(args.repository, allow_execution=args.allow_execution,
                              allow_downloads=args.allow_downloads, image=args.go_image, runner=args.runner,
                              custom_checks=custom, timeout=args.check_timeout)
            # Fail early on model connectivity before a potentially long NVD batch retrieval.
            model = Ollama(args.ollama_url, args.model)
            names = [m["name"] for m in model.models().get("models", [])]
            if args.model not in names:
                raise ServiceError("Requested local model is not installed on the Ollama endpoint")
            output = args.output or Path("artifacts") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            output.mkdir(parents=True, exist_ok=False)
            output.chmod(0o700)
            emit = Events(output / "events.jsonl")
            execution = repo.execution_preflight()
            emit("execution_mode", **execution)
            emit("preflight_start")
            probe = model.probe_tools()
            emit("preflight_passed", **probe)
        def nvd_progress(kind, **data):
            if args.command == "scan":
                emit(kind, **data)
            else:
                print(f"{kind}: " + json.dumps(data), file=sys.stderr, flush=True)
        nvd = NVD(key, timeout=args.nvd_timeout, progress=nvd_progress)
        print("Retrieving live NVD records…", file=sys.stderr, flush=True)
        cves = [nvd.get(args.cve.upper())] if getattr(args, "cve", None) else nvd.recent(args.limit, args.lookback_days)
        if not cves:
            print(f"NVD returned no qualifying CVEs in the last {args.lookback_days} days.", file=sys.stderr)
            return 1
        if not getattr(args, "cve", None) and len(cves) < args.limit:
            print(f"Only {len(cves)} qualifying CVEs found in the searched {args.lookback_days}-day interval.", file=sys.stderr)
        if args.command == "recent":
            print(json.dumps(cves, indent=2))
            return 0
        (output / "cves.json").write_text(json.dumps(cves, indent=2))
        results = []
        for cve in cves:
            emit("investigation_start", cve=cve["id"])
            results.append(investigate(cve, repo, model, emit, args.max_turns))
            write_reports(output, results)
            if results[-1].get("analysis_error"):
                emit("batch_stopped", cve=cve["id"], error=results[-1]["analysis_error"])
                print(f"Analysis failed; stopped remaining CVEs. Diagnostics: {output.resolve()}", file=sys.stderr)
                return 1
        print(f"Report: {(output / 'report.md').resolve()}")
        print(f"JSON and tool events: {output.resolve()}")
        # A completed uncertain investigation is still a valid report, not a clean bill of health.
        return 0
    except KeyboardInterrupt:
        print("Interrupted. Any already completed CVE reports remain on disk.", file=sys.stderr)
        return 130
    except (ServiceError, ValueError, OSError) as exc:
        if "emit" in locals():
            emit("scan_error", error=str(exc))
        print(f"Cannot complete {args.command}: {str(exc).rstrip('.')}.", file=sys.stderr)
        if args.command != "doctor":
            print("No offline CVE fallback was used.", file=sys.stderr)
        return 1
    finally:
        if repo is not None:
            repo.close()


if __name__ == "__main__":
    raise SystemExit(main())
