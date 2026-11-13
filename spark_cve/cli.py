import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import sys

from .agents import investigate
from .attack_surface import analyze_attack_surface
from .clients import NVD, Ollama, ServiceError
from .reporting import Events, write_attack_surface_reports, write_reports
from .tools import ATTACK_SURFACE_SUFFIXES, Repository


def parser():
    root = argparse.ArgumentParser(description="Investigate Go CVE exposure with Nemotron on DGX Spark")
    root.add_argument("--ollama-url", default=os.getenv("OLLAMA_URL", "http://127.0.0.1:11435"))
    root.add_argument("--model", default=os.getenv("NEMOTRON_MODEL", "nemotron-3-nano:30b"))
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check Ollama connectivity and installed model (no source is sent)")
    recent = sub.add_parser("recent", help="Retrieve latest scored HIGH/CRITICAL CVEs live from NVD")
    scan = sub.add_parser("scan", help="Investigate latest CVEs or one manual CVE against a Go repository")
    for command in (recent, scan):
        command.add_argument("--prompt-key", action="store_true", help="Read NVD key without echo; alternatively set NVD_API_KEY")
        command.add_argument("--limit", type=int, default=10)
        command.add_argument("--lookback-days", type=int, default=30)
    scan.add_argument("repository", type=Path)
    scan.add_argument("--cve", help="Investigate this CVE instead of the recent batch; still fetched live")
    scan.add_argument("--output", type=Path, help="New output directory (defaults to artifacts/<timestamp>)")
    scan.add_argument("--max-turns", type=int, default=10, help="Tool turns per agent, plus two final JSON attempts")
    scan.add_argument("--allow-execution", action="store_true", help="Allow fixed Go checks in restricted Docker containers")
    scan.add_argument("--allow-downloads", action="store_true", help="Give check containers network access for Go dependency retrieval")
    scan.add_argument("--go-image", default="golang:1.24", help="Preloaded Docker image appropriate to repository Go version")
    surface = sub.add_parser("attack-surface", help="Report source-supported attack vectors in a local application")
    surface.add_argument("repository", type=Path)
    surface.add_argument("--output", type=Path, help="New output directory (defaults to artifacts/<timestamp>)")
    surface.add_argument("--max-turns", type=int, default=10, help="Tool turns, plus two final JSON attempts")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            models = Ollama(args.ollama_url, args.model).models().get("models", [])
            names = [m["name"] for m in models]
            print(json.dumps({"endpoint": args.ollama_url, "requested_model": args.model, "installed_models": names}, indent=2))
            if args.model not in names:
                print("Requested model is not installed. Have the Spark operator load it locally.", file=sys.stderr)
                return 1
            print("Ollama is reachable and the model is listed. A scan must still verify real tool calling.")
            return 0
        if args.command == "attack-surface":
            if not 1 <= args.max_turns <= 30:
                raise ValueError("max-turns must be 1–30")
            repo = Repository(args.repository, source_suffixes=ATTACK_SURFACE_SUFFIXES)
            model = Ollama(args.ollama_url, args.model)
            names = [m["name"] for m in model.models().get("models", [])]
            if args.model not in names:
                raise ServiceError("Requested local model is not installed on the Ollama endpoint")
            output = args.output or Path("artifacts") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            output.mkdir(parents=True, exist_ok=False)
            output.chmod(0o700)
            result = analyze_attack_surface(repo, model, Events(output / "events.jsonl"), args.max_turns)
            write_attack_surface_reports(output, result)
            print(f"Report: {(output / 'attack-vector-report.md').resolve()}")
            print(f"JSON and tool events: {output.resolve()}")
            return 0
        if not 1 <= args.limit <= 10 or not 1 <= args.lookback_days <= 120:
            raise ValueError("limit must be 1–10 and lookback-days 1–120")
        if args.command == "scan":
            if not 1 <= args.max_turns <= 30:
                raise ValueError("max-turns must be 1–30")
            if args.allow_downloads and not args.allow_execution:
                raise ValueError("--allow-downloads requires --allow-execution")
            repo = Repository(args.repository, allow_execution=args.allow_execution,
                              allow_downloads=args.allow_downloads, image=args.go_image)
            # Fail early on model connectivity before a potentially long NVD batch retrieval.
            model = Ollama(args.ollama_url, args.model)
            names = [m["name"] for m in model.models().get("models", [])]
            if args.model not in names:
                raise ServiceError("Requested local model is not installed on the Ollama endpoint")
        key = getpass.getpass("NVD API key (not saved): ") if args.prompt_key else os.getenv("NVD_API_KEY")
        nvd = NVD(key)
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
        output = args.output or Path("artifacts") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        output.mkdir(parents=True, exist_ok=False)
        output.chmod(0o700)
        emit = Events(output / "events.jsonl")
        (output / "cves.json").write_text(json.dumps(cves, indent=2))
        attack_repo = Repository(args.repository, source_suffixes=ATTACK_SURFACE_SUFFIXES)
        attack_surface = analyze_attack_surface(attack_repo, model, emit, args.max_turns)
        write_attack_surface_reports(output, attack_surface)
        results = []
        for cve in cves:
            emit("investigation_start", cve=cve["id"])
            results.append(investigate(cve, repo, model, emit, args.max_turns,
                                       attack_surface=attack_surface))
            write_reports(output, results)
        print(f"Report: {(output / 'report.md').resolve()}")
        print(f"JSON and tool events: {output.resolve()}")
        # A completed uncertain investigation is still a valid report, not a clean bill of health.
        return 0
    except KeyboardInterrupt:
        print("Interrupted. Any already completed CVE reports remain on disk.", file=sys.stderr)
        return 130
    except (ServiceError, ValueError, OSError) as exc:
        print(f"Cannot complete {args.command}: {exc}.", file=sys.stderr)
        if args.command in {"scan", "recent"}:
            print("No offline CVE fallback was used.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
