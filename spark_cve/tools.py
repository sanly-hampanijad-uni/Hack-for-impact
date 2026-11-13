import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


EXCLUDED = {".git", ".aws", ".ssh", ".codex", ".agents", "vendor", "node_modules", ".venv", "artifacts"}
TEXT_SUFFIXES = {".go", ".mod", ".sum", ".work", ".md", ".yaml", ".yml", ".json", ".toml", ".txt", ".conf"}
ATTACK_SURFACE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".csproj", ".cjs", ".cts", ".dart", ".ex", ".exs",
    ".h", ".hpp", ".html", ".java", ".js", ".jsx", ".kt", ".kts", ".mjs", ".mts",
    ".php", ".properties", ".py", ".rb", ".razor", ".rs", ".scala", ".sh", ".sql",
    ".svelte", ".swift", ".ts", ".tsx", ".vue", ".xml", ".ps1", ".jsp",
}


def tool(name, description, properties, required=()):
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties,
                           "required": list(required), "additionalProperties": False}}}


TOOLS = [
    tool("list_files", "List permitted repository text files. Path is relative to the repository root; use '.' for its root.",
         {"path": {"type": "string"}}),
    tool("read_file", "Read numbered lines from a repository-relative file path.",
         {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["path"]),
    tool("search_code", "Literal, case-insensitive search with numbered matches; optional path is repository-relative.",
         {"query": {"type": "string"}, "path": {"type": "string"}}, ["query"]),
    tool("inspect_dependencies", "Read Go manifests. Declared requirements are NOT the resolved build list; replacements and workspaces matter.", {}),
    tool("compare_versions", "Compare simple Go release versions deterministically. Returns unknown for pseudo/prerelease versions.",
         {"installed": {"type": "string"}, "boundary": {"type": "string"}}, ["installed", "boundary"]),
    tool("run_check", "Execute a fixed Go check in a disposable restricted Docker container, if enabled.",
         {"check_id": {"type": "string", "enum": ["go_test", "go_vet", "go_build_list"]}}, ["check_id"]),
]
ATTACK_SURFACE_TOOLS = [item for item in TOOLS if item["function"]["name"] != "run_check"]


class Repository:
    def __init__(self, root, *, allow_execution=False, allow_downloads=False, image="golang:1.24",
                 timeout=90, source_suffixes=()):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError("Repository directory does not exist")
        self.allow_execution, self.allow_downloads = allow_execution, allow_downloads
        self.image, self.timeout = image, timeout
        self.source_suffixes = TEXT_SUFFIXES | set(source_suffixes)
        self.evidence = []
        # Snapshot only eligible source files; no secret contents or Git objects.
        self.snapshot = self.fingerprint()

    def fingerprint(self):
        digest = hashlib.sha256()
        for path in self.files():
            digest.update(str(path.relative_to(self.root)).encode())
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def permitted(self, path):
        relative = path.relative_to(self.root)
        return (not any(p.startswith(".") or p in EXCLUDED for p in relative.parts)
                and path.suffix in self.source_suffixes and path.stat().st_size <= 256_000
                and not any(s in path.name.lower() for s in ("secret", "credential", "id_rsa", "private_key")))

    def resolve(self, path="."):
        if not isinstance(path, str):
            raise ValueError("Repository path must be a string")
        if re.match(r"^[a-zA-Z]:", path) or path.startswith(("\\\\", "//")):
            raise ValueError("Absolute paths are not permitted")
        relative = path.replace("\\", "/").lstrip("/") or "."
        if ".." in relative.split("/"):
            raise ValueError("Path escapes repository")
        candidate = self.root / relative
        # Reject all symlinks, including ones pointing back inside the repository.
        if any(p.is_symlink() for p in [candidate, *candidate.parents] if p != self.root.parent):
            raise ValueError("Symlink paths are not permitted")
        candidate = candidate.resolve()
        if not candidate.is_relative_to(self.root):
            raise ValueError("Path escapes repository")
        return candidate

    def files(self, path="."):
        base = self.resolve(path)
        if base.is_file():
            if self.permitted(base):
                yield base
            return
        for directory, dirs, names in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in EXCLUDED
                             and not (Path(directory) / d).is_symlink())
            for name in sorted(names):
                file = Path(directory) / name
                if not file.is_symlink() and self.permitted(file):
                    yield file

    def list_files(self, path="."):
        files = [str(f.relative_to(self.root)) for f in self.files(path)]
        return {"files": files[:500], "truncated": len(files) > 500,
                "scope": "Text allowlist only; excludes hidden files, vendor, symlinks, secrets, files over 256KB."}

    def read_file(self, path, start_line=1, end_line=120):
        file = self.resolve(path)
        if not file.is_file() or not self.permitted(file):
            raise ValueError("File unavailable or excluded")
        if type(start_line) is not int or type(end_line) is not int or start_line < 1 or end_line < start_line:
            raise ValueError("Invalid line interval")
        lines = file.read_text(errors="replace").splitlines()
        end = min(end_line, start_line + 119)
        numbered = [f"{i + 1}: {line[:1000]}" for i, line in enumerate(lines) if start_line <= i + 1 <= end]
        return {"path": str(file.relative_to(self.root)), "total_lines": len(lines),
                "lines": numbered, "truncated": end < min(end_line, len(lines)) or any(len(x) > 1000 for x in lines[start_line-1:end])}

    def search_code(self, query, path="."):
        if not isinstance(query, str) or not 1 <= len(query) <= 200:
            raise ValueError("Search query must contain 1–200 characters")
        matches = []
        for file in self.files(path):
            for i, line in enumerate(file.read_text(errors="replace").splitlines(), 1):
                if query.casefold() in line.casefold():
                    matches.append({"path": str(file.relative_to(self.root)), "line": i, "text": line[:1000]})
                    if len(matches) > 60:
                        return {"matches": matches[:60], "truncated": True}
        return {"matches": matches, "truncated": False,
                "limitation": "No match is not proof of absence; excluded/generated/runtime code is not searched."}

    def inspect_dependencies(self):
        manifests = []
        for path in self.files():
            if path.name not in {"go.mod", "go.work", "modules.txt"}:
                continue
            raw = path.read_text(errors="replace")
            declared, in_require = [], False
            for number, line in enumerate(raw.splitlines(), 1):
                stripped = line.split("//", 1)[0].strip()
                if stripped == "require (":
                    in_require = True
                    continue
                if stripped == ")":
                    in_require = False
                match = re.match(r"(?:require\s+)?([\w.\-/]+)\s+(v\S+)", stripped)
                if match and (in_require or stripped.startswith("require ")):
                    declared.append({"module": match[1], "version": match[2], "line": number})
            manifests.append({"path": str(path.relative_to(self.root)), "declared_requirements": declared,
                              "manifest": raw[:20000], "truncated": len(raw) > 20000})
            if len(manifests) >= 15:
                break
        return {"manifests": manifests, "resolution": "unresolved",
                "limitations": "go.mod requirements are minima. replace/exclude/go.work, build tags, transitive modules and toolchain versions need separate verification. go.sum is not a resolved lockfile. At most 15 manifests shown."}

    def compare_versions(self, installed, boundary):
        def parse(value):
            match = re.fullmatch(r"(?:go|v)?(\d+)\.(\d+)(?:\.(\d+))?(?:\+incompatible)?", value)
            return tuple(int(x or 0) for x in match.groups()) if match else None
        a, b = parse(installed), parse(boundary)
        return {"installed": installed, "boundary": boundary,
                "comparison": "unknown" if a is None or b is None else "less" if a < b else "greater" if a > b else "equal",
                "note": "Compares version strings only; does not establish active module version or product identity."}

    def run_check(self, check_id):
        if not self.allow_execution:
            return {"error": "Execution disabled; start with --allow-execution to enable isolated checks."}
        commands = {"go_test": "go test -count=1 -timeout=45s ./...", "go_vet": "go vet ./...",
                    "go_build_list": "go list -m -json all"}
        if check_id not in commands:
            raise ValueError("Unknown check")
        # Copy only permitted text files into staging: secrets and symlinks never enter the container.
        import tempfile
        with tempfile.TemporaryDirectory(prefix="spark-cve-check-") as directory:
            staging = Path(directory)
            staging.chmod(0o755)
            for source in self.files():
                target = staging / source.relative_to(self.root)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            import uuid
            name = "spark-cve-" + uuid.uuid4().hex[:12]
            command = ["docker", "run", "--rm", "--name", name, "--pull=never",
                       "--network=bridge" if self.allow_downloads else "--network=none",
                       "--memory=2g", "--cpus=2", "--pids-limit=128", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", "--read-only", "--user=65534:65534",
                       "--tmpfs=/tmp:rw,exec,size=1g,mode=1777", "--mount", f"type=bind,src={staging},dst=/input,readonly",
                       "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/cache", "-e", "GOMODCACHE=/tmp/mod",
                       "-e", "GOTOOLCHAIN=local", self.image, "sh", "-c",
                       "mkdir /tmp/work && cp -R /input/. /tmp/work/ && chmod -R u+w /tmp/work && cd /tmp/work && " + commands[check_id]]
            try:
                # TemporaryFile prevents unbounded process output from consuming Python memory.
                with tempfile.TemporaryFile() as output:
                    process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
                    try:
                        code = process.wait(timeout=self.timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        return {"error": "Check timed out", "check_id": check_id}
                    output.seek(0)
                    text = output.read(20001).decode(errors="replace")
                    return {"check_id": check_id, "exit_code": code, "output": text[:20000],
                            "truncated": len(text) > 20000, "image": self.image,
                            "limitation": "Executed a filtered copy; excluded fixtures and missing dependencies can cause failures. Container toolchain is not proof of deployment toolchain."}
            finally:
                try:
                    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    def invoke(self, agent, name, arguments, allowed_tools=TOOLS):
        allowed = {t["function"]["name"] for t in allowed_tools}
        if not isinstance(name, str) or name not in allowed:
            result = {"error": "Unknown tool"}
        else:
            try:
                result = getattr(self, name)(**arguments)
            except (ValueError, TypeError, OSError, subprocess.SubprocessError) as exc:
                result = {"error": str(exc)[:300]}
        item = {"id": f"E{len(self.evidence) + 1}", "agent": agent, "tool": name,
                "arguments": arguments, "result": result, "snapshot": self.snapshot}
        self.evidence.append(item)
        return item
