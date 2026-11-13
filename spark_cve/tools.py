import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

from .ecosystems import ecosystem, parse_manifest, checks_for
from .workspace import Workspace


EXCLUDED = {".git", ".aws", ".ssh", ".codex", ".agents", "vendor", "node_modules", ".venv", "artifacts"}
TEXT_SUFFIXES = {".go", ".mod", ".sum", ".work", ".md", ".yaml", ".yml", ".json", ".toml", ".txt", ".conf",
                 ".html", ".css", ".tmpl", ".tpl"}


def tool(name, description, properties, required=()):
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties,
                           "required": list(required), "additionalProperties": False}}}


TOOLS = [
    tool("list_files", "List permitted repository text files; reports truncation.",
         {"path": {"type": "string"}}),
    tool("read_file", "Read numbered lines from a repository file.",
         {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["path"]),
    tool("search_code", "Literal, case-insensitive search with numbered matches.",
         {"query": {"type": "string"}, "path": {"type": "string"}}, ["query"]),
    tool("inspect_dependencies", "Detect stacks and parse manifests/lockfiles across languages. Declarations are not resolved runtime versions.", {}),
    tool("compare_versions", "Compare simple release versions only. Use advisory ecosystem rules; returns unknown for unsupported formats.",
         {"installed": {"type": "string"}, "boundary": {"type": "string"}}, ["installed", "boundary"]),
    tool("run_check", "Execute a fixed Go check using the configured laptop runner in a temporary source copy, if enabled.",
         {"check_id": {"type": "string", "minLength": 1}}, ["check_id"]),

    tool("resolve_dependencies", "Resolve actual build/environment versions where supported; otherwise report lockfile-only or missing coverage.",
         {"ecosystem": {"type": "string"}, "path": {"type": "string"}}),
    tool("inspect_dependency", "List files of a resolved dependency inside the prepared workspace cache. Does not search the application directory.",
         {"package": {"type": "string"}, "ecosystem": {"type": "string"}}, ["package"]),
    tool("read_dependency_file", "Read numbered dependency source from a previously resolved package.",
         {"package": {"type": "string"}, "path": {"type": "string"}, "ecosystem": {"type": "string"},
          "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["package", "path"]),
    tool("prepare_environment", "Install project dependencies in the temporary copy when execution AND downloads are enabled. Does not install system runtimes.",
         {"ecosystem": {"type": "string"}, "path": {"type": "string"}}, ["ecosystem"]),
    tool("run_targeted_test", "Run a selected existing test with fixed ecosystem-specific argv. Inspect assertions and output; a passing test is not proof of CVE exposure.",
         {"ecosystem": {"type": "string"}, "selector": {"type": "string"}, "path": {"type": "string"}}, ["ecosystem", "selector"]),
    tool("discover_tests", "List existing test files/selectors without executing them; do not invent test names.", {}),
    tool("search_dependency", "Search the actual downloaded source of a resolved dependency for an internal symbol.",
         {"package": {"type": "string"}, "query": {"type": "string"}, "ecosystem": {"type": "string"}}, ["package", "query"]),
]


class Repository:
    def __init__(self, root, *, allow_execution=False, allow_downloads=False, image="golang:1.24",
                 timeout=90, runner="local", custom_checks=None):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError("Repository directory does not exist")
        self.allow_execution, self.allow_downloads = allow_execution, allow_downloads
        self.image, self.timeout = image, timeout
        if runner not in {"local", "docker"}:
            raise ValueError("Runner must be local or docker")
        self.runner = runner
        self.custom_checks = custom_checks or {}
        self._workspace = None
        self._workspace_snapshot = None
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
        if (any(p.startswith(".") or p in EXCLUDED or p.lower().endswith("artifacts") for p in relative.parts)
                or path.stat().st_size > 256_000
                or any(s in path.name.lower() for s in ("secret", "credential", "id_rsa", "private_key"))
                or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}):
            return False
        raw = path.read_bytes()
        if b"\x00" in raw:
            return False
        try:
            raw.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    def resolve(self, path="."):
        candidate = self.root / path
        # Reject all symlinks, including ones pointing back inside the repository.
        if any(p.is_symlink() for p in [candidate, *candidate.parents] if p != self.root.parent):
            raise ValueError("Symlink paths are not permitted")
        candidate = candidate.resolve()
        if not candidate.is_relative_to(self.root):
            raise ValueError("Path escapes repository")
        return candidate

    def files(self, path="."):
        base = self.resolve(path)
        if not base.exists():
            raise ValueError("Repository path does not exist; dependency packages must use resolve_dependencies/inspect_dependency")
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
                "scope": "UTF-8 text across languages; excludes hidden files, vendor/generated directories, symlinks, secrets and files over 256KB."}

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
        stacks = set()
        for file in self.files():
            stack = ecosystem(file)
            if not stack:
                continue
            stacks.add(stack)
            raw = file.read_text()
            parsed = parse_manifest(file, raw)
            manifests.append({"path": str(file.relative_to(self.root)), "ecosystem": stack,
                              "declared_requirements": parsed["dependencies"],
                              "manifest": raw[:16000], "truncated": len(raw) > 16000,
                              **{k: v for k, v in parsed.items() if k != "dependencies"}})
            if len(manifests) >= 40:
                break
        return {"manifests": manifests, "ecosystems": sorted(stacks), "resolution": "unresolved",
                "available_checks": self.available_checks(),
                "limitations": "Declarations/lockfiles do not prove deployment versions. At most 40 manifests. Gradle/Yarn/pnpm/Gemfile details may require source inspection; unsupported resolution remains explicit."}

    def projects(self):
        projects = {}
        for file in self.files():
            stack = ecosystem(file)
            if stack:
                path = str(file.parent.relative_to(self.root))
                projects.setdefault((stack, path), set()).add(file.name)
        return projects

    def available_checks(self):
        checks = {}
        for (stack, path), names in self.projects().items():
            for name, argv in checks_for(stack, self.root / path, names).items():
                # A unique check per project; simple root names preserve the CLI API.
                key = name if path == "." else name + ":" + path
                checks[key] = {"argv": argv, "path": path, "ecosystem": stack}
        for name, argv in self.custom_checks.items():
            checks[name] = {"argv": argv, "path": ".", "ecosystem": "custom"}
        return checks

    def discover_tests(self):
        tests = []
        projects = self.projects()
        for file in self.files():
            relative = str(file.relative_to(self.root))
            stack = "go" if file.name.endswith("_test.go") else "python" if file.suffix == ".py" and (file.name.startswith("test_") or file.name.endswith("_test.py")) else "node" if re.search(r"(?:\.test|\.spec)\.[cm]?[jt]sx?$", file.name) else None
            if stack is None:
                continue
            directories = [directory for (kind, directory) in projects if kind == stack and file.is_relative_to(self.root / directory)]
            directory = max(directories, key=len) if directories else "."
            local = str(file.relative_to(self.root / directory))
            names = [m[1] for m in re.finditer(r"^func\s+(Test\w+)\s*\(", file.read_text(), re.M)] if stack == "go" else [local[:-3].replace("/", ".") if stack == "python" else local]
            tests += [{"ecosystem": stack, "file": relative, "path": directory, "selector": name} for name in names]
            if len(tests) >= 100:
                return {"tests": tests[:100], "truncated": True}
        return {"tests": tests, "truncated": False}

    def workspace(self):
        if not self.allow_execution:
            raise ValueError("Execution disabled; use --allow-execution")
        if self.runner != "local":
            raise ValueError("This tool currently requires --runner local; Docker supports fixed Go checks only")
        if self._workspace is not None and self._workspace_snapshot != self.snapshot:
            self.close()
        if self._workspace is None:
            self._workspace = Workspace(self.root, self.files(), self.allow_downloads, self.timeout)
            self._workspace_snapshot = self.snapshot
        return self._workspace

    def close(self):
        if self._workspace:
            self._workspace.close()
            self._workspace = None

    def __del__(self):
        workspace = getattr(self, "_workspace", None)
        if workspace:
            try:
                workspace.close()
            except OSError:
                pass

    def resolve_dependencies(self, ecosystem=None, path="."):
        selected = [(stack, directory) for stack, directory in self.projects()
                    if directory == path and (ecosystem is None or stack == ecosystem)]
        if len(selected) != 1:
            return {"resolution": "unresolved", "error": "Choose one detected ecosystem and its project directory", "projects": [list(p) for p in self.projects()]}
        stack, directory = selected[0]
        if not self.allow_execution:
            return {"resolution": "unresolved", "ecosystem": stack, "reason": "Execution disabled; manifests/locks are declarations only"}
        workspace = self.workspace()
        if stack == "go":
            if self.allow_downloads:
                downloaded = workspace.run(["go", "mod", "download"], directory)
                if downloaded.get("exit_code") != 0:
                    return {**downloaded, "resolution": "unresolved"}
            return workspace.resolve_go(directory)
        if stack == "node":
            result = workspace.run(["npm", "ls", "--all", "--json"], directory)
            if result.get("exit_code") == 0 and not result.get("truncated"):
                data, packages = json.loads(result["output"]), []
                def walk(tree, base):
                    for name, info in tree.get("dependencies", {}).items():
                        packages.append({"package": name, "version": info.get("version")})
                        location = (base / "node_modules" / name).resolve()
                        if location.is_relative_to(workspace.work) and location.is_dir():
                            workspace.dependency_roots[("node", name)] = location
                        walk(info, location)
                walk(data, workspace.work / path)
                return {"resolution": "resolved", "ecosystem": stack, "packages": packages}
            return {**result, "resolution": "unresolved", "next_action": "prepare_environment(node) when downloads are allowed; lockfiles alone are not an installed tree"}
        if stack == "rust":
            result = workspace.run(["cargo", "metadata", "--format-version", "1", "--locked"], directory)
            if result.get("exit_code") == 0 and not result.get("truncated"):
                packages = []
                for item in json.loads(result["output"]).get("packages", []):
                    location = Path(item["manifest_path"]).resolve().parent
                    if location.is_relative_to(workspace.base):
                        workspace.dependency_roots[(stack, item["name"])] = location
                    packages.append({"package": item["name"], "version": item["version"]})
                return {"resolution": "resolved", "ecosystem": stack, "packages": packages}
            return {**result, "resolution": "unresolved"}
        if stack == "python" and workspace.python != sys.executable:
            result = workspace.run([workspace.python, "-m", "pip", "list", "--format=json"], directory)
            if result.get("exit_code") == 0:
                rows = [{"package": p["name"], "version": p["version"]} for p in json.loads(result["output"])]
                return {"resolution": "resolved", "ecosystem": stack, "packages": rows,
                        "scope": "prepared project virtual environment, not deployment"}
        return {"resolution": "unresolved", "ecosystem": stack,
                "reason": "No active-environment resolver available. Inspect manifest/lock evidence; prepare a Python environment if relevant. Never infer NOT AFFECTED from unsupported tooling."}

    def prepare_environment(self, ecosystem, path="."):
        names = self.projects().get((ecosystem, path))
        if names is None:
            raise ValueError("No matching project at this path")
        return self.workspace().prepare(ecosystem, path, names)

    def _dependency(self, package, ecosystem):
        workspace = self.workspace()
        root = workspace.dependency_roots.get((ecosystem, package))
        if root is None:
            raise ValueError("Dependency source is not registered. Resolve dependencies first; local replacements outside the workspace are not read.")
        return root

    def inspect_dependency(self, package, ecosystem="go"):
        root = self._dependency(package, ecosystem)
        result = []
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in EXCLUDED and not (Path(directory) / d).is_symlink()]
            for name in sorted(files):
                p = Path(directory) / name
                if not p.is_symlink() and p.stat().st_size <= 256000:
                    result.append(str(p.relative_to(root)))
        result.sort(key=lambda p: (Path(p).suffix not in {".go", ".py", ".js", ".ts", ".rs", ".java", ".cs", ".php", ".rb"}, p))
        return {"package": package, "files": result[:400], "truncated": len(result) > 400,
                "next_action": "Use search_dependency for internal symbols, then read_dependency_file at the returned path/line"}

    def search_dependency(self, package, query, ecosystem="go"):
        if not isinstance(query, str) or not 1 <= len(query) <= 200:
            raise ValueError("Invalid dependency query")
        root = self._dependency(package, ecosystem)
        matches = []
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in EXCLUDED and not (Path(directory) / d).is_symlink())
            for name in sorted(files):
                file = Path(directory) / name
                if file.is_symlink() or file.suffix not in {".go", ".py", ".js", ".ts", ".rs", ".java", ".cs", ".php", ".rb"} or file.stat().st_size > 256000:
                    continue
                for number, line in enumerate(file.read_text(errors="replace").splitlines(), 1):
                    if query.casefold() in line.casefold():
                        matches.append({"path": str(file.relative_to(root)), "line": number, "text": line[:1000]})
                        if len(matches) >= 40:
                            return {"package": package, "matches": matches, "truncated": True}
        if not matches and "." in query and query.rsplit(".", 1)[-1]:
            leaf = query.rsplit(".", 1)[-1]
            return {**self.search_dependency(package, leaf, ecosystem), "original_query": query, "searched_symbol": leaf}
        return {"package": package, "matches": matches, "truncated": False}

    def read_dependency_file(self, package, path, ecosystem="go", start_line=1, end_line=120):
        root = self._dependency(package, ecosystem)
        candidate = (root / path).resolve()
        if not candidate.is_relative_to(root) or not candidate.is_file() or candidate.stat().st_size > 256000:
            raise ValueError("Dependency path unavailable or outside resolved package")
        if any(p.is_symlink() for p in [root / path, *(root / path).parents] if p.is_relative_to(root)):
            raise ValueError("Dependency symlinks are not followed")
        if any(p.startswith(".") or any(s in p.lower() for s in ("secret", "credential", "private_key")) for p in Path(path).parts):
            raise ValueError("Dependency secret/hidden paths are excluded")
        if candidate.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
            raise ValueError("Dependency key files are excluded")
        raw = candidate.read_bytes()
        if b"\x00" in raw or start_line < 1 or end_line < start_line:
            raise ValueError("Invalid dependency file or line range")
        lines = raw.decode("utf-8").splitlines()
        end = min(end_line, start_line + 119)
        return {"package": package, "path": path, "lines": [f"{i+1}: {s[:1000]}" for i, s in enumerate(lines) if start_line <= i+1 <= end],
                "total_lines": len(lines), "truncated": end < min(end_line, len(lines))}

    def run_targeted_test(self, ecosystem, selector, path="."):
        if not isinstance(selector, str) or not 1 <= len(selector) <= 200 or selector.startswith("-"):
            raise ValueError("Invalid test selector")
        if (ecosystem, path) not in self.projects():
            raise ValueError("No matching project at this path")
        workspace = self.workspace()
        if ecosystem == "go":
            names = [t["selector"] for t in self.discover_tests()["tests"] if t["ecosystem"] == "go" and t["path"] == path]
            try:
                selected = [name for name in names if re.search(selector, name)]
            except re.error:
                raise ValueError("Invalid Go test selector") from None
            if not selected:
                return {"error": "No existing tests match this selector. Choose from discovered tests, do not invent names.", "available_selectors": names}
            argv = ["go", "test", "-v", "-count=1", "-timeout=45s", "-run", selector, "./..."]
        elif ecosystem == "python":
            if not re.fullmatch(r"[\w.]+", selector):
                raise ValueError("Use a unittest module/class/method selector")
            argv = [workspace.python, "-m", "unittest", "-v", selector]
        elif ecosystem == "node":
            candidate = (workspace.work / path / selector).resolve()
            if not candidate.is_relative_to(workspace.work) or not candidate.is_file():
                raise ValueError("Node test must be a file in the repository")
            argv = ["node", "--test", selector]
        elif ecosystem == "rust":
            argv = ["cargo", "test", "--locked", selector]
        else:
            raise ValueError("Targeted-test selection is unsupported for this stack; use a configured project check")
        return {**workspace.run(argv, path), "check_id": "targeted_test", "selector": selector, "ecosystem": ecosystem}

    def compare_versions(self, installed, boundary):
        def parse(value):
            match = re.fullmatch(r"(?:go|v)?(\d+)\.(\d+)(?:\.(\d+))?(?:\+incompatible)?", value)
            return tuple(int(x or 0) for x in match.groups()) if match else None
        a, b = parse(installed), parse(boundary)
        return {"installed": installed, "boundary": boundary,
                "comparison": "unknown" if a is None or b is None else "less" if a < b else "greater" if a > b else "equal",
                "note": "Compares version strings only; does not establish active module version or product identity."}

    def execution_preflight(self):
        """Check prerequisites for the configured laptop runner."""
        if not self.allow_execution:
            return {"enabled": False, "downloads_allowed": False, "runner": self.runner}
        if self.runner == "local":
            available = self.available_checks()
            missing = sorted({info["argv"][0] for info in available.values() if not shutil.which(info["argv"][0])})
            return {"enabled": True, "downloads_allowed": self.allow_downloads, "runner": "local",
                    "available_checks": sorted(available), "missing_runtimes": missing,
                    "limitation": "Missing runtimes disable their checks; source investigation remains available. Host execution is not sandboxed."}
        try:
            result = subprocess.run(["docker", "image", "inspect", "--", self.image],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError("Execution requires a working Docker CLI and daemon. Start Docker or omit --allow-execution.") from None
        if result.returncode:
            raise ValueError(f"Docker cannot inspect image {self.image!r}. Start Docker and preload the Go image; then retry with --go-image IMAGE.")
        return {"enabled": True, "downloads_allowed": self.allow_downloads, "runner": "docker", "image": self.image}

    def _run_local_check(self, check_id):
        info = self.available_checks().get(check_id)
        if info is None:
            raise ValueError("Unknown check; inspect_dependencies lists configured checks")
        workspace = self.workspace()
        argv = list(info["argv"])
        if info["ecosystem"] == "python":
            argv[0] = workspace.python
        if not self.allow_downloads and argv[0] in {"mvn", "gradle"}:
            argv.append("-o" if argv[0] == "mvn" else "--offline")
        if check_id.startswith("go_build_list"):
            return {**self.resolve_dependencies("go", info["path"]), "check_id": check_id}
        return {**workspace.run(argv, info["path"]), "check_id": check_id, "ecosystem": info["ecosystem"]}

    def run_check(self, check_id):
        if not self.allow_execution:
            return {"error": "Execution disabled; start with --allow-execution to enable project checks."}
        if self.runner == "local":
            return self._run_local_check(check_id)
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

    def invoke(self, agent, name, arguments):
        allowed = {t["function"]["name"] for t in TOOLS}
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
