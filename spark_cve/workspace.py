"""Reusable local execution workspace. A temporary copy is not a sandbox."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile


class Workspace:
    def __init__(self, root, files, downloads, timeout):
        self.temporary = tempfile.TemporaryDirectory(prefix="spark-cve-work-")
        self.base = Path(self.temporary.name)
        self.work = self.base / "source"
        self.work.mkdir()
        for source in files:
            target = self.work / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(source.stat().st_mode & 0o777)
        self.downloads, self.timeout = downloads, timeout
        self.env = {k: os.environ[k] for k in ("PATH", "SystemRoot", "WINDIR") if k in os.environ}
        home = self.base / "home"
        home.mkdir()
        self.env.update({"HOME": str(home), "USERPROFILE": str(home), "GOENV": "off",
                         "GOPATH": str(self.base / "gopath"), "GOCACHE": str(self.base / "cache"),
                         "GOMODCACHE": str(self.base / "modules"), "GOTOOLCHAIN": "local",
                         "GOPROXY": "https://proxy.golang.org" if downloads else "off",
                         "GOSUMDB": "sum.golang.org" if downloads else "off",
                         "TMPDIR": str(self.base), "TMP": str(self.base), "TEMP": str(self.base),
                         "npm_config_cache": str(self.base / "npm-cache"),
                         "npm_config_userconfig": os.devnull, "PIP_CONFIG_FILE": os.devnull,
                         "PIP_DISABLE_PIP_VERSION_CHECK": "1", "CARGO_HOME": str(self.base / "cargo")})
        if not downloads:
            self.env.update({"PIP_NO_INDEX": "1", "npm_config_offline": "true", "CARGO_NET_OFFLINE": "true"})
        self.dependency_roots = {}
        self.python = sys.executable

    def close(self):
        self.temporary.cleanup()

    def run(self, argv, path="."):
        cwd = (self.work / path).resolve()
        if not cwd.is_relative_to(self.work) or not cwd.is_dir():
            return {"error": "Check directory is outside the prepared repository or missing"}
        binary = shutil.which(argv[0], path=self.env.get("PATH"))
        if not binary:
            return {"error": f"Required executable is unavailable: {argv[0]}", "command": argv}
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen([binary, *argv[1:]], cwd=cwd, env=self.env,
                                       stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=os.name == "posix")
            try:
                code = process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
                return {"error": "Check timed out", "command": argv, "execution_started": True}
            output.seek(0)
            raw = output.read(150001)
        return {"command": argv, "exit_code": code, "output": raw[:150000].decode(errors="replace"),
                "truncated": len(raw) > 150000, "execution_started": True,
                "runner": "local", "path": path,
                "limitation": "Filtered temporary copy; host-user permissions, not a sandbox. Excluded fixtures may affect results. Test success alone does not prove CVE exposure."}

    def resolve_go(self, path):
        result = self.run(["go", "list", "-m", "-json", "all"], path)
        if result.get("exit_code") != 0 or result.get("truncated"):
            return {**result, "resolution": "unresolved"}
        text = result["output"]
        # go may print download messages before JSON. Do not try to interpret them as modules.
        decoder, records = json.JSONDecoder(), []
        position = 0
        while position < len(text):
            while position < len(text) and text[position].isspace():
                position += 1
            if position >= len(text):
                break
            if text[position] != "{":
                newline = text.find("\n", position)
                if newline < 0:
                    break
                position = newline + 1
                continue
            module, length = decoder.raw_decode(text[position:])
            position += length
            effective = module.get("Replace", module)
            directory = effective.get("Dir")
            available = False
            if directory:
                directory = Path(directory).resolve()
                available = directory.is_relative_to(self.base)
                if available:
                    self.dependency_roots[("go", module["Path"])] = directory
            records.append({"package": module["Path"], "version": module.get("Version"),
                            "effective_version": effective.get("Version"), "main": module.get("Main", False),
                            "replacement": module.get("Replace", {}).get("Path"), "source_available": available})
        return {"resolution": "resolved" if records else "unresolved", "ecosystem": "go", "path": path,
                "packages": records, "command": result["command"], "exit_code": 0}

    def prepare(self, stack, path, files):
        if not self.downloads:
            return {"error": "Dependency installation requires --allow-downloads"}
        if stack == "node":
            return self.run(["npm", "ci" if "package-lock.json" in files else "install", "--ignore-scripts", "--no-audit", "--no-fund"], path)
        if stack == "go":
            return self.run(["go", "mod", "download"], path)
        if stack == "rust":
            return self.run(["cargo", "fetch", "--locked"], path)
        if stack == "python":
            environment = self.work / path / ".spark-venv"
            result = self.run([sys.executable, "-m", "venv", str(environment)], path)
            if result.get("exit_code") != 0:
                return result
            self.python = str(environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
            args = [self.python, "-m", "pip", "install", "-r", "requirements.txt"] if "requirements.txt" in files else [self.python, "-m", "pip", "install", "."]
            return self.run(args, path)
        return {"error": f"Automatic dependency installation is not implemented for {stack}; supply a prepared runtime or an operator-configured check"}
