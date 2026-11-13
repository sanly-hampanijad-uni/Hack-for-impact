"""Small deterministic ecosystem adapters; declarations never imply resolution."""
import json
import re
import sys
import tomllib
import xml.etree.ElementTree as ET


MANIFESTS = {
    "go.mod": "go", "go.work": "go", "package.json": "node", "package-lock.json": "node",
    "yarn.lock": "node", "pnpm-lock.yaml": "node", "requirements.txt": "python",
    "pyproject.toml": "python", "poetry.lock": "python", "uv.lock": "python", "Pipfile.lock": "python",
    "Cargo.toml": "rust", "Cargo.lock": "rust", "pom.xml": "java", "build.gradle": "java",
    "build.gradle.kts": "java", "composer.json": "php", "composer.lock": "php",
    "Gemfile": "ruby", "Gemfile.lock": "ruby", "packages.lock.json": "dotnet",
}


def ecosystem(path):
    return MANIFESTS.get(path.name, "dotnet" if path.suffix in {".csproj", ".fsproj", ".vbproj"} else None)


def parse_manifest(path, raw):
    stack = ecosystem(path)
    rows = []
    def add(name, version, kind="declared", **extra):
        rows.append({"package": name, "module": name, "version": str(version), "kind": kind, **extra})
    try:
        if path.name == "go.mod":
            active = False
            for i, line in enumerate(raw.splitlines(), 1):
                text = line.split("//", 1)[0].strip()
                if text == "require (":
                    active = True
                elif text == ")":
                    active = False
                else:
                    match = re.fullmatch(r"(?:require\s+)?([\w.\-/]+)\s+(v\S+)", text)
                    if match and (active or text.startswith("require ")):
                        add(match[1], match[2], line=i)
        elif path.name == "package.json":
            data = json.loads(raw)
            for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for name, value in data.get(group, {}).items():
                    add(name, value, group=group)
        elif path.name == "package-lock.json":
            data = json.loads(raw)
            for location, info in data.get("packages", {}).items():
                if "node_modules/" in location and info.get("version"):
                    add(info.get("name", location.rsplit("node_modules/", 1)[-1]), info["version"], "locked")
            if not data.get("packages"):
                def visit(deps):
                    for name, info in deps.items():
                        if info.get("version"):
                            add(name, info["version"], "locked")
                        visit(info.get("dependencies", {}))
                visit(data.get("dependencies", {}))
        elif path.name == "requirements.txt":
            for line in raw.splitlines():
                match = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*([^#;]*)", line)
                if match:
                    add(match[1], match[2].strip() or "unspecified")
        elif path.suffix == ".toml" or path.name in {"poetry.lock", "uv.lock"}:
            data = tomllib.loads(raw)
            if stack == "python":
                for spec in data.get("project", {}).get("dependencies", []):
                    match = re.match(r"([\w.-]+)(.*)", spec)
                    if match:
                        add(match[1], match[2] or "unspecified")
                for name, version in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
                    add(name, version)
                for item in data.get("package", []):
                    add(item["name"], item.get("version", "unknown"), "locked")
            elif stack == "rust":
                for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                    for name, value in data.get(group, {}).items():
                        add(name, value.get("version", "path/git/workspace") if isinstance(value, dict) else value)
        elif path.name == "Cargo.lock":
            for item in tomllib.loads(raw).get("package", []):
                add(item["name"], item["version"], "locked")
        elif path.name == "Pipfile.lock":
            data = json.loads(raw)
            for group in ("default", "develop"):
                for name, info in data.get(group, {}).items():
                    add(name, info.get("version", "unknown"), "locked")
        elif path.name in {"composer.json", "composer.lock"}:
            data = json.loads(raw)
            if path.name.endswith(".json"):
                for group in ("require", "require-dev"):
                    for name, version in data.get(group, {}).items():
                        add(name, version)
            else:
                for item in data.get("packages", []) + data.get("packages-dev", []):
                    add(item["name"], item["version"], "locked")
        elif path.name == "pom.xml" or path.suffix in {".csproj", ".fsproj", ".vbproj"}:
            if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
                raise ValueError("XML entity declarations are not supported")
            root = ET.fromstring(raw)
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag == "dependency":
                    children = {c.tag.rsplit("}", 1)[-1]: c.text for c in element}
                    add(str(children.get("groupId", "")) + ":" + str(children.get("artifactId", "")), children.get("version", "managed"))
                elif tag == "PackageReference":
                    add(element.attrib.get("Include", "unknown"), element.attrib.get("Version", "managed"))
        elif path.name == "Gemfile.lock":
            for name, version in re.findall(r"^    ([\w.-]+) \(([^)]+)\)", raw, re.M):
                add(name, version, "locked")
        elif path.name == "packages.lock.json":
            for deps in json.loads(raw).get("dependencies", {}).values():
                for name, info in deps.items():
                    add(name, info.get("resolved", "unknown"), "locked")
    except (ValueError, TypeError, KeyError, AttributeError, ET.ParseError) as exc:
        return {"ecosystem": stack, "dependencies": rows[:300], "parse_error": type(exc).__name__}
    return {"ecosystem": stack, "dependencies": rows[:300], "truncated": len(rows) > 300}


def checks_for(stack, directory, names, custom=None):
    """Return fixed argv; only the operator can configure arbitrary commands."""
    if stack == "go":
        return {"go_test": ["go", "test", "-count=1", "-timeout=45s", "-v", "./..."],
                "go_vet": ["go", "vet", "./..."], "go_build_list": ["go", "list", "-m", "-json", "all"]}
    if stack == "python":
        args = [sys.executable, "-m", "unittest", "discover", "-v"]
        if (directory / "tests").is_dir():
            args += ["-s", "tests"]
        return {"python_test": args, "python_pytest": [sys.executable, "-m", "pytest", "-v"]}
    if stack == "node":
        try:
            data = json.loads((directory / "package.json").read_text())
        except (ValueError, OSError):
            data = {}
        return {"node_test": ["npm", "test"] if data.get("scripts", {}).get("test") else ["node", "--test"],
                "node_dependencies": ["npm", "ls", "--all", "--json"]}
    if stack == "rust":
        return {"rust_test": ["cargo", "test", "--locked"],
                "rust_dependencies": ["cargo", "metadata", "--format-version", "1", "--locked"]}
    if stack == "java":
        return {"java_test": ["mvn", "-B", "test"]} if "pom.xml" in names else {"java_test": ["gradle", "test", "--no-daemon"]}
    if stack == "dotnet":
        return {"dotnet_test": ["dotnet", "test", "--no-restore"]}
    if stack == "php":
        return {"php_test": ["composer", "run-script", "test"]}
    if stack == "ruby":
        return {"ruby_test": ["bundle", "exec", "rake", "test"]}
    return {}
