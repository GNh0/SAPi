"""Trusted local driver registry. It describes build/launch commands, not language limits."""
import hashlib
import json
import os
from pathlib import Path
import sys


def source_hashes(root):
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in (root/"sdks",root/"services") for p in folder.rglob("*")
            if p.is_file() and p.suffix in (".py",".cs",".java",".js",".toml",".xml",".json",".props",".csproj")}

class Commands(dict):
    def checked_hashes(self, root):
        if source_hashes(root)!=self.source_sha256:raise RuntimeError("SDK/service source changed during verification")
        return self.source_sha256

def build_registry(root: Path, work: Path, manifest: Path, run, env, snapshot=None):
    before=source_hashes(root) if snapshot is None else snapshot
    entries = json.loads(manifest.read_text("utf-8"))
    if not isinstance(entries, dict) or not entries:
        raise ValueError("at least one implementation required")
    jars = []
    needs_java = "{java_classpath}" in json.dumps(entries)
    lock = json.loads((root / "tools" / "dependencies.json").read_text("utf-8")) if needs_java else {}
    for name, expected in lock.items():
        path = work / "jars" / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"jar integrity failure: {name}")
        jars.append(path)
    (work / "java").mkdir(exist_ok=True)
    values = {"root": str(root), "work": str(work), "python": env.get("SAPI_PYTHON", sys.executable),
              "node": env.get("SAPI_NODE", "node"), "java": env.get("SAPI_JAVA", "java"), "javac": env.get("SAPI_JAVAC", "javac"),
              "pathsep": os.pathsep, "java_classpath": os.pathsep.join(str(p) for p in jars)}
    sources = [str(p) for p in (root / "sdks" / "java" / "src" / "main" / "java").rglob("*.java")]
    commands = Commands();commands.source_sha256=before
    for name, entry in entries.items():
        if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in name):
            raise ValueError("invalid implementation name")
        def expand(command):
            if not isinstance(command, list) or not command or any(not isinstance(x, str) for x in command):
                raise ValueError("argv list required")
            result = []
            for token in command:
                result.extend(sources if token == "{java_sources}" else [token.format_map(values)])
            return result
        logs = []
        for command in entry.get("build", []):
            logs.append(run(expand(command), env=env))
        if logs:
            (work / f"{name}-build.log").write_text("\n".join(logs), encoding="utf-8", newline="\n")
        if "artifact" in entry:
            matches = list(work.glob(entry["artifact"]))
            if len(matches) != 1:
                raise RuntimeError(f"ambiguous {name} artifact: {matches}")
            values["artifact"] = str(matches[0])
        commands[name] = expand(entry["command"])
        values.pop("artifact", None)
    return commands
