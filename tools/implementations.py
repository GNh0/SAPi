"""Trusted local driver registry. It describes build/launch commands, not language limits."""
import hashlib
import json
import os
from pathlib import Path
import sys


def build_registry(root: Path, work: Path, manifest: Path, run, env):
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
    values = {"root": str(root), "work": str(work), "python": sys.executable,
              "pathsep": os.pathsep, "java_classpath": os.pathsep.join(str(p) for p in jars)}
    sources = [str(p) for p in (root / "sdks" / "java" / "src" / "main" / "java").rglob("*.java")]
    commands = {}
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
