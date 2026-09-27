"""Create local prerelease packages from a verified source tree; never publish packages."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, env, cwd=ROOT):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if result.returncode:
        raise RuntimeError(f"package command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    work, out = args.work_dir.resolve(), args.output_dir.resolve()
    report_path = work / "verification.json"
    verification = json.loads(report_path.read_text("utf-8"))
    if verification["failures"] or verification["passed"] != verification["total"]:
        raise RuntimeError("passing verification required before packaging")
    for name, digest in verification["source_sha256"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"source changed since verification: {name}")
    out.mkdir(parents=True, exist_ok=True)
    stage = work / "packaging" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    stage.mkdir(parents=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(work / "pydeps")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    logs = []
    shutil.copytree(ROOT / "sdks" / "python", stage / "python", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build"))
    logs.append(run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(stage / "python")], env))
    for project in ("SApi.Protocol", "SApi.AspNetCore"):
        logs.append(run(["dotnet", "pack", str(ROOT / "sdks" / "dotnet" / project / f"{project}.csproj"),
                         "--artifacts-path", str(work / "package-dotnet"), "--configuration", "Release", "--output", str(out),
                         "--nologo", "--verbosity", "quiet", "-p:NuGetAudit=false"], env))
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm: raise RuntimeError("npm required")
    logs.append(run([npm, "pack", "--pack-destination", str(out)], env, ROOT / "sdks" / "javascript"))
    base = "sapi-protocol-0.1.0-alpha.1"
    pom_dir = stage / "java" / "META-INF" / "maven" / "io.github.gnh0.sapi" / "sapi-protocol"
    pom_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "sdks" / "java" / "pom.xml", pom_dir / "pom.xml")
    shutil.copyfile(ROOT / "sdks" / "java" / "pom.xml", out / (base + ".pom"))
    logs.append(run(["jar", "--create", "--file", str(out / (base + ".jar")), "-C", str(work / "java"),
                     "io/github/gnh0/sapi", "-C", str(stage / "java"), "META-INF"], env))
    expected = {"SApi.Protocol.0.1.0-alpha.1.nupkg": "lib/net8.0/SApi.Protocol.dll",
                "SApi.AspNetCore.0.1.0-alpha.1.nupkg": "lib/net8.0/SApi.AspNetCore.dll",
                "sapi_protocol-0.1.0a1-py3-none-any.whl": "sapi/codec.py", base + ".jar": "io/github/gnh0/sapi/SecureServer.class"}
    for name, member in expected.items():
        with zipfile.ZipFile(out / name) as archive:
            if member not in archive.namelist(): raise RuntimeError(f"missing package content: {name}: {member}")
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(out.iterdir())
              if path.suffix in (".whl", ".gz", ".nupkg", ".tgz", ".jar", ".pom")}
    report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "verification_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(), "packages_sha256": hashes,
              "checks": "build/pack success and required archive members; package registry publication not performed"}
    (work / "packages.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    (work / "package.log").write_text("\n".join(logs), encoding="utf-8", newline="\n")
    (out / "SHA256SUMS").write_text("\n".join(digest + "  " + name for name, digest in hashes.items()) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"packages": list(hashes)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
