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
from implementations import source_hashes


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
    state_path = work / "state-verification.json"
    state = json.loads(state_path.read_text("utf-8"))
    profiles = {name: json.loads((work / (name + "-verification.json")).read_text("utf-8")) for name in ("security", "application")}
    if verification["failures"] or verification["passed"] != verification["total"]:
        raise RuntimeError("passing verification required before packaging")
    if state["failures"] or state["passed"] != state["total"]: raise RuntimeError("passing state verification required before packaging")
    for profile in profiles.values():
        if profile["failures"] or profile["passed"] != profile["total"]:raise RuntimeError("passing application security verification required before packaging")
    source_snapshot = source_hashes(ROOT)
    for verified in (verification,state,*profiles.values()):
        if verified["source_sha256"] != source_snapshot:
            raise RuntimeError("source tree changed since verification")
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
    shutil.copytree(ROOT / "services/state", stage / "state", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build"))
    logs.append(run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(stage / "state")], env))
    shutil.copytree(ROOT / "services/application", stage / "application", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build"))
    logs.append(run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(stage / "application")], env))
    for project in ("SApi.Protocol", "SApi.AspNetCore", "SApi.AspNet"):
        logs.append(run(["dotnet", "pack", str(ROOT / "sdks" / "dotnet" / project / f"{project}.csproj"),
                         "--artifacts-path", str(work / "package-dotnet"), "--configuration", "Release", "--output", str(out),
                         "--nologo", "--verbosity", "quiet", "-p:NuGetAudit=false"], env))
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm: raise RuntimeError("npm required")
    logs.append(run([npm, "pack", "--pack-destination", str(out)], env, ROOT / "sdks" / "javascript"))
    base = "sapi-protocol-0.1.0-alpha.4"
    pom_dir = stage / "java" / "META-INF" / "maven" / "io.github.gnh0.sapi" / "sapi-protocol"
    pom_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "sdks" / "java" / "pom.xml", pom_dir / "pom.xml")
    shutil.copyfile(ROOT / "sdks" / "java" / "pom.xml", out / (base + ".pom"))
    logs.append(run(["jar", "cf", str(out / (base + ".jar")), "-C", str(work / "java"),
                     "io/github/gnh0/sapi", "-C", str(stage / "java"), "META-INF"], env))
    expected = {"SApi.Protocol.0.1.0-alpha.4.nupkg": "lib/net8.0/SApi.Protocol.dll",
                "SApi.AspNetCore.0.1.0-alpha.4.nupkg": "lib/net8.0/SApi.AspNetCore.dll",
                "SApi.AspNet.0.1.0-alpha.4.nupkg": "lib/net462/SApi.AspNet.dll",
                "sapi_protocol-0.1.0a4-py3-none-any.whl": "sapi/codec.py", "sapi_state-0.1.0a4-py3-none-any.whl": "sapi_state/cli.py", "sapi_application-0.1.0a4-py3-none-any.whl": "sapi_application/application.py", base + ".jar": "io/github/gnh0/sapi/SecureServer.class"}
    for name, member in expected.items():
        with zipfile.ZipFile(out / name) as archive:
            if member not in archive.namelist(): raise RuntimeError(f"missing package content: {name}: {member}")
    for package, framework in (("SApi.Protocol","net462"),("SApi.Protocol","netstandard2.0"),("SApi.Protocol","net6.0"),("SApi.AspNetCore","net6.0")):
        with zipfile.ZipFile(out / (package + ".0.1.0-alpha.4.nupkg")) as archive:
            if f"lib/{framework}/{package}.dll" not in archive.namelist(): raise RuntimeError("missing compatibility assembly")
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(out.iterdir())
              if path.suffix in (".whl", ".gz", ".nupkg", ".tgz", ".jar", ".pom")}
    if source_hashes(ROOT) != source_snapshot:
        raise RuntimeError("source tree changed during packaging")
    report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_sha256": source_snapshot,
              "verification_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(), "packages_sha256": hashes,
              "state_verification_sha256": hashlib.sha256(state_path.read_bytes()).hexdigest(),
              "security_verification_sha256": hashlib.sha256((work / "security-verification.json").read_bytes()).hexdigest(),
              "application_verification_sha256": hashlib.sha256((work / "application-verification.json").read_bytes()).hexdigest(),
              "checks": "build/pack success and required archive members; package registry publication not performed"}
    (work / "packages.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    (work / "package.log").write_text("\n".join(logs), encoding="utf-8", newline="\n")
    (out / "SHA256SUMS").write_text("\n".join(digest + "  " + name for name, digest in hashes.items()) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"packages": list(hashes)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
