"""Query OSV for exact project/build package versions; preserve a dated report."""
import argparse
import datetime
import hashlib
import importlib.metadata
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--work-dir", type=Path, required=True); args = parser.parse_args()
    work = args.work_dir.resolve()
    packages = [{"package": {"ecosystem": "PyPI", "name": d.metadata["Name"]}, "version": d.version}
                for d in importlib.metadata.distributions(path=[str(work / "pydeps")])]
    for artifact, version in (("jackson-core", "2.22.3"), ("jackson-databind", "2.22.3"), ("jackson-annotations", "2.22")):
        packages.append({"package": {"ecosystem": "Maven", "name": "com.fasterxml.jackson.core:" + artifact}, "version": version})
    packages.sort(key=lambda x: (x["package"]["ecosystem"], x["package"]["name"]))
    request = urllib.request.Request("https://api.osv.dev/v1/querybatch", json.dumps({"queries": packages}).encode(),
                                    {"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response: observed = json.load(response)
    if len(observed["results"]) != len(packages): raise RuntimeError("incomplete OSV response")
    findings = []
    for package, result in zip(packages, observed["results"]):
        if result.get("vulns"): findings.append({"query": package, "advisories": result["vulns"]})
    report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "provider": "https://api.osv.dev/v1/querybatch",
              "queries": packages, "findings": findings,
              "scope": "Exact installed PyPI and Maven project/build dependencies. Runtime/OS, unreported vulnerabilities and local code are outside this advisory query.",
              "dependency_lock_sha256": hashlib.sha256((ROOT / "tools/dependencies.json").read_bytes()).hexdigest()}
    (work / "dependency-audit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"packages": len(packages), "findings": len(findings)}))
    return 1 if findings else 0


if __name__ == "__main__": raise SystemExit(main())
