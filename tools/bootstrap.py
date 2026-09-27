"""Fetch pinned build dependencies into an explicit scratch folder; never install globally."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
JARS = {"jackson-core": "2.22.3", "jackson-databind": "2.22.3", "jackson-annotations": "2.22"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--write-lock", action="store_true", help="maintainer: update hashes after trusted HTTPS download")
    args = parser.parse_args()
    jar_dir = args.work_dir.resolve() / "jars"
    jar_dir.mkdir(parents=True, exist_ok=True)
    lock_path = ROOT / "tools" / "dependencies.json"
    expected = json.loads(lock_path.read_text("utf-8")) if lock_path.exists() else {}
    observed = {}
    for artifact, version in JARS.items():
        name = f"{artifact}-{version}.jar"
        url = f"https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/{artifact}/{version}/{name}"
        target = jar_dir / name
        if not target.exists():
            with urllib.request.urlopen(url, timeout=30) as response:
                target.write_bytes(response.read())
        sha = hashlib.sha256(target.read_bytes()).hexdigest()
        if not args.write_lock and (name not in expected or expected[name] != sha):
            raise RuntimeError(f"dependency integrity check failed: {name}")
        observed[name] = sha
        print(name, sha)
    if args.write_lock:
        lock_path.write_text(json.dumps(observed, indent=2) + "\n", encoding="utf-8", newline="\n")
    pydeps = args.work_dir.resolve() / "pydeps"
    subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--target", str(pydeps),
                    "cryptography==50.0.1", "build==1.3.0", "setuptools==84.0.0", "wheel==0.48.0", "psycopg[binary]==3.3.6"], check=True)


if __name__ == "__main__":
    main()
