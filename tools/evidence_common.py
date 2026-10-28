"""Local evidence provenance; no credentials, exception messages, or payloads."""
import hashlib
import importlib.metadata
import json
import platform
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def provenance():
    files = []
    for folder in ('sdks/python', 'services/application', 'services/state'):
        files.extend((ROOT / folder).rglob('*.py'))
        files.extend((ROOT / folder).glob('pyproject.toml'))
    files.extend((ROOT / 'tools').glob('*.py'))
    files.extend((ROOT / 'tests').glob('*.py'))
    hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(set(files)) if '__pycache__' not in p.parts}
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, stderr=subprocess.DEVNULL, text=True).strip()
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, stderr=subprocess.DEVNULL, text=True).strip())
    except (OSError, subprocess.SubprocessError):
        commit, dirty = None, None
    try: crypto = importlib.metadata.version('cryptography')
    except importlib.metadata.PackageNotFoundError: crypto = None
    packages = sorted((d.metadata.get('Name', 'unknown'), d.version) for d in importlib.metadata.distributions())
    return json.dumps({'git_commit': commit, 'git_dirty': dirty, 'source_sha256': hashes, 'installed_distributions': packages,
                       'python': sys.version.split()[0], 'platform': platform.platform(),
                       'sqlite': sqlite3.sqlite_version, 'cryptography': crypto,
                       'scope': 'Python source trees, tool/test sources and installed distribution versions; binaries, OS configuration and external services not captured'}, sort_keys=True)


def failure_category(exc):
    # Never persist exception text, paths, wire data or third-party class names.
    if isinstance(exc, TimeoutError): return 'timeout'
    if isinstance(exc, OSError): return 'io_error'
    if isinstance(exc, (ValueError, TypeError)): return 'invalid_response_or_input'
    return 'unexpected_error'
