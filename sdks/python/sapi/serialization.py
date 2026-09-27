from __future__ import annotations
import base64
import hashlib
import json
import math
import re
from .errors import SapiError

def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise SapiError()
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise SapiError() from exc
    if b64(raw) != value:
        raise SapiError()
    return raw


def _tree(value, depth=0):
    if depth > 32:
        raise SapiError()
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise SapiError()
    elif isinstance(value, (int, float)):
        if not math.isfinite(value) or (int(value) == value and abs(value) > 9007199254740991):
            raise SapiError()
    elif isinstance(value, list):
        for item in value:
            _tree(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SapiError()
            _tree(key, depth + 1)
            _tree(item, depth + 1)
    else:
        raise SapiError()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SapiError()
        result[key] = value
    return result


def parse(raw: bytes):
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(SapiError()))
        _tree(value)
        return value
    except Exception as exc:
        raise SapiError() from exc


def encode(value) -> bytes:
    _tree(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(wire: str) -> str:
    return b64(hashlib.sha256(wire.encode("ascii")).digest())
