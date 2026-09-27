"""Generate PUBLIC TEST vectors. Fixed IVs/test keys MUST NOT be reused in real traffic."""
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[1]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def derive(master, service, kid, direction):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"SAPI/0.1 HKDF-SHA-256",
                info=f"SAPI/0.1|{service}|{kid}|{direction}".encode("ascii")).derive(master)


def seal(master, payload, *, direction="req", service="demo", kid="alice-k1", header_raw=None, body_raw=None):
    header = {"alg": "dir", "enc": "A256GCM", "typ": "sapi+jwe", "kid": kid, "sapi": "0.1",
              "dir": direction, "svc": service, "crit": ["sapi", "dir", "svc"]}
    raw = header_raw if header_raw is not None else json.dumps(header, separators=(",", ":")).encode("utf-8")
    protected = b64(raw)
    iv = bytes(range(12))  # TEST ONLY, never exposed as a nonce option by production-facing SDKs.
    body = body_raw if body_raw is not None else json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    encrypted = AESGCM(derive(master, service, kid, direction)).encrypt(iv, body, protected.encode("ascii"))
    return ".".join((protected, "", b64(iv), b64(encrypted[:-16]), b64(encrypted[-16:])))


def main():
    keys = {"alice-k1": {"key": b64(bytes(range(32))), "subject": "alice", "scopes": ["echo", "orders"]},
            "bob-k1": {"key": b64(bytes(range(32, 64))), "subject": "bob", "scopes": ["echo"]}}
    request = {"id": "00112233445566778899aabbccddeeff", "iat": 1700000000, "exp": 1700000060,
               "op": "echo", "data": {"message": "안녕 🌐"}}
    wire = seal(bytes(range(32)), request)
    response = {"id": request["id"], "iat": 1700000001, "exp": 1700000061,
                "req": b64(hashlib.sha256(wire.encode("ascii")).digest()), "ok": True, "data": request["data"]}
    derived = {kid: {direction: derive(base64.urlsafe_b64decode(v["key"] + "="), "demo", kid, direction).hex()
                     for direction in ("req", "res")} for kid, v in keys.items()}
    data = {"warning": "PUBLIC TEST KEYS AND FIXED IVS; NEVER USE IN PRODUCTION", "now": 1700000005, "keys": keys,
            "derived": derived, "vectors": [{"dir": "req", "wire": wire, "payload": request},
                                           {"dir": "res", "wire": seal(bytes(range(32)), response, direction="res"), "payload": response}]}
    (ROOT / "tests" / "vectors.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
