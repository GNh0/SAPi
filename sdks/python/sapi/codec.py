import hashlib
import hmac
import math
import secrets
import threading
import time
from typing import Callable
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .constants import MAX_WIRE, MAX_BODY, NAME, REQUEST_ID, HEADER_KEYS
from .errors import SapiError
from .models import KeyRecord, Principal, RequestContext
from .serialization import b64, unb64, parse, encode, digest

class Codec:
    def __init__(self, service: str, keys: dict[str, KeyRecord], clock: Callable[[], int] | None = None):
        if not NAME.fullmatch(service) or not keys or any(not NAME.fullmatch(k) or not isinstance(v, KeyRecord) for k, v in keys.items()):
            raise ValueError("valid service and key identifiers required")
        self.service, self._keys = service, dict(keys)
        self.clock = clock or (lambda: int(time.time()))
        self._counts = {}
        self._lock = threading.Lock()

    def derive(self, kid: str, direction: str) -> bytes:
        if direction not in ("req", "res") or kid not in self._keys:
            raise SapiError()
        prk = hmac.new(b"SAPI/0.1 HKDF-SHA-256", self._keys[kid].master, hashlib.sha256).digest()
        info = f"SAPI/0.1|{self.service}|{kid}|{direction}".encode("ascii")
        return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    def principal(self, kid: str) -> Principal:
        if kid not in self._keys:
            raise SapiError()
        record = self._keys[kid]
        return Principal(record.subject, record.scopes)

    def _validate(self, payload, direction):
        if not isinstance(payload, dict):
            raise SapiError()
        if direction == "req":
            expected = {"id", "iat", "exp", "op", "data"}
            if not isinstance(payload.get("op"), str) or not NAME.fullmatch(payload["op"]):
                raise SapiError()
        else:
            if type(payload.get("ok")) is not bool:
                raise SapiError()
            expected = {"id", "iat", "exp", "req", "ok", "data" if payload["ok"] else "error"}
            if not isinstance(payload.get("req"), str) or len(unb64(payload["req"])) != 32:
                raise SapiError()
            if not payload["ok"] and (not isinstance(payload.get("error"), str) or not NAME.fullmatch(payload["error"])):
                raise SapiError()
        if set(payload) != expected or not isinstance(payload.get("id"), str) or not REQUEST_ID.fullmatch(payload["id"]):
            raise SapiError()
        if "data" in expected and not isinstance(payload["data"], dict):
            raise SapiError()
        for name in ("iat", "exp"):
            v = payload[name]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or int(v) != v or not 0 <= v <= 9007199254740991:
                raise SapiError()
        now = self.clock()
        if not 1 <= payload["exp"] - payload["iat"] <= 60 or payload["iat"] > now + 5 or now >= payload["exp"]:
            raise SapiError()

    def seal(self, kid: str, direction: str, payload: dict) -> str:
        if direction not in ("req", "res"):
            raise SapiError()
        self._validate(payload, direction)
        body = encode(payload)
        if len(body) > MAX_BODY:
            raise SapiError()
        with self._lock:
            key = (kid, direction)
            count = self._counts.get(key, 0)
            if count >= 1048576:
                raise SapiError("key_rotation_required")
            self._counts[key] = count + 1
        header = {"alg": "dir", "enc": "A256GCM", "typ": "sapi+jwe", "kid": kid,
                  "sapi": "0.1", "dir": direction, "svc": self.service, "crit": ["sapi", "dir", "svc"]}
        protected = b64(encode(header))
        iv = secrets.token_bytes(12)
        encrypted = AESGCM(self.derive(kid, direction)).encrypt(iv, body, protected.encode("ascii"))
        return ".".join((protected, "", b64(iv), b64(encrypted[:-16]), b64(encrypted[-16:])))

    def open(self, wire: str, direction: str):
        try:
            if not isinstance(wire, str) or len(wire) > MAX_WIRE or not wire.isascii() or direction not in ("req", "res"):
                raise SapiError()
            parts = wire.split(".")
            if len(parts) != 5 or parts[1] != "":
                raise SapiError()
            header_raw = unb64(parts[0])
            if len(header_raw) > 1024:
                raise SapiError()
            header = parse(header_raw)
            if not isinstance(header, dict) or set(header) != HEADER_KEYS:
                raise SapiError()
            if any(header.get(k) != v for k, v in {"alg": "dir", "enc": "A256GCM", "typ": "sapi+jwe", "sapi": "0.1", "dir": direction, "svc": self.service}.items()):
                raise SapiError()
            if header["crit"] != ["sapi", "dir", "svc"] or not isinstance(header["kid"], str) or not NAME.fullmatch(header["kid"]):
                raise SapiError()
            iv, ciphertext, tag = (unb64(parts[i]) for i in (2, 3, 4))
            if len(iv) != 12 or len(tag) != 16 or len(ciphertext) > MAX_BODY:
                raise SapiError()
            plaintext = AESGCM(self.derive(header["kid"], direction)).decrypt(iv, ciphertext + tag, parts[0].encode("ascii"))
            payload = parse(plaintext)
            self._validate(payload, direction)
            return header["kid"], payload
        except Exception as exc:
            raise SapiError() from exc

    def request(self, kid: str, operation: str, data: dict) -> RequestContext:
        now = self.clock()
        payload = {"id": secrets.token_hex(16), "iat": now, "exp": now + 60, "op": operation, "data": data}
        return RequestContext(self.seal(kid, "req", payload), kid, payload["id"])

    def accept_response(self, context: RequestContext, wire: str) -> dict:
        with context.lock:
            if context.consumed:
                raise SapiError("response_replay")
            kid, payload = self.open(wire, "res")
            if kid != context.kid or payload["id"] != context.request_id or not hmac.compare_digest(payload["req"], digest(context.wire)):
                raise SapiError()
            context.consumed = True
            return payload
