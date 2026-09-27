from __future__ import annotations
import hashlib
import hmac
import math
import secrets
import time
import threading
from typing import Callable, Optional, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .constants import MAX_WIRE, MAX_BODY, NAME, REQUEST_ID, HEADER_KEYS
from .errors import SapiError
from .models import KeyRecord, Principal, RequestContext
from .keys import KeyProvider, StaticKeyProvider
from .serialization import b64, unb64, parse, encode, digest

class Codec:
    def __init__(self, service: str, keys: Union[dict[str, KeyRecord], KeyProvider], clock: Optional[Callable[[], int]] = None):
        if not NAME.fullmatch(service):
            raise ValueError("valid service and key identifiers required")
        if isinstance(keys, dict):
            if not keys or any(not NAME.fullmatch(k) or not isinstance(v, KeyRecord) for k, v in keys.items()):
                raise ValueError("valid key records required")
            keys = StaticKeyProvider(keys)
        if not callable(getattr(keys, "get", None)) or not callable(getattr(keys, "reserve", None)):
            raise ValueError("key provider required")
        self.service, self._provider = service, keys
        self.clock = clock or (lambda: int(time.time()))

    def derive(self, kid: str, direction: str) -> bytes:
        if direction not in ("req", "res"):
            raise SapiError()
        return self._derive(kid, direction, self._provider.get(self.service, kid))

    def _derive(self, kid, direction, record):
        prk = hmac.new(b"SAPI/0.1 HKDF-SHA-256", record.master, hashlib.sha256).digest()
        info = f"SAPI/0.1|{self.service}|{kid}|{direction}".encode("ascii")
        return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    def principal(self, kid: str) -> Principal:
        record = self._provider.get(self.service, kid)
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
        record = self._provider.reserve(self.service, kid, direction)
        return self._seal_reserved(kid, direction, body, record)

    def prepare_response(self, kid):
        record = self._provider.reserve(self.service, kid, "res")
        lock, used = threading.Lock(), False
        def finish(payload):
            nonlocal used
            with lock:
                if used: raise SapiError("reservation_used")
                used = True
            self._validate(payload, "res")
            body = encode(payload)
            if len(body) > MAX_BODY: raise SapiError()
            return self._seal_reserved(kid, "res", body, record)
        return finish

    def _seal_reserved(self, kid, direction, body, record):
        header = {"alg": "dir", "enc": "A256GCM", "typ": "sapi+jwe", "kid": kid,
                  "sapi": "0.1", "dir": direction, "svc": self.service, "crit": ["sapi", "dir", "svc"]}
        protected = b64(encode(header))
        iv = secrets.token_bytes(12)
        encrypted = AESGCM(self._derive(kid, direction, record)).encrypt(iv, body, protected.encode("ascii"))
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
