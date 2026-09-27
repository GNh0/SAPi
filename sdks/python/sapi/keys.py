from __future__ import annotations
"""Replaceable key storage and atomic encryption-budget reservation."""
import threading
from typing import Protocol
from .errors import SapiError
from .models import KeyRecord


class KeyProvider(Protocol):
    def get(self, service: str, kid: str) -> KeyRecord: ...
    def reserve(self, service: str, kid: str, direction: str) -> KeyRecord: ...


class StaticKeyProvider:
    """Explicit local/test provisioned keys; managed deployments use a state provider."""
    def __init__(self, keys: dict[str, KeyRecord]):
        self._keys, self._counts, self._lock = dict(keys), {}, threading.Lock()

    def get(self, service, kid):
        if kid not in self._keys:
            raise SapiError()
        return self._keys[kid]

    def reserve(self, service, kid, direction):
        record = self.get(service, kid)
        with self._lock:
            name = (service, kid, direction)
            count = self._counts.get(name, 0)
            if count >= 1048576:
                raise SapiError("key_rotation_required")
            self._counts[name] = count + 1
        return record
