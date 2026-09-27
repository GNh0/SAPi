import threading
from typing import Protocol
from .errors import SapiError

class ReplayStore(Protocol):
    """Claim must reserve atomically until expiry; storage failures must raise."""
    def claim(self, key: str, expiry: int, now: int) -> bool: ...


class MemoryReplayStore:
    """Single-process prototype only. Replace with atomic durable storage in production."""
    def __init__(self, capacity=10000):
        if capacity < 1:
            raise ValueError("positive capacity required")
        self.capacity, self.entries, self.lock = capacity, {}, threading.Lock()

    def claim(self, key: str, expiry: int, now: int) -> bool:
        with self.lock:
            self.entries = {k: exp for k, exp in self.entries.items() if exp > now}
            if key in self.entries:
                return False
            if len(self.entries) >= self.capacity:
                raise SapiError("replay_capacity")
            self.entries[key] = expiry
            return True
