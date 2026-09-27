import threading
from typing import Protocol
from .errors import SapiError

class ReplayStore(Protocol):
    """Claim must reserve atomically until expiry; storage failures must raise."""
    def claim(self, key: str, expiry: int, now: int) -> bool: ...
    def admit(self, service: str, kid: str, subject: str, operation: str, now: int, requests=60, period=60) -> bool: ...


class MemoryReplayStore:
    """Single-process prototype only. Replace with atomic durable storage in production."""
    def __init__(self, capacity=10000):
        if capacity < 1:
            raise ValueError("positive capacity required")
        self.capacity, self.entries, self.lock = capacity, {}, threading.Lock()
        self.rates = {}

    def admit(self, service, kid, subject, operation, now, requests=60, period=60):
        with self.lock:
            self.rates = {k:v for k,v in self.rates.items() if v[0]+v[2]>now}
            pending = []
            for name, count, seconds in (("global|" + service + "|" + subject, 60, 60), ("op|" + service + "|" + subject + "|" + operation, requests, period)):
                start, used, previous_period = self.rates.get(name, (now, 0, seconds))
                if now >= start + max(seconds, previous_period): start, used, previous_period = now, 0, seconds
                if used >= count: return False
                if name not in self.rates and len(self.rates) + sum(k not in self.rates for k,_ in pending) >= 10000: raise SapiError("rate_capacity")
                pending.append((name, (start, used + 1, max(seconds,previous_period))))
            self.rates.update(pending)
            return True

    def claim(self, key: str, expiry: int, now: int) -> bool:
        with self.lock:
            self.entries = {k: exp for k, exp in self.entries.items() if exp > now}
            if key in self.entries:
                return False
            if len(self.entries) >= self.capacity:
                raise SapiError("replay_capacity")
            self.entries[key] = expiry
            return True
