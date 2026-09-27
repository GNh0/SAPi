from __future__ import annotations
import threading
from dataclasses import dataclass, field
from .constants import NAME

@dataclass(frozen=True)
class KeyRecord:
    master: bytes
    subject: str
    scopes: frozenset[str] = frozenset()

    def __post_init__(self):
        if not isinstance(self.master, bytes) or len(self.master) != 32 or not NAME.fullmatch(self.subject):
            raise ValueError("32-byte key and valid subject required")
        object.__setattr__(self, "scopes", frozenset(self.scopes))


@dataclass
class RequestContext:
    wire: str
    kid: str
    request_id: str
    consumed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


@dataclass(frozen=True)
class Principal:
    """Identity exposed to business policies; it never contains key material."""
    subject: str
    scopes: frozenset[str]
