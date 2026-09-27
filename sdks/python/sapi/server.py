from typing import Callable
from .codec import Codec
from .constants import NAME, MAX_BODY
from .errors import SapiError
from .replay import MemoryReplayStore, ReplayStore
from .serialization import encode, digest

class SecureServer:
    def __init__(self, codec: Codec, replay_store: ReplayStore | None = None):
        self.codec = codec
        self.replay = replay_store if replay_store is not None else MemoryReplayStore()
        self.operations = {}

    def register(self, name: str, scope: str, validator: Callable, policy: Callable, handler: Callable):
        if not NAME.fullmatch(name) or not NAME.fullmatch(scope) or name in self.operations or not all(callable(x) for x in (validator, policy, handler)):
            raise ValueError("unique operation, scope, validator, policy and handler required")
        self.operations[name] = (scope, validator, policy, handler)

    def handle(self, wire: str) -> str:
        kid, request = self.codec.open(wire, "req")
        principal = self.codec.principal(kid)
        finish = self.codec.prepare_response(kid)
        now = self.codec.clock()
        response = {"id": request["id"], "iat": now, "exp": now + 60,
                    "req": digest(wire), "ok": False}
        try:
            if not self.replay.claim(f"{self.codec.service}|{kid}|{request['id']}", int(request["exp"]), self.codec.clock()):
                raise SapiError("replay")
            operation = self.operations.get(request["op"])
            if operation is None:
                raise SapiError("unknown_operation")
            scope, validator, policy, handler = operation
            if scope not in principal.scopes:
                raise SapiError("forbidden")
            if validator(request["data"]) is not True:
                raise SapiError("invalid_input")
            if policy(principal, request["data"]) is not True:
                raise SapiError("forbidden")
            result = handler(principal, request["data"])
            if not isinstance(result, dict):
                raise ValueError("handler result must be an object")
            # Check output before setting success; exceptions never leak through plaintext.
            if len(encode(result)) > MAX_BODY - 512:
                raise ValueError("handler result too large")
            response.update(ok=True, data=result)
        except SapiError as exc:
            response["error"] = exc.code if exc.code in {"replay", "replay_capacity", "unknown_operation", "forbidden", "invalid_input"} else "internal_error"
        except Exception:
            response["error"] = "internal_error"
        return finish(response)
