from __future__ import annotations
from typing import Callable, Optional
from .codec import Codec
from .constants import NAME, MAX_BODY
from .errors import SapiError
from .replay import MemoryReplayStore, ReplayStore
from .serialization import encode, digest
from .schema import Schema

class SecureServer:
    def __init__(self, codec: Codec, replay_store: Optional[ReplayStore] = None):
        self.codec = codec
        self.replay = replay_store if replay_store is not None else MemoryReplayStore()
        self.operations = {}

    def register(self, name: str, scope: str, input_schema, output_schema, policy: Callable, handler: Callable, *, requests=60, period=60):
        if not NAME.fullmatch(name) or not NAME.fullmatch(scope) or name in self.operations or not all(callable(x) for x in (policy, handler)) or type(requests) is not int or not 1 <= requests <= 10000 or type(period) is not int or not 1 <= period <= 3600:
            raise ValueError("operation, schemas, policy, handler and bounded rate required")
        self.operations[name] = (scope, Schema(input_schema, root_object=True), Schema(output_schema, root_object=True), policy, handler, requests, period)

    def inventory(self):
        return [{"name": name, "scope": op[0], "requests": op[5], "period": op[6]} for name,op in sorted(self.operations.items())]

    def handle(self, wire: str) -> str:
        kid, request = self.codec.open(wire, "req")
        principal = self.codec.principal(kid)
        finish = self.codec.prepare_response(kid)
        now = self.codec.clock()
        response = {"id": request["id"], "iat": now, "exp": now + 60,
                    "req": digest(wire), "ok": False}
        try:
            operation = self.operations.get(request["op"])
            if self.replay.admit(self.codec.service, kid, principal.subject, request["op"] if operation else "unknown", self.codec.clock(), operation[5] if operation else 60, operation[6] if operation else 60) is not True:
                raise SapiError("rate_limited")
            if not self.replay.claim(f"{self.codec.service}|{kid}|{request['id']}", int(request["exp"]), self.codec.clock()):
                raise SapiError("replay")
            if operation is None:
                raise SapiError("unknown_operation")
            scope, input_schema, output_schema, policy, handler, _, _ = operation
            if scope not in principal.scopes:
                raise SapiError("forbidden")
            if input_schema.validate(request["data"]) is not True:
                raise SapiError("invalid_input")
            if policy(principal, request["data"]) is not True:
                raise SapiError("forbidden")
            if input_schema.validate(request["data"]) is not True:
                raise SapiError("invalid_input")
            if self.codec.clock() >= request["exp"]:
                raise SapiError("invalid_input")
            result = handler(principal, request["data"])
            if not isinstance(result, dict) or not output_schema.validate(result):
                raise ValueError("handler result must be an object")
            # Check output before setting success; exceptions never leak through plaintext.
            if len(encode(result)) > MAX_BODY - 512:
                raise ValueError("handler result too large")
            response.update(ok=True, data=result)
        except SapiError as exc:
            response["error"] = exc.code if exc.code in {"replay", "replay_capacity", "rate_limited", "rate_capacity", "unknown_operation", "forbidden", "invalid_input"} else "internal_error"
        except Exception:
            response["error"] = "internal_error"
        return finish(response)
