from __future__ import annotations
from typing import Callable, Optional
from .codec import Codec
from .constants import NAME, MAX_BODY
from .errors import SapiError
from .replay import MemoryReplayStore, ReplayStore
from .serialization import encode, digest
from .schema import Schema

class SecureServer:
    def __init__(self, codec: Codec, replay_store: Optional[ReplayStore] = None, *, split_budget=False):
        self.codec = codec
        self.replay = replay_store if replay_store is not None else MemoryReplayStore()
        if type(split_budget) is not bool or (split_budget and not callable(getattr(self.replay,'claim_bounded',None))): raise ValueError('explicit split-budget store required')
        self.split_budget=split_budget
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
            key=f"{self.codec.service}|{kid}|{request['id']}"
            bounded=self.replay.claim_bounded if self.split_budget else None
            if bounded is None:
                if self.replay.admit(self.codec.service, kid, principal.subject, request["op"] if operation else "unknown", self.codec.clock(), operation[5] if operation else 60, operation[6] if operation else 60) is not True:
                    raise SapiError("rate_limited")
                if not self.replay.claim(key,int(request["exp"]),self.codec.clock()): raise SapiError("replay")
            else:
                decision=bounded(self.codec.service,principal.subject,key,int(request["exp"]),self.codec.clock())
                if decision not in ('accepted','replay','rate_limited'): raise RuntimeError('invalid replay decision')
                if decision!='accepted': raise SapiError(decision)
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
            if bounded is not None and self.replay.admit(self.codec.service,kid,principal.subject,request["op"],self.codec.clock(),operation[5],operation[6]) is not True:
                raise SapiError("rate_limited")
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
            response["error"] = exc.code if exc.code in {"replay", "replay_capacity", "rate_limited", "rate_capacity", "unknown_operation", "forbidden", "invalid_input", "idempotency_conflict", "idempotency_expired", "idempotency_capacity", "idempotency_clock"} else "internal_error"
        except Exception:
            response["error"] = "internal_error"
        return finish(response)
