"""JSON-lines test harness; keys arrive via init, never via a bundled production default."""
import concurrent.futures
import json
import sys
from sapi import Codec, KeyRecord, MemoryReplayStore, SapiError, SecureServer
from sapi.serialization import unb64
from sapi.http import exchange
from sapi.state import StateClient

codec = server = None
state = None
contexts = {}
executions = 0


def invoke(command):
    global codec, server, contexts, executions, state
    action = command["action"]
    if action == "init":
        now = command.get("now")
        keys = {kid: KeyRecord(unb64(v["key"]), v["subject"], frozenset(v["scopes"])) for kid, v in command["keys"].items()}
        state = StateClient(**command["state"]) if "state" in command else None
        codec = Codec(command.get("service", "demo"), state or keys, (lambda: now) if now is not None else None)
        if command.get("store") == "fail":
            class BrokenStore:
                def claim(self, *args):
                    raise RuntimeError("storage unavailable")
            store = BrokenStore()
        else:
            store = state or MemoryReplayStore(command.get("capacity", 10000))
        server = SecureServer(codec, store)
        contexts, executions = {}, 0

        def counted(_principal, data):
            global executions
            executions += 1
            return data

        server.register("echo", "echo", lambda d: set(d) == {"message"} and isinstance(d["message"], str) and len(d["message"].encode("utf-8")) <= 4096,
                        lambda p, d: True, counted)
        server.register("own", "orders", lambda d: set(d) == {"owner"} and isinstance(d["owner"], str),
                        lambda p, d: d["owner"] == p.subject, counted)
        server.register("fail", "echo", lambda d: True, lambda p, d: True,
                        lambda p, d: (_ for _ in ()).throw(RuntimeError("private internal details")))
        return {"ready": True}
    if action == "derive":
        return {"key": codec.derive(command["kid"], command["dir"]).hex()}
    if action == "seal":
        return {"wire": codec.seal(command["kid"], command["dir"], command["payload"])}
    if action == "open":
        kid, payload = codec.open(command["wire"], command["dir"])
        return {"kid": kid, "payload": payload}
    if action == "request":
        context = state.request(codec, command["subject"], command["op"], command["data"]) if "subject" in command else codec.request(command["kid"], command["op"], command["data"])
        contexts[command.get("slot", "default")] = context
        return {"wire": context.wire}
    if action == "accept":
        return {"payload": codec.accept_response(contexts[command.get("slot", "default")], command["wire"])}
    if action == "handle":
        return {"wire": server.handle(command["wire"])}
    if action == "http":
        try:
            return {"wire": exchange(command["url"], command["wire"], ca_file=command.get("ca"), timeout=command.get("timeout_ms", 30000) / 1000)}
        except Exception:
            return {"error": "transport_error"}
    if action == "parallel":
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            wires = list(pool.map(server.handle, [command["wire"]] * 16))
        return {"wires": wires}
    if action == "stats":
        return {"executions": executions}
    if action == "bad_registration":
        try:
            server.register("bad", "echo", lambda d: True, None, lambda p, d: d)
        except ValueError:
            return {"rejected": True}
        return {"rejected": False}
    raise ValueError("unknown action")


for line in sys.stdin:
    try:
        output = invoke(json.loads(line))
    except SapiError as exc:
        output = {"error": exc.code}
    except Exception:
        output = {"error": "invalid_message"}
    print(json.dumps(output, ensure_ascii=True), flush=True)
