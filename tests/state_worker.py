"""Isolated process store verification; never exports key bytes."""
import json
import sys
import os
from sapi_state.cli import authority, load
from sapi_state.vault import Identity, StateError

config, _ = load(sys.argv[1])
if "--loopback-postgres-test" in sys.argv:
    from sapi_state import Authority, Database
    from sapi.serialization import unb64
    from pathlib import Path
    value = json.loads(Path(config["secrets"]).read_text())
    vault = Authority(Database(config["database"], allow_local_postgres=True),
                      {k: unb64(v) for k, v in value["keks"].items()}, config["primary"],
                      unb64(value["audit_key"]), anchor_path=config["anchor"])
else:
    vault = authority(config)
actor = Identity("test-service", "service", "demo")
for line in sys.stdin:
    try:
        value = json.loads(line)
        if value["action"] == "crash_after_checkpoint":
            vault.clock = lambda: vault._read_anchor()["clock"]
            original = vault._write_anchor
            def crash(checkpoint):
                original(checkpoint); os._exit(17)
            vault._write_anchor = crash
            vault.key(actor, "demo", value["kid"], "res")
        elif value["action"] == "claim": result = vault.claim(actor, value["name"], value["expiry"])
        elif value["action"] == "admit": result = vault.admit(actor,"demo",value["kid"],value.get("operation","echo"),value.get("requests",60),60)
        elif value["action"] == "reserve":
            vault.key(actor, "demo", value["kid"], "res"); result = {"reserved": True}
        else: raise ValueError()
    except StateError as exc: result = {"error": exc.code}
    except Exception: result = {"error": "state_unavailable"}
    print(json.dumps(result), flush=True)
