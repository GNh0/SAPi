"""Durability, lifecycle, mTLS roles and managed SDK integration checks."""
import argparse
import concurrent.futures
from contextlib import contextmanager
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import subprocess
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--postgres", help="explicit loopback test DSN")
    args = parser.parse_args(); work = args.work_dir.resolve()
    for path in (work / "pydeps", ROOT / "sdks/python", ROOT / "services/state"): sys.path.insert(0, str(path))
    from sapi import Codec, KeyRecord, SapiError
    from sapi.state import StateClient
    from sapi.serialization import unb64
    from sapi_state import Authority, Database, Identity, StateError
    from sapi_state.cli import initialize, load, main as cli_main
    from sapi_state.files import private_directory, write_json
    from sapi_state.pki import enroll
    from sapi_state.server import make_server
    from implementations import build_registry
    from verify import Driver, run

    area = private_directory(work / ("state-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")))
    config_path = initialize(area / "operator", area / "anchors", "127.0.0.1", 8443, "demo", "alice")
    config, acl = load(config_path)
    secrets_value = json.loads(Path(config["secrets"]).read_text())
    keks = {k: unb64(v) for k, v in secrets_value["keks"].items()}; audit_key = unb64(secrets_value["audit_key"])
    actors = {v.role: v for v in acl.values()}; admin, service, client_actor = actors["admin"], actors["service"], actors["client"]
    env = dict(os.environ); env["PYTHONPATH"] = os.pathsep.join((str(work / "pydeps"), str(ROOT / "sdks/python"), str(ROOT / "services/state")))
    env["PYTHONDONTWRITEBYTECODE"] = "1"; env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    commands = build_registry(ROOT, work, ROOT / "tests/implementations.json", run, env)
    clients = {name: Driver(name + " managed client", command, env) for name, command in commands.items()}
    servers = {name: Driver(name + " managed server", command, env) for name, command in commands.items()}
    cases = []; serial = 0
    def add(name, function): cases.append(unittest.FunctionTestCase(function, description=name))
    def expect(code, function):
        try: function()
        except (StateError, SapiError) as exc: assert exc.code == code, (code, exc.code); return
        raise AssertionError("expected " + code)
    def fresh(*, clock=None, capacity=100000, extra_roots=None):
        nonlocal serial
        serial += 1; folder = private_directory(area / ("case-" + str(serial)))
        database = Database(str(folder / "state.sqlite"))
        roots = dict(keks, **(extra_roots or {}))
        vault = Authority(database, roots, "root-1", audit_key, anchor_path=area / "anchors" / (str(serial) + ".json"), capacity=capacity, clock=clock)
        return vault, folder
    @contextmanager
    def remote(vault, identities=None):
        gateway = make_server(vault, identities or acl, certificate=config["certificate"], private_key=config["private_key"], ca_file=config["ca"], port=0)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True); thread.start()
        options = {"url": f"https://127.0.0.1:{gateway.server_port}", "ca_file": config["ca"]}
        def settings(role):
            return dict(options, certificate=str(Path(config["ca"]).parent / (role + ".pem")), private_key=str(Path(config["ca"]).parent / (role + ".key")))
        try: yield settings
        finally: gateway.shutdown(); gateway.server_close(); thread.join(timeout=2)
    def reset(driver, options, **extra):
        result = driver.call(action="init", keys={}, state=options, **extra)
        assert result == {"ready": True}, result
    def wire(result): assert "wire" in result, result; return result["wire"]

    try:
        for c_name, client in clients.items():
            for s_name, server in servers.items():
                def integration(client=client, server=server):
                    vault, _ = fresh(); vault.issue(admin, "demo", "alice", ["echo", "orders"])
                    with remote(vault) as settings:
                        reset(client, settings("client")); reset(server, settings("service"))
                        request = wire(client.call(action="request", subject="alice", op="echo", data={"message": "managed 🌐"}))
                        response = wire(server.call(action="handle", wire=request))
                        assert client.call(action="accept", wire=response)["payload"]["data"] == {"message": "managed 🌐"}
                        reset(server, settings("service"))
                        repeated = wire(server.call(action="handle", wire=request))
                        assert client.call(action="open", dir="res", wire=repeated)["payload"]["error"] == "replay"
                        assert server.call(action="stats") == {"executions": 0}
                add(f"managed mTLS: {c_name} -> {s_name}, durable replay after SDK restart", integration)
        for name, server in servers.items():
            def budget(server=server):
                vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"], message_limit=1)["kid"]
                local = Codec("demo", {kid: KeyRecord(unb64(vault.key(client_actor, "demo", kid)["master"]), "alice", frozenset(["echo"]))})
                with remote(vault) as settings:
                    reset(server, settings("service"))
                    request = local.request(kid, "echo", {"message": "once"}); local.accept_response(request, wire(server.call(action="handle", wire=request.wire)))
                    reset(server, settings("service")); request = local.request(kid, "echo", {"message": "capacity"})
                    assert server.call(action="handle", wire=request.wire) == {"error": "key_rotation_required"}
                    assert server.call(action="stats") == {"executions": 0}
                    with vault.db.transaction() as tx: assert tx.execute("SELECT COUNT(*) AS n FROM sapi_replay").fetchone()["n"] == 1
                expect("key_rotation_required", lambda: vault.key(service, "demo", kid, "res"))
            add(name + ": response budget reserved before handler or replay claim", budget)
            def revocation(server=server):
                vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
                local = Codec("demo", {kid: KeyRecord(unb64(vault.key(client_actor, "demo", kid)["master"]), "alice", frozenset(["echo"]))})
                request = local.request(kid, "echo", {"message": "revoked"})
                with remote(vault) as settings:
                    reset(server, settings("service")); vault.revoke(admin, "demo", kid)
                    assert server.call(action="handle", wire=request.wire) == {"error": "invalid_message"}
                    assert server.call(action="stats") == {"executions": 0}
            add(name + ": revoked key unavailable without SDK cache", revocation)
            def unavailable(server=server):
                vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
                local = Codec("demo", {kid: KeyRecord(unb64(vault.key(client_actor, "demo", kid)["master"]), "alice", frozenset(["echo"]))})
                request = local.request(kid, "echo", {"message": "unavailable"})
                with remote(vault) as settings: options = settings("service")
                reset(server, options)
                assert server.call(action="handle", wire=request.wire) == {"error": "invalid_message"}
                assert server.call(action="stats") == {"executions": 0}
            add(name + ": authority failure blocks handler", unavailable)

        def lifecycle():
            current = [1700000000]; vault, _ = fresh(clock=lambda: current[0])
            kid = vault.issue(admin, "demo", "alice", ["echo"], ttl=300, message_limit=5)["kid"]
            before = vault.key(client_actor, "demo", kid)["master"]; vault.key(client_actor, "demo", kid, "req")
            newer = vault.rotate(admin, "demo", kid)["kid"]
            assert newer != kid and vault.key(client_actor, "demo", newer)["master"] != before
            expect("key_retired", lambda: vault.key(client_actor, "demo", kid, "req"))
            assert vault.key(service, "demo", kid, "res")["master"] == before
            current[0] += 120; expect("key_retired", lambda: vault.key(service, "demo", kid))
            current[0] -= 20; expect("clock_rollback", lambda: vault.key(service, "demo", newer))
        add("lifecycle: fresh rotation, retiring grace, old request refusal, clock rollback", lifecycle)
        def automatic():
            current = [1700000000]; vault, _ = fresh(clock=lambda: current[0])
            kid = vault.issue(admin, "demo", "alice", ["echo"], ttl=300, message_limit=5)["kid"]
            for _ in range(4): vault.key(client_actor, "demo", kid, "req")
            next_kid = vault.active(client_actor, "demo", "alice")["kid"]; assert next_kid != kid
            current[0] += 121; assert vault.active(client_actor, "demo", "alice")["kid"] != next_kid
        add("automatic rotation: usage threshold and expiry threshold", automatic)
        def scopes():
            vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
            for actor in (client_actor, service): expect("forbidden", lambda actor=actor: vault.issue(actor, "demo", "bob", ["echo"]))
            expect("forbidden", lambda: vault.key(Identity("other", "client", "demo", "bob"), "demo", kid))
            expect("forbidden", lambda: vault.key(Identity("other", "service", "other"), "demo", kid))
            expect("forbidden", lambda: vault.key(client_actor, "demo", kid, "res"))
            expect("forbidden", lambda: vault.key(service, "demo", kid, "req"))
            expect("forbidden", lambda: vault.claim(client_actor, "demo|" + kid + "|" + "0" * 32, int(time.time()) + 60))
        add("roles: administrator, service, client and subject isolation", scopes)
        def postgres_policy():
            for host in ("/tmp", "@abstract", "localhost,/tmp", "localhost,", ""):
                import urllib.parse
                target = "postgresql://user@localhost/db?host=" + urllib.parse.quote(host, safe="") + "&sslmode=verify-full"
                try: Database(target)
                except ValueError: pass
                else: raise AssertionError("non-TCP database host accepted")
            try: Database("postgresql://user@127.0.0.1/db?sslmode=disable")
            except ValueError: pass
            else: raise AssertionError("plaintext production connection accepted")
        add("PostgreSQL configuration: TCP hosts and verified TLS required", postgres_policy)
        def mtls():
            vault, _ = fresh(); pki = Path(config["ca"]).parent; enroll(pki, "unlisted")
            with remote(vault) as settings:
                unknown = settings("client"); unknown.update(certificate=str(pki / "unlisted.pem"), private_key=str(pki / "unlisted.key"))
                expect("forbidden", lambda: StateClient(**unknown).call("active", service="demo", subject="alice"))
                from sapi.http import post
                try: post(settings("admin")["url"] + "/v1/state", b'{"action":"audit"}', "application/json", ca_file=config["ca"])
                except Exception: pass
                else: raise AssertionError("client certificate required")
                expect("state_unavailable", lambda: StateClient(**dict(settings("admin"), url=settings("admin")["url"].replace("127.0.0.1", "localhost"))).call("audit"))
        add("mTLS: missing certificate, unregistered certificate and hostname mismatch", mtls)
        def operator_commands():
            from sapi_state.cli import authority
            from sapi_state.locking import operator_lease
            path = initialize(area / "operator-test", area / "operator-test-anchors", "127.0.0.1", 8443, "demo", "alice")
            c, identities = load(path); old = next(f for f, value in identities.items() if value.role == "admin")
            cli_main(["enroll", "--config", str(path), "--name", "admin-2", "--role", "admin"])
            cli_main(["identity-revoke", "--config", str(path), "--fingerprint", old])
            cli_main(["server-renew", "--config", str(path), "--name", "server-2"])
            cli_main(["root-add", "--config", str(path), "--root-id", "root-2"])
            c, identities = load(path); a = authority(c)
            actor = next(value for value in identities.values() if value.role == "admin")
            assert c["admin_certificate"].endswith("admin-2.pem") and c["certificate"].endswith("server-2.pem")
            a.issue(actor, "demo", "alice", ["echo"])
            cli_main(["root-retire", "--config", str(path), "--root-id", "root-1"])
            c, identities = load(path); a = authority(c)
            gateway = make_server(a, identities, certificate=c["certificate"], private_key=c["private_key"], ca_file=c["ca"], port=0)
            threading.Thread(target=gateway.serve_forever, daemon=True).start()
            try:
                StateClient(f"https://127.0.0.1:{gateway.server_port}", ca_file=c["ca"], certificate=c["admin_certificate"], private_key=c["admin_key"]).call("audit")
            finally: gateway.shutdown(); gateway.server_close()
            with operator_lease(path):
                try: cli_main(["root-add", "--config", str(path), "--root-id", "locked-root"])
                except OSError: pass
                else: raise AssertionError("operator lease was bypassed")
        add("operator CLI: certificate renewal, administrator replacement, KEK retirement and lease", operator_commands)
        def concurrency():
            vault, folder = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"], message_limit=8)["kid"]
            worker_config = dict(config, database=vault.db.target, anchor=str(vault.anchor_path)); write_json(folder / "config.json", worker_config)
            workers = [Driver("state worker", [sys.executable, str(ROOT / "tests/state_worker.py"), str(folder / "config.json")], env) for _ in range(8)]
            try:
                name = "demo|" + kid + "|" + "0" * 32; expiry = int(time.time()) + 60
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(lambda worker: worker.call(action="claim", name=name, expiry=expiry), workers))
                    assert sum(r.get("claimed") is True for r in results) == 1, results
                    counts = list(pool.map(lambda worker: worker.call(action="reserve", kid=kid), workers))
                    assert all(r == {"reserved": True} for r in counts), counts
                expect("key_rotation_required", lambda: vault.key(service, "demo", kid, "res"))
                restarted = Authority(Database(vault.db.target), keks, "root-1", audit_key, anchor_path=vault.anchor_path)
                assert restarted.claim(service, name, expiry) == {"claimed": False}
            finally:
                for worker in workers: worker.close()
        add("process persistence: eight workers, one replay winner, shared usage budget", concurrency)
        def concurrent_admission():
            vault, _ = fresh();kid=vault.issue(admin,"demo","alice",["echo"])["kid"]
            vault.quota(admin,"demo","alice",3,60)
            folder=area/"admission";folder.mkdir();worker_config=dict(config,database=vault.db.target,anchor=str(vault.anchor_path));write_json(folder/"config.json",worker_config)
            workers=[Driver("quota worker",[sys.executable,str(ROOT/"tests/state_worker.py"),str(folder/"config.json")],env) for _ in range(8)]
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    results=list(pool.map(lambda w:w.call(action="admit",kid=kid),workers))
                assert sum(r.get("admitted") is True for r in results)==3,results
                rotated=vault.rotate(admin,"demo",kid)["kid"]
                assert workers[0].call(action="admit",kid=rotated,operation="other")=={"admitted":False}
            finally:
                for worker in workers:worker.close()
        add("process admission: eight workers, three winners, rotation cannot reset subject quota",concurrent_admission)
        def capacity():
            now = [1700000000]; vault, _ = fresh(clock=lambda: now[0], capacity=1)
            kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]; name = "demo|" + kid + "|"
            assert vault.claim(service, name + "0" * 32, now[0] + 1)["claimed"]
            expect("replay_capacity", lambda: vault.claim(service, name + "1" * 32, now[0] + 60))
            now[0] += 1; assert vault.claim(service, name + "1" * 32, now[0] + 60)["claimed"]
        add("durable capacity: reject when full, cleanup after expiry", capacity)
        def rollback():
            vault, folder = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
            snapshot = folder / "snapshot.sqlite"
            with sqlite3.connect(vault.db.target) as source, sqlite3.connect(snapshot) as destination: source.backup(destination)
            vault.key(client_actor, "demo", kid, "req"); vault.claim(service, "demo|" + kid + "|" + "0" * 32, int(time.time()) + 60); vault.revoke(admin, "demo", kid)
            with sqlite3.connect(snapshot) as source, sqlite3.connect(vault.db.target) as destination: source.backup(destination)
            expect("audit_rollback", lambda: vault.key(client_actor, "demo", kid))
            expect("audit_rollback", lambda: Authority(Database(vault.db.target), keks, "root-1", audit_key, anchor_path=vault.anchor_path))
            write_json(folder / "config.json", dict(config, database=vault.db.target, anchor=str(vault.anchor_path)))
            cli_main(["recover", "--config", str(folder / "config.json"), "--directory", str(folder / "recovered"), "--anchor-directory", str(area / "recovery-anchor")])
            recovered, _ = load(folder / "recovered/config.json")
            from sapi_state.cli import authority
            expect("invalid_key", lambda: authority(recovered).key(client_actor, "demo", kid))
            assert snapshot.exists() and Path(vault.db.target).exists()
        add("backup rollback: startup and live access denied; recovery quarantines old keys", rollback)
        def fault():
            vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]; original = vault._write_anchor
            def fail(_): raise OSError("test write failure")
            vault._write_anchor = fail
            try: vault.claim(service, "demo|" + kid + "|" + "0" * 32, int(time.time()) + 60)
            except OSError: pass
            else: raise AssertionError("anchor write must fail closed")
            vault._write_anchor = original
            assert vault.claim(service, "demo|" + kid + "|" + "0" * 32, int(time.time()) + 60)["claimed"]
            try:
                with vault.db.transaction() as tx:
                    vault._audit(tx, admin, "test_commit_failure", {}); vault._write_anchor(dict(vault._verify_audit(tx), root=vault._read_anchor()["root"], clock=int(time.time()))); raise OSError("simulated commit failure")
            except OSError: pass
            expect("audit_rollback", lambda: vault.key(client_actor, "demo", kid))
        add("fault injection: anchor write rollback and anchor-ahead-of-COMMIT denial", fault)
        def process_crash():
            vault, folder = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
            write_json(folder / "config.json", dict(config, database=vault.db.target, anchor=str(vault.anchor_path)))
            result = subprocess.run([sys.executable, str(ROOT / "tests/state_worker.py"), str(folder / "config.json")],
                                    input=json.dumps({"action": "crash_after_checkpoint", "kid": kid}) + "\n", env=env, text=True, capture_output=True, timeout=10)
            assert result.returncode == 17, (result.returncode, result.stderr[-1000:])
            expect("audit_rollback", lambda: vault.key(service, "demo", kid))
        add("actual process exit after durable checkpoint and before SQL commit fails closed", process_crash)
        def load_test():
            vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
            peer = Authority(Database(vault.db.target), keks, "root-1", audit_key, anchor_path=vault.anchor_path)
            expiry = int(time.time()) + 60
            def claim(n):
                return (vault if n % 2 else peer).claim(service, "demo|" + kid + "|" + format(n, "032x"), expiry)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                assert all(r["claimed"] for r in pool.map(claim, range(64)))
                assert all(not r["claimed"] for r in pool.map(claim, range(64)))
        add("shared authority load: 64 concurrent distinct claims and 64 durable duplicates", load_test)
        def deleted_root():
            vault, _ = fresh()
            with vault.db.transaction() as tx: tx.execute("DELETE FROM sapi_roots WHERE root_id='root-1'")
            expect("state_tampered", lambda: Authority(Database(vault.db.target), keks, "root-1", audit_key, anchor_path=vault.anchor_path))
        add("startup: missing committed KEK counter cannot be initialized as a new root", deleted_root)
        def tamper():
            vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]; vault.key(client_actor, "demo", kid, "req")
            with vault.db.transaction() as tx: tx.execute("UPDATE sapi_keys SET req_count=0 WHERE kid=?", (kid,))
            expect("state_tampered", lambda: vault.key(client_actor, "demo", kid))
            vault, _ = fresh(); vault.issue(admin, "demo", "alice", ["echo"])
            with vault.db.transaction() as tx: tx.execute("UPDATE sapi_audit SET event='{}' WHERE seq=1")
            expect("audit_tampered", lambda: vault.audit(admin))
            vault.anchor_path.write_bytes(b'{}'); expect("anchor_invalid", lambda: vault.audit(admin))
        add("integrity: counter, audit event and checkpoint modification detected", tamper)
        def partial_restore():
            vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
            with vault.db.transaction() as tx: old = dict(tx.execute("SELECT * FROM sapi_keys WHERE kid=?", (kid,)).fetchone())
            vault.key(client_actor, "demo", kid, "req")
            with vault.db.transaction() as tx:
                tx.execute("UPDATE sapi_keys SET req_count=?,tag=? WHERE kid=?", (old["req_count"], old["tag"], kid))
            expect("state_tampered", lambda: vault.key(client_actor, "demo", kid))
            vault, _ = fresh(); kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]
            name = "demo|" + kid + "|" + "0" * 32; expiry = int(time.time()) + 60
            vault.claim(service, name, expiry)
            with vault.db.transaction() as tx: tx.execute("DELETE FROM sapi_replay WHERE name=?", (name,))
            expect("state_tampered", lambda: vault.claim(service, name, expiry))
        add("partial rollback: formerly signed key row and deleted live replay rejected", partial_restore)
        def tree_properties():
            from sapi_state.tree import Tree, TreeError, pointer
            import random
            vault, _ = fresh(); values = {}; rng = random.Random(20260927)
            with vault.db.transaction() as tx:
                tree = Tree(tx, pointer(), audit_key)
                for _ in range(500):
                    name = "property-" + str(rng.randrange(70))
                    value = str(rng.randrange(1000)) if rng.randrange(3) else None
                    tree.set(name, value)
                    if value is None: values.pop(name, None)
                    else: values[name] = value
                    for n in range(70): assert tree.get("property-" + str(n)) == values.get("property-" + str(n))
                committed = dict(tree.root)
                row = tx.execute("SELECT * FROM sapi_tree WHERE name=?", (committed["name"],)).fetchone()
                tx.execute("UPDATE sapi_tree SET digest='modified' WHERE name=?", (row["name"],))
                try: Tree(tx, committed, audit_key)
                except TreeError: pass
                else: raise AssertionError("modified tree root accepted")
                # Always rollback this isolated property transaction.
            # The test never uses the now-uncommitted authority again.
        add("authenticated dictionary: 500 deterministic insert/update/delete transitions", tree_properties)
        def rewrap():
            root = secrets.token_bytes(32); vault, _ = fresh(extra_roots={"root-2": root})
            kid = vault.issue(admin, "demo", "alice", ["echo"])["kid"]; master = vault.key(client_actor, "demo", kid)["master"]
            assert vault.rewrap(admin, "root-2") == {"rewrapped": 1}
            restarted = Authority(Database(vault.db.target), {"root-2": root}, "root-2", audit_key, anchor_path=vault.anchor_path)
            assert restarted.key(client_actor, "demo", kid)["master"] == master
            assert unb64(master) not in Path(vault.db.target).read_bytes()
            exported = json.dumps(restarted.audit(admin)); assert master not in exported and "audit_key" not in exported
            try: Authority(Database(vault.db.target), {"root-2": secrets.token_bytes(32)}, "root-2", audit_key, anchor_path=vault.anchor_path)
            except Exception: pass
            else: raise AssertionError("wrong KEK must fail")
        add("root rotation: rewrap, retire old KEK, encrypted storage and secret-free audit", rewrap)

        class Slow(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"])); self.send_response(200)
                self.send_header("Content-Type", "application/sapi+jwe"); self.send_header("Content-Length", "100"); self.end_headers()
                try:
                    for _ in range(20): self.wfile.write(b"a"); self.wfile.flush(); time.sleep(.1)
                except (OSError, ValueError): pass
        slow = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow); slow.daemon_threads = True
        threading.Thread(target=slow.serve_forever, daemon=True).start()
        for name, client in clients.items():
            def deadline(client=client):
                start = time.monotonic(); result = client.call(action="http", url=f"http://127.0.0.1:{slow.server_port}/sapi", wire="a", timeout_ms=500)
                elapsed = time.monotonic() - start
                assert result == {"error": "transport_error"} and elapsed < 2, (result, elapsed)
            add(name + ": absolute deadline during continuously arriving response body", deadline)

        if args.postgres:
            def postgres():
                database = Database(args.postgres, allow_local_postgres=True)
                with database.transaction() as tx:
                    for table in ("sapi_replay", "sapi_rates", "sapi_quotas", "sapi_keys", "sapi_roots", "sapi_audit", "sapi_meta", "sapi_tree"): tx.execute("DELETE FROM " + table)
                anchor = area / "anchors/postgres.json"
                a = Authority(database, keks, "root-1", audit_key, anchor_path=anchor)
                b = Authority(Database(args.postgres, allow_local_postgres=True), keks, "root-1", audit_key, anchor_path=anchor)
                kid = a.issue(admin, "demo", "alice", ["echo"], message_limit=4)["kid"]
                expiry = int(time.time()) + 60; name = "demo|" + kid + "|" + "0" * 32
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(lambda n: (a if n % 2 else b).claim(service, name, expiry), range(16)))
                    assert sum(r["claimed"] for r in results) == 1
                for _ in range(4): b.key(service, "demo", kid, "res")
                expect("key_rotation_required", lambda: a.key(service, "demo", kid, "res"))
                b.revoke(admin, "demo", kid); expect("key_revoked", lambda: a.key(client_actor, "demo", kid))
                assert a.audit(admin)["checkpoint"] == b.audit(admin)["checkpoint"]
                kid = a.issue(admin, "demo", "alice", ["echo"], message_limit=8)["kid"]
                worker_config = dict(config, database=args.postgres, anchor=str(anchor))
                write_json(area / "postgres-config.json", worker_config)
                workers = [Driver("postgres process", [sys.executable, str(ROOT / "tests/state_worker.py"), str(area / "postgres-config.json"), "--loopback-postgres-test"], env) for _ in range(8)]
                try:
                    name = "demo|" + kid + "|" + "1" * 32
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        result = list(pool.map(lambda worker: worker.call(action="claim", name=name, expiry=int(time.time()) + 60), workers))
                        assert sum(r.get("claimed") is True for r in result) == 1, result
                        result = list(pool.map(lambda worker: worker.call(action="reserve", kid=kid), workers))
                        assert all(r == {"reserved": True} for r in result), result
                    expect("key_rotation_required", lambda: a.key(service, "demo", kid, "res"))
                    a.quota(admin,"demo","alice",3,60)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        admitted=list(pool.map(lambda w:w.call(action="admit",kid=kid),workers))
                    assert sum(r.get("admitted") is True for r in admitted)==3,admitted
                    rotated=a.rotate(admin,"demo",kid)["kid"]
                    assert workers[0].call(action="admit",kid=rotated,operation="other")=={"admitted":False}
                    a.quota(admin,"demo","alice",1000,60)
                finally:
                    for worker in workers: worker.close()
                with remote(a) as first, remote(b) as second:
                    for c_name, client in clients.items():
                        for s_name, server in servers.items():
                            reset(client, first("client")); reset(server, second("service"))
                            request = wire(client.call(action="request", subject="alice", op="echo", data={"message": "postgres shared"}))
                            response = wire(server.call(action="handle", wire=request))
                            assert client.call(action="accept", wire=response)["payload"]["ok"] is True
                # Use the current active key for revocation rather than an automatically
                # retired key selected earlier in the integration matrix.
                kid = a.active(client_actor, "demo", "alice")["kid"]; a.revoke(admin, "demo", kid)
                with remote(a) as settings:
                    for driver in clients.values():
                        reset(driver, settings("client"))
                        assert driver.call(action="request", kid=kid, op="echo", data={"message": "revoked"}) == {"error": "key_revoked"}
            add("PostgreSQL: two authorities, shared anchor, concurrency, budget and revocation", postgres)

        class Result(unittest.TextTestResult):
            def __init__(self, *values, **options): super().__init__(*values, **options); self.passed = []
            def addSuccess(self, test): super().addSuccess(test); self.passed.append(test.shortDescription())
        result = unittest.TextTestRunner(verbosity=1, resultclass=Result).run(unittest.TestSuite(cases))
        slow.shutdown(); slow.server_close()
        hashes = {}
        for folder in (ROOT / "sdks", ROOT / "services"):
            for path in folder.rglob("*"):
                if path.is_file() and path.suffix in (".py", ".js", ".cs", ".java", ".toml", ".csproj", ".props", ".json", ".xml"):
                    hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "passed": len(result.passed), "total": result.testsRun,
                  "failures": [test.shortDescription() for test, _ in result.failures + result.errors], "cases": result.passed,
                  "backends": ["sqlite"] + (["postgresql"] if args.postgres else []), "implementations": list(commands), "source_sha256": hashes}
        (work / "state-verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(json.dumps({k: report[k] for k in ("passed", "total", "failures", "backends")}))
        return 0 if result.wasSuccessful() else 1
    finally:
        for driver in [*clients.values(), *servers.values()]: driver.close()


if __name__ == "__main__": sys.exit(main())
