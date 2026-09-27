"""Build reference SDKs and run interoperability/security/HTTP(S) checks in scratch."""
import argparse
import datetime
import hashlib
import http.server
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import queue
import random
import shutil
import subprocess
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Driver:
    def __init__(self, name, command, env):
        self.name = name
        self.process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
        self.lines = queue.Queue()
        self.errors = []
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._stderr, daemon=True).start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _stderr(self):
        for line in self.process.stderr:
            self.errors.append(line.rstrip())

    def call(self, **command):
        with self.lock:
            self.process.stdin.write(json.dumps(command, ensure_ascii=True) + "\n")
            self.process.stdin.flush()
            try:
                line = self.lines.get(timeout=40)
            except queue.Empty:
                raise RuntimeError(f"{self.name}: harness timed out")
            if line is None:
                raise RuntimeError(f"{self.name}: process exited: {self.errors[-5:]}")
            return json.loads(line)

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)


def run(command, **kwargs):
    completed = subprocess.run(command, cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True, **kwargs)
    if completed.returncode:
        raise RuntimeError(f"command failed: {command}\n{completed.stdout}\n{completed.stderr}")
    return completed.stdout + completed.stderr


def certificates(folder):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    folder.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAPI Local Test CA")])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ca_file = folder / "ca.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for kind in ("valid", "wrong_host"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        hosts = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))] if kind == "valid" else [x509.DNSName("wrong.example")]
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(hosts), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_key, hashes.SHA256()))
        (folder / f"{kind}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (folder / f"{kind}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_file


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--implementations", type=Path, default=ROOT / "tests" / "implementations.json",
                        help="trusted local build/launch registry; any language can implement the driver contract")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(work / "pydeps"))
    sys.path.insert(0, str(ROOT / "sdks" / "python"))
    from sapi.serialization import b64, unb64
    import cryptography
    import generate_vectors as reference
    fixture = json.loads((ROOT / "tests" / "vectors.json").read_text("utf-8"))
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join((str(work / "pydeps"), str(ROOT / "sdks" / "python")))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    env["DOTNET_NOLOGO"] = "1"
    from implementations import build_registry
    commands = build_registry(ROOT, work, args.implementations.resolve(), run, env)
    ca_file = certificates(work / "certificates")
    env["NODE_EXTRA_CA_CERTS"] = str(ca_file)
    clients, servers, live = {}, {}, []
    test_cases = []
    def add(name, fn):
        test_cases.append(unittest.FunctionTestCase(fn, description=name))
    def reset(driver, **options):
        result = driver.call(action="init", keys=fixture["keys"], now=fixture["now"], **options)
        assert result == {"ready": True}, result
    def require_wire(output):
        assert "wire" in output, output
        return output["wire"]
    try:
        for name, command in commands.items():
            clients[name] = Driver(name + " client", command, env)
            servers[name] = Driver(name + " server", command, env)
        for name, client in clients.items():
            def hkdf(client=client):
                reset(client)
                for kid, directions in fixture["derived"].items():
                    for direction, key in directions.items():
                        assert client.call(action="derive", kid=kid, dir=direction) == {"key": key}
            add(name + ": HKDF matches independent standard implementation", hkdf)
            for vector in fixture["vectors"]:
                def vector_test(client=client, vector=vector):
                    reset(client)
                    assert client.call(action="open", wire=vector["wire"], dir=vector["dir"]) == {"kid": "alice-k1", "payload": vector["payload"]}
                add(name + ": fixed " + vector["dir"] + " vector", vector_test)
        for c_name, client in clients.items():
            for s_name, server in servers.items():
                def matrix(client=client, server=server):
                    reset(client); reset(server)
                    wire = require_wire(client.call(action="request", kid="alice-k1", op="echo", data={"message": "안녕 🌐"}))
                    assert "안녕" not in wire and "message" not in wire
                    response = require_wire(server.call(action="handle", wire=wire))
                    payload = client.call(action="accept", wire=response)["payload"]
                    assert payload["ok"] is True and payload["data"] == {"message": "안녕 🌐"}, payload
                    assert client.call(action="accept", wire=response) == {"error": "response_replay"}
                    replay = require_wire(server.call(action="handle", wire=wire))
                    assert client.call(action="open", wire=replay, dir="res")["payload"]["error"] == "replay"
                    assert server.call(action="stats") == {"executions": 1}
                add(f"interop: {c_name} -> {s_name} request/response", matrix)

        for name, client in clients.items():
            def parser_properties(client=client):
                reset(client); rng = random.Random(20260927)
                master = unb64(fixture["keys"]["alice-k1"]["key"])
                alphabet = ["", "plain", "한글 🌐", "\u0000\n\t", "\"\\/", "__proto__", "constructor"]
                def value(depth=0):
                    choices = [None, True, False, rng.randrange(-1000000, 1000000), rng.uniform(-100, 100), 1e-307, rng.choice(alphabet)]
                    if depth < 5:
                        choices.extend([[value(depth + 1) for _ in range(rng.randrange(4))],
                                        {rng.choice(alphabet) + str(n): value(depth + 1) for n in range(rng.randrange(4))}])
                    return rng.choice(choices)
                for _ in range(100):
                    payload = {"id": "%032x" % rng.getrandbits(128), "iat": fixture["now"], "exp": fixture["now"] + 60,
                               "op": "echo", "data": {"value": value()}}
                    body = json.dumps(payload, ensure_ascii=bool(rng.randrange(2)), separators=(",", ":") if rng.randrange(2) else None).encode("utf-8")
                    wire = reference.seal(master, payload, body_raw=body)
                    assert client.call(action="open", wire=wire, dir="req")["payload"] == payload
                    parts = wire.split("."); position = rng.choice((2, 3, 4)); raw = bytearray(unb64(parts[position]))
                    raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8); parts[position] = b64(bytes(raw))
                    assert client.call(action="open", wire=".".join(parts), dir="req") == {"error": "invalid_message"}
            add(name + ": seeded structured JSON differential fuzzing and authentication mutations", parser_properties)

        original = fixture["vectors"][0]["wire"]
        payload = fixture["vectors"][0]["payload"]
        master = unb64(fixture["keys"]["alice-k1"]["key"])
        parts = original.split(".")
        tag = bytearray(unb64(parts[4])); tag[0] ^= 1
        changed = parts.copy(); changed[4] = b64(bytes(tag))
        attacks = {"modified authentication tag": ".".join(changed), "wrong direction": fixture["vectors"][1]["wire"],
                   "too large wire": "x" * 131073, "base64 padding": original + "=", "not encrypted JSON": json.dumps(payload)}
        tag_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        changed = parts.copy(); changed[4] = parts[4][:-1] + tag_chars[tag_chars.index(parts[4][-1]) ^ 1]
        attacks["noncanonical base64 bits"] = ".".join(changed)
        for index, label in ((2, "modified IV"), (3, "modified ciphertext")):
            changed = parts.copy(); raw = bytearray(unb64(parts[index])); raw[0] ^= 1; changed[index] = b64(bytes(raw))
            attacks[label] = ".".join(changed)
        changed = parts.copy(); changed[0] = b64(unb64(parts[0]) + b" ")
        attacks["changed protected bytes with identical header semantics"] = ".".join(changed)
        changed = parts.copy(); changed[2] = b64(bytes(11))
        attacks["wrong IV length"] = ".".join(changed)
        attacks["wrong master key with known kid"] = reference.seal(bytes(range(32, 64)), payload)
        attacks["oversized decrypted body"] = reference.seal(master, payload, body_raw=b" " * 65537)
        nested = {}; cursor = nested
        for _ in range(33): cursor["nested"] = {}; cursor = cursor["nested"]
        attacks["excessive JSON depth"] = reference.seal(master, dict(payload, data=nested))
        for label, updates in {"expired": {"iat": 1699999945, "exp": 1700000005}, "future issue": {"iat": 1700000011, "exp": 1700000071},
                               "too long lifetime": {"exp": 1700000061}, "boolean timestamp": {"iat": True}, "fractional timestamp": {"iat": 1700000000.5},
                               "missing operation": {"op": None}, "data array": {"data": []}, "unknown payload field": {"extra": True},
                               "unsafe integer": {"iat": 9007199254740992}, "zero lifetime": {"exp": 1700000000}}.items():
            attacks[label] = reference.seal(master, dict(payload, **updates))
        header = json.loads(unb64(parts[0]))
        for label, updates in {"algorithm downgrade": {"alg": "none"}, "unknown encryption": {"enc": "A128GCM"}, "wrong version": {"sapi": "0.2"},
                               "unknown critical field": {"crit": ["sapi", "dir", "svc", "other"]}, "unknown header": {"zip": "DEF"}, "missing critical field": {"crit": []}}.items():
            attacks[label] = reference.seal(master, payload, header_raw=json.dumps(dict(header, **updates)).encode())
        attacks["other service"] = reference.seal(master, payload, service="other")
        attacks["unknown key"] = reference.seal(master, payload, kid="unknown-k1")
        attacks["duplicate header member"] = reference.seal(master, payload, header_raw=unb64(parts[0]).replace(b'{', b'{"alg":"dir",', 1))
        attacks["duplicate operation member"] = reference.seal(master, payload, body_raw=json.dumps(payload).replace('"op": "echo"', '"op":"own","op":"echo"').encode())
        attacks["duplicate nested member"] = reference.seal(master, payload, body_raw=json.dumps(payload).replace('"message":', '"message":"wrong","message":').encode())
        attacks["invalid UTF8"] = reference.seal(master, payload, body_raw=b'\xff')
        attacks["UTF8 BOM body"] = reference.seal(master, payload, body_raw=b'\xef\xbb\xbf' + json.dumps(payload).encode())
        attacks["UTF8 BOM header"] = reference.seal(master, payload, header_raw=b'\xef\xbb\xbf' + unb64(parts[0]))
        attacks["nonfinite JSON number"] = reference.seal(master, payload, body_raw=json.dumps(payload).replace('1700000000', 'NaN').encode())
        attacks["trailing JSON document"] = reference.seal(master, payload, body_raw=json.dumps(payload).encode() + b' {}')
        attacks["unpaired escaped surrogate"] = reference.seal(master, payload, body_raw=json.dumps(payload).replace('"message":', '"message":"\\ud800","removed":').encode())
        for name, server in servers.items():
            def baseline(server=server):
                reset(server)
                response = require_wire(server.call(action="handle", wire=original))
                assert server.call(action="open", wire=response, dir="res")["payload"]["ok"] is True
                assert server.call(action="stats") == {"executions": 1}
            add(name + ": valid attack-fixture baseline reaches handler", baseline)
            for label, wire in attacks.items():
                def reject(server=server, wire=wire):
                    reset(server)
                    assert server.call(action="handle", wire=wire) == {"error": "invalid_message"}
                    assert server.call(action="stats") == {"executions": 0}
                add(name + ": rejects " + label + " before handler", reject)
            for operation, kid, data, code in [("own", "alice-k1", {"owner": "bob"}, "forbidden"), ("own", "bob-k1", {"owner": "bob"}, "forbidden"),
                                              ("echo", "alice-k1", {"message": "hi", "admin": True}, "invalid_input"), ("unknown", "alice-k1", {}, "unknown_operation"),
                                              ("fail", "alice-k1", {}, "internal_error")]:
                def policy_test(server=server, operation=operation, kid=kid, data=data, code=code):
                    reset(server)
                    wire = require_wire(server.call(action="request", kid=kid, op=operation, data=data))
                    response = require_wire(server.call(action="handle", wire=wire))
                    opened = server.call(action="accept", wire=response)["payload"]
                    assert opened["ok"] is False and opened["error"] == code and "data" not in opened
                    assert server.call(action="stats") == {"executions": 0}
                add(name + ": encrypted error " + code + " for " + operation + " " + kid, policy_test)
            def concurrency(server=server):
                reset(server)
                wire = require_wire(server.call(action="request", kid="alice-k1", op="echo", data={"message": "once"}))
                wires = server.call(action="parallel", wire=wire)["wires"]
                results = [server.call(action="open", wire=w, dir="res")["payload"] for w in wires]
                assert sum(p["ok"] for p in results) == 1
                assert all(p["ok"] or p["error"] == "replay" for p in results)
                assert server.call(action="stats") == {"executions": 1}
            add(name + ": concurrent replay executes once", concurrency)
            def capacity(server=server):
                reset(server, capacity=1)
                wires = [require_wire(server.call(action="request", kid="alice-k1", op="echo", data={"message": "hi"})) for _ in range(2)]
                assert server.call(action="open", wire=require_wire(server.call(action="handle", wire=wires[0])), dir="res")["payload"]["ok"] is True
                error = server.call(action="open", wire=require_wire(server.call(action="handle", wire=wires[1])), dir="res")["payload"]
                assert error["error"] == "replay_capacity" and server.call(action="stats")["executions"] == 1
            add(name + ": replay capacity fails closed", capacity)
            def unavailable(server=server):
                reset(server, store="fail")
                wire = require_wire(server.call(action="request", kid="alice-k1", op="echo", data={"message": "hi"}))
                result = server.call(action="accept", wire=require_wire(server.call(action="handle", wire=wire)))["payload"]
                assert result["error"] == "internal_error" and server.call(action="stats")["executions"] == 0
            add(name + ": replay storage failure fails closed", unavailable)
            def registration(server=server):
                reset(server)
                assert server.call(action="bad_registration") == {"rejected": True}
            add(name + ": missing policy cannot register", registration)
            def ownership_allowed(server=server):
                reset(server)
                wire = require_wire(server.call(action="request", kid="alice-k1", op="own", data={"owner": "alice"}))
                response = require_wire(server.call(action="handle", wire=wire))
                assert server.call(action="accept", wire=response)["payload"]["data"] == {"owner": "alice"}
                assert server.call(action="stats") == {"executions": 1}
            add(name + ": correct ownership and scope reaches handler", ownership_allowed)
            def response_binding(server=server):
                reset(server)
                first = require_wire(server.call(action="request", kid="alice-k1", op="echo", data={"message": "first"}, slot="first"))
                second = require_wire(server.call(action="request", kid="alice-k1", op="echo", data={"message": "second"}, slot="second"))
                response = require_wire(server.call(action="handle", wire=second))
                assert server.call(action="accept", wire=response, slot="first") == {"error": "invalid_message"}
                assert server.call(action="accept", wire=response, slot="second")["payload"]["data"] == {"message": "second"}
                assert server.call(action="accept", wire=require_wire(server.call(action="handle", wire=first)), slot="first")["payload"]["data"] == {"message": "first"}
            add(name + ": response swap rejected without consuming valid context", response_binding)
            def nonces(server=server):
                reset(server)
                wires = [require_wire(server.call(action="seal", kid="alice-k1", dir="req", payload=payload)) for _ in range(100)]
                assert len({w.split('.')[2] for w in wires}) == 100
            add(name + ": new IV for every message sample", nonces)
            for field in ("req", "kid"):
                def response_metadata(server=server, field=field):
                    reset(server)
                    wire = require_wire(server.call(action="request", kid="alice-k1", op="echo", data={"message": "bound"}))
                    request = server.call(action="open", wire=wire, dir="req")["payload"]
                    response = {"id": request["id"], "iat": fixture["now"], "exp": fixture["now"] + 60,
                                "req": reference.b64(hashlib.sha256(wire.encode("ascii")).digest()), "ok": True, "data": {"message": "bound"}}
                    key, kid = master, "alice-k1"
                    if field == "req": response["req"] = b64(bytes(32))
                    else: key, kid = unb64(fixture["keys"]["bob-k1"]["key"]), "bob-k1"
                    altered = reference.seal(key, response, direction="res", kid=kid)
                    assert server.call(action="accept", wire=altered) == {"error": "invalid_message"}
                    legitimate = require_wire(server.call(action="handle", wire=wire))
                    assert server.call(action="accept", wire=legitimate)["payload"]["ok"] is True
                add(name + ": independently checks response " + field, response_metadata)

        spec = importlib.util.spec_from_file_location("sapi_demo_transport", ROOT / "examples" / "http_server.py")
        adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
        gateway = {"backend": None}
        def dispatch(wire):
            return require_wire(gateway["backend"].call(action="handle", wire=wire))
        for scheme, kind in (("http", None), ("https", "valid"), ("wrong_host", "wrong_host")):
            options = {} if kind is None else {"certificate": str(work / "certificates" / f"{kind}.pem"), "private_key": str(work / "certificates" / f"{kind}.key")}
            transport = adapter.make_server(dispatch, **options)
            thread = threading.Thread(target=transport.serve_forever, daemon=True); thread.start(); live.append(transport)
            url = f"{'http' if kind is None else 'https'}://127.0.0.1:{transport.server_port}/sapi"
            for c_name, client in clients.items():
                targets = servers.items() if scheme != "wrong_host" else [next(iter(servers.items()))]
                for s_name, server in targets:
                    def http_test(client=client, server=server, url=url, scheme=scheme):
                        reset(client); reset(server); gateway["backend"] = server
                        wire = require_wire(client.call(action="request", kid="alice-k1", op="echo", data={"message": "HTTP/HTTPS secret"}))
                        result = client.call(action="http", url=url, wire=wire, ca=str(ca_file))
                        if scheme == "wrong_host":
                            assert result == {"error": "transport_error"}, result
                            assert server.call(action="stats") == {"executions": 0}
                        else:
                            response = client.call(action="accept", wire=require_wire(result))["payload"]
                            assert response["ok"] is True and response["data"] == {"message": "HTTP/HTTPS secret"}
                            assert server.call(action="stats") == {"executions": 1}
                    add(f"{scheme}: {c_name} -> {s_name} native HTTP client and encrypted handler", http_test)
        registry = json.loads(args.implementations.read_text("utf-8"))
        for s_name, entry in registry.items():
            if "http_server" not in entry.get("features", []): continue
            server = servers[s_name]
            for c_name, client in clients.items():
                def framework_transport(client=client, server=server):
                    reset(client); reset(server)
                    url = server.call(action="http_server_start")["url"]
                    try:
                        wire = require_wire(client.call(action="request", kid="alice-k1", op="echo", data={"message": "framework adapter"}))
                        response = require_wire(client.call(action="http", url=url, wire=wire))
                        assert client.call(action="accept", wire=response)["payload"]["data"] == {"message": "framework adapter"}
                        assert server.call(action="stats") == {"executions": 1}
                        # Framework adapter must not forward unauthenticated plaintext to the handler.
                        assert client.call(action="http", url=url, wire='{"op":"echo","data":{}}') == {"error": "transport_error"}
                        assert server.call(action="stats") == {"executions": 1}
                    finally:
                        assert server.call(action="http_server_stop") == {"stopped": True}
                add(f"framework HTTP server: {c_name} -> {s_name} real endpoint", framework_transport)
        class Result(unittest.TextTestResult):
            def __init__(self, *args, **kwargs): super().__init__(*args, **kwargs); self.passed = []
            def addSuccess(self, test): super().addSuccess(test); self.passed.append(test.shortDescription())
        result = unittest.TextTestRunner(verbosity=1, resultclass=Result).run(unittest.TestSuite(test_cases))
        hashes = {}
        for path in (ROOT / "sdks").rglob("*"):
            if path.is_file() and path.suffix in (".py", ".js", ".java", ".cs", ".csproj", ".props", ".toml", ".xml", ".json"):
                hashes[str(path.relative_to(ROOT)).replace("\\", "/")] = hashlib.sha256(path.read_bytes()).hexdigest()
        def version(program, flag):
            return run([program, flag]).strip() if shutil.which(program) else None
        report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "passed": len(result.passed), "total": result.testsRun,
                  "failures": [test.shortDescription() for test, _ in result.failures + result.errors], "cases": result.passed,
                  "implementations": list(commands),
                  "environment": {"python": sys.version.split()[0], "cryptography": cryptography.__version__, "node": version("node", "--version"),
                                  "dotnet_sdk": version("dotnet", "--version"), "java": version("java", "-version")}, "source_sha256": hashes}
        (work / "verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(json.dumps({k: report[k] for k in ("passed", "total", "failures")}, ensure_ascii=False))
        return 0 if result.wasSuccessful() else 1
    finally:
        for transport in live:
            transport.shutdown(); transport.server_close()
        for driver in [*clients.values(), *servers.values()]:
            driver.close()


if __name__ == "__main__":
    sys.exit(main())
