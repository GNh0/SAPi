"""Operator commands. Private initialization is exclusive; recovery creates new state."""
import argparse
import json
from pathlib import Path
import secrets
from contextlib import nullcontext
from sapi.constants import NAME
from sapi.serialization import b64, unb64
from sapi.state import StateClient
from .files import private_directory, write_json
from .pki import create_ca, enroll
from .storage import Database
from .vault import Authority, Identity
from .server import make_server
from .locking import operator_lease


def load(path):
    path = Path(path).resolve(); config = json.loads(path.read_text("utf-8"))
    identities = {}
    for fingerprint, value in config["identities"].items():
        if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint) or value["role"] not in ("admin", "service", "client"):
            raise ValueError("invalid certificate ACL")
        if value["role"] != "admin" and not NAME.fullmatch(value.get("service", "")): raise ValueError("service required")
        if value["role"] == "client" and not NAME.fullmatch(value.get("subject", "")): raise ValueError("subject required")
        identities[fingerprint] = Identity(fingerprint, **value)
    return config, identities


def authority(config):
    secrets_file = json.loads(Path(config["secrets"]).read_text("utf-8"))
    database = Database(config["database"])
    return Authority(database, {k: unb64(v) for k, v in secrets_file["keks"].items()}, config["primary"], unb64(secrets_file["audit_key"]), anchor_path=config["anchor"], capacity=config.get("replay_capacity", 100000))


def admin_client(config):
    return StateClient(config["url"], ca_file=config["ca"], certificate=config["admin_certificate"], private_key=config["admin_key"])


def initialize(directory, anchor_directory, host, port, service, subject, database=None):
    directory, anchor_directory = Path(directory).resolve(), Path(anchor_directory).resolve()
    if directory == anchor_directory or directory in anchor_directory.parents: raise ValueError("anchor directory must be outside the database backup directory")
    if directory.exists(): raise FileExistsError("use a new private initialization directory")
    if not NAME.fullmatch(service) or not NAME.fullmatch(subject): raise ValueError("valid service and subject required")
    private_directory(directory); private_directory(anchor_directory)
    pki = directory / "pki"; create_ca(pki)
    enroll(pki, "server", host=host)
    acl = {}
    for name, role in (("admin", "admin"), ("service", "service"), ("client", "client")):
        fingerprint = enroll(pki, name)
        acl[fingerprint] = {"role": role}
        if role != "admin": acl[fingerprint]["service"] = service
        if role == "client": acl[fingerprint]["subject"] = subject
    write_json(directory / "secrets.json", {"keks": {"root-1": b64(secrets.token_bytes(32))}, "audit_key": b64(secrets.token_bytes(32))})
    config = {"database": database or str(directory / "state.sqlite"), "anchor": str(anchor_directory / "checkpoint.json"), "secrets": str(directory / "secrets.json"), "primary": "root-1",
              "host": host, "port": port, "url": "https://" + ("[" + host + "]" if ":" in host else host) + ":" + str(port),
              "ca": str(pki / "ca.pem"), "certificate": str(pki / "server.pem"), "private_key": str(pki / "server.key"),
              "admin_certificate": str(pki / "admin.pem"), "admin_key": str(pki / "admin.key"), "identities": acl}
    write_json(directory / "config.json", config)
    authority(config)
    return directory / "config.json"


def _main(argv=None):
    parser = argparse.ArgumentParser(prog="sapi-state")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--directory", required=True); init.add_argument("--anchor-directory", required=True)
    init.add_argument("--host", default="127.0.0.1"); init.add_argument("--port", type=int, default=8443)
    init.add_argument("--service", required=True); init.add_argument("--subject", required=True); init.add_argument("--database")
    for command in ("serve", "issue", "rotate", "revoke", "audit", "root-add", "rewrap", "root-retire", "enroll", "identity-revoke", "server-renew", "recover"):
        child = sub.add_parser(command); child.add_argument("--config", required=True)
        if command in ("issue", "rotate", "revoke"): child.add_argument("--service", required=True)
        if command in ("rotate", "revoke"): child.add_argument("--kid", required=True)
        if command == "issue":
            child.add_argument("--subject", required=True); child.add_argument("--scope", action="append", required=True)
            child.add_argument("--ttl", type=int, default=86400); child.add_argument("--message-limit", type=int, default=1048576)
        if command in ("root-add", "rewrap", "root-retire"): child.add_argument("--root-id", required=True)
        if command == "audit": child.add_argument("--output", required=True)
        if command == "enroll":
            child.add_argument("--name", required=True); child.add_argument("--role", choices=("admin", "service", "client"), required=True)
            child.add_argument("--service"); child.add_argument("--subject")
        if command == "identity-revoke": child.add_argument("--fingerprint", required=True)
        if command == "server-renew": child.add_argument("--name", required=True)
        if command == "recover":
            child.add_argument("--directory", required=True); child.add_argument("--anchor-directory", required=True)
    args = parser.parse_args(argv)
    if args.command == "init":
        result = {"config": str(initialize(args.directory, args.anchor_directory, args.host, args.port, args.service, args.subject, args.database))}
    else:
        config, identities = load(args.config)
        if args.command == "serve":
            server = make_server(authority(config), identities, certificate=config["certificate"], private_key=config["private_key"], ca_file=config["ca"], host=config["host"], port=config["port"])
            try: server.serve_forever()
            except KeyboardInterrupt: pass
            finally: server.server_close()
            return
        elif args.command in ("issue", "rotate", "revoke", "rewrap"):
            parameters = {k: getattr(args, k) for k in ("service", "subject", "kid", "ttl", "message_limit", "root_id") if hasattr(args, k)}
            if args.command == "issue": parameters["scopes"] = args.scope
            result = admin_client(config).call(args.command, **parameters)
        elif args.command == "audit":
            client = admin_client(config); events = []; after = 0
            while True:
                page = client.call("audit", after=after); events.extend(page["events"])
                if page["next"] == after: break
                after = page["next"]
            write_json(args.output, {"checkpoint": page["checkpoint"], "events": events}); result = {"output": str(Path(args.output).resolve()), "events": len(events)}
        elif args.command in ("root-add", "root-retire"):
            if not NAME.fullmatch(args.root_id): raise ValueError("valid root id required")
            vault = authority(config); value = json.loads(Path(config["secrets"]).read_text("utf-8"))
            if args.command == "root-add":
                if args.root_id in value["keks"]: raise ValueError("root already exists")
                value["keks"][args.root_id] = b64(secrets.token_bytes(32)); config["primary"] = args.root_id
            else:
                if args.root_id == config["primary"]: raise ValueError("cannot retire the primary root")
                with vault._transaction() as tx:
                    if tx.execute("SELECT COUNT(*) AS n FROM sapi_keys WHERE sealed IS NOT NULL AND root_id=?", (args.root_id,)).fetchone()["n"]: raise ValueError("rewrap all keys before retiring a root")
                del value["keks"][args.root_id]
            write_json(config["secrets"], value, replace=True); write_json(args.config, config, replace=True)
            result = {"root_id": args.root_id, "restart_required": True}
        elif args.command in ("enroll", "identity-revoke"):
            if args.command == "enroll":
                if not NAME.fullmatch(args.name) or (args.role != "admin" and not NAME.fullmatch(args.service or "")) or (args.role == "client" and not NAME.fullmatch(args.subject or "")): raise ValueError("role bindings required")
                fingerprint = enroll(Path(config["ca"]).parent, args.name)
                value = {"role": args.role}
                if args.role != "admin": value["service"] = args.service
                if args.role == "client": value["subject"] = args.subject
                config["identities"][fingerprint] = value
                if args.role == "admin":
                    config["admin_certificate"] = str(Path(config["ca"]).parent / (args.name + ".pem"))
                    config["admin_key"] = str(Path(config["ca"]).parent / (args.name + ".key"))
            else:
                from cryptography import x509
                from .pki import fingerprint as certificate_fingerprint
                current = certificate_fingerprint(x509.load_pem_x509_certificate(Path(config["admin_certificate"]).read_bytes()))
                if args.fingerprint == current: raise ValueError("enroll a replacement administrator before removing the configured identity")
                fingerprint = args.fingerprint; del config["identities"][fingerprint]
                if not any(v["role"] == "admin" for v in config["identities"].values()): raise ValueError("retain an administrator identity")
            write_json(args.config, config, replace=True); result = {"fingerprint": fingerprint, "restart_required": True}
        elif args.command == "server-renew":
            if not NAME.fullmatch(args.name): raise ValueError("valid certificate name required")
            enroll(Path(config["ca"]).parent, args.name, host=config["host"])
            config["certificate"] = str(Path(config["ca"]).parent / (args.name + ".pem"))
            config["private_key"] = str(Path(config["ca"]).parent / (args.name + ".key"))
            write_json(args.config, config, replace=True); result = {"certificate": config["certificate"], "restart_required": True}
        elif args.command == "recover":
            # Never import keys or replay entries from the suspect backup. Keep original
            # files intact. New KEKs, audit key and empty state require explicit reissue.
            directory, anchor_directory = Path(args.directory).resolve(), Path(args.anchor_directory).resolve()
            if directory.exists() or directory == anchor_directory or directory in anchor_directory.parents: raise ValueError("new separate recovery directories required")
            private_directory(directory); private_directory(anchor_directory)
            previous = Path(config["anchor"]).read_text("utf-8")
            config.update(database=str(directory / "state.sqlite"), anchor=str(anchor_directory / "checkpoint.json"), secrets=str(directory / "secrets.json"), primary="recovery-root")
            write_json(config["secrets"], {"keks": {"recovery-root": b64(secrets.token_bytes(32))}, "audit_key": b64(secrets.token_bytes(32))})
            write_json(directory / "recovery.json", {"previous_checkpoint": json.loads(previous), "old_keys": "quarantined; explicit reissue required"})
            write_json(directory / "config.json", config); authority(config)
            result = {"config": str(directory / "config.json"), "reissue_required": True}
    print(json.dumps(result, ensure_ascii=False))


def main(argv=None):
    import sys
    values = list(sys.argv[1:] if argv is None else argv)
    local = values and values[0] in ("serve", "root-add", "root-retire", "enroll", "identity-revoke", "server-renew", "recover")
    config_path = next((v.split("=", 1)[1] for v in values if v.startswith("--config=")), None)
    if "--config" in values and values.index("--config") + 1 < len(values): config_path = values[values.index("--config") + 1]
    with operator_lease(config_path) if local and config_path else nullcontext():
        return _main(values)


if __name__ == "__main__": main()
