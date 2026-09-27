"""Operator-owned deployment configuration; no credentials from API data."""
import argparse
import json
from pathlib import Path
import secrets
from sapi import Codec
from sapi.constants import NAME
from sapi.serialization import parse
from sapi.state import StateClient
from sapi_state.cli import load
from sapi_state.files import private_directory,write_private,write_json
from sapi_state.locking import operator_lease
from sapi_state.pki import enroll
from .application import Application
from .records import Records
from .server import make_server


def initialize(directory,state_config,service,*,host="127.0.0.1",port=8444,service_certificate=None,service_key=None):
    directory=Path(directory).resolve()
    if directory.exists() or not NAME.fullmatch(service) or not 1<=port<=65535:raise ValueError("fresh directory, service and port required")
    # Offline issuance holds the same CA operator lease as key/certificate changes.
    with operator_lease(state_config):
        source,identities=load(state_config)
        pki=Path(source["ca"]).parent
        cert=Path(service_certificate) if service_certificate else pki/"service.pem"
        key=Path(service_key) if service_key else pki/"service.key"
        from cryptography import x509
        from sapi_state.pki import fingerprint
        identity=identities.get(fingerprint(x509.load_pem_x509_certificate(cert.read_bytes())))
        if identity is None or identity.role!="service" or identity.service!=service:raise ValueError("registered service identity required")
        private_directory(directory);private_directory(directory/"pki")
        enroll(pki,"server",host=host,output_directory=directory/"pki")
        for target,path in (("ca.pem",source["ca"]),("service.pem",cert),("service.key",key)):
            write_private(directory/"pki"/target,Path(path).read_bytes())
        authority_host=source["host"]
        if ":" in authority_host:authority_host="["+authority_host+"]"
        state={"url":"https://"+authority_host+":"+str(source["port"]),"ca_file":str(directory/"pki/ca.pem"),"certificate":str(directory/"pki/service.pem"),"private_key":str(directory/"pki/service.key")}
        config={"service":service,"host":host,"port":port,"database":str(directory/"records.sqlite"),"certificate":str(directory/"pki/server.pem"),"private_key":str(directory/"pki/server.key"),"state":state,
                "collections":{"orders":{"schema":{"type":"object","properties":{"description":{"type":"string","maxBytes":256},"quantity":{"type":"integer","min":1,"max":1000}}},"read_scope":"orders_read","write_scope":"orders_write","initial":"created","transitions":{"submit":{"from":"created","to":"submitted","scope":"orders_write"},"complete":{"from":"submitted","to":"completed","scope":"orders_write"}}}},"targets":{},"allowed_origins":[]}
        Records(config["database"])
        write_json(directory/"config.json",config)
        return directory/"config.json"


def open_application(path):
    raw=Path(path).read_bytes()
    if len(raw)>65536:raise ValueError("bounded config required")
    config=parse(raw)
    required={"service","host","port","database","certificate","private_key","state","collections","targets","allowed_origins"}
    if set(config)!=required:raise ValueError("complete application config required")
    state=StateClient(**config["state"])
    app=Application(Codec(config["service"],state),state,Records(config["database"]),config["collections"],config["targets"])
    return app,config


def main(argv=None):
    parser=argparse.ArgumentParser(prog="sapi-application")
    sub=parser.add_subparsers(dest="command",required=True)
    init=sub.add_parser("init");init.add_argument("--directory",required=True);init.add_argument("--state-config",required=True);init.add_argument("--service",required=True)
    init.add_argument("--host",default="127.0.0.1");init.add_argument("--port",type=int,default=8444);init.add_argument("--service-certificate");init.add_argument("--service-key")
    for command in ("serve","inventory"):
        child=sub.add_parser(command);child.add_argument("--config",required=True)
        if command=="serve":child.add_argument("--http",action="store_true",help="explicit plaintext transport; SAPi messages remain authenticated/encrypted")
    args=parser.parse_args(argv)
    if args.command=="init":
        path=initialize(args.directory,args.state_config,args.service,host=args.host,port=args.port,service_certificate=args.service_certificate,service_key=args.service_key)
        print(json.dumps({"config":str(path)}));return
    with operator_lease(args.config):
        app,config=open_application(args.config)
        if args.command=="inventory":print(json.dumps({"operations":app.inventory()}));return
        server=make_server(app,host=config["host"],port=config["port"],certificate=None if args.http else config["certificate"],private_key=None if args.http else config["private_key"],allowed_origins=config["allowed_origins"])
        try:server.serve_forever()
        except KeyboardInterrupt:pass
        finally:server.server_close()


if __name__=="__main__":main()
