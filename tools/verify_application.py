"""Real gateway, SQL, TLS and SSRF regressions against disposable local services."""
import argparse
from contextlib import contextmanager
import datetime
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def main():
    from implementations import source_hashes
    snapshot=source_hashes(ROOT)
    parser=argparse.ArgumentParser();parser.add_argument("--work-dir",type=Path,required=True);parser.add_argument("--postgres")
    parser.add_argument("--implementations", type=Path, default=ROOT/"tests/implementations.json")
    args=parser.parse_args();work=args.work_dir.resolve()
    paths=(work/"pydeps",ROOT/"sdks/python",ROOT/"services/state",ROOT/"services/application")
    for folder in paths:sys.path.insert(0,str(folder))
    from sapi import Codec,KeyRecord,Schema,Principal,SapiError
    from sapi.serialization import unb64
    from sapi.egress import Egress
    import sapi.egress as egress_module
    from sapi_state import Authority,Database
    from sapi_state.cli import initialize,load
    from sapi_state.files import private_directory
    from sapi_state.pki import enroll
    from sapi_state.server import make_server as state_server
    from sapi_application import Application,Records,make_server
    from sapi_application.cli import initialize as initialize_app,open_application
    from implementations import build_registry
    from verify import Driver,run
    area=private_directory(work/("application-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")))
    state_path=initialize(area/"operator",area/"anchors","127.0.0.1",8443,"demo","alice")
    config,acl=load(state_path)
    app_path=initialize_app(area/"application",state_path,"demo")
    secrets_value=json.loads(Path(config["secrets"]).read_text(encoding="utf-8"))
    authority=Authority(Database(config["database"]),{k:unb64(v) for k,v in secrets_value["keks"].items()},"root-1",unb64(secrets_value["audit_key"]),anchor_path=config["anchor"])
    admin=next(a for a in acl.values() if a.role=="admin")
    authority.issue(admin,"demo","alice",["orders_read","orders_write","catalog_read"])
    authority.quota(admin,"demo","alice",1000,60)
    control=state_server(authority,acl,certificate=config["certificate"],private_key=config["private_key"],ca_file=config["ca"],port=0)
    control_thread=threading.Thread(target=control.serve_forever,daemon=True);control_thread.start()
    app_config=json.loads(app_path.read_text(encoding="utf-8"));app_config["state"]["url"]="https://127.0.0.1:"+str(control.server_port)
    app_path.write_text(json.dumps(app_config),encoding="utf-8")
    app,app_config=open_application(app_path)
    owner=Principal("bob",frozenset(["orders_write"]))
    app.records.mutate("create","demo","orders",owner,{"id":"foreign","data":{"description":"private","quantity":1}},initial="created",write_phases=["created"])
    env=dict(os.environ,PYTHONPATH=os.pathsep.join(map(str,paths)),PYTHONDONTWRITEBYTECODE="1",DOTNET_CLI_TELEMETRY_OPTOUT="1",NODE_EXTRA_CA_CERTS=config["ca"])
    commands=build_registry(ROOT,work,args.implementations.resolve(),run,env,snapshot)
    clients={n:Driver(n+" application client",c,env) for n,c in commands.items()}
    settings={"url":app_config["state"]["url"],"ca_file":config["ca"],"certificate":str(Path(config["ca"]).parent/"client.pem"),"private_key":str(Path(config["ca"]).parent/"client.key")}
    cases=[];live=[]
    def add(name,function):cases.append(unittest.FunctionTestCase(function,description=name))
    def wire(value):assert "wire" in value,value;return value["wire"]
    @contextmanager
    def serving(server):
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:yield server
        finally:server.shutdown();server.server_close();thread.join(timeout=2)
    def expect_failure(function):
        try:function()
        except (SapiError,ValueError,OSError):return
        raise AssertionError("unsafe outbound call accepted")
    try:
        for tls in (False,True):
            listener=make_server(app,port=0,certificate=app_config["certificate"] if tls else None,private_key=app_config["private_key"] if tls else None,peer_requests=1000)
            thread=threading.Thread(target=listener.serve_forever,daemon=True);thread.start();live.append((listener,thread))
            url=("https" if tls else "http")+"://127.0.0.1:"+str(listener.server_port)+"/sapi"
            for name,client in clients.items():
                def application_flow(client=client,name=name,url=url,tls=tls):
                    assert client.call(action="init",service="demo",keys={},state=settings)=={"ready":True}
                    def call(op,data):
                        request=wire(client.call(action="request",subject="alice",op=op,data=data))
                        response=wire(client.call(action="http",url=url,wire=request,ca=config["ca"]))
                        return client.call(action="accept",wire=response)["payload"]
                    id=("tls_" if tls else "http_")+name
                    injected="admin' OR 1=1; UPDATE sapi_app_records SET owner='admin'; --"
                    result=call("orders_create",{"id":id,"data":{"description":injected,"quantity":1}})
                    assert result["ok"] is True and result["data"]["records"][0]["data"]["description"]==injected,result
                    assert call("orders_get",{"id":"foreign"})["data"]=={"found":False,"records":[]}
                    assert call("orders_update",{"id":"foreign","version":1,"data":{"description":"stolen","quantity":1}})["data"]=={"changed":False,"records":[]}
                    for invalid in ({"id":id,"owner":"bob"},{"id":id,"sql":"SELECT * FROM sapi_app_records"}):
                        assert call("orders_get",invalid)["error"]=="invalid_input"
                    for payload in ({"description":{"$ne":None},"quantity":1},{"description":"hello","quantity":1,"is_admin":True},{"description":"hello","quantity":"1"}):
                        assert call("orders_update",{"id":id,"version":1,"data":payload})["error"]=="invalid_input"
                    assert call("orders_complete",{"id":id,"version":1})["error"]=="forbidden"
                    result=call("orders_submit",{"id":id,"version":1});assert result["data"]["records"][0]["phase"]=="submitted"
                    assert call("orders_update",{"id":id,"version":2,"data":{"description":"late","quantity":1}})["error"]=="forbidden"
                    assert call("orders_complete",{"id":id,"version":2})["data"]["records"][0]["phase"]=="completed"
                    assert call("orders_delete",{"id":id,"version":3})["error"]=="forbidden"
                    for op in ("execute","fetch_url","orders_sql"):
                        assert call(op,{"command":"arbitrary","url":"http://169.254.169.254/"})["error"]=="unknown_operation"
                add(f"{'HTTPS' if tls else 'HTTP'}: {name}, managed gateway SQL/ownership/fields/workflow",application_flow)
        def optimistic_write():
            import concurrent.futures
            p=Principal("alice",frozenset());id="concurrent"
            app.records.mutate("create","demo","orders",p,{"id":id,"data":{"description":"first","quantity":1}},initial="created",write_phases=["created"])
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results=list(pool.map(lambda n:app.records.mutate("update","demo","orders",p,{"id":id,"version":1,"data":{"description":str(n),"quantity":1}},initial="created",write_phases=["created"]),range(16)))
            assert sum(r["changed"] for r in results)==1
            assert app.records.get("demo","orders",p,{"id":id})["records"][0]["version"]==2
        add("application: 16 concurrent distinct writes commit one expected version",optimistic_write)
        def commit_budget():
            big=Application(app.server.codec,app.server.replay,app.records,{"large":{"schema":{"type":"object","properties":{"blob":{"type":"string","maxBytes":65536}}},"read_scope":"orders_read","write_scope":"orders_write"}})
            kid=authority.active(admin,"demo","alice")["kid"];key=authority.key(admin,"demo",kid)
            local=Codec("demo",{kid:KeyRecord(unb64(key["master"]),"alice",frozenset(key["scopes"]))})
            def call(operation,data):
                request=local.request(kid,operation,data);return local.accept_response(request,big.handle(request.wire))
            assert call("large_create",{"id":"too_large","data":{"blob":"x"*65000}})["error"]=="invalid_input"
            p=Principal("alice",frozenset())
            assert app.records.get("demo","large",p,{"id":"too_large"})=={"found":False,"records":[]}
            assert call("large_create",{"id":"version_limit","data":{"blob":"original"}})["ok"]
            with app.records.db.transaction() as tx:tx.execute("UPDATE sapi_app_records SET version=? WHERE collection=? AND owner=? AND id=?",(9007199254740991,"large","alice","version_limit"))
            assert call("large_update",{"id":"version_limit","version":9007199254740991,"data":{"blob":"replacement"}})["error"]=="forbidden"
            stored=app.records.get("demo","large",p,{"id":"version_limit"})["records"][0]
            assert stored["version"]==9007199254740991 and stored["data"]["blob"]=="original"
            try:app.records.mutate("create","demo","large",p,{"id":"schema_failure","data":{"blob":"x"}},initial="created",write_phases=["created"],output_schema=Schema({"type":"object","properties":{}}))
            except SapiError:pass
            else:raise AssertionError("output failure committed")
            assert app.records.get("demo","large",p,{"id":"schema_failure"})["found"] is False
        add("application: rejected output budget/schema rolls back; version overflow cannot commit",commit_budget)
        def transport():
            class Counting:
                count=0
                def handle(self,wire):self.count+=1;return "accepted"
            receiver=Counting()
            with serving(make_server(receiver,port=0,peer_requests=100,allowed_origins=["https://client.example"])) as listener:
                def raw(headers):
                    sock=socket.create_connection(("127.0.0.1",listener.server_port),timeout=2)
                    try:sock.sendall(b"POST /sapi HTTP/1.1\r\nHost: localhost\r\n"+headers+b"\r\nx");return sock.recv(32768)
                    except OSError:return b""
                    finally:sock.close()
                valid=b"Content-Type: application/sapi+jwe\r\nContent-Length: 1\r\n"
                for suffix in (b"Content-Length: 1\r\n",b"Transfer-Encoding:\r\n",b"Content-Encoding:\r\n",b"Origin: https://evil.example\r\n",b"X: "+b"a"*17000+b"\r\n"):
                    assert b"200 OK" not in raw(valid+suffix)
                assert receiver.count==0
                assert b"200 OK" in raw(valid+b"Origin: https://client.example\r\n")
                assert receiver.count==1
            receiver=Counting()
            with serving(make_server(receiver,port=0,peer_requests=2)) as listener:
                for n in range(3):
                    conn=http.client.HTTPConnection("127.0.0.1",listener.server_port,timeout=2)
                    try:
                        conn.request("POST","/sapi",b"x",{"Content-Type":"application/sapi+jwe","X-Forwarded-For":"192.0.2."+str(n)})
                        response=conn.getresponse();assert n<2;response.read()
                    except (OSError,http.client.HTTPException):assert n==2
                    finally:conn.close()
                assert receiver.count==2
        add("transport: framing, empty TE, metadata size, CORS and spoofed forwarded identity",transport)
        def ssrf():
            empty={"type":"object","properties":{}}
            target={"origin":"https://public.example","path":"/","input":empty,"output":empty}
            protected=Egress({"allowed":target},timeout=.2)
            expect_failure(lambda:protected.fetch("http://169.254.169.254/",{}))
            for ip in ("192.0.0.8","192.0.0.11","192.88.99.1","fec0::1","f000::1","3fff::1","::ffff:8.8.8.8","127.0.0.1","0.0.0.0","10.1.2.3","169.254.169.254","100.100.100.200","::1","fd00::1","fe80::1","::ffff:127.0.0.1","224.0.0.1","64:ff9b::a00:1","64:ff9b:1::a00:1","2002:7f00:1::","2001:4860:4860::8888%eth0"):
                address=[(socket.AF_INET,socket.SOCK_STREAM,6,"",(ip,443))]
                with patch.object(egress_module,"_lookup",return_value=address),patch.object(egress_module,"_connect") as connection:
                    expect_failure(lambda:protected.fetch("allowed",{}));assert connection.call_count==0,ip
            with patch.object(egress_module,"_lookup",return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("8.8.8.8",443)),(socket.AF_INET,socket.SOCK_STREAM,6,"",("10.1.2.3",443))]),patch.object(egress_module,"_connect") as connection:
                expect_failure(lambda:protected.fetch("allowed",{}));assert connection.call_count==0
            for origin in ("http://public.example","https://public.example@127.0.0.1","https://public.example:0","file:///etc/passwd"):
                expect_failure(lambda origin=origin:Egress({"x":dict(target,origin=origin)}))
        add("egress: destination selection, private/mapped/metadata IPs and mixed DNS",ssrf)
        enroll(Path(config["ca"]).parent,"upstream",host="public.example")
        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                if self.path.startswith("/redirect"):
                    self.send_response(302);self.send_header("Location","http://169.254.169.254/");self.end_headers();return
                if self.path.startswith("/slow"):
                    self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length","512");self.end_headers()
                    try:
                        for _ in range(512):self.wfile.write(b"x");self.wfile.flush();time.sleep(.01)
                    except OSError:pass
                    return
                if self.path.startswith("/headers"):
                    self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("X-Large","x"*17000);self.end_headers();return
                if self.path.startswith("/framing"):
                    self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length","2");self.send_header("Transfer-Encoding","chunked");self.end_headers();return
                body=b'{"value":"ok"}' if not self.path.startswith("/secret") else b'{"value":"ok","secret":"do-not-send"}'
                if self.path.startswith("/duplicate"):body=b'{"value":"ok","value":"bad"}'
                self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)+(10 if self.path.startswith("/truncated") else 0)));self.end_headers();self.wfile.write(body)
        upstream=http.server.ThreadingHTTPServer(("127.0.0.1",0),Upstream)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(str(Path(config["ca"]).parent/"upstream.pem"),str(Path(config["ca"]).parent/"upstream.key"));upstream.socket=tls.wrap_socket(upstream.socket,server_side=True)
        upstream_thread=threading.Thread(target=upstream.serve_forever,daemon=True);upstream_thread.start();live.append((upstream,upstream_thread))
        def pinned_tls():
            schema={"type":"object","properties":{"value":{"type":"string","maxBytes":8}}};empty={"type":"object","properties":{}}
            target={"origin":"https://public.example:"+str(upstream.server_port),"path":"/good","input":empty,"output":schema}
            addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("8.8.8.8",upstream.server_port))]
            selected=[]
            def connect(address,timeout):
                selected.append(address);assert address==("8.8.8.8",upstream.server_port)
                return socket.create_connection(("127.0.0.1",upstream.server_port),timeout)
            with patch.object(egress_module,"_lookup",side_effect=[addresses,[(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",upstream.server_port))]]) as resolver,patch.object(egress_module,"_connect",side_effect=connect):
                assert Egress({"good":target},ca_file=config["ca"]).fetch("good",{})=={"value":"ok"}
                assert resolver.call_count==1 and len(selected)==1
            for path in ("/redirect","/secret","/headers","/framing","/duplicate","/truncated"):
                with patch.object(egress_module,"_lookup",return_value=addresses),patch.object(egress_module,"_connect",side_effect=connect):
                    expect_failure(lambda path=path:Egress({"x":dict(target,path=path)},ca_file=config["ca"]).fetch("x",{}))
            with patch.object(egress_module,"_lookup",return_value=addresses),patch.object(egress_module,"_connect",side_effect=connect):
                start=time.monotonic();expect_failure(lambda:Egress({"x":dict(target,path="/slow")},ca_file=config["ca"],timeout=.2).fetch("x",{}));assert time.monotonic()-start<1
            with patch.object(egress_module,"_lookup",return_value=addresses),patch.object(egress_module,"_connect",side_effect=connect):
                expect_failure(lambda:Egress({"x":dict(target,origin="https://wrong.example:"+str(upstream.server_port))},ca_file=config["ca"]).fetch("x",{}))
        add("egress: real TLS, numeric DNS pin, rebind, redirect, hostname and output schema",pinned_tls)
        def handshake_deadline():
            class Stalled(socketserver.BaseRequestHandler):
                def handle(self):self.server.release.wait(.8)
            listener=socketserver.ThreadingTCPServer(("127.0.0.1",0),Stalled);listener.daemon_threads=True;listener.release=threading.Event()
            with serving(listener):
                port=listener.server_address[1];empty={"type":"object","properties":{}}
                target={"origin":"https://public.example:"+str(port),"path":"/","input":empty,"output":empty}
                addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("8.8.8.8",port))]
                def delayed_connect(address,timeout):
                    assert address==("8.8.8.8",port);time.sleep(.3);return socket.create_connection(("127.0.0.1",port),timeout)
                try:
                    with patch.object(egress_module,"_lookup",return_value=addresses),patch.object(egress_module,"_connect",side_effect=delayed_connect):
                        start=time.monotonic();expect_failure(lambda:Egress({"x":target},ca_file=config["ca"],timeout=.4).fetch("x",{}));elapsed=time.monotonic()-start
                        assert elapsed<.6,elapsed
                finally:listener.release.set()
        add("egress: delayed TCP and stalled TLS share one absolute deadline",handshake_deadline)
        if args.postgres:
            def postgres():
                records=Records(args.postgres,allow_local_postgres=True)
                with records.db.transaction() as tx:tx.execute("DELETE FROM sapi_app_records")
                p=Principal("alice",frozenset());data={"id":"p1","data":{"description":"' OR 1=1 --","quantity":1}}
                assert records.mutate("create","demo","orders",p,data,initial="created",write_phases=["created"])["changed"]
                assert records.get("demo","orders",Principal("bob",frozenset()),{"id":"p1"})=={"found":False,"records":[]}
                assert records.get("demo","orders",p,{"id":"p1"})["records"][0]["data"]==data["data"]
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    results=list(pool.map(lambda n:records.mutate("update","demo","orders",p,{"id":"p1","version":1,"data":{"description":str(n),"quantity":1}},initial="created",write_phases=["created"]),range(16)))
                assert sum(r["changed"] for r in results)==1
                result=records.mutate("transition","demo","orders",p,{"id":"p1","version":2},initial="created",write_phases=[],transition={"from":"created","to":"submitted"})
                assert result["records"][0]["phase"]=="submitted" and result["records"][0]["version"]==3
                expect_failure(lambda:records.mutate("update","demo","orders",p,{"id":"p1","version":3,"data":{"description":"late","quantity":1}},initial="created",write_phases=["created"]))
            add("PostgreSQL: actual application records and bound ownership",postgres)
        class Result(unittest.TextTestResult):
            def __init__(self,*a,**kw):super().__init__(*a,**kw);self.passed=[]
            def addSuccess(self,test):super().addSuccess(test);self.passed.append(test.shortDescription())
        result=unittest.TextTestRunner(verbosity=1,resultclass=Result).run(unittest.TestSuite(cases))
        hashes={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for folder in (ROOT/"sdks",ROOT/"services") for p in folder.rglob("*") if p.is_file() and p.suffix in (".py",".cs",".java",".js",".toml",".xml",".json",".props",".csproj")}
        hashes=commands.checked_hashes(ROOT)
        report={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"passed":len(result.passed),"total":result.testsRun,"failures":[t.shortDescription() for t,_ in result.failures+result.errors],"cases":result.passed,"implementations":list(commands),"backends":["sqlite"]+(["postgresql"] if args.postgres else []),"source_sha256":hashes}
        (work/"application-verification.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
        print(json.dumps({k:report[k] for k in ("passed","total","failures")}));return 0 if result.wasSuccessful() else 1
    finally:
        for client in clients.values():client.close()
        for listener,thread in live:listener.shutdown();listener.server_close();thread.join(timeout=2)
        control.shutdown();control.server_close();control_thread.join(timeout=2)


if __name__=="__main__":sys.exit(main())
