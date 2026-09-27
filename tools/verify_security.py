"""Execute application attack regressions with authenticated clients and real SQL."""
import argparse
import concurrent.futures
from contextlib import contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--work-dir",type=Path,required=True)
    args=parser.parse_args();work=args.work_dir.resolve()
    for folder in (work/"pydeps",ROOT/"sdks/python",ROOT/"services/state"):sys.path.insert(0,str(folder))
    from implementations import build_registry
    from verify import Driver,run
    from sapi_state import Authority,Database,Identity,StateError
    from sapi_state.cli import initialize,load
    from sapi_state.files import private_directory
    from sapi_state.server import make_server
    from sapi.serialization import unb64
    fixture=json.loads((ROOT/"tests/vectors.json").read_text(encoding="utf-8"))
    env=dict(os.environ,PYTHONPATH=os.pathsep.join((str(work/"pydeps"),str(ROOT/"sdks/python"),str(ROOT/"services/state"))),PYTHONDONTWRITEBYTECODE="1",DOTNET_CLI_TELEMETRY_OPTOUT="1")
    commands=build_registry(ROOT,work,ROOT/"tests/implementations.json",run,env)
    clients={n:Driver(n+" security client",c,env) for n,c in commands.items()}
    servers={n:Driver(n+" security server",c,env) for n,c in commands.items()}
    cases=[]
    def add(name,function):cases.append(unittest.FunctionTestCase(function,description=name))
    def reset(driver,**settings):assert driver.call(action="init",keys=fixture["keys"],now=fixture["now"],service="demo",**settings)=={"ready":True}
    def wire(result):assert "wire" in result,result;return result["wire"]
    def call(client,server,operation,data,kid="alice-k1"):
        request=wire(client.call(action="request",kid=kid,op=operation,data=data))
        response=wire(server.call(action="handle",wire=request))
        return client.call(action="accept",wire=response)["payload"]
    area=private_directory(work/("security-"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")))
    try:
        for name,driver in clients.items():
            def schema_cases(driver=driver):
                schema={"type":"object","properties":{"name":{"type":"string","maxBytes":12},"age":{"type":"integer","min":0,"max":120},"flags":{"type":"array","items":{"type":"boolean"},"maxItems":3},"nested":{"type":"object","properties":{"tag":{"type":"string","enum":["user","guest"]}}}},"optional":["flags"]}
                good={"name":"한글","age":30,"nested":{"tag":"user"}}
                vectors=[(good,True),({**good,"name":"😀😀😀"},True),({**good,"name":"😀😀😀😀"},False),({**good,"age":"30"},False),({**good,"age":True},False),({**good,"age":1.5},False),({**good,"age":121},False),({**good,"role":"admin"},False),({**good,"nested":{"tag":"user","is_admin":True}},False),({**good,"nested":{"tag":{"$ne":None}}},False),({**good,"name":{"$regex":".*"}},False),({**good,"flags":[True,False,True,False]},False),({**good,"flags":["true"]},False),({**good,"name":"hello\x00"},False),({k:v for k,v in good.items() if k!="age"},False)]
                for value,valid in vectors:assert driver.call(action="schema",schema=schema,value=value)=={"compiled":True,"valid":valid},(value,name)
                malformed=[{"type":"object","properties":{},"additionalProperties":True},{"type":"string","pattern":"(a+)+$"},{"type":"string","format":"unknown"},{"type":"number","min":3,"max":2},{"type":"array","items":{"type":"string"},"maxItems":65},{"type":"string","enum":[]},{"type":"string","enum":["x","x"]},{"type":"object","properties":{"constructor":{"type":"string"}}},{"type":"object","properties":{"$where":{"type":"string"}}},{"type":"object","properties":{"a.b":{"type":"string"}}},{"type":"object","properties":{},"optional":["missing"]},{"type":"object","properties":{},"$ref":"https://untrusted.invalid/schema"}]
                malformed += [{"type":"integer","min":None},{"type":"number","max":None},{"type":"object","properties":{},"optional":None},{"type":"string","maxBytes":None},{"type":"array","items":{"type":"string"},"minItems":None},{"type":"string","format":None},{"type":"object","properties":{"field\n":{"type":"string"}}}]
                for definition in malformed:assert driver.call(action="schema",schema=definition,value={})=={"compiled":False},definition
                for form,good_value,bad_value in [("identifier","record-1","../file"),("uuid","123e4567-e89b-12d3-a456-426614174000","123E4567-e89b-12d3-a456-426614174000")]:
                    definition={"type":"string","format":form};assert driver.call(action="schema",schema=definition,value=good_value)["valid"] is True;assert driver.call(action="schema",schema=definition,value=bad_value)["valid"] is False
            for form,value in [("identifier","record-1\n"),("uuid","123e4567-e89b-12d3-a456-426614174000\n")]:
                    assert driver.call(action="schema",schema={"type":"string","format":form},value=value)=={"compiled":True,"valid":False}
            add(name+": closed schema, NoSQL operators, coercion and bounded UTF-8",schema_cases)
            def sql_cases(driver=driver):
                declarations=[("id","owner",["id"],["Owner"],False),("id","owner",["id"],["ID"],False),("id","ID",["id"],["name"],False),("id","owner",["id","ID"],["name"],False),("id","owner",["id"],["Name","name"],False),("id","owner",["id"],["name\n"],False),("Id","Owner",["Id"],["Display_Name"],True)]
                for id_column,owner_column,read,write,valid in declarations:
                    assert driver.call(action="sql_config",id_column=id_column,owner_column=owner_column,read=read,write=write)=={"compiled":valid},(id_column,owner_column,read,write)
                reset(driver);db=sqlite3.connect(":memory:")
                db.execute("CREATE TABLE accounts(id TEXT NOT NULL,owner TEXT NOT NULL,display_name TEXT,role TEXT NOT NULL DEFAULT 'user',notes TEXT,PRIMARY KEY(owner,id))")
                db.executemany("INSERT INTO accounts VALUES(?,?,?,?,?)",[("a1","alice","Alice","user",None),("b1","bob","Bob","user",None),("root","admin","Administrator","admin",None)])
                def plan(kind,id,**extra):return driver.call(action="sql",kid="alice-k1",kind=kind,id=id,**extra)
                def execute(value):assert "text" in value,value;return db.execute(value["text"],value["values"])
                try:
                    for injection in ["a1' OR 1=1 --","' UNION SELECT id,owner,display_name,role FROM accounts --","'; UPDATE accounts SET role='admin'; --","admin 1=1"]:
                        result=plan("select",injection,owner="admin");assert injection not in result["text"];assert execute(result).fetchall()==[],result
                    assert execute(plan("select","b1",owner="bob")).fetchall()==[]
                    attack="'; UPDATE accounts SET role='admin'; --";assert execute(plan("update","a1",changes={"display_name":attack})).rowcount==1
                    assert db.execute("SELECT display_name,role FROM accounts WHERE owner='alice'").fetchone()==(attack,"user")
                    for field in ("owner","id","role","is_admin","display_name = 'x'; DROP TABLE accounts; --"):
                        assert plan("update","a1",changes={field:"admin"})=={"blocked":True},field
                    assert plan("update","a1",changes={"display_name":{"$ne":None}})=={"blocked":True}
                    assert execute(plan("update","b1",changes={"display_name":"stolen"})).rowcount==0
                    assert execute(plan("delete","b1")).rowcount==0
                    assert db.execute("SELECT role FROM accounts WHERE owner='bob'").fetchone()==("user",)
                    assert execute(plan("insert","a2",changes={"display_name":"O'Reilly"})).rowcount==1
                    assert execute(plan("select","a2")).fetchone()==("a2","alice","O'Reilly","user")
                    for dialect,marker in (("dollar","$1"),("named","@p0"),("format","%s")):
                        bound=plan("select","a1",dialect=dialect);assert marker in bound["text"] and bound["values"]==["alice","a1"]
                finally:db.close()
            add(name+": SQL injection, stored text, object ownership and column escalation on SQLite",sql_cases)
        for c_name,client in clients.items():
            for s_name,server in servers.items():
                def processing(client=client,server=server):
                    for data in ({"message":"hello","role":"admin"},{"message":{"$ne":None}},{"message":"hello","__proto__":{"admin":True}},{"message":["hello"]}):
                        reset(client);reset(server);response=call(client,server,"echo",data);assert response["error"]=="invalid_input",response;assert server.call(action="stats")["executions"]==0
                    reset(client);reset(server);assert call(client,server,"admin",{})["error"]=="forbidden";assert server.call(action="stats")["executions"]==0
                    response=call(client,server,"leak",{});assert response["error"]=="internal_error" and "private-value" not in json.dumps(response)
                    reset(client);reset(server)
                    for n in range(3):
                        result=call(client,server,"limited",{"message":"limited"})
                        assert result.get("ok") is (n<2) and (n<2 or result["error"]=="rate_limited"),result
                    assert server.call(action="stats")["executions"]==2
                add(f"processing: {c_name} -> {s_name}, mass assignment, function scope, output and quota",processing)

        config_path=initialize(area/"operator",area/"anchors","127.0.0.1",8443,"demo","alice")
        config,acl=load(config_path);raw=json.loads(Path(config["secrets"]).read_text(encoding="utf-8"));roots={k:unb64(v) for k,v in raw["keks"].items()};audit=unb64(raw["audit_key"])
        admin=next(a for a in acl.values() if a.role=="admin");actor=next(a for a in acl.values() if a.role=="service")
        sequence=0
        def authority(clock=None):
            nonlocal sequence
            sequence+=1
            database=Database(str(area/("quota-"+str(sequence)+".sqlite")));anchor=area/"anchors"/(str(sequence)+".json")
            return Authority(database,roots,"root-1",audit,anchor_path=anchor,clock=clock),database,anchor
        def persistent_quota():
            current=[1700000000];a,db,anchor=authority(lambda:current[0]);kid=a.issue(admin,"demo","alice",["echo"])["kid"]
            a.quota(admin,"demo","alice",3,60)
            b=Authority(db,roots,"root-1",audit,anchor_path=anchor,clock=lambda:current[0])
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results=list(pool.map(lambda n:(a if n%2 else b).admit(actor,"demo",kid,"echo",3,60)["admitted"],range(16)))
            assert sum(results)==3,results
            kid=a.rotate(admin,"demo",kid)["kid"];assert b.admit(actor,"demo",kid,"echo",3,60)=={"admitted":False}
            restarted=Authority(db,roots,"root-1",audit,anchor_path=anchor,clock=lambda:current[0]);assert restarted.admit(actor,"demo",kid,"other",60,60)=={"admitted":False}
            current[0]+=60;assert restarted.admit(actor,"demo",kid,"echo",3,60)=={"admitted":True}
            try:a.quota(Identity("bad","client","demo","alice"),"demo","alice",10000,1)
            except StateError as e:assert e.code=="forbidden"
            else:raise AssertionError("client changed its quota")
        add("quota: two authorities, 16 concurrent distinct attempts, restart and key rotation",persistent_quota)
        def changed_period():
            current=[1700000000];a,db,anchor=authority(lambda:current[0]);kid=a.issue(admin,"demo","alice",["echo"])["kid"]
            a.quota(admin,"demo","alice",1,60);assert a.admit(actor,"demo",kid,"echo")["admitted"]
            current[0]+=30;a.quota(admin,"demo","alice",1,3600)
            current[0]+=30;assert a.admit(actor,"demo",kid,"echo")=={"admitted":False}
            a.quota(admin,"demo","alice",1,1)
            assert a.admit(actor,"demo",kid,"echo")=={"admitted":False}
            current[0]=1700003600;assert a.admit(actor,"demo",kid,"echo")["admitted"]
        add("quota: live period extension survives old expiry and shortening cannot reset usage",changed_period)
        def quota_tamper():
            for table in ("sapi_rates","sapi_quotas"):
                a,db,anchor=authority();kid=a.issue(admin,"demo","alice",["echo"])["kid"];a.quota(admin,"demo","alice",2,60);a.admit(actor,"demo",kid,"echo",2,60)
                with db.transaction() as tx:tx.execute("DELETE FROM "+table)
                try:Authority(db,roots,"root-1",audit,anchor_path=anchor)
                except StateError as e:assert e.code=="state_tampered"
                else:raise AssertionError("deleted security state accepted")
        add("quota: rate/administrator policy deletion detected on restart",quota_tamper)
        for name,server in servers.items():
            def managed(server=server):
                a,db,anchor=authority();kid=a.issue(admin,"demo","alice",["echo"])["kid"]
                listener=make_server(a,acl,certificate=config["certificate"],private_key=config["private_key"],ca_file=config["ca"],port=0)
                thread=threading.Thread(target=listener.serve_forever,daemon=True);thread.start()
                options=dict(url="https://127.0.0.1:"+str(listener.server_port),ca_file=config["ca"],certificate=str(Path(config["ca"]).parent/"service.pem"),private_key=str(Path(config["ca"]).parent/"service.key"))
                local=clients["python"];record=a.key(admin,"demo",kid)
                try:
                    for n in range(3):
                        assert local.call(action="init",service="demo",keys={kid:{"key":record["master"],"subject":"alice","scopes":["echo"]}})=={"ready":True}
                        assert server.call(action="init",service="demo",keys={},state=options)=={"ready":True}
                        response=call(local,server,"limited",{"message":"persistent"},kid=kid)
                        assert response["ok"] is (n<2) and (n<2 or response["error"]=="rate_limited"),response
                finally:listener.shutdown();listener.server_close();thread.join(timeout=2)
            add(name+": mTLS admission cannot be reset by SDK restart",managed)
        class Result(unittest.TextTestResult):
            def __init__(self,*a,**kw):super().__init__(*a,**kw);self.passed=[]
            def addSuccess(self,test):super().addSuccess(test);self.passed.append(test.shortDescription())
        result=unittest.TextTestRunner(verbosity=1,resultclass=Result).run(unittest.TestSuite(cases))
        hashes={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for folder in (ROOT/"sdks",ROOT/"services") for p in folder.rglob("*") if p.is_file() and p.suffix in (".py",".cs",".java",".js",".toml",".xml",".json",".props",".csproj")}
        report={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"passed":len(result.passed),"total":result.testsRun,"failures":[t.shortDescription() for t,_ in result.failures+result.errors],"cases":result.passed,"implementations":list(commands),"backends":["sqlite"],"source_sha256":hashes}
        (work/"security-verification.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8",newline="\n")
        print(json.dumps({k:report[k] for k in ("passed","total","failures")}));return 0 if result.wasSuccessful() else 1
    finally:
        for driver in [*clients.values(),*servers.values()]:driver.close()


if __name__=="__main__":sys.exit(main())
