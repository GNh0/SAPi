"""Consume the local packages in isolated projects, without editing global installations."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--package-dir", type=Path, required=True)
    args = parser.parse_args()
    work, packages = args.work_dir.resolve(), args.package_dir.resolve()
    report = json.loads((work / "packages.json").read_text("utf-8"))
    for name, digest in report["packages_sha256"].items():
        if hashlib.sha256((packages / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("package changed: " + name)
    stage = work / "consumers" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    stage.mkdir(parents=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", DOTNET_CLI_TELEMETRY_OPTOUT="1")
    logs = []
    def run(command, cwd=stage):
        result = subprocess.run(command, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace", capture_output=True)
        logs.append(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"consumer failed: {command}\n{result.stdout}\n{result.stderr}")
        return result.stdout.strip()
    wheel = stage / "wheel"
    wheel.mkdir()
    with zipfile.ZipFile(packages / "sapi_protocol-0.1.0a4-py3-none-any.whl") as archive:
        for member in archive.namelist():
            if not (wheel / member).resolve().is_relative_to(wheel): raise RuntimeError("invalid archive path")
        archive.extractall(wheel)
    env["PYTHONPATH"] = os.pathsep.join((str(wheel), str(work / "pydeps")))
    python_code = '''import secrets
from sapi import Codec, KeyRecord, SecureServer, Schema, OwnedSql
keys={"k1":KeyRecord(secrets.token_bytes(32),"client",frozenset({"echo"}))}
client=Codec("demo",keys); server=SecureServer(Codec("demo",keys))
schema={"type":"object","properties":{"message":{"type":"string","maxBytes":128}}}
assert Schema(schema).validate({"message":"package"})
assert OwnedSql("accounts","id","owner",["id"],["name"]).select(client.principal("k1"),"record").bind()[1]==("client","record")
server.register("echo","echo",schema,schema,lambda p,d: p.subject=="client",lambda p,d:d)
context=client.request("k1","echo",{"message":"package"})
assert client.accept_response(context,server.handle(context.wire))["data"]=={"message":"package"}
print("python package consumed")
'''
    sdk_python = env.get("SAPI_PYTHON", sys.executable)
    sdk_deps = env.get("SAPI_SDK_DEPS", str(work / "pydeps"))
    run([sdk_python, "-c", "import sys;sys.path[:0]=" + repr([str(wheel), sdk_deps]) + ";" + python_code])
    with zipfile.ZipFile(packages / "sapi_state-0.1.0a4-py3-none-any.whl") as archive:
        for member in archive.namelist():
            if not (wheel / member).resolve().is_relative_to(wheel): raise RuntimeError("invalid archive path")
        archive.extractall(wheel)
    run([sys.executable, "-m", "sapi_state.cli", "init", "--directory", str(stage / "operator"), "--anchor-directory", str(stage / "anchors"), "--service", "demo", "--subject", "client"])
    run([sys.executable, "-c", "from sapi_state.cli import load,authority; from sapi_state.vault import Identity; c,_=load(r'" + str(stage / "operator/config.json") + "'); a=authority(c); kid=a.issue(Identity('package','admin'),'demo','client',['echo'])['kid']; assert a.key(Identity('package','client','demo','client'),'demo',kid)['subject']=='client'"])
    with zipfile.ZipFile(packages / "sapi_application-0.1.0a4-py3-none-any.whl") as archive:
        for member in archive.namelist():
            if not (wheel / member).resolve().is_relative_to(wheel):raise RuntimeError("invalid archive path")
        archive.extractall(wheel)
    run([sys.executable,"-m","sapi_application.cli","init","--directory",str(stage/"application"),"--state-config",str(stage/"operator/config.json"),"--service","demo"])
    inventory=json.loads(run([sys.executable,"-m","sapi_application.cli","inventory","--config",str(stage/"application/config.json")]))["operations"]
    if len(inventory)!=6 or not any(row["name"]=="orders_submit" for row in inventory):raise RuntimeError("application wheel inventory failed")
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    node = stage / "node"; node.mkdir()
    (node / "package.json").write_text('{"private":true,"type":"module"}', encoding="utf-8", newline="\n")
    run([npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", str(packages / "sapi-protocol-0.1.0-alpha.4.tgz")], node)
    javascript = '''import {Codec, SecureServer, Schema, OwnedSql} from 'sapi-protocol';
import {exchange} from 'sapi-protocol/http';
import {StateClient} from 'sapi-protocol/state-node';
import {webcrypto} from 'node:crypto';
const keys={k1:{master:webcrypto.getRandomValues(new Uint8Array(32)),subject:'client',scopes:['echo']}};
const client=new Codec('demo',keys), server=new SecureServer(new Codec('demo',keys));
const schema={type:'object',properties:{message:{type:'string',maxBytes:128}}};
if(!new Schema(schema).validate({message:'package'})||new OwnedSql('accounts','id','owner',['id'],['name']).select(await client.principal('k1'),'record').bind().values[0]!=='client')throw Error('missing security API');
server.register('echo','echo',schema,schema,p=>p.subject==='client',(p,d)=>d);
const context=await client.request('k1','echo',{message:'package'});
const response=await client.acceptResponse(context,await server.handle(context.wire));
if(response.data.message!=='package'||typeof exchange!=='function'||typeof StateClient!=='function')throw Error('invalid package');
console.log('javascript package consumed');
'''
    run([env.get("SAPI_NODE","node"), "--input-type=module", "-e", javascript], node)
    dotnet = stage / "dotnet"; dotnet.mkdir()
    project = dotnet / "Consumer.csproj"
    project.write_text('''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup><ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App"/><PackageReference Include="SApi.AspNetCore" Version="0.1.0-alpha.4"/></ItemGroup></Project>''', encoding="utf-8", newline="\n")
    (dotnet / "Program.cs").write_text('''using System.Security.Cryptography;
using SApi.Protocol;
using SApi.AspNetCore;
var keys=new Dictionary<string,KeyRecord>{["k1"]=new(RandomNumberGenerator.GetBytes(32),"client",new[]{"echo"})};
var client=new Codec("demo",keys); var server=new SecureServer(new Codec("demo",keys));
var schema=Codec.Json(new{type="object",properties=new{message=new{type="string",maxBytes=128}}});
if(!new Schema(schema).Validate(Codec.Json(new{message="package"}))||new OwnedSql("accounts","id","owner",new[]{"id"},new[]{"name"}).Select(client.Principal("k1"),Codec.Json("record")).Bind().Values[0]?.ToString()!="client")throw new Exception("missing security API");
server.Register("echo","echo",schema,schema,(p,d)=>p.Subject=="client",(p,d)=>d);
var context=client.Request("k1","echo",Codec.Json(new{message="package"}));
if(client.AcceptResponse(context,server.Handle(context.Wire)).GetProperty("data").GetProperty("message").GetString()!="package")throw new Exception("invalid package");
Console.WriteLine("dotnet packages consumed: "+typeof(EndpointExtensions).FullName);
if(typeof(StateClient).GetMethod("FromPemFiles")==null)throw new Exception("missing state API");
''', encoding="utf-8", newline="\n")
    global_cache = Path(env.get("NUGET_PACKAGES", str(Path.home()/".nuget/packages")))
    env["NUGET_PACKAGES"] = str(stage / "nuget-cache")
    run(["dotnet", "restore", str(project), "--source", str(packages), "-p:NuGetAudit=false", "--verbosity", "quiet"])
    run(["dotnet", "run", "--project", str(project), "--no-restore", "--configuration", "Release", "--verbosity", "quiet"])
    extra_dotnet = []
    for target in (["net462", "net6.0", "standard"] if os.name == "nt" else ["net6.0", "standard"]):
        consumer = stage / target; consumer.mkdir()
        adapter = "SApi.AspNet" if target == "net462" else "SApi.AspNetCore"
        references = '<Reference Include="System.Web"/><Reference Include="System.Net.Http"/><PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies.net462" Version="1.0.3" PrivateAssets="all"/>' if target == "net462" else '<FrameworkReference Include="Microsoft.AspNetCore.App"/>'
        tfm = "net6.0" if target=="standard" else target
        if target=="standard":
            adapter="SApi.Protocol"
            references='<Reference Include="SApi.Protocol"><HintPath>'+str(stage/"nuget-cache/sapi.protocol/0.1.0-alpha.4/lib/netstandard2.0/SApi.Protocol.dll")+'</HintPath></Reference><PackageReference Include="BouncyCastle.Cryptography" Version="2.7.0"/><PackageReference Include="System.Text.Json" Version="8.0.6"/>'
        project_file = consumer/"Consumer.csproj"
        project_file.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>'+tfm+'</TargetFramework><AutoGenerateBindingRedirects>true</AutoGenerateBindingRedirects></PropertyGroup><ItemGroup><PackageReference Include="'+adapter+'" Version="0.1.0-alpha.4"'+(' ExcludeAssets="all"' if target=="standard" else '')+'/>'+references+'</ItemGroup></Project>',encoding="utf-8",newline="\n")
        (consumer/"Program.cs").write_text('''using System;
using System.Collections.Generic;
using SApi.Protocol;
class Consumer {
 static void Main() {
  var bytes=new byte[32];using(var random=System.Security.Cryptography.RandomNumberGenerator.Create()){random.GetBytes(bytes);}
  var keys=new Dictionary<string,KeyRecord>{{"k1",new KeyRecord(bytes,"client",new[]{"echo"})}};
  var client=new Codec("demo",keys);var server=new SecureServer(new Codec("demo",keys));
  var schema=Codec.Json(new{type="object",properties=new{message=new{type="string",maxBytes=128}}});
  server.Register("echo","echo",schema,schema,(p,d)=>p.Subject=="client",(p,d)=>d);
  var context=client.Request("k1","echo",Codec.Json(new{message="package"}));
  if(client.AcceptResponse(context,server.Handle(context.Wire)).GetProperty("data").GetProperty("message").GetString()!="package")throw new Exception("invalid package");
  if(!new Schema(schema).Validate(Codec.Json(new{message="package"})))throw new Exception("schema");
  CHECK_ADAPTER
  Console.WriteLine("compatibility package consumed: "+Environment.Version);
 }
}'''.replace('CHECK_ADAPTER','SApi.AspNet.RouteExtensions.MapSapi(System.Web.Routing.RouteTable.Routes,server);if(System.Web.Routing.RouteTable.Routes.Count!=1)throw new Exception("route");' if target=='net462' else 'if(typeof(SApi.AspNetCore.EndpointExtensions).Name!="EndpointExtensions")throw new Exception("adapter");' if target=='net6.0' else ''),encoding="utf-8",newline="\n")
        run(["dotnet","restore",str(project_file),"--source",str(packages),"--source",str(global_cache),"-p:NuGetAudit=false","--verbosity","quiet"])
        run(["dotnet","build",str(project_file),"--no-restore","--configuration","Release","--verbosity","quiet"])
        binary=consumer/"bin/Release"/tfm/("Consumer.exe" if target=="net462" else "Consumer.dll")
        run([str(binary)] if target=="net462" else ["dotnet",str(binary)])
        extra_dotnet.append("NuGet "+target+" dependency restore/roundtrip/schema" + ("/adapter" if target!="standard" else " (netstandard2.0 assembly on .NET 6)"))
    java = stage / "java"; java.mkdir()
    source = java / "Consumer.java"
    source.write_text('''import io.github.gnh0.sapi.*;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
public class Consumer {
 public static void main(String[] args) {
  byte[] key=new byte[32]; new SecureRandom().nextBytes(key);
  Map<String,KeyRecord> keys=java.util.Collections.singletonMap("k1",new KeyRecord(key,"client",java.util.Collections.singleton("echo")));
  Codec client=new Codec("demo",keys); SecureServer server=new SecureServer(new Codec("demo",keys));
  com.fasterxml.jackson.databind.node.ObjectNode schema=Sapi.object();schema.put("type","object");schema.set("properties",Sapi.object().set("message",Sapi.object().put("type","string").put("maxBytes",128)));
  if(!new Schema(schema).validate(Sapi.object().put("message","package"))||!new OwnedSql("accounts","id","owner",java.util.Arrays.asList("id"),java.util.Arrays.asList("name")).select(client.principal("k1"),Sapi.object().textNode("record")).values().get(0).equals("client"))throw new AssertionError();
  server.register("echo","echo",schema,schema,(p,d)->p.subject.equals("client"),(p,d)->d);
  RequestContext context=client.request("k1","echo",Sapi.object().put("message","package"));
  if(!client.acceptResponse(context,server.handle(context.wire)).get("data").get("message").textValue().equals("package"))throw new AssertionError();
  System.out.println("java package consumed");
  if(StateClient.class.getConstructors().length==0)throw new AssertionError();
 }
}''', encoding="utf-8", newline="\n")
    cp = os.pathsep.join((str(packages / "sapi-protocol-0.1.0-alpha.4.jar"), *[str(p) for p in (work / "jars").glob("*.jar")]))
    run([env.get("SAPI_JAVAC","javac"), *(["-source","8","-target","8"] if env.get("SAPI_JAVAC") else ["--release","8"]), "-encoding", "UTF-8", "-cp", cp, "-d", str(java), str(source)])
    run([env.get("SAPI_JAVA","java"), "-cp", str(java) + os.pathsep + cp, "Consumer"])
    (work / "package-smoke.log").write_text("\n".join(logs), encoding="utf-8", newline="\n")
    result = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "passed": ["python wheel import/roundtrip", "state wheel operator init/issue/key", "application wheel init/inventory", "npm package exports/roundtrip/state export", "NuGet dependency restore/roundtrip/adapter assembly/state API", "Java JAR consumer compile/roundtrip/state API"] + extra_dotnet,
              "packages_report_sha256": hashlib.sha256((work / "packages.json").read_bytes()).hexdigest()}
    (work / "package-smoke.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
