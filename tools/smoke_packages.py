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
    with zipfile.ZipFile(packages / "sapi_protocol-0.1.0a1-py3-none-any.whl") as archive:
        for member in archive.namelist():
            if not (wheel / member).resolve().is_relative_to(wheel): raise RuntimeError("invalid archive path")
        archive.extractall(wheel)
    env["PYTHONPATH"] = os.pathsep.join((str(wheel), str(work / "pydeps")))
    python_code = '''import secrets
from sapi import Codec, KeyRecord, SecureServer
keys={"k1":KeyRecord(secrets.token_bytes(32),"client",frozenset({"echo"}))}
client=Codec("demo",keys); server=SecureServer(Codec("demo",keys))
server.register("echo","echo",lambda d: True,lambda p,d: p.subject=="client",lambda p,d:d)
context=client.request("k1","echo",{"message":"package"})
assert client.accept_response(context,server.handle(context.wire))["data"]=={"message":"package"}
print("python package consumed")
'''
    run([sys.executable, "-c", python_code])
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    node = stage / "node"; node.mkdir()
    (node / "package.json").write_text('{"private":true,"type":"module"}', encoding="utf-8", newline="\n")
    run([npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", str(packages / "sapi-protocol-0.1.0-alpha.1.tgz")], node)
    javascript = '''import {Codec, SecureServer} from 'sapi-protocol';
import {exchange} from 'sapi-protocol/http';
const keys={k1:{master:crypto.getRandomValues(new Uint8Array(32)),subject:'client',scopes:['echo']}};
const client=new Codec('demo',keys), server=new SecureServer(new Codec('demo',keys));
server.register('echo','echo',()=>true,p=>p.subject==='client',(p,d)=>d);
const context=await client.request('k1','echo',{message:'package'});
const response=await client.acceptResponse(context,await server.handle(context.wire));
if(response.data.message!=='package'||typeof exchange!=='function')throw Error('invalid package');
console.log('javascript package consumed');
'''
    run(["node", "--input-type=module", "-e", javascript], node)
    dotnet = stage / "dotnet"; dotnet.mkdir()
    project = dotnet / "Consumer.csproj"
    project.write_text('''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup><ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App"/><PackageReference Include="SApi.AspNetCore" Version="0.1.0-alpha.1"/></ItemGroup></Project>''', encoding="utf-8", newline="\n")
    (dotnet / "Program.cs").write_text('''using System.Security.Cryptography;
using SApi.Protocol;
using SApi.AspNetCore;
var keys=new Dictionary<string,KeyRecord>{["k1"]=new(RandomNumberGenerator.GetBytes(32),"client",new[]{"echo"})};
var client=new Codec("demo",keys); var server=new SecureServer(new Codec("demo",keys));
server.Register("echo","echo",d=>true,(p,d)=>p.Subject=="client",(p,d)=>d);
var context=client.Request("k1","echo",Codec.Json(new{message="package"}));
if(client.AcceptResponse(context,server.Handle(context.Wire)).GetProperty("data").GetProperty("message").GetString()!="package")throw new Exception("invalid package");
Console.WriteLine("dotnet packages consumed: "+typeof(EndpointExtensions).FullName);
''', encoding="utf-8", newline="\n")
    env["NUGET_PACKAGES"] = str(stage / "nuget-cache")
    run(["dotnet", "restore", str(project), "--source", str(packages), "-p:NuGetAudit=false", "--verbosity", "quiet"])
    run(["dotnet", "run", "--project", str(project), "--no-restore", "--configuration", "Release", "--verbosity", "quiet"])
    java = stage / "java"; java.mkdir()
    source = java / "Consumer.java"
    source.write_text('''import io.github.gnh0.sapi.*;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
public class Consumer {
 public static void main(String[] args) {
  byte[] key=new byte[32]; new SecureRandom().nextBytes(key);
  Map<String,KeyRecord> keys=Map.of("k1",new KeyRecord(key,"client",Set.of("echo")));
  Codec client=new Codec("demo",keys); SecureServer server=new SecureServer(new Codec("demo",keys));
  server.register("echo","echo",d->true,(p,d)->p.subject.equals("client"),(p,d)->d);
  RequestContext context=client.request("k1","echo",Sapi.object().put("message","package"));
  if(!client.acceptResponse(context,server.handle(context.wire)).get("data").get("message").textValue().equals("package"))throw new AssertionError();
  System.out.println("java package consumed");
 }
}''', encoding="utf-8", newline="\n")
    cp = os.pathsep.join((str(packages / "sapi-protocol-0.1.0-alpha.1.jar"), *[str(p) for p in (work / "jars").glob("*.jar")]))
    run(["javac", "--release", "11", "-encoding", "UTF-8", "-cp", cp, "-d", str(java), str(source)])
    run(["java", "-cp", str(java) + os.pathsep + cp, "Consumer"])
    (work / "package-smoke.log").write_text("\n".join(logs), encoding="utf-8", newline="\n")
    result = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "passed": ["python wheel import/roundtrip", "npm package exports/roundtrip", "NuGet dependency restore/roundtrip/adapter assembly", "Java JAR consumer compile/roundtrip"],
              "packages_report_sha256": hashlib.sha256((work / "packages.json").read_bytes()).hexdigest()}
    (work / "package-smoke.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
