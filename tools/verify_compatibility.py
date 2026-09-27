"""Run the same contracts with explicitly selected older SDK runtimes."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--work-dir",type=Path,required=True)
    parser.add_argument("--implementations",type=Path,default=ROOT/"tests"/("implementations-legacy-windows.json" if os.name=="nt" else "implementations-legacy.json"))
    parser.add_argument("--reuse-reports",action="store_true",help="reuse completed suites only after checking every SDK/service hash and implementation list")
    args=parser.parse_args();work=args.work_dir.resolve();work.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    from implementations import source_hashes
    logs=[]
    for name in ("verify","verify_state","verify_security","verify_application"):
        if args.reuse_reports:
            report_name={"verify":"verification","verify_state":"state-verification","verify_security":"security-verification","verify_application":"application-verification"}[name]
            report=json.loads((work/(report_name+".json")).read_text("utf-8"))
            if report["failures"] or report["passed"]!=report["total"] or report["implementations"]!=list(json.loads(args.implementations.read_text("utf-8"))):raise RuntimeError("incompatible suite report")
            if report["source_sha256"]!=source_hashes(ROOT):raise RuntimeError("source changed since verification")
            continue
        result=subprocess.run([sys.executable,str(ROOT/"tools"/(name+".py")),"--work-dir",str(work),"--implementations",str(args.implementations.resolve())],cwd=ROOT,env=env,text=True,encoding="utf-8",errors="replace",capture_output=True)
        logs.append(result.stdout+result.stderr);(work/"compatibility.log").write_text("\n".join(logs),encoding="utf-8",newline="\n")
        print(result.stdout.strip(),flush=True)
        if result.returncode:print(result.stderr,file=sys.stderr);return result.returncode
    # Exercise the address policy on the selected Python process, whose stdlib classification differs.
    sdk_python=env.get("SAPI_PYTHON",sys.executable)
    code='''import sys,json,socket
sys.path[:0]=sys.argv[1:]
import sapi.egress as e
from sapi import SapiError, Codec, SecureServer
from typing import get_type_hints
assert get_type_hints(Codec.__init__)["keys"] and get_type_hints(SecureServer.__init__)["replay_store"]
blocked=["192.0.0.8","192.0.0.11","192.88.99.1","fec0::1","f000::1","3fff::1","::ffff:8.8.8.8","2002:808:808::1"]
for address in blocked:
 e._lookup=lambda *args,**kwargs:[(socket.AF_INET,socket.SOCK_STREAM,6,"",(address,443))]
 try:e._resolve("fixture",443,1)
 except SapiError:pass
 else:raise AssertionError(address)
for address in ["8.8.8.8","2606:4700:4700::1111"]:
 e._lookup=lambda *args,**kwargs:[(socket.AF_INET,socket.SOCK_STREAM,6,"",(address,443))]
 assert e._resolve("fixture",443,1)==address
print(json.dumps({"python":sys.version.split()[0],"address_policy_cases":10}))
'''
    result=subprocess.run([sdk_python,"-c",code,str(ROOT/"sdks/python"),env.get("SAPI_SDK_DEPS",str(work/"pydeps"))],cwd=ROOT,env=env,text=True,encoding="utf-8",capture_output=True)
    if result.returncode:print(result.stderr,file=sys.stderr);return result.returncode
    names=("verification","state-verification","security-verification","application-verification")
    reports={name:json.loads((work/(name+".json")).read_text("utf-8")) for name in names}
    result={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"driver_runtimes":reports["verification"]["driver_runtimes"],"suites":{name:{k:r[k] for k in ("passed","total","failures")} for name,r in reports.items()},"report_sha256":{name:hashlib.sha256((work/(name+".json")).read_bytes()).hexdigest() for name in names},"python_policy":json.loads(result.stdout),"framework_execution":"net462 assemblies execute on the installed Windows CLR 4.x; this does not certify a separate original 4.6.2 installation" if os.name=="nt" else None}
    (work/"compatibility.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n");print(json.dumps(result));return 0

if __name__=="__main__":sys.exit(main())
