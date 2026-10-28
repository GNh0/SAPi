"""Local, bounded comparison of SAPi with an authenticated JSON orders API."""
import argparse
from contextlib import closing
import datetime
import hashlib
import hmac
import http.client
import http.server
import json
import platform
from pathlib import Path
import secrets
import sqlite3
import socket
import statistics
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT/'tools', ROOT/'sdks/python', ROOT/'services/state', ROOT/'services/application'):
    sys.path.insert(0, str(path))
from comparison_common import COLLECTIONS, baseline_transport, BaselineQuota, BaselineCostBudget
from evidence_common import provenance, failure_category
from sapi import Codec, KeyRecord, Principal, SapiError, SplitBudgetMemoryReplayStore
from sapi.serialization import parse, digest as wire_digest
from sapi_application import Application, Records, make_server

VARIANTS = ('baseline', 'baseline_replay', 'sapi')
RAW_CASES = {
    'raw_probe':('GET','/.env',None,None,404,501),
    'raw_backup':('GET','/config.bak',None,None,404,501),
    'raw_wordpress':('GET','/wp-admin/',None,None,404,501),
    'raw_wrong_method':('GET','/sapi',None,None,404,501),
    'raw_xml_root':('POST','/',b'<fixture/>','application/xml',400,400),
    'raw_xml_api':('POST','/api',b'<fixture/>','application/xml',400,400),
    'raw_xml_soap':('POST','/soap',b'<fixture/>','application/xml',400,400),
    'raw_xml_xml':('POST','/xml',b'<fixture/>','application/xml',400,400),
    'raw_xml_endpoint':('POST','/sapi',b'<fixture/>','application/xml',400,400),
    'raw_wrong_path':('POST','/api',b'x','application/sapi+jwe',400,400),
    'framing_content_encoding':('POST','',b'x','',400,400),
    'framing_oversized':('POST','',b'','',400,400),
    'framing_duplicate_length':('POST','',b'x','',400,400),
    'framing_transfer_encoding':('POST','',b'x','',400,400),
    'invalid_wire':('POST','',b'x','',401,400),
}
ADAPTED_CASES=frozenset(('framing_content_encoding','framing_oversized','framing_duplicate_length','framing_transfer_encoding','invalid_wire'))
FIXTURES = [(name,'endpoint_adapted' if name in ADAPTED_CASES else 'same_raw','http_'+str(case[4]),'http_'+str(case[5]),False) for name,case in RAW_CASES.items()] + [
    ('normal_create','equivalent_authenticated','created','created',True),
    ('invalid_schema','equivalent_authenticated','invalid_input','invalid_input',False),
    ('missing_scope','equivalent_authenticated','forbidden','forbidden',False),
    ('foreign_owner','equivalent_authenticated','not_changed','not_changed',False),
    ('invalid_transition','equivalent_authenticated','forbidden','forbidden',False),
    ('normal_get','equivalent_authenticated','found','found',False),
    ('repeat_get','equivalent_authenticated','found','replay',False),
    ('tampered_message','sapi_only','not_measured','http_400',False),
    ('normal_submit','equivalent_authenticated','submitted','submitted',True),
    ('post_submit_update','equivalent_authenticated','forbidden','forbidden',False),
]
SUMMARY = {name:'synthetic '+name.replace('_',' ') for name in RAW_CASES}
SUMMARY.update({'normal_create':'valid order', 'invalid_schema':'quantity has wrong type', 'missing_scope':'read-only principal attempts delete', 'foreign_owner':'update another principal order', 'invalid_transition':'complete before submit', 'normal_get':'read own order', 'repeat_get':'repeat identical previous request', 'tampered_message':'alter an authenticated SAPi message ciphertext; no plaintext baseline comparison','normal_submit':'valid state transition','post_submit_update':'attempt update after submission'})
DDL = '''
CREATE TABLE runs (run_id TEXT PRIMARY KEY, started_utc TEXT NOT NULL, repetitions INTEGER NOT NULL, environment TEXT NOT NULL, scope TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE observations (run_id TEXT NOT NULL, repetition INTEGER NOT NULL, case_id TEXT NOT NULL, variant TEXT NOT NULL, correlation_id TEXT NOT NULL, sequence_index INTEGER NOT NULL, comparison_mode TEXT NOT NULL, fixture_summary TEXT NOT NULL, expected_result TEXT NOT NULL, result TEXT NOT NULL, http_status INTEGER, decision_stage TEXT NOT NULL, reason TEXT NOT NULL, expected_db_change INTEGER NOT NULL, db_changed INTEGER NOT NULL, before_digest TEXT NOT NULL, after_digest TEXT NOT NULL, before_state TEXT NOT NULL, after_state TEXT NOT NULL, gateway_calls INTEGER NOT NULL, business_calls INTEGER NOT NULL, egress_observation TEXT NOT NULL, elapsed_ns INTEGER, verdict TEXT NOT NULL, PRIMARY KEY(run_id,repetition,case_id,variant), FOREIGN KEY(run_id) REFERENCES runs(run_id));
'''


def digest(records):
    with records.db.transaction() as tx:
        rows = [tuple(r) for r in tx.execute('SELECT service,collection,owner,id,version,phase,payload FROM sapi_app_records ORDER BY service,collection,owner,id').fetchall()]
    checksum=hashlib.sha256(json.dumps(rows,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
    phases={p:sum(1 for r in rows if r[5]==p) for p in ('created','submitted','completed')}
    phases['other']=sum(1 for r in rows if r[5] not in phases)
    return checksum, json.dumps({'rows':len(rows),'phases':phases,'version_sum':sum(r[4] for r in rows)},sort_keys=True)


def expected_snapshot(include_own,submitted=False):
    payload=json.dumps({'description':'fixture','quantity':1},ensure_ascii=False,separators=(',',':'))
    rows=[('demo','orders','bob','foreign',1,'created',payload)]
    if include_own: rows.insert(0,('demo','orders','alice','own',2 if submitted else 1,'submitted' if submitted else 'created',payload))
    checksum=hashlib.sha256(json.dumps(rows,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
    summary=json.dumps({'rows':len(rows),'phases':{'created':len(rows)-int(submitted),'submitted':int(submitted),'completed':0,'other':0},'version_sum':len(rows)+int(submitted)},sort_keys=True)
    return checksum,summary


def start_variant(kind, folder, *, idempotency=False, split_budget=False, collections=None):
    if split_budget and kind not in ('baseline_replay','sapi'): raise ValueError('split budget requires replay-aware variant')
    db = folder/(kind+'.sqlite'); db.touch(); records = Records(str(db),enable_idempotency=idempotency)
    records.mutate('create','demo','orders',Principal('bob',frozenset()),{'id':'foreign','data':{'description':'fixture','quantity':1}},initial='created',write_phases=['created'])
    keys={'writer':KeyRecord(secrets.token_bytes(32),'alice',frozenset({'orders_read','orders_write'})), 'writer2':KeyRecord(secrets.token_bytes(32),'alice',frozenset({'orders_read','orders_write'})), 'reader':KeyRecord(secrets.token_bytes(32),'alice',frozenset({'orders_read'}))}
    codec=Codec('demo',keys)
    counts={'gateway':0,'business':0}
    class CountedRecords:
        idempotency_enabled=idempotency
        def get(self,*a,**kw): counts['business']+=1; return records.get(*a,**kw)
        def mutate(self,*a,**kw): counts['business']+=1; return records.mutate(*a,**kw)
        def receipt(self,*a,**kw): counts['business']+=1; return records.receipt(*a,**kw)
    app=Application(codec,SplitBudgetMemoryReplayStore() if split_budget and kind=='sapi' else None,CountedRecords(),COLLECTIONS if collections is None else collections,enable_idempotency=idempotency,split_budget=split_budget and kind=='sapi')
    tokens={name:secrets.token_urlsafe(32) for name in keys}
    replay_seen=set(); replay_lock=threading.Lock(); quota=BaselineQuota(); cost=BaselineCostBudget()
    if kind == 'sapi':
        class Gateway:
            def handle(self,wire): counts['gateway']+=1; return app.handle(wire)
        server=make_server(Gateway(),port=0,peer_requests=200 if split_budget else 100,timeout=3)
    else:
        class Baseline(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*a): pass
            def respond(self,status,payload=None):
                body=json.dumps(payload,separators=(',',':')).encode() if payload is not None else b''
                self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(body); self.close_connection=True
            def do_GET(self): self.respond(404)
            def do_POST(self):
                sizes=self.headers.get_all('Content-Length',[])
                if not baseline_transport(self.path,sizes,self.headers.get_all('Content-Type',[]),self.headers.get('Transfer-Encoding'),self.headers.get('Content-Encoding')):
                    self.respond(400); return
                auth=self.headers.get_all('Authorization',[]); identity=None
                if len(auth)==1:
                    for name,token in tokens.items():
                        if hmac.compare_digest(auth[0], 'Bearer '+token): identity=name
                if identity is None: self.respond(401); return
                counts['gateway']+=1
                op='orders_'+self.path[len('/orders/'):]
                operation=app.server.operations.get(op)
                try:
                    if not (cost.admit(keys[identity].subject,int(time.time())) if split_budget else quota.admit(keys[identity].subject,op if operation else 'unknown',int(time.time()),operation[5] if operation else 60,operation[6] if operation else 60)):
                        self.respond(429,{'ok':False,'error':'rate_limited'}); return
                except Exception:
                    self.respond(503,{'ok':False,'error':'rate_capacity'}); return
                if kind=='baseline_replay':
                    values=self.headers.get_all('X-Request-ID',[])
                    if len(values)!=1 or len(values[0])!=32 or any(c not in '0123456789abcdef' for c in values[0]): self.respond(400,{'ok':False,'error':'invalid_input'}); return
                    with replay_lock:
                        key=(identity,values[0])
                        if key in replay_seen: self.respond(409,{'ok':False,'error':'replay'}); return
                        if len(replay_seen)>=1000: self.respond(503,{'ok':False,'error':'capacity'}); return
                        replay_seen.add(key)
                try:
                    data=parse(self.rfile.read(int(sizes[0])))
                except SapiError:
                    self.respond(400,{'ok':False,'error':'invalid_input'}); return
                try:
                    if operation is None: self.respond(404); return
                    scope,inschema,outschema,policy,handler,_,_=operation
                    principal=Principal(keys[identity].subject,keys[identity].scopes)
                    if scope not in principal.scopes: raise SapiError('forbidden')
                    if not inschema.validate(data): raise SapiError('invalid_input')
                    if not policy(principal,data): raise SapiError('forbidden')
                    if split_budget and not quota.admit(principal.subject,op,int(time.time()),operation[5],operation[6]): raise SapiError('rate_limited')
                    response=handler(principal,data)
                    if not outschema.validate(response): raise ValueError()
                    self.respond(200,{'ok':True,'data':response})
                except SapiError as exc:
                    code=exc.code if exc.code in ('replay','replay_capacity','rate_limited','rate_capacity','unknown_operation','forbidden','invalid_input','idempotency_conflict','idempotency_expired','idempotency_capacity','idempotency_clock') else 'internal_error'
                    self.respond(403 if code=='forbidden' else 429 if code=='rate_limited' else 409 if code=='idempotency_conflict' else 410 if code=='idempotency_expired' else 503 if code in ('idempotency_capacity','idempotency_clock') else 500 if code=='internal_error' else 400,{'ok':False,'error':code})
                except Exception: self.respond(500,{'ok':False,'error':'internal_error'})
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Baseline); server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    return records,codec,tokens,counts,server,thread


def exchange(server,method,path,body=b'',headers=None):
    conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=4)
    try:
        conn.request(method,path,body,headers or {}); response=conn.getresponse(); return response.status,response.read()
    finally: conn.close()


def action(case,kind,codec,tokens,server,repeat):
    if case in RAW_CASES:
        method,path,body,media,_,_=RAW_CASES[case]
        body=body or b''
        if case in ADAPTED_CASES:
            path='/sapi' if kind=='sapi' else '/orders/get'
            media='application/sapi+jwe' if kind=='sapi' else 'application/json'
        headers=[]
        if media: headers.append('Content-Type: '+media)
        if method=='POST': headers.append('Content-Length: '+('200000' if case=='framing_oversized' else str(len(body))))
        if case=='framing_content_encoding': headers.append('Content-Encoding: gzip')
        if case=='framing_duplicate_length': headers.append('Content-Length: 1')
        if case=='framing_transfer_encoding': headers.append('Transfer-Encoding: chunked')
        raw=(method+' '+path+' HTTP/1.1\r\nHost: localhost\r\n'+'\r\n'.join(headers)+'\r\n\r\n').encode()+body
        with socket.create_connection(('127.0.0.1',server.server_port),timeout=4) as sock:
            sock.sendall(raw); sock.shutdown(socket.SHUT_WR); first=sock.recv(1024).split(b'\r\n',1)[0]
        status=int(first.split()[1])
        return 'http_'+str(status),status,None
    if case=='tampered_message':
        if kind!='sapi': return 'not_measured',None,repeat
        context=codec.request('writer','orders_get',{'id':'own'})
        parts=context.wire.split('.'); parts[3]=('A' if parts[3][0]!='A' else 'B')+parts[3][1:]
        status,_=exchange(server,'POST','/sapi','.'.join(parts).encode('ascii'),{'Content-Type':'application/sapi+jwe'})
        return 'http_'+str(status),status,repeat
    data={'description':'fixture','quantity':1}
    payloads={'normal_create':('writer','create',{'id':'own','data':data}), 'invalid_schema':('writer','update',{'id':'own','version':1,'data':{'description':'fixture','quantity':'1'}}), 'missing_scope':('reader','delete',{'id':'own','version':1}), 'foreign_owner':('writer','update',{'id':'foreign','version':1,'data':data}), 'invalid_transition':('writer','complete',{'id':'own','version':1}), 'normal_get':('writer','get',{'id':'own'}), 'repeat_get':('writer','get',{'id':'own'}), 'normal_submit':('writer','submit',{'id':'own','version':1}), 'post_submit_update':('writer','update',{'id':'own','version':2,'data':data})}
    identity,operation,body=payloads[case]
    if kind=='sapi':
        context=repeat if case=='repeat_get' else codec.request(identity,'orders_'+operation,body)
        status,wire=exchange(server,'POST','/sapi',context.wire.encode('ascii'),{'Content-Type':'application/sapi+jwe'})
        if status!=200: return 'transport_error',status,context
        # Decode a response to the repeated request without reusing a consumed client context.
        if case=='repeat_get':
            kid,response=codec.open(wire.decode('ascii'),'res')
            if kid!=context.kid or response['id']!=context.request_id or response['req']!=wire_digest(context.wire): raise ValueError('response correlation failed')
        else: response=codec.accept_response(context,wire.decode('ascii'))
        next_repeat=context if case=='normal_get' else repeat
    else:
        body_bytes=json.dumps(body,separators=(',',':')).encode()
        request_id=repeat if case=='repeat_get' else uuid.uuid4().hex
        status,wire=exchange(server,'POST','/orders/'+operation,body_bytes,{'Content-Type':'application/json','Authorization':'Bearer '+tokens[identity],'X-Request-ID':request_id})
        response=json.loads(wire); next_repeat=request_id if case=='normal_get' else repeat
    if not response['ok']: return response['error'],status,next_repeat
    result=response['data']
    record={'id':'own','version':1,'phase':'created','data':data}
    if operation=='create' and result=={'changed':True,'records':[record]}: code='created'
    elif operation=='get' and result=={'found':True,'records':[record]}: code='found'
    elif operation=='submit' and result=={'changed':True,'records':[dict(record,version=2,phase='submitted')]}: code='submitted'
    elif result=={'changed':False,'records':[]}: code='not_changed'
    else: code='unexpected_success'
    return code,status,next_repeat


def expected_for(name, variant):
    fixture=next(f for f in FIXTURES if f[0]==name)
    result=fixture[3] if variant=='sapi' else fixture[2]
    if name=='repeat_get' and variant=='baseline_replay': result='replay'
    status=(RAW_CASES[name][5 if variant=='sapi' else 4] if name in RAW_CASES else
            (400 if variant=='sapi' else None) if name=='tampered_message' else
            200 if variant=='sapi' else 409 if name=='repeat_get' and variant=='baseline_replay' else
            400 if name=='invalid_schema' else 403 if name in ('missing_scope','invalid_transition','post_submit_update') else 200)
    gateway=1 if name=='invalid_wire' and variant=='sapi' else 0 if name in RAW_CASES or (name=='tampered_message' and variant!='sapi') else 1
    business=1 if name in ('normal_create','foreign_owner','invalid_transition','normal_get','normal_submit','post_submit_update') or (name=='repeat_get' and variant=='baseline') else 0
    return result,status,gateway,business,fixture[4]


def execute(db_path,repetitions):
    if db_path.exists(): raise ValueError('use a new result database path')
    db_path.parent.mkdir(parents=True,exist_ok=True)
    run_id=uuid.uuid4().hex
    with closing(sqlite3.connect(db_path)) as out:
        out.executescript(DDL)
        out.execute('PRAGMA user_version=1')
        out.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)',(run_id,datetime.datetime.now(datetime.timezone.utc).isoformat(),repetitions,provenance(),'SQLite records; ephemeral credentials; egress and external file access not measured','running')); out.commit()
        for rep in range(1,repetitions+1):
            with tempfile.TemporaryDirectory(prefix='sapi-comparison-') as tmp:
                rotation=(rep-1)%len(VARIANTS)
                order=VARIANTS[rotation:]+VARIANTS[:rotation]
                for sequence_index,variant in enumerate(order):
                    records,codec,tokens,counts,server,thread=start_variant(variant,Path(tmp)); repeat=None
                    try:
                        for name,mode,baseline_expected,sapi_expected,expected_change in FIXTURES:
                            expected,expected_status,expected_gateway,expected_business,expected_change=expected_for(name,variant)
                            before,before_state=digest(records); old=counts.copy(); started=time.perf_counter_ns()
                            failure=None
                            try: result,status,repeat=action(name,variant,codec,tokens,server,repeat)
                            except Exception as exc: result,status='execution_error',None; failure=failure_category(exc)
                            elapsed=time.perf_counter_ns()-started if not (name=='tampered_message' and variant!='sapi') else None; after,after_state=digest(records); changed=before!=after
                            gateway=counts['gateway']-old['gateway']; business=counts['business']-old['business']
                            ok=result==expected and status==expected_status and changed==expected_change and gateway==expected_gateway and business==expected_business
                            stage=('message_authentication' if variant=='sapi' else 'authentication') if name=='invalid_wire' else 'transport_or_route' if name in RAW_CASES else 'message_authentication' if name=='tampered_message' and variant=='sapi' else 'not_measured' if name=='tampered_message' else {'normal_create':'business','invalid_schema':'schema','missing_scope':'scope','foreign_owner':'ownership','invalid_transition':'workflow','normal_get':'business','normal_submit':'workflow','post_submit_update':'workflow','repeat_get':'replay' if variant!='baseline' else 'business'}[name]
                            verdict='not_measured' if ok and result=='not_measured' else 'pass' if ok else 'fail'
                            out.execute('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(run_id,rep,name,variant,uuid.uuid5(uuid.UUID(run_id),str(rep)+':'+name).hex,sequence_index,mode,SUMMARY[name],expected,result,status,stage,failure or result,int(expected_change),int(changed),before,after,before_state,after_state,gateway,business,'not_measured',elapsed,verdict)); out.commit()
                    finally: server.shutdown(); server.server_close(); thread.join(timeout=3)
        out.execute("UPDATE runs SET status='completed' WHERE run_id=?",(run_id,)); out.commit()
    return run_id


def report(db_path,run_id=None):
    if not db_path.is_file(): raise ValueError('result database does not exist')
    with closing(sqlite3.connect(db_path.resolve().as_uri()+'?mode=ro',uri=True)) as db:
        db.row_factory=sqlite3.Row
        version=db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0,1): raise ValueError('unsupported evidence schema')
        if run_id is None:
            row=db.execute('SELECT run_id FROM runs ORDER BY started_utc DESC LIMIT 1').fetchone()
            if row is None: raise ValueError('no runs')
            run_id=row['run_id']
        run=db.execute('SELECT * FROM runs WHERE run_id=?',(run_id,)).fetchone()
        if run is None: raise ValueError('run not found')
        rows=db.execute('SELECT * FROM observations WHERE run_id=? ORDER BY repetition,case_id,variant',(run_id,)).fetchall()
        integrity=db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        summary=[]
        for name,mode,_,_,_ in FIXTURES:
            group=[r for r in rows if r['case_id']==name]
            variants={v:[r for r in group if r['variant']==v] for v in VARIANTS}
            state_equal = all({r['variant'] for r in group if r['repetition']==rep}==set(VARIANTS) and len({r['before_digest'] for r in group if r['repetition']==rep})==1 and len({r['after_digest'] for r in group if r['repetition']==rep})==1 for rep in range(1,run['repetitions']+1))
            def valid_row(r):
                variant=r['variant']; expected,expected_status,expected_gateway,expected_business,expected_change=expected_for(name,variant)
                before_expected=expected_snapshot(name not in RAW_CASES and name!='normal_create',submitted=name=='post_submit_update')
                after_expected=expected_snapshot(name not in RAW_CASES,submitted=name in ('normal_submit','post_submit_update'))
                expected_verdict='not_measured' if expected=='not_measured' and version==1 else 'pass'
                return (r['expected_result']==expected and r['result']==expected and r['http_status']==expected_status and r['expected_db_change']==int(expected_change) and r['db_changed']==int(expected_change) and (r['before_digest'],r['before_state'])==before_expected and (r['after_digest'],r['after_state'])==after_expected and r['db_changed']==int(r['before_digest']!=r['after_digest']) and r['gateway_calls']==expected_gateway and r['business_calls']==expected_business and r['verdict']==expected_verdict)
            paired = all(len({r['correlation_id'] for r in group if r['repetition']==rep})==1 for rep in range(1,run['repetitions']+1))
            valid_group = len(group)==run['repetitions']*3 and state_equal and paired and all(valid_row(r) for r in group)
            classification = 'not_verified' if not valid_group else 'protocol_configuration_difference' if name in RAW_CASES and RAW_CASES[name][4]!=RAW_CASES[name][5] else 'sapi_message_authentication_only' if name=='tampered_message' else 'replay_configuration_difference' if name=='repeat_get' else 'same_observed_outcome'
            examples=[]
            for variant in VARIANTS:
                first=next((r for r in variants[variant] if r['repetition']==1),None)
                if first:
                    examples.append({k:first[k] for k in ('variant','fixture_summary','expected_result','result','http_status','decision_stage','reason','before_state','after_state','db_changed','gateway_calls','business_calls','egress_observation','verdict')})
            timing_ranges={v:[min(r['elapsed_ns'] for r in variants[v]),max(r['elapsed_ns'] for r in variants[v])] if variants[v] and not (mode=='sapi_only' and v!='sapi') else None for v in VARIANTS}
            summary.append({'timing_range_ns':timing_ranges, 'examples':examples, 'classification':classification, 'state_equal':state_equal, 'case':name,'mode':mode,'baseline_results':sorted({r['result'] for r in variants['baseline']}),'baseline_replay_results':sorted({r['result'] for r in variants['baseline_replay']}),'sapi_results':sorted({r['result'] for r in variants['sapi']}),'all_pass':valid_group if mode!='sapi_only' else None,'evidence_consistent':valid_group,'baseline_median_ns':statistics.median(r['elapsed_ns'] for r in variants['baseline']) if variants['baseline'] and mode!='sapi_only' else None,'baseline_replay_median_ns':statistics.median(r['elapsed_ns'] for r in variants['baseline_replay']) if variants['baseline_replay'] and mode!='sapi_only' else None,'sapi_median_ns':statistics.median(r['elapsed_ns'] for r in variants['sapi']) if variants['sapi'] else None})
        expected_count=run['repetitions']*len(FIXTURES)*3
        status=run['status'] if version==1 else 'legacy_unversioned'
        return {'run_id':run_id,'status':status,'started_utc':run['started_utc'],'repetitions':run['repetitions'],'environment':run['environment'],'scope':run['scope'],'observations':len(rows),'expected_observations':expected_count,'integrity_check':integrity,'all_pass':status=='completed' and integrity and len(rows)==expected_count and all(x['evidence_consistent'] for x in summary),'cases':summary,'limits':['all_pass checks fixture evidence consistency only, not unmeasured outcomes or overall security.','Expected stages are inferred, not traced. Egress and external file access are not measured.','HTTP status reflects protocol/configuration differences, not a security score.','Durable replay, TLS, distributed systems and OS-wide effects are not tested.','Timing is local end-to-end with rotating variant order; small samples do not establish general performance.', 'The message-tampering case has no baseline observation; baseline timing is not measured.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='command',required=True)
    run=sub.add_parser('run'); run.add_argument('--db',type=Path,required=True); run.add_argument('--repetitions',type=int,default=6)
    query=sub.add_parser('report'); query.add_argument('--db',type=Path,required=True); query.add_argument('--run-id')
    args=parser.parse_args()
    if args.command=='run':
        if not 1<=args.repetitions<=30: parser.error('repetitions must be 1..30')
        run_id=execute(args.db,args.repetitions)
    else: run_id=args.run_id
    result=report(args.db,run_id); print(json.dumps(result,indent=2)); return 0 if result['all_pass'] else 1
if __name__=='__main__': sys.exit(main())
