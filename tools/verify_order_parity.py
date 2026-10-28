"""Synthetic orders feature parity; no observation of live traffic is implied."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import uuid
from compare_api_security import VARIANTS, digest, exchange, start_variant
from evidence_common import provenance, failure_category
from orders_contract import expected_digest

D1={'description':'fixture','quantity':1}
D2={'description':'updated fixture','quantity':2}
def record(id,version,phase,data): return {'id':id,'version':version,'phase':phase,'data':data}
def changed(value,rows): return {'changed':value,'records':rows}
def found(value,rows): return {'found':value,'records':rows}
STEPS=[
 ('missing_get','writer','get',{'id':'missing'},found(False,[])),
 ('create','writer','create',{'id':'own','data':D1},changed(True,[record('own',1,'created',D1)])),
 ('get','writer','get',{'id':'own'},found(True,[record('own',1,'created',D1)])),
 ('reader_get','reader','get',{'id':'own'},found(True,[record('own',1,'created',D1)])),
 ('duplicate_create','writer','create',{'id':'own','data':D1},changed(False,[])),
 ('update','writer','update',{'id':'own','version':1,'data':D2},changed(True,[record('own',2,'created',D2)])),
 ('stale_update','writer','update',{'id':'own','version':1,'data':D1},changed(False,[])),
 ('foreign_get','writer','get',{'id':'foreign'},found(False,[])),
 ('foreign_update','writer','update',{'id':'foreign','version':1,'data':D1},changed(False,[])),
 ('invalid_schema','writer','update',{'id':'own','version':2,'data':{'description':'fixture','quantity':'1'}},'invalid_input'),
 ('missing_scope','reader','delete',{'id':'own','version':2},'forbidden'),
 ('submit','writer','submit',{'id':'own','version':2},changed(True,[record('own',3,'submitted',D2)])),
 ('post_submit_update','writer','update',{'id':'own','version':3,'data':D1},'forbidden'),
 ('complete','writer','complete',{'id':'own','version':3},changed(True,[record('own',4,'completed',D2)])),
 ('completed_delete','writer','delete',{'id':'own','version':4},'forbidden'),
 ('create_for_delete','writer','create',{'id':'disposable','data':D1},changed(True,[record('disposable',1,'created',D1)])),
 ('delete','writer','delete',{'id':'disposable','version':1},changed(True,[])),
 ('deleted_get','writer','get',{'id':'disposable'},found(False,[])),
]
MUTATIONS={'create','update','submit','complete','create_for_delete','delete'}


def run(db_path):
    if db_path.exists(): raise ValueError('new database required')
    db_path.parent.mkdir(parents=True,exist_ok=True)
    run_id=uuid.uuid4().hex
    with closing(sqlite3.connect(db_path)) as db:
        db.execute('PRAGMA user_version=1')
        db.execute('CREATE TABLE parity_runs (run_id TEXT PRIMARY KEY, status TEXT NOT NULL, environment TEXT NOT NULL)')
        db.execute('CREATE TABLE parity_results (run_id TEXT, step_index INTEGER, feature TEXT, variant TEXT, expected_outcome TEXT, observed_outcome TEXT, before_digest TEXT, after_digest TEXT, expected_change INTEGER, db_changed INTEGER, handler_calls INTEGER, verdict TEXT, provenance TEXT, failure_reason TEXT, PRIMARY KEY(run_id,step_index,variant))')
        db.execute('INSERT INTO parity_runs VALUES(?,?,?)',(run_id,'running',provenance())); db.commit()
        with tempfile.TemporaryDirectory(prefix='sapi-parity-') as temp:
            for variant in VARIANTS:
                records,codec,tokens,counts,server,thread=start_variant(variant,Path(temp))
                try:
                    for index,(name,kid,op,data,expected) in enumerate(STEPS):
                        before,_=digest(records);old=counts['business']; outcome='execution_error'; failure_reason=None
                        try:
                            if variant=='sapi':
                                context=codec.request(kid,'orders_'+op,data)
                                status,wire=exchange(server,'POST','/sapi',context.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                                response=codec.accept_response(context,wire.decode('ascii')) if status==200 else {}
                            else:
                                body=json.dumps(data,separators=(',',':')).encode()
                                status,wire=exchange(server,'POST','/orders/'+op,body,{'Content-Type':'application/json','Authorization':'Bearer '+tokens[kid],'X-Request-ID':uuid.uuid4().hex})
                                response=json.loads(wire)
                            actual=response.get('data') if response.get('ok') is True else response.get('error')
                            expected_status=200 if variant=='sapi' or isinstance(expected,dict) else 403 if expected=='forbidden' else 400
                            outcome='matches_expected' if actual==expected and status==expected_status else 'mismatch'
                        except Exception as exc: failure_reason=failure_category(exc)
                        after,_=digest(records);changed_state=before!=after;handler=counts['business']-old
                        expected_handler=0 if name in ('invalid_schema','missing_scope') else 1
                        passed=outcome=='matches_expected' and changed_state==(name in MUTATIONS) and handler==expected_handler and before==expected_digest(index,False) and after==expected_digest(index,True)
                        db.execute('INSERT INTO parity_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(run_id,index,name,variant,'matches_expected',outcome,before,after,int(name in MUTATIONS),int(changed_state),handler,'pass' if passed else 'fail','synthetic_feature_parity',failure_reason)); db.commit()
                finally: server.shutdown();server.server_close();thread.join(timeout=3)
        db.execute("UPDATE parity_runs SET status='completed' WHERE run_id=?",(run_id,)); db.commit()
    return run_id


def report(db_path,run_id):
    with closing(sqlite3.connect(db_path.resolve().as_uri()+'?mode=ro',uri=True)) as db:
        version=db.execute('PRAGMA user_version').fetchone()[0]
        if version != 1: raise ValueError('unsupported evidence schema; preserve legacy evidence')
        run=db.execute('SELECT status,environment FROM parity_runs WHERE run_id=?',(run_id,)).fetchone()
        if run is None: raise ValueError('run not found')
        rows=db.execute('SELECT step_index,feature,variant,observed_outcome,before_digest,after_digest,verdict FROM parity_results WHERE run_id=? ORDER BY step_index,variant',(run_id,)).fetchall()
        result=[]
        for index,(name,*_) in enumerate(STEPS):
            group=[r for r in rows if r[0]==index]
            passed=len(group)==3 and {r[2] for r in group}==set(VARIANTS) and all(r[1]==name and r[3]=='matches_expected' and r[6]=='pass' and r[4]==expected_digest(index,False) and r[5]==expected_digest(index,True) for r in group)
            result.append({'feature':name,'pass':passed})
        integrity=db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        return {'run_id':run_id,'status':run[0],'environment':json.loads(run[1]),'provenance':'synthetic_feature_parity','steps':len(STEPS),'observations':len(rows),'integrity_check':integrity,'all_pass':run[0]=='completed' and integrity and len(rows)==3*len(STEPS) and all(x['pass'] for x in result),'features':result,'limitations':['Shared orders business implementation; not independent implementations.','Synthetic controls only; not real-traffic evidence.','Does not cover arbitrary APIs, TLS or distributed state.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--db',type=Path,required=True);parser.add_argument('--report-run');args=parser.parse_args()
    result=report(args.db,args.report_run or run(args.db));print(json.dumps(result,indent=2));return 0 if result['all_pass'] else 1
if __name__=='__main__':sys.exit(main())
