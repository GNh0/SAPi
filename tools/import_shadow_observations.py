"""Import bounded, sanitized observation features; execute only fixed local fixtures."""
import argparse
from contextlib import closing
import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import uuid

from compare_api_security import RAW_CASES, VARIANTS, action, digest, expected_for, start_variant
from sapi.serialization import parse

MAX_BYTES=65536
MAX_EVENTS=64
PATHS={'dotenv','config_backup','wordpress','root','api','soap','xml','sapi','other'}
METHODS={'GET','POST','OTHER'}
MEDIA={'none','xml','sapi','json','other'}
SIZES={'unknown','zero','small','medium','large'}
MAPPING={('GET','dotenv','none'):'raw_probe',('GET','config_backup','none'):'raw_backup',('GET','wordpress','none'):'raw_wordpress',('GET','sapi','none'):'raw_wrong_method',('POST','root','xml'):'raw_xml_root',('POST','api','xml'):'raw_xml_api',('POST','soap','xml'):'raw_xml_soap',('POST','xml','xml'):'raw_xml_xml',('POST','sapi','xml'):'raw_xml_endpoint'}
DDL='''
CREATE TABLE IF NOT EXISTS shadow_batches (batch_id TEXT PRIMARY KEY, batch_digest TEXT NOT NULL, imported_utc TEXT NOT NULL, sample_percent INTEGER NOT NULL, overflow INTEGER NOT NULL, seen INTEGER NOT NULL, sampled_out INTEGER NOT NULL, queue_dropped INTEGER NOT NULL, observer_error INTEGER NOT NULL, emitted INTEGER NOT NULL, new_events INTEGER NOT NULL, duplicates INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS shadow_events (request_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL, observed_utc TEXT NOT NULL, path_class TEXT NOT NULL, method TEXT NOT NULL, media_class TEXT NOT NULL, size_bucket TEXT NOT NULL, original_status INTEGER NOT NULL, observation_provenance TEXT NOT NULL, fixture_id TEXT, mapping_status TEXT NOT NULL, FOREIGN KEY(batch_id) REFERENCES shadow_batches(batch_id));
CREATE TABLE IF NOT EXISTS shadow_results (request_id TEXT NOT NULL, variant TEXT NOT NULL, fixture_id TEXT NOT NULL, experiment_provenance TEXT NOT NULL, expected_result TEXT NOT NULL, result TEXT NOT NULL, http_status INTEGER, inferred_stage TEXT NOT NULL, gateway_calls INTEGER NOT NULL, business_calls INTEGER NOT NULL, database_changed INTEGER NOT NULL, before_digest TEXT NOT NULL, after_digest TEXT NOT NULL, egress_observation TEXT NOT NULL, elapsed_ns INTEGER NOT NULL, verdict TEXT NOT NULL, PRIMARY KEY(request_id,variant), FOREIGN KEY(request_id) REFERENCES shadow_events(request_id));
'''


def valid_uuid(value):
    if not isinstance(value,str) or len(value)!=36: return False
    try: parsed=uuid.UUID(value)
    except ValueError: return False
    return parsed.version==4 and str(parsed)==value


def validate(batch):
    if type(batch) is not dict or set(batch)!={'batch_id','sample_percent','overflow','counters','events'} or not valid_uuid(batch['batch_id']): raise ValueError('invalid batch envelope')
    if type(batch['sample_percent']) is not int or not 1<=batch['sample_percent']<=100 or type(batch['overflow']) is not bool: raise ValueError('invalid sampling metadata')
    counters=batch['counters']
    if type(counters) is not dict or set(counters)!={'seen','sampled_out','queue_dropped','observer_error','emitted'}: raise ValueError('invalid counters')
    if any(type(v) is not int or not 0<=v<=1000000 for v in counters.values()): raise ValueError('invalid counter range')
    events=batch['events']
    if type(events) is not list or len(events)>MAX_EVENTS or counters['emitted']!=len(events) or counters['seen']!=sum(counters[k] for k in ('sampled_out','queue_dropped','observer_error','emitted')): raise ValueError('counter mismatch')
    required={'request_id','observed_utc','path_class','method','media_class','size_bucket','original_status'}
    for event in events:
        if type(event) is not dict or set(event)!=required or not valid_uuid(event['request_id']): raise ValueError('invalid event')
        if not isinstance(event['observed_utc'],str) or len(event['observed_utc'])!=24 or not event['observed_utc'].endswith('Z'): raise ValueError('invalid timestamp')
        try: datetime.datetime.strptime(event['observed_utc'],'%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError: raise ValueError('invalid timestamp') from None
        if not all(type(event[k]) is str for k in ('path_class','method','media_class','size_bucket')) or event['path_class'] not in PATHS or event['method'] not in METHODS or event['media_class'] not in MEDIA or event['size_bucket'] not in SIZES: raise ValueError('invalid feature')
        if type(event['original_status']) is not int or not 100<=event['original_status']<=599: raise ValueError('invalid status')
    return batch


def load_batch(path):
    with path.open('rb') as stream: raw=stream.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES: raise ValueError('batch too large')
    try: return validate(parse(raw))
    except ValueError: raise
    except Exception: raise ValueError('invalid JSON') from None


def fixture(event):
    # Only a single, fixed mapping is allowed; size and original response never select code.
    return MAPPING.get((event['method'],event['path_class'],event['media_class']))


def import_batch(batch,db_path):
    validate(batch)
    db_path.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(db_path)) as db:
        db.executescript(DDL); db.execute('PRAGMA foreign_keys=ON'); db.execute('BEGIN IMMEDIATE')
        try:
            fingerprint=hashlib.sha256(json.dumps(batch,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()
            prior=db.execute('SELECT batch_digest FROM shadow_batches WHERE batch_id=?',(batch['batch_id'],)).fetchone()
            if prior:
                if prior[0]!=fingerprint: raise ValueError('conflicting batch identity')
                db.rollback(); return {'status':'duplicate_batch','new_events':0,'duplicates':0}
            counters=batch['counters']
            db.execute('INSERT INTO shadow_batches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(batch['batch_id'],fingerprint,datetime.datetime.now(datetime.timezone.utc).isoformat(),batch['sample_percent'],int(batch['overflow']),counters['seen'],counters['sampled_out'],counters['queue_dropped'],counters['observer_error'],counters['emitted'],0,0))
            new=[]; duplicates=0
            for event in batch['events']:
                previous=db.execute('SELECT observed_utc,path_class,method,media_class,size_bucket,original_status FROM shadow_events WHERE request_id=?',(event['request_id'],)).fetchone()
                if previous:
                    if previous!=tuple(event[k] for k in ('observed_utc','path_class','method','media_class','size_bucket','original_status')): raise ValueError('conflicting request identity')
                    duplicates+=1; continue
                selected=fixture(event)
                db.execute('INSERT INTO shadow_events VALUES(?,?,?,?,?,?,?,?,?,?,?)',(event['request_id'],batch['batch_id'],event['observed_utc'],event['path_class'],event['method'],event['media_class'],event['size_bucket'],event['original_status'],'site_feature_observation',selected,'mapped' if selected else 'unsupported'))
                if selected: new.append((event['request_id'],selected))
            with tempfile.TemporaryDirectory(prefix='sapi-shadow-') as temp:
                for variant in VARIANTS:
                    if not new: break
                    records,codec,tokens,counts,server,thread=start_variant(variant,Path(temp))
                    try:
                        for request_id,selected in new:
                            before,_=digest(records); old=counts.copy(); started=time.perf_counter_ns()
                            try: result,status,_=action(selected,variant,codec,tokens,server,None)
                            except Exception: result,status='execution_error',None
                            elapsed=time.perf_counter_ns()-started; after,_=digest(records)
                            expected,expected_status,expected_gateway,expected_business,expected_change=expected_for(selected,variant)
                            gateway=counts['gateway']-old['gateway']; business=counts['business']-old['business']; changed=before!=after
                            passed=result==expected and status==expected_status and gateway==expected_gateway and business==expected_business and changed==expected_change
                            db.execute('INSERT INTO shadow_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(request_id,variant,selected,'local_reconstructed_fixture',expected,result,status,'transport_or_route_inferred',gateway,business,int(changed),before,after,'not_measured',elapsed,'pass' if passed else 'fail'))
                    finally: server.shutdown(); server.server_close(); thread.join(timeout=3)
            db.execute('UPDATE shadow_batches SET new_events=?,duplicates=? WHERE batch_id=?',(len(batch['events'])-duplicates,duplicates,batch['batch_id']))
            db.commit()
            return {'status':'imported','new_events':len(batch['events'])-duplicates,'duplicates':duplicates,'mapped':len(new),'unsupported':len(batch['events'])-duplicates-len(new)}
        except BaseException: db.rollback(); raise


def report(path):
    if not path.is_file(): raise ValueError('database does not exist')
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)) as db:
        batches=db.execute('SELECT count(*),coalesce(sum(seen),0),coalesce(sum(sampled_out),0),coalesce(sum(queue_dropped),0),coalesce(sum(observer_error),0),coalesce(sum(duplicates),0),coalesce(sum(overflow),0) FROM shadow_batches').fetchone()
        event_counts=dict(db.execute('SELECT mapping_status,count(*) FROM shadow_events GROUP BY mapping_status').fetchall())
        failures=db.execute("SELECT count(*) FROM shadow_results WHERE verdict<>'pass'").fetchone()[0]
        missing=db.execute("SELECT count(*) FROM shadow_events e WHERE (e.mapping_status='mapped' AND ((SELECT count(*) FROM shadow_results r WHERE r.request_id=e.request_id)<>3 OR (SELECT count(*) FROM shadow_results r WHERE r.request_id=e.request_id AND r.variant IN ('baseline','baseline_replay','sapi') AND r.fixture_id=e.fixture_id)<>3)) OR (e.mapping_status='unsupported' AND EXISTS (SELECT 1 FROM shadow_results r WHERE r.request_id=e.request_id))").fetchone()[0]
        return {'batches':batches[0],'seen':batches[1],'sampled_out':batches[2],'queue_dropped':batches[3],'observer_error':batches[4],'duplicates':batches[5],'overflow_batches':batches[6],'mapped':event_counts.get('mapped',0),'unsupported':event_counts.get('unsupported',0),'failed_results':failures,'incomplete_events':missing,'database_integrity':db.execute('PRAGMA integrity_check').fetchone()[0]=='ok','provenance':'Site-derived classifications and local synthetic fixtures are distinct; original traffic was not replayed.','limitations':['Source counters are self-reported, not independent traffic completeness proof.','No payload, user, credential, external URL, or authenticated SAPi request is inferred.','Egress and external file access are not measured.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='command',required=True)
    ingest=sub.add_parser('import'); ingest.add_argument('--input',type=Path,required=True); ingest.add_argument('--db',type=Path,required=True)
    query=sub.add_parser('report'); query.add_argument('--db',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.command=='import':
            result=import_batch(load_batch(args.input),args.db); print(json.dumps(result))
        result=report(args.db); print(json.dumps(result,indent=2))
        return 0 if result['database_integrity'] and result['failed_results']==0 and result['incomplete_events']==0 else 1
    except (ValueError,OSError,sqlite3.Error):
        print('invalid input or unavailable database',file=sys.stderr); return 2
if __name__=='__main__': sys.exit(main())
