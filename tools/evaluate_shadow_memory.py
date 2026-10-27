"""In-process, isolated gate for limited real request input; never persists raw input."""
import datetime
import hashlib
from contextlib import closing
from pathlib import Path
import secrets
import socket
import sqlite3
import sys
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT/'sdks/python', ROOT/'services/state', ROOT/'services/application'):
    sys.path.insert(0, str(path))
from comparison_common import COLLECTIONS, baseline_transport
from sapi import Codec,KeyRecord,SapiError
from sapi_application import Application
from sapi_application.server import valid_transport
import sapi.egress as egress

MAX_BODY=8192
MAX_PATH=2048
KNOWN_MEDIA={'','application/json','application/sapi+jwe','application/xml','text/xml'}
DDL='''
CREATE TABLE IF NOT EXISTS input_observations (request_id TEXT PRIMARY KEY, observed_utc TEXT NOT NULL, ingested_utc TEXT NOT NULL, path_class TEXT NOT NULL, method_class TEXT NOT NULL, media_class TEXT NOT NULL, size_bucket TEXT NOT NULL, original_status INTEGER NOT NULL, body_relation TEXT NOT NULL, body_persisted INTEGER NOT NULL, auth_presence TEXT NOT NULL, provenance TEXT NOT NULL, duplicate_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS in_memory_results (request_id TEXT NOT NULL, variant TEXT NOT NULL, result TEXT NOT NULL, inferred_stage TEXT NOT NULL, http_status INTEGER, gateway_calls INTEGER NOT NULL, business_attempts INTEGER NOT NULL, business_state_changed INTEGER NOT NULL, state_before_digest TEXT NOT NULL, state_after_digest TEXT NOT NULL, outbound_observation TEXT NOT NULL, provenance TEXT NOT NULL, limitation TEXT NOT NULL, PRIMARY KEY(request_id,variant), FOREIGN KEY(request_id) REFERENCES input_observations(request_id));
'''


def path_class(path):
    path=path.split('?',1)[0]
    if path=='/.env': return 'dotenv'
    if path=='/config.bak': return 'config_backup'
    if path.startswith('/wp-admin/'): return 'wordpress'
    return {'/':'root','/api':'api','/soap':'soap','/xml':'xml','/sapi':'sapi'}.get(path,'orders' if path.startswith('/orders/') else 'other')


def size_bucket(size):
    return 'zero' if not size else 'small' if size<=1024 else 'medium' if size<=65536 else 'large'


def valid_id(value):
    if not isinstance(value,str): return False
    try: result=uuid.UUID(value)
    except (ValueError,AttributeError): return False
    return result.version==4 and str(result)==value


def evaluate(request,db_path):
    """The caller supplies trusted request ID/status and an unmodified bytes object.

    No Authorization value is accepted; a boolean only indicates whether one existed.
    A request exceeding a limit or having unknown media is recorded unsupported.
    """
    fields={'request_id','observed_utc','body_relation','method','path','content_type','content_lengths','transfer_present','encoding_present','authorization_present','body','original_status'}
    if type(request) is not dict or set(request)!=fields or not valid_id(request['request_id']): raise ValueError('invalid envelope')
    observed=request['observed_utc']
    if not isinstance(observed,str) or len(observed)!=24 or not observed.endswith('Z'): raise ValueError('invalid observation timestamp')
    try: datetime.datetime.strptime(observed,'%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError: raise ValueError('invalid observation timestamp') from None
    if request['body_relation'] not in ('original','masked','transformed','unknown'): raise ValueError('invalid body relation')
    method,path,media,body=request['method'],request['path'],request['content_type'],request['body']
    if type(method) is not str or len(method)>16 or type(path) is not str or len(path)>MAX_PATH or not path.startswith('/') or path.startswith('//') or type(media) is not str or len(media)>128 or type(body) is not bytes: raise ValueError('invalid bounded input')
    if type(request['original_status']) is not int or not 100<=request['original_status']<=599 or any(type(request[k]) is not bool for k in ('transfer_present','encoding_present','authorization_present')): raise ValueError('invalid metadata')
    sizes=request['content_lengths']
    if type(sizes) is not list or len(sizes)>2 or any(type(x) is not str or len(x)>8 or not x.isascii() or not x.isdigit() for x in sizes): raise ValueError('invalid length metadata')
    status='too_large' if len(body)>MAX_BODY else 'unknown_media' if media not in KNOWN_MEDIA else 'unknown_method' if method not in ('GET','POST') else None
    # Ambiguous or incomplete content is never interpreted as a complete original body.
    if status is None and len(sizes)==1 and int(sizes[0])!=len(body): status='incomplete_or_mismatched_body'
    classification=path_class(path); media_class={'':'none','application/json':'json','application/sapi+jwe':'sapi','application/xml':'xml','text/xml':'xml'}.get(media,'other')
    db_path=Path(db_path);db_path.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(db_path)) as db:
        db.executescript(DDL);db.execute('PRAGMA foreign_keys=ON');db.execute('BEGIN IMMEDIATE')
        try:
            if db.execute('SELECT 1 FROM input_observations WHERE request_id=?',(request['request_id'],)).fetchone():
                db.execute('UPDATE input_observations SET duplicate_count=duplicate_count+1 WHERE request_id=?',(request['request_id'],)); db.commit(); return 'duplicate_unverified'
            db.execute('INSERT INTO input_observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(request['request_id'],observed,datetime.datetime.now(datetime.timezone.utc).isoformat(),classification,method if method in ('GET','POST') else 'OTHER',media_class,size_bucket(len(body)),request['original_status'],request['body_relation']+'_memory_only',0,'present' if request['authorization_present'] else 'absent','source_request_metadata',0))
            with closing(sqlite3.connect(':memory:')) as sentinel:
                sentinel.execute('CREATE TABLE dummy_records (id TEXT PRIMARY KEY, version INTEGER)')
                sentinel.execute("INSERT INTO dummy_records VALUES ('fixture',1)")
                sentinel.commit()
                def state_digest():
                    rows=sentinel.execute('SELECT id,version FROM dummy_records ORDER BY id').fetchall()
                    return hashlib.sha256(repr(rows).encode('ascii')).hexdigest()
                for variant in ('baseline','baseline_replay','sapi'):
                    before=state_digest(); gateway=business=0; changed=False; http_status=None
                    if status:
                        result='unsupported'; stage='not_evaluated'; limitation=status
                    elif method=='GET':
                        http_status=501 if variant=='sapi' else 404;result='method_or_route_rejected';stage='transport';limitation='method/route gate only'
                    elif variant!='sapi':
                        valid=baseline_transport(path,sizes,[media] if media else [],'present' if request['transfer_present'] else None,'present' if request['encoding_present'] else None)
                        if not valid: result='transport_rejected';stage='transport';http_status=400;limitation='pre-auth transport gate only'
                        elif request['authorization_present']: result='not_measured';stage='authentication';limitation='credential not collected or validated'
                        else: result='credential_absent';stage='authentication';http_status=401;limitation='authenticated business behavior not measured'
                    else:
                        valid=valid_transport(path,sizes,[media] if media else [],'present' if request['transfer_present'] else None,'present' if request['encoding_present'] else None)
                        if not valid: result='transport_rejected';stage='transport';http_status=400;limitation='pre-auth transport gate only; XML not parsed'
                        else:
                            # Credentials are generated only in this process. Business handlers are disabled
                            # before invocation, so input cannot be written into the sentinel database.
                            calls={'business':0}
                            class BlockedRecords:
                                def get(self,*a,**kw): calls['business']+=1; raise SapiError('forbidden')
                                def mutate(self,*a,**kw): calls['business']+=1; raise SapiError('forbidden')
                            codec=Codec('demo',{'isolated':KeyRecord(secrets.token_bytes(32),'test',frozenset({'orders_read','orders_write'}))})
                            app=Application(codec,None,BlockedRecords(),COLLECTIONS)
                            gateway=1
                            try:
                                # Block all Python socket creation and SAPi egress for the isolated call.
                                with patch.object(socket,'socket',side_effect=RuntimeError('network disabled')),patch.object(egress,'_connect',side_effect=RuntimeError('network disabled')):
                                    response=app.handle(body.decode('ascii',errors='strict'))
                                codec.open(response,'res')
                                result='response_under_test_key';stage='message_authentication';http_status=200
                            except (SapiError,UnicodeDecodeError):
                                result='wire_rejected_under_test_keys';stage='message_or_authentication';http_status=400
                            except Exception:
                                result='not_measured';stage='evaluation_error';http_status=None
                            business=calls['business'];limitation='isolated ephemeral test key; production key validity not measured; business handler disabled'
                    after=state_digest(); changed=before!=after
                    db.execute('INSERT INTO in_memory_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(request['request_id'],variant,result,stage,http_status,gateway,business,int(changed),before,after,'python_socket_blocked_during_sapi_call; OS-wide not measured' if gateway else 'not_measured','isolated_supplied_bytes_memory_only',limitation+'; Origin, metadata limits, peer limits and timeouts not measured; in-memory sentinel only, production DB not measured'))
            db.commit();return 'recorded'
        except BaseException: db.rollback(); raise
