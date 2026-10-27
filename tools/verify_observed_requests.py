"""Bounded, loopback-only regression cases inspired by observed request categories."""
import argparse
import datetime
import http.client
import json
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / 'sdks/python', ROOT / 'services/state', ROOT / 'services/application'):
    sys.path.insert(0, str(path))

from sapi import Codec, KeyRecord, Principal
from sapi.constants import MAX_WIRE
import sapi.egress as egress
from sapi_application import Application, Records, make_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='JSON report path (do not use a production directory)')
    args = parser.parse_args()
    cases = []
    with tempfile.TemporaryDirectory(prefix='sapi-regression-') as tmp:
        keys = {'writer': KeyRecord(secrets.token_bytes(32), 'alice', frozenset({'orders_read', 'orders_write'})),
                'reader': KeyRecord(secrets.token_bytes(32), 'alice', frozenset({'orders_read'}))}
        codec = Codec('demo', keys)
        db_path = Path(tmp) / 'records.sqlite'
        db_path.touch()
        records = Records(str(db_path))
        calls = {'gateway': 0, 'business': 0, 'egress_connect': 0}
        class CountedRecords:
            def get(self, *a, **kw):
                calls['business'] += 1
                return records.get(*a, **kw)
            def mutate(self, *a, **kw):
                calls['business'] += 1
                return records.mutate(*a, **kw)
        schema = {'type': 'object', 'properties': {'description': {'type': 'string', 'maxBytes': 256}, 'quantity': {'type': 'integer', 'min': 1, 'max': 1000}}}
        collections = {'orders': {'schema': schema, 'read_scope': 'orders_read', 'write_scope': 'orders_write', 'initial': 'created', 'transitions': {'submit': {'from': 'created', 'to': 'submitted', 'scope': 'orders_write'}, 'complete': {'from': 'submitted', 'to': 'completed', 'scope': 'orders_write'}}}}
        app = Application(codec, None, CountedRecords(), collections)
        class Gateway:
            def handle(self, wire):
                calls['gateway'] += 1
                return app.handle(wire)
        records.mutate('create', 'demo', 'orders', Principal('bob', frozenset()), {'id': 'foreign', 'data': {'description': 'fixture', 'quantity': 1}}, initial='created', write_phases=['created'])
        server = make_server(Gateway(), port=0, peer_requests=100, timeout=2)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def snapshot():
            with records.db.transaction() as tx:
                return [tuple(row) for row in tx.execute('SELECT service,collection,owner,id,version,phase,payload FROM sapi_app_records ORDER BY service,collection,owner,id').fetchall()]
        def exchange(method, path, body=b'', headers=None):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            try:
                conn.request(method, path, body=body, headers=headers or {})
                response = conn.getresponse(); data = response.read()
                return response.status, data
            finally: conn.close()
        def raw(data):
            with socket.create_connection(('127.0.0.1', server.server_port), timeout=3) as sock:
                sock.sendall(data); sock.shutdown(socket.SHUT_WR)
                return sock.recv(1024).split(b'\r\n', 1)[0].decode('ascii', 'replace')
        def send(context):
            status, data = exchange('POST', '/sapi', context.wire.encode('ascii'), {'Content-Type': 'application/sapi+jwe'})
            if status != 200: raise ValueError('unexpected transport response')
            return codec.accept_response(context, data.decode('ascii'))
        def check(name, stage, action, expected, expected_gateway, expected_business, expected_change):
            before, old = snapshot(), calls.copy()
            result = None; error = None
            try: result = action()
            except Exception as exc: error = type(exc).__name__
            after = snapshot()
            # Never serialize unexpected application responses: they may be large or sensitive.
            safe_result = 'matches_expected' if result == expected else 'mismatch'
            observed = {'result': safe_result, 'gateway_calls': calls['gateway']-old['gateway'], 'business_calls': calls['business']-old['business'], 'database_changed': before != after, 'egress_connect_calls': calls['egress_connect']-old['egress_connect']}
            passed = error is None and result == expected and observed['gateway_calls'] == expected_gateway and observed['business_calls'] == expected_business and observed['database_changed'] == expected_change and observed['egress_connect_calls'] == 0
            cases.append({'case': name, 'expected_stage': stage, 'expected_result': expected, 'expected_gateway_calls': expected_gateway, 'expected_business_calls': expected_business, 'expected_database_changed': expected_change, 'expected_egress_connect_calls': 0, 'observed': observed, 'exception': error is not None, 'verdict': 'pass' if passed else 'fail'})
        def forbidden_connect(*a, **kw):
            calls['egress_connect'] += 1
            raise RuntimeError('egress disabled by regression harness')
        try:
            with patch.object(egress, '_connect', side_effect=forbidden_connect):
                for name, method, path in [('env_path', 'GET', '/.env'), ('backup_path', 'GET', '/config.bak'), ('wordpress_path', 'GET', '/wp-admin/'), ('wrong_method', 'GET', '/sapi')]:
                    check(name, 'http_method', lambda m=method,p=path: exchange(m,p)[0], 501, 0, 0, False)
                for path in ('/', '/api', '/soap', '/xml'):
                    check('xml_' + (path.strip('/') or 'root'), 'transport', lambda p=path: exchange('POST', p, b'<fixture/>', {'Content-Type': 'application/xml'})[0], 400, 0, 0, False)
                check('xml_on_endpoint', 'transport', lambda: exchange('POST', '/sapi', b'<fixture/>', {'Content-Type': 'application/xml'})[0], 400, 0, 0, False)
                check('wrong_path_sapi_media', 'transport', lambda: exchange('POST', '/api', b'x', {'Content-Type': 'application/sapi+jwe'})[0], 400, 0, 0, False)
                check('content_encoding', 'transport', lambda: exchange('POST', '/sapi', b'x', {'Content-Type': 'application/sapi+jwe', 'Content-Encoding': 'gzip'})[0], 400, 0, 0, False)
                check('oversized_length', 'transport', lambda: exchange('POST', '/sapi', b'', {'Content-Type':'application/sapi+jwe', 'Content-Length':str(MAX_WIRE+1)})[0], 400, 0, 0, False)
                check('duplicate_length', 'transport', lambda: raw(b'POST /sapi HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/sapi+jwe\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx'), 'HTTP/1.1 400 Bad Request', 0, 0, False)
                check('transfer_encoding', 'transport', lambda: raw(b'POST /sapi HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/sapi+jwe\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx'), 'HTTP/1.1 400 Bad Request', 0, 0, False)
                check('invalid_wire', 'authentication', lambda: exchange('POST','/sapi',b'fixture',{'Content-Type':'application/sapi+jwe'})[0], 400, 1, 0, False)
                def request(kid, op, data): return codec.request(kid, op, data)
                def result(ctx):
                    payload = send(ctx)
                    return payload['data'] if payload['ok'] else payload['error']
                data = {'description':'fixture','quantity':1}
                check('normal_create', 'business', lambda: result(request('writer','orders_create',{'id':'own','data':data})), {'changed':True,'records':[{'id':'own','version':1,'phase':'created','data':data}]}, 1, 1, True)
                check('invalid_schema', 'schema', lambda: result(request('writer','orders_update',{'id':'own','version':1,'data':{'description':'fixture','quantity':'1'}})), 'invalid_input', 1, 0, False)
                check('missing_scope', 'scope', lambda: result(request('reader','orders_delete',{'id':'own','version':1})), 'forbidden', 1, 0, False)
                check('foreign_owner', 'ownership', lambda: result(request('writer','orders_update',{'id':'foreign','version':1,'data':data})), {'changed':False,'records':[]}, 1, 1, False)
                check('invalid_transition', 'workflow', lambda: result(request('writer','orders_complete',{'id':'own','version':1})), 'forbidden', 1, 1, False)
                replay = request('writer','orders_submit',{'id':'own','version':1})
                check('normal_submit', 'business', lambda: result(replay), {'changed':True,'records':[{'id':'own','version':2,'phase':'submitted','data':data}]}, 1, 1, True)
                def replay_again():
                    status, wire = exchange('POST','/sapi',replay.wire.encode('ascii'),{'Content-Type':'application/sapi+jwe'})
                    if status != 200: return 'transport_failure'
                    return codec.open(wire.decode('ascii'), 'res')[1]['error']
                check('replay', 'replay', replay_again, 'replay', 1, 0, False)
                check('post_submit_update', 'workflow', lambda: result(request('writer','orders_update',{'id':'own','version':2,'data':data})), 'forbidden', 1, 1, False)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
    report = {'format_version':1, 'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'environment':'disposable SQLite, in-memory replay and ephemeral keys; loopback HTTP', 'observation_limits':{'result':'comparison to fixed expected response; response content is not recorded', 'gateway_calls':'Application.handle entry, before authentication', 'business_calls':'Records get/mutate entry, not arbitrary handlers', 'database_changed':'full application records table comparison only', 'egress_connect_calls':'SAPi egress _connect only; not OS-wide network monitoring', 'external_resource_read':'not measured; XML is rejected before parsing'}, 'cases':cases, 'passed':sum(c['verdict']=='pass' for c in cases), 'total':len(cases)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=True)+'\n', encoding='utf-8')
    print(json.dumps({'passed':report['passed'], 'total':report['total'], 'failed':[c['case'] for c in cases if c['verdict'] != 'pass']}))
    return 0 if report['passed'] == report['total'] else 1

if __name__ == '__main__': sys.exit(main())
