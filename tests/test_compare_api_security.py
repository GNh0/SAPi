"""Independent failure and persistence checks for the local comparison harness."""
import importlib.util
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import json
import uuid

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('comparison',ROOT/'tools/compare_api_security.py')
comparison=importlib.util.module_from_spec(spec); spec.loader.exec_module(comparison)
from comparison_common import reconcile_create

class ComparisonTests(unittest.TestCase):
    def test_requery_and_detect_tampered_observation(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'result.sqlite'
            run=comparison.execute(path,1)
            result=comparison.report(path,run)
            self.assertTrue(result['all_pass'])
            self.assertEqual(result['observations'],len(comparison.FIXTURES)*3)
            tamper=next(c for c in result['cases'] if c['case']=='tampered_message')
            self.assertIsNone(tamper['all_pass'])
            self.assertTrue(all(r['verdict']=='not_measured' for r in tamper['examples'] if r['variant']!='sapi'))
            with closing(sqlite3.connect(path)) as db:
                rows=db.execute('SELECT correlation_id, COUNT(DISTINCT variant) FROM observations GROUP BY correlation_id').fetchall()
                self.assertEqual(len(rows),len(comparison.FIXTURES))
                self.assertTrue(all(n==3 for _,n in rows))
                db.execute("UPDATE observations SET result='unexpected_success', verdict='pass' WHERE case_id='missing_scope' AND variant='baseline'")
                db.commit()
            result=comparison.report(path,run)
            self.assertFalse(result['all_pass'])
            self.assertEqual(next(c for c in result['cases'] if c['case']=='missing_scope')['classification'],'not_verified')
            with closing(sqlite3.connect(path)) as db:
                db.execute("UPDATE observations SET variant='unknown' WHERE case_id='raw_probe' AND variant='baseline_replay'"); db.commit()
            result=comparison.report(path,run)
            self.assertFalse(next(c for c in result['cases'] if c['case']=='raw_probe')['all_pass'])
    def test_failed_action_is_not_reported_as_pass(self):
        original=comparison.action
        def mutated(case,kind,codec,tokens,server,repeat):
            if case=='missing_scope' and kind=='baseline': return 'unexpected_success',200,repeat
            return original(case,kind,codec,tokens,server,repeat)
        with tempfile.TemporaryDirectory() as temp, patch.object(comparison,'action',side_effect=mutated):
            path=Path(temp)/'result.sqlite'; run=comparison.execute(path,1)
            result=comparison.report(path,run)
            self.assertFalse(result['all_pass'])
            self.assertFalse(next(c for c in result['cases'] if c['case']=='missing_scope')['all_pass'])
    def test_replay_baseline_enforces_authentication_and_request_id(self):
        import json
        with tempfile.TemporaryDirectory() as temp:
            records,codec,tokens,counts,server,thread=comparison.start_variant('baseline_replay',Path(temp))
            try:
                body=json.dumps({'id':'foreign'}).encode()
                headers={'Content-Type':'application/json','Authorization':'Bearer '+tokens['writer'],'X-Request-ID':'a'*32}
                self.assertEqual(comparison.exchange(server,'POST','/orders/get',body,{'Content-Type':'application/json'})[0],401)
                status,wire=comparison.exchange(server,'POST','/orders/get',body,headers)
                self.assertEqual(status,200); self.assertEqual(json.loads(wire)['data'],{'found':False,'records':[]})
                status,wire=comparison.exchange(server,'POST','/orders/get',body,headers)
                self.assertEqual(status,409); self.assertEqual(json.loads(wire)['error'],'replay')
                headers['X-Request-ID']='b'*32
                self.assertEqual(comparison.exchange(server,'POST','/orders/get',body,headers)[0],200)
                headers['X-Request-ID']='bad'
                self.assertEqual(comparison.exchange(server,'POST','/orders/get',body,headers)[0],400)
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_missing_report_does_not_create_database(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'missing.sqlite'
            with self.assertRaises(ValueError): comparison.report(path)
            self.assertFalse(path.exists())

    def test_shared_subject_mixed_replay_budget_and_valid_request(self):
        for variant in ('baseline_replay','sapi'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp:
                records,codec,tokens,counts,server,thread=comparison.start_variant(variant,Path(temp))
                try:
                    if variant=='sapi':
                        request=codec.request('writer','orders_get',{'id':'missing'})
                        def send():
                            status,wire=comparison.exchange(server,'POST','/sapi',request.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                            return status,codec.open(wire.decode(),'res')[1]
                        self.assertTrue(send()[1]['ok'])
                        for _ in range(59): self.assertEqual(send()[1]['error'],'replay')
                        other=codec.request('writer2','orders_get',{'id':'missing'})
                        status,wire=comparison.exchange(server,'POST','/sapi',other.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                        self.assertEqual(status,200);self.assertEqual(codec.accept_response(other,wire.decode())['error'],'rate_limited')
                    else:
                        body=json.dumps({'id':'missing'}).encode()
                        headers={'Content-Type':'application/json','Authorization':'Bearer '+tokens['writer'],'X-Request-ID':'a'*32}
                        def send():
                            status,wire=comparison.exchange(server,'POST','/orders/get',body,headers);return status,json.loads(wire)
                        self.assertTrue(send()[1]['ok'])
                        for _ in range(59): self.assertEqual(send()[1]['error'],'replay')
                        headers.update(Authorization='Bearer '+tokens['writer2'],**{'X-Request-ID':'b'*32})
                        status,response=send();self.assertEqual(status,429);self.assertEqual(response['error'],'rate_limited')
                    self.assertEqual(counts['business'],1)
                finally:
                    server.shutdown();server.server_close();thread.join(timeout=3)

    def test_baseline_subject_and_operation_windows_have_fixed_boundaries(self):
        quota=comparison.BaselineQuota()
        for i in range(60):
            self.assertTrue(quota.admit('alice','read' if i%2 else 'write',100))
        self.assertFalse(quota.admit('alice','read',159))
        self.assertTrue(quota.admit('bob','read',159))
        self.assertTrue(quota.admit('alice','read',160))
        limited=comparison.BaselineQuota()
        for _ in range(10): self.assertTrue(limited.admit('alice','fetch',200,10,60))
        self.assertFalse(limited.admit('alice','fetch',200,10,60))
        self.assertTrue(limited.admit('alice','read',200))

    def test_split_budget_preserves_normal_request_but_limits_total_cost(self):
        for variant in ('baseline_replay','sapi'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as temp:
                records,codec,tokens,counts,server,thread=comparison.start_variant(variant,Path(temp),split_budget=True)
                try:
                    if variant=='sapi':
                        first=codec.request('writer','orders_get',{'id':'missing'})
                        def send(ctx):
                            status,wire=comparison.exchange(server,'POST','/sapi',ctx.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                            self.assertEqual(status,200);return codec.open(wire.decode(),'res')[1]
                        fresh=lambda:codec.request('writer2','orders_get',{'id':'missing'})
                    else:
                        body=json.dumps({'id':'missing'}).encode()
                        first={'Content-Type':'application/json','Authorization':'Bearer '+tokens['writer'],'X-Request-ID':'a'*32}
                        def send(headers):
                            status,wire=comparison.exchange(server,'POST','/orders/get',body,headers)
                            self.assertIn(status,(200,409,429));return json.loads(wire)
                        fresh=lambda:{'Content-Type':'application/json','Authorization':'Bearer '+tokens['writer2'],'X-Request-ID':uuid.uuid4().hex}
                    self.assertTrue(send(first)['ok'])
                    for _ in range(59):self.assertEqual(send(first)['error'],'replay')
                    self.assertTrue(send(fresh())['ok'])
                    for _ in range(59):self.assertEqual(send(first)['error'],'replay')
                    self.assertEqual(send(fresh())['error'],'rate_limited')
                    self.assertEqual(counts['business'],2)
                finally: server.shutdown();server.server_close();thread.join(timeout=3)

    def test_unexpected_handler_failure_is_semantically_internal_error(self):
        for variant in ('baseline','baseline_replay','sapi'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp, patch.object(comparison.Records,'get',side_effect=RuntimeError('private failure')):
                records,codec,tokens,counts,server,thread=comparison.start_variant(variant,Path(temp))
                try:
                    if variant=='sapi':
                        request=codec.request('writer','orders_get',{'id':'missing'})
                        status,wire=comparison.exchange(server,'POST','/sapi',request.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                        response=codec.accept_response(request,wire.decode());self.assertEqual(status,200)
                    else:
                        headers={'Content-Type':'application/json','Authorization':'Bearer '+tokens['writer'],'X-Request-ID':uuid.uuid4().hex}
                        status,wire=comparison.exchange(server,'POST','/orders/get',json.dumps({'id':'missing'}).encode(),headers)
                        response=json.loads(wire);self.assertEqual(status,500)
                    self.assertFalse(response['ok']);self.assertEqual(response['error'],'internal_error');self.assertNotIn('private failure',str(response))
                finally:
                    server.shutdown();server.server_close();thread.join(timeout=3)

    def test_lost_write_response_requires_lookup_not_automatic_retry(self):
        for variant in ('baseline','baseline_replay','sapi'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp:
                records,codec,tokens,counts,server,thread=comparison.start_variant(variant,Path(temp))
                try:
                    data={'id':'own','data':{'description':'fixture','quantity':1}}
                    def invoke(operation,payload):
                        if variant=='sapi':
                            ctx=codec.request('writer','orders_'+operation,payload)
                            status,wire=comparison.exchange(server,'POST','/sapi',ctx.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                            self.assertEqual(status,200);return codec.accept_response(ctx,wire.decode())
                        headers={'Content-Type':'application/json','Authorization':'Bearer '+tokens['writer'],'X-Request-ID':uuid.uuid4().hex}
                        status,wire=comparison.exchange(server,'POST','/orders/'+operation,json.dumps(payload).encode(),headers)
                        self.assertEqual(status,200);return json.loads(wire)
                    first=invoke('create',data);self.assertTrue(first['data']['changed'])
                    second=invoke('create',data);self.assertFalse(second['data']['changed'])
                    lookup=invoke('get',{'id':'own'});self.assertTrue(lookup['data']['found'])
                    self.assertEqual(lookup['data']['records'][0]['data'],data['data']);self.assertEqual(counts['business'],3)
                    self.assertEqual(reconcile_create(lookup,'own',data['data']),'current_matches_request')
                finally:
                    server.shutdown();server.server_close();thread.join(timeout=3)

    def test_reconciliation_never_promotes_missing_or_malformed_state_to_success(self):
        intended={'description':'fixture','quantity':1}
        self.assertEqual(reconcile_create({'ok':True,'data':{'found':False,'records':[]}},'own',None),'unknown')
        self.assertEqual(reconcile_create({'ok':True,'data':{'found':False,'records':[]}},'own',{}),'unknown')
        self.assertEqual(reconcile_create({'ok':True,'data':{'found':False,'records':[]}},'own',{'description':'\ud800','quantity':1}),'unknown')
        self.assertEqual(reconcile_create({'ok':True,'data':{'found':False,'records':[]}},'own',intended),'not_found')
        self.assertEqual(reconcile_create({'ok':True,'data':{'found':True,'records':[{'id':'own','version':1,'phase':'created','data':{'description':'other','quantity':1}}]}},'own',intended),'current_differs')
        # Invalid orders data is unknown, even if Python considers True equal to 1.
        self.assertEqual(reconcile_create({'ok':True,'data':{'found':True,'records':[{'id':'own','version':1,'phase':'created','data':{'description':'fixture','quantity':True}}]}},'own',intended),'unknown')
        for response in ({}, {'ok':False}, {'ok':True,'data':{'found':False,'records':[{}]}}, {'ok':True,'data':{'found':True,'records':[{'id':'foreign','version':1,'phase':'created','data':intended}]}}):
            self.assertEqual(reconcile_create(response,'own',intended),'unknown')
        for row in ({'id':'own','version':1,'phase':'','data':intended}, {'id':'own','version':9007199254740992,'phase':'created','data':intended}):
            self.assertEqual(reconcile_create({'ok':True,'data':{'found':True,'records':[row]}},'own',intended),'unknown')

if __name__=='__main__': unittest.main()
