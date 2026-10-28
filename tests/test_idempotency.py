"""Opt-in durable receipt contract using actual local SQLite transactions."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
import json
import copy
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
for p in ('tools','sdks/python','services/state','services/application'): sys.path.insert(0,str(ROOT/p))
from sapi import Principal, SapiError
from sapi_application import Records
import compare_api_security as comparison

DATA={'description':'fixture','quantity':1}
ALICE=Principal('alice',frozenset({'orders_read','orders_write'}))
BOB=Principal('bob',frozenset({'orders_read','orders_write'}))

def write(records,principal=ALICE,**changes):
    data={'id':'one','data':DATA,'operation_id':'op1'};data.update(changes)
    return records.mutate('create','demo','orders',principal,data,initial='created',write_phases=['created'],operation_name='orders_create')

class ReceiptTests(unittest.TestCase):
    def test_scope_mismatch_restart_receipt_and_expiry(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
            path=str(Path(temp)/'records.sqlite'); Path(path).touch(); now=[1000]
            records=Records(path,enable_idempotency=True,clock=lambda:now[0])
            first=write(records);self.assertTrue(first['changed'])
            self.assertEqual(write(records),first)
            with self.assertRaises(SapiError) as conflict: write(records,data={'description':'different','quantity':1})
            self.assertEqual(conflict.exception.code,'idempotency_conflict')
            self.assertTrue(write(records,BOB)['changed'])
            restarted=Records(path,enable_idempotency=True,clock=lambda:now[0])
            receipt=restarted.receipt('demo','orders',ALICE,{'operation_id':'op1'})
            self.assertEqual(receipt,{'found':True,'expired':False,**first})
            updated=restarted.mutate('update','demo','orders',ALICE,{'id':'one','version':1,'data':{'description':'later','quantity':2}},initial='created',write_phases=['created'])
            self.assertEqual(updated['records'][0]['version'],2)
            self.assertEqual(restarted.receipt('demo','orders',ALICE,{'operation_id':'op1'}),receipt)
            self.assertEqual(restarted.get('demo','orders',ALICE,{'id':'one'})['records'][0]['version'],2)
            self.assertFalse(restarted.receipt('demo','other',ALICE,{'operation_id':'op1'})['found'])
            now[0]+=86400
            self.assertTrue(restarted.receipt('demo','orders',ALICE,{'operation_id':'op1'})['expired'])
            with self.assertRaises(SapiError) as expired: write(restarted)
            self.assertEqual(expired.exception.code,'idempotency_expired')
            now[0]-=86400
            with self.assertRaises(SapiError) as rollback: restarted.receipt('demo','orders',ALICE,{'operation_id':'op1'})
            self.assertEqual(rollback.exception.code,'idempotency_clock')
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_records').fetchone()[0],2)
                self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_receipts').fetchone()[0],2)

    def test_concurrent_retry_has_one_effect_and_same_receipt(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
            path=str(Path(temp)/'records.sqlite');Path(path).touch();records=Records(path,enable_idempotency=True)
            with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(lambda _:write(records),range(8)))
            self.assertTrue(results[0]['changed']);self.assertTrue(all(r==results[0] for r in results))
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_records').fetchone()[0],1)
                self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_receipts').fetchone()[0],1)

    def test_changed_contract_identifier_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
            path=Path(temp)/'records.sqlite';path.touch();records=Records(str(path),enable_idempotency=True)
            data={'id':'one','data':DATA,'operation_id':'op1'}
            def invoke(contract_id):return records.mutate('create','demo','orders',ALICE,data,initial='created',write_phases=['created'],operation_name='orders_create',contract_id=contract_id)
            self.assertTrue(invoke('a'*64)['changed'])
            with self.assertRaises(SapiError) as conflict:invoke('b'*64)
            self.assertEqual(conflict.exception.code,'idempotency_conflict')

    def test_rollback_does_not_leave_receipt_or_write(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
            path=str(Path(temp)/'records.sqlite');Path(path).touch();records=Records(path,enable_idempotency=True)
            original=records._mutate_tx
            def fail(*args,**kwargs): original(*args,**kwargs);raise RuntimeError('simulated failure')
            with patch.object(records,'_mutate_tx',side_effect=fail):
                with self.assertRaises(RuntimeError): write(records)
            self.assertFalse(records.receipt('demo','orders',ALICE,{'operation_id':'op1'})['found'])
            self.assertTrue(write(records)['changed'])
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_records').fetchone()[0],1)
                self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_receipts').fetchone()[0],1)

    def test_receipt_capacity_fails_closed_before_business_write(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
            path=str(Path(temp)/'records.sqlite');Path(path).touch();records=Records(path,enable_idempotency=True,clock=lambda:1000)
            with closing(sqlite3.connect(path)) as db:
                db.executemany('INSERT INTO sapi_app_receipts VALUES(?,?,?,?,?,?,?)',(('demo','other','k'+str(i),'orders','x',None,1) for i in range(10000)));db.commit()
            with self.assertRaises(SapiError) as failure:write(records)
            self.assertEqual(failure.exception.code,'idempotency_capacity')
            with closing(sqlite3.connect(path)) as db:self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_records').fetchone()[0],0)

    def test_killed_writer_rolls_back_before_receipt_and_retry_succeeds(self):
        script='''\nimport sys,time\nfrom pathlib import Path\nroot=Path(sys.argv[1])\nfor p in ("sdks/python","services/state","services/application"):sys.path.insert(0,str(root/p))\nfrom sapi import Principal\nfrom sapi_application import Records\nr=Records(sys.argv[2],enable_idempotency=True)\noriginal=r._mutate_tx\ndef block(*a,**kw):\n result=original(*a,**kw);Path(sys.argv[3]).write_text("ready");time.sleep(30);return result\nr._mutate_tx=block\nr.mutate("create","demo","orders",Principal("alice",frozenset()),{"id":"one","data":{"description":"fixture","quantity":1},"operation_id":"op1"},initial="created",write_phases=["created"],operation_name="orders_create")\n'''
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
            path=str(Path(temp)/'records.sqlite');Path(path).touch();marker=Path(temp)/'started'
            Records(path,enable_idempotency=True)
            child=subprocess.Popen([sys.executable,'-c',script,str(ROOT),path,str(marker)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                until=time.monotonic()+8
                while not marker.exists() and child.poll() is None and time.monotonic()<until: time.sleep(.02)
                self.assertTrue(marker.exists(),'child did not reach transaction')
                child.kill();child.wait(timeout=5)
            finally:
                if child.poll() is None: child.kill();child.wait(timeout=5)
            records=Records(path,enable_idempotency=True)
            self.assertFalse(records.receipt('demo','orders',ALICE,{'operation_id':'op1'})['found'])
            with closing(sqlite3.connect(path)) as db:self.assertEqual(db.execute('SELECT count(*) FROM sapi_app_records').fetchone()[0],0)
            self.assertTrue(write(records)['changed'])

    def test_legacy_off_and_local_api_sapi_same_receipt(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
            old_path=Path(temp)/'old.sqlite';old_path.touch();old=Records(str(old_path))
            with self.assertRaises(SapiError): write(old)
            with closing(sqlite3.connect(old.db.target)) as db:self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='sapi_app_receipts'").fetchone())
        for variant in ('baseline','baseline_replay','sapi'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
                records,codec,tokens,counts,server,thread=comparison.start_variant(variant,Path(temp),idempotency=True)
                def invoke(operation,payload,kid='writer',ordinary_status=200):
                    if variant=='sapi':
                        ctx=codec.request(kid,'orders_'+operation,payload)
                        status,body=comparison.exchange(server,'POST','/sapi',ctx.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                        self.assertEqual(status,200);return codec.accept_response(ctx,body.decode())
                    h={'Content-Type':'application/json','Authorization':'Bearer '+tokens[kid],'X-Request-ID':uuid.uuid4().hex}
                    status,body=comparison.exchange(server,'POST','/orders/'+operation,json.dumps(payload).encode(),h)
                    self.assertEqual(status,ordinary_status);return json.loads(body)
                try:
                    payload={'id':'own','data':DATA,'operation_id':'receipt1'}
                    first=invoke('create',payload);again=invoke('create',payload,'writer2')
                    self.assertTrue(first['ok']);self.assertEqual(again['data'],first['data']);self.assertTrue(first['data']['changed'])
                    receipt=invoke('receipt',{'operation_id':'receipt1'})
                    self.assertEqual(receipt['data'],{'found':True,'expired':False,**first['data']})
                    denied=invoke('receipt',{'operation_id':'receipt1'},'reader',403)
                    self.assertEqual(denied['error'],'forbidden')
                    wrong=invoke('create',{**payload,'data':{'description':'other','quantity':1}},ordinary_status=409)
                    self.assertEqual(wrong['error'],'idempotency_conflict')
                    with closing(sqlite3.connect(records.db.target)) as db:
                        self.assertEqual(db.execute("SELECT count(*) FROM sapi_app_records WHERE owner='alice'").fetchone()[0],1)
                finally: server.shutdown();server.server_close();thread.join(timeout=3)

    def test_same_transition_rule_under_distinct_declared_operations_conflicts(self):
        collections=copy.deepcopy(comparison.COLLECTIONS)
        collections['orders']['transitions']['approve']=copy.deepcopy(collections['orders']['transitions']['submit'])
        for variant in ('baseline_replay','sapi'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory(dir=ROOT.parent/'evidence'/'local-runs') as temp:
                records,codec,tokens,counts,server,thread=comparison.start_variant(variant,Path(temp),idempotency=True,collections=collections)
                def call(op,payload,expected_status):
                    if variant=='sapi':
                        ctx=codec.request('writer','orders_'+op,payload)
                        status,body=comparison.exchange(server,'POST','/sapi',ctx.wire.encode(),{'Content-Type':'application/sapi+jwe'})
                        self.assertEqual(status,200);return codec.accept_response(ctx,body.decode())
                    headers={'Content-Type':'application/json','Authorization':'Bearer '+tokens['writer'],'X-Request-ID':uuid.uuid4().hex}
                    status,body=comparison.exchange(server,'POST','/orders/'+op,json.dumps(payload).encode(),headers)
                    self.assertEqual(status,expected_status);return json.loads(body)
                try:
                    self.assertTrue(call('create',{'id':'own','data':DATA},200)['ok'])
                    payload={'id':'own','version':1,'operation_id':'same-key'}
                    first=call('submit',payload,200);self.assertTrue(first['data']['changed'])
                    second=call('approve',payload,409);self.assertEqual(second['error'],'idempotency_conflict')
                    self.assertEqual(call('submit',payload,200)['data'],first['data'])
                    current=call('get',{'id':'own'},200)['data']['records'][0]
                    self.assertEqual((current['phase'],current['version']),('submitted',2))
                finally: server.shutdown();server.server_close();thread.join(timeout=3)

if __name__=='__main__':unittest.main()
