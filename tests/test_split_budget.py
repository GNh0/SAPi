"""Split-budget opt-in contract; legacy defaults remain unchanged."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'sdks/python'))
from sapi import Codec, KeyRecord, SecureServer, SplitBudgetMemoryReplayStore, MemoryReplayStore, SapiError

SCHEMA={'type':'object','properties':{'value':{'type':'string','maxBytes':8}}}

class SplitBudgetTests(unittest.TestCase):
    def setup_server(self,store,split=False):
        keys={'one':KeyRecord(b'a'*32,'alice',frozenset({'write'})), 'two':KeyRecord(b'b'*32,'alice',frozenset({'write'}))}
        codec=Codec('demo',keys,clock=lambda:1000)
        calls=[]
        server=SecureServer(codec,store,split_budget=split)
        server.register('put','write',SCHEMA,SCHEMA,lambda p,d:True,lambda p,d:(calls.append(d['value']) or d))
        def invoke(context): return codec.open(server.handle(context.wire),'res')[1]
        return codec,invoke,calls

    def test_replays_do_not_spend_business_budget_but_cost_remains_bounded(self):
        codec,invoke,calls=self.setup_server(SplitBudgetMemoryReplayStore(),split=True)
        first=codec.request('one','put',{'value':'one'})
        self.assertTrue(invoke(first)['ok'])
        for _ in range(59): self.assertEqual(invoke(first)['error'],'replay')
        second=codec.request('two','put',{'value':'two'})
        self.assertTrue(invoke(second)['ok'])
        for _ in range(59): self.assertEqual(invoke(first)['error'],'replay')
        self.assertEqual(invoke(codec.request('one','put',{'value':'three'}))['error'],'rate_limited')
        self.assertEqual(calls,['one','two'])

    def test_fresh_business_budget_and_invalid_input_are_distinct(self):
        codec,invoke,calls=self.setup_server(SplitBudgetMemoryReplayStore(cost_limit=120),split=True)
        for _ in range(20): self.assertEqual(invoke(codec.request('one','put',{'value':1}))['error'],'invalid_input')
        for _ in range(60): self.assertTrue(invoke(codec.request('two','put',{'value':'ok'}))['ok'])
        self.assertEqual(invoke(codec.request('one','put',{'value':'ok'}))['error'],'rate_limited')
        self.assertEqual(len(calls),60)

    def test_concurrent_identical_wire_executes_once(self):
        codec,invoke,calls=self.setup_server(SplitBudgetMemoryReplayStore(),split=True)
        context=codec.request('one','put',{'value':'once'})
        with ThreadPoolExecutor(max_workers=12) as pool:
            results=list(pool.map(lambda _:invoke(context),range(20)))
        self.assertEqual(sum(r['ok'] for r in results),1)
        self.assertEqual(sum(r.get('error')=='replay' for r in results),19)
        self.assertEqual(calls,['once'])

    def test_default_store_preserves_existing_budget_order(self):
        codec,invoke,calls=self.setup_server(MemoryReplayStore())
        first=codec.request('one','put',{'value':'one'})
        self.assertTrue(invoke(first)['ok'])
        for _ in range(59): self.assertEqual(invoke(first)['error'],'replay')
        self.assertEqual(invoke(codec.request('two','put',{'value':'two'}))['error'],'rate_limited')
        self.assertEqual(calls,['one'])

    def test_cost_window_capacity_and_backend_failure_are_fail_closed(self):
        store=SplitBudgetMemoryReplayStore(capacity=1,cost_limit=2,cost_period=60)
        self.assertEqual(store.claim_bounded('demo','alice','a',1100,1000),'accepted')
        self.assertEqual(store.claim_bounded('demo','alice','a',1100,1000),'replay')
        self.assertEqual(store.claim_bounded('demo','alice','b',1100,1000),'rate_limited')
        self.assertEqual(store.claim_bounded('demo','alice','a',1100,1060),'replay')
        with self.assertRaises(SapiError) as failure: store.claim_bounded('demo','bob','b',1100,1060)
        self.assertEqual(failure.exception.code,'rate_capacity')
        class Broken(MemoryReplayStore):
            def claim_bounded(self,*args): return None
        codec,invoke,calls=self.setup_server(Broken(),split=True)
        self.assertEqual(invoke(codec.request('one','put',{'value':'no'}))['error'],'internal_error')
        self.assertEqual(calls,[])
        codec,invoke,calls=self.setup_server(Broken())
        self.assertTrue(invoke(codec.request('one','put',{'value':'yes'}))['ok'])
        self.assertEqual(calls,['yes'])
        with self.assertRaises(ValueError): SecureServer(codec,MemoryReplayStore(),split_budget=True)

if __name__=='__main__': unittest.main()
