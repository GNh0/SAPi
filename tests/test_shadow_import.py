"""Shadow adapter/import integration, bounds, provenance and idempotence."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import import_shadow_observations as shadow


def batch(events,**overrides):
    counters={'seen':len(events),'sampled_out':0,'queue_dropped':0,'observer_error':0,'emitted':len(events)}
    return {'batch_id':str(uuid.uuid4()),'sample_percent':100,'overflow':False,'counters':counters,'events':events,**overrides}


def event(path='dotenv',media='none',method='GET'):
    return {'request_id':str(uuid.uuid4()),'observed_utc':'2026-01-01T00:00:00.000Z','path_class':path,'method':method,'media_class':media,'size_bucket':'zero','original_status':404}


class ShadowTests(unittest.TestCase):
    def test_adapter_to_import_and_fail_open(self):
        script='''
import { createShadowBuffer, handleWithShadow } from './examples/shadow/adapter.mjs';
const buffer=createShadowBuffer({samplePercent:100,capacity:2});
const response = new Response('ok',{status:200});
await handleWithShadow(new Request('http://localhost/.env?token=secret'),async()=>response,buffer);
await handleWithShadow(new Request('http://localhost/sensitive-trace'),async()=>response,buffer);
await handleWithShadow(new Request('http://localhost/.env'),async()=>response,buffer);
const actual=await handleWithShadow(new Request('http://localhost/'),async()=>response,{observe(){throw Error('fail')}});
if (actual !== response) throw Error('response changed');
console.log(JSON.stringify(buffer.drain()));
'''
        result=subprocess.run(['node','--input-type=module','-e',script],cwd=ROOT,text=True,capture_output=True,check=True,timeout=10)
        self.assertNotIn('secret',result.stdout); self.assertNotIn('sensitive-trace',result.stdout); self.assertNotIn('localhost',result.stdout)
        value=json.loads(result.stdout); shadow.validate(value)
        self.assertEqual(value['counters']['queue_dropped'],1)
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'shadow.sqlite'; imported=shadow.import_batch(value,db)
            self.assertEqual((imported['mapped'],imported['unsupported']),(1,1))
            self.assertEqual(shadow.import_batch(value,db)['status'],'duplicate_batch')
            report=shadow.report(db); self.assertEqual((report['mapped'],report['unsupported'],report['queue_dropped']),(1,1,1)); self.assertEqual(report['failed_results'],0)
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute('SELECT count(*) FROM shadow_results').fetchone()[0],3)
                self.assertEqual(conn.execute('SELECT DISTINCT experiment_provenance FROM shadow_results').fetchone()[0],'local_reconstructed_fixture')
                self.assertEqual(conn.execute('SELECT DISTINCT observation_provenance FROM shadow_events').fetchone()[0],'site_feature_observation')
    def test_duplicate_identity_and_conflicting_batch(self):
        first=event(); value=batch([first])
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'shadow.sqlite'; shadow.import_batch(value,db)
            duplicate=batch([first]); self.assertEqual(shadow.import_batch(duplicate,db)['duplicates'],1)
            conflict=dict(first,original_status=200)
            with self.assertRaises(ValueError): shadow.import_batch(batch([conflict]),db)
            altered=dict(value,events=[conflict])
            with self.assertRaises(ValueError): shadow.import_batch(altered,db)
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute('SELECT count(*) FROM shadow_events').fetchone()[0],1)
                self.assertEqual(conn.execute('SELECT count(*) FROM shadow_results').fetchone()[0],3)
    def test_rejects_untrusted_fields_malformed_counters_and_sizes(self):
        item=event(); item['payload']='not allowed'
        with self.assertRaises(ValueError): shadow.validate(batch([item]))
        value=batch([event()]); value['counters']['seen']=999
        with self.assertRaises(ValueError): shadow.validate(value)
        with self.assertRaises(ValueError): shadow.validate(batch([event() for _ in range(65)]))
        value=batch([event()]); value['events'][0]['method']={'bad':1}
        with self.assertRaises(ValueError): shadow.validate(value)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'large.json';path.write_bytes(b'x'*(shadow.MAX_BYTES+1))
            with self.assertRaises(ValueError): shadow.load_batch(path)
            path.write_bytes(b'{"batch_id":1,"batch_id":2}')
            with self.assertRaises(ValueError): shadow.load_batch(path)

if __name__=='__main__': unittest.main()
