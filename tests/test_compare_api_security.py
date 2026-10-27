"""Independent failure and persistence checks for the local comparison harness."""
import importlib.util
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('comparison',ROOT/'tools/compare_api_security.py')
comparison=importlib.util.module_from_spec(spec); spec.loader.exec_module(comparison)

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

if __name__=='__main__': unittest.main()
