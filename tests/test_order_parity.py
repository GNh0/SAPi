from contextlib import closing
import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
spec=importlib.util.spec_from_file_location('parity',ROOT/'tools/verify_order_parity.py');parity=importlib.util.module_from_spec(spec);spec.loader.exec_module(parity)

class ParityTests(unittest.TestCase):
    def test_failure_on_blocked_normal_operation(self):
        original=parity.exchange
        def negative(server,method,path,body=b'',headers=None):
            if path=='/orders/get': return 403,b'{"ok":false,"error":"forbidden"}'
            return original(server,method,path,body,headers)
        with tempfile.TemporaryDirectory() as temp, patch.object(parity,'exchange',side_effect=negative):
            path=Path(temp)/'parity.sqlite';run=parity.run(path);result=parity.report(path,run)
            self.assertFalse(result['all_pass'])
            self.assertFalse(next(x for x in result['features'] if x['feature']=='get')['pass'])
    def test_completeness_detects_missing_variant(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'parity.sqlite';run=parity.run(path);self.assertTrue(parity.report(path,run)['all_pass'])
            with closing(sqlite3.connect(path)) as db:
                db.execute("DELETE FROM parity_results WHERE feature='update' AND variant='sapi'");db.commit()
            self.assertFalse(parity.report(path,run)['all_pass'])

if __name__=='__main__': unittest.main()
