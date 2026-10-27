"""Crash, migration, oracle and redacted diagnostic controls."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import compare_api_security as comparison
import verify_order_parity as parity
from migrate_evidence import migrate


class LifecycleTests(unittest.TestCase):
    def test_forced_process_exit_preserves_partial_results(self):
        for module, function, table in [('compare_api_security','action','observations'),('verify_order_parity','exchange','parity_results')]:
            with self.subTest(module=module), tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'result.sqlite'
                script=("import os,sys; sys.path.insert(0,'tools'); import "+module+" as m\n"
                        "original=m."+function+"; calls=0\n"
                        "def stop(*a,**kw):\n global calls\n calls+=1\n if calls==2: os._exit(73)\n return original(*a,**kw)\n"
                        "m."+function+"=stop\n"
                        + ("m.execute(__import__('pathlib').Path(sys.argv[1]),1)" if module=='compare_api_security' else "m.run(__import__('pathlib').Path(sys.argv[1]))"))
                proc=subprocess.run([sys.executable,'-c',script,str(path)],cwd=ROOT,timeout=30)
                self.assertEqual(proc.returncode,73)
                with closing(sqlite3.connect(path)) as db:
                    self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                    self.assertEqual(db.execute('SELECT count(*) FROM '+table).fetchone()[0],1)
                    run_id=db.execute('SELECT run_id FROM '+table).fetchone()[0]
                result=comparison.report(path,run_id) if module=='compare_api_security' else parity.report(path,run_id)
                self.assertEqual(result['status'],'running'); self.assertFalse(result['all_pass'])

    def test_independent_oracle_rejects_matching_wrong_states(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'p.sqlite'; run=parity.run(path)
            with closing(sqlite3.connect(path)) as db:
                db.execute("UPDATE parity_results SET after_digest=? WHERE feature='update'",('0'*64,)); db.commit()
            self.assertFalse(next(x for x in parity.report(path,run)['features'] if x['feature']=='update')['pass'])

    def test_failure_reason_has_no_exception_text(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(parity,'exchange',side_effect=ValueError('secret-fixture-marker')):
            path=Path(temp)/'p.sqlite'; run=parity.run(path)
            with closing(sqlite3.connect(path)) as db:
                reason=db.execute("SELECT failure_reason FROM parity_results WHERE variant='baseline' LIMIT 1").fetchone()[0]
                self.assertEqual(reason,'invalid_response_or_input')
            self.assertNotIn(b'secret-fixture-marker',path.read_bytes())
            self.assertFalse(parity.report(path,run)['all_pass'])

    def test_migrate_legacy_copy_preserves_original_and_does_not_certify(self):
        with tempfile.TemporaryDirectory() as temp:
            original=Path(temp)/'old.sqlite'; dest=Path(temp)/'new.sqlite'
            with closing(sqlite3.connect(original)) as db:
                db.execute('CREATE TABLE parity_results (run_id TEXT, step_index INTEGER, feature TEXT, variant TEXT, expected_outcome TEXT, observed_outcome TEXT, before_digest TEXT, after_digest TEXT, expected_change INTEGER, db_changed INTEGER, handler_calls INTEGER, verdict TEXT, provenance TEXT, PRIMARY KEY(run_id,step_index,variant))')
                db.execute("INSERT INTO parity_results VALUES ('old',0,'missing_get','baseline','matches_expected','matches_expected','x','x',0,0,1,'pass','synthetic_feature_parity')"); db.commit()
            before=original.read_bytes(); migrate(original,dest,'parity'); self.assertEqual(before,original.read_bytes())
            self.assertEqual(parity.report(dest,'old')['status'],'legacy_unverified')
            self.assertFalse(parity.report(dest,'old')['all_pass'])
            with self.assertRaises(ValueError): migrate(original,dest,'parity')

    def test_migrate_comparison_copy_is_unverified(self):
        with tempfile.TemporaryDirectory() as temp:
            original=Path(temp)/'old.sqlite'; dest=Path(temp)/'new.sqlite'
            with closing(sqlite3.connect(original)) as db:
                db.executescript(comparison.DDL.replace(', status TEXT NOT NULL',''))
                db.execute("INSERT INTO runs VALUES ('old','2026-01-01',1,'{}','legacy')"); db.commit()
            before=original.read_bytes(); migrate(original,dest,'comparison')
            self.assertEqual(before,original.read_bytes())
            result=comparison.report(dest,'old')
            self.assertEqual(result['status'],'legacy_unverified'); self.assertFalse(result['all_pass'])

    def test_rejects_wrong_columns_types_or_constraints_without_output(self):
        schemas=["CREATE TABLE runs(x); CREATE TABLE observations(x);",
                 comparison.DDL.replace(', status TEXT NOT NULL','').replace('repetitions INTEGER NOT NULL','repetitions TEXT NOT NULL'),
                 comparison.DDL.replace(', status TEXT NOT NULL','').replace('PRIMARY KEY(run_id,repetition,case_id,variant)', 'PRIMARY KEY(run_id,repetition,case_id)')]
        for schema in schemas:
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as temp:
                original=Path(temp)/'old.sqlite'; dest=Path(temp)/'new.sqlite'
                with closing(sqlite3.connect(original)) as db: db.executescript(schema)
                before=original.read_bytes()
                with self.assertRaises(ValueError): migrate(original,dest,'comparison')
                self.assertFalse(dest.exists()); self.assertEqual(before,original.read_bytes())

    def test_rejects_unrecognized_parity_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            original=Path(temp)/'old.sqlite'; dest=Path(temp)/'new.sqlite'
            with closing(sqlite3.connect(original)) as db: db.execute('CREATE TABLE parity_results(x)')
            before=original.read_bytes()
            with self.assertRaises(ValueError): migrate(original,dest,'parity')
            self.assertFalse(dest.exists()); self.assertEqual(before,original.read_bytes())

if __name__=='__main__': unittest.main()
