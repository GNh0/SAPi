"""Shadow DB version, legacy migration and fail-closed schema checks."""
from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import evaluate_shadow_memory as memory
import import_shadow_observations as importer
from migrate_shadow_evidence import migrate


def request():
    return {'request_id':str(uuid.uuid4()),'observed_utc':'2026-01-01T00:00:00.000Z','body_relation':'unknown','method':'POST','path':'/sapi','content_type':'application/xml','content_lengths':['1'],'transfer_present':False,'encoding_present':False,'authorization_present':False,'body':b'x','original_status':400}


def batch():
    return {'batch_id':str(uuid.uuid4()),'sample_percent':100,'overflow':False,'counters':{'seen':0,'sampled_out':0,'queue_dropped':0,'observer_error':0,'emitted':0},'events':[]}


class ShadowSchemaTests(unittest.TestCase):
    def test_new_version_and_migrate_copy(self):
        for kind in ('memory','import'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                old=Path(temp)/'old.sqlite'; new=Path(temp)/'new.sqlite'
                if kind=='memory': memory.evaluate(request(),old)
                else: importer.import_batch(batch(),old)
                with closing(sqlite3.connect(old)) as db:
                    self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],1)
                    db.execute('PRAGMA application_id=0'); db.execute('PRAGMA user_version=0'); db.commit()
                original=old.read_bytes(); migrate(old,new,kind)
                self.assertEqual(old.read_bytes(),original)
                with closing(sqlite3.connect(new)) as db: self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],1)
                if kind=='memory': self.assertEqual(memory.evaluate(request(),new),'recorded')
                else: self.assertEqual(importer.report(new)['batches'],1)

    def test_rejects_legacy_wrong_kind_and_modified_schema_without_write(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'in.sqlite'; out=Path(temp)/'out.sqlite'
            memory.evaluate(request(),path)
            with self.assertRaises(ValueError): importer.import_batch(batch(),path)
            with self.assertRaises(ValueError): migrate(path,out,'memory')
            self.assertFalse(out.exists())
            with closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA application_id=0'); db.execute('PRAGMA user_version=0')
                db.execute('CREATE TABLE unexpected(x)'); db.commit()
            before=path.read_bytes()
            with self.assertRaises(ValueError): migrate(path,out,'memory')
            with self.assertRaises(ValueError): memory.evaluate(request(),path)
            self.assertFalse(out.exists()); self.assertEqual(path.read_bytes(),before)

    def test_rejects_wrong_legacy_column_and_missing_foreign_key(self):
        changes=[memory.DDL.replace('original_status INTEGER NOT NULL','original_status TEXT NOT NULL'),
                 memory.DDL.replace(', FOREIGN KEY(request_id) REFERENCES input_observations(request_id)','')]
        for ddl in changes:
            with self.subTest(ddl=ddl), tempfile.TemporaryDirectory() as temp:
                old=Path(temp)/'old.sqlite'; dest=Path(temp)/'new.sqlite'
                with closing(sqlite3.connect(old)) as db: db.executescript(ddl)
                before=old.read_bytes()
                with self.assertRaises(ValueError): migrate(old,dest,'memory')
                self.assertFalse(dest.exists()); self.assertEqual(old.read_bytes(),before)

if __name__=='__main__': unittest.main()
