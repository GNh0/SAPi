"""Memory-only actual-input boundary: no payload retention or network access."""
from contextlib import closing
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import evaluate_shadow_memory as memory


def request(**changes):
    value={'request_id':str(uuid.uuid4()),'observed_utc':'2026-01-01T00:00:00.000Z','body_relation':'original','method':'POST','path':'/sapi','content_type':'application/sapi+jwe','content_lengths':['7'],'transfer_present':False,'encoding_present':False,'authorization_present':False,'body':b'fixture','original_status':400}
    value.update(changes);return value


class MemoryBoundaryTests(unittest.TestCase):
    def test_actual_bytes_memory_only_and_dedup(self):
        raw=b'private-fixture-marker';req=request(path='/sapi?secret-query-marker',content_type='application/xml',body=raw,content_lengths=[str(len(raw))])
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'out.sqlite';self.assertEqual(memory.evaluate(req,db),'recorded');self.assertEqual(memory.evaluate(req,db),'duplicate_unverified')
            with closing(sqlite3.connect(db)) as con:
                self.assertEqual(con.execute('SELECT count(*) FROM input_observations').fetchone()[0],1)
                self.assertEqual(con.execute('SELECT duplicate_count FROM input_observations').fetchone()[0],1)
                self.assertEqual(con.execute('SELECT count(*) FROM in_memory_results').fetchone()[0],3)
                rows=con.execute('SELECT result,body_relation,body_persisted FROM in_memory_results JOIN input_observations USING(request_id)').fetchall()
                self.assertTrue(all(r[0]=='transport_rejected' and r[1]=='original_memory_only' and r[2]==0 for r in rows))
            self.assertNotIn(raw,db.read_bytes());self.assertNotIn(b'secret-query-marker',db.read_bytes())
    def test_unknown_and_oversize_are_unprocessed(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'out.sqlite'; a=request(content_type='application/unknown'); b=request(body=b'x'*8193,content_lengths=['8193'])
            memory.evaluate(a,db);memory.evaluate(b,db)
            with closing(sqlite3.connect(db)) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM in_memory_results WHERE result='unsupported' AND gateway_calls=0").fetchone()[0],6)
    def test_missing_vs_unavailable_credentials_and_sapi_wire(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'out.sqlite'; a=request(path='/orders/get',content_type='application/json',body=b'{}',content_lengths=['2']); b=dict(a,request_id=str(uuid.uuid4()),authorization_present=True); c=request()
            for item in (a,b,c): memory.evaluate(item,db)
            with closing(sqlite3.connect(db)) as con:
                self.assertEqual(con.execute("SELECT result FROM in_memory_results WHERE request_id=? AND variant='baseline'",(a['request_id'],)).fetchone()[0],'credential_absent')
                self.assertEqual(con.execute("SELECT result FROM in_memory_results WHERE request_id=? AND variant='baseline'",(b['request_id'],)).fetchone()[0],'not_measured')
                self.assertEqual(con.execute("SELECT result FROM in_memory_results WHERE request_id=? AND variant='sapi'",(c['request_id'],)).fetchone()[0],'wire_rejected_under_test_keys')
                self.assertTrue(all(row[0]==row[1] and row[2]==0 for row in con.execute('SELECT state_before_digest,state_after_digest,business_state_changed FROM in_memory_results')))
    def test_representation_is_recorded_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'out.sqlite'; item=request(body_relation='masked'); memory.evaluate(item,db)
            with closing(sqlite3.connect(db)) as con:
                self.assertEqual(con.execute('SELECT body_relation FROM input_observations').fetchone()[0],'masked_memory_only')

    def test_socket_attempt_is_blocked_and_not_claimed_as_rejection(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(memory.Application,'handle',side_effect=lambda _:socket.socket()):
            db=Path(temp)/'out.sqlite'; item=request(); memory.evaluate(item,db)
            with closing(sqlite3.connect(db)) as con:
                row=con.execute("SELECT result,inferred_stage FROM in_memory_results WHERE variant='sapi'").fetchone()
                self.assertEqual(row,('not_measured','evaluation_error'))

if __name__=='__main__': unittest.main()
