"""Bound parameters, server-owned identity/state and optimistic record mutations."""
import json
import hashlib
import re
import time
from sapi.serialization import parse
from sapi.errors import SapiError
from sapi.serialization import encode
from sapi.constants import MAX_BODY
from sapi_state.storage import SqlStorage

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS sapi_app_records (service TEXT NOT NULL, collection TEXT NOT NULL, owner TEXT NOT NULL, id TEXT NOT NULL, version BIGINT NOT NULL, phase TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(service,collection,owner,id))",
)
RECEIPT_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS sapi_app_receipts (service TEXT NOT NULL, subject TEXT NOT NULL, operation_id TEXT NOT NULL, collection TEXT NOT NULL, fingerprint TEXT NOT NULL, result TEXT, expires BIGINT NOT NULL, PRIMARY KEY(service,subject,operation_id))",
    "CREATE INDEX IF NOT EXISTS sapi_app_receipts_expiry ON sapi_app_receipts(expires)",
    "CREATE TABLE IF NOT EXISTS sapi_app_receipt_meta (name TEXT PRIMARY KEY, value BIGINT NOT NULL)",
)


class Records:
    def __init__(self,target,*,allow_local_postgres=False,enable_idempotency=False,clock=None):
        if type(enable_idempotency) is not bool: raise ValueError('explicit idempotency setting required')
        self.idempotency_enabled=enable_idempotency
        self.clock=clock or time.time
        self.db = SqlStorage(target,schema=SCHEMA+(RECEIPT_SCHEMA if enable_idempotency else ()),allow_local_postgres=allow_local_postgres)

    @staticmethod
    def _get(tx,service,collection,owner,id):
        return tx.execute("SELECT id,version,phase,payload FROM sapi_app_records WHERE service=? AND collection=? AND owner=? AND id=?",(service,collection,owner,id)).fetchone()

    @staticmethod
    def _result(row):
        return [] if row is None else [{"id":row["id"],"version":row["version"],"phase":row["phase"],"data":parse(row["payload"].encode("utf-8"))}]

    @staticmethod
    def _checked(result,output_schema=None):
        if len(encode(result))>MAX_BODY-512 or (output_schema is not None and not output_schema.validate(result)):
            raise SapiError("invalid_input")
        return result

    def get(self,service,collection,principal,data,*,output_schema=None):
        with self.db.transaction() as tx:
            row = self._get(tx,service,collection,principal.subject,data["id"])
            return self._checked({"found":row is not None,"records":self._result(row)},output_schema)

    def _receipt_now(self,tx):
        now=int(self.clock())
        if now<0 or now>9007199254654591: raise SapiError('idempotency_clock')
        row=tx.execute("SELECT value FROM sapi_app_receipt_meta WHERE name='clock'").fetchone()
        if row is not None and now<row['value']: raise SapiError('idempotency_clock')
        tx.execute("INSERT INTO sapi_app_receipt_meta(name,value) VALUES('clock',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",(now,))
        return now

    def mutate(self,kind,service,collection,principal,data,*,initial,write_phases,transition=None,output_schema=None,operation_name=None,contract_id=None):
        operation_id=data.get('operation_id')
        if 'operation_id' in data and (not self.idempotency_enabled or not isinstance(operation_id,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}',operation_id)):
            raise SapiError('invalid_input')
        fingerprint=None
        if operation_id is not None:
            if not isinstance(operation_name,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',operation_name) or (contract_id is not None and (not isinstance(contract_id,str) or not re.fullmatch(r'[0-9a-f]{64}',contract_id))): raise SapiError('invalid_input')
            contract={'version':2,'operation_name':operation_name,'contract_id':contract_id,'kind':kind,'collection':collection,'data':{k:v for k,v in data.items() if k!='operation_id'},'initial':initial,'write_phases':list(write_phases),'transition':transition}
            fingerprint=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
        with self.db.transaction() as tx:
            if operation_id is not None:
                now=self._receipt_now(tx)
                receipt=tx.execute('SELECT collection,fingerprint,result,expires FROM sapi_app_receipts WHERE service=? AND subject=? AND operation_id=?',(service,principal.subject,operation_id)).fetchone()
                if receipt is not None:
                    if receipt['collection']!=collection or receipt['fingerprint']!=fingerprint: raise SapiError('idempotency_conflict')
                    if receipt['expires']<=now or receipt['result'] is None: raise SapiError('idempotency_expired')
                    return self._checked(parse(receipt['result'].encode('utf-8')),output_schema)
                tx.execute('UPDATE sapi_app_receipts SET result=NULL WHERE expires<=? AND result IS NOT NULL',(now,))
                if tx.execute('SELECT COUNT(*) AS n FROM sapi_app_receipts').fetchone()['n']>=10000: raise SapiError('idempotency_capacity')
            result=self._mutate_tx(tx,kind,service,collection,principal,data,initial=initial,write_phases=write_phases,transition=transition,output_schema=output_schema)
            if operation_id is not None:
                self._checked({'found':True,'expired':False,'changed':result['changed'],'records':result['records']})
                tx.execute('INSERT INTO sapi_app_receipts(service,subject,operation_id,collection,fingerprint,result,expires) VALUES(?,?,?,?,?,?,?)',(service,principal.subject,operation_id,collection,fingerprint,json.dumps(result,ensure_ascii=True,separators=(',',':')),now+86400))
            return result

    def receipt(self,service,collection,principal,data,*,output_schema=None):
        if not self.idempotency_enabled or not isinstance(data.get('operation_id'),str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}',data['operation_id']): raise SapiError('invalid_input')
        with self.db.transaction() as tx:
            now=self._receipt_now(tx)
            row=tx.execute('SELECT collection,result,expires FROM sapi_app_receipts WHERE service=? AND subject=? AND operation_id=?',(service,principal.subject,data['operation_id'])).fetchone()
            if row is None or row['collection']!=collection: result={'found':False,'expired':False,'changed':False,'records':[]}
            elif row['expires']<=now or row['result'] is None: result={'found':True,'expired':True,'changed':False,'records':[]}
            else:
                saved=parse(row['result'].encode('utf-8'))
                result={'found':True,'expired':False,'changed':saved['changed'],'records':saved['records']}
            return self._checked(result,output_schema)

    def _mutate_tx(self,tx,kind,service,collection,principal,data,*,initial,write_phases,transition=None,output_schema=None):
        row = self._get(tx,service,collection,principal.subject,data["id"])
        identity = (service,collection,principal.subject,data["id"])
        if kind == "create":
            if row is not None:return self._checked({"changed":False,"records":[]},output_schema)
            payload = json.dumps(data["data"],ensure_ascii=False,separators=(",",":"),allow_nan=False)
            tx.execute("INSERT INTO sapi_app_records VALUES(?,?,?,?,1,?,?)",(*identity,initial,payload))
        else:
            if row is None or row["version"] != data["version"]:return self._checked({"changed":False,"records":[]},output_schema)
            if kind in ("update","transition") and row["version"]>=9007199254740991:raise SapiError("forbidden")
            if kind in ("update","delete") and row["phase"] not in write_phases:raise SapiError("forbidden")
            if kind == "update":
                payload = json.dumps(data["data"],ensure_ascii=False,separators=(",",":"),allow_nan=False)
                tx.execute("UPDATE sapi_app_records SET payload=?,version=version+1 WHERE service=? AND collection=? AND owner=? AND id=? AND version=?",(payload,*identity,data["version"]))
            elif kind == "delete":
                tx.execute("DELETE FROM sapi_app_records WHERE service=? AND collection=? AND owner=? AND id=? AND version=?",(*identity,data["version"]))
                return self._checked({"changed":True,"records":[]},output_schema)
            elif kind == "transition":
                if row["phase"] != transition["from"]:raise SapiError("forbidden")
                tx.execute("UPDATE sapi_app_records SET phase=?,version=version+1 WHERE service=? AND collection=? AND owner=? AND id=? AND version=? AND phase=?",(transition["to"],*identity,data["version"],transition["from"]))
            else:raise ValueError("unsupported record operation")
        # Output rejection must roll back the mutation, before leaving the transaction.
        return self._checked({"changed":True,"records":self._result(self._get(tx,*identity))},output_schema)
