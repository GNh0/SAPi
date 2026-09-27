"""Bound parameters, server-owned identity/state and optimistic record mutations."""
import json
from sapi.serialization import parse
from sapi.errors import SapiError
from sapi.serialization import encode
from sapi.constants import MAX_BODY
from sapi_state.storage import SqlStorage

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS sapi_app_records (service TEXT NOT NULL, collection TEXT NOT NULL, owner TEXT NOT NULL, id TEXT NOT NULL, version BIGINT NOT NULL, phase TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(service,collection,owner,id))",
)


class Records:
    def __init__(self,target,*,allow_local_postgres=False):
        self.db = SqlStorage(target,schema=SCHEMA,allow_local_postgres=allow_local_postgres)

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

    def mutate(self,kind,service,collection,principal,data,*,initial,write_phases,transition=None,output_schema=None):
        with self.db.transaction() as tx:
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
