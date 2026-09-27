"""Role-scoped key lifecycle and durable replay, serialized by database transactions."""
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sapi.constants import NAME, REQUEST_ID
from sapi.serialization import b64, unb64, parse
from .files import write_private
from .tree import Tree, TreeError, pointer


class StateError(Exception):
    def __init__(self, code="state_unavailable"):
        self.code = code; super().__init__(code)


@dataclass(frozen=True)
class Identity:
    fingerprint: str
    role: str
    service: str | None = None
    subject: str | None = None


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


class Authority:
    def __init__(self, database, keks: dict[str, bytes], primary: str, audit_key: bytes, *, anchor_path, capacity=100000, clock=None):
        if primary not in keks or not keks or any(not NAME.fullmatch(k) or not isinstance(v, bytes) or len(v) != 32 for k, v in keks.items()) or len(audit_key) != 32:
            raise ValueError("32-byte external KEKs and separate audit key required")
        if capacity < 1: raise ValueError("positive replay capacity required")
        self.db, self.keks, self.primary, self.audit_key = database, dict(keks), primary, bytes(audit_key)
        self.capacity, self.clock = capacity, clock or (lambda: int(time.time()))
        self.rate_capacity = 100000
        self.anchor_path = Path(anchor_path)
        with self.db.transaction() as tx:
            checkpoint = self._verify_audit(tx)
            if self.anchor_path.exists():
                anchor = self._read_anchor()
                if {k: anchor[k] for k in ("seq", "tag")} != checkpoint: raise StateError("audit_rollback")
                tx.tree = Tree(tx, anchor["root"], self.audit_key)
            elif checkpoint["seq"] != 0 or tx.execute("SELECT COUNT(*) AS n FROM sapi_keys").fetchone()["n"]:
                raise StateError("anchor_missing")
            else:
                tx.tree = Tree(tx, pointer(), self.audit_key)
            for root_id, key in self.keks.items():
                row = tx.execute("SELECT * FROM sapi_roots WHERE root_id=?", (root_id,)).fetchone()
                aad = ("SAPI-STATE/root/" + root_id).encode("ascii")
                if row is None:
                    if tx.tree.get("root|" + root_id) is not None: raise StateError("state_tampered")
                    nonce = secrets.token_bytes(12)
                    proof = AESGCM(key).encrypt(nonce, b"SAPI-STATE root verification", aad)
                    tx.execute("INSERT INTO sapi_roots VALUES(?,?,?,1,'')", (root_id, b64(nonce), b64(proof)))
                    self._sign_root(tx, root_id)
                else:
                    self._check_row("root", row, tx)
                    if AESGCM(key).decrypt(unb64(row["nonce"]), unb64(row["proof"]), aad) != b"SAPI-STATE root verification":
                        raise StateError("invalid_root")
            for row in tx.execute("SELECT * FROM sapi_keys").fetchall():
                self._check_row("key", row, tx)
                if row["sealed"] is not None: self._decrypt(row, tx)
            for table,prefix,count_name in (("sapi_rates","rate|","rate-count"),("sapi_quotas","quota|","quota-count")):
                rows=tx.execute("SELECT * FROM " + table).fetchall()
                if len(rows)!=int(tx.tree.get(count_name) or "0"): raise StateError("state_tampered")
                for row in rows:
                    name=row["name"] if table=="sapi_rates" else row["service"]+"|"+row["subject"]
                    if tx.tree.get(prefix+name)!=hashlib.sha256(canonical(dict(row))).hexdigest(): raise StateError("state_tampered")
            self._write_anchor(dict(checkpoint, root=tx.tree.root, clock=anchor["clock"] if self.anchor_path.exists() else int(self.clock())))

    def _read_anchor(self):
        try:
            raw = self.anchor_path.read_bytes()
            if len(raw) > 1024: raise ValueError()
            record = parse(raw)
            checkpoint = record["checkpoint"]
            expected = b64(hmac.new(self.audit_key, b"SAPI-STATE/checkpoint\x00" + canonical(checkpoint), hashlib.sha256).digest())
            if set(record) != {"checkpoint", "mac"} or set(checkpoint) != {"seq", "tag", "clock", "root"} or type(checkpoint["clock"]) is not int or checkpoint["clock"] < 0 or type(checkpoint["seq"]) is not int or checkpoint["seq"] < 0 or not hmac.compare_digest(expected, record["mac"]): raise ValueError()
            return checkpoint
        except Exception: raise StateError("anchor_invalid")

    def _write_anchor(self, checkpoint):
        mac = b64(hmac.new(self.audit_key, b"SAPI-STATE/checkpoint\x00" + canonical(checkpoint), hashlib.sha256).digest())
        write_private(self.anchor_path, canonical({"checkpoint": checkpoint, "mac": mac}), replace=self.anchor_path.exists())

    @contextmanager
    def _transaction(self):
        with self.db.transaction() as tx:
            anchor = self._read_anchor()
            row = tx.execute("SELECT seq,tag FROM sapi_audit ORDER BY seq DESC LIMIT 1").fetchone()
            checkpoint = {"seq": row["seq"], "tag": row["tag"]} if row else {"seq": 0, "tag": b64(bytes(32))}
            if {k: anchor[k] for k in ("seq", "tag")} != checkpoint: raise StateError("audit_rollback")
            try: tx.tree = Tree(tx, anchor["root"], self.audit_key)
            except TreeError: raise StateError("state_tampered")
            now = int(self.clock())
            if now < anchor["clock"] - 5: raise StateError("clock_rollback")
            now = max(now, anchor["clock"])
            if now != anchor["clock"]:
                # Clock observations survive a subsequently rejected transaction.
                self._write_anchor(dict(checkpoint, root=tx.tree.root, clock=now))
            try: yield tx
            except TreeError: raise StateError("state_tampered")
            row = tx.execute("SELECT seq,tag FROM sapi_audit ORDER BY seq DESC LIMIT 1").fetchone()
            updated = {"seq": row["seq"], "tag": row["tag"]} if row else checkpoint
            if updated != checkpoint or tx.tree.root != anchor["root"]:
                # Anchor first, COMMIT second. A crash in this window requires quarantine
                # recovery; it must never silently restore revoked keys or replay entries.
                self._write_anchor(dict(updated, root=tx.tree.root, clock=now))

    def _row_tag(self, domain, row):
        value = {key: row[key] for key in row.keys() if key != "tag"}
        return b64(hmac.new(self.audit_key, ("SAPI-STATE/" + domain + "\x00").encode() + canonical(value), hashlib.sha256).digest())

    def _check_row(self, domain, row, tx):
        name = "root|" + row["root_id"] if domain == "root" else "key|" + row["service"] + "|" + row["kid"]
        if not hmac.compare_digest(row["tag"], self._row_tag(domain, row)) or tx.tree.get(name) != row["tag"]: raise StateError("state_tampered")

    def _sign_key(self, tx, service, kid):
        row = tx.execute("SELECT * FROM sapi_keys WHERE service=? AND kid=?", (service, kid)).fetchone()
        tx.execute("UPDATE sapi_keys SET tag=? WHERE service=? AND kid=?", (self._row_tag("key", row), service, kid))
        tx.tree.set("key|" + service + "|" + kid, self._row_tag("key", row))

    def _sign_root(self, tx, root_id):
        row = tx.execute("SELECT * FROM sapi_roots WHERE root_id=?", (root_id,)).fetchone()
        tx.execute("UPDATE sapi_roots SET tag=? WHERE root_id=?", (self._row_tag("root", row), root_id))
        tx.tree.set("root|" + root_id, self._row_tag("root", row))

    def _now(self, tx):
        now = int(self.clock())
        row = tx.execute("SELECT value FROM sapi_meta WHERE name='clock'").fetchone()
        last = max(int(row["value"]) if row else now, self._read_anchor()["clock"])
        if now < last - 5: raise StateError("clock_rollback")
        now = max(now, last)
        tx.execute("INSERT INTO sapi_meta(name,value) VALUES('clock',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (str(now),))
        return now

    def _audit(self, tx, actor, action, details):
        row = tx.execute("SELECT seq,tag FROM sapi_audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq, previous = (row["seq"] + 1, row["tag"]) if row else (1, b64(bytes(32)))
        event = canonical({"seq": seq, "time": int(self.clock()), "actor": actor.fingerprint, "role": actor.role, "action": action, "details": details}).decode("utf-8")
        tag = b64(hmac.new(self.audit_key, previous.encode("ascii") + b"\x00" + event.encode("utf-8"), hashlib.sha256).digest())
        tx.execute("INSERT INTO sapi_audit VALUES(?,?,?,?)", (seq, event, previous, tag))

    def _verify_audit(self, tx, anchor=None):
        seq, previous = 0, b64(bytes(32))
        matched = anchor is None
        for row in tx.execute("SELECT * FROM sapi_audit ORDER BY seq").fetchall():
            seq += 1
            tag = b64(hmac.new(self.audit_key, previous.encode("ascii") + b"\x00" + row["event"].encode("utf-8"), hashlib.sha256).digest())
            if row["seq"] != seq or row["previous"] != previous or not hmac.compare_digest(row["tag"], tag): raise StateError("audit_tampered")
            previous = tag
            if anchor is not None and seq == anchor["seq"] and hmac.compare_digest(previous, anchor["tag"]): matched = True
        if anchor is not None and anchor["seq"] == 0 and anchor["tag"] == b64(bytes(32)): matched = True
        if not matched: raise StateError("audit_rollback")
        return {"seq": seq, "tag": previous}

    def _wrap(self, tx, metadata, master, root_id=None):
        root_id = root_id or self.primary
        if root_id not in self.keks: raise StateError("invalid_root")
        row = tx.execute("SELECT * FROM sapi_roots WHERE root_id=?", (root_id,)).fetchone()
        self._check_row("root", row, tx)
        if row["wraps"] >= 1048576: raise StateError("root_rotation_required")
        tx.execute("UPDATE sapi_roots SET wraps=wraps+1 WHERE root_id=?", (root_id,))
        self._sign_root(tx, root_id)
        nonce = secrets.token_bytes(12)
        sealed = AESGCM(self.keks[root_id]).encrypt(nonce, master, canonical(metadata))
        return root_id, b64(nonce), b64(sealed)

    def _decrypt(self, row, tx):
        self._check_row("key", row, tx)
        metadata = parse(row["metadata"].encode("utf-8"))
        if any(metadata[k] != row[k] for k in ("service", "kid", "subject", "status")) or row["sealed"] is None: raise StateError("invalid_key")
        if row["root_id"] not in self.keks: raise StateError("missing_root")
        try:
            key = AESGCM(self.keks[row["root_id"]]).decrypt(unb64(row["nonce"]), unb64(row["sealed"]), canonical(metadata))
        except Exception: raise StateError("invalid_key")
        if len(key) != 32: raise StateError("invalid_key")
        return metadata, key

    @staticmethod
    def _authorize(actor, service, subject=None, admin=False):
        if admin:
            if actor.role != "admin": raise StateError("forbidden")
        elif actor.role not in ("admin", "service", "client") or (actor.role != "admin" and actor.service != service) or (actor.role == "client" and actor.subject != subject):
            raise StateError("forbidden")

    def _live(self, tx, actor, service, kid, now):
        row = tx.execute("SELECT * FROM sapi_keys WHERE service=? AND kid=?", (service, kid)).fetchone()
        if row is None: raise StateError("invalid_key")
        self._authorize(actor, service, row["subject"])
        if row["status"] == "revoked" or row["sealed"] is None: raise StateError("key_revoked")
        metadata, master = self._decrypt(row, tx)
        if now < metadata["not_before"] or now >= metadata["expires"]: raise StateError("key_expired")
        if metadata["status"] == "retiring" and now >= metadata["retire_at"]: raise StateError("key_retired")
        return row, metadata, master

    def _new(self, tx, actor, service, subject, scopes, ttl, limit, now):
        kid = "k_" + secrets.token_hex(16)
        metadata = {"service": service, "kid": kid, "subject": subject, "scopes": sorted(scopes), "status": "active", "issued": now,
                    "not_before": now, "expires": now + ttl, "retire_at": None, "message_limit": limit, "ttl": ttl}
        root_id, nonce, sealed = self._wrap(tx, metadata, secrets.token_bytes(32))
        tx.execute("INSERT INTO sapi_keys VALUES(?,?,?,?,?,?,?,?,0,0,'')", (service, kid, subject, "active", canonical(metadata).decode(), root_id, nonce, sealed))
        self._sign_key(tx, service, kid)
        tx.tree.set("active|" + service + "|" + subject, kid)
        self._audit(tx, actor, "issue", {"service": service, "subject": subject, "kid": kid, "scopes": sorted(scopes)})
        return kid

    def issue(self, actor, service, subject, scopes, ttl=86400, message_limit=1048576):
        self._authorize(actor, service, admin=True)
        if not isinstance(service, str) or not NAME.fullmatch(service) or not isinstance(subject, str) or not NAME.fullmatch(subject) or not isinstance(scopes, list) or not 1 <= len(scopes) <= 64 or any(not isinstance(x, str) or not NAME.fullmatch(x) for x in scopes): raise StateError("invalid_input")
        if type(ttl) is not int or not 300 <= ttl <= 2592000 or type(message_limit) is not int or not 1 <= message_limit <= 1048576: raise StateError("invalid_input")
        with self._transaction() as tx:
            now = self._now(tx)
            if tx.tree.get("active|" + service + "|" + subject) is not None: raise StateError("already_issued")
            kid = self._new(tx, actor, service, subject, scopes, ttl, message_limit, now)
        return {"kid": kid}

    def _rotate(self, tx, actor, row, metadata, master, now):
        metadata = dict(metadata, status="retiring", retire_at=min(metadata["expires"], now + 120))
        root, nonce, sealed = self._wrap(tx, metadata, master)
        tx.execute("UPDATE sapi_keys SET status='retiring',metadata=?,root_id=?,nonce=?,sealed=? WHERE service=? AND kid=?", (canonical(metadata).decode(), root, nonce, sealed, row["service"], row["kid"]))
        self._sign_key(tx, row["service"], row["kid"])
        kid = self._new(tx, actor, row["service"], row["subject"], metadata["scopes"], metadata["ttl"], metadata["message_limit"], now)
        self._audit(tx, actor, "rotate", {"service": row["service"], "old": row["kid"], "new": kid, "retire_at": metadata["retire_at"]})
        return kid

    def rotate(self, actor, service, kid):
        self._authorize(actor, service, admin=True)
        with self._transaction() as tx:
            now = self._now(tx)
            row = tx.execute("SELECT * FROM sapi_keys WHERE service=? AND kid=?", (service, kid)).fetchone()
            if row is None or row["status"] != "active": raise StateError("invalid_key")
            metadata, master = self._decrypt(row, tx)
            if tx.tree.get("active|" + service + "|" + row["subject"]) != kid: raise StateError("state_tampered")
            new = self._rotate(tx, actor, row, metadata, master, now)
        return {"kid": new}

    def active(self, actor, service, subject):
        self._authorize(actor, service, subject)
        with self._transaction() as tx:
            now = self._now(tx)
            kid = tx.tree.get("active|" + service + "|" + subject)
            if kid is None: raise StateError("invalid_key")
            row = tx.execute("SELECT * FROM sapi_keys WHERE service=? AND kid=?", (service, kid)).fetchone()
            if row is None or row["status"] != "active": raise StateError("state_tampered")
            metadata, master = self._decrypt(row, tx)
            # Rotation preserves old decrypt/reply grace, but immediately stops old request encryption.
            if metadata["expires"] - now <= 180 or max(row["req_count"], row["res_count"]) >= max(1, metadata["message_limit"] * 4 // 5):
                kid = self._rotate(tx, actor, row, metadata, master, now)
                row = tx.execute("SELECT * FROM sapi_keys WHERE service=? AND kid=?", (service, kid)).fetchone()
                metadata, master = self._decrypt(row, tx)
            if now < metadata["not_before"]: raise StateError("key_expired")
            return {"kid": row["kid"]}

    def key(self, actor, service, kid, direction=None):
        with self._transaction() as tx:
            now = self._now(tx)
            row, metadata, master = self._live(tx, actor, service, kid, now)
            if direction is not None:
                if direction not in ("req", "res") or (actor.role == "client" and direction != "req") or (actor.role == "service" and direction != "res"): raise StateError("forbidden")
                if direction == "req" and metadata["status"] != "active": raise StateError("key_retired")
                column = "req_count" if direction == "req" else "res_count"
                if row[column] >= metadata["message_limit"]: raise StateError("key_rotation_required")
                tx.execute("UPDATE sapi_keys SET " + column + "=" + column + "+1 WHERE service=? AND kid=?", (service, kid))
                self._sign_key(tx, service, kid)
                self._audit(tx, actor, "reserve", {"service": service, "kid": kid, "direction": direction, "count": row[column] + 1})
            else:
                self._audit(tx, actor, "key_read", {"service": service, "kid": kid})
            return {"master": b64(master), "subject": metadata["subject"], "scopes": metadata["scopes"]}

    def claim(self, actor, name, expiry):
        if actor.role not in ("admin", "service"): raise StateError("forbidden")
        try: service, kid, request_id = name.split("|")
        except (ValueError, AttributeError): raise StateError("invalid_input")
        if not NAME.fullmatch(service) or not NAME.fullmatch(kid) or not REQUEST_ID.fullmatch(request_id) or type(expiry) is not int: raise StateError("invalid_input")
        with self._transaction() as tx:
            now = self._now(tx)
            self._live(tx, actor, service, kid, now)
            if not now < expiry <= now + 65: raise StateError("invalid_input")
            count = int(tx.tree.get("replay-count") or "0")
            for expired in tx.execute("SELECT * FROM sapi_replay WHERE expiry<=? ORDER BY expiry LIMIT 1000", (now,)).fetchall():
                if tx.tree.get("replay|" + expired["name"]) != self._replay_tag(expired): raise StateError("state_tampered")
                tx.execute("DELETE FROM sapi_replay WHERE name=?", (expired["name"],))
                tx.tree.set("replay|" + expired["name"], None); count -= 1
            row = tx.execute("SELECT * FROM sapi_replay WHERE name=?", (name,)).fetchone()
            committed = tx.tree.get("replay|" + name)
            if (row is None and committed is not None) or (row is not None and committed != self._replay_tag(row)): raise StateError("state_tampered")
            if row is not None:
                tx.tree.set("replay-count", str(count))
                return {"claimed": False}
            if count >= self.capacity: raise StateError("replay_capacity")
            tx.execute("INSERT INTO sapi_replay VALUES(?,?)", (name, expiry))
            tx.tree.set("replay|" + name, self._replay_tag({"name": name, "expiry": expiry}))
            tx.tree.set("replay-count", str(count + 1))
            self._audit(tx, actor, "claim", {"service": service, "kid": kid, "request_id": request_id, "expiry": expiry})
        return {"claimed": True}

    def admit(self, actor, service, kid, operation, requests=60, period=60):
        """Global subject limit plus trusted operation limit; survives key rotation."""
        if actor.role not in ("admin", "service"): raise StateError("forbidden")
        if not isinstance(operation, str) or not NAME.fullmatch(operation) or type(requests) is not int or not 1 <= requests <= 10000 or type(period) is not int or not 1 <= period <= 3600: raise StateError("invalid_input")
        with self._transaction() as tx:
            now = self._now(tx); key_row, _, _ = self._live(tx, actor, service, kid, now)
            quota=tx.execute("SELECT * FROM sapi_quotas WHERE service=? AND subject=?",(service,key_row["subject"])).fetchone()
            committed=tx.tree.get("quota|"+service+"|"+key_row["subject"])
            if (quota is None and committed is not None) or (quota is not None and committed!=hashlib.sha256(canonical(dict(quota))).hexdigest()): raise StateError("state_tampered")
            expired=tx.execute("SELECT * FROM sapi_rates WHERE expiry<=? ORDER BY expiry LIMIT 1000",(now,)).fetchall()
            for row in expired:
                if tx.tree.get("rate|"+row["name"])!=hashlib.sha256(canonical(dict(row))).hexdigest(): raise StateError("state_tampered")
                tx.execute("DELETE FROM sapi_rates WHERE name=?",(row["name"],));tx.tree.set("rate|"+row["name"],None)
            if expired:
                tx.tree.set("rate-count",str(int(tx.tree.get("rate-count") or "0")-len(expired)))
                self._audit(tx,actor,"rate_expire",{"count":len(expired)})
            pending = []
            for name, count, seconds in (("global|" + service + "|" + key_row["subject"], quota["requests"] if quota else 60, quota["period"] if quota else 60), ("op|" + service + "|" + key_row["subject"] + "|" + operation, requests, period)):
                row = tx.execute("SELECT * FROM sapi_rates WHERE name=?", (name,)).fetchone()
                committed = tx.tree.get("rate|" + name)
                if (row is None and committed is not None) or (row is not None and committed != hashlib.sha256(canonical(dict(row))).hexdigest()): raise StateError("state_tampered")
                if row is None:
                    rows = int(tx.tree.get("rate-count") or "0")
                    if rows + len([r for r in pending if r[1]]) >= self.rate_capacity: raise StateError("rate_capacity")
                started, used = (row["started"], row["used"]) if row else (now, 0)
                # Changing a configured period never resets a live counter.
                effective_period = max(seconds, row["period"] if row else seconds)
                if now >= started + effective_period: started, used, effective_period = now, 0, seconds
                if used >= count: return {"admitted": False}
                pending.append(({"name": name, "started": started, "period": effective_period, "requests": count, "used": used + 1, "expiry":started+effective_period}, row is None))
            for row, created in pending:
                tx.execute("INSERT INTO sapi_rates VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET started=excluded.started,period=excluded.period,requests=excluded.requests,used=excluded.used,expiry=excluded.expiry", (row["name"], row["started"], row["period"], row["requests"], row["used"],row["expiry"]))
                tx.tree.set("rate|" + row["name"], hashlib.sha256(canonical(row)).hexdigest())
                if created: tx.tree.set("rate-count", str(int(tx.tree.get("rate-count") or "0") + 1))
            self._audit(tx, actor, "admit", {"service": service, "subject": key_row["subject"], "operation": operation})
        return {"admitted": True}

    def quota(self,actor,service,subject,requests,period):
        self._authorize(actor,service,admin=True)
        if not isinstance(service,str) or not NAME.fullmatch(service) or not isinstance(subject,str) or not NAME.fullmatch(subject) or type(requests) is not int or not 1<=requests<=10000 or type(period) is not int or not 1<=period<=3600: raise StateError("invalid_input")
        with self._transaction() as tx:
            now=self._now(tx);name="quota|"+service+"|"+subject
            previous=tx.execute("SELECT * FROM sapi_quotas WHERE service=? AND subject=?",(service,subject)).fetchone();committed=tx.tree.get(name)
            if (previous is None and committed is not None) or (previous is not None and committed!=hashlib.sha256(canonical(dict(previous))).hexdigest()): raise StateError("state_tampered")
            count=int(tx.tree.get("quota-count") or "0")
            if previous is None and count>=self.rate_capacity: raise StateError("rate_capacity")
            row={"service":service,"subject":subject,"requests":requests,"period":period}
            tx.execute("INSERT INTO sapi_quotas VALUES(?,?,?,?) ON CONFLICT(service,subject) DO UPDATE SET requests=excluded.requests,period=excluded.period",(service,subject,requests,period))
            tx.tree.set(name,hashlib.sha256(canonical(row)).hexdigest())
            if previous is None: tx.tree.set("quota-count",str(count+1))
            rate_name="global|"+service+"|"+subject
            rate=tx.execute("SELECT * FROM sapi_rates WHERE name=?",(rate_name,)).fetchone();rate_hash=tx.tree.get("rate|"+rate_name)
            if (rate is None and rate_hash is not None) or (rate is not None and rate_hash!=hashlib.sha256(canonical(dict(rate))).hexdigest()):raise StateError("state_tampered")
            if rate is not None and rate["expiry"]>now:
                updated=dict(rate);updated["period"]=max(rate["period"],period);updated["expiry"]=rate["started"]+updated["period"];updated["requests"]=requests
                tx.execute("UPDATE sapi_rates SET period=?,expiry=?,requests=? WHERE name=?",(updated["period"],updated["expiry"],requests,rate_name))
                tx.tree.set("rate|"+rate_name,hashlib.sha256(canonical(updated)).hexdigest())
            self._audit(tx,actor,"quota",row)
        return {"configured":True}

    @staticmethod
    def _replay_tag(row):
        return hashlib.sha256(canonical({"name": row["name"], "expiry": row["expiry"]})).hexdigest()

    def revoke(self, actor, service, kid):
        self._authorize(actor, service, admin=True)
        with self._transaction() as tx:
            self._now(tx)
            row = tx.execute("SELECT * FROM sapi_keys WHERE service=? AND kid=?", (service, kid)).fetchone()
            if row is None: raise StateError("invalid_key")
            self._check_row("key", row, tx)
            tx.execute("UPDATE sapi_keys SET status='revoked',sealed=NULL,nonce=NULL WHERE service=? AND kid=?", (service, kid))
            self._sign_key(tx, service, kid)
            if tx.tree.get("active|" + service + "|" + row["subject"]) == kid:
                tx.tree.set("active|" + service + "|" + row["subject"], None)
            self._audit(tx, actor, "revoke", {"service": service, "kid": kid})
        return {"revoked": True}

    def rewrap(self, actor, root_id):
        self._authorize(actor, "", admin=True)
        if root_id not in self.keks: raise StateError("invalid_root")
        with self._transaction() as tx:
            self._now(tx); count = 0
            for row in tx.execute("SELECT * FROM sapi_keys WHERE sealed IS NOT NULL AND root_id<>?", (root_id,)).fetchall():
                metadata, master = self._decrypt(row, tx)
                root, nonce, sealed = self._wrap(tx, metadata, master, root_id)
                tx.execute("UPDATE sapi_keys SET root_id=?,nonce=?,sealed=? WHERE service=? AND kid=?", (root, nonce, sealed, row["service"], row["kid"])); count += 1
                self._sign_key(tx, row["service"], row["kid"])
            self._audit(tx, actor, "rewrap", {"root_id": root_id, "keys": count})
        return {"rewrapped": count}

    def audit(self, actor, anchor=None, after=0):
        self._authorize(actor, "", admin=True)
        if type(after) is not int or after < 0: raise StateError("invalid_input")
        with self._transaction() as tx:
            checkpoint = self._verify_audit(tx, anchor)
            events = [parse(row["event"].encode()) for row in tx.execute("SELECT event FROM sapi_audit WHERE seq>? ORDER BY seq LIMIT 100", (after,)).fetchall()]
        return {"checkpoint": checkpoint, "events": events, "next": events[-1]["seq"] if events else after}
