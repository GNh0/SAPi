"""Authenticated ordered dictionary, committed by the external checkpoint.

A deterministic HMAC priority keeps the treap balanced without exposing a chosen
insertion-order strategy. Every traversed node is checked against its parent hash.
"""
import hashlib
import hmac
import json

EMPTY = hashlib.sha256(b"SAPI-STATE/empty-tree").hexdigest()


class TreeError(Exception): pass


def pointer(name=None, digest=EMPTY): return {"name": name, "hash": digest}


class Tree:
    def __init__(self, tx, root, key):
        self.tx, self.root, self.key = tx, dict(root), key
        if self.root["name"] is not None: self._load(self.root)

    @staticmethod
    def _hash(row):
        fields = {k: row[k] for k in ("name", "digest", "priority", "left_name", "left_hash", "right_name", "right_hash")}
        return hashlib.sha256(b"SAPI-STATE/node\x00" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _load(self, reference):
        if reference["name"] is None:
            if reference["hash"] != EMPTY: raise TreeError()
            return None
        row = self.tx.execute("SELECT * FROM sapi_tree WHERE name=?", (reference["name"],)).fetchone()
        if row is None or not hmac.compare_digest(self._hash(row), reference["hash"]) or not hmac.compare_digest(row["hash"], reference["hash"]): raise TreeError()
        return dict(row)

    def _save(self, row):
        row["hash"] = self._hash(row)
        self.tx.execute("INSERT INTO sapi_tree VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET digest=excluded.digest,priority=excluded.priority,left_name=excluded.left_name,left_hash=excluded.left_hash,right_name=excluded.right_name,right_hash=excluded.right_hash,hash=excluded.hash",
                        tuple(row[k] for k in ("name", "digest", "priority", "left_name", "left_hash", "right_name", "right_hash", "hash")))
        return pointer(row["name"], row["hash"])

    @staticmethod
    def _child(row, side): return pointer(row[side + "_name"], row[side + "_hash"])
    @staticmethod
    def _attach(row, side, child): row[side + "_name"], row[side + "_hash"] = child["name"], child["hash"]

    def get(self, name):
        reference = self.root
        for _ in range(128):
            row = self._load(reference)
            if row is None: return None
            if row["name"] == name: return row["digest"]
            reference = self._child(row, "left" if name < row["name"] else "right")
        raise TreeError()

    def set(self, name, value):
        self.root = self._put(self.root, name, value, 0)

    def _put(self, reference, name, value, depth):
        if depth > 128: raise TreeError()
        row = self._load(reference)
        if row is None:
            if value is None: return reference
            row = {"name": name, "digest": value, "priority": hmac.new(self.key, b"SAPI-STATE/priority\x00" + name.encode(), hashlib.sha256).hexdigest(),
                   "left_name": None, "left_hash": EMPTY, "right_name": None, "right_hash": EMPTY}
            return self._save(row)
        if name == row["name"]:
            if value is None:
                merged = self._merge(self._child(row, "left"), self._child(row, "right"), depth + 1)
                self.tx.execute("DELETE FROM sapi_tree WHERE name=?", (name,))
                return merged
            row["digest"] = value
            return self._save(row)
        side = "left" if name < row["name"] else "right"
        child_pointer = self._put(self._child(row, side), name, value, depth + 1)
        self._attach(row, side, child_pointer)
        child = self._load(child_pointer)
        if child is not None and child["priority"] < row["priority"]:
            opposite = "right" if side == "left" else "left"
            self._attach(row, side, self._child(child, opposite))
            self._attach(child, opposite, self._save(row))
            return self._save(child)
        return self._save(row)

    def _merge(self, left, right, depth):
        if depth > 128: raise TreeError()
        a, b = self._load(left), self._load(right)
        if a is None: return right
        if b is None: return left
        if a["priority"] < b["priority"]:
            self._attach(a, "right", self._merge(self._child(a, "right"), right, depth + 1))
            return self._save(a)
        self._attach(b, "left", self._merge(left, self._child(b, "left"), depth + 1))
        return self._save(b)
