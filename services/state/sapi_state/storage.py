"""Bounded, committed transactions. SQLite is local; PostgreSQL permits replicas."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS sapi_tree (name TEXT PRIMARY KEY, digest TEXT NOT NULL, priority TEXT NOT NULL, left_name TEXT, left_hash TEXT NOT NULL, right_name TEXT, right_hash TEXT NOT NULL, hash TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sapi_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sapi_roots (root_id TEXT PRIMARY KEY, nonce TEXT NOT NULL, proof TEXT NOT NULL, wraps BIGINT NOT NULL, tag TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sapi_keys (service TEXT NOT NULL, kid TEXT NOT NULL, subject TEXT NOT NULL, status TEXT NOT NULL, metadata TEXT NOT NULL, root_id TEXT NOT NULL, nonce TEXT, sealed TEXT, req_count BIGINT NOT NULL, res_count BIGINT NOT NULL, tag TEXT NOT NULL, PRIMARY KEY(service,kid))",
    "CREATE UNIQUE INDEX IF NOT EXISTS sapi_one_active ON sapi_keys(service,subject) WHERE status='active'",
    "CREATE TABLE IF NOT EXISTS sapi_replay (name TEXT PRIMARY KEY, expiry BIGINT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS sapi_replay_expiry ON sapi_replay(expiry)",
    "CREATE TABLE IF NOT EXISTS sapi_audit (seq BIGINT PRIMARY KEY, event TEXT NOT NULL, previous TEXT NOT NULL, tag TEXT NOT NULL)",
)


class Transaction:
    def __init__(self, connection, postgres):
        self.connection, self.postgres = connection, postgres

    def execute(self, statement, values=()):
        return self.connection.execute(statement.replace("?", "%s") if self.postgres else statement, values)


class Database:
    def __init__(self, target: str, *, allow_local_postgres=False, timeout=5):
        self.target, self.timeout = target, timeout
        self.postgres = target.startswith(("postgresql://", "postgres://"))
        if self.postgres:
            from psycopg.conninfo import conninfo_to_dict
            options = conninfo_to_dict(target)
            hosts = options.get("host", "").split(",")
            if any(not host.strip() or host.strip().startswith(("/", "@")) for host in hosts): raise ValueError("explicit PostgreSQL TCP hostnames required")
            local = options.get("host") in ("127.0.0.1", "localhost", "::1")
            if options.get("sslmode") != "verify-full" and not (allow_local_postgres and local):
                raise ValueError("PostgreSQL requires sslmode=verify-full; explicit loopback test exception available")
        else:
            path = Path(target).resolve()
            if not path.is_file():
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
                from .files import protect
                protect(path)
            self.target = str(path)
            connection = self._connect()
            try:
                mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                if mode.lower() != "wal": raise RuntimeError("durable WAL unavailable")
            finally:
                connection.close()
        with self.transaction() as tx:
            for statement in SCHEMA: tx.execute(statement)
            row = tx.execute("SELECT value FROM sapi_meta WHERE name='schema'").fetchone()
            if row is not None and row["value"] != "1": raise RuntimeError("unsupported state schema")
            tx.execute("INSERT INTO sapi_meta(name,value) VALUES('schema','1') ON CONFLICT(name) DO NOTHING")

    def _connect(self):
        if self.postgres:
            import psycopg
            from psycopg.rows import dict_row
            return psycopg.connect(self.target, connect_timeout=self.timeout, autocommit=True, row_factory=dict_row)
        connection = sqlite3.connect(self.target, timeout=self.timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    @contextmanager
    def transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN" if self.postgres else "BEGIN IMMEDIATE")
            if self.postgres:
                connection.execute("SET LOCAL lock_timeout='5s'")
                connection.execute("SET LOCAL statement_timeout='5s'")
                connection.execute("SET LOCAL synchronous_commit=on")
                connection.execute("SELECT pg_advisory_xact_lock(746321019)")
            yield Transaction(connection, self.postgres)
            connection.execute("COMMIT")
        except BaseException:
            try: connection.execute("ROLLBACK")
            except Exception: pass
            raise
        finally:
            connection.close()
