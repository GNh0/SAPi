"""Strict versioned SQLite schemas for the two isolated shadow evidence stores."""
from contextlib import closing
import sqlite3
from migrate_evidence import schema_signature

MEMORY_ID = 0x534D454D
IMPORT_ID = 0x53494D50
VERSION = 1


def expected_signature(ddl):
    with closing(sqlite3.connect(':memory:')) as reference:
        reference.executescript(ddl)
        return schema_signature(reference)


def check_schema(db, ddl, application_id, *, legacy=False):
    expected_version = 0 if legacy else VERSION
    expected_id = 0 if legacy else application_id
    if db.execute('PRAGMA user_version').fetchone()[0] != expected_version or db.execute('PRAGMA application_id').fetchone()[0] != expected_id:
        raise ValueError('unsupported shadow evidence version or kind')
    if schema_signature(db) != expected_signature(ddl):
        raise ValueError('unrecognized shadow evidence schema')


def initialize(db, ddl, application_id):
    db.execute('BEGIN IMMEDIATE')
    try:
        empty = not db.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").fetchone()
        if empty:
            if db.execute('PRAGMA user_version').fetchone()[0] != 0 or db.execute('PRAGMA application_id').fetchone()[0] != 0:
                raise ValueError('unsupported empty database')
            for statement in ddl.split(';'):
                if statement.strip(): db.execute(statement)
            db.execute(f'PRAGMA application_id={application_id}')
            db.execute(f'PRAGMA user_version={VERSION}')
        check_schema(db, ddl, application_id)
        db.commit()
    except BaseException:
        db.rollback()
        raise
