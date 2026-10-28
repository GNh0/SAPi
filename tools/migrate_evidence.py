"""Copy a recognized unversioned local evidence DB into v1 without changing its source."""
import argparse
from contextlib import closing
from pathlib import Path
import re
import sqlite3

LEGACY_SCHEMAS = {
    'comparison': '''
CREATE TABLE runs (run_id TEXT PRIMARY KEY, started_utc TEXT NOT NULL, repetitions INTEGER NOT NULL, environment TEXT NOT NULL, scope TEXT NOT NULL);
CREATE TABLE observations (run_id TEXT NOT NULL, repetition INTEGER NOT NULL, case_id TEXT NOT NULL, variant TEXT NOT NULL, correlation_id TEXT NOT NULL, sequence_index INTEGER NOT NULL, comparison_mode TEXT NOT NULL, fixture_summary TEXT NOT NULL, expected_result TEXT NOT NULL, result TEXT NOT NULL, http_status INTEGER, decision_stage TEXT NOT NULL, reason TEXT NOT NULL, expected_db_change INTEGER NOT NULL, db_changed INTEGER NOT NULL, before_digest TEXT NOT NULL, after_digest TEXT NOT NULL, before_state TEXT NOT NULL, after_state TEXT NOT NULL, gateway_calls INTEGER NOT NULL, business_calls INTEGER NOT NULL, egress_observation TEXT NOT NULL, elapsed_ns INTEGER, verdict TEXT NOT NULL, PRIMARY KEY(run_id,repetition,case_id,variant), FOREIGN KEY(run_id) REFERENCES runs(run_id));
''',
    'parity': '''
CREATE TABLE parity_results (run_id TEXT, step_index INTEGER, feature TEXT, variant TEXT, expected_outcome TEXT, observed_outcome TEXT, before_digest TEXT, after_digest TEXT, expected_change INTEGER, db_changed INTEGER, handler_calls INTEGER, verdict TEXT, provenance TEXT, PRIMARY KEY(run_id,step_index,variant));
''',
}


def schema_signature(db):
    # Comparing CREATE SQL preserves checks, collations, defaults, keys and foreign keys;
    # reject added views, triggers or indexes rather than silently accepting a different contract.
    entries=db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
    return [(kind,name,re.sub(r'\s+', '', sql or '').lower()) for kind,name,sql in entries]


def migrate(source, destination, kind):
    source, destination = Path(source), Path(destination)
    if not source.is_file() or destination.exists() or kind not in ('comparison', 'parity'):
        raise ValueError('existing source, new destination and known kind required')
    with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro', uri=True)) as old:
        if old.execute('PRAGMA user_version').fetchone()[0] != 0 or old.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('source is not an intact unversioned database')
        with closing(sqlite3.connect(':memory:')) as reference:
            reference.executescript(LEGACY_SCHEMAS[kind])
            if schema_signature(old) != schema_signature(reference): raise ValueError('unrecognized legacy schema')
        with closing(sqlite3.connect(destination)) as new:
            old.backup(new)
            try:
                new.execute('BEGIN IMMEDIATE')
                if kind == 'comparison':
                    new.execute("ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'legacy_unverified'")
                else:
                    new.execute('ALTER TABLE parity_results ADD COLUMN failure_reason TEXT')
                    new.execute('CREATE TABLE parity_runs (run_id TEXT PRIMARY KEY, status TEXT NOT NULL, environment TEXT NOT NULL)')
                    new.execute("INSERT INTO parity_runs SELECT DISTINCT run_id, 'legacy_unverified', '{}' FROM parity_results")
                new.execute('PRAGMA user_version=1')
                new.commit()
            except BaseException:
                new.rollback(); raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True); p.add_argument('--destination',type=Path,required=True)
    p.add_argument('--kind',choices=('comparison','parity'),required=True)
    args=p.parse_args(); migrate(args.source,args.destination,args.kind)
    print('Copied legacy evidence; provenance/completeness remains unverified.')

if __name__=='__main__': main()
