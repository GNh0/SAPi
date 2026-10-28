"""Copy a recognized unversioned shadow evidence database to version 1."""
import argparse
from contextlib import closing
from pathlib import Path
import sqlite3
from evaluate_shadow_memory import DDL as MEMORY_DDL
from import_shadow_observations import DDL as IMPORT_DDL
from shadow_schema import MEMORY_ID, IMPORT_ID, VERSION, check_schema

KINDS = {'memory': (MEMORY_DDL, MEMORY_ID), 'import': (IMPORT_DDL, IMPORT_ID)}


def migrate(source, destination, kind):
    source, destination = Path(source), Path(destination)
    if kind not in KINDS or not source.is_file() or destination.exists():
        raise ValueError('existing source, new destination and known kind required')
    ddl, application_id = KINDS[kind]
    with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro', uri=True)) as old:
        check_schema(old, ddl, application_id, legacy=True)
        if old.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or old.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('legacy evidence integrity failed')
        # An exclusive create prevents overwriting an existing file, including a race.
        with destination.open('xb'): pass
        try:
            with closing(sqlite3.connect(destination)) as new:
                old.backup(new)
                check_schema(new, ddl, application_id, legacy=True)
                if new.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or new.execute('PRAGMA foreign_key_check').fetchone():
                    raise ValueError('copied evidence integrity failed')
                new.execute('BEGIN IMMEDIATE')
                new.execute(f'PRAGMA application_id={application_id}')
                new.execute(f'PRAGMA user_version={VERSION}')
                check_schema(new, ddl, application_id)
                new.commit()
        except BaseException:
            destination.unlink(missing_ok=True)
            raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True); parser.add_argument('--destination',type=Path,required=True)
    parser.add_argument('--kind',choices=tuple(KINDS),required=True)
    args=parser.parse_args(); migrate(args.source,args.destination,args.kind)
    print('Copied recognized legacy evidence; provenance and completeness remain unchanged.')

if __name__=='__main__': main()
