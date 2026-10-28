import { DatabaseSync } from 'node:sqlite';
import worker from './drivers/receipt-contract-worker.mjs';

const sqlite = new DatabaseSync(':memory:');
const db = {
  prepare(sql) {
    const prepare = () => sqlite.prepare(sql);
    const bound = args => ({
      async first() { return prepare().get(...args) ?? null; },
      async run() { return prepare().run(...args); },
      async all() { return {results: prepare().all(...args)}; },
      _sql: sql, _args: args,
    });
    return {...bound([]), bind(...args) { return bound(args); }};
  },
  async batch(statements) {
    sqlite.exec('BEGIN');
    try {
      const results = statements.map(s => sqlite.prepare(s._sql).run(...s._args));
      sqlite.exec('COMMIT');
      return results;
    } catch (error) { sqlite.exec('ROLLBACK'); throw error; }
  },
};
try {
  const response = await worker.fetch(new Request('http://localhost/'), {TEST_DB: db});
  if (!response.ok) throw new Error(`fixture failed: ${response.status}`);
  console.log(await response.text());
} finally { sqlite.close(); }