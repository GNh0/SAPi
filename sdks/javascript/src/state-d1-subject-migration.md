# Unicode subject guard migration

This is a reviewed, administrator-only upgrade from the NAME-only 2ba2378 exclusive schema. Request handling never installs or updates triggers. Do not apply this to a shared or uncertain database. The SQL changes exactly two triggers and does not update policy, owner, claims, rates, counters, or existing rows.

1. Stop new admissions, drain old and new workers and all other database writers; reconcile in-flight and uncertain operations. If drain cannot be established, stop. Make a recoverable backup. Read and retain the current owner, policy, row counts, trigger definitions, and schema version. Confirm exclusive ownership and that retained namespace rows are valid. Do not clear rows.
2. Compare the UTF-8 SHA-256 of each `sqlite_schema.sql` value after converting CRLF to LF (no added newline) with the old hashes below. Abort on any mismatch, missing trigger, ambiguous database state, or unknown schema. This preflight requires writers to remain drained until verification completes.
3. Split `state-d1-subject-migration.sql` only on the exact `--> statement-breakpoint` marker and pass the four complete statements in order to one `D1Database.batch()` call. Trigger bodies contain semicolons; never split on semicolons or use line-based `exec()`. A D1 batch is transactional; do not deploy workers while the result is uncertain.
4. On success, read both definitions and compare with the new hashes below; recheck owner, policy, counts and existing rows. An error or lost response can have an uncertain commit outcome. Keep writers drained and read from the primary database, compare both trigger definitions and retained state, and reconcile before any next step. Do not blindly rerun the migration.
5. Only after validation, deploy matching code and reopen traffic under a separate approved procedure. The D1 adapter accepts subject strings of 1-1024 UTF-16 code units, at most 4096 UTF-8 bytes; unpaired surrogates are rejected. Other code units, including NUL and control characters, are preserved exactly.

| Trigger | 2ba2378 old SHA-256 | Unicode guard SHA-256 |
| --- | --- | --- |
| sapi_replay_owner_validate | 325d4e34ad01851b38af91d109d51177bcbceef979cb1e0fc7bf5a1fe7346b29 | 689dddb989546fe4c8a9abec2bfb6bf5fc89bff651495bc18204f80e1b1bf4b9 |
| sapi_replay_rate_owner_guard | f7b75a41ef8b9c79f509156f6ab9e1cf7877f3953b5b2c279dabde5003bc2ca3 | 62f1625bd99167477984347800bcfc21e36c25e110338b361d884fd6b4772a55 |

Rollback requires stopping new requests and draining all writers again. The old NAME-only trigger rejects Unicode subjects and NUL. If any retained rows cannot satisfy the old guard, do not restore it or delete live evidence; wait for the full retention window and reconcile uncertain work, then perform separately approved bounded cleanup. Confirm every retained row and policy is compatible, restore the exact old two trigger definitions together in a single reviewed batch, verify hashes and data, then deploy the matching old code. If those conditions cannot be demonstrated, remain stopped and investigate.

Local SQLite is not proof of production D1 concurrency or cost. A retry of an uncertain write may have already committed; never treat a missing response as proof of rollback.
