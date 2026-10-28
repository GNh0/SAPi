# Evidence package: scope and audit status

This package is a local engineering evidence set, not an independent security audit or a completed real-traffic demonstration. It contains no production observation dataset and no Site/D1 integration. All executed inputs were synthetic. The external reviewer should assess the source, assumptions, negative controls, limitations and reproducibility before relying on any claim.

## Requirements and status

| Requirement | Evidence | Status / gap |
| --- | --- | --- |
| Fair baseline | `tools/compare_api_security.py`: ordinary bearer JSON, request-ID replay-protected JSON, SAPi; shared SQLite orders handler and initial data | Local synthetic tests only; shared handler is a control, not independent implementation. No generalized security ranking. |
| Real inbound request | `tools/evaluate_shadow_memory.py`: bounded in-process request bytes and fixed transport predicates, metadata-only results, blocked business handler | Contract and synthetic test only. No real source, secure bridge, production key, deployment or actual request result. Source integrity and actual Worker integration are unresolved. |
| Preserve provenance | Separate original source response metadata, caller-declared body relation and isolated result in SQLite | The caller's `original` claim cannot be independently verified; raw bytes are not persisted. File, memory dump and OS-wide network access are not comprehensively observed. |
| Full supplied orders features | `tools/verify_order_parity.py`: create/get/update/delete/submit/complete and normal/error/authorization paths across three configurations | Synthetic orders manifest only. It is not proof of every possible API, SDK, edge case, application or deployment. Read/write scopes and owned records are exercised; TLS and distributed state are not. |
| Schema, scopes, ownership, workflow, replay and altered SAPi wire | Local regression/comparison scripts and bounded negative controls | Cases are controlled fixtures, not real attacks. Replay on hardened JSON is in-memory request-ID reuse protection, not body-bound, persistent or distributed. SAPi-only tamper does not establish superiority to correctly configured HTTPS. |
| DB evidence | Synthetic result SQLite files; `input_observations` / `in_memory_results` schema and `shadow_*` tables | No live-input DB is included. SQLite integrity checks are not tamper evidence or trusted provenance. Synthetic sentinel state is not production DB state. |
| Worker viability | `examples/shadow/worker-inspector.mjs` uses JS ESM/WebCrypto `Codec` and `SecureServer` without Node transport/state-node imports; `tests/test_worker_inspector.mjs` runs it in Node's restricted VM with WebCrypto | Local VM is not Sites Worker/Cloudflare runtime, a bundler, or production integration. Conditional `node:crypto` in `platform.js` exists; the test prohibits dynamic import and provides WebCrypto. Real packaging remains unverified. |
| Replay and D1 | SDK expects `claim` and `admit`; `MemoryReplayStore` works locally | In-memory state is per isolate, resets, and is not distributed. No D1 adapter or operational D1 change is supplied. A durable adapter must provide atomic replay admission/expiry, concurrent quota/rate decisions, bounded capacity and fail-closed failure behavior, with documented transaction and replication semantics; key usage/reservation must also be safe across replicas. Whether a particular D1 design meets these contracts is unverified and requires platform-specific testing. |
| Sampling/drop accounting | Bounded synthetic `adapter.mjs` and `import_shadow_observations.py` | Counters are source-reported; shutdown, transport loss, queue overflow and adversarial source authenticity remain integration concerns. Feature mapping yields local reconstructed cases only. |
| Deployment and insertion point | None | User approval and authorized access to the Site source and deployment are still required. Source archive access was reported unavailable by the parent; this package does not work around it. |

## Additional local inspection (base `8617301`, handoff `a062b4b`)

The Worker VM probe additionally sends the same authenticated wire to two independent `MemoryReplayStore` instances: both accept it. Two inspectors sharing one store, concurrently given a fresh wire, return one `authenticated_no_handler` and one `replay`. This confirms the local isolation hazard, not distributed atomicity. Static key-provider reservation counters are likewise process-local; replay storage alone does not solve distributed key usage. The VM intentionally supplies WebCrypto and disallows dynamic imports, but it does not test whether the Sites bundler accepts the conditional `node:crypto` import. The optional `state-node` imports Node HTTPS and filesystem APIs and cannot be assumed to run in a Worker. No real D1 adapter or platform concurrency test has been performed.

A read-only search of the tracked project configuration and documentation found no GNho Site project identifier, `gnholabs.com`, workbench table names, or Wrangler deployment configuration. This does not establish that no other authorized source or deployment path exists. The Site's previously reported source access failure remains unresolved.

For a live trial the owner must identify an authorized source revision and deployment route, the exact request hook and server-issued `request_id`, and a separate isolated evaluation destination and retention policy. A bounded asynchronous bridge must preserve the source ID, record loss and representation changes, and never delay or change the original response; the example adapter's independently generated ID is not that linkage. Before live enablement, verify resource and privacy controls, isolation from the production database and external network, runtime packaging, and atomic durable replay/rate/key-reservation behavior under concurrent Worker instances and store failures. D1 availability alone is not evidence that those contracts hold. No public deployment or production configuration change is authorized by this local evidence.

## Reproduction

```text
python -m unittest discover -s tests -p test_shadow_memory.py -v
python -m unittest discover -s tests -p test_shadow_import.py -v
python -m unittest discover -s tests -p test_compare_api_security.py -v
python -m unittest discover -s tests -p test_order_parity.py -v
node --experimental-vm-modules tests/test_worker_inspector.mjs
python tools/verify_order_parity.py --db /absolute/new-scratch/parity.sqlite
python tools/compare_api_security.py run --db /absolute/new-scratch/comparison.sqlite --repetitions 9
python tools/compare_api_security.py report --db /absolute/new-scratch/comparison.sqlite
python tools/verify_observed_requests.py --output /absolute/scratch/standalone.json
```

Requires repository dependencies and Node WebCrypto; no production data or credentials. The parity test applies fixed expected responses and expected record-change flags, checks all three variants and matching before/after full-table digests, and fails a deliberately blocked normal read or missing result. The comparison checks fixed expected outcomes, handler entries and expected fixture state; an isolated mutation disabling baseline replay must fail the replay case. Other controls ensure unrecognized or oversized source input is unsupported, duplicate IDs do not execute twice, stored output excludes a synthetic marker, and a Python socket attempt is blocked and recorded as not measured. These are checks of the harness, not proof of attack coverage.

Existing application/security regression commands in `docs/VALIDATION.md` cover additional behavior and require the project's dependencies. Exact run counts and source revision for this package are in the accompanying result summary; results should be rerun against the current source and environment rather than assumed to transfer. Timings are small local repeated observations with rotated order, not a benchmark. A caught failure may reflect transport or infrastructure rather than a security result; it must not be silently converted to a pass.
