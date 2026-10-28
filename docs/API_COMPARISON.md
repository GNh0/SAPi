# Local API comparison experiment

This is a bounded technical experiment, not a production service or a general security ranking. It starts three actual loopback HTTP servers, each with a separate temporary SQLite business database containing the same synthetic record. All three share the same orders schema, policy and bound-SQL `Records` handler: this deliberately controls the business layer, but is not an independent comparison of different application implementations.

The ordinary JSON API uses ephemeral bearer credentials, scope, input/output schema and ownership/workflow checks. The enhanced JSON configuration adds a process-local locked, bounded request-ID set, keyed by credential identity; duplicate IDs return `replay`, and a full set fails closed. IDs remain until the process stops. This is an explicit local replay control, not a production-ready durable, distributed, expiring or body-bound replay mechanism. A caller who changes an ID can send another request; protecting tokens and IDs in transit still requires HTTPS. SAPi uses its authenticated/encrypted messages and in-memory replay store. Both baseline configurations are implemented and executed, not simulated. Neither loopback listener uses TLS. Generated credentials and keys exist only in memory.

Identical raw probes are sent to all variants. For malformed content encoding, length, transfer framing and invalid wire the endpoint and media type are adapted to each protocol; this is not an identical-byte comparison. XML is a harmless fixture and is rejected without parsing; no conclusion about an XML parser or XXE follows. HTTP status and route differences describe configuration, not security superiority. Authenticated cases carry equivalent business operations, not identical wire bytes. The original 23 standalone cases are represented by the raw, adapted, schema, scope, ownership, replay, transition and normal-control categories. Their response codes and routes may differ because the endpoints differ; the standalone suite remains the reference for exact SAPi transport assertions. The added SAPi-only case changes ciphertext of a valid authenticated message and observes rejection and no business call. There is no corresponding baseline result: bare JSON over HTTP has no comparable message-authentication layer, and HTTPS also protects transport integrity when properly configured. This is not evidence that encryption is superior to HTTPS. No real suspicious URL, external payload, address or live traffic is used.

```text
python tools/compare_api_security.py run --db /absolute/scratch/comparison.sqlite --repetitions 9
python tools/compare_api_security.py report --db /absolute/scratch/comparison.sqlite
python -m unittest discover -s tests -p test_compare_api_security.py -v
```

`run` requires a new database path and 1–30 repetitions. Each repetition starts fresh business databases and credentials. Variant order rotates deterministically by repetition, and the order index is recorded. Run metadata records Python/platform versions and relevant source hashes. `report` can select `--run-id`; it re-reads stored observations, checks fixed expectations and expected fixture states, variant pairing, record counts and SQLite `integrity_check`. Failures and incomplete runs do not produce a successful summary. The SQLite check and consistency checks are not a tamper-evident signature; someone able to rewrite the whole DB can forge it. Protect the result DB.

`runs` and `observations` link repetition, case and variant with a common correlation ID. Each observation stores a fixed safe fixture summary, normalized expected and observed response, HTTP status, inferred stage/reason, handler/gateway entries, full business-table before/after digests, safe aggregate row/phase/version summaries, change flag, elapsed time and `not_measured` egress. No request/response body, token, key, real person or external address is recorded. The user-facing report includes a first-repetition input → response → before/after state → observed effects chain for each variant. `business_calls` means entry to `Records.get/mutate`, not arbitrary code. Gateway entry is after bearer authentication for the JSON APIs but before SAPi message authentication; it is not directly comparable as a security or performance score. The stage is inferred from results and entry counts, not traced. Replay/rate state is outside the business-table snapshot. External file access and OS-wide network activity are not measured.

Example query:

```sql
SELECT repetition, case_id, correlation_id, variant, fixture_summary,
       decision_stage, reason, result, http_status, before_state, after_state,
       db_changed, business_calls, egress_observation, elapsed_ns, verdict
FROM observations
WHERE run_id = :run_id
ORDER BY repetition, case_id, sequence_index;
```

Reports distinguish matching outcomes, replay configuration differences, SAPi-only message authentication, route/protocol differences and unmeasured outcomes; no single security or block-rate score is computed. Local elapsed times include protocol-specific encoding/decoding and scheduling; median is descriptive only. Rotation reduces one order bias but not warmup, endpoint, transport, OS, caching or sample-size effects. The repeated SAPi request reuses a prepared message; unmeasured baseline tamper timings are omitted. These are not performance benchmarks. TLS, durable/distributed replay, independent third-party APIs, PostgreSQL, external calls, higher load and real deployment topology require separate controlled studies. Public exposure, production data and deployment remain outside this experiment.
