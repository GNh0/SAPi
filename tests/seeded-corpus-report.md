# Local seeded SDK corpus

This is a finite, synthetic, offline test of the JavaScript SDK and the existing SQLite receipt example. It is not a test of external traffic or a security superiority measurement.

The corpus selects from 37 fixed templates. A seed reproduces the template sequence and case IDs, not the cryptographically random keys, request IDs, IVs, or wire bytes. Each normal case uses a fresh memory replay store; the D1-policy cases share a local SQLite database through a D1-shaped adapter. This does not establish long-running memory-store behavior or distributed Cloudflare D1 behavior. The test prints a source-file SHA-256; a caller-provided base commit is explicitly labelled as an unverified claim. Collect the actual checkout commit, status, and source hash independently outside the process.

| Layer | Examples | Evidence |
| --- | --- | --- |
| Header before authentication | authenticated duplicate header, direction and service mismatch; malformed base64, IV and tag | reject and no handler/effect/receipt; normal follow-up |
| Authentication | altered tag or ciphertext; wrong key | reject and no handler/effect/receipt; normal follow-up |
| Body after decryption | authenticated duplicate member, invalid UTF-8, lone surrogate, extra field and expiry | reject and no handler/effect/receipt; normal follow-up |
| Policy and schema | missing scope, other owner, type; ASCII-byte length 31/32/33, integer 9/10/11, array length 1/2/3 | fixed success/rejection and effect/receipt oracle |
| Valid data | SQL-shaped text, Korean text, email; authenticated reordered/escaped JSON | successful operation; raw response is verified against request context and digest |
| Replay and receipt | sequential duplicate, eight simultaneous duplicates, new wire with same operation key, invalid precommit output | handler, effect and receipt counts |
| Storage | synthetic one-shot store error, D1 policy mismatch on SQLite adapter | fail closed; follow-up after the synthetic error or explicit policy correction |

With source SHA-256 `f74fa8d1bde072a9d3b568ddb296cfd8dd4356d4d5caa474630a00d893f646a0`, seed 1028 ran 1,000 cases twice with identical per-template counts and 1,000 passing each time; seed 42 ran 1,000 cases once, also passing. Explicit normal template counts were 274, 274 and 271 respectively, plus valid recovery requests after rejected cases. No normal control was observed to fail. These are repetitions of fixed templates, not thousands of distinct mutations. A prior standalone receipt-contract test also covered injected receipt-write failure and simulated postcommit delivery loss with receipt lookup and retry; those are not yet corpus templates.

The event-loop timer exits the disposable test process after an asynchronous case deadline and marks that case unknown; a synchronous event-loop stall cannot trigger it. CPU and overall time checks run between cases. No independent hard watchdog was verified in this environment. Future tests must not interpret an interrupted or unreported case as a pass.

Still unmeasured: full wire, UTF-8 byte, numeric, array and depth boundary matrices; broader authenticated escape variants; key revocation propagation; NFC/NFD business equivalence; automatic safe input minimization; long-term replay accumulation; real D1 concurrency, costs and response uncertainty; and live external traffic. The test records a failing template descriptor but does not claim it has minimized the input.

## Boundary extension

With source SHA-256 `780192258281ac7120eb5d9c6f8833540304e6c8a3adb8226aa29e4de1dc46bc`, seeds 1028 and 42 each completed 1,000 selected cases. Fixed authenticated controls separately checked decoded protected-header lengths 1023/1024/1025 and decrypted body lengths 65535/65536/65537; lower and exact limits were accepted by the codec, while above-limit inputs were rejected. Wire lengths 131071/131072/131073 were malformed and all rejected: tighter header and body limits prevent constructing a valid wire of those sizes, so these are not successful semantic boundary controls. The parser checked integer 2^53-2, 2^53-1, and 2^53, plus JSON depth 31/32/33. The schema checked array size 63/64/65 and integer, boolean, and fractional types.

One finite sequence reused a memory replay store with capacity two across Alice and Bob, tested a duplicate, advanced time past expiry, and checked that a fresh request succeeded and handler counts matched. That sequence does not measure database effects and is not an endurance or distributed test.

`run_seeded_corpus.mjs` proposes a separate whole-run watchdog. On this Windows host, its piped child-process self-test failed with `spawn_failed: EPERM`; it did not establish process termination or a hard timeout. No fallback was used. Direct executions above used only the in-process cooperative timer. The earlier source hash and test results remain historical; they are not evidence for the newer file.

## Normal-control accounting and input evidence

The fixed `seeded-corpus-oracle.mjs` assigns an expected class to every template. The normal-control denominator includes normal templates, expected-success boundary controls, the shared replay sequence, and normal recovery requests. `normalFalseBlocks` conservatively counts a failure in any such control, including an effect or receipt mismatch, so it is a control-failure indicator rather than proof that a particular rejection occurred. With corpus source SHA-256 `9ce69d23199becda6bea218acc91735880d02474bec0ea7dd4cc2a7a9470f583`, seed 1028 completed 1,000 cases with 1,012 normal controls attempted and passed and zero normal-control failures. A deliberately altered disposable copy forced `field_order` to fail: the run stopped with `fail=1` and `normalFalseBlocks=1`; the original source was not changed by that negative control. Unit checks cover the other fixed normal classifications, boundary and recovery accounting.

`run_seeded_corpus.ps1` independently reads local Git HEAD and dirty status and hashes the JavaScript SDK source, fixture, corpus, oracle, and launchers before and after the run, reporting changes. These are local reproducibility records, not signed or tamper-proof evidence. The launcher does not provide a hard watchdog. A dry run while the checkout was dirty correctly reported `dirty=true`, 20 completed cases, and unchanged collected inputs.

## Failure classification revision

The old `normalFalseBlocks` combined different failures and is retained above only as historical wording. The current report uses `normalRejected` for an observed rejection, `normalSemanticMismatch` for a verified success response followed by an oracle mismatch, `normalUncertain` when available observations cannot distinguish them, and `normalContractFailures` for their sum. The normal denominator still includes expected-success boundary and recovery controls. A result may remain uncertain if response verification fails or execution is interrupted. The label `normalSemanticMismatch` is a failed overall control after a success response; it does not by itself identify which particular state assertion failed.

With corpus SHA-256 `9dd61b65444882627a4d99d702b715f191f7dbc61b29adbab49ea9718f2ac506`, seed 1028 completed 1,000 cases and 1,012 normal controls with all four failure counters zero. Three deliberately altered disposable copies forced a `field_order` rejection, success with wrong handler count, and an ambiguous exception. Each stopped with one normal contract failure and exactly its corresponding rejection, semantic mismatch, or uncertainty counter set. The original file was not changed by the negative controls.

For this seed, the 1,012 controls comprise 537 normal corpus cases, 463 normal recovery requests after rejection cases, and 12 separate expected-success boundary/sequence controls. Some of the last 12 exercise parsers or schemas rather than business requests; do not describe the full denominator as business traffic.

Input evidence additionally includes the SDK package manifest, Node version, executable path and SHA-256, built-in SQLite version, and the explicitly selected seed/count plus presence of relevant options. It does not dump the environment. Comparing before and after snapshots cannot detect a file modified and restored during execution, and these records are not signatures.

## CI integration, pending verification

A finite step has been added to the existing Node 24 `verify` job on both existing OS matrix entries, after checkout and Node setup; no schedule or new job was added. It runs the oracle accounting test, the watchdog's intentional event-loop-stall self-test, then two whole-run watchdog invocations with fixed seeds 1028 and 42 and 128 cases each. A normal child must return a complete report; the stall self-test must observe both an accepted kill and child close. Failures or unknown timeouts are failures, not passes. It uses the existing 45-second whole-run limit per invocation and one-second stall limit, with a two-minute CI step limit as an outer bound. The maximum planned matrix cost is 512 selected cases plus fixed boundary checks; this sample does not guarantee every template is selected.

The parent watchdog remains unverified locally because piped child creation returned `EPERM`. Its CI execution must demonstrate the runner's independent-process behavior; a successful CI test would not retroactively prove the local environment supports it or impose a two-second hard limit on each case. If process creation or termination is denied in CI, preserve that result as a runner limitation and do not bypass it.
