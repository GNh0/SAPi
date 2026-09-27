# sapi-protocol

Experimental SAPI/0.1 ESM reference SDK using Web Crypto; no Node import in the protocol modules.
Node 16+ is supported through native Web Crypto and a bounded HTTP fallback; browsers require a secure context and trusted code/key provisioning.
Browser execution is not covered by the current automated tests.

Public imports: `Codec`, `SecureServer`, `MemoryReplayStore`, `SapiError`, `b64`, `unb64`, `digest`.
Optional transport: `import {exchange} from 'sapi-protocol/http'`.

Read [usage](https://github.com/GNh0/SAPi/blob/main/docs/USAGE.md) and
[security limits](https://github.com/GNh0/SAPi/blob/main/spec/SECURITY.md).
This prerelease has not received an independent security audit.
