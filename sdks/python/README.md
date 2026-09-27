# sapi-protocol

Experimental SAPI/0.1 PSK reference SDK for Python 3.9.2+.
Public API: `Codec`, `KeyRecord`, `Principal`, `RequestContext`, `SecureServer`, `ReplayStore`, `MemoryReplayStore`, `SapiError`.
HTTP/HTTPS binding: `from sapi.http import exchange`.

Read [usage](https://github.com/GNh0/SAPi/blob/main/docs/USAGE.md) and
[security limits](https://github.com/GNh0/SAPi/blob/main/spec/SECURITY.md).
This prerelease has not received an independent security audit. Never use the public vector keys in real traffic.
