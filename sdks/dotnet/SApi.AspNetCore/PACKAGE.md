# SApi.AspNetCore

SAPI/0.1 endpoint adapter for ASP.NET Core 6+. It depends on `SApi.Protocol`.
Register input/output schemas and authorization policies on a `SecureServer`, then call `app.MapSapi(server)`.
The only mapped operation endpoint is `POST /sapi`; authentication failures return an empty 400 response.

Read [protocol and security limits](https://github.com/GNh0/SAPi/tree/main/spec) before use.
Connect `StateClient` for persistent replay/admission and managed keys; the default memory store is scoped to one process.
