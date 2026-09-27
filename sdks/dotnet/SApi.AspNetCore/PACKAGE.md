# SApi.AspNetCore

Experimental SAPI/0.1 endpoint adapter for ASP.NET Core 8+. It depends on `SApi.Protocol`.
Register explicit validators and authorization policies on a `SecureServer`, then call `app.MapSapi(server)`.
The only mapped operation endpoint is `POST /sapi`; authentication failures return an empty 400 response.

Read [protocol and security limits](https://github.com/GNh0/SAPi/tree/main/spec) before use.
The default replay store is single-process memory. This prerelease has not received an independent security audit.
