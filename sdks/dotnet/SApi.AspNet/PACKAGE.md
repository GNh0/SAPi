# SApi.AspNet

Classic ASP.NET routing adapter for .NET Framework 4.6.2 and later.
Register `RouteTable.Routes.MapSapi(server)` during application startup after defining the server's operations.
The endpoint accepts SAPi messages at `/sapi`; all message, schema, authorization and replay checks use `SApi.Protocol`.
