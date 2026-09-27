using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using SApi.Protocol;

namespace SApi.AspNetCore;

public static class EndpointExtensions
{
    public static IEndpointConventionBuilder MapSapi(this IEndpointRouteBuilder endpoints, SecureServer server)
    {
        return endpoints.MapPost("/sapi", async (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            if (context.Request.ContentType != "application/sapi+jwe" || context.Request.QueryString.HasValue ||
                context.Request.Headers.ContainsKey("Authorization") || context.Request.ContentLength > Codec.MaxWire)
            { context.Response.StatusCode = 400; return; }
            try
            {
                var bytes = new byte[Codec.MaxWire + 1]; var count = 0;
                while (count < bytes.Length)
                {
                    var read = await context.Request.Body.ReadAsync(bytes.AsMemory(count), context.RequestAborted);
                    if (read == 0) break; count += read;
                }
                if (count > Codec.MaxWire) throw new SapiException();
                for (var i = 0; i < count; i++) if (bytes[i] > 127) throw new SapiException();
                var response = server.Handle(Encoding.ASCII.GetString(bytes, 0, count));
                context.Response.ContentType = "application/sapi+jwe";
                await context.Response.WriteAsync(response, context.RequestAborted);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
            catch { context.Response.StatusCode = 400; }
        });
    }
}
