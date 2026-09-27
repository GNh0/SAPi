using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using SApi.AspNetCore;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using SApi.Protocol;

Console.InputEncoding = Encoding.UTF8; Console.OutputEncoding = new UTF8Encoding(false);
WebApplication? application = null;
Codec? codec = null; SecureServer? server = null; var contexts = new Dictionary<string, RequestContext>(); var executions = 0;
object Invoke(JsonElement c)
{
    string Text(string key) => c.GetProperty(key).GetString()!;
    string Slot() => c.TryGetProperty("slot", out var s) ? s.GetString()! : "default";
    var action = Text("action");
    if (action == "init")
    {
        var keys = new Dictionary<string, KeyRecord>();
        foreach (var f in c.GetProperty("keys").EnumerateObject())
        {
            var scopes = new List<string>(); foreach (var scope in f.Value.GetProperty("scopes").EnumerateArray()) scopes.Add(scope.GetString()!);
            keys.Add(f.Name, new KeyRecord(Codec.UnB64(f.Value.GetProperty("key").GetString()!), f.Value.GetProperty("subject").GetString()!, scopes));
        }
        Func<long>? clock = c.TryGetProperty("now", out var n) && n.ValueKind != JsonValueKind.Null ? () => (long)n.GetDouble() : null;
        codec = new Codec(c.TryGetProperty("service", out var svc) ? svc.GetString()! : "demo", keys, clock);
        IReplayStore store = c.TryGetProperty("store", out var storeKind) && storeKind.GetString() == "fail" ? new BrokenStore() : new MemoryReplayStore(c.TryGetProperty("capacity", out var cap) ? cap.GetInt32() : 10000);
        server = new SecureServer(codec, store); executions = 0; contexts.Clear();
        bool OneString(JsonElement d, string field)
        {
            var count = 0; foreach (var _ in d.EnumerateObject()) count++;
            return count == 1 && d.TryGetProperty(field, out var v) && v.ValueKind == JsonValueKind.String;
        }
        JsonElement Counted(KeyRecord p, JsonElement d) { Interlocked.Increment(ref executions); return d; }
        server.Register("echo", "echo", d => OneString(d, "message") && Encoding.UTF8.GetByteCount(d.GetProperty("message").GetString()!) <= 4096, (p, d) => true, Counted);
        server.Register("own", "orders", d => OneString(d, "owner"), (p, d) => p.Subject == d.GetProperty("owner").GetString(), Counted);
        server.Register("fail", "echo", d => true, (p, d) => true, (p, d) => throw new InvalidOperationException("private internal details"));
        return new {ready = true};
    }
    if (action == "derive") return new {key = Convert.ToHexString(codec!.Derive(Text("kid"), Text("dir"))).ToLowerInvariant()};
    if (action == "seal") return new {wire = codec!.Seal(Text("kid"), Text("dir"), c.GetProperty("payload"))};
    if (action == "open") {var o = codec!.Open(Text("wire"), Text("dir")); return new {kid = o.Kid, payload = o.Payload};}
    if (action == "request") {var ctx = codec!.Request(Text("kid"), Text("op"), c.GetProperty("data")); contexts[Slot()] = ctx; return new {wire = ctx.Wire};}
    if (action == "accept") return new {payload = codec!.AcceptResponse(contexts[Slot()], Text("wire"))};
    if (action == "handle") return new {wire = server!.Handle(Text("wire"))};
    if (action == "http_server_start")
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel().UseUrls("http://127.0.0.1:0");
        application = builder.Build();
        application.MapSapi(server!);
        application.StartAsync().GetAwaiter().GetResult();
        foreach (var address in application.Urls) return new {url = address + "/sapi"};
        throw new InvalidOperationException("no bound address");
    }
    if (action == "http_server_stop")
    {
        application!.StopAsync().GetAwaiter().GetResult();
        application.DisposeAsync().AsTask().GetAwaiter().GetResult(); application = null;
        return new {stopped = true};
    }
    if (action == "http")
    {
        try
        {
            using var ca = c.TryGetProperty("ca", out var caFile) ? X509Certificate2.CreateFromPem(File.ReadAllText(caFile.GetString()!)) : null;
            return new {wire = HttpBinding.ExchangeAsync(new Uri(Text("url")), Text("wire"), ca).GetAwaiter().GetResult()};
        }
        catch {return new {error = "transport_error"};}
    }
    if (action == "parallel")
    {
        var tasks = new Task<string>[16]; var wire = Text("wire");
        for (var i = 0; i < tasks.Length; i++) tasks[i] = Task.Run(() => server!.Handle(wire));
        return new {wires = Task.WhenAll(tasks).GetAwaiter().GetResult()};
    }
    if (action == "stats") return new {executions};
    if (action == "bad_registration")
    {
        try {server!.Register("bad", "echo", d => true, null!, (p, d) => d); return new {rejected = false};}
        catch (ArgumentException) {return new {rejected = true};}
    }
    throw new SapiException();
}
string? line;
while ((line = Console.ReadLine()) != null)
{
    object output;
    try { output = Invoke(Codec.Parse(Encoding.UTF8.GetBytes(line))); }
    catch (SapiException e) { output = new {error = e.Code}; }
    catch { output = new {error = "invalid_message"}; }
    Console.WriteLine(JsonSerializer.Serialize(output));
}
sealed class BrokenStore : IReplayStore { public bool Claim(string key, long expiry, long now) => throw new IOException("storage unavailable"); }
