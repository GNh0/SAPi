using System.Text;
using System.Text.Json;

namespace SApi.Protocol;

public sealed class SecureServer
{
    private sealed record Operation(string Scope, Schema Input, Schema Output,
        Func<KeyRecord, JsonElement, bool> Policy, Func<KeyRecord, JsonElement, JsonElement> Handler, int Requests, int Period);
    private readonly Dictionary<string, Operation> operations = new(StringComparer.Ordinal);
    private readonly IReplayStore replay;
    private readonly Codec codec;
    public SecureServer(Codec codec, IReplayStore? replay = null) { this.codec = codec; this.replay = replay ?? new MemoryReplayStore(); }
    public void Register(string name, string scope, JsonElement input, JsonElement output,
        Func<KeyRecord, JsonElement, bool> policy, Func<KeyRecord, JsonElement, JsonElement> handler, int requests = 60, int period = 60)
    {
        if (!Codec.ValidName(name) || !Codec.ValidName(scope) || operations.ContainsKey(name) || policy == null || handler == null || requests is < 1 or > 10000 || period is < 1 or > 3600) throw new ArgumentException("operation, schemas, policy, handler and bounded rate required");
        operations.Add(name, new Operation(scope, new Schema(input,true), new Schema(output,true), policy, handler, requests, period));
    }
    public JsonElement Inventory() => Codec.Json(operations.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new {name=p.Key,scope=p.Value.Scope,requests=p.Value.Requests,period=p.Value.Period}));
    public string Handle(string wire)
    {
        var (kid, request) = codec.Open(wire, "req"); var principal = codec.Principal(kid); var now = codec.Now;
        var finish = codec.PrepareResponse(kid);
        var response = new Dictionary<string, object> { ["id"] = request.GetProperty("id").GetString()!, ["iat"] = now,
            ["exp"] = now + 60, ["req"] = Codec.Digest(wire), ["ok"] = false };
        try
        {
            operations.TryGetValue(request.GetProperty("op").GetString()!, out var operation);
            if (!replay.Admit(codec.Service,kid,principal.Subject,operation == null ? "unknown" : request.GetProperty("op").GetString()!,codec.Now,operation?.Requests ?? 60,operation?.Period ?? 60)) throw new SapiException("rate_limited");
            if (!replay.Claim($"{codec.Service}|{kid}|{request.GetProperty("id").GetString()}", (long)request.GetProperty("exp").GetDouble(), codec.Now)) throw new SapiException("replay");
            if (operation == null) throw new SapiException("unknown_operation");
            if (!principal.HasScope(operation.Scope)) throw new SapiException("forbidden");
            var data = request.GetProperty("data");
            if (!operation.Input.Validate(data)) throw new SapiException("invalid_input");
            if (!operation.Policy(principal, data)) throw new SapiException("forbidden");
            if (codec.Now >= request.GetProperty("exp").GetDouble()) throw new SapiException("invalid_input");
            var result = operation.Handler(principal, data);
            // Parse again to check duplicate members and interoperable JSON.
            var checkedResult = Codec.Parse(Encoding.UTF8.GetBytes(result.GetRawText()));
            if (checkedResult.ValueKind != JsonValueKind.Object || !operation.Output.Validate(checkedResult) || Encoding.UTF8.GetByteCount(checkedResult.GetRawText()) > Codec.MaxBody - 512) throw new SapiException();
            response["ok"] = true; response["data"] = checkedResult;
        }
        catch (SapiException e) { response["error"] = e.Code is "replay" or "replay_capacity" or "rate_limited" or "rate_capacity" or "unknown_operation" or "forbidden" or "invalid_input" ? e.Code : "internal_error"; }
        catch { response["error"] = "internal_error"; }
        return finish(Codec.Json(response));
    }
}
