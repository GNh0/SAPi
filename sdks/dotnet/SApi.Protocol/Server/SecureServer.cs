using System.Text;
using System.Text.Json;

namespace SApi.Protocol;

public sealed class SecureServer
{
    private sealed record Operation(string Scope, Func<JsonElement, bool> Validator,
        Func<KeyRecord, JsonElement, bool> Policy, Func<KeyRecord, JsonElement, JsonElement> Handler);
    private readonly Dictionary<string, Operation> operations = new(StringComparer.Ordinal);
    private readonly IReplayStore replay;
    private readonly Codec codec;
    public SecureServer(Codec codec, IReplayStore? replay = null) { this.codec = codec; this.replay = replay ?? new MemoryReplayStore(); }
    public void Register(string name, string scope, Func<JsonElement, bool> validator,
        Func<KeyRecord, JsonElement, bool> policy, Func<KeyRecord, JsonElement, JsonElement> handler)
    {
        if (!Codec.ValidName(name) || !Codec.ValidName(scope) || operations.ContainsKey(name) || validator == null || policy == null || handler == null) throw new ArgumentException("all operation callbacks required");
        operations.Add(name, new Operation(scope, validator, policy, handler));
    }
    public string Handle(string wire)
    {
        var (kid, request) = codec.Open(wire, "req"); var principal = codec.Principal(kid); var now = codec.Now;
        var finish = codec.PrepareResponse(kid);
        var response = new Dictionary<string, object> { ["id"] = request.GetProperty("id").GetString()!, ["iat"] = now,
            ["exp"] = now + 60, ["req"] = Codec.Digest(wire), ["ok"] = false };
        try
        {
            if (!replay.Claim($"{codec.Service}|{kid}|{request.GetProperty("id").GetString()}", (long)request.GetProperty("exp").GetDouble(), codec.Now)) throw new SapiException("replay");
            if (!operations.TryGetValue(request.GetProperty("op").GetString()!, out var operation)) throw new SapiException("unknown_operation");
            if (!principal.HasScope(operation.Scope)) throw new SapiException("forbidden");
            var data = request.GetProperty("data");
            if (!operation.Validator(data)) throw new SapiException("invalid_input");
            if (!operation.Policy(principal, data)) throw new SapiException("forbidden");
            var result = operation.Handler(principal, data);
            // Parse again to check duplicate members and interoperable JSON.
            var checkedResult = Codec.Parse(Encoding.UTF8.GetBytes(result.GetRawText()));
            if (checkedResult.ValueKind != JsonValueKind.Object || Encoding.UTF8.GetByteCount(checkedResult.GetRawText()) > Codec.MaxBody - 512) throw new SapiException();
            response["ok"] = true; response["data"] = checkedResult;
        }
        catch (SapiException e) { response["error"] = e.Code is "replay" or "replay_capacity" or "unknown_operation" or "forbidden" or "invalid_input" ? e.Code : "internal_error"; }
        catch { response["error"] = "internal_error"; }
        return finish(Codec.Json(response));
    }
}
