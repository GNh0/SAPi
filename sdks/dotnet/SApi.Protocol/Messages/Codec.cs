using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SApi.Protocol;

using static SApi.Protocol.JsonFormat;

public sealed class Codec
{
    public const int MaxWire = 131072, MaxBody = 65536;
    private static readonly Regex Name = new("\\A[A-Za-z0-9_-]{1,64}\\z", RegexOptions.CultureInvariant);
    private static readonly Regex IdPattern = new("\\A[0-9a-f]{32}\\z", RegexOptions.CultureInvariant);
    private static readonly Regex Base64Pattern = new("\\A[A-Za-z0-9_-]+\\z", RegexOptions.CultureInvariant);
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly string[] HeaderFields = { "alg", "enc", "typ", "kid", "sapi", "dir", "svc", "crit" };
    private readonly IKeyProvider keys;
    private readonly Func<long> clock;
    public string Service { get; }
    public long Now => clock();
    public Codec(string service, IReadOnlyDictionary<string, KeyRecord> keys, Func<long>? clock = null) : this(service, new StaticKeyProvider(keys), clock) { }
    public Codec(string service, IKeyProvider keys, Func<long>? clock = null)
    {
        if (!ValidName(service)) throw new ArgumentException("service required");
        Service = service; this.keys = keys ?? throw new ArgumentNullException(nameof(keys));
        this.clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }
    public static bool ValidName(string? value) => value != null && Name.IsMatch(value);
    public KeyRecord Principal(string kid) => keys.Get(Service, kid);
    public static string B64(byte[] raw) => Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] UnB64(string value)
    {
        if (!Base64Pattern.IsMatch(value)) throw new SapiException();
        try
        {
            var result = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
            if (B64(result) != value) throw new SapiException();
            return result;
        }
        catch { throw new SapiException(); }
    }
    public static string Digest(string wire) => B64(SHA256.HashData(Encoding.ASCII.GetBytes(wire)));
    public byte[] Derive(string kid, string direction)
    {
        if (direction != "req" && direction != "res") throw new SapiException();
        return Derive(kid, direction, Principal(kid));
    }
    private byte[] Derive(string kid, string direction, KeyRecord record)
    {
        var prk = HMACSHA256.HashData(Utf8.GetBytes("SAPI/0.1 HKDF-SHA-256"), record.Master);
        var info = Utf8.GetBytes($"SAPI/0.1|{Service}|{kid}|{direction}");
        var input = new byte[info.Length + 1]; info.CopyTo(input, 0); input[^1] = 1;
        return HMACSHA256.HashData(prk, input);
    }
    public static JsonElement Parse(byte[] bytes) => JsonFormat.Parse(bytes);
    public static JsonElement Json(object value) => JsonFormat.Json(value);
    private void Validate(JsonElement payload, string direction)
    {
        if (direction == "req")
        {
            Exact(payload, "id", "iat", "exp", "op", "data");
            if (!ValidName(payload.GetProperty("op").GetString())) throw new SapiException();
        }
        else
        {
            if (payload.GetProperty("ok").ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new SapiException();
            var ok = payload.GetProperty("ok").GetBoolean();
            Exact(payload, "id", "iat", "exp", "req", "ok", ok ? "data" : "error");
            if (UnB64(payload.GetProperty("req").GetString()!).Length != 32 || (!ok && !ValidName(payload.GetProperty("error").GetString()))) throw new SapiException();
        }
        if (!IdPattern.IsMatch(payload.GetProperty("id").GetString()!)) throw new SapiException();
        if (payload.TryGetProperty("data", out var data) && data.ValueKind != JsonValueKind.Object) throw new SapiException();
        var issued = Integer(payload.GetProperty("iat")); var expiry = Integer(payload.GetProperty("exp"));
        var now = Now;
        if (expiry - issued < 1 || expiry - issued > 60 || issued > now + 5 || now >= expiry) throw new SapiException();
    }
    public string Seal(string kid, string direction, JsonElement payload)
    {
        if (direction != "req" && direction != "res") throw new SapiException();
        Tree(payload); Validate(payload, direction);
        var body = Utf8.GetBytes(payload.GetRawText()); if (body.Length > MaxBody) throw new SapiException();
        return SealReserved(kid, direction, body, keys.Reserve(Service, kid, direction));
    }
    internal Func<JsonElement, string> PrepareResponse(string kid)
    {
        var record = keys.Reserve(Service, kid, "res"); var used = 0;
        return payload =>
        {
            if (Interlocked.Exchange(ref used, 1) != 0) throw new SapiException("reservation_used");
            Tree(payload); Validate(payload, "res");
            var body = Utf8.GetBytes(payload.GetRawText()); if (body.Length > MaxBody) throw new SapiException();
            return SealReserved(kid, "res", body, record);
        };
    }
    private string SealReserved(string kid, string direction, byte[] body, KeyRecord record)
    {
        var header = new Dictionary<string, object> {
            ["alg"] = "dir", ["enc"] = "A256GCM", ["typ"] = "sapi+jwe", ["kid"] = kid,
            ["sapi"] = "0.1", ["dir"] = direction, ["svc"] = Service, ["crit"] = new[] {"sapi", "dir", "svc"}
        };
        var protectedHeader = B64(JsonSerializer.SerializeToUtf8Bytes(header));
        var iv = RandomNumberGenerator.GetBytes(12); var ciphertext = new byte[body.Length]; var tag = new byte[16];
        using var aes = new AesGcm(Derive(kid, direction, record), 16);
        aes.Encrypt(iv, body, ciphertext, tag, Encoding.ASCII.GetBytes(protectedHeader));
        return string.Join('.', protectedHeader, "", B64(iv), B64(ciphertext), B64(tag));
    }
    public (string Kid, JsonElement Payload) Open(string wire, string direction)
    {
        try
        {
            if (wire.Length > MaxWire || (direction != "req" && direction != "res")) throw new SapiException();
            foreach (var c in wire) if (c > 127) throw new SapiException();
            var parts = wire.Split('.'); if (parts.Length != 5 || parts[1] != "") throw new SapiException();
            var rawHeader = UnB64(parts[0]); if (rawHeader.Length > 1024) throw new SapiException();
            var header = Parse(rawHeader); Exact(header, HeaderFields);
            var expected = new Dictionary<string, string> { ["alg"] = "dir", ["enc"] = "A256GCM", ["typ"] = "sapi+jwe", ["sapi"] = "0.1", ["dir"] = direction, ["svc"] = Service };
            foreach (var pair in expected) if (header.GetProperty(pair.Key).GetString() != pair.Value) throw new SapiException();
            var kid = header.GetProperty("kid").GetString()!; if (!ValidName(kid)) throw new SapiException();
            var crit = header.GetProperty("crit");
            if (crit.ValueKind != JsonValueKind.Array || crit.GetArrayLength() != 3 || crit[0].GetString() != "sapi" || crit[1].GetString() != "dir" || crit[2].GetString() != "svc") throw new SapiException();
            var iv = UnB64(parts[2]); var cipher = UnB64(parts[3]); var tag = UnB64(parts[4]);
            if (iv.Length != 12 || tag.Length != 16 || cipher.Length > MaxBody) throw new SapiException();
            var plain = new byte[cipher.Length]; using var aes = new AesGcm(Derive(kid, direction), 16);
            aes.Decrypt(iv, cipher, tag, plain, Encoding.ASCII.GetBytes(parts[0]));
            var payload = Parse(plain); Validate(payload, direction); return (kid, payload);
        }
        catch { throw new SapiException(); }
    }
    public RequestContext Request(string kid, string operation, JsonElement data)
    {
        var now = Now; var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var payload = Json(new Dictionary<string, object> { ["id"] = id, ["iat"] = now, ["exp"] = now + 60, ["op"] = operation, ["data"] = data });
        return new RequestContext(Seal(kid, "req", payload), kid, id);
    }
    public JsonElement AcceptResponse(RequestContext context, string wire)
    {
        lock (context.Sync)
        {
            if (context.Consumed) throw new SapiException("response_replay");
            var (kid, payload) = Open(wire, "res");
            if (kid != context.Kid || payload.GetProperty("id").GetString() != context.Id || payload.GetProperty("req").GetString() != Digest(context.Wire)) throw new SapiException();
            context.Consumed = true; return payload;
        }
    }
}
