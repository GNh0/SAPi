using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SApi.Protocol;

/// <summary>Closed, bounded schemas from SAPI Application Security Profile v1.</summary>
public sealed class Schema
{
    private const double Safe = 9007199254740991;
    private readonly JsonElement definition;
    private int nodes;
    private static readonly Regex Field = new("\\A[A-Za-z][A-Za-z0-9_]{0,63}\\z", RegexOptions.CultureInvariant);
    private static readonly Regex Identifier = new("\\A[A-Za-z0-9][A-Za-z0-9_.:-]*\\z", RegexOptions.CultureInvariant);
    private static readonly Regex Uuid = new("\\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\\z", RegexOptions.CultureInvariant);
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public Schema(JsonElement definition, bool rootObject = false)
    {
        this.definition = Codec.Parse(Encoding.UTF8.GetBytes(definition.GetRawText()));
        Compile(this.definition, 0);
        if (rootObject && Type(this.definition) != "object") throw new ArgumentException("object schema required");
    }
    private static string Type(JsonElement s) => s.GetProperty("type").GetString()!;
    private static double Number(JsonElement s, string key, double fallback) => s.TryGetProperty(key, out var v) ? v.GetDouble() : fallback;
    private static bool Integer(double n) => Runtime.Finite(n) && Math.Abs(n) <= Safe && n == Math.Truncate(n);
    private static void Bounds(JsonElement s, string lower, string upper, double fallback, double cap)
    {
        var lo = Number(s, lower, 0); var hi = Number(s, upper, fallback);
        if (!Integer(lo) || !Integer(hi) || lo < 0 || lo > hi || hi > cap) throw new ArgumentException("invalid bounds");
    }
    private void Compile(JsonElement s, int depth)
    {
        if (++nodes > 256 || depth > 16 || s.ValueKind != JsonValueKind.Object || !s.TryGetProperty("type", out var t) || t.ValueKind != JsonValueKind.String) throw new ArgumentException("bounded schema required");
        string[] allowed = Type(s) switch {
            "object" => ["properties", "optional"], "array" => ["items", "minItems", "maxItems"],
            "string" => ["minBytes", "maxBytes", "format", "enum"], "integer" or "number" => ["min", "max"],
            "boolean" or "null" => [], _ => throw new ArgumentException("unsupported schema")};
        if (s.EnumerateObject().Any(p => p.Name != "type" && !allowed.Contains(p.Name))) throw new ArgumentException("unsupported schema property");
        switch (Type(s))
        {
            case "object":
                var props = s.GetProperty("properties");
                if (props.ValueKind != JsonValueKind.Object || props.EnumerateObject().Count() > 64 || props.EnumerateObject().Any(p => !Field.IsMatch(p.Name) || p.Name is "constructor" or "prototype" or "__proto__")) throw new ArgumentException("safe properties required");
                if (s.TryGetProperty("optional", out var optional))
                {
                    if (optional.ValueKind != JsonValueKind.Array || optional.EnumerateArray().Any(k => k.ValueKind != JsonValueKind.String || !props.TryGetProperty(k.GetString()!, out _)) || optional.EnumerateArray().Select(k => k.GetString()).Distinct().Count() != optional.GetArrayLength()) throw new ArgumentException("invalid optional");
                }
                foreach (var prop in props.EnumerateObject()) Compile(prop.Value, depth + 1);
                break;
            case "array": Bounds(s, "minItems", "maxItems", 16, 64); Compile(s.GetProperty("items"), depth + 1); break;
            case "string":
                Bounds(s, "minBytes", "maxBytes", 4096, 65536);
                if (s.TryGetProperty("format", out var format) && (format.ValueKind != JsonValueKind.String || format.GetString() is not ("text" or "identifier" or "uuid"))) throw new ArgumentException("unsupported format");
                if (s.TryGetProperty("enum", out var values) && (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() is < 1 or > 64 || values.EnumerateArray().Any(v => v.ValueKind != JsonValueKind.String || !StringValid(s, v.GetString()!)) || values.EnumerateArray().Select(v => v.GetString()).Distinct().Count() != values.GetArrayLength())) throw new ArgumentException("invalid enum");
                break;
            case "integer": case "number":
                var lo = Number(s, "min", -Safe); var hi = Number(s, "max", Safe);
                if (!Runtime.Finite(lo) || !Runtime.Finite(hi) || Math.Abs(lo) > Safe || Math.Abs(hi) > Safe || lo > hi || (Type(s) == "integer" && (!Integer(lo) || !Integer(hi)))) throw new ArgumentException("invalid numeric bounds");
                break;
        }
    }
    private static bool StringValid(JsonElement s, string value)
    {
        int count; try {count = Utf8.GetByteCount(value);} catch (EncoderFallbackException) {return false;}
        if (count < Number(s, "minBytes", 0) || count > Number(s, "maxBytes", 4096) || value.Any(c => c < 32 && c is not ('\t' or '\n' or '\r') || c == 127)) return false;
        var format = s.TryGetProperty("format", out var f) ? f.GetString() : "text";
        return format switch {"identifier" => Identifier.IsMatch(value), "uuid" => Uuid.IsMatch(value), _ => true};
    }
    public bool Validate(JsonElement value) {try {return Validate(definition, value);} catch {return false;}}
    private static bool Validate(JsonElement s, JsonElement v)
    {
        switch (Type(s))
        {
            case "object":
                if (v.ValueKind != JsonValueKind.Object) return false;
                var props = s.GetProperty("properties"); var optional = s.TryGetProperty("optional", out var o) ? new HashSet<string>(o.EnumerateArray().Select(k => k.GetString()!), StringComparer.Ordinal) : [];
                return v.EnumerateObject().All(p => props.TryGetProperty(p.Name, out var child) && Validate(child, p.Value)) && props.EnumerateObject().All(p => optional.Contains(p.Name) || v.TryGetProperty(p.Name, out _));
            case "array": return v.ValueKind == JsonValueKind.Array && v.GetArrayLength() >= Number(s, "minItems", 0) && v.GetArrayLength() <= Number(s, "maxItems", 16) && v.EnumerateArray().All(item => Validate(s.GetProperty("items"), item));
            case "string": return v.ValueKind == JsonValueKind.String && StringValid(s, v.GetString()!) && (!s.TryGetProperty("enum", out var values) || values.EnumerateArray().Any(x => x.GetString() == v.GetString()));
            case "integer": case "number": return v.ValueKind == JsonValueKind.Number && Runtime.Finite(v.GetDouble()) && (Type(s) != "integer" || Integer(v.GetDouble())) && v.GetDouble() >= Number(s, "min", -Safe) && v.GetDouble() <= Number(s, "max", Safe);
            case "boolean": return v.ValueKind is JsonValueKind.True or JsonValueKind.False;
            default: return v.ValueKind == JsonValueKind.Null;
        }
    }
}
