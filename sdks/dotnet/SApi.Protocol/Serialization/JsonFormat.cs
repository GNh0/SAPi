using System.Text;
using System.Text.Json;

namespace SApi.Protocol;

internal static class JsonFormat
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public static void ValidString(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (!char.IsSurrogate(value[i])) continue;
            if (!char.IsHighSurrogate(value[i]) || i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1])) throw new SapiException();
            i++;
        }
    }
    public static void Tree(JsonElement value, int depth = 0)
    {
        if (depth > 32) throw new SapiException();
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject())
                {
                    if (!seen.Add(property.Name)) throw new SapiException();
                    ValidString(property.Name); Tree(property.Value, depth + 1);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray()) Tree(item, depth + 1);
                break;
            case JsonValueKind.String: ValidString(value.GetString()!); break;
            case JsonValueKind.Number:
                var number = value.GetDouble();
                if (!Runtime.Finite(number) || (Math.Floor(number) == number && Math.Abs(number) > 9007199254740991d)) throw new SapiException();
                break;
            case JsonValueKind.True: case JsonValueKind.False: case JsonValueKind.Null: break;
            default: throw new SapiException();
        }
    }
    public static JsonElement Parse(byte[] bytes)
    {
        try
        {
            // Decode strictly: replacement of malformed UTF-8 is never allowed.
            using var document = JsonDocument.Parse(Utf8.GetString(bytes), new JsonDocumentOptions { MaxDepth = 33 });
            Tree(document.RootElement); return document.RootElement.Clone();
        }
        catch { throw new SapiException(); }
    }
    public static JsonElement Json(object value) => Parse(JsonSerializer.SerializeToUtf8Bytes(value));
    public static void Exact(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new SapiException();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) seen.Add(property.Name);
        if (seen.Count != fields.Length) throw new SapiException();
        foreach (var field in fields) if (!seen.Contains(field)) throw new SapiException();
    }
    public static long Integer(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Number) throw new SapiException();
        var number = value.GetDouble();
        if (!Runtime.Finite(number) || number < 0 || number > 9007199254740991d || Math.Floor(number) != number) throw new SapiException();
        return (long)number;
    }
}
