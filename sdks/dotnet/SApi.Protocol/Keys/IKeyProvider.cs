namespace SApi.Protocol;

public interface IKeyProvider
{
    KeyRecord Get(string service, string kid);
    KeyRecord Reserve(string service, string kid, string direction);
}

public sealed class StaticKeyProvider : IKeyProvider
{
    private readonly Dictionary<string, KeyRecord> keys;
    private readonly Dictionary<string, int> counts = new();
    private readonly object sync = new();
    public StaticKeyProvider(IReadOnlyDictionary<string, KeyRecord> records)
    {
        if (records.Count == 0 || records.Keys.Any(k => !Codec.ValidName(k))) throw new ArgumentException("valid keys required");
        keys = new(StringComparer.Ordinal); foreach (var record in records) keys.Add(record.Key, record.Value);
    }
    public KeyRecord Get(string service, string kid) => keys.TryGetValue(kid, out var value) ? value : throw new SapiException();
    public KeyRecord Reserve(string service, string kid, string direction)
    {
        var record = Get(service, kid);
        lock (sync)
        {
            var name = service + "|" + kid + "|" + direction;
            counts.TryGetValue(name, out var count);
            if (count >= 1048576) throw new SapiException("key_rotation_required");
            counts[name] = count + 1;
        }
        return record;
    }
}
