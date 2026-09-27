namespace SApi.Protocol;

public sealed class MemoryReplayStore : IReplayStore
{
    private readonly Dictionary<string, long> entries = new();
    private readonly object sync = new();
    private readonly int capacity;
    public MemoryReplayStore(int capacity = 10000)
    {
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity)); this.capacity = capacity;
    }
    public bool Claim(string key, long expiry, long now)
    {
        lock (sync)
        {
            var expired = new List<string>();
            foreach (var pair in entries) if (pair.Value <= now) expired.Add(pair.Key);
            foreach (var keyToRemove in expired) entries.Remove(keyToRemove);
            if (entries.ContainsKey(key)) return false;
            if (entries.Count >= capacity) throw new SapiException("replay_capacity");
            entries[key] = expiry; return true;
        }
    }
}
