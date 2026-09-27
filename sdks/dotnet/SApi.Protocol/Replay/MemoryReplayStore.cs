namespace SApi.Protocol;

public sealed class MemoryReplayStore : IReplayStore
{
    private readonly Dictionary<string, long> entries = new();
    private readonly Dictionary<string, (long Start, int Used, int Period)> rates = new();
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
    public bool Admit(string service, string kid, string subject, string operation, long now, int requests = 60, int period = 60)
    {
        lock (sync)
        {
            foreach(var stale in rates.Where(p=>p.Value.Start+p.Value.Period<=now).Select(p=>p.Key).ToArray()) rates.Remove(stale);
            var pending = new Dictionary<string, (long Start, int Used, int Period)>();
            foreach (var (name, count, seconds) in new[] {($"global|{service}|{subject}",60,60),($"op|{service}|{subject}|{operation}",requests,period)})
            {
                var (start,used,previous) = rates.TryGetValue(name, out var value) ? value : (now,0,seconds);
                if (now >= start + Math.Max(seconds,previous)) {start=now; used=0;previous=seconds;}
                if (used >= count) return false;
                if (!rates.ContainsKey(name) && rates.Count + pending.Keys.Count(k => !rates.ContainsKey(k)) >= 10000) throw new SapiException("rate_capacity");
                pending[name]=(start,used+1,Math.Max(seconds,previous));
            }
            foreach (var pair in pending) rates[pair.Key]=pair.Value;
            return true;
        }
    }
}
