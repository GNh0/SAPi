namespace SApi.Protocol;

public interface IReplayStore
{
    // MUST atomically reserve until expiry. Storage failure MUST throw, never return true.
    bool Claim(string key, long expiry, long now);
}
