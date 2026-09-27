namespace SApi.Protocol;

public interface IReplayStore
{
    // MUST atomically reserve until expiry. Storage failure MUST throw, never return true.
    bool Claim(string key, long expiry, long now);
    bool Admit(string service, string kid, string subject, string operation, long now, int requests = 60, int period = 60);
}
