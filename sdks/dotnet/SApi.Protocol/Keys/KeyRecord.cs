namespace SApi.Protocol;

public sealed class KeyRecord
{
    internal byte[] Master { get; }
    private readonly HashSet<string> scopes;
    public string Subject { get; }
    public KeyRecord(byte[] master, string subject, IEnumerable<string>? scopes = null)
    {
        if (master.Length != 32 || !Codec.ValidName(subject)) throw new ArgumentException("32-byte key and subject required");
        Master = (byte[])master.Clone(); Subject = subject;
        this.scopes = new HashSet<string>(scopes ?? Array.Empty<string>(), StringComparer.Ordinal);
    }
    public bool HasScope(string scope) => scopes.Contains(scope);
}
