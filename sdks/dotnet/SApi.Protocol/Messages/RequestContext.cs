namespace SApi.Protocol;

public sealed class RequestContext
{
    public string Wire { get; }
    public string Kid { get; }
    public string Id { get; }
    internal bool Consumed;
    internal object Sync { get; } = new();
    internal RequestContext(string wire, string kid, string id) { Wire = wire; Kid = kid; Id = id; }
}
