using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace SApi.Protocol;

/// <summary>Optional mTLS state authority adapter. Keys are fetched without a cache.</summary>
public sealed class StateClient : IKeyProvider, IReplayStore, IDisposable
{
#if NET6_0_OR_GREATER
    private readonly HttpClient client;
#else
    private readonly X509Certificate2 legacyRoot, legacyIdentity;
#endif
    private readonly Uri endpoint;
    private readonly TimeSpan timeout;
    private X509Certificate2? ownedRoot, ownedIdentity;
    public static StateClient FromPemFiles(Uri origin, string caFile, string certificate, string privateKey, TimeSpan? timeout = null)
    {
#if !NET6_0_OR_GREATER
        var (root, identity) = LegacyTransport.Pem(caFile, certificate, privateKey);
#else
        var root = X509Certificate2.CreateFromPem(File.ReadAllText(caFile));
        X509Certificate2? identity = null;
#endif
        try
        {
#if NET6_0_OR_GREATER
            identity = X509Certificate2.CreateFromPemFile(certificate, privateKey);
            if (OperatingSystem.IsWindows())
            {
                var imported = new X509Certificate2(identity.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.DefaultKeySet);
                identity.Dispose(); identity = imported;
            }
#endif
            return new StateClient(origin, root, identity, timeout) {ownedRoot = root, ownedIdentity = identity};
        }
        catch {root.Dispose(); identity?.Dispose(); throw;}
    }
    public StateClient(Uri origin, X509Certificate2 trustedRoot, X509Certificate2 clientIdentity, TimeSpan? timeout = null)
    {
        if (origin.Scheme != "https" || origin.AbsolutePath != "/" || origin.Query.Length != 0 || origin.Fragment.Length != 0 || origin.UserInfo.Length != 0) throw new ArgumentException("HTTPS authority origin required");
        if (!clientIdentity.HasPrivateKey) throw new ArgumentException("client private key required");
        endpoint = new Uri(origin, "/v1/state"); this.timeout = timeout ?? TimeSpan.FromSeconds(10);
#if !NET6_0_OR_GREATER
        legacyRoot = trustedRoot; legacyIdentity = clientIdentity;
#else
        var handler = new HttpClientHandler {AllowAutoRedirect = false, ClientCertificateOptions = ClientCertificateOption.Manual};
        handler.ClientCertificates.Add(clientIdentity);
        handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
        {
            if (cert == null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
            using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(trustedRoot); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true; chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            return chain.Build(cert);
        };
        client = new HttpClient(handler) {Timeout = Timeout.InfiniteTimeSpan};
#endif
    }
    public JsonElement Call(string action, Dictionary<string, object>? parameters = null) => CallAsync(action, parameters).GetAwaiter().GetResult();
    public async Task<JsonElement> CallAsync(string action, Dictionary<string, object>? parameters = null)
    {
        try
        {
            var value = parameters == null ? new Dictionary<string, object>() : new(parameters); value["action"] = action;
#if !NET6_0_OR_GREATER
            var response = await LegacyTransport.PostAsync(endpoint, JsonSerializer.SerializeToUtf8Bytes(value), "application/json", 1048576, legacyRoot, legacyIdentity, timeout, CancellationToken.None).ConfigureAwait(false);
            var result = Codec.Parse(response.Body);
            if (result.TryGetProperty("error", out var error)) throw new SapiException(error.GetString() ?? "state_unavailable");
            if (response.Status != 200) throw new SapiException("state_unavailable"); return result;
#else
            using var cancellation = new CancellationTokenSource(timeout);
            using var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value));
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) {Content = content};
            request.Headers.ConnectionClose = true;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token).ConfigureAwait(false);
            if (response.Content.Headers.ContentType?.MediaType != "application/json") throw new SapiException("state_unavailable");
            using var stream = await response.Content.ReadAsStreamAsync(cancellation.Token).ConfigureAwait(false);
            using var bytes = new MemoryStream(); var buffer = new byte[8192];
            while (true)
            {
                var n = await stream.ReadAsync(buffer, cancellation.Token).ConfigureAwait(false); if (n == 0) break;
                if (bytes.Length + n > 1048576) throw new SapiException("state_unavailable"); bytes.Write(buffer, 0, n);
            }
            var result = Codec.Parse(bytes.ToArray());
            if (result.TryGetProperty("error", out var error)) throw new SapiException(error.GetString() ?? "state_unavailable");
            if (!response.IsSuccessStatusCode) throw new SapiException("state_unavailable"); return result;
#endif
        }
        catch (SapiException e) {if (e.Code == "transport_error") throw new SapiException("state_unavailable"); throw;}
        catch {throw new SapiException("state_unavailable");}
    }
    private static KeyRecord Record(JsonElement value) => new(Codec.UnB64(value.GetProperty("master").GetString()!), value.GetProperty("subject").GetString()!, value.GetProperty("scopes").EnumerateArray().Select(s => s.GetString()!));
    public KeyRecord Get(string service, string kid) => Record(Call("key", new() {["service"] = service, ["kid"] = kid}));
    public KeyRecord Reserve(string service, string kid, string direction) => Record(Call("reserve", new() {["service"] = service, ["kid"] = kid, ["direction"] = direction}));
    public bool Claim(string name, long expiry, long now) => Call("claim", new() {["name"] = name, ["expiry"] = expiry}).GetProperty("claimed").GetBoolean();
    public bool Admit(string service, string kid, string subject, string operation, long now, int requests = 60, int period = 60) => Call("admit", new() {["service"]=service,["kid"]=kid,["operation"]=operation,["requests"]=requests,["period"]=period}).GetProperty("admitted").GetBoolean();
    public RequestContext Request(Codec codec, string subject, string operation, JsonElement data)
    {
        for (var n = 0; ; n++)
        {
            var kid = Call("active", new() {["service"] = codec.Service, ["subject"] = subject}).GetProperty("kid").GetString()!;
            try {return codec.Request(kid, operation, data);}
            catch (SapiException e) when (n < 2 && e.Code is "key_retired" or "key_rotation_required") { }
        }
    }
    public void Dispose()
    {
#if NET6_0_OR_GREATER
        client.Dispose();
#endif
        ownedRoot?.Dispose(); ownedIdentity?.Dispose();
    }
}
