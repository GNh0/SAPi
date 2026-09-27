using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SApi.Protocol;

public static class HttpBinding
{
    // Explicit CA option adds a trusted root; hostname validation is always retained.
    public static async Task<string> ExchangeAsync(Uri url, string wire, X509Certificate2? trustedRoot = null,
        CancellationToken cancellationToken = default, TimeSpan? deadline = null)
    {
        if ((url.Scheme != "http" && url.Scheme != "https") || url.AbsolutePath != "/sapi" ||
            url.Query.Length != 0 || url.Fragment.Length != 0 || url.UserInfo.Length != 0) throw new ArgumentException("HTTP(S) /sapi URL required");
        if (wire.Length > Codec.MaxWire) throw new SapiException();
        foreach (var ch in wire) if (ch > 127) throw new SapiException();
#if !NET6_0_OR_GREATER
        var response = await LegacyTransport.PostAsync(url, Encoding.ASCII.GetBytes(wire), "application/sapi+jwe", Codec.MaxWire, trustedRoot, null, deadline ?? TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false);
        if (response.Status != 200 || response.Body.Any(b => b > 127)) throw new SapiException("transport_error");
        return Encoding.ASCII.GetString(response.Body);
#else
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        if (trustedRoot != null)
        {
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            {
                if (cert == null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
                return chain.Build(cert);
            };
        }
        using var client = new HttpClient(handler) {Timeout = TimeSpan.FromSeconds(30)};
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(deadline ?? TimeSpan.FromSeconds(30));
        using var content = new ByteArrayContent(Encoding.ASCII.GetBytes(wire));
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/sapi+jwe");
        using var request = new HttpRequestMessage(HttpMethod.Post, url) {Content = content};
        request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/sapi+jwe"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if ((int)response.StatusCode != 200 || response.Content.Headers.ContentType?.MediaType != "application/sapi+jwe") throw new SapiException("transport_error");
        using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        var buffer = new byte[Codec.MaxWire + 1]; var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total), timeout.Token); if (n == 0) break; total += n;
        }
        if (total > Codec.MaxWire) throw new SapiException("transport_error");
        for (var i = 0; i < total; i++) if (buffer[i] > 127) throw new SapiException("transport_error");
        return Encoding.ASCII.GetString(buffer, 0, total);
#endif
    }
}
