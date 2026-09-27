#if !NET6_0_OR_GREATER
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace SApi.Protocol;

internal static class LegacyTransport
{
    internal static (X509Certificate2 Root, X509Certificate2 Identity) Pem(string caFile, string certificate, string privateKey)
    {
        var parser = new X509CertificateParser();
        var root = new X509Certificate2(parser.ReadCertificate(File.ReadAllBytes(caFile)).GetEncoded());
        try
        {
            using var reader = new StreamReader(privateKey); var value = new PemReader(reader).ReadObject();
            var key = value is AsymmetricCipherKeyPair pair ? pair.Private : value as AsymmetricKeyParameter;
            if (key == null || !key.IsPrivate) throw new ArgumentException("private PEM key required");
            var cert = parser.ReadCertificate(File.ReadAllBytes(certificate));
            var store = new Pkcs12StoreBuilder().Build(); store.SetKeyEntry("sapi", new AsymmetricKeyEntry(key), new[] {new X509CertificateEntry(cert)});
            using var bytes = new MemoryStream(); store.Save(bytes, Array.Empty<char>(), new SecureRandom());
            return (root, new X509Certificate2(bytes.ToArray(), "", X509KeyStorageFlags.DefaultKeySet));
        }
        catch {root.Dispose(); throw;}
    }
    private static bool Trusted(X509Certificate2? certificate, X509Chain? supplied, SslPolicyErrors errors, X509Certificate2 root)
    {
        if (certificate == null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.Add(root);
        if (supplied != null) foreach (X509ChainElement element in supplied.ChainElements) chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromMilliseconds(1);
        // This policy property exists on newer hosts even when the portable reference API lacks it.
        typeof(X509ChainPolicy).GetProperty("DisableCertificateDownloads")?.SetValue(chain.ChainPolicy, true);
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        if (!chain.Build(certificate) || chain.ChainElements.Count == 0) return false;
        foreach (var status in chain.ChainStatus) if ((status.Status & ~X509ChainStatusFlags.UntrustedRoot) != 0) return false;
        // AllowUnknownCertificateAuthority only permits the caller's exact root, never arbitrary roots.
        return chain.ChainElements[chain.ChainElements.Count - 1].Certificate.RawData.SequenceEqual(root.RawData);
    }
    internal static async Task<(int Status, byte[] Body)> PostAsync(Uri url, byte[] body, string type, int limit,
        X509Certificate2? root, X509Certificate2? identity, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(timeout));
        var request = (HttpWebRequest)WebRequest.Create(url);
        request.Method = "POST"; request.ContentType = type; request.Accept = type; request.ContentLength = body.Length;
        request.AllowAutoRedirect = false; request.KeepAlive = false;
        request.Timeout = request.ReadWriteTimeout = Math.Max(1, (int)timeout.TotalMilliseconds);
        if (identity != null) request.ClientCertificates.Add(identity);
        if (root != null) request.ServerCertificateValidationCallback = (_, cert, chain, errors) =>
        {
            if (cert is X509Certificate2 native) return Trusted(native, chain, errors, root);
            if (cert == null) return false; using var imported = new X509Certificate2(cert); return Trusted(imported, chain, errors, root);
        };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(timeout);
        using var abort = deadline.Token.Register(request.Abort);
        using (var output = await request.GetRequestStreamAsync().ConfigureAwait(false)) await output.WriteAsync(body, 0, body.Length, deadline.Token).ConfigureAwait(false);
        HttpWebResponse response;
        try {response = (HttpWebResponse)await request.GetResponseAsync().ConfigureAwait(false);}
        catch (WebException e) when (e.Response is HttpWebResponse) {response = (HttpWebResponse)e.Response;}
        using (response)
        {
            if (response.ContentType.Split(';')[0] != type || response.ContentLength > limit || !string.IsNullOrEmpty(response.ContentEncoding)) throw new SapiException("transport_error");
            using var stream = response.GetResponseStream(); using var bytes = new MemoryStream(); var buffer = new byte[8192];
            while (true) {var n = await stream.ReadAsync(buffer, 0, buffer.Length, deadline.Token).ConfigureAwait(false); if (n == 0) break; if (bytes.Length + n > limit) throw new SapiException("transport_error"); bytes.Write(buffer, 0, n);}
            deadline.Token.ThrowIfCancellationRequested();
            if (response.ContentLength >= 0 && response.ContentLength != bytes.Length) throw new SapiException("transport_error");
            return ((int)response.StatusCode, bytes.ToArray());
        }
    }
}
#endif
