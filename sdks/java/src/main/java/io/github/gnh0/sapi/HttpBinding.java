package io.github.gnh0.sapi;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class HttpBinding {
    private HttpBinding() {}
    public static String exchange(URI url, String wire, File caFile) throws Exception {
        return exchange(url, wire, caFile, Duration.ofSeconds(30));
    }
    public static String exchange(URI url, String wire, File caFile, Duration timeout) throws Exception {
        if (!(url.getScheme().equals("http") || url.getScheme().equals("https")) || !"/sapi".equals(url.getPath()) || url.getQuery() != null || url.getFragment() != null || url.getUserInfo() != null) throw new IllegalArgumentException("HTTP(S) /sapi URL required");
        if (wire.length() > Sapi.MAX_WIRE) throw new SapiException();
        for (int i = 0; i < wire.length(); i++) if (wire.charAt(i) > 127) throw new SapiException();
        HttpClient.Builder builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(30));
        if (caFile != null) {
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType()); trust.load(null, null);
            try (InputStream stream = new FileInputStream(caFile)) { trust.setCertificateEntry("sapi-ca", CertificateFactory.getInstance("X.509").generateCertificate(stream)); }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(trust);
            SSLContext context = SSLContext.getInstance("TLS"); context.init(null, factory.getTrustManagers(), null); builder.sslContext(context);
        }
        // Default HttpClient endpoint identification checks the server hostname.
        HttpRequest request = HttpRequest.newBuilder(url).timeout(timeout).header("Content-Type", "application/sapi+jwe")
            .header("Accept", "application/sapi+jwe").POST(HttpRequest.BodyPublishers.ofString(wire, StandardCharsets.US_ASCII)).build();
        java.util.concurrent.CompletableFuture<HttpResponse<byte[]>> pending = builder.build().sendAsync(request, info -> {
            if (info.statusCode() != 200 || !info.headers().firstValue("Content-Type").orElse("").split(";")[0].equals("application/sapi+jwe"))
                return HttpResponse.BodySubscribers.replacing(new byte[0]);
            return HttpResponse.BodySubscribers.mapping(new LimitedSubscriber(), data -> data);
        });
        HttpResponse<byte[]> response;
        try { response = pending.get(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS); }
        catch (Exception e) { pending.cancel(true); throw e; }
        if (response.statusCode() != 200 || !response.headers().firstValue("Content-Type").orElse("").split(";")[0].equals("application/sapi+jwe")) throw new SapiException("transport_error");
        byte[] data = response.body(); for (byte b : data) if ((b & 255) > 127) throw new SapiException("transport_error");
        return new String(data, StandardCharsets.US_ASCII);
    }
    private static final class LimitedSubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final java.util.concurrent.CompletableFuture<byte[]> future = new java.util.concurrent.CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private java.util.concurrent.Flow.Subscription subscription;
        public java.util.concurrent.CompletionStage<byte[]> getBody() { return future; }
        public void onSubscribe(java.util.concurrent.Flow.Subscription value) { subscription = value; value.request(1); }
        public void onNext(java.util.List<java.nio.ByteBuffer> buffers) {
            try {
                for (java.nio.ByteBuffer b : buffers) {
                    if (bytes.size() + b.remaining() > Sapi.MAX_WIRE) throw new SapiException("transport_error");
                    byte[] chunk = new byte[b.remaining()]; b.get(chunk); bytes.write(chunk);
                }
                subscription.request(1);
            } catch (Exception e) { subscription.cancel(); future.completeExceptionally(e); }
        }
        public void onError(Throwable error) { future.completeExceptionally(error); }
        public void onComplete() { future.complete(bytes.toByteArray()); }
    }
}
