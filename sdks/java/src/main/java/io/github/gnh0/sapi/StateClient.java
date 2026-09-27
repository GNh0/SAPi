package io.github.gnh0.sapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.concurrent.*;
import javax.net.ssl.*;
import static io.github.gnh0.sapi.Sapi.*;

public final class StateClient implements KeyProvider, ReplayStore {
    private final HttpClient client; private final URI endpoint; private final Duration timeout;
    public StateClient(URI origin, File caFile, File certificate, File privateKey) throws Exception {
        this(origin, caFile, certificate, privateKey, Duration.ofSeconds(10));
    }
    public StateClient(URI origin, File caFile, File certificate, File privateKey, Duration timeout) throws Exception {
        if (!"https".equals(origin.getScheme()) || !(origin.getPath().isEmpty() || origin.getPath().equals("/")) || origin.getQuery() != null || origin.getFragment() != null || origin.getUserInfo() != null) throw new IllegalArgumentException("HTTPS authority origin required");
        endpoint = origin.resolve("/v1/state"); this.timeout = timeout;
        CertificateFactory certificates = CertificateFactory.getInstance("X.509");
        KeyStore trust = KeyStore.getInstance("PKCS12"); trust.load(null, null);
        try (var input = Files.newInputStream(caFile.toPath())) {
            int n = 0; for (var cert : certificates.generateCertificates(input)) trust.setCertificateEntry("ca-" + n++, cert);
        }
        java.security.cert.Certificate[] chain;
        try (var input = Files.newInputStream(certificate.toPath())) {chain = certificates.generateCertificates(input).toArray(new java.security.cert.Certificate[0]);}
        String pem = Files.readString(privateKey.toPath()).replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem); java.security.PrivateKey key;
        try {key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded));}
        catch (Exception e) {key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));}
        KeyStore identity = KeyStore.getInstance("PKCS12"); identity.load(null, null); char[] password = new char[0];
        identity.setKeyEntry("identity", key, password, chain);
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(identity, password);
        TrustManagerFactory tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tm.init(trust);
        SSLContext context = SSLContext.getInstance("TLS"); context.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        client = HttpClient.newBuilder().sslContext(context).followRedirects(HttpClient.Redirect.NEVER).connectTimeout(timeout).build();
    }
    public JsonNode call(String action, ObjectNode parameters) {
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            ObjectNode value = parameters.deepCopy(); value.put("action", action);
            HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(timeout).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(encode(value))).build();
            pending = client.sendAsync(request, info -> new BoundedBody());
            HttpResponse<byte[]> response = pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!response.headers().firstValue("Content-Type").orElse("").equals("application/json")) throw new SapiException("state_unavailable");
            JsonNode result = parse(response.body()); if (result.has("error")) throw new SapiException(text(result.get("error")));
            if (response.statusCode() != 200) throw new SapiException("state_unavailable"); return result;
        } catch (SapiException e) {throw e;}
        catch (Exception e) {if (pending != null) pending.cancel(true); throw new SapiException("state_unavailable");}
    }
    private KeyRecord record(JsonNode value) {
        HashSet<String> scopes = new HashSet<>(); for (JsonNode scope : value.get("scopes")) scopes.add(text(scope));
        return new KeyRecord(unb64(text(value.get("master"))), text(value.get("subject")), scopes);
    }
    public KeyRecord get(String service, String kid) {return record(call("key", object().put("service", service).put("kid", kid)));}
    public KeyRecord reserve(String service, String kid, String direction) {return record(call("reserve", object().put("service", service).put("kid", kid).put("direction", direction)));}
    public boolean claim(String name, long expiry, long now) {return call("claim", object().put("name", name).put("expiry", expiry)).get("claimed").booleanValue();}
    public RequestContext request(Codec codec, String subject, String operation, JsonNode data) {
        for (int n = 0; ; n++) {
            String kid = text(call("active", object().put("service", codec.service).put("subject", subject)).get("kid"));
            try {return codec.request(kid, operation, data);}
            catch (SapiException e) {if (n >= 2 || !(e.code.equals("key_retired") || e.code.equals("key_rotation_required"))) throw e;}
        }
    }
    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> future = new CompletableFuture<>(); private final ByteArrayOutputStream bytes = new ByteArrayOutputStream(); private Flow.Subscription subscription;
        public CompletionStage<byte[]> getBody() {return future;}
        public void onSubscribe(Flow.Subscription value) {subscription = value; value.request(1);}
        public void onNext(java.util.List<java.nio.ByteBuffer> buffers) {
            try {
                for (var buffer : buffers) {if (bytes.size() + buffer.remaining() > 1048576) throw new SapiException("state_unavailable"); byte[] chunk = new byte[buffer.remaining()]; buffer.get(chunk); bytes.write(chunk);}
                subscription.request(1);
            } catch (Exception e) {subscription.cancel(); future.completeExceptionally(e);}
        }
        public void onError(Throwable error) {future.completeExceptionally(error);}
        public void onComplete() {future.complete(bytes.toByteArray());}
    }
}
