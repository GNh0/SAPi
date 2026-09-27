package io.github.gnh0.sapi;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
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
        SSLContext context = null;
        if (caFile != null) {
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType()); trust.load(null, null);
            try (InputStream stream = new FileInputStream(caFile)) { trust.setCertificateEntry("sapi-ca", CertificateFactory.getInstance("X.509").generateCertificate(stream)); }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(trust);
            context = SSLContext.getInstance("TLS"); context.init(null, factory.getTrustManagers(), null);
        }
        Transport.Response response=Transport.post(url,wire.getBytes(StandardCharsets.US_ASCII),"application/sapi+jwe","application/sapi+jwe",Sapi.MAX_WIRE,context,timeout);
        if(response.status!=200)throw new SapiException("transport_error");for(byte b:response.body)if((b&255)>127)throw new SapiException("transport_error");return new String(response.body,StandardCharsets.US_ASCII);
    }
}
