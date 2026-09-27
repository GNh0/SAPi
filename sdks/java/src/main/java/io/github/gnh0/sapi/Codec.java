package io.github.gnh0.sapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static io.github.gnh0.sapi.Sapi.*;

public final class Codec {
    public final String service;
    private final KeyProvider keys;
    private final LongSupplier clock;
    public Codec(String service, Map<String, KeyRecord> keys) { this(service, keys, () -> System.currentTimeMillis() / 1000); }
    public Codec(String service, Map<String, KeyRecord> keys, LongSupplier clock) { this(service, new StaticKeyProvider(keys), clock); }
    public Codec(String service, KeyProvider keys) { this(service, keys, () -> System.currentTimeMillis() / 1000); }
    public Codec(String service, KeyProvider keys, LongSupplier clock) {
        if (!name(service) || keys == null) throw new IllegalArgumentException("service and keys required");
        this.service = service; this.keys = keys; this.clock = clock;
    }
    public long now() { return clock.getAsLong(); }
    public KeyRecord principal(String kid) { return keys.get(service, kid); }
    public byte[] derive(String kid, String direction) {
        if (!Set.of("req", "res").contains(direction)) throw new SapiException();
        return derive(kid, direction, principal(kid));
    }
    private byte[] derive(String kid, String direction, KeyRecord record) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(utf8("SAPI/0.1 HKDF-SHA-256"), "HmacSHA256"));
            byte[] prk = mac.doFinal(record.master);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] info = utf8("SAPI/0.1|" + service + "|" + kid + "|" + direction);
            byte[] input = Arrays.copyOf(info, info.length + 1); input[input.length - 1] = 1;
            return mac.doFinal(input);
        } catch (Exception e) { throw new SapiException(); }
    }
    private void validate(JsonNode p, String direction) {
        if (direction.equals("req")) {
            exact(p, "id", "iat", "exp", "op", "data"); if (!name(text(p.get("op")))) throw new SapiException();
        } else {
            if (p.get("ok") == null || !p.get("ok").isBoolean()) throw new SapiException(); boolean ok = p.get("ok").booleanValue();
            exact(p, "id", "iat", "exp", "req", "ok", ok ? "data" : "error");
            if (unb64(text(p.get("req"))).length != 32 || (!ok && !name(text(p.get("error"))))) throw new SapiException();
        }
        if (!text(p.get("id")).matches("[0-9a-f]{32}") || (p.has("data") && !p.get("data").isObject())) throw new SapiException();
        long issued = integer(p.get("iat")), expiry = integer(p.get("exp")), now = now();
        if (expiry - issued < 1 || expiry - issued > 60 || issued > now + 5 || now >= expiry) throw new SapiException();
    }
    public String seal(String kid, String direction, JsonNode payload) {
        if (!Set.of("req", "res").contains(direction)) throw new SapiException(); validate(payload, direction);
        byte[] body = encode(payload); if (body.length > MAX_BODY) throw new SapiException();
        return sealReserved(kid, direction, body, keys.reserve(service, kid, direction));
    }
    java.util.function.Function<JsonNode, String> prepareResponse(String kid) {
        KeyRecord record = keys.reserve(service, kid, "res"); java.util.concurrent.atomic.AtomicBoolean used = new java.util.concurrent.atomic.AtomicBoolean();
        return payload -> {
            if (used.getAndSet(true)) throw new SapiException("reservation_used");
            validate(payload, "res"); byte[] body = encode(payload); if (body.length > MAX_BODY) throw new SapiException();
            return sealReserved(kid, "res", body, record);
        };
    }
    private String sealReserved(String kid, String direction, byte[] body, KeyRecord record) {
        ObjectNode h = object().put("alg", "dir").put("enc", "A256GCM").put("typ", "sapi+jwe").put("kid", kid)
            .put("sapi", "0.1").put("dir", direction).put("svc", service);
        h.putArray("crit").add("sapi").add("dir").add("svc"); String protectedHeader = b64(encode(h));
        byte[] iv = new byte[12]; RANDOM.nextBytes(iv);
        try {
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derive(kid, direction, record), "AES"), new GCMParameterSpec(128, iv));
            aes.updateAAD(utf8(protectedHeader)); byte[] encrypted = aes.doFinal(body);
            return String.join(".", protectedHeader, "", b64(iv), b64(Arrays.copyOf(encrypted, encrypted.length - 16)), b64(Arrays.copyOfRange(encrypted, encrypted.length - 16, encrypted.length)));
        } catch (Exception e) { throw new SapiException(); }
    }
    public Opened open(String wire, String direction) {
        try {
            if (wire == null || wire.length() > MAX_WIRE || !Set.of("req", "res").contains(direction)) throw new SapiException();
            for (int i = 0; i < wire.length(); i++) if (wire.charAt(i) > 127) throw new SapiException();
            String[] parts = wire.split("\\.", -1); if (parts.length != 5 || !parts[1].isEmpty()) throw new SapiException();
            byte[] header = unb64(parts[0]); if (header.length > 1024) throw new SapiException(); JsonNode h = parse(header);
            exact(h, "alg", "enc", "typ", "kid", "sapi", "dir", "svc", "crit");
            if (!text(h.get("alg")).equals("dir") || !text(h.get("enc")).equals("A256GCM") || !text(h.get("typ")).equals("sapi+jwe") || !text(h.get("sapi")).equals("0.1") || !text(h.get("dir")).equals(direction) || !text(h.get("svc")).equals(service)) throw new SapiException();
            String kid = text(h.get("kid")); if (!name(kid)) throw new SapiException(); JsonNode crit = h.get("crit");
            if (!crit.isArray() || crit.size() != 3 || !text(crit.get(0)).equals("sapi") || !text(crit.get(1)).equals("dir") || !text(crit.get(2)).equals("svc")) throw new SapiException();
            byte[] iv = unb64(parts[2]), encrypted = unb64(parts[3]), tag = unb64(parts[4]);
            if (iv.length != 12 || tag.length != 16 || encrypted.length > MAX_BODY) throw new SapiException();
            byte[] joined = Arrays.copyOf(encrypted, encrypted.length + 16); System.arraycopy(tag, 0, joined, encrypted.length, 16);
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derive(kid, direction), "AES"), new GCMParameterSpec(128, iv));
            aes.updateAAD(utf8(parts[0])); JsonNode p = parse(aes.doFinal(joined)); validate(p, direction); return new Opened(kid, p);
        } catch (Exception e) { throw new SapiException(); }
    }
    public RequestContext request(String kid, String operation, JsonNode data) {
        byte[] raw = new byte[16]; RANDOM.nextBytes(raw); StringBuilder id = new StringBuilder();
        for (byte b : raw) id.append(String.format(Locale.ROOT, "%02x", b & 255)); long now = now();
        ObjectNode p = object().put("id", id.toString()).put("iat", now).put("exp", now + 60).put("op", operation); p.set("data", data.deepCopy());
        return new RequestContext(seal(kid, "req", p), kid, id.toString());
    }
    public JsonNode acceptResponse(RequestContext context, String wire) {
        synchronized (context) {
            if (context.consumed) throw new SapiException("response_replay"); Opened o = open(wire, "res");
            if (!o.kid.equals(context.kid) || !text(o.payload.get("id")).equals(context.id) || !text(o.payload.get("req")).equals(digest(context.wire))) throw new SapiException();
            context.consumed = true; return o.payload;
        }
    }
}
