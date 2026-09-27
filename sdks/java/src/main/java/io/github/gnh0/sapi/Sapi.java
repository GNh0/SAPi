package io.github.gnh0.sapi;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;

/** Experimental SAPI/0.1. Read spec/SECURITY.md before deploying. */
public final class Sapi {
    private Sapi() {}
    public static final int MAX_WIRE = 131072, MAX_BODY = 65536;
    static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(33).maxStringLength(MAX_BODY).maxNumberLength(100).build()).build())
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    static boolean name(String v) { return v != null && v.matches("[A-Za-z0-9_-]{1,64}"); }
    public static String b64(byte[] v) { return Base64.getUrlEncoder().withoutPadding().encodeToString(v); }
    public static byte[] unb64(String s) {
        try {
            if (s == null || !s.matches("[A-Za-z0-9_-]+")) throw new SapiException();
            byte[] raw = Base64.getUrlDecoder().decode(s);
            if (!b64(raw).equals(s)) throw new SapiException(); return raw;
        } catch (Exception e) { throw new SapiException(); }
    }
    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static void validString(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i); if (!Character.isSurrogate(c)) continue;
            if (!Character.isHighSurrogate(c) || i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(++i))) throw new SapiException();
        }
    }
    private static void tree(JsonNode v, int depth) {
        if (v == null || depth > 32) throw new SapiException();
        if (v.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = v.properties().iterator();
            while (fields.hasNext()) { Map.Entry<String, JsonNode> f = fields.next(); validString(f.getKey()); tree(f.getValue(), depth + 1); }
        } else if (v.isArray()) { for (JsonNode x : v) tree(x, depth + 1); }
        else if (v.isTextual()) validString(v.textValue());
        else if (v.isNumber()) {
            double n = v.doubleValue();
            if (!Double.isFinite(n) || (Math.floor(n) == n && Math.abs(n) > 9007199254740991d)) throw new SapiException();
        } else if (!v.isNull() && !v.isBoolean()) throw new SapiException();
    }
    public static JsonNode parse(byte[] raw) {
        try {
            String s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
            JsonNode value = JSON.readTree(s); tree(value, 0); return value;
        } catch (Exception e) { throw new SapiException(); }
    }
    public static byte[] encode(JsonNode v) {
        tree(v, 0); try { return JSON.writeValueAsBytes(v); } catch (Exception e) { throw new SapiException(); }
    }
    public static ObjectNode object() { return JSON.createObjectNode(); }
    public static String digest(String wire) {
        try { return b64(MessageDigest.getInstance("SHA-256").digest(wire.getBytes(StandardCharsets.US_ASCII))); }
        catch (Exception e) { throw new SapiException(); }
    }
    static void exact(JsonNode v, String... fields) {
        if (!v.isObject() || v.size() != fields.length) throw new SapiException();
        for (String f : fields) if (!v.has(f)) throw new SapiException();
    }
    static String text(JsonNode v) { if (v == null || !v.isTextual()) throw new SapiException(); return v.textValue(); }
    static long integer(JsonNode v) {
        if (v == null || !v.isNumber()) throw new SapiException(); double n = v.doubleValue();
        if (!Double.isFinite(n) || n < 0 || n > 9007199254740991d || Math.floor(n) != n) throw new SapiException(); return (long)n;
    }
}
