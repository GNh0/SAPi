import io.github.gnh0.sapi.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public final class JavaDriver {
    static Codec codec;
    static SecureServer server;
    static StateClient state;
    static Map<String, RequestContext> contexts = new HashMap<>();
    static AtomicInteger executions = new AtomicInteger();
    static boolean oneString(JsonNode d, String key) {return d.isObject() && d.size() == 1 && d.has(key) && d.get(key).isTextual();}
    static JsonNode invoke(JsonNode c) throws Exception {
        String action = c.get("action").textValue(); String slot = c.path("slot").asText("default");
        if (action.equals("init")) {
            Map<String, KeyRecord> keys = new HashMap<>();
            Iterator<Map.Entry<String, JsonNode>> fields = c.get("keys").properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> f = fields.next(); Set<String> scopes = new HashSet<>();
                for (JsonNode s : f.getValue().get("scopes")) scopes.add(s.textValue());
                keys.put(f.getKey(), new KeyRecord(Sapi.unb64(f.getValue().get("key").textValue()), f.getValue().get("subject").textValue(), scopes));
            }
            state = null;
            if (c.has("state")) {
                JsonNode s = c.get("state"); state = new StateClient(java.net.URI.create(s.get("url").textValue()), new File(s.get("ca_file").textValue()), new File(s.get("certificate").textValue()), new File(s.get("private_key").textValue()), java.time.Duration.ofMillis((long)(s.path("timeout").asDouble(10) * 1000)));
            }
            KeyProvider provider = state != null ? state : new StaticKeyProvider(keys);
            codec = c.hasNonNull("now") ? new Codec(c.path("service").asText("demo"), provider, () -> c.get("now").longValue()) : new Codec(c.path("service").asText("demo"), provider);
            ReplayStore store = c.path("store").asText().equals("fail") ? (k, exp, now) -> {throw new RuntimeException("storage unavailable");} : new MemoryReplayStore(c.path("capacity").asInt(10000));
            if (state != null) store = state;
            server = new SecureServer(codec, store); contexts.clear(); executions.set(0);
            server.register("echo", "echo", d -> oneString(d, "message") && d.get("message").textValue().getBytes(StandardCharsets.UTF_8).length <= 4096,
                (p, d) -> true, (p, d) -> {executions.incrementAndGet(); return d;});
            server.register("own", "orders", d -> oneString(d, "owner"), (p, d) -> p.subject.equals(d.get("owner").textValue()), (p, d) -> {executions.incrementAndGet(); return d;});
            server.register("fail", "echo", d -> true, (p, d) -> true, (p, d) -> {throw new RuntimeException("private internal details");});
            return Sapi.object().put("ready", true);
        }
        if (action.equals("derive")) {
            StringBuilder hex = new StringBuilder(); for (byte b : codec.derive(c.get("kid").textValue(), c.get("dir").textValue())) hex.append(String.format(Locale.ROOT, "%02x", b & 255));
            return Sapi.object().put("key", hex.toString());
        }
        if (action.equals("seal")) return Sapi.object().put("wire", codec.seal(c.get("kid").textValue(), c.get("dir").textValue(), c.get("payload")));
        if (action.equals("open")) {Opened o = codec.open(c.get("wire").textValue(), c.get("dir").textValue()); ObjectNode r = Sapi.object().put("kid", o.kid); r.set("payload", o.payload); return r;}
        if (action.equals("request")) {RequestContext ctx = c.has("subject") ? state.request(codec, c.get("subject").textValue(), c.get("op").textValue(), c.get("data")) : codec.request(c.get("kid").textValue(), c.get("op").textValue(), c.get("data")); contexts.put(slot, ctx); return Sapi.object().put("wire", ctx.wire);}
        if (action.equals("accept")) {ObjectNode r = Sapi.object(); r.set("payload", codec.acceptResponse(contexts.get(slot), c.get("wire").textValue())); return r;}
        if (action.equals("handle")) return Sapi.object().put("wire", server.handle(c.get("wire").textValue()));
        if (action.equals("http")) {
            try {return Sapi.object().put("wire", io.github.gnh0.sapi.HttpBinding.exchange(java.net.URI.create(c.get("url").textValue()), c.get("wire").textValue(), c.has("ca") ? new File(c.get("ca").textValue()) : null, java.time.Duration.ofMillis(c.path("timeout_ms").asLong(30000))));}
            catch (Exception e) {return Sapi.object().put("error", "transport_error");}
        }
        if (action.equals("stats")) return Sapi.object().put("executions", executions.get());
        if (action.equals("parallel")) {
            ExecutorService pool = Executors.newFixedThreadPool(8);
            try {
                List<Future<String>> jobs = new ArrayList<>(); for (int i = 0; i < 16; i++) jobs.add(pool.submit(() -> server.handle(c.get("wire").textValue())));
                ObjectNode r = Sapi.object(); var wires = r.putArray("wires"); for (Future<String> job : jobs) wires.add(job.get()); return r;
            } finally {pool.shutdown();}
        }
        if (action.equals("bad_registration")) {
            try {server.register("bad", "echo", d -> true, null, (p, d) -> d); return Sapi.object().put("rejected", false);}
            catch (IllegalArgumentException e) {return Sapi.object().put("rejected", true);}
        }
        throw new SapiException();
    }
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
        String line;
        while ((line = in.readLine()) != null) {
            JsonNode result;
            try {result = invoke(Sapi.parse(line.getBytes(StandardCharsets.UTF_8)));}
            catch (SapiException e) {result = Sapi.object().put("error", e.code);}
            catch (Exception e) {result = Sapi.object().put("error", "invalid_message");}
            out.println(new String(Sapi.encode(result), StandardCharsets.UTF_8));
        }
    }
}
