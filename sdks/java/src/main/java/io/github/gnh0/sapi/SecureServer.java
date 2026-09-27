package io.github.gnh0.sapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import static io.github.gnh0.sapi.Sapi.*;

public final class SecureServer {
    private static final class Operation {
        final String scope; final Predicate<JsonNode> validator; final BiPredicate<KeyRecord, JsonNode> policy; final BiFunction<KeyRecord, JsonNode, JsonNode> handler;
        Operation(String scope, Predicate<JsonNode> validator, BiPredicate<KeyRecord, JsonNode> policy, BiFunction<KeyRecord, JsonNode, JsonNode> handler) { this.scope = scope; this.validator = validator; this.policy = policy; this.handler = handler; }
    }
    private final Codec codec; private final ReplayStore replay;
    private final Map<String, Operation> operations = new ConcurrentHashMap<>();
    public SecureServer(Codec codec) { this(codec, new MemoryReplayStore()); }
    public SecureServer(Codec codec, ReplayStore replay) { this.codec = Objects.requireNonNull(codec); this.replay = Objects.requireNonNull(replay); }
    public void register(String name, String scope, Predicate<JsonNode> validator, BiPredicate<KeyRecord, JsonNode> policy, BiFunction<KeyRecord, JsonNode, JsonNode> handler) {
        if (!name(name) || !name(scope) || validator == null || policy == null || handler == null || operations.putIfAbsent(name, new Operation(scope, validator, policy, handler)) != null) throw new IllegalArgumentException("all callbacks required");
    }
    public String handle(String wire) {
        Opened opened = codec.open(wire, "req"); JsonNode request = opened.payload; KeyRecord principal = codec.principal(opened.kid); long now = codec.now();
        java.util.function.Function<JsonNode, String> finish = codec.prepareResponse(opened.kid);
        ObjectNode response = object().put("id", text(request.get("id"))).put("iat", now).put("exp", now + 60).put("req", digest(wire)).put("ok", false);
        try {
            if (!replay.claim(codec.service + "|" + opened.kid + "|" + text(request.get("id")), integer(request.get("exp")), codec.now())) throw new SapiException("replay");
            Operation o = operations.get(text(request.get("op"))); if (o == null) throw new SapiException("unknown_operation");
            if (!principal.hasScope(o.scope)) throw new SapiException("forbidden"); JsonNode data = request.get("data");
            if (!o.validator.test(data)) throw new SapiException("invalid_input"); if (!o.policy.test(principal, data)) throw new SapiException("forbidden");
            JsonNode result = o.handler.apply(principal, data);
            if (result == null || !result.isObject() || encode(result).length > MAX_BODY - 512) throw new SapiException();
            response.put("ok", true); response.set("data", result);
        } catch (SapiException e) { response.put("error", Set.of("replay", "replay_capacity", "unknown_operation", "forbidden", "invalid_input").contains(e.code) ? e.code : "internal_error"); }
        catch (Exception e) { response.put("error", "internal_error"); }
        return finish.apply(response);
    }
}
