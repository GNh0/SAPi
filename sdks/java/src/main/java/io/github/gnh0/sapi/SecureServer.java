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
        final String scope; final Schema input,output; final BiPredicate<KeyRecord, JsonNode> policy; final BiFunction<KeyRecord, JsonNode, JsonNode> handler; final int requests,period;
        Operation(String scope, JsonNode input,JsonNode output, BiPredicate<KeyRecord, JsonNode> policy, BiFunction<KeyRecord, JsonNode, JsonNode> handler,int requests,int period) {this.scope=scope;this.input=new Schema(input,true);this.output=new Schema(output,true);this.policy=policy;this.handler=handler;this.requests=requests;this.period=period;}
    }
    private final Codec codec; private final ReplayStore replay;
    private final Map<String, Operation> operations = new ConcurrentHashMap<>();
    public SecureServer(Codec codec) { this(codec, new MemoryReplayStore()); }
    public SecureServer(Codec codec, ReplayStore replay) { this.codec = Objects.requireNonNull(codec); this.replay = Objects.requireNonNull(replay); }
    public void register(String name,String scope,JsonNode input,JsonNode output,BiPredicate<KeyRecord,JsonNode> policy,BiFunction<KeyRecord,JsonNode,JsonNode> handler) {register(name,scope,input,output,policy,handler,60,60);}
    public void register(String name,String scope,JsonNode input,JsonNode output,BiPredicate<KeyRecord,JsonNode> policy,BiFunction<KeyRecord,JsonNode,JsonNode> handler,int requests,int period) {
        if (!name(name) || !name(scope) || policy == null || handler == null || requests<1 || requests>10000 || period<1 || period>3600 || operations.putIfAbsent(name,new Operation(scope,input,output,policy,handler,requests,period))!=null) throw new IllegalArgumentException("operation, schemas, policy, handler and bounded rate required");
    }
    public JsonNode inventory() {com.fasterxml.jackson.databind.node.ArrayNode value=object().arrayNode(); operations.keySet().stream().sorted().forEach(name -> {Operation o=operations.get(name);value.add(object().put("name",name).put("scope",o.scope).put("requests",o.requests).put("period",o.period));});return value;}
    public String handle(String wire) {
        Opened opened = codec.open(wire, "req"); JsonNode request = opened.payload; KeyRecord principal = codec.principal(opened.kid); long now = codec.now();
        java.util.function.Function<JsonNode, String> finish = codec.prepareResponse(opened.kid);
        ObjectNode response = object().put("id", text(request.get("id"))).put("iat", now).put("exp", now + 60).put("req", digest(wire)).put("ok", false);
        try {
            Operation o=operations.get(text(request.get("op")));
            if (!replay.admit(codec.service,opened.kid,principal.subject,o==null?"unknown":text(request.get("op")),codec.now(),o==null?60:o.requests,o==null?60:o.period)) throw new SapiException("rate_limited");
            if (!replay.claim(codec.service + "|" + opened.kid + "|" + text(request.get("id")), integer(request.get("exp")), codec.now())) throw new SapiException("replay");
            if (o == null) throw new SapiException("unknown_operation");
            if (!principal.hasScope(o.scope)) throw new SapiException("forbidden"); JsonNode data = request.get("data");
            if (!o.input.validate(data)) throw new SapiException("invalid_input"); if (!o.policy.test(principal, data)) throw new SapiException("forbidden");
            if (!o.input.validate(data)) throw new SapiException("invalid_input");
            if (codec.now() >= integer(request.get("exp"))) throw new SapiException("invalid_input");
            JsonNode result = o.handler.apply(principal, data);
            if (result == null || !result.isObject() || !o.output.validate(result) || encode(result).length > MAX_BODY - 512) throw new SapiException();
            response.put("ok", true); response.set("data", result);
        } catch (SapiException e) { response.put("error", Legacy.set("replay", "replay_capacity", "rate_limited", "rate_capacity", "unknown_operation", "forbidden", "invalid_input").contains(e.code) ? e.code : "internal_error"); }
        catch (Exception e) { response.put("error", "internal_error"); }
        return finish.apply(response);
    }
}
