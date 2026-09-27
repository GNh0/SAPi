package io.github.gnh0.sapi;

import java.util.Map;
import java.util.HashMap;

public final class StaticKeyProvider implements KeyProvider {
    private final Map<String, KeyRecord> keys;
    private final Map<String, Integer> counts = new HashMap<>();
    public StaticKeyProvider(Map<String, KeyRecord> keys) {
        if (keys.isEmpty() || keys.keySet().stream().anyMatch(k -> !Sapi.name(k))) throw new IllegalArgumentException("valid keys required");
        this.keys = Map.copyOf(keys);
    }
    public KeyRecord get(String service, String kid) {
        KeyRecord record = keys.get(kid); if (record == null) throw new SapiException(); return record;
    }
    public synchronized KeyRecord reserve(String service, String kid, String direction) {
        KeyRecord record = get(service, kid); String name = service + "|" + kid + "|" + direction;
        int count = counts.getOrDefault(name, 0);
        if (count >= 1048576) throw new SapiException("key_rotation_required");
        counts.put(name, count + 1); return record;
    }
}
