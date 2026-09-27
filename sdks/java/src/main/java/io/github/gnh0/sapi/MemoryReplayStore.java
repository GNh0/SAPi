package io.github.gnh0.sapi;

import java.util.HashMap;
import java.util.Map;
import static io.github.gnh0.sapi.Sapi.*;

public final class MemoryReplayStore implements ReplayStore {
    private final Map<String, Long> entries = new HashMap<>(); private final int capacity;
    public MemoryReplayStore() { this(10000); }
    public MemoryReplayStore(int capacity) { if (capacity < 1) throw new IllegalArgumentException(); this.capacity = capacity; }
    public synchronized boolean claim(String key, long expiry, long now) {
        entries.entrySet().removeIf(e -> e.getValue() <= now);
        if (entries.containsKey(key)) return false; if (entries.size() >= capacity) throw new SapiException("replay_capacity");
        entries.put(key, expiry); return true;
    }
}
