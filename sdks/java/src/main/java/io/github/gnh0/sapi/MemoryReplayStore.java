package io.github.gnh0.sapi;

import java.util.HashMap;
import java.util.Map;
import static io.github.gnh0.sapi.Sapi.*;

public final class MemoryReplayStore implements ReplayStore {
    private final Map<String, Long> entries = new HashMap<>(); private final int capacity;
    private final Map<String, long[]> rates = new HashMap<>();
    public MemoryReplayStore() { this(10000); }
    public MemoryReplayStore(int capacity) { if (capacity < 1) throw new IllegalArgumentException(); this.capacity = capacity; }
    public synchronized boolean claim(String key, long expiry, long now) {
        entries.entrySet().removeIf(e -> e.getValue() <= now);
        if (entries.containsKey(key)) return false; if (entries.size() >= capacity) throw new SapiException("replay_capacity");
        entries.put(key, expiry); return true;
    }
    public synchronized boolean admit(String service,String kid,String subject,String operation,long now,int requests,int period) {
        rates.entrySet().removeIf(e->e.getValue()[0]+e.getValue()[2]<=now);
        Map<String,long[]> pending=new HashMap<>();
        String[] names={"global|"+service+"|"+subject,"op|"+service+"|"+subject+"|"+operation}; int[] counts={60,requests},seconds={60,period};
        for (int n=0;n<2;n++) {
            long[] previous=rates.getOrDefault(names[n],new long[]{now,0,seconds[n]}); long start=previous[0],used=previous[1];
            long span=Math.max(seconds[n],previous[2]);if (now>=start+span) {start=now; used=0;span=seconds[n];}
            if (used>=counts[n]) return false;
            if (!rates.containsKey(names[n])&&rates.size()+pending.keySet().stream().filter(k->!rates.containsKey(k)).count()>=10000) throw new SapiException("rate_capacity");
            pending.put(names[n],new long[]{start,used+1,span});
        }
        rates.putAll(pending); return true;
    }
}
