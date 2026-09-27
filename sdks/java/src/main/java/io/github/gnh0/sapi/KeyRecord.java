package io.github.gnh0.sapi;

import java.util.Set;
import static io.github.gnh0.sapi.Sapi.*;

public final class KeyRecord {
    final byte[] master;
    public final String subject;
    private final Set<String> scopes;
    public KeyRecord(byte[] master, String subject, Set<String> scopes) {
        if (master.length != 32 || !name(subject)) throw new IllegalArgumentException("key and subject required");
        this.master = master.clone(); this.subject = subject; this.scopes = Set.copyOf(scopes);
    }
    public boolean hasScope(String scope) { return scopes.contains(scope); }
}
