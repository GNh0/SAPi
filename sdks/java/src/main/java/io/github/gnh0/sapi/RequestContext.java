package io.github.gnh0.sapi;

import static io.github.gnh0.sapi.Sapi.*;

public final class RequestContext {
    public final String wire, kid, id;
    boolean consumed;
    RequestContext(String wire, String kid, String id) { this.wire = wire; this.kid = kid; this.id = id; }
}
