package io.github.gnh0.sapi;

import com.fasterxml.jackson.databind.JsonNode;
import static io.github.gnh0.sapi.Sapi.*;

public final class Opened {
    public final String kid;
    public final JsonNode payload;
    Opened(String kid, JsonNode payload) { this.kid = kid; this.payload = payload; }
}
