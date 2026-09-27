package io.github.gnh0.sapi;

public interface KeyProvider {
    KeyRecord get(String service, String kid);
    KeyRecord reserve(String service, String kid, String direction);
}
