package io.github.gnh0.sapi;



public final class SapiException extends RuntimeException {
    public final String code;
    public SapiException() { this("invalid_message"); }
    public SapiException(String code) { super(code); this.code = code; }
}
