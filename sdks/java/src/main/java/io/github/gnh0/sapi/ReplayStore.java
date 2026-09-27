package io.github.gnh0.sapi;



/** MUST reserve atomically until expiry; storage failure MUST throw. */
public interface ReplayStore { boolean claim(String key, long expiry, long now); }
