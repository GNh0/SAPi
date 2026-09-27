package io.github.gnh0.sapi;



/** MUST reserve atomically until expiry; storage failure MUST throw. */
public interface ReplayStore {
    boolean claim(String key, long expiry, long now);
    default boolean admit(String service,String kid,String subject,String operation,long now,int requests,int period) {throw new SapiException("security_store_required");}
}
