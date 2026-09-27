package io.github.gnh0.sapi;

import java.util.*;

/** Java 8 collection snapshots; nulls and duplicate factory elements are rejected. */
public final class Legacy {
    private Legacy() {}
    @SafeVarargs public static <T> Set<T> set(T... values) {
        Set<T> result=new HashSet<>(); for(T value:values) if(!result.add(Objects.requireNonNull(value))) throw new IllegalArgumentException("duplicate element");
        return Collections.unmodifiableSet(result);
    }
    @SafeVarargs public static <T> List<T> list(T... values) {return listCopy(Arrays.asList(values));}
    public static <T> Set<T> setCopy(Collection<T> values) {Set<T> result=new HashSet<>();for(T value:values) result.add(Objects.requireNonNull(value));return Collections.unmodifiableSet(result);}
    public static <T> List<T> listCopy(Collection<T> values) {List<T> result=new ArrayList<>();for(T value:values) result.add(Objects.requireNonNull(value));return Collections.unmodifiableList(result);}
    public static <K,V> Map<K,V> mapCopy(Map<K,V> values) {Map<K,V> result=new HashMap<>();values.forEach((k,v)->result.put(Objects.requireNonNull(k),Objects.requireNonNull(v)));return Collections.unmodifiableMap(result);}
}
