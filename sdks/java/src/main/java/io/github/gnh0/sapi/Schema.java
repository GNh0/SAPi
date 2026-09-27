package io.github.gnh0.sapi;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.util.*;
import java.util.regex.Pattern;

/** Closed bounded schemas; no coercion, remote references or configured regex. */
public final class Schema {
    private static final double SAFE = 9007199254740991d;
    private static final Pattern FIELD = Pattern.compile("[A-Za-z][A-Za-z0-9_]{0,63}"), ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.:-]*"), UUID = Pattern.compile("[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}");
    private final JsonNode definition; private int nodes;
    public Schema(JsonNode value) {this(value, false);}
    public Schema(JsonNode value, boolean rootObject) {definition = value.deepCopy(); compile(definition,0); if (rootObject && !type(definition).equals("object")) throw new IllegalArgumentException("object schema required");}
    private static String type(JsonNode s) {return s.get("type").textValue();}
    private static double number(JsonNode s, String key, double fallback) {JsonNode v = s.get(key); if (v == null) return fallback; if (!v.isNumber()) throw new IllegalArgumentException("numeric bound required"); return v.doubleValue();}
    private static boolean integer(double n) {return Double.isFinite(n) && Math.abs(n) <= SAFE && n == Math.floor(n);}
    private static void bounds(JsonNode s, String lo, String hi, double fallback, double cap) {double a=number(s,lo,0),b=number(s,hi,fallback); if (!integer(a)||!integer(b)||a<0||a>b||b>cap) throw new IllegalArgumentException("invalid bounds");}
    private void compile(JsonNode s, int depth) {
        if (++nodes>256 || depth>16 || s==null || !s.isObject() || !s.has("type") || !s.get("type").isTextual()) throw new IllegalArgumentException("bounded schema required");
        Set<String> allowed;
        switch(type(s)) {
            case "object": allowed=Legacy.set("properties","optional"); break;
            case "array": allowed=Legacy.set("items","minItems","maxItems"); break;
            case "string": allowed=Legacy.set("minBytes","maxBytes","format","enum"); break;
            case "integer": case "number": allowed=Legacy.set("min","max"); break;
            case "boolean": case "null": allowed=Legacy.set(); break;
            default: throw new IllegalArgumentException("unsupported schema");
        }
        s.fieldNames().forEachRemaining(k -> {if (!k.equals("type") && !allowed.contains(k)) throw new IllegalArgumentException("unsupported schema property");});
        switch(type(s)) {
            case "object":
                JsonNode props=s.get("properties"); if (props==null||!props.isObject()||props.size()>64) throw new IllegalArgumentException("safe properties required");
                props.fieldNames().forEachRemaining(k -> {if (!FIELD.matcher(k).matches() || Legacy.set("constructor","prototype","__proto__").contains(k)) throw new IllegalArgumentException("safe properties required");});
                if (s.has("optional")) {JsonNode opt=s.get("optional"); Set<String> seen=new HashSet<>(); if (!opt.isArray()) throw new IllegalArgumentException("invalid optional"); for (JsonNode k:opt) if (!k.isTextual() || !props.has(k.textValue()) || !seen.add(k.textValue())) throw new IllegalArgumentException("invalid optional");}
                for (JsonNode child:props) compile(child,depth+1); break;
            case "array": bounds(s,"minItems","maxItems",16,64); compile(s.get("items"),depth+1); break;
            case "string":
                bounds(s,"minBytes","maxBytes",4096,65536);
                if (s.has("format") && (!s.get("format").isTextual() || !Legacy.set("text","identifier","uuid").contains(s.get("format").textValue()))) throw new IllegalArgumentException("unsupported format");
                if (s.has("enum")) {JsonNode values=s.get("enum"); Set<String> seen=new HashSet<>(); if (!values.isArray()||values.size()<1||values.size()>64) throw new IllegalArgumentException("invalid enum"); for (JsonNode v:values) if (!v.isTextual()||!stringValid(s,v.textValue())||!seen.add(v.textValue())) throw new IllegalArgumentException("invalid enum");} break;
            case "integer": case "number":
                double a=number(s,"min",-SAFE),b=number(s,"max",SAFE); if (!Double.isFinite(a)||!Double.isFinite(b)||Math.abs(a)>SAFE||Math.abs(b)>SAFE||a>b||(type(s).equals("integer")&&(!integer(a)||!integer(b)))) throw new IllegalArgumentException("invalid numeric bounds"); break;
        }
    }
    private static boolean stringValid(JsonNode s,String v) {
        int size; try {size=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).encode(CharBuffer.wrap(v)).remaining();} catch (Exception e) {return false;}
        if (size<number(s,"minBytes",0)||size>number(s,"maxBytes",4096)||v.chars().anyMatch(c -> (c<32&&c!='\t'&&c!='\n'&&c!='\r')||c==127)) return false;
        String form=s.has("format")?s.get("format").textValue():"text";
        return form.equals("identifier")?ID.matcher(v).matches():form.equals("uuid")?UUID.matcher(v).matches():true;
    }
    public boolean validate(JsonNode value) {return validate(definition,value);}
    private static boolean validate(JsonNode s,JsonNode v) {
        if (v==null) return false;
        switch(type(s)) {
            case "object":
                if (!v.isObject()) return false; JsonNode props=s.get("properties"); Set<String> optional=new HashSet<>(); if (s.has("optional")) for (JsonNode k:s.get("optional")) optional.add(k.textValue());
                Iterator<String> fields=v.fieldNames(); while (fields.hasNext()) {String k=fields.next(); if (!props.has(k)||!validate(props.get(k),v.get(k))) return false;}
                fields=props.fieldNames(); while (fields.hasNext()) {String k=fields.next(); if (!optional.contains(k)&&!v.has(k)) return false;} return true;
            case "array": if (!v.isArray()||v.size()<number(s,"minItems",0)||v.size()>number(s,"maxItems",16)) return false; for (JsonNode x:v) if (!validate(s.get("items"),x)) return false; return true;
            case "string": if (!v.isTextual()||!stringValid(s,v.textValue())) return false; if (s.has("enum")) {for (JsonNode x:s.get("enum")) if (x.textValue().equals(v.textValue())) return true; return false;} return true;
            case "integer": case "number": double n=v.doubleValue(); return v.isNumber()&&Double.isFinite(n)&&(!type(s).equals("integer")||integer(n))&&n>=number(s,"min",-SAFE)&&n<=number(s,"max",SAFE);
            case "boolean": return v.isBoolean();
            default: return v.isNull();
        }
    }
}
