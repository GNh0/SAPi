package io.github.gnh0.sapi;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import java.util.regex.Pattern;
public final class OwnedSql {
    private final String table,id,owner; private final List<String> read,write;
    private static final Pattern IDENTIFIER=Pattern.compile("[A-Za-z][A-Za-z0-9_]{0,63}");
    public OwnedSql(String table,String idColumn,String ownerColumn,List<String> readColumns,List<String> writeColumns) {
        read=Legacy.listCopy(readColumns);write=Legacy.listCopy(writeColumns);List<String> names=new ArrayList<>(Legacy.list(table,idColumn,ownerColumn));names.addAll(read);names.addAll(write);
        if(names.stream().anyMatch(n->!IDENTIFIER.matcher(n).matches())||idColumn.equals(ownerColumn)||read.size()<1||read.size()>64||write.size()>64||new HashSet<>(read).size()!=read.size()||new HashSet<>(write).size()!=write.size()||write.contains(idColumn)||write.contains(ownerColumn))throw new IllegalArgumentException("fixed identifiers and column allowlists required");
        this.table=table;id=idColumn;owner=ownerColumn;
        List<String> foldedRead=new ArrayList<>(),foldedWrite=new ArrayList<>();read.forEach(n->foldedRead.add(n.toLowerCase(Locale.ROOT)));write.forEach(n->foldedWrite.add(n.toLowerCase(Locale.ROOT)));
        if(id.toLowerCase(Locale.ROOT).equals(owner.toLowerCase(Locale.ROOT))||new HashSet<>(foldedRead).size()!=read.size()||new HashSet<>(foldedWrite).size()!=write.size()||foldedWrite.contains(id.toLowerCase(Locale.ROOT))||foldedWrite.contains(owner.toLowerCase(Locale.ROOT)))throw new IllegalArgumentException("case-insensitive SQL column identities required");
    }
    private static Object scalar(JsonNode v) {if(v==null)throw new IllegalArgumentException();if(v.isNull())return null;if(v.isBoolean())return v.booleanValue();if(v.isTextual()&&v.textValue().getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=65536)return v.textValue();if(v.isNumber()&&Double.isFinite(v.doubleValue())&&Math.abs(v.doubleValue())<=9007199254740991d){if(v.isIntegralNumber())return Long.valueOf(v.longValue());return Double.valueOf(v.doubleValue());}throw new IllegalArgumentException("bounded SQL scalar required");}
    private List<Object> identity(KeyRecord p,JsonNode value) {return new ArrayList<>(Arrays.asList(p.subject,scalar(value)));}
    public SqlPlan select(KeyRecord p,JsonNode value) {return new SqlPlan("SELECT "+String.join(",",read)+" FROM "+table+" WHERE "+owner+"=? AND "+id+"=?",identity(p,value));}
    public SqlPlan delete(KeyRecord p,JsonNode value) {return new SqlPlan("DELETE FROM "+table+" WHERE "+owner+"=? AND "+id+"=?",identity(p,value));}
    private Map<String,Object> changes(JsonNode values) {if(!values.isObject()||values.size()==0)throw new IllegalArgumentException("column values required");values.fieldNames().forEachRemaining(n->{if(!write.contains(n))throw new IllegalArgumentException("undeclared or immutable column");});Map<String,Object> result=new LinkedHashMap<>();for(String n:write)if(values.has(n))result.put(n,scalar(values.get(n)));return result;}
    public SqlPlan update(KeyRecord p,JsonNode value,JsonNode data) {Map<String,Object> changes=changes(data);List<Object> values=new ArrayList<>(changes.values());values.addAll(identity(p,value));return new SqlPlan("UPDATE "+table+" SET "+String.join(",",changes.keySet().stream().map(n->n+"=?").toArray(String[]::new))+" WHERE "+owner+"=? AND "+id+"=?",values);}
    public SqlPlan insert(KeyRecord p,JsonNode value,JsonNode data) {Map<String,Object> changes=changes(data);List<String> columns=new ArrayList<>(Legacy.list(owner,id));columns.addAll(changes.keySet());List<Object> values=identity(p,value);values.addAll(changes.values());return new SqlPlan("INSERT INTO "+table+" ("+String.join(",",columns)+") VALUES ("+String.join(",",Collections.nCopies(columns.size(),"?"))+")",values);}
}
