package io.github.gnh0.sapi;
import java.sql.*;
import java.util.*;
public final class SqlPlan {
    private final String statement; private final List<Object> values;
    SqlPlan(String text,List<Object> values) {this.statement=text;this.values=Collections.unmodifiableList(new ArrayList<>(values));}
    public String text(String dialect) {
        if (!Legacy.set("qmark","format","dollar","named").contains(dialect)) throw new IllegalArgumentException("unsupported dialect");
        StringBuilder result=new StringBuilder();int count=0;
        for(char c:statement.toCharArray()) {if(c!='?')result.append(c);else {int n=count++;result.append(dialect.equals("format")?"%s":dialect.equals("dollar")?"$"+(n+1):dialect.equals("named")?"@p"+n:"?");}}
        if(count!=values.size())throw new IllegalArgumentException("SQL parameter mismatch");return result.toString();
    }
    public List<Object> values() {return values;}
    public PreparedStatement prepare(Connection connection) throws SQLException {PreparedStatement command=connection.prepareStatement(text("qmark"));try {for(int n=0;n<values.size();n++)command.setObject(n+1,values.get(n));return command;}catch(SQLException e){command.close();throw e;}}
}
