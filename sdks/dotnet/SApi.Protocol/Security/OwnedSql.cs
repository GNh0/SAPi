using System.Data.Common;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SApi.Protocol;

public sealed class SqlPlan
{
    private readonly string statement;
    private readonly object?[] values;
    internal SqlPlan(string statement, IEnumerable<object?> values) {this.statement=statement;this.values=values.ToArray();}
    public (string Text, object?[] Values) Bind(string dialect="qmark")
    {
        if (dialect is not ("qmark" or "format" or "dollar" or "named")) throw new ArgumentException("unsupported dialect");
        var count=0; var text=Regex.Replace(statement,"\\?",_=>{var n=count++;return dialect switch {"format"=>"%s","dollar"=>"$"+(n+1),"named"=>"@p"+n,_=>"?"};});
        if (count!=values.Length) throw new ArgumentException("SQL parameter mismatch");return (text,(object?[])values.Clone());
    }
    public DbCommand CreateCommand(DbConnection connection)
    {
        var command=connection.CreateCommand();
        try
        {
            var plan=Bind("named");command.CommandText=plan.Text;
            for(var n=0;n<values.Length;n++) {var parameter=command.CreateParameter();parameter.ParameterName="@p"+n;parameter.Value=values[n]??DBNull.Value;command.Parameters.Add(parameter);}
            return command;
        }
        catch {command.Dispose();throw;}
    }
}

public sealed class OwnedSql
{
    private readonly string table,id,owner;
    private readonly string[] read,write;
    private static readonly Regex Identifier=new("\\A[A-Za-z][A-Za-z0-9_]{0,63}\\z",RegexOptions.CultureInvariant);
    public OwnedSql(string table,string idColumn,string ownerColumn,IEnumerable<string> readColumns,IEnumerable<string> writeColumns)
    {
        read=readColumns.ToArray();write=writeColumns.ToArray();
        if (new[]{table,idColumn,ownerColumn}.Concat(read).Concat(write).Any(n=>n==null||!Identifier.IsMatch(n)) || idColumn==ownerColumn || read.Length is <1 or >64 || write.Length>64 || read.Distinct().Count()!=read.Length || write.Distinct().Count()!=write.Length || write.Any(n=>n==idColumn||n==ownerColumn)) throw new ArgumentException("fixed identifiers and column allowlists required");
        this.table=table;id=idColumn;owner=ownerColumn;
        var foldedRead=read.Select(n=>n.ToLowerInvariant()).ToArray();var foldedWrite=write.Select(n=>n.ToLowerInvariant()).ToArray();
        if(id.ToLowerInvariant()==owner.ToLowerInvariant()||foldedRead.Distinct().Count()!=read.Length||foldedWrite.Distinct().Count()!=write.Length||foldedWrite.Any(n=>n==id.ToLowerInvariant()||n==owner.ToLowerInvariant()))throw new ArgumentException("case-insensitive SQL column identities required");
    }
    private static object? Scalar(JsonElement v) => v.ValueKind switch {
        JsonValueKind.Null=>null,JsonValueKind.True=>true,JsonValueKind.False=>false,
        JsonValueKind.String when System.Text.Encoding.UTF8.GetByteCount(v.GetString()!)<=65536=>v.GetString(),
        JsonValueKind.Number when double.IsFinite(v.GetDouble())&&Math.Abs(v.GetDouble())<=9007199254740991d=>v.TryGetInt64(out var n)?(object)n:v.GetDouble(),
        _=>throw new ArgumentException("bounded SQL scalar required")};
    private static object?[] Identity(KeyRecord p,JsonElement v) => [p.Subject,Scalar(v)];
    public SqlPlan Select(KeyRecord p,JsonElement value) => new($"SELECT {string.Join(',',read)} FROM {table} WHERE {owner}=? AND {id}=?",Identity(p,value));
    public SqlPlan Delete(KeyRecord p,JsonElement value) => new($"DELETE FROM {table} WHERE {owner}=? AND {id}=?",Identity(p,value));
    private (string Name,object? Value)[] Changes(JsonElement value)
    {
        if(value.ValueKind!=JsonValueKind.Object || !value.EnumerateObject().Any() || value.EnumerateObject().Any(p=>!write.Contains(p.Name))) throw new ArgumentException("undeclared or immutable column");
        return write.Where(n=>value.TryGetProperty(n,out _)).Select(n=>(n,Scalar(value.GetProperty(n)))).ToArray();
    }
    public SqlPlan Update(KeyRecord p,JsonElement value,JsonElement changes)
    {
        var pairs=Changes(changes);return new($"UPDATE {table} SET "+string.Join(',',pairs.Select(pair=>pair.Name+"=?"))+$" WHERE {owner}=? AND {id}=?",pairs.Select(pair=>pair.Value).Concat(Identity(p,value)));
    }
    public SqlPlan Insert(KeyRecord p,JsonElement value,JsonElement changes)
    {
        var pairs=Changes(changes);var columns=new[]{owner,id}.Concat(pairs.Select(pair=>pair.Name)).ToArray();return new($"INSERT INTO {table} ({string.Join(',',columns)}) VALUES ({string.Join(',',columns.Select(_=>"?"))})",Identity(p,value).Concat(pairs.Select(pair=>pair.Value)));
    }
}
