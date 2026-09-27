"""Tenant-bound SQL with fixed identifiers and bound values, never SQL from a request."""
from dataclasses import dataclass
import math
import re
from .models import Principal

IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")


def scalar(value):
    if value is None or type(value) is bool: return value
    if type(value) is str and len(value.encode("utf-8")) <= 65536: return value
    if type(value) in (int,float) and math.isfinite(value) and abs(value) <= 9007199254740991: return value
    raise ValueError("bounded SQL scalar required")


@dataclass(frozen=True)
class SqlPlan:
    statement: str
    values: tuple

    def bind(self, dialect="qmark"):
        if dialect not in ("qmark", "format", "dollar", "named"): raise ValueError("unsupported SQL dialect")
        index = 0
        def placeholder(_):
            nonlocal index
            current = index; index += 1
            return {"qmark":"?", "format":"%s", "dollar":"$" + str(current + 1), "named":"@p" + str(current)}[dialect]
        text = re.sub(r"\?", placeholder, self.statement)
        if index != len(self.values): raise ValueError("SQL parameter mismatch")
        return text, self.values

    def execute(self, connection, dialect="qmark"):
        if dialect not in ("qmark", "format"): raise ValueError("DB-API positional dialect required")
        text, values = self.bind(dialect)
        return connection.execute(text, values)


class OwnedSql:
    def __init__(self, table, id_column, owner_column, read_columns, write_columns):
        names = [table,id_column,owner_column,*read_columns,*write_columns]
        if any(type(n) is not str or not IDENTIFIER.fullmatch(n) for n in names): raise ValueError("fixed identifiers required")
        read_fold,write_fold=[n.lower() for n in read_columns],[n.lower() for n in write_columns]
        if id_column.lower() == owner_column.lower() or not 1 <= len(read_columns) <= 64 or len(write_columns) > 64 or len(set(read_fold)) != len(read_columns) or len(set(write_fold)) != len(write_columns) or set(write_fold) & {id_column.lower(),owner_column.lower()}: raise ValueError("fixed table, identity and column allowlists required")
        self.table, self.id, self.owner = table, id_column, owner_column
        self.read, self.write = tuple(read_columns), tuple(write_columns)

    def _identity(self, principal, value):
        if not isinstance(principal, Principal): raise ValueError("authenticated Principal required")
        return scalar(principal.subject), scalar(value)

    def select(self, principal, value):
        return SqlPlan(f"SELECT {','.join(self.read)} FROM {self.table} WHERE {self.owner}=? AND {self.id}=?", self._identity(principal,value))

    def delete(self, principal, value):
        return SqlPlan(f"DELETE FROM {self.table} WHERE {self.owner}=? AND {self.id}=?", self._identity(principal,value))

    def _changes(self, values):
        if type(values) is not dict or not values or values.keys() - set(self.write): raise ValueError("undeclared or immutable column")
        return [(name,scalar(values[name])) for name in self.write if name in values]

    def update(self, principal, value, values):
        pairs = self._changes(values)
        return SqlPlan(f"UPDATE {self.table} SET " + ",".join(k + "=?" for k,_ in pairs) + f" WHERE {self.owner}=? AND {self.id}=?", tuple(v for _,v in pairs) + self._identity(principal,value))

    def insert(self, principal, value, values):
        pairs = self._changes(values); columns = [self.owner,self.id,*[k for k,_ in pairs]]
        return SqlPlan(f"INSERT INTO {self.table} (" + ",".join(columns) + ") VALUES (" + ",".join("?" for _ in columns) + ")", self._identity(principal,value) + tuple(v for _,v in pairs))
