import {hasOwn} from './platform.js';
const identifier = /^[A-Za-z][A-Za-z0-9_]{0,63}(?![\s\S])/;
const scalar = value => {
  if (value === null || typeof value === 'boolean' || (typeof value === 'string' && new TextEncoder().encode(value).length <= 65536) || (typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER)) return value;
  throw new TypeError('bounded SQL scalar required');
};
const token = Symbol('trusted SQL plan');
export class SqlPlan {
  #statement; #values;
  constructor(statement, values, trusted) {if (trusted !== token) throw new TypeError('use OwnedSql');this.#statement=statement;this.#values=Object.freeze([...values]);}
  bind(dialect='qmark') {
    if (!['qmark','format','dollar','named'].includes(dialect)) throw new TypeError('unsupported dialect'); let count=0;
    const text=this.#statement.replace(/\?/g,()=>{const n=count++;return {qmark:'?',format:'%s',dollar:`$${n+1}`,named:`@p${n}`}[dialect];});
    if (count!==this.#values.length) throw new TypeError('SQL parameter mismatch');return {text,values:[...this.#values]};
  }
  async execute(postgresClient) {const {text,values}=this.bind('dollar');return postgresClient.query(text,values);}
}
export class OwnedSql {
  #table; #id; #owner; #read; #write;
  constructor(table,idColumn,ownerColumn,readColumns,writeColumns) {
    if (![readColumns,writeColumns].every(Array.isArray) || [table,idColumn,ownerColumn,...readColumns,...writeColumns].some(n=>typeof n!=='string'||!identifier.test(n)) || idColumn===ownerColumn || readColumns.length<1 || readColumns.length>64 || writeColumns.length>64 || new Set(readColumns).size!==readColumns.length || new Set(writeColumns).size!==writeColumns.length || writeColumns.some(n=>[idColumn,ownerColumn].includes(n))) throw new TypeError('fixed identifiers and column allowlists required');
    this.#table=table;this.#id=idColumn;this.#owner=ownerColumn;this.#read=[...readColumns];this.#write=[...writeColumns];
    const read=readColumns.map(n=>n.toLowerCase()),write=writeColumns.map(n=>n.toLowerCase());
    if(idColumn.toLowerCase()===ownerColumn.toLowerCase()||new Set(read).size!==read.length||new Set(write).size!==write.length||write.some(n=>[idColumn.toLowerCase(),ownerColumn.toLowerCase()].includes(n)))throw new TypeError('case-insensitive SQL column identities required');
  }
  #identity(p,id) {if (!p || typeof p.subject!=='string' || !(p.scopes instanceof Set)) throw new TypeError('authenticated principal required');return [scalar(p.subject),scalar(id)];}
  #plan(text,values) {return new SqlPlan(text,values,token);}
  select(p,id) {return this.#plan(`SELECT ${this.#read.join(',')} FROM ${this.#table} WHERE ${this.#owner}=? AND ${this.#id}=?`,this.#identity(p,id));}
  delete(p,id) {return this.#plan(`DELETE FROM ${this.#table} WHERE ${this.#owner}=? AND ${this.#id}=?`,this.#identity(p,id));}
  #changes(values) {if (!values || typeof values!=='object' || Array.isArray(values) || !Object.keys(values).length || Object.keys(values).some(n=>!this.#write.includes(n))) throw new TypeError('undeclared or immutable column');return this.#write.filter(n=>hasOwn(values,n)).map(n=>[n,scalar(values[n])]);}
  update(p,id,values) {const pairs=this.#changes(values);return this.#plan(`UPDATE ${this.#table} SET ${pairs.map(([n])=>n+'=?').join(',')} WHERE ${this.#owner}=? AND ${this.#id}=?`,[...pairs.map(([,v])=>v),...this.#identity(p,id)]);}
  insert(p,id,values) {const pairs=this.#changes(values),columns=[this.#owner,this.#id,...pairs.map(([n])=>n)];return this.#plan(`INSERT INTO ${this.#table} (${columns.join(',')}) VALUES (${columns.map(()=>'?').join(',')})`,[...this.#identity(p,id),...pairs.map(([,v])=>v)]);}
}
