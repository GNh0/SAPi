// D1-backed implementation for SecureServer's default replay interface.
// Install state-d1.sql explicitly.
// A fixed 30-second hold prevents an instance with a smaller configured skew
// from clearing a claim still accepted by another supported instance.
const retentionSkew = 30;
const nowSql = "CAST(unixepoch() AS INTEGER)";
const isInteger = x => Number.isSafeInteger(x) && x >= 0;
const validName = x => typeof x === 'string' && /^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(x);
// No normalization or replacement: lone surrogates cannot be encoded losslessly.
function validSubject(value) {
  if (typeof value !== 'string' || value.length===0 || value.length>1024) return false;
  for (let i=0;i<value.length;i++) {
    const c=value.charCodeAt(i);
    if (c>=0xd800 && c<=0xdbff) {const d=value.charCodeAt(++i);if (!(d>=0xdc00 && d<=0xdfff)) return false;}
    else if (c>=0xdc00 && c<=0xdfff) return false;
  }
  return new TextEncoder().encode(value).length<=4096;
}
function exactRecord(value, keys) {
  if (value === null || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual=Reflect.ownKeys(value);
  return actual.length===keys.length && keys.every(key => {
    const descriptor=Object.getOwnPropertyDescriptor(value,key);
    return descriptor && descriptor.enumerable && Object.hasOwn(descriptor,'value');
  });
}
const servicePattern=/^[A-Za-z0-9_-]{1,64}(?![\s\S])/;
function canonicalOperations(operations) {
  if (!operations || Object.getPrototypeOf(operations)!==Object.prototype) throw new TypeError('operations must be a plain object');
  const entries=Object.entries(operations);
  if (entries.length>1000) throw new TypeError('too many operations');
  const normalized=Object.create(null);
  for (const [name,value] of entries.sort(([a],[b])=>a<b?-1:a>b?1:0)) {
    if (!servicePattern.test(name) || !exactRecord(value,['requests','period'])) throw new TypeError('invalid operation policy');
    limit(value.requests,10000,'requests'); limit(value.period,3600,'period');
    normalized[name]=Object.freeze({requests:value.requests,period:value.period});
  }
  return Object.freeze(normalized);
}
function keyParts(key) {
  if (typeof key !== 'string') throw new TypeError('invalid replay key');
  const parts = key.split('|');
  if (parts.length !== 3 || !/^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(parts[0]) || !/^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(parts[1]) || !/^[0-9a-f]{32}(?![\s\S])/.test(parts[2])) throw new TypeError('invalid SDK replay key');
  return parts;
}
function limit(value, max, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new TypeError(`${name} is out of range`);
  return value;
}
export class D1ReplayStore {
  constructor(db, {mode, service, policyVersion, operations={}, capacity=10000, rateCapacity=10000, maxClockSkew=5, costLimit=120, costPeriod=60}={}) {
    if (!db || typeof db.prepare !== 'function' || typeof db.batch !== 'function') throw new TypeError('D1 binding required');
    if (typeof service !== 'string' || !servicePattern.test(service) || typeof policyVersion!=='string' || !/^[A-Za-z0-9_.-]{1,64}(?![\s\S])/.test(policyVersion)) throw new TypeError('fixed service and policyVersion required');
    if (mode !== 'exclusive') throw new TypeError('explicit exclusive mode required');
    this.mode=mode;
    this.db = db;
    this.service=service;
    this.policyVersion=policyVersion;
    this.operations=canonicalOperations(operations);
    this.capacity = limit(capacity, 10000, 'capacity');
    this.rateCapacity = limit(rateCapacity, 10000, 'rateCapacity');
    if (!Number.isSafeInteger(maxClockSkew) || maxClockSkew < 0 || maxClockSkew > 30) throw new TypeError('maxClockSkew is out of range');
    this.maxClockSkew = maxClockSkew;
    this.costLimit = limit(costLimit,10000,'costLimit');
    this.costPeriod = limit(costPeriod,3600,'costPeriod');
    this.policyConfig=JSON.stringify({mode:this.mode,capacity:this.capacity,rateCapacity:this.rateCapacity,maxClockSkew:this.maxClockSkew,costLimit:this.costLimit,costPeriod:this.costPeriod,operations:this.operations});
    Object.freeze(this);
  }
  policyRecord() { return {service:this.service,version:this.policyVersion,config:this.policyConfig}; }
  async assertPolicy() {
    const row=await this.db.prepare('SELECT 1 AS ok FROM sapi_replay_policy p JOIN sapi_replay_owner o ON o.singleton=1 AND o.service=p.service AND o.version=p.version AND o.config=p.config WHERE p.service=? AND p.version=? AND p.config=?').bind(this.service,this.policyVersion,this.policyConfig).first();
    if (!exactRecord(row,['ok']) || row.ok!==1) throw new Error('D1 replay policy missing or mismatch');
  }
  async claim(key, expiry, now) {
    const tuple=keyParts(key);
    if (tuple[0]!==this.service || !isInteger(expiry) || !isInteger(now)) throw new TypeError('invalid replay claim');
    await this.assertPolicy();
    key=JSON.stringify(tuple);
    const clock = nowSql;
    // Keep expired claims through the tolerated skew so a lagging isolate cannot reuse them.
    const row = await this.db.prepare(`INSERT INTO sapi_replay_claims(name,expires)
      SELECT ?,? WHERE EXISTS(SELECT 1 FROM sapi_replay_policy p JOIN sapi_replay_owner o ON o.singleton=1 AND o.service=p.service AND o.version=p.version AND o.config=p.config WHERE p.service=? AND p.version=? AND p.config=?) AND abs(${clock}-?)<=? AND ?>${clock}+? AND ?<=${clock}+65+?
      AND (EXISTS(SELECT 1 FROM sapi_replay_claims WHERE name=?) OR (SELECT count(*) FROM sapi_replay_claims)<?)
      ON CONFLICT(name) DO UPDATE SET expires=excluded.expires WHERE sapi_replay_claims.expires+?<=${clock}
      RETURNING 1 AS claimed`).bind(key,expiry,this.service,this.policyVersion,this.policyConfig,now,this.maxClockSkew,expiry,this.maxClockSkew,expiry,this.maxClockSkew,key,this.capacity,retentionSkew).first();
    if (row === null) return false;
    if (!exactRecord(row,['claimed']) || row.claimed !== 1) throw new Error('uncertain D1 claim');
    return true;
  }
  async admit(service,kid,subject,operation,now,requests=60,period=60) {
    if (![service,kid,operation].every(validName) || !validSubject(subject) || !isInteger(now)) throw new TypeError('invalid rate input');
    limit(requests,10000,'requests'); limit(period,3600,'period');
    const expected=this.operations[operation] ?? (operation==='unknown'?{requests:60,period:60}:null);
    if (service!==this.service || !expected || expected.requests!==requests || expected.period!==period) throw new Error('operation policy mismatch');
    await this.assertPolicy();
    const globalName=JSON.stringify(['global',service,subject]);
    const operationName=JSON.stringify(['operation',service,subject,operation]);
    const clock=nowSql, id=crypto.randomUUID();
    // One INSERT and its trigger atomically check/update both buckets. It does not
    // reuse caller time for the window: D1 execution time is authoritative.
    const row=await this.db.prepare(`INSERT INTO sapi_replay_admission(id,global_name,operation_name,at,requested,period)
     SELECT ?,?,?,${clock},?,? WHERE EXISTS(SELECT 1 FROM sapi_replay_policy p JOIN sapi_replay_owner o ON o.singleton=1 AND o.service=p.service AND o.version=p.version AND o.config=p.config WHERE p.service=? AND p.version=? AND p.config=?) AND abs(${clock}-?)<=?
     AND NOT EXISTS(SELECT 1 FROM sapi_replay_rates WHERE name=? AND ${clock}<started+max(period,60) AND used>=60)
     AND NOT EXISTS(SELECT 1 FROM sapi_replay_rates WHERE name=? AND ${clock}<started+max(period,?) AND used>=?)
     AND (SELECT count(*) FROM sapi_replay_rates)+(NOT EXISTS(SELECT 1 FROM sapi_replay_rates WHERE name=?))+(NOT EXISTS(SELECT 1 FROM sapi_replay_rates WHERE name=?))<=?
     RETURNING id`).bind(id,globalName,operationName,requests,period,this.service,this.policyVersion,this.policyConfig,now,this.maxClockSkew,globalName,operationName,period,requests,globalName,operationName,this.rateCapacity).first();
    if (row === null) return false;
    if (!exactRecord(row,['id']) || row.id !== id) throw new Error('uncertain D1 admission');
    return true;
  }
  async claimBounded(service,subject,key,expiry,now) {
    const tuple=keyParts(key);
    if (!validName(service) || !validSubject(subject) || tuple[0]!==service || !isInteger(expiry) || !isInteger(now)) throw new TypeError('invalid bounded claim');
    if (service!==this.service) throw new TypeError('service policy mismatch');
    await this.assertPolicy();
    // The SDK's replay identity is service+kid+id. Subject partitions cost,
    // while replay retains that same key identity across all subjects.
    const claimName=JSON.stringify(tuple), costName=JSON.stringify(['cost',service,subject]);
    const clock=nowSql,id=crypto.randomUUID();
    const row=await this.db.prepare(`INSERT INTO sapi_replay_bounded(id,cost_name,claim_name,expires,at,period,skew,decision)
      SELECT ?,?,?,?,${clock},?,?,CASE WHEN EXISTS (SELECT 1 FROM sapi_replay_claims WHERE name=? AND expires+?>${clock}) THEN 'replay' ELSE 'accepted' END
      WHERE EXISTS(SELECT 1 FROM sapi_replay_policy p JOIN sapi_replay_owner o ON o.singleton=1 AND o.service=p.service AND o.version=p.version AND o.config=p.config WHERE p.service=? AND p.version=? AND p.config=?) AND abs(${clock}-?)<=? AND ?>${clock}+? AND ?<=${clock}+65+?
      AND NOT EXISTS (SELECT 1 FROM sapi_replay_rates WHERE name=? AND ${clock}<started+max(period,?) AND used>=?)
      AND ((SELECT count(*) FROM sapi_replay_rates)+(NOT EXISTS(SELECT 1 FROM sapi_replay_rates WHERE name=?)))<=?
      AND (EXISTS(SELECT 1 FROM sapi_replay_claims WHERE name=?) OR (SELECT count(*) FROM sapi_replay_claims)<?)
      RETURNING id,decision`).bind(id,costName,claimName,expiry,this.costPeriod,retentionSkew,claimName,retentionSkew,this.service,this.policyVersion,this.policyConfig,now,this.maxClockSkew,expiry,this.maxClockSkew,expiry,this.maxClockSkew,costName,this.costPeriod,this.costLimit,costName,this.rateCapacity,claimName,this.capacity).first();
    if (row===null) return 'rate_limited';
    if (!exactRecord(row,['id','decision']) || row.id!==id || (row.decision !== 'accepted' && row.decision !== 'replay')) throw new Error('uncertain D1 bounded claim');
    return row.decision;
  }
  // Explicit bounded maintenance only: no unbounded scan or delete on requests.
  async cleanup(limitRows=100) {
    limit(limitRows,100,'limitRows');
    await this.assertPolicy();
    const claims=this.db.prepare(`DELETE FROM sapi_replay_claims WHERE EXISTS(SELECT 1 FROM sapi_replay_policy p JOIN sapi_replay_owner o ON o.singleton=1 AND o.service=p.service AND o.version=p.version AND o.config=p.config WHERE p.service=? AND p.version=? AND p.config=?) AND name IN
      (SELECT name FROM sapi_replay_claims WHERE json_extract(name,'$[0]')=? AND expires+?<=${nowSql} ORDER BY expires LIMIT ?)`).bind(this.service,this.policyVersion,this.policyConfig,this.service,retentionSkew,limitRows);
    const rates=this.db.prepare(`DELETE FROM sapi_replay_rates WHERE EXISTS(SELECT 1 FROM sapi_replay_policy p JOIN sapi_replay_owner o ON o.singleton=1 AND o.service=p.service AND o.version=p.version AND o.config=p.config WHERE p.service=? AND p.version=? AND p.config=?) AND name IN
      (SELECT name FROM sapi_replay_rates WHERE json_extract(name,'$[1]')=? AND started+3600+?<=${nowSql} ORDER BY started LIMIT ?)`).bind(this.service,this.policyVersion,this.policyConfig,this.service,this.maxClockSkew,limitRows);
    await this.db.batch([claims,rates]);
  }
}

// Explicit administrator operation; never called by claim/admit/cleanup.
// The same policy may be rechecked after an uncertain response.
export async function initializeExclusivePolicy(db,store) {
  if (!(store instanceof D1ReplayStore) || store.db!==db) throw new TypeError('matching configured store required');
  const {service,version,config}=store.policyRecord();
  const row=await db.prepare(`INSERT INTO sapi_replay_owner(singleton,service,version,config)
   SELECT 1,?,?,? WHERE
   NOT EXISTS(SELECT 1 FROM sapi_replay_policy WHERE service<>? OR version<>? OR config<>?)
   AND (SELECT count(*) FROM sapi_replay_claims)<=? AND (SELECT count(*) FROM sapi_replay_rates)<=?
   AND NOT EXISTS(SELECT 1 FROM sapi_replay_claims WHERE CASE WHEN json_valid(name) THEN NOT COALESCE(((json_type(name) IS 'array') AND (json_array_length(name)=3) AND (json_type(name,'$[0]') IS 'text' AND json_extract(name,'$[0]') IS ?) AND ((json_type(name,'$[1]') IS 'text' AND instr(json_extract(name,'$[1]'),char(0))=0 AND length(json_extract(name,'$[1]')) BETWEEN 1 AND 64 AND json_extract(name,'$[1]') NOT GLOB '*[^A-Za-z0-9_-]*')) AND (json_type(name,'$[2]') IS 'text' AND instr(json_extract(name,'$[2]'),char(0))=0 AND length(json_extract(name,'$[2]'))=32 AND json_extract(name,'$[2]') NOT GLOB '*[^0-9a-f]*') AND (name=json_array(json_extract(name,'$[0]'),json_extract(name,'$[1]'),json_extract(name,'$[2]')))),0) ELSE 1 END)
   AND NOT EXISTS(SELECT 1 FROM sapi_replay_rates WHERE CASE WHEN json_valid(name) THEN NOT COALESCE(((json_type(name) IS 'array') AND (json_type(name,'$[0]') IS 'text' AND json_extract(name,'$[0]') IN ('global','cost','operation')) AND (json_type(name,'$[1]') IS 'text' AND json_extract(name,'$[1]') IS ?) AND ((json_type(name,'$[2]') IS 'text' AND length(CAST(json_extract(name,'$[2]') AS BLOB)) BETWEEN 1 AND 4096 AND (WITH RECURSIVE u(h,i,units) AS (SELECT hex(CAST(json_extract(name,'$[2]') AS BLOB)),1,0 UNION ALL SELECT h,i+CASE WHEN (substr(h,i+0,2) BETWEEN '00' AND '7F') THEN 2 WHEN (substr(h,i+0,2) BETWEEN 'C2' AND 'DF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF')) THEN 4 WHEN ((substr(h,i+0,2)='E0' AND substr(h,i+2,2) BETWEEN 'A0' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'E1' AND 'EC' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='ED' AND substr(h,i+2,2) BETWEEN '80' AND '9F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'EE' AND 'EF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF'))) THEN 6 ELSE 8 END,units+CASE WHEN ((substr(h,i+0,2)='F0' AND substr(h,i+2,2) BETWEEN '90' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'F1' AND 'F3' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='F4' AND substr(h,i+2,2) BETWEEN '80' AND '8F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF'))) THEN 2 ELSE 1 END FROM u WHERE i<=length(h) AND units<=1024 AND ((substr(h,i+0,2) BETWEEN '00' AND '7F') OR (substr(h,i+0,2) BETWEEN 'C2' AND 'DF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF')) OR ((substr(h,i+0,2)='E0' AND substr(h,i+2,2) BETWEEN 'A0' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'E1' AND 'EC' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='ED' AND substr(h,i+2,2) BETWEEN '80' AND '9F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'EE' AND 'EF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF'))) OR ((substr(h,i+0,2)='F0' AND substr(h,i+2,2) BETWEEN '90' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'F1' AND 'F3' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='F4' AND substr(h,i+2,2) BETWEEN '80' AND '8F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF'))))) SELECT EXISTS(SELECT 1 FROM u WHERE i=length(h)+1 AND units BETWEEN 1 AND 1024)))) AND ((((json_extract(name,'$[0]') IN ('global','cost')) AND json_array_length(name)=3 AND name=json_array(json_extract(name,'$[0]'),json_extract(name,'$[1]'),json_extract(name,'$[2]'))) OR (json_extract(name,'$[0]')='operation' AND json_array_length(name)=4 AND (json_type(name,'$[3]') IS 'text' AND instr(json_extract(name,'$[3]'),char(0))=0 AND length(json_extract(name,'$[3]')) BETWEEN 1 AND 64 AND json_extract(name,'$[3]') NOT GLOB '*[^A-Za-z0-9_-]*') AND name=json_array(json_extract(name,'$[0]'),json_extract(name,'$[1]'),json_extract(name,'$[2]'),json_extract(name,'$[3]')))))),0) ELSE 1 END)
   ON CONFLICT(singleton) DO NOTHING RETURNING service,version,config`).bind(service,version,config,service,version,config,store.capacity,store.rateCapacity,service,service).first();
  if (row!==null && (!exactRecord(row,['service','version','config']) || row.service!==service || row.version!==version || row.config!==config)) throw new Error('uncertain exclusive initialization');
  if (row!==null) return true;
  // Reads use the primary binding; fail closed if the owner cannot be confirmed.
  const existing=await db.prepare(`SELECT o.service,o.version,o.config FROM sapi_replay_owner o JOIN sapi_replay_policy p ON p.service=o.service AND p.version=o.version AND p.config=o.config
   WHERE o.singleton=1 AND o.service=? AND o.version=? AND o.config=?
   AND NOT EXISTS(SELECT 1 FROM sapi_replay_policy WHERE service<>? OR version<>? OR config<>?)
   AND (SELECT count(*) FROM sapi_replay_claims)<=? AND (SELECT count(*) FROM sapi_replay_rates)<=?
   AND NOT EXISTS(SELECT 1 FROM sapi_replay_claims WHERE CASE WHEN json_valid(name) THEN NOT COALESCE(((json_type(name) IS 'array') AND (json_array_length(name)=3) AND (json_type(name,'$[0]') IS 'text' AND json_extract(name,'$[0]') IS ?) AND ((json_type(name,'$[1]') IS 'text' AND instr(json_extract(name,'$[1]'),char(0))=0 AND length(json_extract(name,'$[1]')) BETWEEN 1 AND 64 AND json_extract(name,'$[1]') NOT GLOB '*[^A-Za-z0-9_-]*')) AND (json_type(name,'$[2]') IS 'text' AND instr(json_extract(name,'$[2]'),char(0))=0 AND length(json_extract(name,'$[2]'))=32 AND json_extract(name,'$[2]') NOT GLOB '*[^0-9a-f]*') AND (name=json_array(json_extract(name,'$[0]'),json_extract(name,'$[1]'),json_extract(name,'$[2]')))),0) ELSE 1 END)
   AND NOT EXISTS(SELECT 1 FROM sapi_replay_rates WHERE CASE WHEN json_valid(name) THEN NOT COALESCE(((json_type(name) IS 'array') AND (json_type(name,'$[0]') IS 'text' AND json_extract(name,'$[0]') IN ('global','cost','operation')) AND (json_type(name,'$[1]') IS 'text' AND json_extract(name,'$[1]') IS ?) AND ((json_type(name,'$[2]') IS 'text' AND length(CAST(json_extract(name,'$[2]') AS BLOB)) BETWEEN 1 AND 4096 AND (WITH RECURSIVE u(h,i,units) AS (SELECT hex(CAST(json_extract(name,'$[2]') AS BLOB)),1,0 UNION ALL SELECT h,i+CASE WHEN (substr(h,i+0,2) BETWEEN '00' AND '7F') THEN 2 WHEN (substr(h,i+0,2) BETWEEN 'C2' AND 'DF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF')) THEN 4 WHEN ((substr(h,i+0,2)='E0' AND substr(h,i+2,2) BETWEEN 'A0' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'E1' AND 'EC' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='ED' AND substr(h,i+2,2) BETWEEN '80' AND '9F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'EE' AND 'EF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF'))) THEN 6 ELSE 8 END,units+CASE WHEN ((substr(h,i+0,2)='F0' AND substr(h,i+2,2) BETWEEN '90' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'F1' AND 'F3' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='F4' AND substr(h,i+2,2) BETWEEN '80' AND '8F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF'))) THEN 2 ELSE 1 END FROM u WHERE i<=length(h) AND units<=1024 AND ((substr(h,i+0,2) BETWEEN '00' AND '7F') OR (substr(h,i+0,2) BETWEEN 'C2' AND 'DF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF')) OR ((substr(h,i+0,2)='E0' AND substr(h,i+2,2) BETWEEN 'A0' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'E1' AND 'EC' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='ED' AND substr(h,i+2,2) BETWEEN '80' AND '9F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'EE' AND 'EF' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF'))) OR ((substr(h,i+0,2)='F0' AND substr(h,i+2,2) BETWEEN '90' AND 'BF' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2) BETWEEN 'F1' AND 'F3' AND (substr(h,i+2,2) BETWEEN '80' AND 'BF') AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF')) OR (substr(h,i+0,2)='F4' AND substr(h,i+2,2) BETWEEN '80' AND '8F' AND (substr(h,i+4,2) BETWEEN '80' AND 'BF') AND (substr(h,i+6,2) BETWEEN '80' AND 'BF'))))) SELECT EXISTS(SELECT 1 FROM u WHERE i=length(h)+1 AND units BETWEEN 1 AND 1024)))) AND ((((json_extract(name,'$[0]') IN ('global','cost')) AND json_array_length(name)=3 AND name=json_array(json_extract(name,'$[0]'),json_extract(name,'$[1]'),json_extract(name,'$[2]'))) OR (json_extract(name,'$[0]')='operation' AND json_array_length(name)=4 AND (json_type(name,'$[3]') IS 'text' AND instr(json_extract(name,'$[3]'),char(0))=0 AND length(json_extract(name,'$[3]')) BETWEEN 1 AND 64 AND json_extract(name,'$[3]') NOT GLOB '*[^A-Za-z0-9_-]*') AND name=json_array(json_extract(name,'$[0]'),json_extract(name,'$[1]'),json_extract(name,'$[2]'),json_extract(name,'$[3]')))))),0) ELSE 1 END)`).bind(service,version,config,service,version,config,store.capacity,store.rateCapacity,service,service).first();
  if (existing===null) return false;
  if (!exactRecord(existing,['service','version','config']) || existing.service!==service || existing.version!==version || existing.config!==config) throw new Error('uncertain exclusive initialization');
  return true;
}
