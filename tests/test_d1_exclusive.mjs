// Exclusive-mode local integration test; every binding is a disposable D1.
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';
const spec=process.env.D1_TEST_MINIFLARE?pathToFileURL(process.env.D1_TEST_MINIFLARE).href:'miniflare';
const {Miniflare}=await import(spec),persist=await mkdtemp(join(tmpdir(),'sapi-exclusive-'));
const schema=await readFile(new URL('../sdks/javascript/src/state-d1.sql',import.meta.url),'utf8');let mf;
const now=()=>Math.floor(Date.now()/1000), key=(service,n)=>`${service}|kid|${n.toString(16).padStart(32,'0')}`;
async function deny(p){try{return (await p)!==true}catch{return true}}
async function schemaInit(db){let sql='',trigger=false;
 for(const line of schema.split(/\r?\n/)){
  if(!sql&&(!line.trim()||line.trim().startsWith('--')))continue;
  if(!sql&&line.trim().startsWith('CREATE TRIGGER'))trigger=true;
  sql+=line+'\n';if((trigger&&(line.trim()==='END;'||/\bBEGIN\b.*\bEND;\s*$/.test(line)))||(!trigger&&line.trim().endsWith(';'))){await db.prepare(sql).run();sql='';trigger=false}
 }
 if(sql.trim())throw Error('incomplete schema');
}
try{
 mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',d1Databases:['A','B','RACE','DIRTY','OVERCAP','MATCH','ACK','BADJSON','FOREIGNPOLICY'],d1Persist:persist});
 const bindings=Object.fromEntries(await Promise.all(['A','B','RACE','DIRTY','OVERCAP','MATCH','ACK','BADJSON','FOREIGNPOLICY'].map(async n=>[n,await mf.getD1Database(n)])));
 for(const db of Object.values(bindings))await schemaInit(db);
 const opts=service=>({mode:'exclusive',service,policyVersion:'v1',capacity:2,rateCapacity:2,operations:{write:{requests:2,period:60}}});
 const a=new D1ReplayStore(bindings.A,opts('serviceA')),b=new D1ReplayStore(bindings.B,opts('serviceB'));
 for(const invalid of [{service:'x',policyVersion:'v1'},{mode:'shared',service:'x',policyVersion:'v1'}])assert.throws(()=>new D1ReplayStore(bindings.A,invalid),TypeError);
 assert.equal(await initializeExclusivePolicy(bindings.A,a),true);assert.equal(await initializeExclusivePolicy(bindings.B,b),true);
 assert.equal(await initializeExclusivePolicy(bindings.A,a),true,'same initializer is idempotent');
 assert.equal(await a.claim(key('serviceA',1),now()+55,now()),true);assert.equal(await a.claim(key('serviceA',2),now()+55,now()),true);
 assert.equal(await a.claim(key('serviceA',3),now()+55,now()),false,'A exhausts its own claim cap');
 assert.equal(await b.claim(key('serviceB',1),now()+55,now()),true,'B retains its own independent claim capacity');
 assert.equal(await a.admit('serviceA','kid','subA','write',now(),2,60),true);
 assert.equal(await a.admit('serviceA','kid','anotherA','write',now(),2,60),false,'A exhausts its own two rate slots');
 assert.equal(await b.admit('serviceB','kid','subB','write',now(),2,60),true,'B retains independent rate capacity');
 for(const [n,expected] of [['A',2],['B',1]])assert.equal(Number((await bindings[n].prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),expected);
 for(const n of ['A','B'])assert.equal(Number((await bindings[n].prepare('SELECT count(*) AS n FROM sapi_replay_rates').first()).n),2);
 const smaller=new D1ReplayStore(bindings.A,{...opts('serviceA'),capacity:1});
 assert.equal(await deny(initializeExclusivePolicy(bindings.A,smaller)),true,'shrinking a live DB must not silently overwrite policy');
 assert.equal(Number((await bindings.A.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),2,'refused shrink retains existing rows');
 assert.equal(await a.claim(key('serviceA',1),now()+55,now()),false,'refused shrink retains old claim');
 await bindings.A.prepare('UPDATE sapi_replay_claims SET expires=?').bind(now()-40).run();await a.cleanup(100);
 assert.equal(Number((await bindings.A.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),0);
 assert.equal(Number((await bindings.B.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),1,'cleanup is isolated to owned DB');
 const raceStores=Array.from({length:20},(_,i)=>new D1ReplayStore(bindings.RACE,opts(i%2?'serviceB':'serviceA')));
 const results=await Promise.all(raceStores.map(x=>initializeExclusivePolicy(bindings.RACE,x).catch(()=>false)));
 assert.ok(results.some(Boolean),'one owner can initialize');
 assert.equal(new Set(results.map((ok,i)=>ok?raceStores[i].service:null).filter(Boolean)).size,1,'same DB cannot accept both services');
 const raceRows=(await bindings.RACE.prepare('SELECT service FROM sapi_replay_policy').all()).results;assert.equal(raceRows.length,1);
 const lost=results.map((ok,i)=>ok?null:raceStores[i]).find(Boolean);assert.equal(await deny(lost.claim(key(lost.service,1),now()+55,now())),true,'losing owner cannot claim');
 // Existing other-service rows and excess rows must not be adopted as clean.
 const dirtyStore=new D1ReplayStore(bindings.DIRTY,opts('serviceA'));
 await bindings.DIRTY.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify(['serviceB','kid','1'.repeat(32)]),now()+55).run();
 assert.equal(await deny(initializeExclusivePolicy(bindings.DIRTY,dirtyStore)),true,'foreign legacy data rejected');
 const overStore=new D1ReplayStore(bindings.OVERCAP,opts('serviceA'));
 for(let i=0;i<3;i++)await bindings.OVERCAP.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify(['serviceA','kid',i.toString(16).padStart(32,'0')]),now()+55).run();
 assert.equal(await deny(initializeExclusivePolicy(bindings.OVERCAP,overStore)),true,'legacy over-cap data rejected');
 assert.equal(Number((await bindings.OVERCAP.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),3,'rejection preserves data');
 const badStore=new D1ReplayStore(bindings.BADJSON,opts('serviceA'));
 await bindings.BADJSON.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind('not-json',now()+55).run();
 assert.equal(await deny(initializeExclusivePolicy(bindings.BADJSON,badStore)),true,'malformed legacy namespace rejected');
 assert.equal(Number((await bindings.BADJSON.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),1);
 const foreignPolicyStore=new D1ReplayStore(bindings.FOREIGNPOLICY,opts('serviceA'));
 const foreignPolicy=new D1ReplayStore(bindings.FOREIGNPOLICY,opts('serviceB')).policyRecord();
 await bindings.FOREIGNPOLICY.prepare('INSERT INTO sapi_replay_policy(service,version,config) VALUES (?,?,?)').bind(foreignPolicy.service,foreignPolicy.version,foreignPolicy.config).run();
 assert.equal(await deny(initializeExclusivePolicy(bindings.FOREIGNPOLICY,foreignPolicyStore)),true,'different legacy service policy rejected');
 const acknowledged=bindings.ACK;let injected=false;
 const lossDb={prepare(statement){const p=acknowledged.prepare(statement);return {bind(...args){const q=p.bind(...args);return {async first(){const result=await q.first();if(statement.includes('INSERT INTO sapi_replay_owner')){injected=true;throw Error('simulated lost initialization response')}return result},run:()=>q.run(),all:()=>q.all()}}}},batch:(...args)=>acknowledged.batch(...args)};
 const uncertainStore=new D1ReplayStore(lossDb,opts('serviceA'));
 await assert.rejects(initializeExclusivePolicy(lossDb,uncertainStore),/simulated lost/);assert.equal(injected,true);
 const recoveredStore=new D1ReplayStore(acknowledged,opts('serviceA'));
 assert.equal(await initializeExclusivePolicy(acknowledged,recoveredStore),true,'uncertain initial result reconciles by safe retry');
 assert.equal(Number((await acknowledged.prepare('SELECT count(*) AS n FROM sapi_replay_owner').first()).n),1);
 assert.equal(Number((await acknowledged.prepare('SELECT count(*) AS n FROM sapi_replay_policy').first()).n),1);
 await assert.rejects(acknowledged.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify(['serviceB','kid','a'.repeat(32)]),now()+55).run(),'owner trigger rejects foreign contamination');
 assert.equal(await initializeExclusivePolicy(acknowledged,recoveredStore),true);
 assert.equal(Number((await acknowledged.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),0);
 await bindings.B.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify(['serviceB','kid',(10).toString(16).padStart(32,'0')]),now()+55).run();
 await assert.rejects(bindings.B.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify(['serviceB','kid',(11).toString(16).padStart(32,'0')]),now()+55).run(),'owner trigger rejects over-cap contamination');
 assert.equal(await initializeExclusivePolicy(bindings.B,b),true);
 assert.equal(Number((await bindings.B.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),2);
 const matchStore=new D1ReplayStore(bindings.MATCH,opts('serviceA')),old=matchStore.policyRecord();
 await bindings.MATCH.prepare('INSERT INTO sapi_replay_policy(service,version,config) VALUES (?,?,?)').bind(old.service,old.version,old.config).run();
 await bindings.MATCH.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify(['serviceA','kid','1'.repeat(32)]),now()+55).run();
 assert.equal(await initializeExclusivePolicy(bindings.MATCH,matchStore),true,'matching in-limit legacy data can be adopted');
 assert.equal(Number((await bindings.MATCH.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),1);
 console.log('Exclusive D1: two DB isolation, same-DB race, shrink, cleanup, legacy adoption/rejection passed');
}finally{
 if(mf)await mf.dispose();const base=resolve(tmpdir()),target=resolve(persist);
 if(!target.startsWith(base+sep)||!target.slice(base.length+1).startsWith('sapi-exclusive-'))throw Error('unsafe disposable path');
 await rm(target,{recursive:true,force:true});
}