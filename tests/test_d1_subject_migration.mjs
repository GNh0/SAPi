// Local rehearsal of NAME-only exclusive -> expanded subject guards. Requires
// an exact checked-in fixture for the prior schema; never runs on a live DB.
import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import {mkdtemp,readFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join,resolve,sep} from 'node:path';import {pathToFileURL} from 'node:url';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';import {Codec,SecureServer} from '../sdks/javascript/src/index.js';
const legacyBytes=await readFile(new URL('./fixtures/state-d1-name-only-2ba2378.sql',import.meta.url));
assert.equal(legacyBytes.length,10874,'historical schema byte length');
assert.equal(createHash('sha256').update(legacyBytes).digest('hex'),'753a6d6a9cad0d442ae39d21b0ca84e614e08ba7c4e4823cb74411036f0b2f35','historical schema SHA-256');
const legacy=legacyBytes.toString('utf8');
const expectedOldHashes={sapi_replay_owner_validate:'325d4e34ad01851b38af91d109d51177bcbceef979cb1e0fc7bf5a1fe7346b29',sapi_replay_rate_owner_guard:'f7b75a41ef8b9c79f509156f6ab9e1cf7877f3953b5b2c279dabde5003bc2ca3'};
const migration=await readFile(new URL('../sdks/javascript/src/state-d1-subject-migration.sql',import.meta.url),'utf8');
const statements=migration.split('--> statement-breakpoint').map(x=>x.trim()).filter(Boolean);assert.equal(statements.length,4);
const triggerNames=['sapi_replay_owner_validate','sapi_replay_rate_owner_guard'];
const expectedNew=Object.fromEntries(statements.filter(s=>s.startsWith('CREATE TRIGGER')).map(s=>{const name=s.match(/^CREATE TRIGGER\s+(\w+)/)?.[1];return [name,s.replace(/;\s*$/,'')]}));
assert.deepEqual(Object.keys(expectedNew).sort(),[...triggerNames].sort());
const spec=process.env.D1_TEST_MINIFLARE?pathToFileURL(process.env.D1_TEST_MINIFLARE).href:'miniflare';const {Miniflare}=await import(spec),persist=await mkdtemp(join(tmpdir(),'sapi-subject-migration-'));let mf;
async function apply(db,text){let sql='',trigger=false;for(const line of text.split(/\r?\n/)){if(!sql&&(!line.trim()||line.trim().startsWith('--')))continue;if(!sql&&line.trim().startsWith('CREATE TRIGGER'))trigger=true;sql+=line+'\n';if((trigger&&(line.trim()==='END;'||/\bBEGIN\b.*\bEND;\s*$/.test(line)))||(!trigger&&line.trim().endsWith(';'))){await db.prepare(sql).run();sql='';trigger=false}}if(sql.trim())throw Error('incomplete schema')}
async function triggerState(db){const rows=(await db.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND name IN ('sapi_replay_owner_validate','sapi_replay_rate_owner_guard') ORDER BY name").all()).results;return Object.fromEntries(rows.map(r=>[r.name,r.sql]))}
async function snapshot(db){const all=async table=>(await db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all()).results;return {owner:await all('sapi_replay_owner'),policy:await all('sapi_replay_policy'),claims:await all('sapi_replay_claims'),rates:await all('sapi_replay_rates')}}
try{
 mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',d1Databases:['ROLLBACK','MID','LOSS'],d1Persist:persist});
 const dbs=[await mf.getD1Database('ROLLBACK'),await mf.getD1Database('MID'),await mf.getD1Database('LOSS')],config={mode:'exclusive',service:'svc',policyVersion:'v1',capacity:50,rateCapacity:50,operations:{write:{requests:2,period:60}}};
 const before=[];for(const db of dbs){await apply(db,legacy);const store=new D1ReplayStore(db,config);assert.equal(await initializeExclusivePolicy(db,store),true);const now=Math.floor(Date.now()/1000);assert.equal(await store.claim('svc|kid|'+'1'.repeat(32),now+55,now),true);assert.equal(await store.admit('svc','kid','ascii','write',now,2,60),true);before.push({rows:await snapshot(db),triggers:await triggerState(db)});assert.equal(Object.keys(before.at(-1).triggers).length,2);for(const [name,definition] of Object.entries(before.at(-1).triggers))assert.equal(createHash('sha256').update(definition.replace(/\r\n/g,'\n')).digest('hex'),expectedOldHashes[name],`historical trigger ${name} SHA-256`);await assert.rejects(db.prepare('INSERT INTO sapi_replay_rates(name,started,used,period) VALUES (?,0,1,60)').bind(JSON.stringify(['global','svc','사용자'])).run(),'old guard rejects Unicode')}
 const [rollback,mid,loss]=dbs;
 const conflict=rollback.prepare('INSERT INTO sapi_replay_policy(service,version,config) VALUES (?,?,?)').bind('svc','v1','conflict');
 await assert.rejects(rollback.batch([...statements.map(s=>rollback.prepare(s)),conflict]),'later failure aborts whole D1 batch');
 assert.deepEqual(await triggerState(rollback),before[0].triggers,'failure leaves both old trigger definitions');assert.deepEqual(await snapshot(rollback),before[0].rows,'failure retains all rows');
 await assert.rejects(rollback.prepare('INSERT INTO sapi_replay_rates(name,started,used,period) VALUES (?,0,1,60)').bind(JSON.stringify(['global','svc','사용자'])).run(),'old guard remains active after rollback');
 const midConflict=mid.prepare('INSERT INTO sapi_replay_policy(service,version,config) VALUES (?,?,?)').bind('svc','v1','conflict');
 await assert.rejects(mid.batch([...statements.slice(0,2).map(s=>mid.prepare(s)),midConflict,...statements.slice(2).map(s=>mid.prepare(s))]),'failure between trigger replacements aborts whole batch');
 assert.deepEqual(await triggerState(mid),before[1].triggers,'partial replacement rolls back to both old guards');
 assert.deepEqual(await snapshot(mid),before[1].rows);
 let lost=false;try{await loss.batch(statements.map(s=>loss.prepare(s)));throw Error('simulated lost batch response')}catch{lost=true}assert.equal(lost,true);
 assert.deepEqual(await triggerState(loss),expectedNew,'reconcile both actual definitions after unknown result');assert.deepEqual(await snapshot(loss),before[2].rows,'successful migration preserves old owner, policy and data');
 const provider={async get(){return {master:new Uint8Array(32).fill(42),subject:'사용자',scopes:['write']}},async reserve(service,kid){return this.get(service,kid)}};
 const codec=new Codec('svc',provider),store=new D1ReplayStore(loss,config),server=new SecureServer(codec,store,{splitBudget:true}),shape={type:'object',properties:{ok:{type:'boolean'}}};let handled=0;
 server.register('write','write',shape,shape,()=>true,()=>{handled++;return {ok:true}},{requests:2,period:60});
 const request=await codec.request('kid','write',{ok:true}),response=await codec.acceptResponse(request,await server.handle(request.wire));assert.equal(response.ok,true);assert.equal(handled,1);
 console.log('D1 guard upgrade: four-statement batch rollback, exact trigger reconciliation after lost response, retained ASCII data and Unicode SDK passed');
}finally{if(mf)await mf.dispose();const base=resolve(tmpdir()),target=resolve(persist);if(!target.startsWith(base+sep)||!target.slice(base.length+1).startsWith('sapi-subject-migration-'))throw Error('unsafe disposable path');await rm(target,{recursive:true,force:true})}