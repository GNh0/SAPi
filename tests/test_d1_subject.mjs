// Subject compatibility with a trusted custom key provider, local disposable D1.
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join,resolve,sep} from 'node:path';import {pathToFileURL} from 'node:url';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';import {Codec,SecureServer,MemoryReplayStore} from '../sdks/javascript/src/index.js';
const spec=process.env.D1_TEST_MINIFLARE?pathToFileURL(process.env.D1_TEST_MINIFLARE).href:'miniflare';const {Miniflare}=await import(spec),persist=await mkdtemp(join(tmpdir(),'sapi-subject-'));
const schema=await readFile(new URL('../sdks/javascript/src/state-d1.sql',import.meta.url),'utf8');let mf;
async function apply(db){let sql='',trigger=false;for(const line of schema.split(/\r?\n/)){if(!sql&&(!line.trim()||line.trim().startsWith('--')))continue;if(!sql&&line.trim().startsWith('CREATE TRIGGER'))trigger=true;sql+=line+'\n';if((trigger&&(line.trim()==='END;'||/\bBEGIN\b.*\bEND;\s*$/.test(line)))||(!trigger&&line.trim().endsWith(';'))){await db.prepare(sql).run();sql='';trigger=false}}if(sql.trim())throw Error('incomplete schema')}
const valid=['user@example.com','사용자','person@example.invalid','사용자@example.invalid','alpha|beta','alpha',"x'); DROP TABLE sapi_replay_policy;--",'nul\u0000tail','é','e\u0301','가'.repeat(1024),'x'.repeat(1024),'😀'.repeat(512)];
const invalid=['','x'.repeat(1025),'가'.repeat(1025),'😀'.repeat(513),'\ud800','\udfff'];
try{
 mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',d1Databases:['MAIN','LEGACY','BAD',...invalid.map((_,i)=>'INVALID'+i)],d1Persist:persist});
 const main=await mf.getD1Database('MAIN'),legacy=await mf.getD1Database('LEGACY'),bad=await mf.getD1Database('BAD');for(const db of [main,legacy,bad])await apply(db);const invalidDbs=await Promise.all(invalid.map((_,i)=>mf.getD1Database('INVALID'+i)));for(const db of invalidDbs)await apply(db);
 const config={mode:'exclusive',service:'svc',policyVersion:'v1',operations:{write:{requests:2,period:60}},costLimit:5};
 const store=new D1ReplayStore(main,config);assert.equal(await initializeExclusivePolicy(main,store),true);
 const sharedKey=crypto.getRandomValues(new Uint8Array(32));const byKid=Object.fromEntries(valid.map((subject,i)=>['k'+i,subject]));
 const provider={async get(_service,kid){return {master:sharedKey,subject:byKid[kid],scopes:['write']}},async reserve(service,kid){return this.get(service,kid)}};
 const codec=new Codec('svc',provider),server=new SecureServer(codec,store,{splitBudget:true}),shape={type:'object',properties:{ok:{type:'boolean'}}};let handlers=0;
 server.register('write','write',shape,shape,()=>true,()=>{handlers++;return {ok:true}},{requests:2,period:60});
 const memory=new SecureServer(codec,new MemoryReplayStore());memory.register('write','write',shape,shape,()=>true,()=>({ok:true}),{requests:2,period:60});
 for(const kid of ['k0','k1']){const c=await codec.request(kid,'write',{ok:true});assert.equal((await codec.acceptResponse(c,await memory.handle(c.wire))).ok,true,'original custom provider subject works with memory');}
 for(let i=0;i<valid.length;i++){const ctx=await codec.request('k'+i,'write',{ok:true}),reply=await codec.acceptResponse(ctx,await server.handle(ctx.wire));assert.equal(reply.ok,true,`valid subject ${i} accepted`)}
 assert.equal(handlers,valid.length);
 const rates=(await main.prepare('SELECT name FROM sapi_replay_rates').all()).results.map(r=>JSON.parse(r.name));
 for(const subject of valid)assert.ok(rates.some(row=>row[0]==='global'&&row[1]==='svc'&&row[2]===subject),'subject retained exactly');
 assert.notEqual('é','e\u0301');assert.ok(rates.some(row=>row[2]==='é'));assert.ok(rates.some(row=>row[2]==='e\u0301'));
 assert.equal((await main.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name='sapi_replay_policy'").first()).n,1,'SQL-like text is data');
 for(const [i,subject] of invalid.entries()){
  await assert.rejects(store.admit('svc','kid',subject,'write',Math.floor(Date.now()/1000),2,60),`invalid ${i} rejected by JS`);
  const tuple=JSON.stringify(['global','svc',subject]);
  await assert.rejects(main.prepare('INSERT INTO sapi_replay_rates(name,started,used,period) VALUES (?,0,1,60)').bind(tuple).run(),`invalid ${i} rejected by SQL`);
  const old=invalidDbs[i];await old.prepare('INSERT INTO sapi_replay_rates(name,started,used,period) VALUES (?,0,1,60)').bind(tuple).run();
  let rejected=false;try{rejected=(await initializeExclusivePolicy(old,new D1ReplayStore(old,config)))!==true}catch{rejected=true}
  assert.equal(rejected,true,`invalid legacy ${i} rejected`);assert.equal(Number((await old.prepare('SELECT count(*) AS n FROM sapi_replay_rates').first()).n),1);
 }
 for(const bytes of ['eda080','c080','f4908080','80']){
  const insert=`INSERT INTO sapi_replay_rates(name,started,used,period) SELECT json_array('global','svc',CAST(x'${bytes}' AS TEXT)),0,1,60`;
  await assert.rejects(main.prepare(insert).run(),`invalid UTF-8 bytes ${bytes} rejected by SQL guard`);
 }
 // Even hostile-looking strings are exact values, not SQL or delimiter syntax.
 assert.notDeepEqual(['global','svc','alpha|beta'],['global','svc','alpha','beta']);
 const legacySubject='legacy\u0000@example.invalid',legacyName=JSON.stringify(['global','svc',legacySubject]);
 await legacy.prepare('INSERT INTO sapi_replay_rates(name,started,used,period) VALUES (?,0,1,60)').bind(legacyName).run();
 assert.equal(await initializeExclusivePolicy(legacy,new D1ReplayStore(legacy,config)),true,'valid legacy Unicode/NUL namespace can be adopted');
 await bad.prepare('INSERT INTO sapi_replay_rates(name,started,used,period) VALUES (?,0,1,60)').bind('[ "global", "svc", "subject" ]').run();
 const badStore=new D1ReplayStore(bad,config);let rejected=false;try{rejected=(await initializeExclusivePolicy(bad,badStore))!==true}catch{rejected=true}assert.equal(rejected,true,'noncanonical legacy tuple rejected');assert.equal(Number((await bad.prepare('SELECT count(*) AS n FROM sapi_replay_rates').first()).n),1);
 console.log(`D1 subject contract: ${valid.length} custom-provider values accepted and exact, ${invalid.length} invalid values rejected, legacy guards passed`);
}finally{if(mf)await mf.dispose();const base=resolve(tmpdir()),target=resolve(persist);if(!target.startsWith(base+sep)||!target.slice(base.length+1).startsWith('sapi-subject-'))throw Error('unsafe disposable path');await rm(target,{recursive:true,force:true})}