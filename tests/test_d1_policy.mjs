// Disposable local D1 policy integration test. No network or production binding.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';
import {Codec,SecureServer,StaticKeyProvider} from '../sdks/javascript/src/index.js';
const specifier=process.env.D1_TEST_MINIFLARE ? pathToFileURL(process.env.D1_TEST_MINIFLARE).href : 'miniflare';
const {Miniflare}=await import(specifier), persist=await mkdtemp(join(tmpdir(),'sapi-d1-policy-'));
const schema=await readFile(new URL('../sdks/javascript/src/state-d1.sql',import.meta.url),'utf8');
const options={mode:'exclusive',service:'example',policyVersion:'v1',operations:{write:{requests:2,period:60}},costLimit:4,costPeriod:60};
const now=()=>Math.floor(Date.now()/1000), key=i=>`example|kid|${i.toString(16).padStart(32,'0')}`;
const validationDb={prepare(){},batch(){}};
for (const invalidService of [1, true, null, undefined, {toString:()=> 'example'}]) {
 assert.throws(()=>new D1ReplayStore(validationDb,{...options,service:invalidService}),TypeError,'service must be a string');
}
assert.doesNotThrow(()=>new D1ReplayStore(validationDb,options),'valid string service accepted');
let mf;
async function denied(promise) {try {let x=await promise;return x===false||x==='rate_limited'} catch{return true}}
try {
 mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',d1Databases:['TEST_DB'],d1Persist:persist});
 const db=await mf.getD1Database('TEST_DB');let sql='',inTrigger=false;
 for (const line of schema.split(/\r?\n/)) {
  if (!sql&&(!line.trim()||line.trim().startsWith('--')))continue;
  if (!sql&&line.trim().startsWith('CREATE TRIGGER'))inTrigger=true;
  sql+=line+'\n';
  if((inTrigger&&(line.trim()==='END;'||/\bBEGIN\b.*\bEND;\s*$/.test(line)))||(!inTrigger&&line.trim().endsWith(';'))){await db.prepare(sql).run();sql='';inTrigger=false}
 }
 if(sql.trim())throw Error('incomplete schema');
 const base=new D1ReplayStore(db,options),record=base.policyRecord();
 assert.equal(await denied(base.claim(key(1),now()+55,now())),true,'missing policy rejects claim');
 assert.equal(await denied(base.admit('example','kid','sub','write',now(),2,60)),true,'missing policy rejects admission');
 const setup=await Promise.all(Array.from({length:20},()=>initializeExclusivePolicy(db,base)));
 assert.equal(setup.filter(Boolean).length,20,'same exclusive policy initialization is idempotent');
 assert.equal(Number((await db.prepare('SELECT count(*) AS n FROM sapi_replay_policy WHERE service=?').bind('example').first()).n),1);
 const same=new D1ReplayStore(db,options),different=new D1ReplayStore(db,{...options,costLimit:5});
 const sharedAdmissions=await Promise.all(Array.from({length:10},(_,i)=>(i%2?same:base).admit('example','kid','sharedBudget','write',now(),2,60)));
 assert.equal(sharedAdmissions.filter(x=>x===true).length,2,'matching objects share one business budget');
 assert.equal(sharedAdmissions.filter(x=>x===false).length,8);
 const sharedCost=await Promise.all(Array.from({length:10},(_,i)=>(i%2?same:base).claimBounded('example','sharedBudget',key(20+i),now()+55,now())));
 assert.equal(sharedCost.filter(x=>x==='accepted').length,4,'matching objects share one separate cost budget');
 assert.equal(sharedCost.filter(x=>x==='rate_limited').length,6);
 const businessName=JSON.stringify(['operation','example','sharedBudget','write']),costName=JSON.stringify(['cost','example','sharedBudget']);
 assert.equal(Number((await db.prepare('SELECT used FROM sapi_replay_rates WHERE name=?').bind(businessName).first()).used),2);
 assert.equal(Number((await db.prepare('SELECT used FROM sapi_replay_rates WHERE name=?').bind(costName).first()).used),4);
 const claims=await Promise.all(Array.from({length:20},(_,i)=>(i%2?same:base).claim(key(2),now()+55,now())));
 assert.equal(claims.filter(x=>x===true).length,1,'matching instances share replay claim');
 assert.equal(await denied(different.claim(key(3),now()+55,now())),true,'different policy cannot claim');
 assert.equal(await denied(different.admit('example','kid','sub','write',now(),2,60)),true,'different policy cannot admit');
 assert.equal(await denied(different.claimBounded('example','sub',key(4),now()+55,now())),true,'different policy cannot claim bounded');
 const keys=new StaticKeyProvider({kid:{master:crypto.getRandomValues(new Uint8Array(32)),subject:'sub',scopes:['write']}}),codec=new Codec('example',keys);
 const shape={type:'object',properties:{ok:{type:'boolean'}}};let called=0;
 for(const splitBudget of [false,true]){
  const server=new SecureServer(codec,different,{splitBudget});server.register('write','write',shape,shape,()=>true,()=>{called++;return {ok:true}},{requests:2,period:60});
  const ctx=await codec.request('kid','write',{ok:true});const result=await codec.acceptResponse(ctx,await server.handle(ctx.wire));
  assert.notEqual(result.ok,true,'mismatched policy must not return success');
 }
 assert.equal(called,0,'mismatched policy never invokes handler');
 // Default non-split SDK path remains compatible with the matching policy.
 const defaultServer=new SecureServer(codec,base);defaultServer.register('write','write',shape,shape,()=>true,()=>{called++;return {ok:true}},{requests:2,period:60});
 const defaultCtx=await codec.request('kid','write',{ok:true});
 assert.equal((await codec.acceptResponse(defaultCtx,await defaultServer.handle(defaultCtx.wire))).ok,true);
 assert.equal((await codec.open(await defaultServer.handle(defaultCtx.wire),'res')).payload.error,'replay');
 assert.equal(called,1,'default replay denial does not reinvoke handler');
 // An established exclusive owner makes policy changes fail at the DB boundary.
 const differentRecord=different.policyRecord();
 await assert.rejects(db.prepare('UPDATE sapi_replay_policy SET config=? WHERE service=?').bind(differentRecord.config,'example').run());
 assert.equal(await base.claim(key(5),now()+55,now()),true,'rejected policy mutation preserves authorized operation');
 const expKey=key(6),encoded=JSON.stringify(expKey.split('|'));
 await db.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(encoded,now()-40).run();
 const result=await Promise.all([base.cleanup(100),base.claim(expKey,now()+55,now())]);
 assert.equal(result[1],true,'expired claim can be renewed despite cleanup');
 assert.equal(await base.claim(expKey,now()+55,now()),false,'cleanup never deletes renewed claim');
 console.log('D1 exclusive policy: idempotent initialization, shared budgets, mismatch, immutable policy, expiry/cleanup passed');
} finally {
 if(mf)await mf.dispose();const base=resolve(tmpdir()),target=resolve(persist);
 if(!target.startsWith(base+sep)||!target.slice(base.length+1).startsWith('sapi-d1-policy-'))throw Error('unsafe disposable path');
 await rm(target,{recursive:true,force:true});
}