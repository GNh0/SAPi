// Optional integration test: set D1_TEST_MINIFLARE to an installed Miniflare
// entry point, or install Miniflare in this project. Uses only a disposable D1.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';
import {Codec,SecureServer,StaticKeyProvider} from '../sdks/javascript/src/index.js';

const specifier = process.env.D1_TEST_MINIFLARE
  ? pathToFileURL(process.env.D1_TEST_MINIFLARE).href : 'miniflare';
const {Miniflare} = await import(specifier);
const persist = await mkdtemp(join(tmpdir(), 'sapi-d1-test-'));
const schema = await readFile(new URL('../sdks/javascript/src/state-d1.sql', import.meta.url), 'utf8');
let mf;
async function start() {
  mf = new Miniflare({modules:true, script:'export default {fetch(){return new Response("ok")}}',
    compatibilityDate:'2026-05-15', d1Databases:['TEST_DB','OTHER_DB','SPLIT_DB','BOUNDED_DB','FULL_DB','LOSS_DB','ADMISSION_DB'], d1Persist:persist});
  return mf.getD1Database('TEST_DB');
}
const now = () => Math.floor(Date.now()/1000);
const key = (kid, number) => `service|${kid}|${number.toString(16).padStart(32,'0')}`;
async function denied(promise) {
  try { return (await promise) !== true; } catch { return true; }
}
// Simulate an acknowledged write whose result is lost after execution. This
// wrapper may not affect batch implementations, so the test must assert firing.
function afterWriteLoss(real) {
  let fired = false;
  function wrap(p,sql) {
    return {bind(...args){return wrap(p.bind(...args),sql);},
      async first(...args){const v=await p.first(...args);if(!sql.includes('INSERT INTO sapi_replay_'))return v;fired=true;throw new Error('injected lost result');},
      async run(...args){const v=await p.run(...args);fired=true;throw new Error('injected lost result');},
      async all(...args){const v=await p.all(...args);fired=true;throw new Error('injected lost result');}};
  }
  return {db:{prepare(sql){return wrap(real.prepare(sql),sql);},
    async batch(statements){const v=await real.batch(statements);fired=true;throw new Error('injected lost result');}},
    fired:()=>fired};
}
try {
  let db=await start();
  async function applySchema(db){let sql='',inTrigger=false;
  for (const line of schema.split(/\r?\n/)) {
    if (!sql && (!line.trim() || line.trim().startsWith('--'))) continue;
    if (!sql && line.trim().startsWith('CREATE TRIGGER')) inTrigger=true;
    sql+=line+'\n';
    if ((inTrigger && (line.trim()==='END;'||/\bBEGIN\b.*\bEND;\s*$/.test(line))) || (!inTrigger && line.trim().endsWith(';'))) {
      await db.prepare(sql).run();sql='';inTrigger=false;
    }
  }
  if (sql.trim()) throw new Error('incomplete D1 schema statement');}
  const dbOther=await mf.getD1Database('OTHER_DB'),dbSplit=await mf.getD1Database('SPLIT_DB'),dbBounded=await mf.getD1Database('BOUNDED_DB'),dbFull=await mf.getD1Database('FULL_DB'),dbLoss=await mf.getD1Database('LOSS_DB'),dbAdmission=await mf.getD1Database('ADMISSION_DB');
  for(const target of [db,dbOther,dbSplit,dbBounded,dbFull,dbLoss,dbAdmission])await applySchema(target);
  const options=(service,extra={})=>({mode:'exclusive',service,policyVersion:'v1',...extra});
  const install=async (service,extra={},target=db)=>{const o=options(service,extra),store=new D1ReplayStore(target,o);assert.equal(await initializeExclusivePolicy(target,store),true);return o};
  const baseConfig=await install('service',{operations:{write:{requests:2,period:60}}});
  let store=new D1ReplayStore(db,baseConfig);
  const t=now(), duplicate=key('keyA',1);
  const outcomes=await Promise.all(Array.from({length:32},()=>store.claim(duplicate,t+55,t)));
  assert.equal(outcomes.filter(x=>x===true).length,1,'one winner on concurrent identical claim');
  assert.equal(outcomes.filter(x=>x===false).length,31,'all other claims are duplicates');
  assert.equal(await store.claim(key('keyB',1),t+55,now()),true,'different key id namespace');
  const otherStore=new D1ReplayStore(dbOther,await install('other',{},dbOther));
  assert.equal(await otherStore.claim('other|keyA|'+(1).toString(16).padStart(32,'0'),t+55,now()),true,'different service namespace');
  assert.equal(await denied(store.claim(key('keyA',2),now(),now())),true,'expired request fails closed');
  assert.equal(await denied(store.claim(key('keyA',4),now()+4,now())),true,'near-expiry skew margin fails closed');
  assert.equal(await denied(store.claim(key('keyA',5),now()+55,now()+120)),true,'excessive clock skew fails closed');
  const holdKey=key('keyA',6), holdName=JSON.stringify(holdKey.split('|'));
  await db.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(holdName,now()-20).run();
  assert.equal(await store.claim(holdKey,now()+55,now()),false,'retention skew keeps prior claim');
  await db.prepare('UPDATE sapi_replay_claims SET expires=? WHERE name=?').bind(now()-40,holdName).run();
  assert.equal(await store.claim(holdKey,now()+55,now()),true,'claim can be reused after retention');
  const admission=await Promise.all(Array.from({length:12},()=>store.admit('service','keyA','subjectA','write',now(),2,60)));
  assert.equal(admission.filter(x=>x===true).length,2,'operation limit enforced atomically');
  assert.equal(admission.filter(x=>x===false).length,10,'excess denied');
  const globalBucket=JSON.stringify(['global','service','subjectA']);
  assert.equal(Number((await db.prepare('SELECT used FROM sapi_replay_rates WHERE name=?').bind(globalBucket).first()).used),2,'denied operation requests do not increment global bucket');
  assert.equal(await store.admit('service','keyB','subjectB','write',now(),2,60),true,'separate subject admission');
  await assert.rejects(store.admit('alpha|beta','key','gamma','write',now(),1,60),'service policy rejects invalid tuple');
  // End-to-end SDK order: split cost claim, policy, business admission.
  const splitConfig=await install('splitService',{costLimit:3,costPeriod:60,operations:{write:{requests:2,period:60}}},dbSplit);
  const split=new D1ReplayStore(dbSplit,splitConfig);
  const keys=new StaticKeyProvider({kid:{master:crypto.getRandomValues(new Uint8Array(32)),subject:'splitSubject',scopes:['write']}});
  const codec=new Codec('splitService',keys),server=new SecureServer(codec,split,{splitBudget:true});
  const inputSchema={type:'object',properties:{allowed:{type:'boolean'}}},outputSchema={type:'object',properties:{ok:{type:'boolean'}}};
  let handlers=0;server.register('write','write',inputSchema,outputSchema,(_p,d)=>d.allowed,()=>{handlers++;return {ok:true}},{requests:2,period:60});
  const request=async allowed=>codec.request('kid','write',{allowed});
  const call=async ctx=>codec.acceptResponse(ctx,await server.handle(ctx.wire));
  const policyDenied=await request(false);assert.equal((await call(policyDenied)).error,'forbidden');
  const valid=await request(true);assert.equal((await call(valid)).ok,true);
  assert.equal((await codec.open(await server.handle(valid.wire),'res')).payload.error,'replay');
  const limited=await request(true);assert.equal((await call(limited)).error,'rate_limited');
  assert.equal(handlers,1,'no handler on policy, replay or cost-limit rejection');
  assert.equal(await split.admit('splitService','kid','splitSubject','write',now(),2,60),true,'replay cost is separate from business quota');
  assert.equal(await split.admit('splitService','kid','splitSubject','write',now(),2,60),false);
  const bounded=new D1ReplayStore(dbBounded,await install('boundedService',{costLimit:7,costPeriod:60},dbBounded));
  const boundedKey='boundedService|kid|'+(10).toString(16).padStart(32,'0');
  const bnow=now(), boundedResults=await Promise.all(Array.from({length:20},()=>bounded.claimBounded('boundedService','subject',boundedKey,bnow+55,bnow)));
  assert.equal(boundedResults.filter(x=>x==='accepted').length,1);
  assert.equal(boundedResults.filter(x=>x==='replay').length,6);
  assert.equal(boundedResults.filter(x=>x==='rate_limited').length,13,'duplicate requests consume bounded cost');
  const full=new D1ReplayStore(dbFull,await install('fullService',{capacity:2},dbFull));
  assert.equal(await full.claim('fullService|kid|'+(1).toString(16).padStart(32,'0'),now()+55,now()),true);
  assert.equal(await full.claim('fullService|kid|'+(2).toString(16).padStart(32,'0'),now()+55,now()),true);
  assert.equal(await denied(full.claim('fullService|kid|'+(999).toString(16).padStart(32,'0'),now()+55,now())),true,'capacity exhaustion fails closed');
  const lossConfig=await install('lossService',{operations:{write:{requests:60,period:60}}},dbLoss);
  const wireLoss=afterWriteLoss(dbLoss), uncertain=new D1ReplayStore(wireLoss.db,lossConfig), lossCodec=new Codec('lossService',keys);
  let lossHandlers=0;const lossServer=new SecureServer(lossCodec,uncertain,{splitBudget:true});
  lossServer.register('write','write',inputSchema,outputSchema,()=>true,()=>{lossHandlers++;return {ok:true}});
  const wireContext=await lossCodec.request('kid','write',{allowed:true});
  const uncertainReply=await lossCodec.acceptResponse(wireContext,await lossServer.handle(wireContext.wire));
  assert.equal(uncertainReply.error,'internal_error');assert.equal(lossHandlers,0);assert.equal(wireLoss.fired(),true);
  const recovery=new SecureServer(lossCodec,new D1ReplayStore(dbLoss,lossConfig),{splitBudget:true});
  recovery.register('write','write',inputSchema,outputSchema,()=>true,()=>{lossHandlers++;return {ok:true}});
  assert.equal((await lossCodec.open(await recovery.handle(wireContext.wire),'res')).payload.error,'replay');
  assert.equal(lossHandlers,0,'unknown claim result must not execute the handler');
  const admissionConfig=await install('admissionLoss',{operations:{write:{requests:1,period:60}}},dbAdmission);
  const lostAdmission=afterWriteLoss(dbAdmission), admissionCodec=new Codec('admissionLoss',keys);
  let admissionHandlers=0;const lostAdmissionServer=new SecureServer(admissionCodec,new D1ReplayStore(lostAdmission.db,admissionConfig));
  lostAdmissionServer.register('write','write',inputSchema,outputSchema,()=>true,()=>{admissionHandlers++;return {ok:true}},{requests:1,period:60});
  const pendingAdmission=await admissionCodec.request('kid','write',{allowed:true});
  const admissionReply=await admissionCodec.acceptResponse(pendingAdmission,await lostAdmissionServer.handle(pendingAdmission.wire));
  assert.equal(admissionReply.error,'internal_error');assert.equal(admissionHandlers,0);assert.equal(lostAdmission.fired(),true);
  const recoveredAdmission=new SecureServer(admissionCodec,new D1ReplayStore(dbAdmission,admissionConfig));
  recoveredAdmission.register('write','write',inputSchema,outputSchema,()=>true,()=>{admissionHandlers++;return {ok:true}},{requests:1,period:60});
  const newWire=await admissionCodec.request('kid','write',{allowed:true});
  assert.equal((await admissionCodec.acceptResponse(newWire,await recoveredAdmission.handle(newWire.wire))).error,'rate_limited');
  assert.equal(admissionHandlers,0,'unknown admission result does not refund committed budget');
  const loss=afterWriteLoss(db), unknownKey=key('keyA',3), failedStore=new D1ReplayStore(loss.db,baseConfig);
  assert.equal(await denied(failedStore.claim(unknownKey,now()+55,now())),true,'lost acknowledgement fails closed');
  assert.equal(loss.fired(),true,'loss occurred after database execution');
  assert.equal(await store.claim(unknownKey,now()+55,now()),false,'committed unknown claim cannot be reused');
  // Maintenance is bounded and never deletes still-live claims.
  const expired = Array.from({length:105}, (_, i) => db.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify(['service','cleanup',i.toString(16).padStart(32,'0')]),now()-40));
  await db.batch(expired);
  await store.cleanup(100);
  assert.equal(Number((await db.prepare("SELECT count(*) AS n FROM sapi_replay_claims WHERE json_extract(name,'$[0]')='service' AND json_extract(name,'$[1]')='cleanup'").first()).n),5,'cleanup deletes no more than 100 claims');
  assert.equal(await store.claim(duplicate,now()+50,now()),false,'cleanup preserves live claims');
  await assert.rejects(store.cleanup(101),TypeError);
  const malformedDb={prepare(sql){return {bind(){return this},async first(){return sql.includes('SELECT 1 AS ok FROM sapi_replay_policy')?{ok:1}:{decision:'not-a-decision'}}}},async batch(){throw Error('unused')}};
  const malformedServer=new SecureServer(lossCodec,new D1ReplayStore(malformedDb,lossConfig),{splitBudget:true});
  let malformedHandlers=0;malformedServer.register('write','write',inputSchema,outputSchema,()=>true,()=>{malformedHandlers++;return {ok:true}});
  const malformedCtx=await lossCodec.request('kid','write',{allowed:true});
  assert.equal((await lossCodec.acceptResponse(malformedCtx,await malformedServer.handle(malformedCtx.wire))).error,'internal_error');
  assert.equal(malformedHandlers,0,'invalid database result fails closed');
  await mf.dispose();mf=null;
  db=await start();store=new D1ReplayStore(db,baseConfig);
  assert.equal(await store.claim(duplicate,now()+50,now()),false,'persisted claim survives Miniflare recreation');
  assert.equal(await store.admit('service','keyA','subjectA','write',now(),2,60),false,'rate state survives Miniflare recreation');
  console.log('Miniflare D1: concurrent claim and cost budgets, SDK policy ordering, namespaces, expiry, capacity, uncertain writes, cleanup and Miniflare recreation passed');
} finally {
  if(mf) await mf.dispose();
  const base=resolve(tmpdir()), target=resolve(persist);
  if (!target.startsWith(base+sep) || !target.slice(base.length+1).startsWith('sapi-d1-test-')) throw new Error('unsafe disposable path');
  await rm(target,{recursive:true,force:true});
}