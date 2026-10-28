// Rehearsal only: explicit admin transition, never used by request paths.
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';
const spec=process.env.D1_TEST_MINIFLARE?pathToFileURL(process.env.D1_TEST_MINIFLARE).href:'miniflare';
const {Miniflare}=await import(spec),persist=await mkdtemp(join(tmpdir(),'sapi-transition-'));
const full=await readFile(new URL('../sdks/javascript/src/state-d1.sql',import.meta.url),'utf8');
const marker='-- Additive, explicit transition';const base=full.slice(0,full.indexOf(marker));
const migration=await readFile(new URL('../sdks/javascript/src/state-d1-exclusive-migration.sql',import.meta.url),'utf8');let mf;
async function apply(db,text){let sql='',trigger=false;for(const line of text.split(/\r?\n/)){if(!sql&&(!line.trim()||line.trim().startsWith('--')))continue;if(!sql&&line.trim().startsWith('CREATE TRIGGER'))trigger=true;sql+=line+'\n';if((trigger&&(line.trim()==='END;'||/\bBEGIN\b.*\bEND;\s*$/.test(line)))||(!trigger&&line.trim().endsWith(';'))){await db.prepare(sql).run();sql='';trigger=false}}if(sql.trim())throw Error('incomplete statement')}
try{
 const names=['OK','WRONG','DIRTY','SMALL','LOSS','NEWNOOWNER'];mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',d1Databases:names,d1Persist:persist});
 const dbs=Object.fromEntries(await Promise.all(names.map(async n=>[n,await mf.getD1Database(n)])));const service='svc',version='v1',opts={mode:'exclusive',service,policyVersion:version,capacity:2,rateCapacity:2,operations:{write:{requests:2,period:60}}};
 const now=Math.floor(Date.now()/1000),namespace=s=>JSON.stringify([s,'kid','1'.repeat(32)]);
 for(const [name,db] of Object.entries(dbs)){
  await apply(db,base);const record=new D1ReplayStore(db,opts).policyRecord(),oldObject=JSON.parse(record.config);delete oldObject.mode;
  const oldConfig=JSON.stringify(oldObject);await db.prepare('INSERT INTO sapi_replay_policy(service,version,config) VALUES (?,?,?)').bind(service,version,name==='NEWNOOWNER'?record.config:oldConfig).run();
  await db.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(namespace(name==='DIRTY'?'foreign':service),now+55).run();
  if(name==='SMALL')await db.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(JSON.stringify([service,'kid','2'.repeat(32)]),now+55).run();
  await apply(db,migration);
 }
 function records(db,newOpts=opts){const r=new D1ReplayStore(db,newOpts).policyRecord(),old=JSON.parse(r.config);delete old.mode;return {r,old:JSON.stringify(old)}}
 function transition(db,expectedOld,r){return db.batch([
  db.prepare('UPDATE sapi_replay_policy SET config=? WHERE service=? AND version=? AND config=?').bind(r.config,r.service,r.version,expectedOld),
  db.prepare('INSERT INTO sapi_replay_owner(singleton,service,version,config) SELECT 1,?,?,? WHERE changes()=1 AND EXISTS(SELECT 1 FROM sapi_replay_policy WHERE service=? AND version=? AND config=?) ON CONFLICT(singleton) DO NOTHING').bind(r.service,r.version,r.config,r.service,r.version,r.config),
 ])}
 const ok=records(dbs.OK),okResult=await transition(dbs.OK,ok.old,ok.r);assert.equal(okResult[0].meta.changes,1);assert.equal(okResult[1].meta.changes,1);
 assert.equal(await initializeExclusivePolicy(dbs.OK,new D1ReplayStore(dbs.OK,opts)),true);
 assert.equal(Number((await dbs.OK.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),1,'valid transition preserves retained claim');
 for(const name of ['WRONG','DIRTY','SMALL']){
  const db=dbs[name],before=await db.prepare('SELECT service,version,config FROM sapi_replay_policy').first();
  const config=name==='SMALL'?{...opts,capacity:1}:opts,r=new D1ReplayStore(db,config).policyRecord();let old=before.config;if(name==='WRONG')old+=' ';
  try{await transition(db,old,r)}catch{}
  assert.deepEqual(await db.prepare('SELECT service,version,config FROM sapi_replay_policy').first(),before,`${name}: policy unchanged`);
  assert.equal(Number((await db.prepare('SELECT count(*) AS n FROM sapi_replay_owner').first()).n),0,`${name}: no owner`);
  assert.equal(Number((await db.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),name==='SMALL'?2:1,`${name}: claims preserved`);
 }
 const newNoOwner=records(dbs.NEWNOOWNER);
 const noOwnerResult=await transition(dbs.NEWNOOWNER,newNoOwner.old,newNoOwner.r);
 assert.equal(noOwnerResult[0].meta.changes,0,'wrong old condition updates no policy');
 assert.equal(noOwnerResult[1].meta.changes,0,'changes() prevents an unearned owner');
 assert.equal(Number((await dbs.NEWNOOWNER.prepare('SELECT count(*) AS n FROM sapi_replay_owner').first()).n),0);
 assert.equal((await dbs.NEWNOOWNER.prepare('SELECT config FROM sapi_replay_policy WHERE service=?').bind(service).first()).config,newNoOwner.r.config);
 const lost=records(dbs.LOSS);let replyLost=false;try{await transition(dbs.LOSS,lost.old,lost.r);throw Error('lost admin batch acknowledgement')}catch{replyLost=true}
 assert.equal(replyLost,true);const owner=await dbs.LOSS.prepare('SELECT service,version,config FROM sapi_replay_owner WHERE singleton=1').first();assert.deepEqual(owner,lost.r);
 const retry=await transition(dbs.LOSS,lost.old,lost.r);assert.equal(retry[0].meta.changes,0);assert.equal(retry[1].meta.changes,0);assert.equal(Number((await dbs.LOSS.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),1);
 console.log('Admin transition rehearsal: exact old config, rollback on foreign/over-cap, wrong-config no-op and lost acknowledgement reconciliation passed');
}finally{if(mf)await mf.dispose();const root=resolve(tmpdir()),target=resolve(persist);if(!target.startsWith(root+sep)||!target.slice(root.length+1).startsWith('sapi-transition-'))throw Error('unsafe disposable path');await rm(target,{recursive:true,force:true})}