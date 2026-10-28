// Disposable D1 negative tests: malformed namespaces cannot be adopted or inserted.
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join,resolve,sep} from 'node:path';import {pathToFileURL} from 'node:url';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';
const spec=process.env.D1_TEST_MINIFLARE?pathToFileURL(process.env.D1_TEST_MINIFLARE).href:'miniflare';
const {Miniflare}=await import(spec),persist=await mkdtemp(join(tmpdir(),'sapi-namespace-'));
const schema=await readFile(new URL('../sdks/javascript/src/state-d1.sql',import.meta.url),'utf8');let mf;
const service='svc',id='1'.repeat(32),opts={mode:'exclusive',service,policyVersion:'v1',capacity:20,rateCapacity:20};
const cases=[
 ['claim',JSON.stringify([service,null,null])],['claim',JSON.stringify([service,'bad|kid',id])],['claim',JSON.stringify([service,'kid','abc'])],['claim',JSON.stringify([service,'kid',1])],['claim',`[ "${service}","kid","${id}" ]`],
 ['rate',JSON.stringify(['global',service])],['rate',JSON.stringify(['global',service,null])],['rate',JSON.stringify(['global',service,'x'.repeat(1025)])],['rate',JSON.stringify(['global',service,'subject','extra'])],
 ['rate',JSON.stringify(['cost',service,'subject','extra'])],['rate',JSON.stringify(['operation',service,'subject'])],['rate',JSON.stringify(['operation',service,'subject',null])],['rate',JSON.stringify(['operation',service,'subject','bad|operation'])],['rate',`[ "global","${service}","subject" ]`],
];
async function apply(db){let sql='',trigger=false;for(const line of schema.split(/\r?\n/)){if(!sql&&(!line.trim()||line.trim().startsWith('--')))continue;if(!sql&&line.trim().startsWith('CREATE TRIGGER'))trigger=true;sql+=line+'\n';if((trigger&&(line.trim()==='END;'||/\bBEGIN\b.*\bEND;\s*$/.test(line)))||(!trigger&&line.trim().endsWith(';'))){await db.prepare(sql).run();sql='';trigger=false}}if(sql.trim())throw Error('incomplete schema')}
async function insert(db,type,name){return type==='claim'?db.prepare('INSERT INTO sapi_replay_claims(name,expires) VALUES (?,?)').bind(name,Math.floor(Date.now()/1000)+60).run():db.prepare('INSERT INTO sapi_replay_rates(name,started,used,period) VALUES (?,?,?,?)').bind(name,Math.floor(Date.now()/1000),1,60).run()}
async function denied(p){try{return (await p)!==true}catch{return true}}
try{
 const names=['OWNER',...cases.map((_,i)=>'OLD'+i)];mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',d1Databases:names,d1Persist:persist});
 const dbs=Object.fromEntries(await Promise.all(names.map(async n=>[n,await mf.getD1Database(n)])));for(const db of Object.values(dbs))await apply(db);
 const ownerDb=dbs.OWNER,owner=new D1ReplayStore(ownerDb,opts);assert.equal(await initializeExclusivePolicy(ownerDb,owner),true);
 for(let i=0;i<cases.length;i++){
  const [type,name]=cases[i],db=dbs['OLD'+i];await insert(db,type,name);const old=new D1ReplayStore(db,opts);
  assert.equal(await denied(initializeExclusivePolicy(db,old)),true,`legacy invalid namespace ${i} must be rejected`);
  const table=type==='claim'?'sapi_replay_claims':'sapi_replay_rates';assert.equal(Number((await db.prepare(`SELECT count(*) AS n FROM ${table}`).first()).n),1,`legacy row ${i} preserved`);
  await assert.rejects(insert(ownerDb,type,name),`owner rejects invalid namespace ${i}`);
 }
 assert.equal(Number((await ownerDb.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),0);
 assert.equal(Number((await ownerDb.prepare('SELECT count(*) AS n FROM sapi_replay_rates').first()).n),0);
 await insert(ownerDb,'claim',JSON.stringify([service,'kid',id]));await insert(ownerDb,'rate',JSON.stringify(['global',service,'subject']));
 console.log(`D1 namespace guards: ${cases.length} invalid legacy tuples and direct inserts rejected, rows preserved; valid tuples accepted`);
}finally{if(mf)await mf.dispose();const base=resolve(tmpdir()),target=resolve(persist);if(!target.startsWith(base+sep)||!target.slice(base.length+1).startsWith('sapi-namespace-'))throw Error('unsafe disposable path');await rm(target,{recursive:true,force:true})}