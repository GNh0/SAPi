// Historical cd9d821 shared-capacity counterexample, not an exclusive-mode test.
// Run only after checking out cd9d821 and setting SAPI_RUN_HISTORICAL_D1=1.
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {D1ReplayStore} from '../sdks/javascript/src/state-d1.js';
import {Codec,SecureServer,StaticKeyProvider} from '../sdks/javascript/src/index.js';
if(process.env.SAPI_RUN_HISTORICAL_D1!=='1'){console.log('SKIP: historical shared-capacity counterexample requires cd9d821');process.exit(0)}
const spec=process.env.D1_TEST_MINIFLARE?pathToFileURL(process.env.D1_TEST_MINIFLARE).href:'miniflare';
const {Miniflare}=await import(spec),persist=await mkdtemp(join(tmpdir(),'sapi-cross-capacity-'));
const schema=await readFile(new URL('../sdks/javascript/src/state-d1.sql',import.meta.url),'utf8');let mf;
try{
 mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',d1Databases:['TEST_DB'],d1Persist:persist});
 const db=await mf.getD1Database('TEST_DB');let sql='',trigger=false;
 for(const line of schema.split(/\r?\n/)){
  if(!sql&&(!line.trim()||line.trim().startsWith('--')))continue;
  if(!sql&&line.trim().startsWith('CREATE TRIGGER'))trigger=true;
  sql+=line+'\n';if((trigger&&line.trim()==='END;')||(!trigger&&line.trim().endsWith(';'))){await db.prepare(sql).run();sql='';trigger=false}
 }
 if(sql.trim())throw Error('incomplete schema');
 const opts=service=>({service,policyVersion:'v1',capacity:2,rateCapacity:2,operations:{write:{requests:2,period:60}}});
 const a=new D1ReplayStore(db,opts('serviceA')),b=new D1ReplayStore(db,opts('serviceB'));
 for(const store of [a,b]){const r=store.policyRecord();await db.prepare('INSERT INTO sapi_replay_policy(service,version,config) VALUES(?,?,?)').bind(r.service,r.version,r.config).run()}
 const now=()=>Math.floor(Date.now()/1000),key=(service,n)=>`${service}|kid|${n.toString(16).padStart(32,'0')}`;
 assert.equal(await a.claim(key('serviceA',1),now()+55,now()),true);
 assert.equal(await a.claim(key('serviceA',2),now()+55,now()),true);
 assert.equal(await b.claim(key('serviceB',1),now()+55,now()),false);
 const claimRows=(await db.prepare('SELECT name FROM sapi_replay_claims ORDER BY name').all()).results;
 assert.deepEqual(claimRows.map(r=>JSON.parse(r.name)[0]),['serviceA','serviceA']);
 assert.equal(await a.admit('serviceA','kid','subjectA','write',now(),2,60),true);
 assert.equal(await b.admit('serviceB','kid','subjectB','write',now(),2,60),false);
 const rateRows=(await db.prepare('SELECT name,used FROM sapi_replay_rates ORDER BY name').all()).results;
 assert.equal(rateRows.length,2);assert.ok(rateRows.every(r=>JSON.parse(r.name)[1]==='serviceA'&&r.used===1));
 const provider=new StaticKeyProvider({kid:{master:crypto.getRandomValues(new Uint8Array(32)),subject:'subjectB',scopes:['write']}});
 const codec=new Codec('serviceB',provider),server=new SecureServer(codec,b),shape={type:'object',properties:{ok:{type:'boolean'}}};let handlers=0;
 server.register('write','write',shape,shape,()=>true,()=>{handlers++;return {ok:true}},{requests:2,period:60});
 const request=await codec.request('kid','write',{ok:true}),response=await codec.acceptResponse(request,await server.handle(request.wire));
 assert.equal(response.error,'rate_limited');assert.equal(handlers,0);
 assert.equal(Number((await db.prepare('SELECT count(*) AS n FROM sapi_replay_claims').first()).n),2);
 assert.equal(Number((await db.prepare('SELECT count(*) AS n FROM sapi_replay_rates').first()).n),2);
 console.log(JSON.stringify({claimCapacity:2,rateCapacity:2,serviceAClaims:2,serviceBClaimAccepted:false,totalClaims:2,serviceAAdmissions:1,serviceBAdmissionAccepted:false,totalRateRows:2,serviceBHandlerCalls:handlers,sdkError:response.error}));
}finally{
 if(mf)await mf.dispose();const base=resolve(tmpdir()),target=resolve(persist);
 if(!target.startsWith(base+sep)||!target.slice(base.length+1).startsWith('sapi-cross-capacity-'))throw Error('unsafe disposable path');
 await rm(target,{recursive:true,force:true});
}