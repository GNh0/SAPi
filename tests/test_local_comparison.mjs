import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createLocalComparison} from '../examples/shadow/local-comparison.mjs';
import {createShadowBuffer} from '../examples/shadow/adapter.mjs';
import {runMixed,fixturePlan} from '../examples/shadow/mixed-runner.mjs';
import {atomicReplayAdapter} from '../examples/shadow/atomic-replay-contract.mjs';
import {Codec,SecureServer,StaticKeyProvider,MemoryReplayStore,SplitBudgetMemoryReplayStore} from '../sdks/javascript/src/index.js';
import {createEvidence,readEvidenceSummary,stateDigest} from '../examples/shadow/sqlite-evidence.mjs';
import {createProcessComparison,parseFixtureOutput,terminateVerifiedChild} from '../examples/shadow/process-comparison.mjs';
import {validateArtifactRoot,validateArtifactFile} from '../examples/shadow/artifact-path.mjs';
import {DatabaseSync} from 'node:sqlite';
import {unlinkSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
const envelope=(overrides={})=>({correlationId:crypto.randomUUID(),operation:'put',identity:'allowed',data:{id:'one',value:'hello'},...overrides});

test('shadow observation uses supplied server id and excludes workbench source',()=>{
  const shadow=createShadowBuffer({samplePercent:100}), id=crypto.randomUUID(), response=new Response('ok');
  shadow.observe(new Request('https://example.invalid/'),response,{requestId:id});
  shadow.observe(new Request('https://example.invalid/api/workbench/review',{method:'POST',body:'sensitive-source'}),response,{requestId:crypto.randomUUID()});
  shadow.observe(new Request('https://example.invalid/'),response,{requestId:'caller-supplied'});
  const batch=shadow.drain();
  assert.equal(batch.events.length,1);assert.equal(batch.events[0].request_id,id);
  assert.equal(batch.counters.seen,2);assert.equal(batch.counters.observer_error,1);
  assert.equal(JSON.stringify(batch).includes('sensitive-source'),false);
});

test('opt-in split budget preserves valid requests after replay while bounding total cost',async()=>{
  const master=crypto.getRandomValues(new Uint8Array(32));
  const provider=new StaticKeyProvider({a:{master,subject:'alice',scopes:['read']},b:{master,subject:'alice',scopes:['read']},c:{master,subject:'bob',scopes:['read']}});
  const codec=new Codec('demo',provider), schema={type:'object',properties:{id:{type:'string',maxBytes:32}}};
  const store=new SplitBudgetMemoryReplayStore(), server=new SecureServer(codec,store,{splitBudget:true});
  let calls=0; server.register('get','read',schema,schema,()=>true,(_p,d)=>{calls++;return d;});
  const request=async kid=>(await codec.request(kid,'get',{id:'one'})).wire;
  const send=async wire=>(await codec.open(await server.handle(wire),'res')).payload;
  const original=await request('a'); assert.equal((await send(original)).ok,true);
  for(let i=0;i<59;i++) assert.equal((await send(original)).error,'replay');
  assert.equal((await send(await request('b'))).ok,true);
  for(let i=0;i<59;i++) assert.equal((await send(original)).error,'replay');
  assert.equal((await send(await request('b'))).error,'rate_limited');
  assert.equal((await send(await request('c'))).ok,true);
  assert.equal(calls,3);
  assert.throws(()=>new SecureServer(codec,new MemoryReplayStore(),{splitBudget:true}),/split-budget/);
});

test('split budget enforces business limits and one winner for concurrent duplicate',async()=>{
  const master=crypto.getRandomValues(new Uint8Array(32));
  const provider=new StaticKeyProvider({a:{master,subject:'alice',scopes:['read']}});
  const codec=new Codec('demo',provider), store=new SplitBudgetMemoryReplayStore();
  const server=new SecureServer(codec,store,{splitBudget:true});
  const schema={type:'object',properties:{id:{type:'string',maxBytes:32}}}; let calls=0;
  server.register('get','read',schema,schema,()=>true,(_p,d)=>{calls++;return d;},{requests:2,period:60});
  const req=async()=>(await codec.request('a','get',{id:'one'})).wire;
  const send=async wire=>(await codec.open(await server.handle(wire),'res')).payload;
  const wire=await req(); const both=await Promise.all([send(wire),send(wire)]);
  assert.equal(both.filter(x=>x.ok).length,1); assert.equal(both.filter(x=>x.error==='replay').length,1);
  assert.equal((await send(await req())).ok,true);
  assert.equal((await send(await req())).error,'rate_limited'); assert.equal(calls,2);
  const bad=new SecureServer(codec,{claimBounded:async()=>true,admit:async()=>true},{splitBudget:true});
  bad.register('get','read',schema,schema,()=>true,()=>{throw Error('must not execute');});
  assert.equal((await codec.open(await bad.handle(await req()),'res')).payload.error,'internal_error');
});

test('default admission remains unchanged and concurrent split cost is bounded',async()=>{
  const master=crypto.getRandomValues(new Uint8Array(32));
  const provider=new StaticKeyProvider({a:{master,subject:'alice',scopes:['read']}});
  const codec=new Codec('demo',provider), schema={type:'object',properties:{id:{type:'string',maxBytes:32}}};
  const setup=store=>{const s=new SecureServer(codec,store,store instanceof SplitBudgetMemoryReplayStore?{splitBudget:true}:{});s.register('get','read',schema,schema,()=>true,(_p,d)=>d);return s;};
  const send=async(s,w)=>(await codec.open(await s.handle(w),'res')).payload;
  const make=async data=>(await codec.request('a','get',data)).wire;
  const legacy=setup(new MemoryReplayStore()), wire=await make({id:'one'});
  assert.equal((await send(legacy,wire)).ok,true);
  for(let i=0;i<59;i++) assert.equal((await send(legacy,wire)).error,'replay');
  assert.equal((await send(legacy,await make({id:'two'}))).error,'rate_limited');
  const split=setup(new SplitBudgetMemoryReplayStore(10000,{costLimit:3}));
  assert.equal((await send(split,await make({id:7}))).error,'invalid_input');
  const wires=await Promise.all([make({id:'a'}),make({id:'b'}),make({id:'c'})]);
  const outcomes=await Promise.all(wires.map(w=>send(split,w)));
  assert.equal(outcomes.filter(x=>x.ok).length,2);
  assert.equal(outcomes.filter(x=>x.error==='rate_limited').length,1);
});

test('atomic adapter exposes only explicitly supported split decisions to SDK',async()=>{
  const master=crypto.getRandomValues(new Uint8Array(32));
  const provider=new StaticKeyProvider({a:{master,subject:'alice',scopes:['read']}});
  const codec=new Codec('demo',provider), schema={type:'object',properties:{id:{type:'string',maxBytes:32}}};
  const backend=new SplitBudgetMemoryReplayStore();
  assert.throws(()=>atomicReplayAdapter(new MemoryReplayStore(),{splitBudget:true}),/split-budget/);
  const wrapped=atomicReplayAdapter(backend,{splitBudget:true});
  const server=new SecureServer(codec,wrapped,{splitBudget:true}); let calls=0;
  server.register('get','read',schema,schema,()=>true,(_p,d)=>{calls++;return d;});
  const wire=(await codec.request('a','get',{id:'one'})).wire;
  const send=async w=>(await codec.open(await server.handle(w),'res')).payload;
  const results=await Promise.all([send(wire),send(wire)]);
  assert.equal(results.filter(x=>x.ok).length,1);assert.equal(results.filter(x=>x.error==='replay').length,1);assert.equal(calls,1);
  const invalid=atomicReplayAdapter({claim:()=>true,admit:()=>true,claimBounded:()=>true},{splitBudget:true});
  const rejecting=new SecureServer(codec,invalid,{splitBudget:true});
  rejecting.register('get','read',schema,schema,()=>true,()=>{throw Error('unexpected handler');});
  const fresh=(await codec.request('a','get',{id:'two'})).wire;
  assert.equal((await codec.open(await rejecting.handle(fresh),'res')).payload.error,'internal_error');
});

test('async replay claim is awaited and requires a boolean',async()=>{
  const master=crypto.getRandomValues(new Uint8Array(32));
  const provider=new StaticKeyProvider({a:{master,subject:'alice',scopes:['read']}});
  const codec=new Codec('demo',provider), schema={type:'object',properties:{id:{type:'string',maxBytes:32}}};
  class AsyncClaim extends SplitBudgetMemoryReplayStore { async claim(...args) {return super.claim(...args);} }
  const server=new SecureServer(codec,new AsyncClaim(),{splitBudget:true});let calls=0;
  server.register('get','read',schema,schema,()=>true,(_p,d)=>{calls++;return d;});
  const wire=(await codec.request('a','get',{id:'one'})).wire;
  const send=async()=>(await codec.open(await server.handle(wire),'res')).payload;
  const results=await Promise.all([send(),send()]);
  assert.equal(results.filter(x=>x.ok).length,1);assert.equal(results.filter(x=>x.error==='replay').length,1);assert.equal(calls,1);
  class InvalidClaim extends SplitBudgetMemoryReplayStore { async claim(){return 'yes';} }
  await assert.rejects(new InvalidClaim().claimBounded('demo','alice','x',1100,1000),/boolean/);
});

test('request expiring during split admission never reaches handler',async()=>{
  let now=1000;const master=crypto.getRandomValues(new Uint8Array(32));
  const provider=new StaticKeyProvider({a:{master,subject:'alice',scopes:['read']}});
  const codec=new Codec('demo',provider,()=>now), schema={type:'object',properties:{id:{type:'string',maxBytes:32}}};
  class SlowAdmission extends SplitBudgetMemoryReplayStore { async admit(...args){const allowed=super.admit(...args);now=1001;return allowed;} }
  const server=new SecureServer(codec,new SlowAdmission(),{splitBudget:true});let calls=0;
  server.register('get','read',schema,schema,()=>true,(_p,d)=>{calls++;return d;});
  const wire=await codec.seal('a','req',{id:'0'.repeat(32),iat:1000,exp:1001,op:'get',data:{id:'one'}});
  const payload=(await codec.open(await server.handle(wire),'res')).payload;
  assert.equal(payload.error,'invalid_input');assert.equal(calls,0);
});
async function recorded(options, inspect=()=>{}) {
  const dir=validateArtifactRoot();
  const path=resolve(dir,`sapi-test-${crypto.randomUUID()}.sqlite`), evidence=createEvidence(path);
  try {
    const result=await runMixed({...options,evidence}); evidence.close();
    const db=new DatabaseSync(path,{readOnly:true});
    try { await inspect(db,result); } finally { db.close(); }
    return result;
  } finally { try {evidence.close();} catch {} unlinkSync(path); }
}

test('actual SDK and ordinary fixed handler agree; bounded envelope and storage', async()=>{
  const compare=createLocalComparison().compare;
  const normal=await compare(envelope());
  assert.equal(normal.ordinary.reason,'accepted'); assert.equal(normal.secure.reason,'accepted');
  assert.deepEqual(normal.after.baseline,normal.after.sapi);
  for(const [patch,reason] of [[{data:{id:'one',value:4}},'invalid_input'],[{identity:'denied'},'forbidden'],[{operation:'unknown'},'unknown_operation']]) {
    const r=await compare(envelope(patch)); assert.equal(r.ordinary.reason,reason); assert.equal(r.secure.reason,reason); assert.deepEqual(r.before,r.after);
  }
  await assert.rejects(compare(envelope({extra:true})),/unsupported/);
  await assert.rejects(compare(envelope({operation:'other'})),/unsupported/);
  await assert.rejects(compare(envelope({data:{id:'a',value:'x'.repeat(9000)}})),/unsupported/);
  await assert.rejects(compare(envelope({correlationId:normal.correlationId})),/duplicate/);
});

test('independent dummy contract checks create, overwrite, UTF-8 limits and denied writes',async()=>{
  const compare=createLocalComparison().compare;
  const check=async(data,expected,identity='allowed')=>{
    const r=await compare(envelope({data,identity}));
    assert.equal(r.ordinary.ok,expected==='accepted');assert.equal(r.secure.ok,expected==='accepted');
    assert.equal(r.ordinary.reason,expected);assert.equal(r.secure.reason,expected);
    return r;
  };
  let r=await check({id:'item1',value:'first'},'accepted');
  assert.deepEqual(r.before,{baseline:{},sapi:{}});assert.deepEqual(r.after,{baseline:{item1:'first'},sapi:{item1:'first'}});
  r=await check({id:'item1',value:'changed'},'accepted');
  assert.deepEqual(r.before,{baseline:{item1:'first'},sapi:{item1:'first'}});assert.deepEqual(r.after,{baseline:{item1:'changed'},sapi:{item1:'changed'}});
  r=await check({id:'item2',value:'가'.repeat(21)+'a'},'accepted');
  assert.equal(r.after.baseline.item2,'가'.repeat(21)+'a');assert.deepEqual(r.after.baseline,r.after.sapi);
  for(const data of [{id:'item3',value:'가'.repeat(22)},{id:'a/b',value:'x'},{id:'item3\n',value:'x'},{id:'item3',value:'x',extra:true}]) {
    r=await check(data,'invalid_input');assert.deepEqual(r.before,r.after);
  }
  r=await check({id:'item1',value:'blocked'},'forbidden','denied');assert.deepEqual(r.before,r.after);
});

test('dummy baseline and SDK share the fixed subject budget',async()=>{
  const compare=createLocalComparison().compare;
  for(let i=0;i<60;i++) {
    const r=await compare(envelope({data:{id:'same',value:'ok'}}));
    assert.equal(r.ordinary.reason,'accepted');assert.equal(r.secure.reason,'accepted');
  }
  const limited=await compare(envelope({data:{id:'same',value:'ok'}}));
  assert.equal(limited.ordinary.reason,'rate_limited');assert.equal(limited.secure.reason,'rate_limited');
  assert.deepEqual(limited.before,limited.after);
});

test('disabled, deterministic dry run, caps, stop, failure and real loopback',async()=>{
  await assert.rejects(runMixed(),/disabled/);
  await assert.rejects(runMixed({enabled:true,concurrency:2}),/limits/);
  await assert.rejects(runMixed({enabled:true,runs:8}),/limits/);
  const a=await runMixed({enabled:true,seed:7}), b=await runMixed({enabled:true,seed:7});
  assert.deepEqual(a,b); assert.equal(a.pass,false); assert.equal(a.planned,4);
  const ac=new AbortController(); ac.abort(); const stopped=await runMixed({enabled:true,signal:ac.signal});
  assert.equal(stopped.omitted,4); assert.equal(stopped.pass,false);
  const fail=await recorded({enabled:true,dryRun:false,compare:async()=>{throw Error('no');}});
  assert.equal(fail.outcomes[0].status,'error'); assert.equal(fail.omitted,3); assert.equal(fail.pass,false);
  const timed=await recorded({enabled:true,dryRun:false,timeoutMs:5,compare:()=>new Promise(()=>{})});
  assert.equal(timed.outcomes[0].reason,'timeout_unknown'); assert.equal(timed.omitted,3); assert.equal(timed.pass,false);
  const wrong=await recorded({enabled:true,dryRun:false,seed:3,compare:async()=>({ordinary:{reason:'accepted'},secure:{reason:'accepted'},before:{baseline:{},sapi:{}},after:{baseline:{},sapi:{}}})});
  assert.equal(wrong.pass,false); assert.equal(wrong.stopped,true);
  const actual=await recorded({enabled:true,dryRun:false,seed:7,compare:createLocalComparison().compare},(db,result)=>{
    const run=db.prepare('SELECT source,status,summary FROM runs').get();
    assert.equal(run.source,'synthetic_fixture'); assert.equal(run.status,'fixture_consistent'); assert.equal(JSON.parse(run.summary).runId,result.runId);
    const metadata=JSON.parse(db.prepare('SELECT metadata FROM runs').get().metadata);
    assert.equal(metadata.targetProvenance,'unverified_callback');
    assert.equal(db.prepare("SELECT count(*) n FROM events WHERE kind='result'").get().n,4);
    assert.equal(db.prepare('PRAGMA user_version').get().user_version,3);
    assert.match(metadata.sourceHash,/^[0-9a-f]{64}$/); assert.match(metadata.sourceCommit,/^(?:[0-9a-f]{40}|unavailable)$/); assert.equal(metadata.fixtureVersion,1);
  });
  assert.equal(actual.pass,true); assert.equal(actual.completed,4); assert.equal(actual.omitted,0);
});

test('shared atomic replay contract rejects concurrent duplicate through SDK',async()=>{
  const claimed=new Set();
  const backend={async claim(key){if(claimed.has(key)) return false; claimed.add(key); return true;},async admit(){return true;}};
  const store=atomicReplayAdapter(backend);
  const key=crypto.getRandomValues(new Uint8Array(32));
  const keys=new StaticKeyProvider({a:{master:key,subject:'client1',scopes:['write']}});
  const codec=new Codec('dummy',keys), left=new SecureServer(new Codec('dummy',keys),store), right=new SecureServer(new Codec('dummy',keys),store);
  const schema={type:'object',properties:{id:{type:'string',maxBytes:32}}};
  for (const s of [left,right]) s.register('put','write',schema,schema,()=>true,(_p,d)=>d);
  const req=await codec.request('a','put',{id:'one'});
  const wires=await Promise.all([left.handle(req.wire),right.handle(req.wire)]);
  const outcomes=await Promise.all(wires.map(async w=>(await codec.open(w,'res')).payload));
  assert.equal(outcomes.filter(x=>x.ok).length,1); assert.equal(outcomes.filter(x=>x.error==='replay').length,1);
  const bad=atomicReplayAdapter({claim:async()=>1,admit:async()=>true}); await assert.rejects(bad.claim('x',1,0),/boolean/);
  let admitted=0;
  const limited=atomicReplayAdapter({claim:async()=>true,admit:async()=>{if(admitted>=1)return false; admitted++; return true;}});
  const decisions=await Promise.all(Array.from({length:10},()=>limited.admit('dummy','a','client1','put',1,1,60)));
  assert.equal(decisions.filter(Boolean).length,1);
});

test('independent oracle rejects ghost state and false ok; blocking and late effects remain unknown',async()=>{
  let seed=0;
  while ((await runMixed({enabled:true,seed})).outcomes[0].fixture!=='valid') seed++;
  const fake=(e,ghost,ok)=>({version:1,correlationId:e.correlationId,
    ordinary:{ok,reason:'accepted',data:e.data},secure:{ok,reason:'accepted',data:e.data},
    before:{baseline:ghost,sapi:ghost},after:{baseline:{...ghost,[e.data.id]:e.data.value},sapi:{...ghost,[e.data.id]:e.data.value}}});
  const ghost=await recorded({enabled:true,dryRun:false,seed,compare:async e=>fake(e,{ghost:'unexpected'},true)});
  assert.equal(ghost.outcomes[0].status,'fail'); assert.equal(ghost.pass,false);
  const badOk=await recorded({enabled:true,dryRun:false,seed,compare:async e=>fake(e,{},false)});
  assert.equal(badOk.outcomes[0].status,'fail'); assert.equal(badOk.pass,false);
  const blocked=await recorded({enabled:true,dryRun:false,seed,timeoutMs:5,compare:e=>{
    const until=performance.now()+50; while(performance.now()<until) {} return fake(e,{},true);
  }},(db)=>{
    const row=db.prepare("SELECT payload FROM events WHERE kind='result'").get();
    assert.equal(JSON.parse(row.payload).result.reason,'timeout_unknown');
  });
  assert.equal(blocked.outcomes[0].reason,'timeout_unknown'); assert.equal(blocked.pass,false);
  let sideEffect=false;
  const late=await recorded({enabled:true,dryRun:false,seed,timeoutMs:5,compare:()=>new Promise(resolve=>setTimeout(()=>{sideEffect=true;resolve({});},30))});
  assert.equal(late.outcomes[0].reason,'timeout_unknown'); assert.equal(late.omitted,3);
  await new Promise(resolve=>setTimeout(resolve,50)); assert.equal(sideEffect,true);
});

test('stop preserves completed result and omitted fixtures in SQLite',async()=>{
  const controller=new AbortController(), compare=createLocalComparison().compare;
  const result=await recorded({enabled:true,dryRun:false,seed:1,signal:controller.signal,compare:async e=>{
    const r=await compare(e); controller.abort(); return r;
  }},(db)=>{
    const run=db.prepare('SELECT source,status,summary FROM runs').get(), summary=JSON.parse(run.summary);
    assert.equal(run.source,'synthetic_fixture'); assert.equal(run.status,'incomplete');
    assert.equal(summary.completed,1); assert.equal(summary.omitted,3); assert.equal(summary.omittedFixtures.length,3);
    assert.equal(db.prepare("SELECT count(*) n FROM events WHERE kind='started'").get().n,1);
    assert.equal(db.prepare("SELECT count(*) n FROM events WHERE kind='result'").get().n,1);
  });
  assert.equal(result.pass,false); assert.equal(result.stopped,true);
});

test('failure evidence excludes unknown keys, raw responses, tokens and oversized values',async()=>{
  const marker='PRIVATE_MARKER_DO_NOT_PERSIST_4e91';
  const result=await recorded({enabled:true,dryRun:false,seed:1,compare:async e=>({
    version:1,correlationId:e.correlationId,token:marker,rawResponse:marker,
    ordinary:{ok:false,reason:marker,unknown:marker},secure:{ok:false,reason:marker},
    before:{baseline:{secret:marker},sapi:{secret:marker}},after:{baseline:{secret:marker},sapi:{secret:marker}},
    oversized:marker.repeat(10000)
  })},(db)=>{
    const contents=JSON.stringify(db.prepare('SELECT metadata,summary FROM runs').all())+JSON.stringify(db.prepare('SELECT payload FROM events').all());
    assert.equal(contents.includes(marker),false);
    assert.equal(contents.includes('rawResponse'),false); assert.equal(contents.includes('token'),false);
    assert.equal(db.prepare("SELECT status FROM runs").get().status,'incomplete');
  });
  assert.equal(result.pass,false); assert.equal(result.stopped,true);
});

test('all rejection values are normalized and finish evidence is retained',async()=>{
  const values=[null,undefined,'secret-message',17,{message:'secret-message'},Object.defineProperty({},'message',{get(){throw Error('must not read');}})];
  for(const value of values) {
    const result=await recorded({enabled:true,dryRun:false,compare:()=>Promise.reject(value)},db=>{
      const run=db.prepare('SELECT status,summary FROM runs').get();
      assert.equal(run.status,'incomplete'); assert.equal(JSON.parse(run.summary).omitted,3);
      const events=db.prepare('SELECT kind,payload FROM events ORDER BY seq').all();
      assert.deepEqual(events.map(e=>e.kind),['started','result','finish']);
      assert.equal(JSON.stringify(events).includes('secret-message'),false);
    });
    assert.equal(result.outcomes[0].reason,'evaluation_error'); assert.equal(result.pass,false);
  }
});

test('unpaired surrogate failure is retained as an unknown evaluation, not a pass',async()=>{
  const compare=createLocalComparison().compare;
  const result=await recorded({enabled:true,dryRun:false,compare:e=>compare({...e,operation:'put',identity:'allowed',data:{id:'x',value:'\ud800'}})},db=>{
    const rows=db.prepare('SELECT kind,payload FROM events ORDER BY seq').all();
    assert.deepEqual(rows.map(r=>r.kind),['started','result','finish']);
    assert.equal(JSON.parse(rows[1].payload).result.reason,'evaluation_error');
    assert.equal(db.prepare('SELECT status FROM runs').get().status,'incomplete');
  });
  assert.equal(result.pass,false);
});

test('evidence rejects contradictory termination and lifecycle claims without committing them',()=>{
  const path=resolve(validateArtifactRoot(),`sapi-test-${crypto.randomUUID()}.sqlite`), evidence=createEvidence(path);
  const runId=crypto.randomUUID(),correlationId=crypto.randomUUID(),now='2026-01-01T00:00:00.000Z';
  const observed={ordinary:{ok:null,reason:'unmeasured'},secure:{ok:null,reason:'unmeasured'}};
  const result={fixture:'valid',correlationId,status:'error',elapsedMs:1,observed};
  try {
    evidence.start({runId,seed:2,planned:['valid','denied','unknown','invalid_schema'],startedUtc:now,timeoutMode:'in_process_observed'});
    evidence.event('started',{index:0,group:0,fixture:'valid',correlationId,startedUtc:now});
    const base={pid:1,sequence:0,killRequested:true,exitObserved:true,normalExited:false};
    for(const termination of [
      {...base,disposition:'terminated',killRequested:false},
      {...base,disposition:'terminated',exitObserved:false},
      {...base,disposition:'terminated',normalExited:true},
      {...base,disposition:'not_started'},
      {...base,disposition:'terminated',sequence:1}
    ]) assert.throws(()=>evidence.event('result',{index:0,group:0,fixture:'valid',result:{...result,reason:'timeout_child_terminated',termination},finishedUtc:now}),/invalid evidence/);
    assert.throws(()=>evidence.finish({runId,planned:4,completed:0,omitted:4,omittedFixtures:['valid','denied','unknown','invalid_schema'],stopped:true,outcomes:[],pass:false}),/invalid evidence/);
    const finalResult={...result,reason:'evaluation_error'};
    evidence.event('result',{index:0,group:0,fixture:'valid',result:finalResult,finishedUtc:now});
    const summary={runId,planned:4,completed:1,omitted:3,omittedFixtures:['denied','unknown','invalid_schema'],stopped:true,outcomes:[finalResult],pass:false};
    assert.throws(()=>evidence.finish({...summary,pass:true}),/invalid evidence/);
    assert.throws(()=>evidence.finish({...summary,omitted:2}),/invalid evidence/);
    evidence.finish(summary);evidence.close();
    const db=new DatabaseSync(path,{readOnly:true});
    try {assert.equal(db.prepare('SELECT count(*) n FROM events').get().n,3);assert.equal(db.prepare('SELECT status FROM runs').get().status,'incomplete');} finally {db.close();}
  } finally {try{evidence.close();}catch{} unlinkSync(path);}
});

test('evidence cannot promote false observations or forged state into a consistent fixture',()=>{
  const path=resolve(validateArtifactRoot(),`sapi-test-${crypto.randomUUID()}.sqlite`), evidence=createEvidence(path);
  const runId=crypto.randomUUID(),correlationId=crypto.randomUUID(),now='2026-01-01T00:00:00.000Z';
  try {
    evidence.start({runId,seed:2,planned:['valid','denied','unknown','invalid_schema'],startedUtc:now,timeoutMode:'in_process_observed'});
    evidence.event('started',{index:0,group:0,fixture:'valid',correlationId,startedUtc:now});
    const empty=stateDigest({}),after=stateDigest({case0:'hello'});
    const proof={beforeOrdinary:empty,beforeSecure:empty,afterOrdinary:after,afterSecure:after};
    const falseObservation={ok:false,reason:'unmeasured'};
    const base={fixture:'valid',correlationId,status:'pass',elapsedMs:1,observed:{ordinary:falseObservation,secure:falseObservation}};
    assert.throws(()=>evidence.event('result',{index:0,group:0,fixture:'valid',result:base,stateProof:proof,finishedUtc:now}),/invalid evidence/);
    const accepted={ok:true,reason:'accepted'},good={...base,observed:{ordinary:accepted,secure:accepted}};
    assert.throws(()=>evidence.event('result',{index:0,group:0,fixture:'valid',result:good,stateProof:{...proof,afterSecure:empty},finishedUtc:now}),/invalid evidence/);
    assert.equal(stateDigest({secret:'PRIVATE_MARKER'}),null);
    evidence.close();const db=new DatabaseSync(path,{readOnly:true});
    try {assert.equal(db.prepare('SELECT status FROM runs').get().status,'running');assert.equal(db.prepare('SELECT count(*) n FROM events').get().n,1);} finally {db.close();}
  } finally {try{evidence.close();}catch{} unlinkSync(path);}
});

test('evidence rejects duplicate, incomplete and wrong-seed fixture plans',()=>{
  const path=resolve(validateArtifactRoot(),`sapi-test-${crypto.randomUUID()}.sqlite`), evidence=createEvidence(path);
  const base={runId:crypto.randomUUID(),seed:2,startedUtc:'2026-01-01T00:00:00.000Z',timeoutMode:'in_process_observed'};
  try {
    for(const planned of [
      ['denied','denied','denied','denied'],
      ['valid','denied','unknown'],
      ['invalid_schema','valid','unknown','denied'],
      ['valid','denied','unknown','invalid_schema','denied','denied','denied','denied']
    ]) assert.throws(()=>evidence.start({...base,planned}),/invalid evidence/);
    evidence.start({...base,planned:['valid','denied','unknown','invalid_schema']});
    evidence.close();
    const db=new DatabaseSync(path,{readOnly:true});
    try {assert.equal(db.prepare('SELECT count(*) n FROM runs').get().n,1);assert.equal(db.prepare('SELECT status FROM runs').get().status,'running');} finally {db.close();}
  } finally {try{evidence.close();}catch{} unlinkSync(path);}
});

test('reader identifies legacy and current evidence without returning raw event data',async()=>{
  const dir=validateArtifactRoot();
  const path=resolve(dir,`sapi-test-${crypto.randomUUID()}.sqlite`);
  const db=new DatabaseSync(path);
  try {
    db.exec("PRAGMA application_id=1396789321; PRAGMA user_version=1; CREATE TABLE runs(x); CREATE TABLE events(payload); INSERT INTO events VALUES('sensitive_legacy');");
  } finally {db.close();}
  try {assert.deepEqual(readEvidenceSummary(path),{version:1,runs:0,events:1});} finally {unlinkSync(path);}
});

test('bounded result parser rejects extra fields and oversized files',()=>{
  assert.throws(()=>parseFixtureOutput(Buffer.alloc(4097)),/size/);
  const bad={version:1,before:{baseline:{},sapi:{}},after:{baseline:{},sapi:{}},ordinary:{ok:false,reason:'forbidden',secret:'marker'},secure:{ok:false,reason:'forbidden'}};
  assert.throws(()=>parseFixtureOutput(Buffer.from(JSON.stringify(bad))),/response/);
});

test('local child is terminated before evidence completion and cannot write later',async()=>{
  const dir=validateArtifactRoot();
  const before=readdirSync(dir).filter(n=>n.startsWith('run-')).sort();
  const isolated=createProcessComparison({seed:1,blockTest:true});
  const pending=recorded({enabled:true,dryRun:false,seed:1,timeoutMs:800,compare:isolated.compare},async db=>{
    const first=JSON.stringify(db.prepare('SELECT kind,payload FROM events ORDER BY seq').all());
    assert.equal(db.prepare('SELECT status FROM runs').get().status,'incomplete');
    await new Promise(resolve=>setTimeout(resolve,2100));
    assert.equal(JSON.stringify(db.prepare('SELECT kind,payload FROM events ORDER BY seq').all()),first);
  });
  for(let i=0;i<50&&!isolated.hasStarted();i++) await new Promise(resolve=>setTimeout(resolve,10));
  assert.equal(isolated.hasStarted(),true);
  const result=await pending;
  assert.equal(result.outcomes[0].reason,'timeout_child_terminated');assert.equal(result.omitted,3);assert.equal(result.pass,false);
  assert.equal(result.outcomes[0].termination.killRequested,true);assert.equal(result.outcomes[0].termination.exitObserved,true);assert.equal(result.outcomes[0].termination.normalExited,false);assert.ok(result.outcomes[0].termination.pid>0);
  assert.deepEqual(readdirSync(dir).filter(n=>n.startsWith('run-')).sort(),before);
});

test('unstarted and already completed child never claim a kill',async()=>{
  const isolated=createProcessComparison({seed:1}), id=crypto.randomUUID();
  assert.deepEqual(await terminateVerifiedChild(isolated.compare,id),{disposition:'not_started',pid:null,sequence:null,killRequested:false,exitObserved:false,normalExited:false});
  const f=fixturePlan(1)[0];
  await isolated.compare({correlationId:id,operation:f.operation,identity:f.identity,data:{...f.data,id:'case0'}});
  const ended=await terminateVerifiedChild(isolated.compare,id);
  assert.equal(ended.disposition,'late_completed');assert.equal(ended.killRequested,false);assert.equal(ended.exitObserved,true);assert.equal(ended.normalExited,true);assert.ok(ended.pid>0);
});

test('normal completion after elapsed deadline is late, not killed',async()=>{
  const isolated=createProcessComparison({seed:1,testAfterExitBlockMs:1000});
  const result=await recorded({enabled:true,dryRun:false,seed:1,timeoutMs:800,compare:isolated.compare});
  assert.equal(result.outcomes[0].reason,'timeout_late_completed');
  assert.equal(result.outcomes[0].termination.killRequested,false);
  assert.equal(result.outcomes[0].termination.exitObserved,true);
  assert.equal(result.outcomes[0].termination.normalExited,true);assert.equal(result.pass,false);
});

test('caller-supplied no-op termination cannot claim child exit',async()=>{
  let sideEffect=false;
  const result=await recorded({enabled:true,dryRun:false,timeoutMs:5,terminate:async()=>{},compare:()=>new Promise(resolve=>setTimeout(()=>{sideEffect=true;resolve({});},30))});
  assert.equal(result.outcomes[0].reason,'timeout_unknown');assert.equal(result.pass,false);
  await new Promise(resolve=>setTimeout(resolve,50));assert.equal(sideEffect,true);
});

test('artifact paths reject outside destinations',()=>{
  assert.throws(()=>validateArtifactRoot(resolve('..')),/fixed/);
  assert.throws(()=>validateArtifactFile(resolve('..','outside.sqlite')),/fixed/);
});

test('two repeated runs preserve independent oracle groups and evidence',async()=>{
  const isolated=createProcessComparison({seed:4,runs:2});
  const result=await recorded({enabled:true,dryRun:false,seed:4,runs:2,compare:isolated.compare},db=>{
    const rows=db.prepare("SELECT payload FROM events WHERE kind='result' ORDER BY seq").all().map(row=>JSON.parse(row.payload));
    assert.deepEqual(rows.map(x=>x.group),[0,0,0,0,1,1,1,1]);
  });
  assert.equal(result.pass,true);assert.equal(result.completed,8);assert.equal(result.omitted,0);
});

test('process fixture plans support every repeat count from two through seven',async()=>{
  const oracle={valid:'accepted',invalid_schema:'invalid_input',denied:'forbidden',unknown:'unknown_operation'};
  for(let runs=2;runs<=7;runs++) {
    const seed=9,plan=fixturePlan(seed,runs),compare=createProcessComparison({seed,runs}).compare;
    let expected={};
    for(let i=0;i<plan.length;i++) {
      if(i%4===0) expected={};
      const f=plan[i],data={...f.data,id:`case${i}`};
      const r=await compare({correlationId:crypto.randomUUID(),operation:f.operation,identity:f.identity,data});
      assert.deepEqual(r.before.baseline,expected);assert.deepEqual(r.before.sapi,expected);
      assert.equal(r.ordinary.reason,oracle[f.name]);assert.equal(r.secure.reason,oracle[f.name]);
      if(f.name==='valid') expected={...expected,[data.id]:'hello'};
      assert.deepEqual(r.after.baseline,expected);assert.deepEqual(r.after.sapi,expected);
    }
  }
});
