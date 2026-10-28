// Finite, synthetic, offline SDK corpus; no production credentials or transport.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {Codec,SecureServer,StaticKeyProvider,MemoryReplayStore,Schema} from '../sdks/javascript/src/index.js';
import {parse} from '../sdks/javascript/src/serialization.js';
import {D1ReplayStore,initializeExclusivePolicy} from '../sdks/javascript/src/state-d1.js';
import {setup,install,business} from '../examples/shadow/receipt-contract.mjs';
import {expectedClass,classificationFailure} from './seeded-corpus-oracle.mjs';

const seed=Number(process.env.SAPI_CORPUS_SEED ?? 1028), count=Number(process.env.SAPI_CORPUS_COUNT ?? 200);
if(!Number.isInteger(seed)||seed<0||seed>0xffffffff||!Number.isInteger(count)||count<1||count>1000)throw Error('invalid corpus bounds');
const deadline=performance.now()+30000, cpuStart=process.cpuUsage(), maxCpuUs=15000000, maxWire=131072;
const claimedBase=process.env.SAPI_CORPUS_COMMIT ?? 'unrecorded';
if(claimedBase!=='unrecorded'&&!/^[0-9a-f]{40}$/.test(claimedBase))throw Error('invalid commit identifier');
const sourceSha256=createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex');
let state=seed>>>0; const random=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state;};
// This is the independent expectation catalog, separate from SDK return values.
const kinds=Object.keys(expectedClass);
const shapeKinds=new Set(['text_sql','text_unicode','text_email','text_31','text_32','text_33','number_9','number_10','number_11','array_1','array_2','array_3']);
const rejectedShapes=new Set(['text_33','number_11','array_3']);
const rawKinds=new Set(['duplicate_header','duplicate_body','invalid_utf8','lone_surrogate','extra_field','expired','field_order','direction','service']);
const enc=new TextEncoder();
async function authenticatedRaw(codec,kind,id,key){
 const header='{"alg":"dir","enc":"A256GCM","typ":"sapi+jwe","kid":"alice","sapi":"0.1","dir":"req","svc":"corpus","crit":["sapi","dir","svc"]}';
 const payload=`{"id":"${id}","iat":1000,"exp":1060,"op":"change","data":{"item":"fixture","operation_key":"${key}","bad_output":false}}`;
 let h=kind==='duplicate_header'?header.slice(0,-1)+',"alg":"dir"}':kind==='direction'?header.replace('"dir":"req"','"dir":"res"'):kind==='service'?header.replace('"svc":"corpus"','"svc":"other"'):header;
 let body=kind==='duplicate_body'?payload.slice(0,-1)+',"op":"change"}':kind==='extra_field'?payload.slice(0,-1)+',"unexpected":1}':kind==='expired'?payload.replace('"iat":1000,"exp":1060','"iat":940,"exp":1000'):kind==='lone_surrogate'?payload.replace('"item":"fixture"','"item":"\\ud800"'):kind==='field_order'?` { "data": { "bad_output": false, "operation_key": "${key}", "item": "\\u0066ixture" }, "op":"change", "exp":1060, "iat":1000, "id":"${id}" } `:payload;
 let bytes=enc.encode(body);if(kind==='invalid_utf8'){bytes=new Uint8Array([...bytes.slice(0,-1),0xff,0x7d]);}
 const protectedPart=Buffer.from(h).toString('base64url'),iv=crypto.getRandomValues(new Uint8Array(12));
 const aes=await crypto.subtle.importKey('raw',await codec.derive('alice','req'),'AES-GCM',false,['encrypt']);
 const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(protectedPart),tagLength:128},aes,bytes));
 return [protectedPart,'',Buffer.from(iv).toString('base64url'),Buffer.from(encrypted.slice(0,-16)).toString('base64url'),Buffer.from(encrypted.slice(-16)).toString('base64url')].join('.');
}
const sqlite=new DatabaseSync(':memory:');
const db={prepare(sql){const p=()=>sqlite.prepare(sql);const b=args=>({async first(){const row=p().get(...args);return row?{...row}:null},async run(){return p().run(...args)},_sql:sql,_args:args});return {...b([]),bind(...a){return b(a)}}},async batch(stmts){sqlite.exec('BEGIN');try{const result=stmts.map(s=>sqlite.prepare(s._sql).run(...s._args));sqlite.exec('COMMIT');return result}catch(e){sqlite.exec('ROLLBACK');throw e}}};
const totals={pass:0,fail:0,normalContractFailures:0,normalRejected:0,normalSemanticMismatch:0,normalUncertain:0,normalAttempts:0,normalPassed:0,unmeasured:0}, byKind={};
let current;
try {
 await setup(db);
 sqlite.exec(readFileSync(new URL('../sdks/javascript/src/state-d1.sql',import.meta.url),'utf8'));
 const d1Options={mode:'exclusive',service:'corpus',policyVersion:'v1',operations:{change:{requests:60,period:60}}};
 const d1Good=new D1ReplayStore(db,d1Options),d1Mismatch=new D1ReplayStore(db,{...d1Options,costLimit:121});
 assert.equal(await initializeExclusivePolicy(db,d1Good),true);
 const alice=crypto.getRandomValues(new Uint8Array(32)),other=crypto.getRandomValues(new Uint8Array(32));
 const provider=new StaticKeyProvider({alice:{master:alice,subject:'alice',scopes:['write']},bob:{master:other,subject:'bob',scopes:['write']},noscope:{master:other,subject:'alice',scopes:['read']}});
 const codec=new Codec('corpus',provider,()=>1000);
 const liveClockCodec=new Codec('corpus',provider);
 const wrong=new Codec('corpus',new StaticKeyProvider({alice:{master:other,subject:'alice',scopes:['write']}}),()=>1000);
 // Independent fixed lower/exact/upper parser and wire boundaries.
 const boundaries=[];
 const startControl=(label,ok)=>{current={id:label,kind:'boundary',expectedClass:ok?'normal':'reject'};if(ok)totals.normalAttempts++};
 const endControl=ok=>{if(ok)totals.normalPassed++};
 const boundary=(label,fn,ok)=>{startControl(label,ok);let accepted=true;try{fn();current.observation='accepted'}catch(e){accepted=false;if(e.code==='invalid_message')current.observation='rejected'}assert.equal(accepted,ok,label);endControl(ok);boundaries.push(label)};
 for(const [n,ok] of [[9007199254740990,true],[9007199254740991,true],[9007199254740992,false]])boundary(`safe_integer_${n}`,()=>parse(enc.encode(String(n))),ok);
 const intSchema=new Schema({type:'integer'});
 for(const [label,value,ok] of [['integer_type',1,true],['boolean_type',true,false],['fraction_type',1.5,false]]){startControl(label,ok);const result=intSchema.validate(value);current.observation=result?'accepted':'rejected';assert.equal(result,ok);endControl(ok);boundaries.push(label)}
 for(const [n,ok] of [[31,true],[32,true],[33,false]])boundary(`json_depth_${n}`,()=>parse(enc.encode('['.repeat(n)+'0'+']'.repeat(n))),ok);
 const arrSchema=new Schema({type:'array',maxItems:64,items:{type:'integer'}});
 for(const [n,ok] of [[63,true],[64,true],[65,false]]){startControl(`array_${n}`,ok);const result=arrSchema.validate(Array(n).fill(1));current.observation=result?'accepted':'rejected';assert.equal(result,ok);endControl(ok);boundaries.push(`array_${n}`)}
 const makeRaw=async(header,body)=>{const h=Buffer.from(header).toString('base64url'),iv=crypto.getRandomValues(new Uint8Array(12)),aes=await crypto.subtle.importKey('raw',await codec.derive('alice','req'),'AES-GCM',false,['encrypt']);const sealed=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(h)},aes,enc.encode(body)));return [h,'',Buffer.from(iv).toString('base64url'),Buffer.from(sealed.slice(0,-16)).toString('base64url'),Buffer.from(sealed.slice(-16)).toString('base64url')].join('.')};
 const head='{"alg":"dir","enc":"A256GCM","typ":"sapi+jwe","kid":"alice","sapi":"0.1","dir":"req","svc":"corpus","crit":["sapi","dir","svc"]}',body='{"id":"00000000000000000000000000000001","iat":1000,"exp":1060,"op":"change","data":{}}';
 const openBoundary=async(label,wire,ok)=>{startControl(label,ok);let accepted=true;try{await codec.open(wire,'req');current.observation='accepted'}catch(e){if(e.code!=='invalid_message')throw e;accepted=false;current.observation='rejected'}assert.equal(accepted,ok,label);endControl(ok);boundaries.push(label)};
 for(const n of [1023,1024,1025])await openBoundary(`header_${n}`,await makeRaw(head+' '.repeat(n-head.length),body),n<=1024);
 for(const n of [65535,65536,65537])await openBoundary(`body_${n}`,await makeRaw(head,body+' '.repeat(n-body.length)),n<=65536);
 // No valid compact wire can reach these lengths under the tighter body/header caps.
 for(const n of [131071,131072,131073])await openBoundary(`wire_${n}`,'a'.repeat(n),false);
 // One replay store over an ordered sequence, including expiry-driven cleanup.
 startControl('shared_replay_expiry_cleanup',true);
 let clock=1000,handled=0;const shared=new MemoryReplayStore(2),sequenceCodec=new Codec('corpus',provider,()=>clock),seq=new SecureServer(sequenceCodec,shared),seqSchema={type:'object',properties:{value:{type:'string',maxBytes:16}}};
 seq.register('sequence','write',seqSchema,seqSchema,()=>true,(_principal,data)=>{handled++;return data});
 const sendSeq=async ctx=>sequenceCodec.acceptResponse(ctx,await seq.handle(ctx.wire));
 const first=await sequenceCodec.request('alice','sequence',{value:'alice'});assert.equal((await sendSeq(first)).data.value,'alice');assert.equal((await sequenceCodec.open(await seq.handle(first.wire),'res')).payload.error,'replay');
 const second=await sequenceCodec.request('bob','sequence',{value:'bob'});assert.equal((await sendSeq(second)).data.value,'bob');clock=1061;
 await assert.rejects(()=>seq.handle(first.wire),e=>e.code==='invalid_message');
 const third=await sequenceCodec.request('alice','sequence',{value:'fresh'});assert.equal((await sendSeq(third)).data.value,'fresh');assert.equal(handled,3);endControl(true);boundaries.push('shared_replay_expiry_cleanup');
 const snapshot=()=>({effects:Number(sqlite.prepare('SELECT sum(value) AS n FROM sapi_internal_effect_items').get().n),receipts:Number(sqlite.prepare('SELECT count(*) AS n FROM sapi_internal_effect_receipts').get().n)});
 for(let i=0;i<count;i++){
  const cpu=process.cpuUsage(cpuStart);if(performance.now()>deadline||cpu.user+cpu.system>maxCpuUs)throw Error('time or CPU limit exceeded');
  const caseDeadline=performance.now()+2000;
  // Timer exits this disposable process: outstanding effects and all later cases are unknown.
  // An event-loop stall cannot be interrupted here; this is not a hard watchdog.
  const bounded=async promise=>{const timer=setTimeout(()=>{process.stderr.write(JSON.stringify({seed,claimedBase,sourceSha256,case:current,status:'timeout_unknown',later:'not_run'})+'\n');process.exit(2)},Math.max(0,caseDeadline-performance.now()));try{return await promise}finally{clearTimeout(timer)}};
  // Every fourth case is an independent normal control, regardless of seed.
  const kind=i%4===0?'valid':kinds[random()%kinds.length], id=`case-${String(i).padStart(4,'0')}`;
  current={id,kind,expectedClass:expectedClass[kind]};if(current.expectedClass==='normal')totals.normalAttempts++;
  const transport={handlers:0},memory=new MemoryReplayStore();let failStore=kind==='store_error';
  if(process.env.SAPI_CORPUS_PROGRESS==='1')console.log(JSON.stringify({type:'started',id,kind}));
  const store=kind==='store_error'?{async admit(...args){if(failStore){failStore=false;throw Error('synthetic storage failure')}return memory.admit(...args)},claim:(...args)=>memory.claim(...args)}:memory;
  const caseCodec=kind==='d1_policy'?liveClockCodec:codec;
  const server=new SecureServer(caseCodec,kind==='d1_policy'?d1Mismatch:store);install(server,db,transport);
  if(shapeKinds.has(kind)){
   const shape={type:'object',properties:{operation_key:{type:'string',maxBytes:40},text:{type:'string',maxBytes:32},n:{type:'integer',min:0,max:10},arr:{type:'array',maxItems:2,items:{type:'integer'}}}};
   server.register('shape','write',shape,shape,()=>true,async(principal,input)=>{transport.handlers++;await business(db,principal,{item:'fixture',operation_key:input.operation_key,bad_output:false});return input});
  }
  byKind[kind]=(byKind[kind]??0)+1;
  const data={item:kind==='forbidden'?'bob_fixture':'fixture',operation_key:`k${i}`,bad_output:kind==='invalid_output'};
  if(kind==='invalid_schema')data.bad_output='not-a-boolean';
  let op='change',input=data;
  if(shapeKinds.has(kind)){
   op='shape';input={operation_key:`k${i}`,text:kind==='text_sql'?"x'; SELECT 1 --":kind==='text_unicode'?'한글 | ,':kind==='text_email'?'user@example.com':kind.startsWith('text_')?'x'.repeat(Number(kind.slice(5))):'ok',n:kind.startsWith('number_')?Number(kind.slice(7)):1,arr:kind.startsWith('array_')?Array(Number(kind.slice(6))).fill(1):[]};
  }
  const request=await (kind==='wrong_key'?wrong:caseCodec).request(kind==='scope'?'noscope':'alice',op,input); let wire=request.wire;
  if(rawKinds.has(kind))wire=await authenticatedRaw(codec,kind,request.id,`k${i}`);
  if(kind==='field_order')request.wire=wire;
  if(kind==='tampered'){const parts=wire.split('.');parts[4]=(parts[4][0]==='A'?'B':'A')+parts[4].slice(1);wire=parts.join('.');}
  if(kind==='ciphertext'){const p=wire.split('.');p[3]=(p[3][0]==='A'?'B':'A')+p[3].slice(1);wire=p.join('.');}
  if(kind==='base64_padding'){const p=wire.split('.');p[0]+='=';wire=p.join('.');}
  if(kind==='short_iv'||kind==='short_tag'){const p=wire.split('.'),index=kind==='short_iv'?2:4;p[index]=Buffer.from(Buffer.from(p[index],'base64url').slice(0,-1)).toString('base64url');wire=p.join('.');}
  assert.ok(Buffer.byteLength(wire)<=maxWire);
  const before=snapshot();let result,thrown=false;
  try{if(kind==='concurrent_replay'){
    const outcomes=await bounded(Promise.all(Array.from({length:8},async()=> (await codec.open(await server.handle(wire),'res')).payload)));
    assert.equal(outcomes.filter(x=>x.ok).length,1);assert.equal(outcomes.filter(x=>x.error==='replay').length,7);result=outcomes.find(x=>x.ok);
   }else{let response;try{response=await bounded(server.handle(wire))}catch(e){if(e.code!=='invalid_message')throw e;thrown=true;current.observation='rejected'}
    if(!thrown)result=rawKinds.has(kind)&&kind!=='field_order'?(await codec.open(response,'res')).payload:await caseCodec.acceptResponse(request,response);}}
  catch(e){throw e;}
  if(result?.ok===true)current.observation='accepted';else if(result?.ok===false)current.observation='rejected';
  let expectedEffect=0,expectedHandlers=0,expectedError;
  if(expectedClass[kind]==='normal'){expectedEffect=1;expectedHandlers=1;assert.equal(thrown,false);assert.equal(result.ok,true);if(shapeKinds.has(kind))assert.equal(JSON.stringify(result.data),JSON.stringify(input));}
  else if(['tampered','ciphertext','wrong_key','direction','service','base64_padding','short_iv','short_tag','duplicate_header','duplicate_body','invalid_utf8','lone_surrogate','extra_field','expired'].includes(kind))assert.equal(thrown,true);
  else {expectedError=kind==='invalid_schema'||rejectedShapes.has(kind)?'invalid_input':['forbidden','scope'].includes(kind)?'forbidden':'internal_error'; expectedHandlers=kind==='invalid_output'?1:0;assert.equal(thrown,false);assert.equal(result.error,expectedError);}
  if(kind==='replay') {const again=(await codec.open(await bounded(server.handle(wire)),'res')).payload;assert.equal(again.error,'replay');}
  if(kind==='business_retry'){const retry=await codec.request('alice','change',data);const again=await codec.acceptResponse(retry,await bounded(server.handle(retry.wire)));assert.equal(again.ok,true);expectedHandlers=2;}
  const after=snapshot();assert.equal(transport.handlers,expectedHandlers);assert.equal(after.effects-before.effects,expectedEffect);assert.equal(after.receipts-before.receipts,expectedEffect);
  if(expectedClass[kind]==='normal')totals.normalPassed++;
  if(expectedEffect===0){
   current={id,kind:'recovery',expectedClass:'normal',afterKind:kind};totals.normalAttempts++;
   // A mismatched deployment is corrected explicitly before the recovery control.
   if(kind==='d1_policy')server.replay=d1Good;
   const follow=await caseCodec.request('alice','change',{item:'fixture',operation_key:`follow${i}`,bad_output:false});
   const response=await caseCodec.acceptResponse(follow,await bounded(server.handle(follow.wire)));current.observation=response.ok===true?'accepted':response.ok===false?'rejected':undefined;assert.equal(response.ok,true);
   const recovered=snapshot();assert.equal(recovered.effects-after.effects,1);assert.equal(recovered.receipts-after.receipts,1);assert.equal(transport.handlers,expectedHandlers+1);
   totals.normalPassed++;
  }
  totals.pass++;
 }
 console.log(JSON.stringify({version:1,source:'local_synthetic',seed,claimedBase,sourceSha256,seedScope:'template selection only; crypto randomness differs',planned:count,completed:totals.pass+totals.unmeasured,...totals,byKind,boundaries,limits:{cases:1000,wallMs:30000,cpuMs:15000,caseMs:2000,wireBytes:maxWire,timeout:'cooperative event-loop timer; process exit; no external watchdog'},unverified:['complete numeric-type and wire semantic matrix','D1 distributed behavior','extended replay endurance','external traffic','automatic minimization']}));
} catch(error){totals.fail++;const category=classificationFailure(current);if(category){totals.normalContractFailures++;totals[category]++}console.error(JSON.stringify({version:1,seed,claimedBase,sourceSha256,case:current,completed:totals.pass,...totals,error:String(error.message).slice(0,300),reproduction:`SAPI_CORPUS_SEED=${seed} SAPI_CORPUS_COUNT=${count}`,minimizedInput:'case descriptor only; raw wire and keys excluded'}));process.exitCode=1;}
finally{sqlite.close();}
