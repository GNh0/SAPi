import assert from 'node:assert/strict';
import {test} from 'node:test';
import {DatabaseSync} from 'node:sqlite';
import {createContractComparison,comparisonModes} from '../examples/shadow/contract-comparison.mjs';
import {readFileSync} from 'node:fs';
import {contractCases,wireMutationKinds,initialModel,advanceModel} from './contract-comparison-oracle.mjs';

async function runComparison(factory=createContractComparison,{quiet=false}={}){
 const deadline=performance.now()+10000,sqlites={},databases={},faults={},report={source:'local_synthetic',cases:contractCases.length,variants:{}};
 const state=mode=>({items:sqlites[mode].prepare('SELECT id,owner,value FROM sapi_internal_effect_items ORDER BY id').all().map(x=>({...x})),receipts:sqlites[mode].prepare('SELECT operation_key,owner,item,operation,normalized,result_json FROM sapi_internal_effect_receipts ORDER BY operation_key').all().map(x=>({...x}))});
 const total=s=>s.items.reduce((sum,x)=>sum+x.value,0);
 try{
  for(const mode of comparisonModes){
   const sqlite=sqlites[mode]=new DatabaseSync(':memory:');
   databases[mode]={prepare(sql){const bound=args=>({_sql:sql,_args:args,bind(...v){return bound(v)},async first(){const row=sqlite.prepare(sql).get(...args);return row?{...row}:null}});return bound([])},async batch(statements){
    const writing=statements.some(x=>x._sql.startsWith('INSERT INTO sapi_internal_effect_receipts'));
    const fault=writing?faults[mode]:null;if(writing)faults[mode]=null;
    if(fault==='before')throw Error('injected before commit');
    sqlite.exec('BEGIN');try{const out=statements.map(x=>sqlite.prepare(x._sql).run(...x._args));sqlite.exec('COMMIT');if(fault==='after')throw Error('injected acknowledgement loss');return out}catch(error){if(sqlite.isTransaction)sqlite.exec('ROLLBACK');throw error}
   }};
   report.variants[mode]={serialExecutions:0,byCategory:{},normal:{attempts:0,rejected:0,uncertain:0,semanticFailures:0},effectMismatches:0,handlerMismatches:0,latencies:[],preparation:[]};
  }
  const fixture=await factory(databases),models=Object.fromEntries(comparisonModes.map(mode=>[mode,initialModel()]));
  async function check(mode,c,{handle=null,countSerial=true}={}){
   assert.ok(performance.now()<deadline,'cooperative whole-test deadline');
   assert.deepEqual(state(mode),models[mode],`${mode}/${c.id}/independent before`);
   const before=state(mode),ticket=handle??await fixture.prepare(mode,c);faults[mode]=c.fault??null;
   const result=await fixture.execute(mode,ticket,{dropResponse:c.dropResponse??false}),after=state(mode),m=report.variants[mode];
   if(countSerial){
    m.serialExecutions++;m.latencies.push(result.latencyMs);m.preparation.push(result.prepareMs);
    const bucket=m.byCategory[c.category]??={attempts:0,accepted:0,rejected:0,uncertain:0};bucket.attempts++;bucket[result.classification]++;
    if(c.category==='normal'){m.normal.attempts++;if(result.classification==='rejected')m.normal.rejected++;if(result.classification==='uncertain')m.normal.uncertain++}
   }
   const delta=total(after)-total(before),receipts=after.receipts.length-before.receipts.length;
   if(delta!==c.effects||receipts!==c.receipts){m.effectMismatches++;if(c.category==='normal')m.normal.semanticFailures++}
   if(result.handlerEntries!==c.handlers)m.handlerMismatches++;
   assert.equal(delta,c.effects,`${mode}/${c.id}/effect`);assert.equal(receipts,c.receipts,`${mode}/${c.id}/receipt`);assert.equal(result.handlerEntries,c.handlers,`${mode}/${c.id}/handler`);
   if(c.expected==='precommit_failure')assert.equal(result.classification,c.responseByMode[mode],`${mode}/${c.id}/precommit response`);
   else assert.equal(result.classification,c.expected,`${mode}/${c.id}/response`);
   if(c.expected==='accepted')assert.deepEqual({...result.receipt},{item:c.input.item,operation_key:c.input.operation_key,state:'committed'});
   if(c.expectedLayer)assert.equal(result.validationLayer,c.expectedLayer,`${mode}/${c.id}/validation layer`);
   models[mode]=advanceModel(models[mode],c);
   assert.deepEqual(after,models[mode],`${mode}/${c.id}/independent item-owner-receipt state`);
   for(const kid of ['alice','bob']){
    const expected=models[mode].receipts.find(x=>x.operation_key===c.input.operation_key&&x.owner===kid);
    const visible=await fixture.readReceipt(mode,kid,c.input.operation_key);
    assert.deepEqual(visible?{...visible}:null,expected?JSON.parse(expected.result_json):null,`${mode}/${c.id}/${kid}/receipt authorization`);
   }

  }
  for(const c of contractCases){
   for(const mode of comparisonModes)await check(mode,c);
   assert.deepEqual(state('ordinary'),state('hardened'),`${c.id}/ordinary-hardened parity`);assert.deepEqual(state('ordinary'),state('sapi'),`${c.id}/ordinary-sapi parity`);
   if(c.expected!=='accepted'){
    const recovery={id:`recovery_${c.id}`,input:{item:'fixture',operation_key:`recovery_${c.id}`.slice(0,40),bad_output:false},expected:'accepted',handlers:1,effects:1,receipts:1,category:'normal'};
    for(const mode of comparisonModes)await check(mode,recovery);
   }
  }
  for(const mode of comparisonModes){
   const before=state(mode),ticket=await fixture.prepare(mode,{input:{item:'fixture',operation_key:'same_wire_race',bad_output:false}});
   const both=await Promise.all(Array.from({length:8},()=>fixture.execute(mode,ticket)));
   assert.equal(both.filter(x=>x.classification==='accepted').length,1);assert.equal(both.filter(x=>x.reason==='replay').length,7);
   assert.equal(both.reduce((sum,x)=>sum+x.handlerEntries,0),1,'handler attribution must not use concurrent global deltas');
   assert.equal(total(state(mode))-total(before),1);assert.equal(state(mode).receipts.length-before.receipts.length,1);
   models[mode]=advanceModel(models[mode],{input:{item:'fixture',operation_key:'same_wire_race',bad_output:false},effects:1,receipts:1});assert.deepEqual(state(mode),models[mode]);
   report.variants[mode].concurrent={attempts:8,accepted:1,replay:7,effects:1,receipts:1};
   const freshBefore=state(mode),freshInput={item:'fixture',operation_key:'fresh_business_race',bad_output:false};
   const freshTickets=await Promise.all(Array.from({length:8},()=>fixture.prepare(mode,{input:freshInput})));
   const fresh=await Promise.all(freshTickets.map(t=>fixture.execute(mode,t)));
   assert.equal(fresh.filter(x=>x.classification==='accepted').length,8);assert.equal(fresh.reduce((sum,x)=>sum+x.handlerEntries,0),8);
   assert.equal(total(state(mode))-total(freshBefore),1);assert.equal(state(mode).receipts.length-freshBefore.receipts.length,1);
   models[mode]=advanceModel(models[mode],{input:freshInput,effects:1,receipts:1});assert.deepEqual(state(mode),models[mode]);
   report.variants[mode].freshBusinessConcurrency={attempts:8,accepted:8,handlers:8,effects:1,receipts:1};
   report.variants[mode].totalExecutions=report.variants[mode].serialExecutions+16;
  }
  assert.deepEqual(state('ordinary'),state('hardened'));assert.deepEqual(state('ordinary'),state('sapi'));
  for(const mode of comparisonModes){
   const final=state(mode);assert.equal(final.receipts.length,17);assert.deepEqual(Object.fromEntries(final.items.map(x=>[x.id,x.value])),{bob_fixture:1,fixture:16,fixture2:0});
   report.variants[mode].commonEffects=17;report.variants[mode].commonReceipts=17;
  }
  // Common-contract results above are separate from mode-specific guarantees.
  for(const mode of comparisonModes){
   const counts=Object.fromEntries(Object.entries(report.variants[mode].byCategory).map(([key,v])=>[key,v.attempts]));
   assert.deepEqual(counts,{normal:16,unauthorized:2,schema_invalid:2,unsupported_operation:1,injected_failure:4,business_conflict:2});
   const protocol=report.variants[mode].protocol={requestIntegrity:{attempted:0,rejected:0,recoveryAccepted:0,notApplicable:[]},responseIntegrity:{status:'not_applicable',requires:'external_authenticated_protected_response_transport'}};
   for(const mutation of wireMutationKinds){
    const c={id:`wire_${mutation}`,input:{item:'fixture',operation_key:`wire_${mutation}`,bad_output:false},category:'wire_integrity',expected:'rejected',effects:0,receipts:0,handlers:0,expectedLayer:mode==='hardened'?(mutation==='kid_relabel'?'hmac_identity_binding':'hmac_verification'):'sapi_request'};
    const ticket=await fixture.prepare(mode,c),changed=await fixture.mutate(mode,ticket,mutation);
    if(mode==='ordinary'){assert.equal(changed.status,'not_applicable');protocol.requestIntegrity.notApplicable.push(mutation);continue}
    assert.equal(changed.status,'ready');await check(mode,c,{handle:changed.handle,countSerial:false});protocol.requestIntegrity.attempted++;protocol.requestIntegrity.rejected++;
    await check(mode,{id:`repair_${mutation}`,input:{item:'fixture',operation_key:`repair_${mutation}`,bad_output:false},category:'normal',expected:'accepted',effects:1,receipts:1,handlers:1},{countSerial:false});protocol.requestIntegrity.recoveryAccepted++;
   }
   const responseCase={id:'response_tag_flip',input:{item:'fixture',operation_key:'response_tag_flip',bad_output:false},category:'wire_integrity',expected:'uncertain',effects:1,receipts:1,handlers:1,expectedLayer:'sapi_response'};
   const changed=await fixture.mutate(mode,await fixture.prepare(mode,responseCase),'response_tag_flip');
   if(mode==='sapi'){
    assert.equal(changed.status,'ready');await check(mode,responseCase,{handle:changed.handle,countSerial:false});
    await check(mode,{...responseCase,id:'response_tag_retry',expected:'accepted',effects:0,receipts:0},{countSerial:false});
    protocol.responseIntegrity={status:'checked',uncertain:1,committedEffects:1,safeLookup:true,freshRetryAdditionalEffects:0};
   }else assert.equal(changed.status,'not_applicable');
   report.variants[mode].totalExecutions+=protocol.requestIntegrity.attempted*2+(mode==='sapi'?2:0);
   assert.deepEqual(state(mode),models[mode]);
   assert.equal(total(state(mode)),{ordinary:17,hardened:21,sapi:22}[mode]);
  }
  const distribution=values=>{values.sort((a,b)=>a-b);return {samples:values.length,p50:values[Math.floor(values.length/2)],p95:values[Math.floor(values.length*.95)]}};
  for(const m of Object.values(report.variants)){m.serialLatencyMs=distribution(m.latencies);m.requestPreparationMs=distribution(m.preparation);delete m.latencies;delete m.preparation}
  if(!quiet)console.log(JSON.stringify(report));
  return report;
 }finally{for(const sqlite of Object.values(sqlites))sqlite.close()}
}

test('common contract and mode-specific wire boundaries',async()=>{await runComparison()});

test('fixed source mutations are caught by independent contract and boundary controls',async()=>{
 const receiptUrl=new URL('../examples/shadow/receipt-contract.mjs',import.meta.url),comparisonUrl=new URL('../examples/shadow/contract-comparison.mjs',import.meta.url);
 const receipt=readFileSync(receiptUrl,'utf8'),comparison=readFileSync(comparisonUrl,'utf8');
 const once=(source,from,to)=>{assert.equal(source.split(from).length,2,'mutation must have one exact target');return source.replace(from,to)};
 const absolute=(source,base,replaceReceipt)=>source.replace(/from (['"])(\.[^'"]+)\1/g,(_match,quote,path)=>`from ${quote}${replaceReceipt&&path==='./receipt-contract.mjs'?replaceReceipt:new URL(path,base).href}${quote}`);
 const moduleUrl=source=>'data:text/javascript;base64,'+Buffer.from(source).toString('base64');
 const mutations=[
  {id:'shared_double_effect',business:once(receipt,'value=value+1','value=value+2')},
  {id:'shared_authorization_bypass',business:once(receipt,"return typeof principal?.subject==='string'&&Object.hasOwn(ownerByItem,input?.item)&&ownerByItem[input.item]===principal.subject;",'return true;')},
  {id:'shared_receipt_owner_leak',business:once(receipt,'WHERE operation_key=? AND owner=?','WHERE operation_key=? AND (owner=? OR 1=1)')},
  {id:'ordinary_scope_bypass',boundary:once(comparison,"!p.scopes.includes('write')",'false')},
  {id:'hmac_verification_bypass',boundary:once(comparison,"await crypto.subtle.verify('HMAC',macKeys[ticket.kid],ticket.mac,enc.encode(ticket.body))",'true')},
 ];
 const killed=[];
 try{
  for(const mutation of mutations){
   const businessUrl=moduleUrl(absolute(mutation.business??receipt,receiptUrl));
   const mutated=await import(moduleUrl(absolute(mutation.boundary??comparison,comparisonUrl,businessUrl)));
   await assert.rejects(()=>runComparison(mutated.createContractComparison,{quiet:true}),error=>{
    assert.equal(error.code,'ERR_ASSERTION','a crash is not evidence the semantic oracle caught the defect');
    assert.match(error.message,/effect|receipt authorization|independent|handler/);return true;
   },`${mutation.id} survived`);
   killed.push(mutation.id);
  }
  console.log(JSON.stringify({mutationControls:{attempted:mutations.length,killed,sourceEdits:false,allFixtureExecutionUpperBound:960,scope:'fixed in-memory source mutations; not exhaustive mutation coverage'}}));
 }finally{
  assert.equal(readFileSync(receiptUrl,'utf8'),receipt,'shared business source must remain unchanged');
  assert.equal(readFileSync(comparisonUrl,'utf8'),comparison,'boundary source must remain unchanged');
 }
});
