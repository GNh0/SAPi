// Finite local runner. No network transport.
import {isVerifiedProcessComparison,terminateVerifiedChild} from './process-comparison.mjs';
import {stateDigest} from './sqlite-evidence.mjs';
const fixtures = [
  {name:'valid', operation:'put',identity:'allowed',data:{id:'fixture',value:'hello'},expected:'accepted'},
  {name:'invalid_schema', operation:'put',identity:'allowed',data:{id:'fixture',value:3},expected:'invalid_input'},
  {name:'denied', operation:'put',identity:'denied',data:{id:'fixture',value:'no'},expected:'forbidden'},
  {name:'unknown', operation:'unknown',identity:'allowed',data:{id:'fixture',value:'no'},expected:'unknown_operation'},
];
const TIMEOUT=Symbol('timeout');
function shuffled(seed) {
  let x=seed >>> 0; const a=[...fixtures];
  for(let i=a.length-1;i>0;i--) { x=(Math.imul(x,1664525)+1013904223)>>>0; const j=x%(i+1); [a[i],a[j]]=[a[j],a[i]]; }
  return a;
}
export function fixturePlan(seed,runs=1) {
  if (!Number.isInteger(seed)||seed<0||seed>0xffffffff||!Number.isInteger(runs)||runs<1||runs>7) throw new TypeError('invalid fixture plan');
  return Array.from({length:runs},(_,i)=>shuffled((seed+i)>>>0)).flat();
}
const same=(a,b)=>a && b && typeof a==='object' && typeof b==='object' && JSON.stringify(Object.entries(a).sort())===JSON.stringify(Object.entries(b).sort());
function observed(response) {
  const allowed=['accepted','forbidden','invalid_input','unknown_operation'];
  return {ok:typeof response?.ok==='boolean'?response.ok:null,reason:allowed.includes(response?.reason)?response.reason:'unmeasured'};
}
function responseMatches(value,reason,data) {
  if (!value || typeof value!=='object' || Array.isArray(value)) return false;
  const accepted=reason==='accepted';
  const keys=accepted?['data','ok','reason']:['ok','reason'];
  return JSON.stringify(Object.keys(value).sort())===JSON.stringify(keys) && value.ok===accepted && value.reason===reason && (!accepted || same(value.data,data));
}
export async function runMixed({enabled=false,dryRun=true,runs=1,intervalMs=1000,concurrency=1,timeoutMs=5000,seed=1,signal,compare,evidence,terminate}={}) {
  if (!enabled) throw new Error('runner disabled');
  if (!Number.isInteger(runs)||runs<1||runs>7||!Number.isInteger(intervalMs)||intervalMs<1000||concurrency!==1||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000||!Number.isInteger(seed)||seed<0||seed>0xffffffff) throw new TypeError('invalid limits');
  if (!dryRun && (typeof compare !== 'function' || evidence?.version!==3 || ['start','event','finish'].some(k=>typeof evidence[k]!=='function'))) throw new TypeError('local comparison and version 3 evidence required');
  const plan=fixturePlan(seed,runs);
  const outcomes=[]; let stopped=false, expectedState={};
  const runId=dryRun?null:crypto.randomUUID();
  if (!dryRun) evidence.start({version:1,runId,inputSource:'synthetic_fixture',targetProvenance:'unverified_callback',seed,planned:plan.map(f=>f.name),startedUtc:new Date().toISOString(),timeoutMode:isVerifiedProcessComparison(compare)?'process_callback_unverified':'in_process_observed'});
  for (let i=0;i<plan.length;i++) {
    if (signal?.aborted) {stopped=true; break;}
    if (i && !dryRun) await new Promise(resolve => setTimeout(resolve,intervalMs));
    if (signal?.aborted) {stopped=true; break;}
    const f=plan[i];
    if (dryRun) {outcomes.push({fixture:f.name,status:'planned'}); continue;}
    if(i%4===0) expectedState={};
    const e={correlationId:crypto.randomUUID(),operation:f.operation,identity:f.identity,data:{...f.data,id:`case${i}`}};
    evidence.event('started',{index:i,group:Math.floor(i/4),fixture:f.name,correlationId:e.correlationId,startedUtc:new Date().toISOString()});
    let timer, record, result;
    const started=performance.now();
    const task=Promise.resolve().then(()=>compare(e));
    try {
      record=await Promise.race([task,new Promise((_,reject)=>{timer=setTimeout(()=>reject(TIMEOUT),timeoutMs);})]);
      const elapsedMs=performance.now()-started;
      if (elapsedMs>timeoutMs) throw TIMEOUT;
      const expectedAfter={...expectedState};
      if (f.expected==='accepted') expectedAfter[e.data.id]=e.data.value;
      const ok=record?.version===1 && record.correlationId===e.correlationId && responseMatches(record.ordinary,f.expected,e.data) && responseMatches(record.secure,f.expected,e.data) && same(record.before?.baseline,expectedState) && same(record.before?.sapi,expectedState) && same(record.after?.baseline,expectedAfter) && same(record.after?.sapi,expectedAfter);
      result={fixture:f.name,correlationId:e.correlationId,status:ok?'pass':'fail',elapsedMs};
      if (ok) expectedState=expectedAfter; else stopped=true;
    } catch (err) {
      result={fixture:f.name,correlationId:e.correlationId,status:'error',reason:err===TIMEOUT?'timeout_unknown':'evaluation_error',elapsedMs:performance.now()-started};
      stopped=true; task.catch(()=>{});
      if (err===TIMEOUT) {
        const termination=await terminateVerifiedChild(compare,e.correlationId);
        if(termination) {
          const reasons={terminated:'timeout_child_terminated',late_completed:'timeout_late_completed',already_exited:'timeout_already_exited',not_started:'timeout_not_started'};
          result.reason=reasons[termination.disposition];result.termination=termination;
        }
      }
    } finally {clearTimeout(timer);}
    result.observed={ordinary:observed(record?.ordinary),secure:observed(record?.secure)};
    // Never persist callback records, raw responses, dummy state, or caller-supplied fields.
    const stateProof=result.status==='pass'?{beforeOrdinary:stateDigest(record.before.baseline),beforeSecure:stateDigest(record.before.sapi),afterOrdinary:stateDigest(record.after.baseline),afterSecure:stateDigest(record.after.sapi)}:undefined;
    evidence.event('result',{index:i,group:Math.floor(i/4),fixture:f.name,result,stateProof,finishedUtc:new Date().toISOString()});
    outcomes.push(result);
    if (stopped) break;
  }
  const omitted=plan.length-outcomes.length;
  const summary={version:3,runId,seed,dryRun,planned:plan.length,completed:outcomes.length,omitted,omittedFixtures:plan.slice(outcomes.length).map(f=>f.name),stopped,outcomes,pass:!dryRun&&!stopped&&omitted===0&&outcomes.every(x=>x.status==='pass')};
  if (!dryRun) evidence.finish(summary);
  return summary;
}
