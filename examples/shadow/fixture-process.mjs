// Fixed synthetic fixtures only. No network, evidence path, or production data is accepted.
import {writeFileSync,renameSync} from 'node:fs';
import {createLocalComparison} from './local-comparison.mjs';
import {fixturePlan} from './mixed-runner.mjs';
const [seedArg,indexArg,mode]=process.argv.slice(2);
const seed=Number(seedArg),index=Number(indexArg);
if (!Number.isInteger(seed)||seed<0||seed>0xffffffff||!Number.isInteger(index)||index<0||index>27||!['run','block-test'].includes(mode)) process.exit(2);
writeFileSync('started','1',{flag:'wx'});
if(mode==='block-test') {const end=performance.now()+2000;while(performance.now()<end){};}
const plan=fixturePlan(seed,7), compare=createLocalComparison().compare;
let result;
for(let i=Math.floor(index/4)*4;i<=index;i++) {
  const f=plan[i];
  result=await compare({correlationId:crypto.randomUUID(),operation:f.operation,identity:f.identity,data:{...f.data,id:`case${i}`}});
}
const state=value=>{
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length>4) throw Error('invalid state');
  const out={};
  for(const [k,v] of Object.entries(value)) {if(!/^case(?:[0-9]|1[0-9]|2[0-7])$/.test(k)||v!=='hello') throw Error('invalid state');out[k]=v;}
  return out;
};
const response=value=>{
  if(!value||typeof value.ok!=='boolean'||!['accepted','invalid_input','forbidden','unknown_operation'].includes(value.reason)) throw Error('invalid response');
  const keys=value.ok?['data','ok','reason']:['ok','reason'];
  if(JSON.stringify(Object.keys(value).sort())!==JSON.stringify(keys)) throw Error('invalid response');
  if(!value.ok) return {ok:false,reason:value.reason};
  if(!value.data||JSON.stringify(Object.keys(value.data).sort())!==JSON.stringify(['id','value'])||!/^case(?:[0-9]|1[0-9]|2[0-7])$/.test(value.data.id)||value.data.value!=='hello') throw Error('invalid data');
  return {ok:true,reason:value.reason,data:{id:value.data.id,value:value.data.value}};
};
const safe={version:1,ordinary:response(result.ordinary),secure:response(result.secure),before:{baseline:state(result.before.baseline),sapi:state(result.before.sapi)},after:{baseline:state(result.after.baseline),sapi:state(result.after.sapi)}};
const encoded=JSON.stringify(safe);if(Buffer.byteLength(encoded)>4096) throw Error('output too large');
writeFileSync('result.tmp',encoded,{flag:'wx'});renameSync('result.tmp','result.json');
