// One disposable local child per synthetic fixture; no IPC, network, or DB path.
import {spawn} from 'node:child_process';
import {mkdtempSync,lstatSync,openSync,readSync,closeSync,unlinkSync,rmdirSync,existsSync,realpathSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join,relative,isAbsolute} from 'node:path';
import {fixturePlan} from './mixed-runner.mjs';
import {validateArtifactRoot} from './artifact-path.mjs';
const worker=fileURLToPath(new URL('./fixture-process.mjs',import.meta.url));
const controls=new WeakMap();
export async function terminateVerifiedChild(compare,correlationId) {
  const terminate=controls.get(compare);
  if(!terminate) return null;
  return await terminate(correlationId);
}
export function isVerifiedProcessComparison(compare) {return controls.has(compare);}
const keys=(o,names)=>o && typeof o==='object' && !Array.isArray(o) && JSON.stringify(Object.keys(o).sort())===JSON.stringify(names);
export function parseFixtureOutput(bytes) {
  if(!Buffer.isBuffer(bytes)||bytes.length>4096) throw Error('invalid result size');
  const value=JSON.parse(bytes.toString('utf8'));
  if(!keys(value,['after','before','ordinary','secure','version'])||value.version!==1) throw Error('invalid result');
  for(const side of ['before','after']) {
    if(!keys(value[side],['baseline','sapi'])) throw Error('invalid state');
    for(const target of ['baseline','sapi']) {
      const s=value[side][target];
      if(!s||typeof s!=='object'||Array.isArray(s)||Object.keys(s).length>4||Object.entries(s).some(([k,v])=>!/^case(?:[0-9]|1[0-9]|2[0-7])$/.test(k)||v!=='hello')) throw Error('invalid state');
    }
  }
  for(const target of ['ordinary','secure']) {
    const x=value[target];
    if(typeof x?.ok!=='boolean'||!['accepted','invalid_input','forbidden','unknown_operation'].includes(x.reason)||!keys(x,x.ok?['data','ok','reason']:['ok','reason'])) throw Error('invalid response');
    if(x.ok && (!keys(x.data,['id','value'])||!/^case(?:[0-9]|1[0-9]|2[0-7])$/.test(x.data.id)||x.data.value!=='hello')) throw Error('invalid data');
  }
  return value;
}
export function createProcessComparison({seed=1,runs=1,blockTest=false,testAfterExitBlockMs=0}={}) {
  if(!Number.isInteger(testAfterExitBlockMs)||testAfterExitBlockMs<0||testAfterExitBlockMs>1000) throw Error('invalid test delay');
  const plan=fixturePlan(seed,runs);const root=validateArtifactRoot();
  let index=0, active=null,last=null;
  const compare=async e=> {
      validateArtifactRoot();
      if(active||index>=plan.length) throw Error('process unavailable');
      const f=plan[index];
      if(e.operation!==f.operation||e.identity!==f.identity||e.data?.id!==`case${index}`||e.data?.value!==f.data.value) throw Error('fixture mismatch');
      const dir=mkdtempSync(join(root,'run-'));
      const rel=relative(realpathSync(root),realpathSync(dir));
      if(!rel||rel.startsWith('..')||isAbsolute(rel)) throw Error('invalid run directory');
      let child;
      try {child=spawn(process.execPath,[worker,String(seed),String(index),blockTest?'block-test':'run'],{cwd:dir,stdio:'ignore',windowsHide:true});}
      catch(error) {rmdirSync(dir);throw error;}
      const item={child,dir,correlationId:e.correlationId,sequence:index,stopping:false,done:null,exit:null,completed:false,killRequested:false}; active=item;last=item;
      item.done=new Promise(resolve=>{
        child.on('error',error=>{if(child.pid===undefined) resolve({error});});
        child.once('exit',(code,signal)=>{item.exit={code,signal};resolve(item.exit);});
      });
      try {
        const exit=await item.done;
        if(item.stopping || exit.error || exit.code!==0) throw Error('child failed');
        const path=join(dir,'result.json'), stat=lstatSync(path);
        if(!stat.isFile()||stat.size>4096) throw Error('invalid result file');
        const fd=openSync(path,'r'), buffer=Buffer.alloc(4097);
        let count;try {count=readSync(fd,buffer,0,buffer.length,0);} finally {closeSync(fd);}
        const record=parseFixtureOutput(buffer.subarray(0,count));
        index++;
        item.completed=true;
        if(testAfterExitBlockMs) {const end=performance.now()+testAfterExitBlockMs;while(performance.now()<end){}}
        return {...record,correlationId:e.correlationId};
      } finally {
        // No recursive deletion; remove only this run's known output files after exit.
        for(const name of ['started','result.tmp','result.json']) {try {unlinkSync(join(dir,name));} catch(e) {if(e.code!=='ENOENT') throw e;}}
        rmdirSync(dir); if(active===item) active=null;
      }
    };
  const terminate=async correlationId=> {
      const item=active?.correlationId===correlationId?active:last?.correlationId===correlationId?last:null;
      if(!item) return {disposition:'not_started',pid:null,sequence:null,killRequested:false,exitObserved:false,normalExited:false};
      if(!item.exit) {
        item.stopping=true;
        if(!item.child.kill()) throw Error('termination unconfirmed');
        item.killRequested=true;
        const exit=await item.done;
        if(exit.error||!item.exit) throw Error('termination unconfirmed');
      }
      const disposition=item.killRequested&&item.exit.signal?'terminated':item.completed?'late_completed':'already_exited';
      return {disposition,pid:item.child.pid??null,sequence:item.sequence,killRequested:item.killRequested,exitObserved:true,normalExited:item.exit.code===0};
    };
  controls.set(compare,terminate);
  return {compare,hasStarted:()=>!!active&&existsSync(join(active.dir,'started'))};
}
