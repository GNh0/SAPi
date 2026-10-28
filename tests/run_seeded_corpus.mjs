// Independent whole-run watchdog. Run only local synthetic corpus.
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const selftest=process.argv.slice(2).includes('--selftest');
const target=fileURLToPath(new URL('./test_seeded_corpus.mjs',import.meta.url));
const args=selftest?['-e','while(true){}']:[target];
const timeout=selftest?1000:45000;
let child, timedOut=false, killAccepted=false, last=null, report=null, buffer='', oversized=false;
try{child=spawn(process.execPath,args,{stdio:['ignore','pipe','pipe'],windowsHide:true,env:{...process.env,SAPI_CORPUS_PROGRESS:'1'}})}catch(e){console.error(JSON.stringify({status:'spawn_failed',reason:e.code??'unknown'}));process.exitCode=1;}
if(child){
 child.on('error',e=>{console.error(JSON.stringify({status:'spawn_failed',reason:e.code??'unknown'}));process.exitCode=1});
 child.stdout.on('data',chunk=>{buffer+=chunk.toString('utf8');if(buffer.length>1024*1024){oversized=true;child.kill();return}let i;while((i=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,i);buffer=buffer.slice(i+1);try{const value=JSON.parse(line);if(value.type==='started')last={id:value.id,kind:value.kind};else if(value.version===1)report=value}catch{oversized=true;child.kill()}}});
 let stderrBytes=0;child.stderr.on('data',chunk=>{stderrBytes+=chunk.length;if(stderrBytes>65536){oversized=true;child.kill()}});
 const timer=setTimeout(()=>{timedOut=true;killAccepted=child.kill();if(!killAccepted)console.error(JSON.stringify({status:'termination_unconfirmed',lastObserved:last}))},timeout);
 child.on('close',(code,signal)=>{clearTimeout(timer);
  if(timedOut){console.log(JSON.stringify({status:selftest&&killAccepted?'watchdog_selftest_terminated':'timeout_unknown',killAccepted,exitObserved:true,code,signal,lastObserved:last,later:'not_run_or_unknown'}));process.exitCode=selftest&&killAccepted?0:2;return}
  if(oversized||code!==0||!report||report.fail!==0||report.completed!==report.planned){console.error(JSON.stringify({status:'incomplete_or_failed',exitObserved:true,code,signal,lastObserved:last,report}));process.exitCode=1;return}
  console.log(JSON.stringify({status:'complete',exitObserved:true,report}));
 });
}
