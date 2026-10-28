import assert from 'node:assert/strict';
import {D1ReplayStore} from '../sdks/javascript/src/state-d1.js';
import {Codec,SecureServer,StaticKeyProvider} from '../sdks/javascript/src/index.js';

const schema={type:'object',properties:{value:{type:'boolean'}}};
const keys=new StaticKeyProvider({kid:{master:crypto.getRandomValues(new Uint8Array(32)),subject:'subject',scopes:['write']}});
let count=0;
async function check(stage, rowFactory, splitBudget=false) {
  const db={prepare(sql){return {bind(...args){return {async first(){
    if (sql.includes('SELECT 1 AS ok FROM sapi_replay_policy')) return {ok:1};
    if (sql.includes('sapi_replay_bounded')) return stage==='bounded' ? rowFactory(args) : {id:args[0],decision:'accepted'};
    if (sql.includes('sapi_replay_admission')) return stage==='admit' ? rowFactory(args) : {id:args[0]};
    if (sql.includes('sapi_replay_claims')) return stage==='claim' ? rowFactory(args) : {claimed:1};
    throw new Error('unexpected test statement');
  }}}}},async batch(){throw new Error('unexpected test batch')}};
  const codec=new Codec('service',keys), server=new SecureServer(codec,new D1ReplayStore(db,{mode:'exclusive',service:'service',policyVersion:'v1',operations:{write:{requests:60,period:60}}}),{splitBudget});
  let called=0;server.register('write','write',schema,schema,()=>true,()=>{called++;return {value:true}});
  const context=await codec.request('kid','write',{value:true});
  const result=await codec.acceptResponse(context,await server.handle(context.wire));
  assert.equal(result.error,'internal_error',`${stage}: malformed response must fail closed`);
  assert.equal(called,0,`${stage}: malformed response must not call handler`);
  count++;
}
for (const factory of [a=>({id:a[0],extra:1}),a=>[{id:a[0]}],()=>({}),()=>({id:'wrong'})]) await check('admit',factory);
for (const factory of [()=>({claimed:1,extra:1}),()=>[{claimed:1}],()=>({}),()=>({claimed:'1'})]) await check('claim',factory);
for (const factory of [a=>({id:a[0],decision:'accepted',extra:1}),a=>[{id:a[0],decision:'accepted'}],()=>({decision:'accepted'}),()=>({id:'wrong',decision:'accepted'}),a=>({id:a[0],decision:'invalid'})]) await check('bounded',factory,true);
console.log(`Malformed D1 result: ${count} cases rejected with handler 0`);