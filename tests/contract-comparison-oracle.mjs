// Fixed business expectations, independent of transport implementations.
const input=(key,item='fixture',bad=false)=>({item,operation_key:key,bad_output:bad});
export const contractCases=Object.freeze([
 {id:'alice_valid',input:input('shared'),expected:'accepted',handlers:1,effects:1,receipts:1,category:'normal'},
 {id:'bob_valid',kid:'bob',input:input('bob','bob_fixture'),expected:'accepted',handlers:1,effects:1,receipts:1,category:'normal'},
 {id:'other_object',kid:'bob',input:input('foreign'),expected:'rejected',handlers:0,effects:0,receipts:0,category:'unauthorized'},
 {id:'missing_scope',kid:'noscope',input:input('scope'),expected:'rejected',handlers:0,effects:0,receipts:0,category:'unauthorized'},
 {id:'wrong_type',input:{...input('type'),item:9},expected:'rejected',handlers:0,effects:0,receipts:0,category:'schema_invalid'},
 {id:'extra_field',input:{...input('extra'),subject:'bob'},expected:'rejected',handlers:0,effects:0,receipts:0,category:'schema_invalid'},
 {id:'unknown_operation',operation:'remove',input:input('operation'),expected:'rejected',handlers:0,effects:0,receipts:0,category:'unsupported_operation'},
 {id:'bad_output',input:input('output','fixture',true),expected:'precommit_failure',responseByMode:{ordinary:'rejected',hardened:'rejected',sapi:'uncertain'},handlers:1,effects:0,receipts:0,category:'injected_failure'},
 {id:'same_business_retry',input:input('shared'),expected:'accepted',handlers:1,effects:0,receipts:0,category:'normal'},
 {id:'different_content',input:input('shared','fixture2'),expected:'uncertain',handlers:1,effects:0,receipts:0,category:'business_conflict'},
 {id:'different_subject_same_key',kid:'bob',input:input('shared','bob_fixture'),expected:'uncertain',handlers:1,effects:0,receipts:0,category:'business_conflict'},
 {id:'precommit_db_failure',fault:'before',input:input('db_before'),expected:'uncertain',handlers:1,effects:0,receipts:0,category:'injected_failure'},
 {id:'commit_ack_loss',fault:'after',input:input('db_after'),expected:'uncertain',handlers:1,effects:1,receipts:1,category:'injected_failure'},
 {id:'ack_loss_retry',input:input('db_after'),expected:'accepted',handlers:1,effects:0,receipts:0,category:'normal'},
 {id:'response_loss',dropResponse:true,input:input('lost'),expected:'uncertain',handlers:1,effects:1,receipts:1,category:'injected_failure'},
 {id:'response_loss_retry',input:input('lost'),expected:'accepted',handlers:1,effects:0,receipts:0,category:'normal'},
]);
for(const row of contractCases){Object.freeze(row.input);if(row.responseByMode)Object.freeze(row.responseByMode);Object.freeze(row)}

// These fixed invariants do not import the shared business implementation.
export const wireMutationKinds=Object.freeze(['body_tamper','signature_flip','kid_relabel','wrong_signer']);
const owners=Object.freeze({fixture:'alice',fixture2:'alice',bob_fixture:'bob'});
export function initialModel(){return {items:[{id:'bob_fixture',owner:'bob',value:0},{id:'fixture',owner:'alice',value:0},{id:'fixture2',owner:'alice',value:0}],receipts:[]}}
export function advanceModel(model,c){
 const next=structuredClone(model);
 if(c.effects===0&&c.receipts===0)return next;
 if(c.effects!==1||c.receipts!==1)throw Error('unsupported expected contract delta');
 const owner=c.kid==='bob'?'bob':'alice',item=c.input.item,key=c.input.operation_key;
 if(owners[item]!==owner||c.input.bad_output!==false||next.receipts.some(x=>x.operation_key===key))throw Error('invalid fixed expectation');
 next.items.find(x=>x.id===item).value++;
 next.receipts.push({operation_key:key,owner,item,operation:'change',normalized:JSON.stringify({action:'increment',item}),result_json:JSON.stringify({item,operation_key:key,state:'committed'})});
 next.receipts.sort((a,b)=>a.operation_key<b.operation_key?-1:a.operation_key>b.operation_key?1:0);return next;
}
