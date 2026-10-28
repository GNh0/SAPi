// Local-only synthetic contract. No live endpoint, credential or runtime access.
import {Schema} from '../../sdks/javascript/src/index.js';
export const inputSchema={type:'object',properties:{item:{type:'string',maxBytes:20},operation_key:{type:'string',minBytes:1,maxBytes:40},bad_output:{type:'boolean'}}};
export const outputSchema={type:'object',properties:{item:{type:'string',maxBytes:20},operation_key:{type:'string',minBytes:1,maxBytes:40},state:{type:'string',enum:['committed']}}};
const inputValidator=new Schema(inputSchema,{rootObject:true}),outputValidator=new Schema(outputSchema,{rootObject:true});
// Output consists exclusively of server-owned fixed ASCII values and a bounded ASCII key.
const encodeOutput=value=>new TextEncoder().encode(JSON.stringify(value));
class PrecommitError extends Error {}
const ownerByItem=Object.freeze({fixture:'alice',fixture2:'alice',bob_fixture:'bob'});
export function authorized(principal,input){return typeof principal?.subject==='string'&&Object.hasOwn(ownerByItem,input?.item)&&ownerByItem[input.item]===principal.subject;}
export async function setup(db){await db.batch([
 db.prepare('CREATE TABLE sapi_internal_effect_items(id TEXT PRIMARY KEY,owner TEXT NOT NULL,value INTEGER NOT NULL)'),
 db.prepare("INSERT INTO sapi_internal_effect_items VALUES ('fixture','alice',0),('fixture2','alice',0),('bob_fixture','bob',0)"),
 db.prepare(`CREATE TABLE sapi_internal_effect_receipts(operation_key TEXT PRIMARY KEY,owner TEXT NOT NULL,item TEXT NOT NULL,operation TEXT NOT NULL,normalized TEXT NOT NULL,result_json TEXT NOT NULL,
   CHECK(length(operation_key) BETWEEN 1 AND 40 AND operation_key NOT GLOB '*[^A-Za-z0-9_-]*'),
   CHECK(operation='change' AND normalized=json_object('action','increment','item',item)),
   CHECK(length(CAST(result_json AS BLOB))<=1024 AND result_json=json_object('item',item,'operation_key',operation_key,'state','committed')))`),
 db.prepare("CREATE TRIGGER effect_once AFTER INSERT ON sapi_internal_effect_receipts BEGIN UPDATE sapi_internal_effect_items SET value=value+1 WHERE id=NEW.item AND owner=NEW.owner; SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,'effect denied') END; END")]);}
export async function lookup(db,principal,key){
 if(!['alice','bob'].includes(principal.subject))return null;
 const row=await db.prepare('SELECT owner,item,operation,normalized,result_json FROM sapi_internal_effect_receipts WHERE operation_key=? AND owner=?').bind(key,principal.subject).first();
 if(!row)return null;let result;try{result=JSON.parse(row.result_json)}catch{throw Error('receipt invalid')}
 if(!outputValidator.validate(result)||result.operation_key!==key||result.item!==row.item||row.operation!=='change'||row.normalized!==JSON.stringify({action:'increment',item:row.item})||result.state!=='committed'||encodeOutput(result).length>1024)throw Error('receipt invalid');
 return result;
}
export async function business(db,principal,input){
 if(!inputValidator.validate(input))throw new PrecommitError('invalid_input_before_commit');
 if(!/^[A-Za-z0-9_-]{1,40}$/.test(input.operation_key))throw new PrecommitError('invalid_operation_key');
 if(!authorized(principal,input))throw Error('forbidden');
 // All output is deterministic from bounded input and checked BEFORE the batch.
 const result=input.bad_output?{wrong:true}:{item:input.item,operation_key:input.operation_key,state:'committed'};
 if(!outputValidator.validate(result))throw new PrecommitError('output_invalid_before_commit');
 let bytes;try{bytes=encodeOutput(result)}catch{throw new PrecommitError('output_serialization_before_commit')}
 if(bytes.length>1024)throw new PrecommitError('output_too_large_before_commit');
 const json=new TextDecoder().decode(bytes);
 // Trigger applies the effect exactly once on the first successful receipt insert.
 const normalized=JSON.stringify({action:'increment',item:input.item});
 await db.batch([db.prepare('INSERT INTO sapi_internal_effect_receipts(operation_key,owner,item,operation,normalized,result_json) VALUES (?,?,?,?,?,?) ON CONFLICT(operation_key) DO NOTHING').bind(input.operation_key,principal.subject,input.item,'change',normalized,json)]);
 const receipt=await lookup(db,principal,input.operation_key);
 if(!receipt||receipt.item!==input.item||JSON.stringify(receipt)!==json)throw Error('receipt_conflict_or_uncertain');
 return receipt;
}
export async function normalApi(db,principal,input,{loseResponse=false,onHandler=()=>{}}={}){
 if(!inputValidator.validate(input))return {outcome:'rejected_before_commit'};
 if(!authorized(principal,input))return {outcome:'forbidden'};
 try{onHandler();const receipt=await business(db,principal,input);if(loseResponse)return {outcome:'delivery_unknown'};return {outcome:'ok',receipt};}catch(error){return {outcome:error instanceof PrecommitError?'rejected_before_commit':'error_or_commit_unknown'}}
}
export function install(server,db,delivery){
 server.register('change','write',inputSchema,outputSchema,authorized,async(principal,input)=>{
  delivery.handlers=(delivery.handlers??0)+1;
  const receipt=await business(db,principal,input);
  if(delivery.fail)throw Error('simulated response encryption or delivery failure after commit');
  return receipt;
 });
}
