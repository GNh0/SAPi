// Finite local fixture only. No listener, production binding or persistent key.
import {Codec,SecureServer,StaticKeyProvider,MemoryReplayStore,Schema} from '../../sdks/javascript/src/index.js';
import {parse,b64,unb64} from '../../sdks/javascript/src/serialization.js';
import {setup,install,normalApi,inputSchema,lookup} from './receipt-contract.mjs';

export const comparisonModes=Object.freeze(['ordinary','hardened','sapi']);
const enc=new TextEncoder(),shape=new Schema(inputSchema,{rootObject:true});
const identities=Object.freeze({alice:{subject:'alice',scopes:['write']},bob:{subject:'bob',scopes:['write']},noscope:{subject:'alice',scopes:['read']}});
const id=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');
const reject=reason=>({classification:'rejected',reason});
function command(value,now){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='data,exp,iat,id,op')return false;
 return /^[0-9a-f]{32}$/.test(value.id)&&Number.isSafeInteger(value.iat)&&Number.isSafeInteger(value.exp)&&value.exp>value.iat&&value.exp-value.iat<=60&&value.iat<=now+5&&value.exp>now&&typeof value.op==='string';
}
function ordinaryResult(result){
 if(result.outcome==='ok')return {classification:'accepted',reason:'ok',receipt:result.receipt};
 if(['forbidden','rejected_before_commit'].includes(result.outcome))return reject(result.outcome);
 return {classification:'uncertain',reason:result.outcome};
}
export async function createContractComparison(databases,{clock=()=>1000,maxExecutions=160}={}){
 if(!Number.isInteger(maxExecutions)||maxExecutions<1||maxExecutions>160)throw TypeError('bounded execution count required');
 const providerKeys={},macKeys={},sessions=new Map(),sessionByKid={};
 for(const [kid,p] of Object.entries(identities)){
  providerKeys[kid]={master:crypto.getRandomValues(new Uint8Array(32)),...p};
  macKeys[kid]=await crypto.subtle.importKey('raw',crypto.getRandomValues(new Uint8Array(32)),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
  const session=id();sessions.set(session,p);sessionByKid[kid]=session;
 }
 const codec=new Codec('comparison',new StaticKeyProvider(providerKeys),clock);
 const stores={},opaque=new WeakMap();
 for(const mode of comparisonModes){if(!databases[mode])throw TypeError('separate fixture databases required');await setup(databases[mode]);stores[mode]=new MemoryReplayStore()}
 let executions=0,mutations=0,receiptReads=0;
 const flip=value=>{const bytes=unb64(value);bytes[0]^=1;return b64(bytes)};
 return {
  async readReceipt(mode,kid,key){
   if(++receiptReads>256||!comparisonModes.includes(mode)||!Object.hasOwn(identities,kid)||!/^[A-Za-z0-9_-]{1,40}$/.test(key))throw TypeError('bounded synthetic receipt lookup required');
   return lookup(databases[mode],identities[kid],key);
  },
  async prepare(mode,{kid='alice',operation='change',input}={}){
   if(!comparisonModes.includes(mode)||!Object.hasOwn(identities,kid))throw TypeError('invalid fixture mode or identity');
   if(enc.encode(JSON.stringify(input)).length>7900)throw TypeError('fixture business input exceeds 7900 bytes');
   const start=performance.now();let ticket;
   if(mode==='sapi')ticket={mode,request:await codec.request(kid,operation,input)};
   else {
    const at=clock(),body=JSON.stringify({id:id(),iat:at,exp:at+60,op:operation,data:input});
    if(enc.encode(body).length>8192)throw TypeError('fixture input exceeds 8192 bytes');
    ticket={mode,kid,body,session:sessionByKid[kid]};
    if(mode==='hardened')ticket.mac=await crypto.subtle.sign('HMAC',macKeys[kid],enc.encode(body));
   }
   const handle=Object.freeze({});opaque.set(handle,{...ticket,prepareMs:performance.now()-start});return handle;
  },
  async mutate(mode,handle,mutation){
   // Fixed local mutation controls; no raw keys, sessions or wires leave here.
   if(++mutations>16)throw Error('fixture mutation cap');
   const original=opaque.get(handle);if(!original||original.mode!==mode)throw TypeError('invalid mutation context');
   if(mode==='ordinary')return {status:'not_applicable',requires:'external_authenticated_protected_transport'};
   const ticket={...original,request:original.request?{...original.request}:undefined};
   if(mode==='hardened'){
    if(mutation==='body_tamper'){const body=JSON.parse(ticket.body);body.data.item='fixture2';ticket.body=JSON.stringify(body)}
    else if(mutation==='signature_flip'){const mac=new Uint8Array(ticket.mac.slice(0));mac[0]^=1;ticket.mac=mac.buffer}
    else if(mutation==='kid_relabel')ticket.kid='bob';
    else if(mutation==='wrong_signer')ticket.mac=await crypto.subtle.sign('HMAC',macKeys.bob,enc.encode(ticket.body));
    else return {status:'not_applicable',requires:'external_authenticated_protected_response_transport'};
   }else {
    const parts=ticket.request.wire.split('.');
    if(mutation==='body_tamper')parts[3]=flip(parts[3]);
    else if(mutation==='signature_flip')parts[4]=flip(parts[4]);
    else if(mutation==='kid_relabel'){const header=JSON.parse(new TextDecoder().decode(unb64(parts[0])));header.kid='bob';parts[0]=b64(enc.encode(JSON.stringify(header)))}
    else if(mutation==='wrong_signer'){
     const wrong=new Codec('comparison',new StaticKeyProvider({alice:{master:providerKeys.bob.master,...identities.alice}}),clock);
     ticket.request=await wrong.request('alice','change',{item:'fixture',operation_key:'wrong_signer',bad_output:false});
    }else if(mutation==='response_tag_flip')ticket.responseMutation=true;
    else throw TypeError('unsupported fixed mutation');
    if(['body_tamper','signature_flip','kid_relabel'].includes(mutation))ticket.request.wire=parts.join('.');
   }
   const changed=Object.freeze({});opaque.set(changed,ticket);return {status:'ready',handle:changed};
  },
  async execute(mode,handle,{dropResponse=false}={}){
   if(++executions>maxExecutions)throw Error('fixture execution cap');
   const ticket=opaque.get(handle);if(!ticket||ticket.mode!==mode)throw TypeError('invalid opaque fixture request');
   const start=performance.now(),delivery={handlers:0};let result,validationLayer='session_fixture';
   try{
    if(mode==='sapi'){
     const server=new SecureServer(codec,stores.sapi);install(server,databases.sapi,delivery);
     validationLayer='sapi_request';let wire=await server.handle(ticket.request.wire);validationLayer='sapi_response';
     if(ticket.responseMutation){const parts=wire.split('.');parts[4]=flip(parts[4]);wire=parts.join('.')}
     if(dropResponse)result={classification:'uncertain',reason:'delivery_unknown'};
     else {const response=await codec.acceptResponse({...ticket.request,consumed:false,busy:false},wire);
      result=response.ok?{classification:'accepted',reason:'ok',receipt:response.data}:response.error==='internal_error'?{classification:'uncertain',reason:response.error}:reject(response.error)}
    } else {
     // ordinary models an authenticated session over an assumed protected
     // transport. hardened additionally authenticates these exact body bytes.
     const p=sessions.get(ticket.session);
     if(!p)result=reject('unauthenticated');
     else if(mode==='hardened'&&p!==identities[ticket.kid]){validationLayer='hmac_identity_binding';result=reject('identity_binding')}
     else if(mode==='hardened'&&!(validationLayer='hmac_verification',await crypto.subtle.verify('HMAC',macKeys[ticket.kid],ticket.mac,enc.encode(ticket.body))))result=reject('authentication');
     else {
      validationLayer='authenticated_command';
      const request=parse(enc.encode(ticket.body)),at=clock();
      if(!command(request,at))result=reject('invalid_message');
      else if(stores[mode].admit('comparison',ticket.kid,p.subject,request.op==='change'?'change':'unknown',at,60,60)!==true)result=reject('rate_limited');
      else if(stores[mode].claim(`comparison|${ticket.kid}|${request.id}`,request.exp,at)!==true)result=reject('replay');
      else if(request.op!=='change')result=reject('unknown_operation');
      else if(!p.scopes.includes('write'))result=reject('forbidden');
      else if(!shape.validate(request.data))result=reject('invalid_input');
      else result=ordinaryResult(await normalApi(databases[mode],p,request.data,{onHandler(){delivery.handlers++}}));
     }
    }
   }catch(error){result=error.code==='invalid_message'&&validationLayer!=='sapi_response'&&delivery.handlers===0?reject(error.code):{classification:'uncertain',reason:'execution_unknown'}}
   if(dropResponse)result={classification:'uncertain',reason:'delivery_unknown'};
   return {...result,validationLayer,handlerEntries:delivery.handlers,latencyMs:performance.now()-start,prepareMs:ticket.prepareMs};
  }
 };
}
