// Local-only comparison: no listener, network, production bindings or persistent credentials.
import {Codec, SecureServer, StaticKeyProvider, MemoryReplayStore} from '../../sdks/javascript/src/index.js';

const schemaDef = {type:'object', properties:{id:{type:'string',format:'identifier',maxBytes:32}, value:{type:'string',maxBytes:64}}};
// Fixed baseline policy is implemented independently from the SDK schema validator.
function validDummyInput(value) {
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value))) return false;
  if(JSON.stringify(Object.keys(value).sort())!==JSON.stringify(['id','value'])) return false;
  if(typeof value.id!=='string'||!/^[A-Za-z0-9]/.test(value.id)||/[^A-Za-z0-9_.:-]/.test(value.id)||new TextEncoder().encode(value.id).length>32) return false;
  return typeof value.value==='string'&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\uD800-\uDFFF]/u.test(value.value)&&new TextEncoder().encode(value.value).length<=64;
}
const allowed = ['correlationId','operation','identity','data'];
const uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;

export function createLocalComparison() {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const keys = new StaticKeyProvider({allowed:{master:key,subject:'client1',scopes:['write']}, denied:{master:key,subject:'other',scopes:[]}});
  const client = new Codec('dummy', keys), server = new SecureServer(new Codec('dummy', keys), new MemoryReplayStore());
  const states = {baseline:new Map(), sapi:new Map()};
  const seen = new Set();
  const windows = new Map();
  let inFlight = false, broken = false;
  function put(which, data) { states[which].set(data.id, data.value); return {id:data.id,value:data.value}; }
  server.register('put','write',schemaDef,schemaDef, p => p.subject === 'client1', (_p,d) => put('sapi',d));
  const snapshot = which => Object.fromEntries([...states[which]].sort(([a],[b]) => a.localeCompare(b)));
  async function baseline(e) {
    const subject=e.identity==='allowed'?'client1':'other', now=client.clock();
    const pending=[];
    for(const key of [subject+'|global',subject+'|'+(e.operation==='put'?'put':'unknown')]) {
      let [start,count]=windows.get(key)??[now,0];
      if(now>=start+60) [start,count]=[now,0];
      if(count>=60) return {ok:false,reason:'rate_limited'};
      pending.push([key,[start,count+1]]);
    }
    for(const [key,value] of pending) windows.set(key,value);
    if (e.operation !== 'put') return {ok:false,reason:'unknown_operation'};
    if (e.identity !== 'allowed') return {ok:false,reason:'forbidden'};
    if (!validDummyInput(e.data)) return {ok:false,reason:'invalid_input'};
    return {ok:true,reason:'accepted',data:put('baseline',e.data)};
  }
  return {
    async compare(e) {
      if (!e || Object.getPrototypeOf(e) !== Object.prototype || Object.keys(e).length !== allowed.length || Object.keys(e).some(k => !allowed.includes(k)) || !uuid.test(e.correlationId) || !['put','unknown'].includes(e.operation) || !['allowed','denied'].includes(e.identity) || !e.data || typeof e.data !== 'object' || Array.isArray(e.data) || new TextEncoder().encode(JSON.stringify(e)).length > 8192) throw new TypeError('unsupported envelope');
      if (inFlight || broken) throw new Error('comparison unavailable');
      if (seen.has(e.correlationId) || seen.size >= 64 || states.baseline.size >= 64 || states.sapi.size >= 64) throw new Error('duplicate or dummy capacity reached');
      seen.add(e.correlationId);
      inFlight = true;
      try {
      const before = {baseline:snapshot('baseline'),sapi:snapshot('sapi')};
      const ordinary = await baseline(e);
      const request = await client.request(e.identity,e.operation,e.data);
      const wire = await server.handle(request.wire);
      const decoded = await client.acceptResponse(request,wire);
      const secure = decoded.ok ? {ok:true,reason:'accepted',data:decoded.data} : {ok:false,reason:decoded.error};
      const after = {baseline:snapshot('baseline'),sapi:snapshot('sapi')};
      const record = {version:1, correlationId:e.correlationId, origin:'synthetic_local', before, after, ordinary, secure};
      return record;
      } catch (error) { broken = true; throw error; }
      finally { inFlight = false; }
    }
  };
}
