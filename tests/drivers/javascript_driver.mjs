import readline from 'node:readline';
import {Codec, SecureServer, MemoryReplayStore, SapiError, unb64, Schema, OwnedSql} from '../../sdks/javascript/src/index.js';
import {exchange} from '../../sdks/javascript/src/http.js';
import {StateClient} from '../../sdks/javascript/src/state-node.js';
let codec, server, state, executions = 0, contexts = new Map();
async function invoke(c) {
  if (c.action === 'init') {
    const keys = Object.fromEntries(Object.entries(c.keys).map(([kid, v]) => [kid, {master: unb64(v.key), subject: v.subject, scopes: v.scopes}]));
    state = c.state ? new StateClient(c.state.url, {caFile: c.state.ca_file, certificate: c.state.certificate, privateKey: c.state.private_key, timeout: (c.state.timeout ?? 10) * 1000}) : null;
    codec = new Codec(c.service ?? 'demo', state ?? keys, c.now == null ? undefined : () => c.now);
    const store = c.store === 'fail' ? {claim() {throw new Error('storage unavailable');}} : state ?? new MemoryReplayStore(c.capacity ?? 10000);
    server = new SecureServer(codec, store); executions = 0; contexts = new Map();
    const counted = (p, d) => {executions++; return d;};
    const echo={type:'object',properties:{message:{type:'string',maxBytes:4096}}},own={type:'object',properties:{owner:{type:'string'}}},empty={type:'object',properties:{}};
    server.register('echo', 'echo', echo, echo, () => true, counted);
    server.register('own', 'orders', own, own, (p, d) => p.subject === d.owner, counted);
    server.register('fail', 'echo', empty, empty, () => true, () => {throw new Error('private internal details');});
    server.register('limited','echo',echo,echo,()=>true,counted,{requests:2,period:60});
    server.register('leak','echo',empty,empty,()=>true,()=>({secret:'private-value'}));
    server.register('admin','admin',empty,empty,()=>true,counted);
    return {ready: true};
  }
  if (c.action === 'derive') return {key: Array.from(await codec.derive(c.kid, c.dir), b => b.toString(16).padStart(2, '0')).join('')};
  if (c.action === 'seal') return {wire: await codec.seal(c.kid, c.dir, c.payload)};
  if (c.action === 'open') return await codec.open(c.wire, c.dir);
  if (c.action === 'request') {const ctx = c.subject ? await state.request(codec, c.subject, c.op, c.data) : await codec.request(c.kid, c.op, c.data); contexts.set(c.slot ?? 'default', ctx); return {wire: ctx.wire};}
  if (c.action === 'accept') return {payload: await codec.acceptResponse(contexts.get(c.slot ?? 'default'), c.wire)};
  if (c.action === 'handle') return {wire: await server.handle(c.wire)};
  if (c.action === 'http') {try {return {wire: await exchange(c.url, c.wire, {timeout: c.timeout_ms ?? 30000})};} catch {return {error: 'transport_error'};}}
  if (c.action === 'parallel') return {wires: await Promise.all(Array.from({length: 16}, () => server.handle(c.wire)))};
  if (c.action === 'stats') return {executions};
  if (c.action === 'schema') {try {const schema=new Schema(c.schema);return {compiled:true,valid:schema.validate(c.value)};} catch {return {compiled:false};}}
  if (c.action === 'inventory') return {operations:server.inventory()};
  if (c.action === 'sql') {try {
    const table=new OwnedSql('accounts','id','owner',['id','owner','display_name','role'],['display_name','notes']),p=await codec.principal(c.kid);
    if (!['select','insert','update','delete'].includes(c.kind)) throw new Error();
    return (['insert','update'].includes(c.kind)?table[c.kind](p,c.id,c.changes):table[c.kind](p,c.id)).bind(c.dialect ?? 'qmark');
  } catch {return {blocked:true};}}
  if (c.action === 'sql_config') {try {new OwnedSql('accounts',c.id_column,c.owner_column,c.read,c.write);return {compiled:true};}catch{return {compiled:false};}}
  if (c.action === 'bad_registration') {
    try {server.register('bad', 'echo', {type:'object',properties:{}}, {type:'object',properties:{}}, null, () => ({})); return {rejected: false};}
    catch {return {rejected: true};}
  }
  throw new Error('unknown action');
}
for await (const line of readline.createInterface({input: process.stdin})) {
  try {console.log(JSON.stringify(await invoke(JSON.parse(line))));}
  catch (e) {console.log(JSON.stringify({error: e instanceof SapiError ? e.code : 'invalid_message'}));}
}
