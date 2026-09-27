import readline from 'node:readline';
import {Codec, SecureServer, MemoryReplayStore, SapiError, unb64} from '../../sdks/javascript/src/index.js';
import {exchange} from '../../sdks/javascript/src/http.js';
let codec, server, executions = 0, contexts = new Map();
async function invoke(c) {
  if (c.action === 'init') {
    const keys = Object.fromEntries(Object.entries(c.keys).map(([kid, v]) => [kid, {master: unb64(v.key), subject: v.subject, scopes: v.scopes}]));
    codec = new Codec(c.service ?? 'demo', keys, c.now == null ? undefined : () => c.now);
    const store = c.store === 'fail' ? {claim() {throw new Error('storage unavailable');}} : new MemoryReplayStore(c.capacity ?? 10000);
    server = new SecureServer(codec, store); executions = 0; contexts = new Map();
    const counted = (p, d) => {executions++; return d;};
    server.register('echo', 'echo', d => Object.keys(d).length === 1 && typeof d.message === 'string' && new TextEncoder().encode(d.message).length <= 4096, () => true, counted);
    server.register('own', 'orders', d => Object.keys(d).length === 1 && typeof d.owner === 'string', (p, d) => p.subject === d.owner, counted);
    server.register('fail', 'echo', () => true, () => true, () => {throw new Error('private internal details');});
    return {ready: true};
  }
  if (c.action === 'derive') return {key: Array.from(await codec.derive(c.kid, c.dir), b => b.toString(16).padStart(2, '0')).join('')};
  if (c.action === 'seal') return {wire: await codec.seal(c.kid, c.dir, c.payload)};
  if (c.action === 'open') return await codec.open(c.wire, c.dir);
  if (c.action === 'request') {const ctx = await codec.request(c.kid, c.op, c.data); contexts.set(c.slot ?? 'default', ctx); return {wire: ctx.wire};}
  if (c.action === 'accept') return {payload: await codec.acceptResponse(contexts.get(c.slot ?? 'default'), c.wire)};
  if (c.action === 'handle') return {wire: await server.handle(c.wire)};
  if (c.action === 'http') {try {return {wire: await exchange(c.url, c.wire)};} catch {return {error: 'transport_error'};}}
  if (c.action === 'parallel') return {wires: await Promise.all(Array.from({length: 16}, () => server.handle(c.wire)))};
  if (c.action === 'stats') return {executions};
  if (c.action === 'bad_registration') {
    try {server.register('bad', 'echo', () => true, null, () => ({})); return {rejected: false};}
    catch {return {rejected: true};}
  }
  throw new Error('unknown action');
}
for await (const line of readline.createInterface({input: process.stdin})) {
  try {console.log(JSON.stringify(await invoke(JSON.parse(line))));}
  catch (e) {console.log(JSON.stringify({error: e instanceof SapiError ? e.code : 'invalid_message'}));}
}
