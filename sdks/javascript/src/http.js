// Works with a trusted fetch implementation. Browser mixed-content/CORS rules still apply.
import {SapiError} from './errors.js';
import {isNode} from './platform.js';
export async function exchange(url, wire, {timeout = 30000} = {}) {
  const address = new URL(url);
  if (!['http:', 'https:'].includes(address.protocol) || address.pathname !== '/sapi' || address.search || address.hash || address.username || address.password) throw new TypeError('HTTP(S) /sapi URL required');
  if (typeof wire !== 'string' || wire.length > 131072 || /[^\x00-\x7f]/.test(wire)) throw new SapiError();
  if (!Number.isFinite(timeout) || timeout <= 0) throw new TypeError('positive timeout required');
  if (isNode && typeof globalThis.fetch !== 'function') return (await import('./http-node.js')).exchangeNode(address,wire,timeout);
  const controller = new AbortController(); let reader, timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => {
    reject(new SapiError('transport_error')); controller.abort();
    if (reader) void reader.cancel().catch(() => {});
  }, timeout); });
  const bounded = operation => Promise.race([operation, deadline]);
  try {
    const response = await bounded(fetch(url, {method: 'POST', body: wire, headers: {'Content-Type': 'application/sapi+jwe', Accept: 'application/sapi+jwe'}, redirect: 'error', signal: controller.signal}));
    if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0] !== 'application/sapi+jwe' || !response.body) throw new SapiError('transport_error');
    const chunks = []; reader = response.body.getReader(); let length = 0;
    while (true) {
      const {done, value} = await bounded(reader.read()); if (done) break;
      length += value.length; if (length > 131072) {void reader.cancel().catch(() => {}); throw new SapiError('transport_error');} chunks.push(value);
    }
    const joined = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) {joined.set(chunk, offset); offset += chunk.length;}
    for (const b of joined) if (b > 127) throw new SapiError('transport_error');
    return new TextDecoder('utf-8', {fatal: true}).decode(joined);
  } finally {clearTimeout(timer);}
}
