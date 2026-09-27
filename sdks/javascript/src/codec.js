// Web Crypto only; usable wherever a trusted Web Crypto runtime is available.
import {MAX_WIRE, MAX_BODY, NAME, HEADER_KEYS} from './constants.js';
import {SapiError} from './errors.js';
import {b64, unb64, object, encode, parse, exact, digest} from './serialization.js';
const encoder = new TextEncoder();

export class Codec {
  #keys; #counts = new Map();
  constructor(service, keys, clock = () => Math.floor(Date.now() / 1000)) {
    if (typeof service !== 'string' || !NAME.test(service) || !keys || !Object.keys(keys).length) throw new TypeError('service and keys required');
    this.service = service; this.clock = clock; this.#keys = new Map();
    for (const [kid, record] of Object.entries(keys)) {
      if (!NAME.test(kid) || !(record.master instanceof Uint8Array) || record.master.length !== 32 || typeof record.subject !== 'string' || !NAME.test(record.subject)) throw new TypeError('invalid key record');
      this.#keys.set(kid, {master: new Uint8Array(record.master), subject: record.subject, scopes: new Set(record.scopes ?? [])});
    }
  }
  principal(kid) {
    const p = this.#keys.get(kid); if (!p) throw new SapiError();
    return {subject: p.subject, scopes: new Set(p.scopes)};
  }
  async derive(kid, direction) {
    const p = this.#keys.get(kid); if (!p || !['req', 'res'].includes(direction)) throw new SapiError();
    const key = await crypto.subtle.importKey('raw', p.master, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt: encoder.encode('SAPI/0.1 HKDF-SHA-256'),
      info: encoder.encode(`SAPI/0.1|${this.service}|${kid}|${direction}`)}, key, 256));
  }
  validate(p, direction) {
    if (!object(p)) throw new SapiError();
    if (direction === 'req') {
      exact(p, ['id', 'iat', 'exp', 'op', 'data']);
      if (typeof p.op !== 'string' || !NAME.test(p.op)) throw new SapiError();
    } else {
      if (typeof p.ok !== 'boolean') throw new SapiError();
      exact(p, ['id', 'iat', 'exp', 'req', 'ok', p.ok ? 'data' : 'error']);
      if (unb64(p.req).length !== 32 || (!p.ok && (typeof p.error !== 'string' || !NAME.test(p.error)))) throw new SapiError();
    }
    if (typeof p.id !== 'string' || !/^[0-9a-f]{32}(?![\s\S])/.test(p.id) || ('data' in p && !object(p.data))) throw new SapiError();
    for (const k of ['iat', 'exp']) if (!Number.isSafeInteger(p[k]) || p[k] < 0) throw new SapiError();
    const now = this.clock();
    if (p.exp - p.iat < 1 || p.exp - p.iat > 60 || p.iat > now + 5 || now >= p.exp) throw new SapiError();
  }
  async seal(kid, direction, payload) {
    if (!['req', 'res'].includes(direction)) throw new SapiError(); this.validate(payload, direction);
    const body = encode(payload); if (body.length > MAX_BODY) throw new SapiError();
    const countKey = `${kid}|${direction}`, count = this.#counts.get(countKey) ?? 0;
    if (count >= 1048576) throw new SapiError('key_rotation_required'); this.#counts.set(countKey, count + 1);
    const header = {alg: 'dir', enc: 'A256GCM', typ: 'sapi+jwe', kid, sapi: '0.1', dir: direction, svc: this.service, crit: ['sapi', 'dir', 'svc']};
    const protectedHeader = b64(encode(header)), iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', await this.derive(kid, direction), 'AES-GCM', false, ['encrypt']);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: encoder.encode(protectedHeader), tagLength: 128}, key, body));
    return [protectedHeader, '', b64(iv), b64(encrypted.slice(0, -16)), b64(encrypted.slice(-16))].join('.');
  }
  async open(wire, direction) {
    try {
      if (typeof wire !== 'string' || wire.length > MAX_WIRE || /[^\x00-\x7f]/.test(wire) || !['req', 'res'].includes(direction)) throw new SapiError();
      const parts = wire.split('.'); if (parts.length !== 5 || parts[1] !== '') throw new SapiError();
      const raw = unb64(parts[0]); if (raw.length > 1024) throw new SapiError(); const h = parse(raw); exact(h, HEADER_KEYS);
      for (const [k, v] of Object.entries({alg: 'dir', enc: 'A256GCM', typ: 'sapi+jwe', sapi: '0.1', dir: direction, svc: this.service})) if (h[k] !== v) throw new SapiError();
      if (typeof h.kid !== 'string' || !NAME.test(h.kid) || JSON.stringify(h.crit) !== '["sapi","dir","svc"]') throw new SapiError();
      const iv = unb64(parts[2]), cipher = unb64(parts[3]), tag = unb64(parts[4]);
      if (iv.length !== 12 || tag.length !== 16 || cipher.length > MAX_BODY) throw new SapiError();
      const joined = new Uint8Array(cipher.length + 16); joined.set(cipher); joined.set(tag, cipher.length);
      const key = await crypto.subtle.importKey('raw', await this.derive(h.kid, direction), 'AES-GCM', false, ['decrypt']);
      const plain = await crypto.subtle.decrypt({name: 'AES-GCM', iv, additionalData: encoder.encode(parts[0]), tagLength: 128}, key, joined);
      const payload = parse(new Uint8Array(plain)); this.validate(payload, direction); return {kid: h.kid, payload};
    } catch { throw new SapiError(); }
  }
  async request(kid, operation, data) {
    const now = this.clock(), id = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
    const wire = await this.seal(kid, 'req', {id, iat: now, exp: now + 60, op: operation, data});
    return {wire, kid, id, consumed: false, busy: false};
  }
  async acceptResponse(context, wire) {
    if (context.consumed || context.busy) throw new SapiError('response_replay');
    context.busy = true;
    try {
      const {kid, payload} = await this.open(wire, 'res');
      if (kid !== context.kid || payload.id !== context.id || payload.req !== await digest(context.wire)) throw new SapiError();
      context.consumed = true; return payload;
    } finally { context.busy = false; }
  }
}
