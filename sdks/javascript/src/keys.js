import {NAME} from './constants.js';
import {SapiError} from './errors.js';

export class StaticKeyProvider {
  #keys = new Map(); #counts = new Map();
  constructor(keys) {
    if (!keys || !Object.keys(keys).length) throw new TypeError('keys required');
    for (const [kid, record] of Object.entries(keys)) {
      if (!NAME.test(kid) || !(record.master instanceof Uint8Array) || record.master.length !== 32 || typeof record.subject !== 'string' || !NAME.test(record.subject) || [...(record.scopes ?? [])].some(s => typeof s !== 'string' || !NAME.test(s))) throw new TypeError('invalid key record');
      this.#keys.set(kid, {master: new Uint8Array(record.master), subject: record.subject, scopes: new Set(record.scopes ?? [])});
    }
  }
  get(service, kid) {
    const p = this.#keys.get(kid); if (!p) throw new SapiError();
    return {master: new Uint8Array(p.master), subject: p.subject, scopes: new Set(p.scopes)};
  }
  reserve(service, kid, direction) {
    const p = this.get(service, kid), ck = `${service}|${kid}|${direction}`, n = this.#counts.get(ck) ?? 0;
    if (n >= 1048576) throw new SapiError('key_rotation_required');
    this.#counts.set(ck, n + 1); return p;
  }
}
